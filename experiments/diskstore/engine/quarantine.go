// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxQuarantinedFiles is the default maximum number of quarantined files
	// kept in each lost+found directory (100).
	DefaultMaxQuarantinedFiles = 100

	// DefaultMinQuarantinedRetention is the default minimum retention duration
	// for quarantined files in lost+found (7 days). Files younger than this retention
	// are not deleted even if the file count exceeds MaxQuarantinedFiles.
	DefaultMinQuarantinedRetention = 7 * 24 * time.Hour
)

// QuarantineOptions configures quarantine bounding and retention for lost+found directories.
type QuarantineOptions struct {
	// Dir is the lost+found directory path.
	Dir string

	// MaxQuarantinedFiles is the maximum number of quarantined files kept in the directory.
	// When exceeded, files older than MinQuarantinedRetention are removed.
	MaxQuarantinedFiles int

	// MinQuarantinedRetention is the minimum duration a quarantined file is kept.
	// Files younger than this retention are not deleted even when MaxQuarantinedFiles is exceeded.
	MinQuarantinedRetention time.Duration

	// Now returns the current time for retention checks. If nil, time.Now is used.
	Now func() time.Time
}

var quarantineCounter atomic.Uint64

func uniqueQuarantinePath(lostDir, segName string) string {
	return filepath.Join(lostDir, fmt.Sprintf("%s.%d.%d.%d", segName, time.Now().UnixNano(), os.Getpid(), quarantineCounter.Add(1)))
}

func parseQuarantineTimestamp(name string) (int64, uint64, error) {
	parts := strings.Split(name, ".")
	if len(parts) < 4 {
		return 0, 0, fmt.Errorf("invalid quarantine file name: %s", name)
	}
	nano, err := strconv.ParseInt(parts[len(parts)-3], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid quarantine timestamp in %s: %w", name, err)
	}
	if _, err := strconv.Atoi(parts[len(parts)-2]); err != nil {
		return 0, 0, fmt.Errorf("invalid quarantine pid in %s: %w", name, err)
	}
	counter, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid quarantine counter in %s: %w", name, err)
	}
	return nano, counter, nil
}

type lostFile struct {
	path    string
	name    string
	nano    int64
	counter uint64
}

func pruneLostFound(storeFS FS, opts QuarantineOptions) error {
	if opts.MaxQuarantinedFiles <= 0 || opts.Dir == "" {
		return nil
	}

	entries, err := storeFS.ReadDir(opts.Dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	var files []lostFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		nano, counter, parseErr := parseQuarantineTimestamp(entry.Name())
		if parseErr != nil {
			slog.Warn("diskstore: ignoring quarantined file with unparseable timestamp", "file", entry.Name(), "error", parseErr)
			continue
		}
		files = append(files, lostFile{
			path:    filepath.Join(opts.Dir, entry.Name()),
			name:    entry.Name(),
			nano:    nano,
			counter: counter,
		})
	}

	if len(files) <= opts.MaxQuarantinedFiles {
		return nil
	}

	// Sort oldest first by nanosecond timestamp and per-process counter
	sort.Slice(files, func(i, j int) bool {
		if files[i].nano != files[j].nano {
			return files[i].nano < files[j].nano
		}
		if files[i].counter != files[j].counter {
			return files[i].counter < files[j].counter
		}
		return files[i].name < files[j].name
	})

	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}

	excess := len(files) - opts.MaxQuarantinedFiles
	var toDelete []lostFile
	for i := 0; i < excess; i++ {
		f := files[i]
		if opts.MinQuarantinedRetention > 0 {
			fileTime := time.Unix(0, f.nano)
			if now.Sub(fileTime) < opts.MinQuarantinedRetention {
				// Younger than minimum retention; do not delete even though over maximum.
				break
			}
		}
		toDelete = append(toDelete, f)
	}

	for _, f := range toDelete {
		if err := storeFS.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("failed to remove excess quarantined file %s: %w", f.path, err)
		}
		slog.Warn("diskstore: deleted oldest quarantined file exceeding lost+found bound", "file", f.path)
	}
	if len(toDelete) > 0 {
		return storeFS.SyncDir(opts.Dir)
	}
	return nil
}

// quarantineFiles moves a list of files from dir into that directory's lost+found
// under the given QuarantineOptions.
//
// The engine moves a file that it cannot account for to quarantine and never deletes it,
// preserving unreferenced or abandoned data for offline recovery, inspection, and forensic
// reconstruction without risking permanent data loss.
//
// It creates lost+found once when moving files, renames each file to a unique quarantine path,
// prunes lost+found, and fsyncs both directories when it moved anything.
// It returns the first error encountered and deletes nothing on that path.
func quarantineFiles(storeFS FS, dir string, files []string, opts QuarantineOptions) error {
	lostDir := filepath.Join(dir, "lost+found")
	opts.Dir = lostDir

	var moved int
	if len(files) > 0 {
		if err := storeFS.MkdirAll(lostDir, StoreDirMode); err != nil {
			return fmt.Errorf("failed to create quarantine directory %s: %w", lostDir, err)
		}
		for _, file := range files {
			name := filepath.Base(file)
			if name == "." || name == "" {
				continue
			}
			src := filepath.Join(dir, name)
			dest := uniqueQuarantinePath(lostDir, name)
			if err := storeFS.Rename(src, dest); err != nil {
				return fmt.Errorf("failed to quarantine %s to %s: %w", src, dest, err)
			}
			slog.Warn("diskstore: moved file to quarantine", "from", src, "to", dest)
			moved++
		}
	}

	if err := pruneLostFound(storeFS, opts); err != nil {
		return fmt.Errorf("failed to prune quarantine directory %s: %w", lostDir, err)
	}

	if moved > 0 {
		// A rename across directories changes two directory entries.
		// Syncing lost+found makes the new entry durable so a crash cannot leave the file
		// in neither directory and lose offline recovery data.
		if err := storeFS.SyncDir(lostDir); err != nil {
			return fmt.Errorf("failed to sync quarantine directory %s: %w", lostDir, err)
		}
		// Syncing the parent directory makes the removal durable so the quarantined
		// file cannot reappear after a subsequent crash.
		if err := storeFS.SyncDir(dir); err != nil {
			return fmt.Errorf("failed to sync directory %s after quarantine: %w", dir, err)
		}
		slog.Debug("diskstore: quarantined files", "dir", dir, "count", moved)
	}

	return nil
}
