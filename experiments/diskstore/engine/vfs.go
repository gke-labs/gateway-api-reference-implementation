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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// File abstracts low-level file I/O operations for diskstore components.
type File interface {
	ReadAt(p []byte, off int64) (n int, err error)
	WriteAt(p []byte, off int64) (n int, err error)
	Sync() error
	Truncate(size int64) error
	Close() error
	Size() (int64, error)
	// SyscallConn returns a raw syscall connection if backed by an OS file.
	// Can return nil if in-memory.
	SyscallConn() (any, error)
}

// FS abstracts filesystem operations.
type FS interface {
	OpenFile(name string, flag int, perm os.FileMode) (File, error)
	Create(name string) (File, error)
	Open(name string) (File, error)
	Remove(name string) error
	Rename(oldpath, newpath string) error
	MkdirAll(path string, perm os.FileMode) error
	ReadDir(dirname string) ([]os.DirEntry, error)
	SyncDir(dirname string) error
}

// OSFile wraps *os.File to implement File.
type OSFile struct {
	file *os.File
}

func (o *OSFile) ReadAt(p []byte, off int64) (n int, err error) {
	return o.file.ReadAt(p, off)
}

func (o *OSFile) WriteAt(p []byte, off int64) (n int, err error) {
	return o.file.WriteAt(p, off)
}

func (o *OSFile) Sync() error {
	return o.file.Sync()
}

func (o *OSFile) Truncate(size int64) error {
	return o.file.Truncate(size)
}

func (o *OSFile) Close() error {
	return o.file.Close()
}

func (o *OSFile) Size() (int64, error) {
	fi, err := o.file.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func (o *OSFile) SyscallConn() (any, error) {
	return o.file.SyscallConn()
}

// OSFS implements FS backed by the host operating system.
type OSFS struct{}

func NewOSFS() FS {
	return &OSFS{}
}

func (o *OSFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &OSFile{file: f}, nil
}

func (o *OSFS) Create(name string) (File, error) {
	return o.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, StoreFileMode)
}

func (o *OSFS) Open(name string) (File, error) {
	return o.OpenFile(name, os.O_RDONLY, 0)
}

func (o *OSFS) Remove(name string) error {
	return os.Remove(name)
}

func (o *OSFS) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

func (o *OSFS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (o *OSFS) ReadDir(dirname string) ([]os.DirEntry, error) {
	return os.ReadDir(dirname)
}

func (o *OSFS) SyncDir(dirname string) error {
	dir, err := os.Open(dirname)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}

// MemFile is an in-memory implementation of File for testing and fault simulation.
type MemFile struct {
	mu     sync.RWMutex
	data   []byte
	closed bool
}

func (m *MemFile) ReadAt(p []byte, off int64) (n int, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return 0, errors.New("file already closed")
	}
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n = copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func amortizedGrow(data []byte, off int64, pLen int) []byte {
	reqLen := int(off) + pLen
	oldLen := len(data)
	if reqLen <= oldLen {
		return data
	}
	if reqLen <= cap(data) {
		data = data[:reqLen]
		if int(off) > oldLen {
			clear(data[oldLen:off])
		}
		return data
	}
	newCap := cap(data) * 2
	if newCap < reqLen {
		newCap = reqLen
	}
	if newCap < 4096 {
		newCap = 4096
	}
	expanded := make([]byte, reqLen, newCap)
	copy(expanded, data)
	return expanded
}

func amortizedTruncate(data []byte, size int64) []byte {
	if int(size) < len(data) {
		return data[:size]
	}
	if int(size) > len(data) {
		oldLen := len(data)
		reqLen := int(size)
		data = amortizedGrow(data, size, 0)
		clear(data[oldLen:reqLen])
	}
	return data
}

func (m *MemFile) WriteAt(p []byte, off int64) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errors.New("file already closed")
	}
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	m.data = amortizedGrow(m.data, off, len(p))
	copy(m.data[off:], p)
	return len(p), nil
}

func (m *MemFile) Sync() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return errors.New("file already closed")
	}
	return nil
}

func (m *MemFile) Truncate(size int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("file already closed")
	}
	if size < 0 {
		return errors.New("negative size")
	}
	m.data = amortizedTruncate(m.data, size)
	return nil
}

func (m *MemFile) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *MemFile) Size() (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return 0, errors.New("file already closed")
	}
	return int64(len(m.data)), nil
}

func (m *MemFile) SyscallConn() (any, error) {
	return nil, nil
}

// MemFS implements an in-memory FS.
type MemFS struct {
	mu          sync.RWMutex
	files       map[string][]byte
	directories map[string]bool
	syncedDirs  map[string]int
}

// NewMemFS creates a new in-memory filesystem.
func NewMemFS() *MemFS {
	return &MemFS{
		files:       make(map[string][]byte),
		directories: make(map[string]bool),
		syncedDirs:  make(map[string]int),
	}
}

func cleanPath(p string) string {
	return filepath.Clean(p)
}

func (m *MemFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cleaned := cleanPath(name)
	dir := filepath.Dir(cleaned)
	if dir != "." && dir != "/" && !m.directories[dir] {
		return nil, fmt.Errorf("directory does not exist: %s: %w", dir, os.ErrNotExist)
	}

	data, exists := m.files[cleaned]
	if !exists {
		if flag&os.O_CREATE == 0 {
			return nil, os.ErrNotExist
		}
		data = make([]byte, 0)
		m.files[cleaned] = data
	} else if flag&os.O_TRUNC != 0 {
		data = make([]byte, 0)
		m.files[cleaned] = data
	}

	mf := &memFileWrapper{
		fs:   m,
		name: cleaned,
	}
	return mf, nil
}

func (m *MemFS) Create(name string) (File, error) {
	return m.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, StoreFileMode)
}

func (m *MemFS) Open(name string) (File, error) {
	return m.OpenFile(name, os.O_RDONLY, 0)
}

func (m *MemFS) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cleaned := cleanPath(name)
	if _, exists := m.files[cleaned]; !exists {
		return os.ErrNotExist
	}
	delete(m.files, cleaned)
	return nil
}

func (m *MemFS) Rename(oldpath, newpath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldClean := cleanPath(oldpath)
	newClean := cleanPath(newpath)

	data, exists := m.files[oldClean]
	if !exists {
		return os.ErrNotExist
	}
	newDir := filepath.Dir(newClean)
	if newDir != "." && newDir != "/" && !m.directories[newDir] {
		return fmt.Errorf("directory does not exist: %s: %w", newDir, os.ErrNotExist)
	}

	m.files[newClean] = data
	delete(m.files, oldClean)
	return nil
}

func (m *MemFS) MkdirAll(path string, perm os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cleaned := cleanPath(path)
	curr := cleaned
	for curr != "." && curr != "/" && curr != "" {
		m.directories[curr] = true
		curr = filepath.Dir(curr)
	}
	return nil
}

type memDirEntry struct {
	name  string
	isDir bool
	size  int64
}

func (e memDirEntry) Name() string               { return e.name }
func (e memDirEntry) IsDir() bool                { return e.isDir }
func (e memDirEntry) Type() os.FileMode          { return 0 }
func (e memDirEntry) Info() (os.FileInfo, error) { return memFileInfo(e), nil }

type memFileInfo memDirEntry

func (i memFileInfo) Name() string       { return i.name }
func (i memFileInfo) Size() int64        { return i.size }
func (i memFileInfo) Mode() os.FileMode  { return StoreFileMode }
func (i memFileInfo) ModTime() time.Time { return time.Time{} }
func (i memFileInfo) IsDir() bool        { return i.isDir }
func (i memFileInfo) Sys() any           { return nil }

func (m *MemFS) ReadDir(dirname string) ([]os.DirEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cleaned := cleanPath(dirname)
	prefix := cleaned + string(filepath.Separator)
	if cleaned == "." {
		prefix = ""
	}

	seen := make(map[string]bool)
	var entries []os.DirEntry

	for name, data := range m.files {
		if prefix == "" || filepath.HasPrefix(name, prefix) {
			rel, err := filepath.Rel(cleaned, name)
			if err != nil || rel == "." {
				continue
			}
			parts := bytes.Split([]byte(rel), []byte{filepath.Separator})
			top := string(parts[0])
			if !seen[top] {
				seen[top] = true
				if len(parts) == 1 {
					entries = append(entries, memDirEntry{name: top, isDir: false, size: int64(len(data))})
				} else {
					entries = append(entries, memDirEntry{name: top, isDir: true, size: 0})
				}
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	return entries, nil
}

func (m *MemFS) SyncDir(dirname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cleaned := cleanPath(dirname)
	m.syncedDirs[cleaned]++
	return nil
}

func (m *MemFS) DirSyncCount(dirname string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncedDirs[cleanPath(dirname)]
}

// memFileWrapper ensures writes update the centralized map in MemFS.
type memFileWrapper struct {
	fs     *MemFS
	name   string
	closed bool
	mu     sync.Mutex
}

func (w *memFileWrapper) ReadAt(p []byte, off int64) (int, error) {
	w.fs.mu.RLock()
	defer w.fs.mu.RUnlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("file closed")
	}
	data, ok := w.fs.files[w.name]
	if !ok {
		return 0, os.ErrNotExist
	}
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= int64(len(data)) {
		return 0, io.EOF
	}
	n := copy(p, data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (w *memFileWrapper) WriteAt(p []byte, off int64) (int, error) {
	w.fs.mu.Lock()
	defer w.fs.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("file closed")
	}
	data := w.fs.files[w.name]
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	data = amortizedGrow(data, off, len(p))
	copy(data[off:], p)
	w.fs.files[w.name] = data
	return len(p), nil
}

func (w *memFileWrapper) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("file closed")
	}
	return nil
}

func (w *memFileWrapper) Truncate(size int64) error {
	w.fs.mu.Lock()
	defer w.fs.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("file closed")
	}
	if size < 0 {
		return errors.New("negative size")
	}
	data := w.fs.files[w.name]
	data = amortizedTruncate(data, size)
	w.fs.files[w.name] = data
	return nil
}

func (w *memFileWrapper) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *memFileWrapper) Size() (int64, error) {
	w.fs.mu.RLock()
	defer w.fs.mu.RUnlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("file closed")
	}
	return int64(len(w.fs.files[w.name])), nil
}

func (w *memFileWrapper) SyscallConn() (any, error) {
	return nil, nil
}
