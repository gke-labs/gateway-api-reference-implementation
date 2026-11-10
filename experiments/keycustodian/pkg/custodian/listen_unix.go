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

//go:build linux || darwin

package custodian

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ListenUnix creates a Unix domain socket listener with mode 0660.
func ListenUnix(socketPath string) (net.Listener, error) {
	fileInfo, err := os.Lstat(socketPath)
	if err == nil {
		if fileInfo.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", socketPath)
		}
		if removeErr := os.Remove(socketPath); removeErr != nil {
			return nil, removeErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if parentDir := filepath.Dir(socketPath); parentDir != "" {
		if mkdirErr := os.MkdirAll(parentDir, 0750); mkdirErr != nil {
			return nil, mkdirErr
		}
	}

	// Set the umask around net.Listen to avoid a window where the socket has default permissions.
	// Note that umask is process-wide, so this must run before other goroutines start.
	oldUmask := unix.Umask(0117)
	listener, listenErr := net.Listen("unix", socketPath)
	unix.Umask(oldUmask)
	if listenErr != nil {
		return nil, listenErr
	}

	return NewCredListener(listener), nil
}
