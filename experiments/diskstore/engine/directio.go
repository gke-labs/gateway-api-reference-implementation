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
	"io"
	"syscall"
)

// DirectIO moves multi-block pages using direct, unbuffered I/O.
type DirectIO interface {
	Readv(file File, off int64, iov [][]byte) error
	Writev(file File, off int64, iov [][]byte) error
	Write(file File, off int64, buf []byte) error
}

type defaultDirectIO struct{}

// NewDirectIO creates a new DirectIO instance.
func NewDirectIO() DirectIO {
	return &defaultDirectIO{}
}

func (d *defaultDirectIO) Readv(file File, off int64, iov [][]byte) error {
	if len(iov) == 0 {
		return nil
	}

	// Check if file supports SyscallConn for raw vectored syscall
	conn, err := file.SyscallConn()
	if err == nil && conn != nil {
		if rawConn, ok := conn.(syscall.RawConn); ok {
			var sysErr error
			err = rawConn.Control(func(fd uintptr) {
				sysErr = platformPreadv(fd, off, iov)
			})
			if err == nil && sysErr == nil {
				return nil
			}
		}
	}

	// Fallback to sequential ReadAt
	currOff := off
	for i, buf := range iov {
		n, readErr := file.ReadAt(buf, currOff)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("readv fallback failed at block %d: %w", i, readErr)
		}
		currOff += int64(n)
	}
	return nil
}

func (d *defaultDirectIO) Writev(file File, off int64, iov [][]byte) error {
	if len(iov) == 0 {
		return nil
	}

	// Check if file supports SyscallConn for raw vectored syscall
	conn, err := file.SyscallConn()
	if err == nil && conn != nil {
		if rawConn, ok := conn.(syscall.RawConn); ok {
			var sysErr error
			err = rawConn.Control(func(fd uintptr) {
				sysErr = platformPwritev(fd, off, iov)
			})
			if err == nil && sysErr == nil {
				return nil
			}
		}
	}

	// Fallback to sequential WriteAt
	currOff := off
	for i, buf := range iov {
		n, writeErr := file.WriteAt(buf, currOff)
		if writeErr != nil {
			return fmt.Errorf("writev fallback failed at block %d: %w", i, writeErr)
		}
		currOff += int64(n)
	}
	return nil
}

func (d *defaultDirectIO) Write(file File, off int64, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}

	// Check if file supports SyscallConn for raw pwrite syscall
	conn, err := file.SyscallConn()
	if err == nil && conn != nil {
		if rawConn, ok := conn.(syscall.RawConn); ok {
			var sysErr error
			err = rawConn.Control(func(fd uintptr) {
				sysErr = platformPwrite(fd, off, buf)
			})
			if err == nil && sysErr == nil {
				return nil
			}
		}
	}

	// Fallback to WriteAt
	_, writeErr := file.WriteAt(buf, off)
	if writeErr != nil {
		return fmt.Errorf("write fallback failed at offset %d: %w", off, writeErr)
	}
	return nil
}
