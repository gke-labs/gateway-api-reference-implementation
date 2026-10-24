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

const (
	// MaxVectorLimit is the maximum number of vector buffers in a single vectored I/O syscall (1024 on Linux/Darwin).
	MaxVectorLimit = 1024
)

// DirectIO moves multi-block pages using direct, unbuffered vectored I/O.
type DirectIO interface {
	Readv(file File, off int64, iov [][]byte) error
	Writev(file File, off int64, iov [][]byte) error
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

	currOff := off
	for len(iov) > 0 {
		chunk := iov
		if len(chunk) > MaxVectorLimit {
			chunk = chunk[:MaxVectorLimit]
		}

		if err := d.readChunk(file, currOff, chunk); err != nil {
			return err
		}

		chunkBytes := int64(0)
		for _, buf := range chunk {
			chunkBytes += int64(len(buf))
		}
		currOff += chunkBytes
		iov = iov[len(chunk):]
	}
	return nil
}

func (d *defaultDirectIO) readChunk(file File, off int64, chunk [][]byte) error {
	if vr, ok := file.(interface{ Readv(off int64, iov [][]byte) error }); ok {
		return vr.Readv(off, chunk)
	}

	// Check if file supports SyscallConn for raw vectored syscall
	conn, err := file.SyscallConn()
	if err == nil && conn != nil {
		if rawConn, ok := conn.(syscall.RawConn); ok {
			var sysErr error
			err = rawConn.Control(func(fd uintptr) {
				sysErr = platformPreadv(fd, off, chunk)
			})
			if err == nil && sysErr == nil {
				return nil
			}
		}
	}

	// Fallback to sequential ReadAt
	currOff := off
	for i, buf := range chunk {
		n, rErr := file.ReadAt(buf, currOff)
		if rErr != nil && !errors.Is(rErr, io.EOF) {
			return fmt.Errorf("readv fallback failed at block %d: %w", i, rErr)
		}
		currOff += int64(n)
	}
	return nil
}

func (d *defaultDirectIO) Writev(file File, off int64, iov [][]byte) error {
	if len(iov) == 0 {
		return nil
	}

	currOff := off
	for len(iov) > 0 {
		chunk := iov
		if len(chunk) > MaxVectorLimit {
			chunk = chunk[:MaxVectorLimit]
		}

		if err := d.writeChunk(file, currOff, chunk); err != nil {
			return err
		}

		chunkBytes := int64(0)
		for _, buf := range chunk {
			chunkBytes += int64(len(buf))
		}
		currOff += chunkBytes
		iov = iov[len(chunk):]
	}
	return nil
}

func (d *defaultDirectIO) writeChunk(file File, off int64, chunk [][]byte) error {
	// If file directly supports vectored writes, use that
	if vw, ok := file.(interface{ Writev(off int64, iov [][]byte) error }); ok {
		return vw.Writev(off, chunk)
	}

	// Check if file supports SyscallConn for raw vectored syscall
	conn, err := file.SyscallConn()
	if err == nil && conn != nil {
		if rawConn, ok := conn.(syscall.RawConn); ok {
			var sysErr error
			err = rawConn.Control(func(fd uintptr) {
				sysErr = platformPwritev(fd, off, chunk)
			})
			if err == nil && sysErr == nil {
				return nil
			}
		}
	}

	// Fallback: coalesce chunk into a single contiguous buffer so a single write call is made
	totalBytes := 0
	for _, buf := range chunk {
		totalBytes += len(buf)
	}
	combined := make([]byte, totalBytes)
	pos := 0
	for _, buf := range chunk {
		copy(combined[pos:], buf)
		pos += len(buf)
	}

	if _, wErr := file.WriteAt(combined, off); wErr != nil {
		return fmt.Errorf("writev fallback failed at offset %d: %w", off, wErr)
	}
	return nil
}
