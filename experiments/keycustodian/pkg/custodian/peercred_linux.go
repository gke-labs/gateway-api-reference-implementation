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

//go:build linux

package custodian

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func getPeerCred(conn net.Conn) (*PeerCred, error) {
	unixConnection, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix socket connection")
	}
	rawConnection, err := unixConnection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credential *unix.Ucred
	var socketOptionErr error
	controlErr := rawConnection.Control(func(fileDescriptor uintptr) {
		credential, socketOptionErr = unix.GetsockoptUcred(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if controlErr != nil {
		return nil, controlErr
	}
	if socketOptionErr != nil {
		return nil, socketOptionErr
	}
	return &PeerCred{
		UID: credential.Uid,
		GID: credential.Gid,
		PID: credential.Pid,
	}, nil
}
