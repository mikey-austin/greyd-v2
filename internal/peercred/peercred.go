/*
 * Copyright (c) 2014-2026 Mikey Austin <mikey@greyd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// Package peercred identifies the process at the other end of a unix
// domain socket.
package peercred

import (
	"errors"
	"net"
)

// Creds are the peer's effective credentials.
type Creds struct {
	UID int
	GID int
	PID int // 0 when the platform does not report it
}

// ErrUnsupported is returned where the platform offers no peer
// credentials; callers must then rely on socket file permissions.
var ErrUnsupported = errors.New("peer credentials not supported")

// Get returns the credentials of the peer of a unix socket connection.
func Get(conn *net.UnixConn) (Creds, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Creds{}, err
	}
	var c Creds
	var gerr error
	if err := raw.Control(func(fd uintptr) { c, gerr = get(int(fd)) }); err != nil {
		return Creds{}, err
	}
	return c, gerr
}
