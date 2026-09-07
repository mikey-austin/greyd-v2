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

// Package sandbox confines a greyd process after it has dropped
// privileges and opened everything it needs. On Linux it sets
// PR_SET_NO_NEW_PRIVS, restricts filesystem access with Landlock and
// installs a seccomp deny list; on OpenBSD it pledges. Elsewhere it is a
// no-op that reports ErrUnsupported.
package sandbox

import (
	"errors"
	"log/slog"
)

// Role selects the confinement profile.
type Role int

// The greyd process roles.
const (
	// RoleMain is the privileged parent: sockets and pipes only.
	RoleMain Role = iota
	// RoleFirewall talks to the firewall over sockets, device files or a
	// helper program.
	RoleFirewall
	// RoleGrey runs the greylister: database files and DNS.
	RoleGrey
	// RoleTool is one of the command line programs.
	RoleTool
)

func (r Role) String() string {
	switch r {
	case RoleMain:
		return "main"
	case RoleFirewall:
		return "firewall"
	case RoleGrey:
		return "grey"
	default:
		return "tool"
	}
}

// Profile describes what a process still needs after confinement.
type Profile struct {
	Role Role
	// Exec permits running helper programs (the pf driver runs pfctl).
	Exec bool
	// Devices permits ioctl on device files (the pf driver uses /dev/pf).
	Devices bool
	// ReadPaths and WritePaths are directories (or files) the process may
	// still read, respectively read and modify. Missing paths are skipped.
	ReadPaths  []string
	WritePaths []string
}

// ErrUnsupported is returned where the platform offers no confinement.
var ErrUnsupported = errors.New("sandboxing not supported on this platform")

// Apply confines the calling process; it cannot be undone. Partial
// support (for example a kernel without Landlock) is logged and the
// remaining mechanisms are still applied.
func Apply(p Profile, log *slog.Logger) error {
	return apply(p, log)
}
