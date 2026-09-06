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

// Package privs implements the security sensitive process operations:
// dropping privileges, chrooting, resource limits, pidfile locking and
// daemonizing. It ports utils.c and the relevant parts of the C mains.
package privs

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// LookupUser resolves a system user by name.
func LookupUser(name string) (*user.User, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("no such user %s", name)
	}
	return u, nil
}

// IDs returns the numeric uid and gid of a user.
func IDs(u *user.User) (uid, gid int, err error) {
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("bad uid %q for %s", u.Uid, u.Username)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("bad gid %q for %s", u.Gid, u.Username)
	}
	return uid, gid, nil
}

// Drop permanently switches the process to the supplied user: the
// supplementary groups are reduced to the user's primary group, then the
// real, effective and saved gid and uid are set. When the process was
// running as root it verifies afterwards that root cannot be regained.
func Drop(u *user.User) error {
	uid, gid, err := IDs(u)
	if err != nil {
		return err
	}
	wasRoot := os.Geteuid() == 0

	// Only root may change the supplementary groups; an unprivileged
	// process can still switch to itself (used by tests and containers).
	if wasRoot {
		if err := unix.Setgroups([]int{gid}); err != nil {
			return fmt.Errorf("setgroups: %w", err)
		}
	}
	if err := setIDs(uid, gid); err != nil {
		return err
	}

	if wasRoot && uid != 0 {
		if err := unix.Setuid(0); err == nil {
			return fmt.Errorf("privileges were not dropped: root regained")
		}
	}
	return nil
}

// Chroot changes the root directory. Time zone information is loaded first
// so that log timestamps stay correct afterwards (the C code calls tzset).
func Chroot(dir string) error {
	loc, err := time.LoadLocation("Local")
	if err == nil {
		time.Local = loc
	}
	if err := unix.Chroot(dir); err != nil {
		return fmt.Errorf("cannot chroot to %s: %w", dir, err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir after chroot: %w", err)
	}
	return nil
}
