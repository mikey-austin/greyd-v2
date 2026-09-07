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

package privs

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrAlreadyRunning is returned when another process holds the pidfile
// lock.
var ErrAlreadyRunning = errors.New("another instance is already running")

// Pidfile is a locked pidfile. The descriptor stays open for the life of
// the process so the lock is held.
type Pidfile struct {
	path string
	f    *os.File
}

// WritePidfile creates (or truncates) the pidfile, takes an exclusive
// fcntl write lock, writes the pid and chowns the file to owner (when
// non-nil). It ports write_pidfile.
func WritePidfile(path string, owner *user.User) (*Pidfile, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644) //nolint:gosec // pidfiles are read by other users
	if err != nil {
		return nil, err
	}

	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lock); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}

	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(f, "%d", os.Getpid()); err != nil {
		_ = f.Close()
		return nil, err
	}

	if owner != nil {
		uid, gid, err := IDs(owner)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Chown(uid, gid); err != nil {
			_ = f.Close()
			return nil, err
		}
	}

	return &Pidfile{path: path, f: f}, nil
}

// Path returns the pidfile path.
func (p *Pidfile) Path() string { return p.path }

// Close releases the lock and unlinks the file. When the process has since
// chrooted into chrootDir the path is made relative to the new root.
func (p *Pidfile) Close(chrootDir string) error {
	if p == nil {
		return nil
	}
	path := p.path
	if chrootDir != "" && len(path) > len(chrootDir) {
		if i := strings.Index(path, chrootDir); i >= 0 {
			path = path[i+len(chrootDir):]
		}
	}
	if p.f != nil {
		_ = p.f.Close()
		p.f = nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not unlink %s: %w", path, err)
	}
	return nil
}
