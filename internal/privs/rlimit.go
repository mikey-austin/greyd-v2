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
	"fmt"

	"golang.org/x/sys/unix"
)

// MaxFilesThreshold is the number of descriptors kept in reserve
// (MAX_FILES_THRESHOLD).
const MaxFilesThreshold = 200

// DefaultMaxCons is the default maximum number of connections
// (CON_DEFAULT_MAX).
const DefaultMaxCons = 800

// MaxFiles returns the number of connections the process may handle: the
// hard descriptor limit less a reserve. It errors when fewer than 10 remain.
func MaxFiles() (int, error) {
	var lim unix.Rlimit
	max := DefaultMaxCons
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err == nil && lim.Max != unix.RLIM_INFINITY {
		if lim.Max > 1<<30 || lim.Max < 0 {
			max = 1 << 30
		} else {
			max = int(lim.Max)
		}
	}
	if max-MaxFilesThreshold < 10 {
		return 0, fmt.Errorf("max files is only %d, refusing to continue", max)
	}
	return max - MaxFilesThreshold, nil
}

// SetMaxFiles self-imposes a descriptor limit (setrlimit RLIMIT_NOFILE).
func SetMaxFiles(n int) error {
	lim := unix.Rlimit{Cur: rlimT(n), Max: rlimT(n)}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return fmt.Errorf("setrlimit: %w", err)
	}
	return nil
}
