//go:build openbsd

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

package sandbox

import (
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/unix"
)

// apply pledges the process. The promises are deliberately generous:
// the runtime needs stdio, every role talks over sockets, and the
// greylister reads and writes database files and resolves names.
func apply(p Profile, log *slog.Logger) error {
	var promises []string
	switch p.Role {
	case RoleMain:
		promises = []string{"stdio", "inet", "unix", "proc", "rpath", "cpath"}
	case RoleFirewall:
		promises = []string{"stdio", "rpath", "wpath", "inet", "unix"}
		if p.Devices {
			promises = append(promises, "pf")
		}
		if p.Exec {
			promises = append(promises, "proc", "exec")
		}
	default:
		promises = []string{"stdio", "rpath", "wpath", "cpath", "flock", "inet", "dns", "unix"}
	}
	set := strings.Join(promises, " ")
	if err := unix.PledgePromises(set); err != nil {
		return fmt.Errorf("pledge %q: %w", set, err)
	}
	log.Debug("sandbox applied", "role", p.Role.String(), "pledge", set)
	return nil
}

// Confined always reports false: pledge state is not queryable.
func Confined() bool { return false }
