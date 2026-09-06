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

// Package version holds build-time values injected by the Makefile through
// -ldflags. They replace the DEFAULT_CONFIG, GREYD_PIDFILE and
// GREYLOGD_PIDFILE preprocessor definitions of the C implementation.
package version

var (
	// Version is the release version of the greyd suite.
	Version = "dev"

	// DefaultConfig is the configuration file used when -f is not given.
	DefaultConfig = "/etc/greyd/greyd.conf"

	// GreydPidfile is the default greyd pidfile location.
	GreydPidfile = "/var/empty/greyd/greyd.pid"

	// GreylogdPidfile is the default greylogd pidfile location.
	GreylogdPidfile = "/var/empty/greylogd/greylogd.pid"
)
