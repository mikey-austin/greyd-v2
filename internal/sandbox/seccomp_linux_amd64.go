//go:build linux && amd64

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

import "golang.org/x/sys/unix"

// archSyscalls are legacy entry points that only exist on amd64 and that
// older code paths may still use.
var archSyscalls = []uint32{
	unix.SYS_ARCH_PRCTL, unix.SYS_POLL, unix.SYS_SELECT, unix.SYS_EPOLL_WAIT, unix.SYS_EPOLL_CREATE,
	unix.SYS_ACCESS, unix.SYS_STAT, unix.SYS_LSTAT, unix.SYS_OPEN, unix.SYS_READLINK, unix.SYS_UNLINK,
	unix.SYS_MKDIR, unix.SYS_RENAME, unix.SYS_DUP2, unix.SYS_PIPE, unix.SYS_GETDENTS, unix.SYS_TIME,
	unix.SYS_CHMOD, unix.SYS_CHOWN, unix.SYS_LCHOWN, unix.SYS_ALARM, unix.SYS_PAUSE,
}
