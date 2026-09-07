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

// Package activation receives listening sockets from a service manager
// following the systemd socket activation protocol (LISTEN_PID,
// LISTEN_FDS and LISTEN_FDNAMES; descriptors start at 3).
package activation

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Listener is one activated socket.
type Listener struct {
	// Name is the FileDescriptorName= of the socket unit ("" when unset).
	Name string
	net.Listener
}

const firstFD = 3

// Listeners returns the activated sockets addressed to this process and
// clears the environment so children do not inherit the protocol. The
// descriptors are marked close-on-exec. It returns nil, nil when the
// process was not socket activated.
func Listeners() ([]Listener, error) {
	defer func() {
		for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
			_ = os.Unsetenv(k)
		}
	}()
	pidStr, fdsStr := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	if pidStr == "" || fdsStr == "" {
		return nil, nil
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid != os.Getpid() {
		return nil, nil
	}
	n, err := strconv.Atoi(fdsStr)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("invalid LISTEN_FDS %q", fdsStr)
	}
	var names []string
	if s := os.Getenv("LISTEN_FDNAMES"); s != "" {
		names = strings.Split(s, ":")
	}
	out := make([]Listener, 0, n)
	for i := 0; i < n; i++ {
		fd := firstFD + i
		syscall.CloseOnExec(fd)
		name := ""
		if i < len(names) {
			name = names[i]
		}
		f := os.NewFile(uintptr(fd), name)
		ln, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			for _, l := range out {
				_ = l.Close()
			}
			return nil, fmt.Errorf("activated descriptor %d (%q): %w", fd, name, err)
		}
		out = append(out, Listener{Name: name, Listener: ln})
	}
	return out, nil
}
