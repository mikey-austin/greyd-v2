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

package greyd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func reuseAddr(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return serr
}

// bind creates the listening sockets while still privileged.
func (d *daemon) bind() error {
	s := d.s
	lc := net.ListenConfig{Control: reuseAddr}

	if s.BindAddress != "" {
		if a, err := netip.ParseAddr(s.BindAddress); err != nil || !a.Is4() {
			return fmt.Errorf("inet_pton: invalid bind_address %q", s.BindAddress)
		}
	}
	ln, err := lc.Listen(context.Background(), "tcp4", net.JoinHostPort(s.BindAddress, strconv.Itoa(s.Port)))
	if err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	d.mainLn = ln

	if s.EnableIPv6 {
		if s.BindAddressIPv6 != "" {
			if a, err := netip.ParseAddr(s.BindAddressIPv6); err != nil || !a.Is6() {
				_ = ln.Close()
				return fmt.Errorf("inet_pton: invalid bind_address_ipv6 %q", s.BindAddressIPv6)
			}
		}
		ln6, err := lc.Listen(context.Background(), "tcp6", net.JoinHostPort(s.BindAddressIPv6, strconv.Itoa(s.Port)))
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("bind IPv6: %w", err)
		}
		d.main6Ln = ln6
	}

	cfgLn, err := d.bindConfig(lc)
	if err != nil {
		d.closeListeners()
		return err
	}
	d.cfgLn = cfgLn
	return nil
}

// bindConfig opens the configuration listener: a unix socket when
// config_socket is set (peer credentials restrict callers), otherwise the
// loopback TCP port of the C implementation (reserved source ports
// restrict callers).
func (d *daemon) bindConfig(lc net.ListenConfig) (net.Listener, error) {
	if path := d.s.ConfigSocket; path != "" {
		if err := removeStaleSocket(path); err != nil {
			return nil, fmt.Errorf("bind local: %w", err)
		}
		ln, err := lc.Listen(context.Background(), "unix", path)
		if err != nil {
			return nil, fmt.Errorf("bind local: %w", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("bind local: %w", err)
		}
		d.cfgUnix = true
		return ln, nil
	}
	ln, err := lc.Listen(context.Background(), "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(d.s.ConfigPort)))
	if err != nil {
		return nil, fmt.Errorf("bind local: %w", err)
	}
	return ln, nil
}

// removeStaleSocket unlinks a leftover socket file; anything else at the
// path is left alone and reported.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	return os.Remove(path)
}

func (d *daemon) closeListeners() {
	for _, l := range []net.Listener{d.mainLn, d.main6Ln, d.cfgLn} {
		if l != nil {
			_ = l.Close()
		}
	}
}

// MainAddr returns the SMTP listener address (tests).
func (d *daemon) MainAddr() net.Addr { return d.mainLn.Addr() }

// CfgAddr returns the configuration listener address (tests).
func (d *daemon) CfgAddr() net.Addr { return d.cfgLn.Addr() }
