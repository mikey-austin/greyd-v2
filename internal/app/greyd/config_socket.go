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
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/peercred"
)

// cfgConnTimeout bounds reading a blacklist from a configuration
// connection.
const cfgConnTimeout = 30 * time.Second

// serveConfig accepts configuration connections one at a time.
func (d *daemon) serveConfig(ctx context.Context) error {
	for {
		conn, err := d.cfgLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
				time.Sleep(time.Second)
				continue
			}
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ECONNABORTED) {
				continue
			}
			return err
		}
		d.handleConfigConn(conn)
	}
}

// handleConfigConn reads one blacklist from an authorised peer.
func (d *daemon) handleConfigConn(conn net.Conn) {
	defer conn.Close()
	if !d.authoriseConfigPeer(conn) {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(cfgConnTimeout))
	rd := ipc.NewReader(conn)
	rd.SetMaxFrame(d.s.MaxConfigFrame)
	m, err := rd.Next()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			d.log.Warn("configuration connection failed", "err", err)
		}
		return
	}
	d.addBlacklist(m, "configuration connection")
}

// authoriseConfigPeer applies the caller check for the listener type: a
// unix socket peer must be root or the daemon's own user, a TCP peer must
// connect from a privileged source port.
func (d *daemon) authoriseConfigPeer(conn net.Conn) bool {
	if d.cfgUnix {
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			return false
		}
		c, err := peercred.Get(uc)
		if errors.Is(err, peercred.ErrUnsupported) {
			// The socket is mode 0600; ownership is the only check.
			return true
		}
		if err != nil {
			d.log.Warn("rejecting configuration connection", "err", err)
			return false
		}
		if c.UID != 0 && c.UID != os.Geteuid() {
			d.log.Warn("rejecting configuration connection from unauthorised user", "uid", c.UID, "pid", c.PID)
			return false
		}
		return true
	}
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.Port >= IPPortReserved {
		d.log.Debug("rejecting configuration connection from unprivileged port")
		return false
	}
	return true
}

// addBlacklist installs a blacklist message; other message types are
// ignored with a log entry.
func (d *daemon) addBlacklist(m ipc.Message, source string) {
	bl, ok := m.(*ipc.BlacklistMessage)
	if !ok {
		d.log.Warn("ignoring unexpected message", "source", source)
		return
	}
	d.installBlacklist(bl)
}

// readTrapPipe installs traplists sent by the greylister.
func (d *daemon) readTrapPipe(ctx context.Context) error {
	rd := ipc.NewReader(d.files.trapIn)
	for {
		m, err := rd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			d.log.Warn("trap pipe message failed", "err", err)
			continue
		}
		d.addBlacklist(m, "trap pipe")
	}
}
