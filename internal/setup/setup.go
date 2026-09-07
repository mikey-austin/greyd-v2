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

// Package setup fetches, parses and ships blacklists to a running greyd
// (main_greyd_setup.c).
package setup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/blacklist"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/logger"
	"github.com/mikey-austin/greyd-v2/internal/settings"
	"github.com/mikey-austin/greyd-v2/internal/spamdlist"
)

const (
	// DefaultMessage is the rejection message of a blacklist without one.
	DefaultMessage = "You have been blacklisted..."
	// FirewallSet is the firewall set replaced in blacklist-only mode.
	FirewallSet = "greyd-blacklist"
	// DefaultConfigPort is greyd's configuration port (GREYD_CFG_PORT).
	DefaultConfigPort = 8026
)

// Options controls a run.
type Options struct {
	// Dryrun parses the lists but ships nothing.
	Dryrun bool
	// Debug prints per-list entry counts through Debugf.
	Debug bool
	// GreyOnly skips the firewall; false corresponds to the -b flag.
	GreyOnly bool
	// Debugf receives debug output; defaults to stderr.
	Debugf func(format string, a ...any)
	// Log receives warnings; nil discards them.
	Log *slog.Logger
}

// Dialer opens a configuration connection to greyd.
type Dialer func() (net.Conn, error)

// Run processes the lists named in setup.lists in order. A blacklist
// starts a new list (flushing the previous one), a whitelist following a
// blacklist subtracts its entries from it. Each finished blacklist is
// collapsed and sent over a fresh connection from dial; when GreyOnly is
// false every CIDR is also loaded into the greyd-blacklist firewall set
// once the final list has been processed.
func Run(ctx context.Context, s *settings.Settings, o Options, fw core.Firewall, dial Dialer) error {
	log := logger.Or(o.Log)
	if o.Debugf == nil {
		o.Debugf = func(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }
	}

	lists := s.Setup.Lists
	if len(lists) == 0 {
		return errors.New("no lists configured")
	}

	r := &runner{ctx: ctx, o: o, fw: fw, dial: dial, log: log}
	var current *blacklist.Blacklist

	for _, name := range lists {
		var (
			section *config.Section
			bltype  blacklist.Type
		)
		if section = s.Blacklists[name]; section != nil {
			if current != nil && !o.Dryrun {
				if err := r.send(current, false); err != nil {
					return err
				}
			}
			current = blacklist.New(name, section.Str("message", DefaultMessage), blacklist.StorageList)
			bltype = blacklist.TypeBlack
		} else if section = s.Whitelists[name]; section != nil && current != nil {
			bltype = blacklist.TypeWhite
		} else {
			continue
		}

		src, err := Open(r.ctx, section, s.Setup)
		if err != nil {
			log.Warn("ignoring list", "list", name, "err", err)
			continue
		}

		count := current.Count
		err = spamdlist.ParseLimited(src, current, bltype, s.Setup.MaxEntries)
		_ = src.Close()
		var perr *spamdlist.Error
		if errors.As(err, &perr) {
			log.Warn("blacklist parse error", "list", name, "line", perr.Line, "col", perr.Col)
		} else if err != nil {
			log.Warn("blacklist parse error", "list", name, "err", err)
		}

		if o.Debug {
			kind := "white"
			if bltype == blacklist.TypeBlack {
				kind = "black"
			}
			o.Debugf("%slist %s %d entries\n", kind, name, (current.Count-count)/2)
		}
	}

	if current != nil && !o.Dryrun {
		return r.send(current, true)
	}
	return nil
}

// runner carries the state shared between send calls.
type runner struct {
	ctx      context.Context
	log      *slog.Logger
	o        Options
	fw       core.Firewall
	dial     Dialer
	allCidrs []string
}

// send ships one collapsed blacklist to greyd (send_blacklist). On the
// final list in blacklist-only mode the accumulated CIDRs replace the
// firewall set first.
func (r *runner) send(bl *blacklist.Blacklist, final bool) error {
	cidrs := bl.Collapse()

	if !r.o.GreyOnly {
		r.allCidrs = append(r.allCidrs, cidrs...)
		if final {
			if r.fw == nil {
				return errors.New("could not configure firewall")
			}
			n, err := r.fw.Replace(r.ctx, FirewallSet, r.allCidrs, core.IPv4)
			if err != nil {
				return fmt.Errorf("could not configure firewall: %w", err)
			}
			if r.o.Debug {
				r.o.Debugf("%d entries added to firewall\n", n)
			}
		}
	}

	conn, err := r.dial()
	if err != nil {
		return fmt.Errorf("could not connect to greyd-config: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := ipc.WriteBlacklist(conn, bl.Name, bl.Message, cidrs); err != nil {
		return fmt.Errorf("could not write to greyd-config: %w", err)
	}
	return nil
}

// dialTimeout bounds connecting to greyd.
const dialTimeout = 10 * time.Second

// DialReserved connects to greyd's configuration port on the loopback
// interface from a privileged source port, which greyd requires of
// configuration clients (rresvport). Ports 1023 down to 512 are tried.
func DialReserved(port int) (net.Conn, error) {
	remote := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	var lastErr error
	for p := 1023; p >= 512; p-- {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}, Timeout: dialTimeout}
		conn, err := d.DialContext(context.Background(), "tcp", remote)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if isBindError(err) {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("could not bind privileged source port: %w", lastErr)
}

// isBindError reports whether dialling failed while binding the local
// address (not permitted, or already in use) rather than while connecting,
// in which case the next reserved port is worth trying.
func isBindError(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL)
}

// DialUnix connects to greyd's configuration socket when config_socket is
// set; greyd checks the peer credentials instead of the source port.
func DialUnix(path string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(context.Background(), "unix", path)
}

// DialAny connects to greyd's configuration port on the loopback
// interface from any source port. It is for tests and for daemons started
// without the privilege to bind reserved ports.
func DialAny(port int) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
}
