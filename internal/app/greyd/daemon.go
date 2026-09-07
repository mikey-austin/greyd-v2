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
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/blacklist"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/privs"
	"github.com/mikey-austin/greyd-v2/internal/settings"
	"github.com/mikey-austin/greyd-v2/internal/smtp"
)

// mainFiles are the parent's pipe ends.
type mainFiles struct {
	greyOut *os.File // -> grey child
	fwOut   *os.File // -> fw child (nat requests)
	natIn   *os.File // <- fw child (nat answers)
	trapIn  *os.File // <- grey child (traplist)
}

func (f mainFiles) closeAll() {
	for _, x := range []*os.File{f.greyOut, f.fwOut, f.natIn, f.trapIn} {
		if x != nil {
			_ = x.Close()
		}
	}
}

// children is what a child starter returns: the parent's pipe ends plus a
// function that terminates the children and waits for them.
type children struct {
	files mainFiles
	// exited is closed when a child exits unexpectedly.
	exited <-chan struct{}
	stop   func()
	// reload forwards a SIGHUP (log reopen) to the children; may be nil.
	reload func()
}

// childStarter launches the firewall and greylister roles; spawnChildren
// re-executes the binary, tests run them in-process.
type childStarter func(ctx context.Context, s *settings.Settings, log *slog.Logger) (*children, error)

// daemon is the main process state (struct Greyd_state).
type daemon struct {
	s        *settings.Settings
	opts     Options
	log      *slog.Logger
	maxFiles int
	maxCons  int
	maxBlack int
	greylist bool

	mainLn  net.Listener
	main6Ln net.Listener
	cfgLn   net.Listener
	// cfgUnix is set when the configuration listener is a unix socket.
	cfgUnix bool

	blMu   sync.Mutex
	blMap  map[string]*blacklist.Blacklist
	blList []*blacklist.Blacklist

	proxies  *blacklist.Blacklist
	counters *smtp.Counters

	natMu     sync.Mutex
	natReader *ipc.Reader

	files   mainFiles
	pidfile *privs.Pidfile
	chroot  string

	started time.Time
	scan    scanStats
	// reload is called on SIGHUP after the parent reopened its own log.
	reload func()
}

// newDaemon validates the configuration and computes the connection
// limits (the first part of main()).
func newDaemon(s *settings.Settings, o Options, maxFiles int, log *slog.Logger) (*daemon, error) {
	d := &daemon{s: s, opts: o, log: log, maxFiles: maxFiles, blMap: make(map[string]*blacklist.Blacklist), started: time.Now()}

	d.maxCons = min(s.MaxCons, maxFiles)
	d.maxBlack = min(s.MaxConsBlack, maxFiles)
	d.greylist = s.Grey.Enable

	if s.ProxyProtocolEnable {
		log.Info("proxy protocol enabled")
		d.proxies = permittedProxies(s.ProxyProtocolPermittedProxies, log)
	}

	if !d.greylist {
		d.maxBlack = d.maxCons
	} else if d.maxBlack > d.maxCons {
		return nil, fmt.Errorf("max black cons (%d) must not exceed total max cons (%d)\n%s", d.maxBlack, d.maxCons, Usage)
	}

	if s.SetRlimit {
		if err := privs.SetMaxFiles(d.maxCons + 15); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// permittedProxies builds the allow list of upstream proxies
// (Greyd_set_proxy_protocol_permitted_proxies).
func permittedProxies(cidrs []string, log *slog.Logger) *blacklist.Blacklist {
	bl := blacklist.New("permitted-proxies", "permitted upstream proxies", blacklist.StorageList)
	if len(cidrs) == 0 {
		log.Warn("no permitted proxies configured, refusing to serve requests")
		return bl
	}
	for _, c := range cidrs {
		if err := bl.Add(c); err != nil {
			log.Warn("ignoring invalid permitted proxy", "proxy", c, "err", err)
			continue
		}
		log.Info("allowing upstream proxy", "proxy", c)
	}
	return bl
}

// snapshotBlacklists returns the current blacklists in configuration
// order.
func (d *daemon) snapshotBlacklists() []*blacklist.Blacklist {
	d.blMu.Lock()
	defer d.blMu.Unlock()
	out := make([]*blacklist.Blacklist, len(d.blList))
	copy(out, d.blList)
	return out
}

// installBlacklist replaces any existing blacklist of the same name and
// otherwise appends (Greyd_process_config).
func (d *daemon) installBlacklist(m *ipc.BlacklistMessage) {
	bl := blacklist.New(m.Name, m.Message, blacklist.StorageTrie)
	for _, a := range m.IPs {
		if err := bl.Add(a); err != nil {
			d.log.Debug("ignoring blacklist entry", "blacklist", m.Name, "entry", a, "err", err)
		}
	}

	d.blMu.Lock()
	defer d.blMu.Unlock()
	if old, ok := d.blMap[m.Name]; ok {
		for i, b := range d.blList {
			if b == old {
				d.blList[i] = bl
				break
			}
		}
	} else {
		d.blList = append(d.blList, bl)
	}
	d.blMap[m.Name] = bl
	d.log.Debug("loaded blacklist", "blacklist", m.Name, "entries", bl.Count)
}
