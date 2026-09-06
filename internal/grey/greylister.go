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

// Package grey implements the greylisting engine (grey.c): it consumes
// greylist tuples and white/trap updates from the main process (and from
// synchronisation), maintains the database, and periodically expires
// entries, whitelists retried tuples, and pushes the whitelist to the
// firewall and the traplist to the main process.
package grey

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

// Defaults from grey.h / grey.c / constants.h.
const (
	TrapName     = "greyd-greytrap"
	TrapMsg      = "Your address %A has mailed to spamtraps here"
	WhiteName    = "greyd-whitelist"
	WhiteNameV6  = "greyd-whitelist-ipv6"
	PassTime     = 60 * 25
	GreyExp      = 60 * 60 * 4
	WhiteExp     = 60 * 60 * 24 * 36
	TrapExp      = 60 * 60 * 24
	ScanInterval = 60 * time.Second
	DBUser       = "greydb"
	// LowPrioGrace is how long after start-up the low priority MX trap is
	// suppressed.
	LowPrioGrace = 60 * time.Second
)

// ErrUnknownType is returned for a message with an unknown type.
var ErrUnknownType = errors.New("unknown message type")

// Syncer announces database changes to other hosts.
type Syncer interface {
	Update(t core.Tuple, now time.Time)
	White(ip string, now, expire time.Time, del bool)
	Trapped(ip string, now, expire time.Time, del bool)
}

// Options configure a Greylister.
type Options struct {
	Config *config.Config
	Store  core.Store
	// Syncer may be nil.
	Syncer Syncer
	// SPF may be nil (SPF disabled).
	SPF core.SPFChecker
	// TrapOut receives the traplist blacklist configuration (main process).
	TrapOut io.Writer
	// FwOut receives whitelist replace requests (firewall process).
	FwOut io.Writer
	// Startup is when the daemon started (for the low priority MX rule).
	Startup time.Time
	// Now is overridable for tests.
	Now func() time.Time
}

// Greylister holds the greylisting engine state.
type Greylister struct {
	cfg     *config.Config
	store   core.Store
	syncer  Syncer
	spf     core.SPFChecker
	trapOut io.Writer
	fwOut   io.Writer
	startup time.Time
	nowFn   func() time.Time

	TraplistName    string
	TraplistMsg     string
	WhitelistName   string
	WhitelistNameV6 string
	LowPrioMX       string
	GreyExp         int64
	WhiteExp        int64
	TrapExp         int64
	PassTime        int64
	Domains         []string
}

// New creates the engine from the grey configuration section (Grey_setup).
func New(o Options) (*Greylister, error) {
	if o.Config == nil || o.Store == nil {
		return nil, errors.New("grey: config and store are required")
	}
	cfg := o.Config
	g := &Greylister{
		cfg: cfg, store: o.Store, syncer: o.Syncer, spf: o.SPF,
		trapOut: o.TrapOut, fwOut: o.FwOut, startup: o.Startup, nowFn: o.Now,
		TraplistName:    cfg.Str("traplist_name", "grey", TrapName),
		TraplistMsg:     cfg.Str("traplist_message", "grey", TrapMsg),
		WhitelistName:   cfg.Str("whitelist_name", "grey", WhiteName),
		WhitelistNameV6: cfg.Str("whitelist_name_ipv6", "grey", WhiteNameV6),
		GreyExp:         int64(cfg.Int("grey_expiry", "grey", GreyExp)),
		WhiteExp:        int64(cfg.Int("white_expiry", "grey", WhiteExp)),
		TrapExp:         int64(cfg.Int("trap_expiry", "grey", TrapExp)),
		PassTime:        int64(cfg.Int("pass_time", "grey", PassTime)),
	}
	if g.nowFn == nil {
		g.nowFn = time.Now
	}
	if g.startup.IsZero() {
		g.startup = g.nowFn()
	}
	// The C code read low_prio_mx from the default section while -M wrote
	// it to the grey section; accept both, grey section first.
	g.LowPrioMX = cfg.Str("low_prio_mx", "grey", cfg.Str("low_prio_mx", "", ""))

	if path := cfg.Str("permitted_domains", "grey", ""); path != "" {
		domains, err := LoadDomains(path)
		if err != nil {
			logger.Warning("failed to load domains from %s: %v", path, err)
		} else {
			g.Domains = domains
		}
	}
	return g, nil
}

func (g *Greylister) now() time.Time { return g.nowFn() }

// ProcessMessage handles one message from the main process or the sync
// receiver (process_message).
func (g *Greylister) ProcessMessage(m *config.Config) error {
	sec := m.Section(config.DefaultSection)
	typ := m.Int("type", "", -1)
	dstIP := m.Str("dst_ip", "", "")
	// Messages relayed from other greyd hosts carry sync = 0 so they are
	// not re-broadcast.
	syncOut := m.Int("sync", "", 1) != 0

	switch typ {
	case ipc.MsgGrey:
		if sec == nil || sec.Get("ip") == nil || sec.Get("helo") == nil || sec.Get("from") == nil || sec.Get("to") == nil {
			return nil
		}
		gt := core.Tuple{
			IP:   sec.Str("ip", ""),
			Helo: sec.Str("helo", ""),
			From: sec.Str("from", ""),
			To:   sec.Str("to", ""),
		}
		return g.processGrey(gt, syncOut, dstIP)

	case ipc.MsgTrap, ipc.MsgWhite:
		if sec == nil || sec.Get("ip") == nil || sec.Get("source") == nil || sec.Get("expires") == nil {
			return nil
		}
		return g.processNonGrey(typ == ipc.MsgTrap, sec.Str("ip", ""), sec.Str("source", ""),
			sec.Str("expires", ""), syncOut, m.Int("delete", "", 0) != 0)

	default:
		return ErrUnknownType
	}
}

// trapCheck reports whether the recipient is a trap: 0 trap, 1 no trap,
// -1 error (trap_check).
func (g *Greylister) trapCheck(to string) (int, error) {
	match, checkDomains := false, false
	if len(g.Domains) > 0 {
		checkDomains = true
		for _, d := range g.Domains {
			if domainMatches(d, to) {
				match = true
			}
		}
	}
	if !match && g.cfg.Bool("db_permitted_domains", "grey", false) {
		checkDomains = true
		_, found, err := g.store.Get(core.DomainPartKey(to))
		if err != nil {
			return -1, err
		}
		if found {
			match = true
		}
	}
	if checkDomains && !match {
		return 0, nil
	}

	_, found, err := g.store.Get(core.MailKey(to))
	if err != nil {
		return -1, err
	}
	if found {
		return 0, nil
	}
	return 1, nil
}

func (g *Greylister) rollback(err error) error {
	_ = g.store.Rollback()
	return err
}

// processGrey handles a greylist tuple (process_grey).
func (g *Greylister) processGrey(gt core.Tuple, syncOut bool, dstIP string) error {
	now := g.now()

	var (
		spamtrap bool
		expire   int64
		key      core.Key
	)
	switch tc, err := g.trapCheck(gt.To); {
	case err != nil:
		return err
	case tc == 1:
		expire = g.GreyExp
		key = core.TupleKey(gt)
	default:
		spamtrap = true
		expire = g.TrapExp
		key = core.IPKey(gt.IP)
	}

	if g.spf != nil && syncOut && !spamtrap && g.cfg.Bool("enable", "spf", true) {
		res, err := g.spf.Check(gt.IP, gt.Helo, gt.From)
		switch res {
		case core.SPFPass:
			logger.Info("SPF passed for %s %s helo %s", gt.IP, gt.From, gt.Helo)
			if g.cfg.Bool("whitelist_on_pass", "spf", false) {
				d := core.Data{First: now.Unix(), Pass: now.Unix(), Expire: now.Unix() + g.WhiteExp}
				if err := g.store.Put(core.IPKey(gt.IP), d); err != nil {
					return err
				}
				logger.Debug("whitelisting %s", gt.IP)
				return nil
			}
		case core.SPFSoftFail:
			if !g.cfg.Bool("trap_on_softfail", "spf", true) {
				break
			}
			fallthrough
		case core.SPFFail:
			logger.Warning("SPF failure for %s %s helo %s", gt.IP, gt.From, gt.Helo)
			spamtrap = true
			expire = g.TrapExp
			key = core.IPKey(gt.IP)
		case core.SPFError:
			logger.Warning("SPF error for %s %s helo %s: %v", gt.IP, gt.From, gt.Helo, err)
		}
	}

	if err := g.store.Begin(); err != nil {
		return err
	}
	d, found, err := g.store.Get(key)
	if err != nil {
		return g.rollback(err)
	}
	if !found {
		// We have a new entry.
		if syncOut && g.LowPrioMX != "" && dstIP == g.LowPrioMX && g.startup.Add(LowPrioGrace).Before(now) {
			// No greylist entry for this tuple, yet the connection was to
			// a low priority MX which cannot be hit first by an RFC
			// conformant client.
			spamtrap = true
			expire = g.TrapExp
			key = core.IPKey(gt.IP)
			logger.Debug("trapping %s for trying %s first for tuple (%s, %s, %s, %s)",
				gt.IP, g.LowPrioMX, gt.IP, gt.Helo, gt.From, gt.To)
		}
		// Making the pass time and expire time the same is significant: a
		// grey entry is not whitelisted unless the same tuple is retried.
		d = core.Data{
			First:  now.Unix(),
			Pass:   now.Unix() + expire,
			Expire: now.Unix() + expire,
			BCount: 1,
			PCount: 0,
		}
		if spamtrap {
			d.PCount = core.PCountTrapped
		}
		if err := g.store.Put(key, d); err != nil {
			return g.rollback(err)
		}
		if syncOut {
			logger.Debug("new %sentry %s from %s to %s, helo %s", trapWord(spamtrap), gt.IP, gt.From, gt.To, gt.Helo)
		}
	} else {
		// We have a previously seen entry.
		d.BCount++
		d.PCount = 0
		if spamtrap {
			d.PCount = core.PCountTrapped
		}
		if d.First+g.PassTime < now.Unix() {
			d.Pass = now.Unix()
		}
		if err := g.store.Put(key, d); err != nil {
			return g.rollback(err)
		}
		if syncOut {
			logger.Debug("updated %sentry %s from %s to %s, helo %s", trapWord(spamtrap), gt.IP, gt.From, gt.To, gt.Helo)
		}
	}

	if g.syncer != nil && syncOut {
		if spamtrap {
			g.syncer.Trapped(gt.IP, now, now.Add(time.Duration(expire)*time.Second), false)
		} else {
			g.syncer.Update(gt, now)
		}
	}
	return g.store.Commit()
}

func trapWord(spamtrap bool) string {
	if spamtrap {
		return "greytrap "
	}
	return ""
}

// processNonGrey handles white and trapped additions/deletions
// (process_non_grey).
func (g *Greylister) processNonGrey(spamtrap bool, ip, source, expires string, syncOut, del bool) error {
	now := g.now()
	expire, err := strconv.ParseInt(expires, 10, 64)
	if !del && (err != nil || expire == 0) {
		logger.Warning("could not parse expires %s", expires)
		return nil
	}

	key := core.IPKey(ip)
	if err := g.store.Begin(); err != nil {
		return err
	}
	d, found, err := g.store.Get(key)
	if err != nil {
		return g.rollback(err)
	}
	kind := "WHITE"
	if spamtrap {
		kind = "TRAP"
	}
	switch {
	case !found && del:
		// Nothing to delete.
	case !found:
		d = core.Data{First: now.Unix(), Pass: now.Unix(), Expire: expire}
		if spamtrap {
			d.PCount = core.PCountTrapped
			d.Pass = expire
		}
		if err := g.store.Put(key, d); err != nil {
			return g.rollback(err)
		}
		if syncOut {
			logger.Debug("new %s from %s for %s, expires %s", kind, source, ip, expires)
		}
	case del:
		if _, err := g.store.Del(key); err != nil {
			return g.rollback(err)
		}
		if syncOut {
			logger.Debug("deleted %s", ip)
		}
	default:
		if spamtrap {
			d.PCount = core.PCountTrapped
			d.BCount++
		} else {
			d.PCount++
		}
		if err := g.store.Put(key, d); err != nil {
			return g.rollback(err)
		}
		if syncOut {
			logger.Debug("updated %s", ip)
		}
	}
	return g.store.Commit()
}

// ScanOnce expires entries and whitelists retried tuples, then sends the
// traplist to the main process and the whitelists to the firewall process
// (Grey_scan_db).
func (g *Greylister) ScanOnce() error {
	now := g.now()
	if err := g.store.Begin(); err != nil {
		return err
	}
	res, err := g.store.Scan(now.Unix(), g.WhiteExp)
	if err != nil {
		return g.rollback(fmt.Errorf("db scan failed: %w", err))
	}
	if err := g.store.Commit(); err != nil {
		return err
	}

	if g.trapOut != nil {
		if err := ipc.WriteBlacklist(g.trapOut, g.TraplistName, g.TraplistMsg, res.Traplist); err != nil {
			logger.Debug("configure_greyd: write failed: %v", err)
		}
	}
	g.updateFirewall(core.IPv4, res.Whitelist)
	if g.cfg.Bool("enable_ipv6", "", false) {
		g.updateFirewall(core.IPv6, res.WhitelistV6)
	}
	return nil
}

func (g *Greylister) updateFirewall(af core.Family, ips []string) {
	if g.fwOut == nil || len(ips) == 0 {
		return
	}
	name := g.WhitelistName
	if af == core.IPv6 {
		name = g.WhitelistNameV6
	}
	if err := ipc.WriteReplace(g.fwOut, name, int(af), ips); err != nil {
		logger.Debug("update firewall: write failed: %v", err)
	}
}
