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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/logger"
	"github.com/mikey-austin/greyd-v2/internal/settings"
	"github.com/mikey-austin/greyd-v2/internal/stats"
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
	Settings *settings.Settings
	Store    core.Store
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
	// Log receives engine events; nil discards them.
	Log *slog.Logger
}

// Greylister holds the greylisting engine state.
type Greylister struct {
	cfg     settings.Grey
	spfCfg  settings.SPF
	ipv6    bool
	store   core.Store
	syncer  Syncer
	spf     core.SPFChecker
	trapOut io.Writer
	fwOut   io.Writer
	startup time.Time
	nowFn   func() time.Time
	log     *slog.Logger

	// Domains are the permitted domain suffixes loaded from the file.
	Domains []string
}

// New creates the engine from the grey settings (Grey_setup).
func New(o Options) (*Greylister, error) {
	if o.Settings == nil || o.Store == nil {
		return nil, errors.New("grey: settings and store are required")
	}
	g := &Greylister{
		cfg: o.Settings.Grey, spfCfg: o.Settings.SPF, ipv6: o.Settings.EnableIPv6,
		store: o.Store, syncer: o.Syncer, spf: o.SPF,
		trapOut: o.TrapOut, fwOut: o.FwOut, startup: o.Startup, nowFn: o.Now,
		log: logger.Or(o.Log),
	}
	if g.nowFn == nil {
		g.nowFn = time.Now
	}
	if g.startup.IsZero() {
		g.startup = g.nowFn()
	}
	if path := g.cfg.PermittedDomains; path != "" {
		domains, err := LoadDomains(path, g.cfg.MaxDomains)
		if err != nil {
			g.log.Warn("failed to load permitted domains", "path", path, "err", err)
		} else {
			g.Domains = domains
		}
	}
	return g, nil
}

// Config returns the grey settings in effect (tests).
func (g *Greylister) Config() settings.Grey { return g.cfg }

func (g *Greylister) now() time.Time { return g.nowFn() }

// ProcessMessage handles one message from the main process or the sync
// receiver (process_message).
func (g *Greylister) ProcessMessage(ctx context.Context, m ipc.Message) error {
	switch v := m.(type) {
	case *ipc.GreyMessage:
		return g.processGrey(ctx, v.Tuple, v.Sync, v.DstIP)
	case *ipc.AddrMessage:
		return g.processNonGrey(ctx, v.Type == ipc.MsgTrap, v.IP, v.Source, v.Expires, v.Sync, v.Delete)
	default:
		return ErrUnknownType
	}
}

// trapCheck reports whether the recipient is a trap: 0 trap, 1 no trap
// (trap_check).
func (g *Greylister) trapCheck(tx core.ReadTx, to string) (int, error) {
	match, checkDomains := false, false
	if len(g.Domains) > 0 {
		checkDomains = true
		for _, d := range g.Domains {
			if domainMatches(d, to) {
				match = true
			}
		}
	}
	if !match && g.cfg.DBPermittedDomains {
		checkDomains = true
		_, found, err := tx.Get(core.DomainPartKey(to))
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

	_, found, err := tx.Get(core.MailKey(to))
	if err != nil {
		return -1, err
	}
	if found {
		return 0, nil
	}
	return 1, nil
}

// processGrey handles a greylist tuple (process_grey).
func (g *Greylister) processGrey(ctx context.Context, gt core.Tuple, syncOut bool, dstIP string) error {
	now := g.now()
	log := g.log.With("ip", gt.IP, "from", gt.From, "to", gt.To, "helo", gt.Helo)

	var (
		spamtrap bool
		expire   int64
		key      core.Key
	)
	var tc int
	if err := g.store.View(ctx, func(tx core.ReadTx) error {
		var err error
		tc, err = g.trapCheck(tx, gt.To)
		return err
	}); err != nil {
		return err
	}
	if tc == 1 {
		expire = g.cfg.GreyExpiry
		key = core.TupleKey(gt)
	} else {
		spamtrap = true
		expire = g.cfg.TrapExpiry
		key = core.IPKey(gt.IP)
	}

	// SPF is evaluated outside the database transaction: it performs DNS
	// lookups and must not hold a write lock meanwhile.
	if g.spf != nil && syncOut && !spamtrap && g.spfCfg.Enable {
		res, err := g.spf.Check(gt.IP, gt.Helo, gt.From)
		switch res {
		case core.SPFPass:
			log.Info("SPF passed")
			if g.spfCfg.WhitelistOnPass {
				d := core.Data{First: now.Unix(), Pass: now.Unix(), Expire: now.Unix() + g.cfg.WhiteExpiry}
				if err := core.Put(ctx, g.store, core.IPKey(gt.IP), d); err != nil {
					return err
				}
				log.Debug("whitelisting after SPF pass")
				return nil
			}
		case core.SPFSoftFail:
			if !g.spfCfg.TrapOnSoftfail {
				break
			}
			fallthrough
		case core.SPFFail:
			log.Warn("SPF failure")
			spamtrap = true
			expire = g.cfg.TrapExpiry
			key = core.IPKey(gt.IP)
		case core.SPFError:
			log.Warn("SPF error", "err", err)
		}
	}

	err := g.store.Update(ctx, func(tx core.Tx) error {
		d, found, err := tx.Get(key)
		if err != nil {
			return err
		}
		if !found {
			// We have a new entry.
			if syncOut && g.cfg.LowPrioMX != "" && dstIP == g.cfg.LowPrioMX && g.startup.Add(LowPrioGrace).Before(now) {
				// No greylist entry for this tuple, yet the connection was
				// to a low priority MX which cannot be hit first by an RFC
				// conformant client.
				spamtrap = true
				expire = g.cfg.TrapExpiry
				key = core.IPKey(gt.IP)
				log.Debug("trapping for trying the low priority MX first", "mx", g.cfg.LowPrioMX)
			}
			// Making the pass time and expire time the same is significant:
			// a grey entry is not whitelisted unless the same tuple is
			// retried.
			d = core.Data{
				First:  now.Unix(),
				Pass:   now.Unix() + expire,
				Expire: now.Unix() + expire,
				BCount: 1,
			}
			if spamtrap {
				d.PCount = core.PCountTrapped
			}
			if err := tx.Put(key, d); err != nil {
				return err
			}
			if syncOut {
				log.Debug("new entry", "greytrap", spamtrap)
			}
			return nil
		}

		// We have a previously seen entry.
		d.BCount++
		d.PCount = 0
		if spamtrap {
			d.PCount = core.PCountTrapped
		}
		if d.First+g.cfg.PassTime < now.Unix() {
			d.Pass = now.Unix()
		}
		if err := tx.Put(key, d); err != nil {
			return err
		}
		if syncOut {
			log.Debug("updated entry", "greytrap", spamtrap)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if g.syncer != nil && syncOut {
		if spamtrap {
			g.syncer.Trapped(gt.IP, now, now.Add(time.Duration(expire)*time.Second), false)
		} else {
			g.syncer.Update(gt, now)
		}
	}
	return nil
}

// processNonGrey handles white and trapped additions/deletions
// (process_non_grey).
func (g *Greylister) processNonGrey(ctx context.Context, spamtrap bool, ip, source, expires string, syncOut, del bool) error {
	now := g.now()
	expire, err := strconv.ParseInt(expires, 10, 64)
	if !del && (err != nil || expire == 0) {
		g.log.Warn("could not parse expires", "expires", expires, "ip", ip)
		return nil
	}
	kind := "WHITE"
	if spamtrap {
		kind = "TRAP"
	}
	log := g.log.With("ip", ip, "source", source, "kind", kind)

	key := core.IPKey(ip)
	return g.store.Update(ctx, func(tx core.Tx) error {
		d, found, err := tx.Get(key)
		if err != nil {
			return err
		}
		switch {
		case !found && del:
			// Nothing to delete.
			return nil
		case !found:
			d = core.Data{First: now.Unix(), Pass: now.Unix(), Expire: expire}
			if spamtrap {
				d.PCount = core.PCountTrapped
				d.Pass = expire
			}
			if err := tx.Put(key, d); err != nil {
				return err
			}
			if syncOut {
				log.Debug("new entry", "expires", expires)
			}
		case del:
			if _, err := tx.Del(key); err != nil {
				return err
			}
			if syncOut {
				log.Debug("deleted entry")
			}
		default:
			if spamtrap {
				d.PCount = core.PCountTrapped
				d.BCount++
			} else {
				d.PCount++
			}
			if err := tx.Put(key, d); err != nil {
				return err
			}
			if syncOut {
				log.Debug("updated entry")
			}
		}
		return nil
	})
}

// ScanOnce expires entries and whitelists retried tuples, then sends the
// traplist to the main process and the whitelists to the firewall process
// (Grey_scan_db).
func (g *Greylister) ScanOnce(ctx context.Context) error {
	now := g.now()
	var res core.ScanResult
	if err := g.store.Update(ctx, func(tx core.Tx) error {
		var err error
		res, err = tx.Scan(now.Unix(), g.cfg.WhiteExpiry)
		return err
	}); err != nil {
		return fmt.Errorf("db scan failed: %w", err)
	}

	if g.trapOut != nil {
		if err := ipc.WriteBlacklist(g.trapOut, g.cfg.TraplistName, g.cfg.TraplistMessage, res.Traplist); err != nil {
			g.log.Debug("could not send traplist", "err", err)
		}
		g.reportCounts(ctx, now)
	}
	g.updateFirewall(core.IPv4, res.Whitelist)
	if g.ipv6 {
		g.updateFirewall(core.IPv6, res.WhitelistV6)
	}
	return nil
}

// reportCounts sends the entry counts to the main process for greyd
// --stats and greyd-monitor.
func (g *Greylister) reportCounts(ctx context.Context, now time.Time) {
	c, err := stats.Summarize(ctx, g.store)
	if err != nil {
		g.log.Debug("could not count database entries", "err", err)
		return
	}
	m := ipc.ScanStats{At: now.Unix(), Grey: c.Grey, White: c.White, Trapped: c.Trapped, Spamtrap: c.Spamtrap, Domain: c.Domain}
	if err := ipc.WriteScanStats(g.trapOut, m); err != nil {
		g.log.Debug("could not send scan statistics", "err", err)
	}
}

func (g *Greylister) updateFirewall(af core.Family, ips []string) {
	if g.fwOut == nil || len(ips) == 0 {
		return
	}
	name := g.cfg.WhitelistName
	if af == core.IPv6 {
		name = g.cfg.WhitelistNameIPv6
	}
	if err := ipc.WriteReplace(g.fwOut, name, int(af), ips); err != nil {
		g.log.Debug("could not send whitelist", "set", name, "err", err)
	}
}
