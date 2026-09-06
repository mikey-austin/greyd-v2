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

// Package greydb implements the greydb command, a port of main_greydb.c.
// It lists, adds and deletes whitelist, greytrap, spamtrap and permitted
// domain entries in the greyd database.
package greydb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/cli"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ip"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/settings"
	"github.com/mikey-austin/greyd-golang/internal/sync"
	"github.com/mikey-austin/greyd-golang/internal/version"
)

const progName = "greydb"

// Entry types (TYPE_* in main_greydb.c).
const (
	typeWhite = iota
	typeTraphit
	typeSpamtrap
	typeDomain
)

// Actions (ACTION_* in main_greydb.c).
const (
	actionList = iota
	actionDel
	actionAdd
)

// nowFunc supplies the current time; tests replace it to obtain exact
// timestamps. The C implementation captures time(NULL) once per update.
var nowFunc = time.Now

// errReported marks a transaction failure whose message has already been
// written to stderr from inside the update closure.
var errReported = errors.New("greydb: failure reported")

// syncer is the subset of the sync engine used by db_update.
type syncer interface {
	White(ip string, now, expire time.Time, del bool)
	Trapped(ip string, now, expire time.Time, del bool)
}

func usage(stderr io.Writer) int {
	fmt.Fprintf(stderr, "usage: %s [-f config] [[-DTt] -a keys] [[-DTt] -d keys] \n", progName)
	return 1
}

// options holds the parsed command line.
type options struct {
	action     int
	typ        int
	configFile string
	opts       *config.Config
	syncSend   int
	keys       []string
}

// parseArgs is a small getopt(3) loop for the option string "adtTDf:Y:".
// It returns ok=false when usage should be printed.
func parseArgs(args []string) (options, bool) {
	o := options{
		action:     actionList,
		typ:        typeWhite,
		configFile: version.DefaultConfig,
		opts:       config.New(),
	}
	opts, rest, err := cli.Parse("adtTDf:Y:", args)
	if err != nil {
		return o, false
	}
	for _, opt := range opts {
		switch opt.Flag {
		case 'a':
			o.action = actionAdd
		case 'd':
			o.action = actionDel
		case 't':
			o.typ = typeTraphit
		case 'T':
			o.typ = typeSpamtrap
		case 'D':
			o.typ = typeDomain
		case 'f':
			o.configFile = opt.Arg
		case 'Y':
			o.opts.AppendListStr("hosts", "sync", opt.Arg)
			o.syncSend++
		}
	}
	o.keys = rest
	return o, true
}

// Run executes greydb with the supplied arguments (excluding the program
// name) and returns the process exit status.
func Run(args []string, stdout, stderr io.Writer) int {
	o, ok := parseArgs(args)
	if !ok {
		return usage(stderr)
	}
	if o.action == actionList && o.typ != typeWhite {
		return usage(stderr)
	}

	cfg := config.New()
	if err := cfg.LoadFile(o.configFile); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}
	cfg.Merge(o.opts)

	// Ensure syslog output is disabled and that privileges are kept.
	cfg.SetInt("syslog_enable", "", 0)
	cfg.SetInt("drop_privs", "", 0)

	s, err := settings.Load(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}

	log, h, err := logger.New(logger.Options{
		Ident:  progName,
		Debug:  s.Debug,
		Syslog: false,
		Stderr: stderr,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}
	defer h.Close()
	for _, w := range s.Warnings {
		log.Warn(w)
	}

	ctx := context.Background()
	hostname := s.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	store, err := core.OpenStore(cfg, core.StoreOptions{Hostname: hostname, Log: log})
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}
	mode := core.OpenRW
	if o.action == actionList {
		mode = core.OpenRO
	}
	if err := store.Open(ctx, mode); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}

	ret := 0
	var eng *sync.Engine
	switch o.action {
	case actionList:
		ret = dbList(ctx, store, stdout, stderr)

	case actionAdd, actionDel:
		// Ensure that the sync bind address is not set (send only).
		s = s.WithoutSyncBind()

		if o.syncSend == 0 {
			o.syncSend += len(s.Sync.Hosts)
		}

		// Setup sync if enabled in configuration file.
		if o.syncSend > 0 {
			eng, err = sync.New(s.Sync, s.Grey.Enable, log)
			if eng == nil {
				if err != nil {
					log.Warn("could not create sync engine", "err", err)
				}
				fmt.Fprintf(stderr, "%s: sync disabled by configuration\n", progName)
				o.syncSend = 0
			} else if err := eng.Start(); err != nil {
				log.Warn("could not start sync engine", "err", err)
				eng.Stop()
				eng = nil
				o.syncSend = 0
			}
		}

		var sy syncer
		if eng != nil {
			sy = eng
		}
		c := 0
		for _, k := range o.keys {
			if k != "" {
				c++
				ret += dbUpdate(ctx, store, k, o.action, o.typ, sy, s.Grey.WhiteExpiry, s.Grey.TrapExpiry, stderr)
			}
		}
		if c == 0 {
			fmt.Fprintf(stderr, "%s: No addresses specified\n", progName)
		}

	default:
		fmt.Fprintf(stderr, "%s: Bad action specified\n", progName)
	}

	if err := store.Close(); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
	}
	if o.syncSend > 0 {
		eng.Stop()
	}
	return ret
}

// dbList prints every database entry (db_list).
func dbList(ctx context.Context, store core.Store, stdout, stderr io.Writer) int {
	err := store.View(ctx, func(tx core.ReadTx) error {
		it, err := tx.Iter(core.IterAll)
		if err != nil {
			return err
		}
		defer it.Close()

		for {
			k, d, ok, err := it.Next()
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			printEntry(stdout, k, d)
		}
	})
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}
	return 0
}

// printEntry writes one database entry in the greydb listing format.
func printEntry(stdout io.Writer, k core.Key, d core.Data) {
	switch k.Type {
	case core.KeyTuple:
		// This is a greylist entry.
		t := k.Tuple
		fmt.Fprintf(stdout, "GREY|%s|%s|%s|%s|%d|%d|%d|%d|%d\n",
			t.IP, t.Helo, t.From, t.To, d.First, d.Pass, d.Expire,
			d.BCount, d.PCount)

	case core.KeyMail:
		fmt.Fprintf(stdout, "SPAMTRAP|%s\n", k.Str)

	case core.KeyDomain:
		fmt.Fprintf(stdout, "DOMAIN|%s\n", k.Str)

	case core.KeyIP:
		// We have a non-greylist entry.
		switch d.PCount {
		case core.PCountTrapped:
			// Spamtrap hit, with expiry time.
			fmt.Fprintf(stdout, "TRAPPED|%s|%d\n", k.Str, d.Expire)
		default:
			// Must be a whitelist entry.
			fmt.Fprintf(stdout, "WHITE|%s|||%d|%d|%d|%d|%d\n", k.Str,
				d.First, d.Pass, d.Expire, d.BCount, d.PCount)
		}
	}
}

// dbUpdate adds or deletes a single entry (db_update). It returns 0 on
// success and 1 on failure.
func dbUpdate(ctx context.Context, store core.Store, key string, action, typ int, s syncer,
	whiteExp, trapExp int64, stderr io.Writer) int {
	warn := func(format string, a ...any) {
		fmt.Fprintf(stderr, "%s: %s\n", progName, fmt.Sprintf(format, a...))
	}
	now := nowFunc().Unix()

	var k core.Key
	switch typ {
	case typeTraphit, typeWhite:
		// We are expecting a numeric IP address.
		if ip.CheckAddr(key) == -1 {
			warn("Invalid IP address %s", key)
			return 1
		}
		k = core.IPKey(key)

	case typeSpamtrap:
		key = core.NormalizeEmail(key)
		if !strings.Contains(key, "@") {
			warn("Not an email address: %s", key)
			return 1
		}
		k = core.MailKey(key)

	case typeDomain:
		key = core.NormalizeEmail(key)
		k = core.DomainKey(key)

	default:
		warn("unknown type %d", typ)
		return 1
	}

	var d core.Data
	err := store.Update(ctx, func(tx core.Tx) error {
		if action == actionDel {
			found, err := tx.Del(k)
			if err != nil {
				warn("Deletion failed")
				return errReported
			}
			if !found {
				warn("No entry for %s", key)
				return errReported
			}
			return nil
		}

		// Add a new entry.
		var found bool
		var err error
		d, found, err = tx.Get(k)
		if err != nil {
			return errReported
		}
		if found {
			// Update the existing entry in the database.
			d.PCount++
			switch typ {
			case typeWhite:
				d.Pass = now
				d.Expire = now + whiteExp
			case typeTraphit:
				d.Expire = now + trapExp
				d.PCount = core.PCountTrapped
			case typeSpamtrap:
				d.Expire = 0
				d.PCount = core.PCountSpamtrap
			case typeDomain:
				d.Expire = 0
				d.PCount = core.PCountDomain
			}
		} else {
			// Create a fresh entry and insert into the database.
			d = core.Data{First: now, BCount: 1}
			switch typ {
			case typeWhite:
				d.Pass = now
				d.Expire = now + whiteExp
			case typeTraphit:
				d.Expire = now + trapExp
				d.PCount = core.PCountTrapped
			case typeSpamtrap, typeDomain:
				d.Expire = 0
				d.PCount = core.PCountSpamtrap
			}
		}
		if err := tx.Put(k, d); err != nil {
			warn("Put failed")
			return errReported
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, errReported) {
			// Transaction begin or commit failure.
			warn("%v", err)
		}
		return 1
	}

	if s != nil {
		del := action == actionDel
		switch typ {
		case typeWhite:
			s.White(key, time.Unix(now, 0), time.Unix(d.Expire, 0), del)
		case typeTraphit:
			s.Trapped(key, time.Unix(now, 0), time.Unix(d.Expire, 0), del)
		}
	}
	return 0
}
