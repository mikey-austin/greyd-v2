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

// Package greylogd implements the greylogd daemon (main_greylogd.c): it
// captures the firewall log of SMTP connections and refreshes the
// whitelist entry of every address seen, optionally announcing each
// update to synchronisation peers.
package greylogd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/grey"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/privs"
	greydsync "github.com/mikey-austin/greyd-golang/internal/sync"
	"github.com/mikey-austin/greyd-golang/internal/version"
)

// progName is the identifier used in usage and log output.
const progName = "greylogd"

// usageText is printed on a command line error.
const usageText = "usage: " + progName + " [-dI] [-f config] [-W whiteexp] " +
	"[-Y synctarget] [-p syncport] [-P pidfile]\n"

// Options holds the parsed command line.
type Options struct {
	// ConfigFile is the main configuration file (-f).
	ConfigFile string
	// Opts carries the flag overrides merged over the configuration file.
	Opts *config.Config
	// SyncSend counts the -Y targets given on the command line.
	SyncSend int
}

// Syncer is the subset of the synchronisation engine greylogd uses.
type Syncer interface {
	White(ip string, now, expire time.Time, del bool)
}

// ParseFlags parses the command line in the getopt style of the C
// program: option letters may be grouped ("-dI") and an option argument
// may be attached ("-W2") or separate ("-W 2"). Parsing stops at "--" or
// at the first non-option argument.
func ParseFlags(args []string) (Options, error) {
	o := Options{ConfigFile: version.DefaultConfig, Opts: config.New()}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			break
		}

		for j := 1; j < len(arg); j++ {
			c := arg[j]
			switch c {
			case 'd':
				o.Opts.SetInt("debug", "", 1)
				continue
			case 'I':
				o.Opts.SetInt("track_outbound", "firewall", 0)
				continue
			case 'f', 'p', 'P', 'W', 'Y':
				// Options taking an argument, handled below.
			default:
				return o, fmt.Errorf("invalid option -- '%c'", c)
			}

			var val string
			if j+1 < len(arg) {
				val = arg[j+1:]
			} else if i+1 < len(args) {
				i++
				val = args[i]
			} else {
				return o, fmt.Errorf("option requires an argument -- '%c'", c)
			}

			switch c {
			case 'f':
				o.ConfigFile = val
			case 'p':
				n, err := strconv.Atoi(val)
				if err != nil {
					return o, fmt.Errorf("invalid port %q", val)
				}
				o.Opts.SetInt("port", "sync", n)
			case 'P':
				o.Opts.SetStr("greylogd_pidfile", "", val)
			case 'W':
				// Convert hours to seconds.
				hours, err := strconv.Atoi(val)
				if err != nil {
					return o, fmt.Errorf("invalid white expiry %q", val)
				}
				o.Opts.SetInt("white_expiry", "grey", hours*60*60)
			case 'Y':
				o.Opts.AppendListStr("hosts", "sync", val)
				o.SyncSend++
			}
			// The argument consumed the rest of this token.
			break
		}
	}

	return o, nil
}

// Run executes the daemon with the supplied command line arguments
// (excluding the program name) and returns the process exit status.
func Run(args []string, stderr io.Writer) int {
	if stderr == nil {
		stderr = os.Stderr
	}

	opts, err := ParseFlags(args)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		_, _ = io.WriteString(stderr, usageText)
		return 1
	}

	cfg := config.New()
	if err := cfg.LoadFile(opts.ConfigFile); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}
	cfg.Merge(opts.Opts)

	if err := logger.Setup(logger.Options{
		Ident:  progName,
		Debug:  cfg.Bool("debug", "", false),
		Syslog: cfg.Bool("syslog_enable", "", true),
		File:   cfg.Str("log_to_file", "", ""),
		Stderr: stderr,
	}); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}

	// Ensure that the sync bind address is not set.
	cfg.Delete("bind_address", "sync")

	syncSend := opts.SyncSend
	if syncSend == 0 {
		syncSend = len(cfg.StrList("hosts", "sync"))
	}

	var (
		eng    *greydsync.Engine
		syncer Syncer
	)
	if syncSend > 0 {
		eng, err = greydsync.New(cfg)
		switch {
		case err != nil:
			logger.Warning("sync disabled by configuration: %v", err)
			eng = nil
		case eng == nil:
			logger.Warning("sync disabled by configuration")
		default:
			if err := eng.Start(); err != nil {
				logger.Warning("could not start sync engine: %v", err)
				eng.Stop()
				eng = nil
			}
		}
	}
	if eng != nil {
		syncer = eng
	}

	dbUser := cfg.Str("user", "grey", grey.DBUser)
	dbPw, err := privs.LookupUser(dbUser)
	if err != nil {
		logger.Error("getpwnam: %v", err)
		eng.Stop()
		return 1
	}

	if cfg.Bool("daemonize", "", true) {
		if err := privs.Daemonize(true); err != nil {
			logger.Warning("daemon: %v", err)
			eng.Stop()
			return 1
		}
	}

	pidfilePath := cfg.Str("greylogd_pidfile", "", version.GreylogdPidfile)
	pidfile, err := privs.WritePidfile(pidfilePath, dbPw)
	if err != nil {
		if errors.Is(err, privs.ErrAlreadyRunning) {
			logger.Error("it appears greylogd is already running...")
		} else {
			logger.Error("could not write pidfile %s: %v", pidfilePath, err)
		}
		eng.Stop()
		return 1
	}

	direction := "inbound direction only"
	if cfg.Bool("track_outbound", "firewall", true) {
		direction = "in both directions"
	}
	logger.Info("listening, %s", direction)

	fw, err := core.OpenFirewall(cfg)
	if err != nil {
		logger.Error("could not obtain firewall handle: %v", err)
		eng.Stop()
		_ = pidfile.Close("")
		return 1
	}

	dropPrivs := cfg.Bool("drop_privs", "", true)
	storeOpts := core.StoreOptions{Hostname: cfg.Str("hostname", "", hostname())}
	if dropPrivs {
		storeOpts.User = dbPw
	}
	store, err := core.OpenStore(cfg, storeOpts)
	if err != nil {
		logger.Error("could not obtain database handle: %v", err)
		_ = fw.Close()
		eng.Stop()
		_ = pidfile.Close("")
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	if err := fw.StartLogCapture(); err != nil {
		logger.Error("could not start firewall log capture: %v", err)
		_ = fw.Close()
		_ = store.Close()
		eng.Stop()
		_ = pidfile.Close("")
		return 1
	}

	if dbPw != nil && dropPrivs {
		if err := privs.Drop(dbPw); err != nil {
			logger.Warning("could not drop privileges: %v", err)
			goto shutdown
		}
	}

	{
		whiteExp := int64(cfg.Int("white_expiry", "grey", grey.WhiteExp))
		if err := store.Open(core.OpenRW); err != nil {
			logger.Warning("could not open database: %v", err)
			goto shutdown
		}

		for ctx.Err() == nil {
			addrs, err := fw.CaptureLog(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logger.Warning("error capturing firewall log: %v", err)
				}
				break
			}
			if len(addrs) == 0 {
				continue
			}
			if err := processAddresses(store, addrs, time.Now(), whiteExp, syncer); err != nil {
				break
			}
		}
	}

shutdown:
	logger.Info("exiting")
	_ = fw.EndLogCapture()
	_ = fw.Close()
	_ = store.Close()
	eng.Stop()
	if err := pidfile.Close(""); err != nil {
		logger.Warning("%v", err)
	}

	return 0
}

// processAddresses refreshes the whitelist entry of each captured address
// within its own transaction: a missing entry is created with first and
// pass set to now, then pcount is incremented and the expiry pushed out by
// whiteExp seconds. Each update is announced to syncer when non-nil. The
// first failure is logged and returned after rolling back.
func processAddresses(store core.Store, addrs []string, now time.Time, whiteExp int64, syncer Syncer) error {
	ts := now.Unix()
	expire := now.Add(time.Duration(whiteExp) * time.Second)

	for _, addr := range addrs {
		key := core.IPKey(addr)
		if err := store.Begin(); err != nil {
			logger.Warning("error starting transaction for %s: %v", addr, err)
			return err
		}

		d, found, err := store.Get(key)
		if err != nil {
			logger.Warning("error querying database for %s: %v", addr, err)
			_ = store.Rollback()
			return err
		}
		if !found {
			// Create new entry.
			d = core.Data{First: ts, Pass: ts}
		}

		// Update existing entry.
		d.PCount++
		d.Expire = ts + whiteExp
		if err := store.Put(key, d); err != nil {
			logger.Warning("error putting %s: %v", addr, err)
			_ = store.Rollback()
			return err
		}

		logger.Info("whitelisting %s", addr)
		if syncer != nil {
			syncer.White(addr, now, expire, false)
		}

		if err := store.Commit(); err != nil {
			logger.Warning("error committing %s: %v", addr, err)
			return err
		}
	}
	return nil
}

// hostname returns the local host name or an empty string.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
