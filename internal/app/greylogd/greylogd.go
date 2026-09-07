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
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/cli"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/privs"
	"github.com/mikey-austin/greyd-golang/internal/sandbox"
	"github.com/mikey-austin/greyd-golang/internal/settings"
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
	opts, _, err := cli.Parse("dIW:Y:f:P:p:", args)
	if err != nil {
		return o, err
	}
	for _, opt := range opts {
		switch opt.Flag {
		case 'd':
			o.Opts.SetInt("debug", "", 1)
		case 'I':
			o.Opts.SetInt("track_outbound", "firewall", 0)
		case 'f':
			o.ConfigFile = opt.Arg
		case 'p':
			n, err := opt.Int()
			if err != nil {
				return o, fmt.Errorf("invalid port %q", opt.Arg)
			}
			o.Opts.SetInt("port", "sync", n)
		case 'P':
			o.Opts.SetStr("greylogd_pidfile", "", opt.Arg)
		case 'W':
			// Convert hours to seconds.
			hours, err := opt.Int()
			if err != nil {
				return o, fmt.Errorf("invalid white expiry %q", opt.Arg)
			}
			o.Opts.SetInt("white_expiry", "grey", hours*60*60)
		case 'Y':
			o.Opts.AppendListStr("hosts", "sync", opt.Arg)
			o.SyncSend++
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

	s, err := settings.Load(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}

	log, h, err := logger.New(logger.Options{
		Ident:  progName,
		Debug:  s.Debug,
		Syslog: s.SyslogEnable,
		File:   s.LogToFile,
		Stderr: stderr,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}
	defer func() { _ = h.Close() }()
	for _, w := range s.Warnings {
		log.Warn(w)
	}

	// Ensure that the sync bind address is not set: greylogd only sends.
	s = s.WithoutSyncBind()

	syncSend := opts.SyncSend
	if syncSend == 0 {
		syncSend = len(s.Sync.Hosts)
	}

	var (
		eng    *greydsync.Engine
		syncer Syncer
	)
	if syncSend > 0 {
		// greylogd never receives, so forwarding of received entries
		// to a greylister is irrelevant.
		eng, err = greydsync.New(s.Sync, false, log)
		switch {
		case err != nil:
			log.Warn("sync disabled by configuration", "err", err)
			eng = nil
		case eng == nil:
			log.Warn("sync disabled by configuration")
		default:
			if err := eng.Start(); err != nil {
				log.Warn("could not start sync engine", "err", err)
				eng.Stop()
				eng = nil
			}
		}
	}
	if eng != nil {
		syncer = eng
	}

	dbPw, err := privs.LookupUser(s.Grey.User)
	if err != nil {
		log.Error("getpwnam", "user", s.Grey.User, "err", err)
		eng.Stop()
		return 1
	}

	if s.Daemonize {
		if err := privs.Daemonize(true); err != nil {
			log.Warn("daemon", "err", err)
			eng.Stop()
			return 1
		}
	}

	pidfilePath := s.GreylogdPidfile
	if pidfilePath == "" {
		pidfilePath = version.GreylogdPidfile
	}
	pidfile, err := privs.WritePidfile(pidfilePath, dbPw)
	if err != nil {
		if errors.Is(err, privs.ErrAlreadyRunning) {
			log.Error("it appears greylogd is already running...")
		} else {
			log.Error("could not write pidfile", "path", pidfilePath, "err", err)
		}
		eng.Stop()
		return 1
	}

	direction := "inbound direction only"
	if cfg.Bool("track_outbound", "firewall", true) {
		direction = "in both directions"
	}
	log.Info("listening", "direction", direction)

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	fw, err := core.OpenFirewall(ctx, cfg, core.FirewallOptions{Log: log})
	if err != nil {
		log.Error("could not obtain firewall handle", "err", err)
		eng.Stop()
		_ = pidfile.Close("")
		return 1
	}

	dropPrivs := s.DropPrivs
	storeOpts := core.StoreOptions{Hostname: s.Hostname, Log: log}
	if storeOpts.Hostname == "" {
		storeOpts.Hostname = hostname()
	}
	if dropPrivs {
		storeOpts.User = dbPw
	}
	store, err := core.OpenStore(cfg, storeOpts)
	if err != nil {
		log.Error("could not obtain database handle", "err", err)
		_ = fw.Close()
		eng.Stop()
		_ = pidfile.Close("")
		return 1
	}

	if err := fw.StartLogCapture(ctx); err != nil {
		log.Error("could not start firewall log capture", "err", err)
		_ = fw.Close()
		_ = store.Close()
		eng.Stop()
		_ = pidfile.Close("")
		return 1
	}

	if dbPw != nil && dropPrivs {
		if err := privs.Drop(dbPw); err != nil {
			log.Warn("could not drop privileges", "err", err)
			goto shutdown
		}
	}

	{
		whiteExp := s.Grey.WhiteExpiry
		if err := store.Open(ctx, core.OpenRW); err != nil {
			log.Warn("could not open database", "err", err)
			goto shutdown
		}
		if s.Sandbox {
			pf := core.NormalizeDriver(s.Firewall.Driver) == "pf"
			p := sandbox.Profile{Role: sandbox.RoleGrey, Exec: pf, Devices: pf, ReadPaths: []string{"/etc"}}
			p.WritePaths = append(p.WritePaths, core.WritablePaths(store)...)
			p.WritePaths = append(p.WritePaths, filepath.Dir(pidfilePath))
			if s.LogToFile != "" {
				p.WritePaths = append(p.WritePaths, filepath.Dir(s.LogToFile))
			}
			if err := sandbox.Apply(p, log); err != nil && !errors.Is(err, sandbox.ErrUnsupported) {
				log.Warn("sandbox not applied", "err", err)
			}
		}

		for ctx.Err() == nil {
			addrs, err := fw.CaptureLog(ctx)
			if err != nil {
				if ctx.Err() == nil {
					log.Warn("error capturing firewall log", "err", err)
				}
				break
			}
			if len(addrs) == 0 {
				continue
			}
			if err := processAddresses(ctx, log, store, addrs, time.Now(), whiteExp, syncer); err != nil {
				break
			}
		}
	}

shutdown:
	log.Info("exiting")
	_ = fw.EndLogCapture()
	_ = fw.Close()
	_ = store.Close()
	eng.Stop()
	if err := pidfile.Close(""); err != nil {
		log.Warn("could not remove pidfile", "err", err)
	}

	return 0
}

// processAddresses refreshes the whitelist entry of each captured address
// within its own transaction: a missing entry is created with first and
// pass set to now, then pcount is incremented and the expiry pushed out by
// whiteExp seconds. Each update is announced to syncer when non-nil. The
// first failure is logged and returned; the failed transaction is rolled
// back by the store.
func processAddresses(ctx context.Context, log *slog.Logger, store core.Store, addrs []string, now time.Time, whiteExp int64, syncer Syncer) error {
	ts := now.Unix()
	expire := now.Add(time.Duration(whiteExp) * time.Second)

	for _, addr := range addrs {
		key := core.IPKey(addr)
		err := store.Update(ctx, func(tx core.Tx) error {
			d, found, err := tx.Get(key)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			if !found {
				// Create new entry.
				d = core.Data{First: ts, Pass: ts}
			}

			// Update existing entry.
			d.PCount++
			d.Expire = ts + whiteExp
			if err := tx.Put(key, d); err != nil {
				return fmt.Errorf("put: %w", err)
			}

			log.Info("whitelisting", "ip", addr)
			if syncer != nil {
				syncer.White(addr, now, expire, false)
			}
			return nil
		})
		if err != nil {
			log.Warn("error updating whitelist entry", "ip", addr, "err", err)
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
