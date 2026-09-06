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
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/privs"
	"github.com/mikey-austin/greyd-golang/internal/procs"
	"github.com/mikey-austin/greyd-golang/internal/settings"
	"github.com/mikey-austin/greyd-golang/internal/version"
)

// Child process roles.
const (
	RoleFirewall = "fw"
	RoleGrey     = "grey"
)

// Constants from constants.h that are not configuration defaults.
const (
	MainUser       = "greyd"
	Backlog        = 10
	NumBlacklists  = 10
	IPPortReserved = 1024
)

// Run is the program entry point: it dispatches on the process role.
func Run(args []string, stdout, stderr io.Writer) int {
	maxFiles, err := privs.MaxFiles()
	if err != nil {
		fmt.Fprintf(stderr, "greyd: %v\n", err)
		return 1
	}
	o, err := ParseFlags(args, maxFiles)
	if err != nil {
		if !errors.Is(err, ErrUsage) {
			fmt.Fprintf(stderr, "greyd: %v\n", err)
		}
		fmt.Fprint(stderr, Usage)
		return 1
	}
	switch {
	case o.ShowVersion:
		fmt.Fprintf(stdout, "greyd %s\n", version.Version)
		return 0
	case o.ListDrivers:
		printDrivers(stdout)
		return 0
	}

	s, err := loadSettings(o)
	if err != nil {
		fmt.Fprintf(stderr, "greyd: %v\n", err)
		return 1
	}
	if o.TestConfig {
		return checkConfig(s, o.ConfigFile, stdout)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer stop()
	signal.Ignore(syscall.SIGPIPE)

	switch procs.Role() {
	case RoleFirewall:
		log, h := newLogger(s, stderr)
		defer h.Close()
		files, err := inheritedFwFiles()
		if err != nil {
			log.Error(err.Error())
			return 1
		}
		if err := runFwChild(ctx, s, files, log); err != nil {
			log.Error("firewall process failed", "err", err)
			return 1
		}
		return 0

	case RoleGrey:
		log, h := newLogger(s, stderr)
		defer h.Close()
		files, err := inheritedGreyFiles()
		if err != nil {
			log.Error(err.Error())
			return 1
		}
		if err := runGreyChild(ctx, s, files, log); err != nil {
			log.Error("greylister failed", "err", err)
			return 1
		}
		return 0
	}

	// Parent: detach first so that sockets and pipes are created in the
	// final process (Go cannot fork after binding, unlike daemon(3)).
	if s.Daemonize {
		if err := privs.Daemonize(true); err != nil {
			fmt.Fprintf(stderr, "greyd: %v\n", err)
			return 1
		}
	}
	log, h := newLogger(s, stderr)
	defer h.Close()
	log.Info("greyd starting", "version", version.Version)
	for _, w := range s.Warnings {
		log.Warn(w)
	}

	d, err := newDaemon(s, o, maxFiles, log)
	if err != nil {
		log.Error(err.Error())
		return 1
	}
	if err := d.bind(); err != nil {
		log.Error(err.Error())
		return 1
	}
	if err := d.serve(ctx, spawnChildren); err != nil {
		log.Error(err.Error())
		return 1
	}
	return 0
}

// loadSettings reads the configuration file, merges the switches over it
// and decodes the result. The hostname defaults to the system's when
// neither the file nor -h sets it.
func loadSettings(o Options) (*settings.Settings, error) {
	cfg := config.New()
	if err := cfg.LoadFile(o.ConfigFile); err != nil {
		return nil, err
	}
	cfg.Merge(o.Opts)
	if cfg.Str("hostname", "", "") == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("gethostname: %w", err)
		}
		cfg.SetStr("hostname", "", h)
	}
	return settings.Load(cfg)
}

// newLogger builds the process logger. A syslog failure is reported on
// stderr by the logger itself and logging continues without it.
func newLogger(s *settings.Settings, stderr io.Writer) (*slog.Logger, *logger.Handler) {
	log, h, err := logger.New(logger.Options{
		Ident:  "greyd",
		Debug:  s.Debug,
		Syslog: s.SyslogEnable,
		File:   s.LogToFile,
		Stderr: stderr,
	})
	if err != nil {
		fmt.Fprintf(stderr, "greyd: %v\n", err)
	}
	return log, h
}

// checkConfig implements -t: report warnings and driver availability
// without starting anything.
func checkConfig(s *settings.Settings, path string, out io.Writer) int {
	rc := 0
	for _, w := range s.Warnings {
		fmt.Fprintf(out, "warning: %s\n", w)
	}
	if d := core.NormalizeDriver(s.Database.Driver); d != "" && !contains(core.StoreDrivers(), d) {
		fmt.Fprintf(out, "error: unknown database driver %q (available: %s)\n", s.Database.Driver, strings.Join(core.StoreDrivers(), ", "))
		rc = 1
	}
	if d := core.NormalizeDriver(s.Firewall.Driver); d != "" && !contains(core.FirewallDrivers(), d) {
		fmt.Fprintf(out, "error: unknown firewall driver %q (available: %s)\n", s.Firewall.Driver, strings.Join(core.FirewallDrivers(), ", "))
		rc = 1
	}
	if rc == 0 {
		fmt.Fprintf(out, "%s: configuration OK\n", path)
	}
	return rc
}

// printDrivers implements --drivers.
func printDrivers(out io.Writer) {
	fmt.Fprintln(out, "database drivers:")
	for _, d := range core.StoreDrivers() {
		fmt.Fprintf(out, "  %s\n", d)
	}
	fmt.Fprintln(out, "firewall drivers:")
	for _, d := range core.FirewallDrivers() {
		fmt.Fprintf(out, "  %s\n", d)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
