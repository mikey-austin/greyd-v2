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
	"os"
	"os/signal"
	"syscall"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/privs"
	"github.com/mikey-austin/greyd-golang/internal/procs"
	"github.com/mikey-austin/greyd-golang/internal/version"
)

// Child process roles.
const (
	RoleFirewall = "fw"
	RoleGrey     = "grey"
)

// Constants from constants.h.
const (
	DefaultPort     = 8025
	DefaultCfgPort  = 8026
	MainUser        = "greyd"
	DefaultChroot   = 1
	ChrootDir       = "/var/empty"
	Backlog         = 10
	NumBlacklists   = 10
	PollTimeout     = 1000
	IPPortReserved  = 1024
	setrlimitDef    = 1
	greylistEnabled = true
)

// Run is the program entry point: it dispatches on the process role.
func Run(args []string, stderr io.Writer) int {
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

	cfg, err := loadConfig(o)
	if err != nil {
		fmt.Fprintf(stderr, "greyd: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer stop()
	signal.Ignore(syscall.SIGPIPE)

	switch procs.Role() {
	case RoleFirewall:
		setupLogging(cfg, stderr)
		files, err := inheritedFwFiles()
		if err != nil {
			logger.Error("%v", err)
			return 1
		}
		if err := runFwChild(ctx, cfg, files); err != nil {
			logger.Error("firewall process: %v", err)
			return 1
		}
		return 0

	case RoleGrey:
		setupLogging(cfg, stderr)
		files, err := inheritedGreyFiles()
		if err != nil {
			logger.Error("%v", err)
			return 1
		}
		if err := runGreyChild(ctx, cfg, files); err != nil {
			logger.Error("greylister: %v", err)
			return 1
		}
		return 0
	}

	// Parent: detach first so that sockets and pipes are created in the
	// final process (Go cannot fork after binding, unlike daemon(3)).
	if cfg.Bool("daemonize", "", true) {
		if err := privs.Daemonize(true); err != nil {
			fmt.Fprintf(stderr, "greyd: %v\n", err)
			return 1
		}
	}
	setupLogging(cfg, stderr)
	logger.Info("greyd %s starting", version.Version)

	d, err := newDaemon(cfg, o, maxFiles)
	if err != nil {
		logger.Error("%v", err)
		return 1
	}
	if err := d.bind(); err != nil {
		logger.Error("%v", err)
		return 1
	}
	if err := d.serve(ctx, spawnChildren); err != nil {
		logger.Error("%v", err)
		return 1
	}
	return 0
}

// loadConfig reads the configuration file and merges the switches over
// it. The hostname defaults to the system's when neither the file nor -h
// sets it.
func loadConfig(o Options) (*config.Config, error) {
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
	return cfg, nil
}

func setupLogging(cfg *config.Config, stderr io.Writer) {
	if err := logger.Setup(logger.Options{
		Ident:  "greyd",
		Debug:  cfg.Bool("debug", "", false),
		Syslog: cfg.Bool("syslog_enable", "", true),
		File:   cfg.Str("log_to_file", "", ""),
		Stderr: stderr,
	}); err != nil {
		fmt.Fprintf(stderr, "greyd: %v\n", err)
	}
}
