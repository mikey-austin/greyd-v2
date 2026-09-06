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

// Package setup is the greyd-setup program (main_greyd_setup.c).
package setup

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/privs"
	"github.com/mikey-austin/greyd-golang/internal/setup"
	"github.com/mikey-austin/greyd-golang/internal/version"
)

const progName = "greyd-setup"

// options holds the parsed command line.
type options struct {
	configFile string
	dryrun     bool
	debug      bool
	greyonly   bool
	daemonize  bool
}

// parseArgs implements getopt(argc, argv, "f:bdDn"). Any error means the
// usage message must be printed.
func parseArgs(args []string) (options, error) {
	o := options{configFile: version.DefaultConfig, greyonly: true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return o, fmt.Errorf("unexpected argument %q", args[i+1])
			}
			return o, nil
		}
		if len(arg) < 2 || arg[0] != '-' {
			return o, fmt.Errorf("unexpected argument %q", arg)
		}
		for j := 1; j < len(arg); j++ {
			switch arg[j] {
			case 'f':
				rest := arg[j+1:]
				if rest == "" {
					i++
					if i >= len(args) {
						return o, fmt.Errorf("option -f requires an argument")
					}
					rest = args[i]
				}
				o.configFile = rest
				j = len(arg)
			case 'n':
				o.dryrun = true
			case 'd':
				o.debug = true
			case 'b':
				o.greyonly = false
			case 'D':
				o.daemonize = true
			default:
				return o, fmt.Errorf("unknown option -%c", arg[j])
			}
		}
	}
	return o, nil
}

// Run executes greyd-setup with the given command line arguments (without
// the program name) and returns the process exit status.
func Run(args []string, stderr io.Writer) int {
	o, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "usage: %s [-bDdn] [-f config]\n", progName)
		return 1
	}

	cfg := config.New()
	if err := cfg.LoadFile(o.configFile); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}

	if o.daemonize {
		if err := privs.Daemonize(false); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", progName, err)
			return 1
		}
	}

	// Don't drop privileges.
	cfg.SetInt("drop_privs", "", 0)

	if len(cfg.StrList("lists", "setup")) == 0 {
		fmt.Fprintf(stderr, "%s: no lists configured in %s\n", progName, o.configFile)
		return 1
	}

	if err := logger.Setup(logger.Options{
		Ident:  progName,
		Debug:  o.debug || cfg.Bool("debug", "", false),
		Syslog: cfg.Bool("syslog_enable", "", true),
		File:   cfg.Str("log_to_file", "", ""),
		Stderr: stderr,
	}); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}

	var fw core.Firewall
	if !o.greyonly && !o.dryrun {
		fw, err = core.OpenFirewall(cfg)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", progName, err)
			return 1
		}
		defer fw.Close()
	}

	cfgPort := cfg.Int("config_port", "", setup.DefaultConfigPort)
	dial := func() (net.Conn, error) { return setup.DialReserved(cfgPort) }

	err = setup.Run(cfg, setup.Options{
		Dryrun:   o.dryrun,
		Debug:    o.debug,
		GreyOnly: o.greyonly,
		Debugf:   func(format string, a ...any) { fmt.Fprintf(stderr, format, a...) },
	}, fw, dial)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", progName, strings.TrimSpace(err.Error()))
		return 1
	}
	return 0
}
