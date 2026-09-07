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

// Package greyd implements the greyd daemon: the privileged parent that
// accepts SMTP and configuration connections, and the firewall and
// greylister child roles it re-executes itself as.
package greyd

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mikey-austin/greyd-v2/internal/cli"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/smtp"
	"github.com/mikey-austin/greyd-v2/internal/version"
)

// Usage is the usage text of main_greyd.c.
const Usage = "usage: greyd [-f config] [-45bdvF] [-B maxblack] [-c maxcon] [-G passtime:greyexp:whiteexp]\n" +
	"\t[-h hostname] [-l address] [-M address] [-n name] [-p port]\n" +
	"\t[-P pidfile] [-S secs] [-s secs] [-L ipv6 address]\n" +
	"\t[-w window] [-Y synctarget] [-y synclisten] [-t] [--drivers] [--stats] [--version]\n"

// ErrUsage signals a command line error; the caller prints Usage.
var ErrUsage = errors.New("usage")

// Options are the parsed command line switches.
type Options struct {
	ConfigFile string
	// Opts holds the switch values as configuration overrides.
	Opts     *config.Config
	SyncSend int
	SyncRecv int
	// Hostname is set by -h.
	Hostname string
	// TestConfig (-t) checks the configuration and exits.
	TestConfig bool
	// ListDrivers (--drivers) prints the compiled-in drivers and exits.
	ListDrivers bool
	// ShowVersion (--version) prints the version and exits.
	ShowVersion bool
	// ShowStats (--stats) prints the counters of the running daemon.
	ShowStats bool
}

// optString lists the switches (getopt "F456f:l:L:c:B:p:bdG:h:s:S:M:n:vw:y:Y:P:").
const optString = "F456f:l:L:c:B:p:bdG:h:s:S:M:n:vw:y:Y:P:t"

// ParseFlags parses the switches. maxFiles bounds -B and -c. The long
// options --drivers and --version are informational and take no
// argument.
func ParseFlags(args []string, maxFiles int) (Options, error) {
	o := Options{ConfigFile: version.DefaultConfig, Opts: config.New()}
	var short []string
	for _, a := range args {
		switch a {
		case "--drivers":
			o.ListDrivers = true
		case "--version":
			o.ShowVersion = true
		case "--stats":
			o.ShowStats = true
		default:
			short = append(short, a)
		}
	}
	opts, rest, err := cli.Parse(optString, short)
	if err != nil {
		return o, ErrUsage
	}
	if len(rest) != 0 {
		return o, ErrUsage
	}
	for _, opt := range opts {
		if err := o.apply(opt.Flag, opt.Arg, maxFiles); err != nil {
			return o, err
		}
	}
	return o, nil
}

func (o *Options) apply(c byte, arg string, maxFiles int) error {
	opts := o.Opts
	atoi := func(s string) (int, error) {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return 0, ErrUsage
		}
		return n, nil
	}
	switch c {
	case 'F':
		opts.SetInt("daemonize", "", 0)
	case 'f':
		o.ConfigFile = arg
	case '4':
		opts.SetStr("error_code", "", "450")
	case '5':
		opts.SetStr("error_code", "", "550")
	case '6':
		opts.SetInt("enable_ipv6", "", 1)
	case 'l':
		opts.SetStr("bind_address", "", arg)
	case 'L':
		opts.SetStr("bind_address_ipv6", "", arg)
	case 'B':
		n, err := atoi(arg)
		if err != nil {
			return err
		}
		if n > maxFiles {
			return fmt.Errorf("%d > system max of %d connections", n, maxFiles)
		}
		opts.SetInt("max_cons_black", "", n)
	case 'c':
		n, err := atoi(arg)
		if err != nil {
			return err
		}
		if n > maxFiles {
			return fmt.Errorf("%d > system max of %d connections", n, maxFiles)
		}
		opts.SetInt("max_cons", "", n)
	case 'p':
		n, err := atoi(arg)
		if err != nil {
			return err
		}
		opts.SetInt("port", "", n)
	case 'P':
		opts.SetStr("greyd_pidfile", "", arg)
	case 'd':
		opts.SetInt("debug", "", 1)
	case 't':
		o.TestConfig = true
	case 'b':
		opts.SetInt("enable", "grey", 0)
	case 'G':
		parts := strings.Split(arg, ":")
		if len(parts) != 3 {
			return ErrUsage
		}
		var vals [3]int
		for i, p := range parts {
			n, err := atoi(p)
			if err != nil || n < 0 {
				return ErrUsage
			}
			vals[i] = n
		}
		// passtime is in minutes, the expiries in hours.
		opts.SetInt("pass_time", "grey", vals[0]*60)
		opts.SetInt("grey_expiry", "grey", vals[1]*60*60)
		opts.SetInt("white_expiry", "grey", vals[2]*60*60)
	case 'h':
		if len(arg) >= 255 {
			return fmt.Errorf("-h arg too long")
		}
		o.Hostname = arg
		opts.SetStr("hostname", "", arg)
	case 's':
		n, err := atoi(arg)
		if err != nil || n < 0 || n > 10*smtp.DefaultStutter {
			return ErrUsage
		}
		opts.SetInt("stutter", "", n)
	case 'S':
		n, err := atoi(arg)
		if err != nil || n < 0 || n > 10*smtp.DefaultGreyStut {
			return ErrUsage
		}
		opts.SetInt("stutter", "grey", n)
	case 'M':
		opts.SetStr("low_prio_mx", "grey", arg)
	case 'n':
		opts.SetStr("banner", "", arg)
	case 'v':
		opts.SetInt("verbose", "", 1)
	case 'w':
		n, err := atoi(arg)
		if err != nil || n <= 0 {
			return ErrUsage
		}
		opts.SetInt("window", "", n)
	case 'Y':
		opts.AppendListStr("hosts", "sync", arg)
		o.SyncSend++
	case 'y':
		opts.SetStr("bind_address", "sync", arg)
		o.SyncRecv++
	default:
		return ErrUsage
	}
	return nil
}
