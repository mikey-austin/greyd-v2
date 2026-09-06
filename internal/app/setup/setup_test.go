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

package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mikey-austin/greyd-golang/adapters/fw/all"
	_ "github.com/mikey-austin/greyd-golang/internal/config/parse"
)

const usage = "usage: greyd-setup [-bDdn] [-f config]\n"

func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want options
		bad  bool
	}{
		{args: nil, want: options{configFile: "/etc/greyd/greyd.conf", greyonly: true}},
		{args: []string{"-f", "x.conf"}, want: options{configFile: "x.conf", greyonly: true}},
		{args: []string{"-fx.conf"}, want: options{configFile: "x.conf", greyonly: true}},
		{args: []string{"-bdDn"}, want: options{configFile: "/etc/greyd/greyd.conf", dryrun: true, debug: true, daemonize: true}},
		{args: []string{"-n", "-d", "-f", "c", "-b"}, want: options{configFile: "c", dryrun: true, debug: true}},
		{args: []string{"-x"}, bad: true},
		{args: []string{"-f"}, bad: true},
		{args: []string{"extra"}, bad: true},
		{args: []string{"-n", "extra"}, bad: true},
	} {
		got, err := parseArgs(tc.args)
		if tc.bad {
			if err == nil {
				t.Errorf("%v: expected error", tc.args)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v: %v", tc.args, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%v: got %+v, want %+v", tc.args, got, tc.want)
		}
	}
}

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{{"-x"}, {"positional"}, {"-f"}} {
		var stderr bytes.Buffer
		if rc := Run(args, &stderr); rc != 1 {
			t.Errorf("%v: rc = %d, want 1", args, rc)
		}
		if stderr.String() != usage {
			t.Errorf("%v: stderr = %q, want usage", args, stderr.String())
		}
	}
}

func TestRunMissingConfig(t *testing.T) {
	var stderr bytes.Buffer
	missing := filepath.Join(t.TempDir(), "nope.conf")
	if rc := Run([]string{"-f", missing}, &stderr); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "error opening file source") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunNoLists(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "greyd.conf")
	if err := os.WriteFile(conf, []byte("section setup { lists = [] }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if rc := Run([]string{"-n", "-f", conf}, &stderr); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if want := "no lists configured in " + conf; !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}

func TestRunDryrun(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(list, []byte("10.0.0.1\n10.0.0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "greyd.conf")
	src := "syslog_enable = 0\n" +
		"section setup { lists = [\"bl\"] }\n" +
		"blacklist bl { file = \"" + list + "\" }\n"
	if err := os.WriteFile(conf, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if rc := Run([]string{"-n", "-d", "-f", conf}, &stderr); rc != 0 {
		t.Fatalf("rc = %d, want 0; stderr: %s", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "blacklist bl 2 entries") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunBlacklistModeNeedsFirewallConfig(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "greyd.conf")
	src := "syslog_enable = 0\nsection setup { lists = [\"bl\"] }\nblacklist bl { file = \"/dev/null\" }\n"
	if err := os.WriteFile(conf, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if rc := Run([]string{"-b", "-f", conf}, &stderr); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "firewall") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
