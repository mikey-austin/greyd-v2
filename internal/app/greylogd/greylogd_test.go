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

package greylogd

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-golang/adapters/db/memory"
	"github.com/mikey-austin/greyd-golang/internal/config"
	_ "github.com/mikey-austin/greyd-golang/internal/config/parse"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, o Options)
	}{
		{"white expiry in hours", []string{"-W", "2"}, func(t *testing.T, o Options) {
			if got := o.Opts.Int("white_expiry", "grey", -1); got != 7200 {
				t.Errorf("white_expiry = %d, want 7200", got)
			}
		}},
		{"attached argument", []string{"-W2"}, func(t *testing.T, o Options) {
			if got := o.Opts.Int("white_expiry", "grey", -1); got != 7200 {
				t.Errorf("white_expiry = %d, want 7200", got)
			}
		}},
		{"inbound only", []string{"-I"}, func(t *testing.T, o Options) {
			if got := o.Opts.Int("track_outbound", "firewall", -1); got != 0 {
				t.Errorf("track_outbound = %d, want 0", got)
			}
		}},
		{"grouped flags", []string{"-dI"}, func(t *testing.T, o Options) {
			if got := o.Opts.Int("debug", "", -1); got != 1 {
				t.Errorf("debug = %d, want 1", got)
			}
			if got := o.Opts.Int("track_outbound", "firewall", -1); got != 0 {
				t.Errorf("track_outbound = %d, want 0", got)
			}
		}},
		{"sync targets", []string{"-Y", "a", "-Y", "b"}, func(t *testing.T, o Options) {
			hosts := o.Opts.StrList("hosts", "sync")
			if len(hosts) != 2 || hosts[0] != "a" || hosts[1] != "b" {
				t.Errorf("hosts = %v, want [a b]", hosts)
			}
			if o.SyncSend != 2 {
				t.Errorf("SyncSend = %d, want 2", o.SyncSend)
			}
		}},
		{"sync port", []string{"-p", "9"}, func(t *testing.T, o Options) {
			if got := o.Opts.Int("port", "sync", -1); got != 9 {
				t.Errorf("sync port = %d, want 9", got)
			}
		}},
		{"pidfile and config", []string{"-P", "/tmp/x.pid", "-f", "/etc/x.conf"}, func(t *testing.T, o Options) {
			if got := o.Opts.Str("greylogd_pidfile", "", ""); got != "/tmp/x.pid" {
				t.Errorf("greylogd_pidfile = %q", got)
			}
			if o.ConfigFile != "/etc/x.conf" {
				t.Errorf("ConfigFile = %q", o.ConfigFile)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := ParseFlags(tc.args)
			if err != nil {
				t.Fatalf("ParseFlags(%v): %v", tc.args, err)
			}
			tc.check(t, o)
		})
	}

	bad := [][]string{{"-x"}, {"-W"}, {"-W", "abc"}, {"-p", "nope"}}
	for _, args := range bad {
		if _, err := ParseFlags(args); err == nil {
			t.Errorf("ParseFlags(%v) succeeded, want error", args)
		}
	}
}

func TestBadFlagPrintsUsage(t *testing.T) {
	var stderr bytes.Buffer
	if rc := Run([]string{"-x"}, &stderr); rc != 1 {
		t.Fatalf("Run returned %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "usage: greylogd [-dI] [-f config] [-W whiteexp] [-Y synctarget] [-p syncport] [-P pidfile]") {
		t.Errorf("usage not printed: %q", stderr.String())
	}
}

// recordingSyncer records White announcements.
type recordingSyncer struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingSyncer) White(ip string, now, expire time.Time, del bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("%s %d %d %v", ip, now.Unix(), expire.Unix(), del))
}

func TestProcessAddresses(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer
	log, h, err := logger.New(logger.Options{Ident: "test", Stderr: &logBuf})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	store := memory.New()
	if err := store.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	syncer := &recordingSyncer{}
	now := time.Unix(1_000_000, 0)
	const whiteExp = int64(3600)

	addrs := []string{"10.0.0.1", "192.168.1.2"}
	if err := processAddresses(ctx, log, store, addrs, now, whiteExp, syncer); err != nil {
		t.Fatalf("processAddresses: %v", err)
	}

	for _, a := range addrs {
		d, found, err := core.Get(ctx, store, core.IPKey(a))
		if err != nil || !found {
			t.Fatalf("Get(%s): found=%v err=%v", a, found, err)
		}
		if d.First != now.Unix() || d.Pass != now.Unix() {
			t.Errorf("%s: first=%d pass=%d, want %d", a, d.First, d.Pass, now.Unix())
		}
		if d.PCount != 1 {
			t.Errorf("%s: pcount=%d, want 1", a, d.PCount)
		}
		if d.Expire != now.Unix()+whiteExp {
			t.Errorf("%s: expire=%d, want %d", a, d.Expire, now.Unix()+whiteExp)
		}
	}

	want := []string{
		fmt.Sprintf("10.0.0.1 %d %d false", now.Unix(), now.Unix()+whiteExp),
		fmt.Sprintf("192.168.1.2 %d %d false", now.Unix(), now.Unix()+whiteExp),
	}
	if len(syncer.calls) != 2 || syncer.calls[0] != want[0] || syncer.calls[1] != want[1] {
		t.Errorf("sync calls = %v, want %v", syncer.calls, want)
	}

	// A second sighting increments pcount and refreshes the expiry while
	// keeping the original first/pass times.
	later := now.Add(10 * time.Minute)
	if err := processAddresses(ctx, log, store, []string{"10.0.0.1"}, later, whiteExp, nil); err != nil {
		t.Fatalf("processAddresses (second): %v", err)
	}
	d, found, err := core.Get(ctx, store, core.IPKey("10.0.0.1"))
	if err != nil || !found {
		t.Fatalf("Get after second call: found=%v err=%v", found, err)
	}
	if d.PCount != 2 {
		t.Errorf("pcount=%d, want 2", d.PCount)
	}
	if d.Expire != later.Unix()+whiteExp {
		t.Errorf("expire=%d, want %d", d.Expire, later.Unix()+whiteExp)
	}
	if d.First != now.Unix() || d.Pass != now.Unix() {
		t.Errorf("first/pass changed: first=%d pass=%d", d.First, d.Pass)
	}
	if len(syncer.calls) != 2 {
		t.Errorf("nil syncer must not be called; calls=%v", syncer.calls)
	}

	for _, want := range []string{"whitelisting ip=10.0.0.1", "whitelisting ip=192.168.1.2"} {
		if !strings.Contains(logBuf.String(), want) {
			t.Errorf("log output missing %q:\n%s", want, logBuf.String())
		}
	}

	// A failing update is reported, logged and rolled back: nothing is
	// written and the syncer is not told.
	ro := memory.New()
	if err := ro.Open(ctx, core.OpenRO); err != nil {
		t.Fatal(err)
	}
	logBuf.Reset()
	if err := processAddresses(ctx, log, ro, []string{"10.0.0.9"}, now, whiteExp, syncer); err == nil {
		t.Fatal("processAddresses on a read-only store succeeded, want error")
	}
	if _, found, err := core.Get(ctx, ro, core.IPKey("10.0.0.9")); err != nil || found {
		t.Errorf("entry written despite failure: found=%v err=%v", found, err)
	}
	if len(syncer.calls) != 2 {
		t.Errorf("syncer called for a failed update; calls=%v", syncer.calls)
	}
	if !strings.Contains(logBuf.String(), "error updating whitelist entry ip=10.0.0.9") {
		t.Errorf("failure not logged:\n%s", logBuf.String())
	}
}

// fakeFirewall hands out one batch of addresses and then blocks until the
// capture context is cancelled.
type fakeFirewall struct {
	mu       sync.Mutex
	addrs    []string
	captures int
	started  bool
	ended    bool
	closed   bool
}

func (f *fakeFirewall) Open(context.Context) error { return nil }
func (f *fakeFirewall) Close() error               { f.mu.Lock(); f.closed = true; f.mu.Unlock(); return nil }
func (f *fakeFirewall) Replace(context.Context, string, []string, core.Family) (int, error) {
	return 0, nil
}
func (f *fakeFirewall) StartLogCapture(context.Context) error {
	f.mu.Lock()
	f.started = true
	f.mu.Unlock()
	return nil
}
func (f *fakeFirewall) EndLogCapture() error { f.mu.Lock(); f.ended = true; f.mu.Unlock(); return nil }
func (f *fakeFirewall) CaptureLog(ctx context.Context) ([]string, error) {
	f.mu.Lock()
	f.captures++
	first := f.captures == 1
	f.mu.Unlock()
	if first {
		return f.addrs, nil
	}
	<-ctx.Done()
	return nil, nil
}
func (f *fakeFirewall) LookupOrigDst(_ context.Context, _, proxy netip.AddrPort) (netip.AddrPort, error) {
	return proxy, nil
}

func TestRunEndToEnd(t *testing.T) {
	if os.Getenv("GREYD_NO_SIGNAL_TEST") != "" {
		t.Skip("GREYD_NO_SIGNAL_TEST set")
	}

	me, err := user.Current()
	if err != nil {
		t.Skipf("cannot determine current user: %v", err)
	}

	const dbName = "logd-test"
	memory.Reset(dbName)
	t.Cleanup(func() { memory.Reset(dbName) })

	fw := &fakeFirewall{addrs: []string{"1.2.3.4"}}
	core.RegisterFirewall("fake", func(*config.Config, core.FirewallOptions) (core.Firewall, error) { return fw, nil })

	dir := t.TempDir()
	pidfile := filepath.Join(dir, "greylogd.pid")
	conf := filepath.Join(dir, "greyd.conf")
	content := fmt.Sprintf(`
daemonize = 0
drop_privs = 0
syslog_enable = 0
greylogd_pidfile = "%s"

section grey {
    user = "%s"
}

section firewall {
    driver = "fake"
}

section database {
    driver = "memory",
    name = "%s"
}
`, pidfile, me.Username, dbName)
	if err := os.WriteFile(conf, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- Run([]string{"-f", conf}, &stderr) }()

	// Wait until the captured address has been whitelisted.
	ctx := context.Background()
	view := memory.Open(dbName)
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, found, err := core.Get(ctx, view, core.IPKey("1.2.3.4"))
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if found {
			break
		}
		select {
		case rc := <-done:
			t.Fatalf("Run exited early with %d; stderr:\n%s", rc, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for whitelist entry; stderr:\n%s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := os.Stat(pidfile); err != nil {
		t.Errorf("pidfile not written: %v", err)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("kill: %v", err)
	}

	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("Run returned %d, want 0; stderr:\n%s", rc, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Run did not exit after SIGTERM; stderr:\n%s", stderr.String())
	}

	if _, err := os.Stat(pidfile); !os.IsNotExist(err) {
		t.Errorf("pidfile still present after exit (err=%v)", err)
	}

	d, found, err := core.Get(ctx, view, core.IPKey("1.2.3.4"))
	if err != nil || !found {
		t.Fatalf("entry missing after run: found=%v err=%v", found, err)
	}
	if d.PCount != 1 {
		t.Errorf("pcount=%d, want 1", d.PCount)
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()
	if !fw.started || !fw.ended || !fw.closed {
		t.Errorf("firewall lifecycle: started=%v ended=%v closed=%v", fw.started, fw.ended, fw.closed)
	}

	out := stderr.String()
	for _, want := range []string{`listening direction="in both directions"`, "whitelisting ip=1.2.3.4", "exiting"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q:\n%s", want, out)
		}
	}
}
