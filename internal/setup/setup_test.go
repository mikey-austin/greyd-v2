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
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/fw/dummy"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/config/parse"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/logger"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

// frame is one blacklist message received by the fake greyd.
type frame struct {
	name, message string
	ips           []string
}

// fakeGreyd accepts configuration connections and records one frame per
// connection.
type fakeGreyd struct {
	ln     net.Listener
	mu     sync.Mutex
	frames []frame
	wg     sync.WaitGroup
}

func newFakeGreyd(t *testing.T) *fakeGreyd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGreyd{ln: ln}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		// Connections are read one at a time, as greyd serves its
		// configuration socket, so frames keep the order Run sent them
		// in (Run finishes one connection before opening the next).
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			msg, err := ipc.NewReader(conn).Next()
			_ = conn.Close()
			if err != nil {
				continue
			}
			if bl, ok := msg.(*ipc.BlacklistMessage); ok {
				g.mu.Lock()
				g.frames = append(g.frames, frame{name: bl.Name, message: bl.Message, ips: bl.IPs})
				g.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		g.wg.Wait()
	})
	return g
}

func (g *fakeGreyd) dial() (net.Conn, error) {
	return net.Dial("tcp", g.ln.Addr().String())
}

// received waits until want frames have arrived (or two seconds pass),
// then stops accepting, waits for the readers and returns the frames in
// arrival order. Run closes its connections before returning, but the
// accept loop may not have taken the last one out of the backlog yet, and
// closing the listener would discard it.
func (g *fakeGreyd) received(t *testing.T, want int) []frame {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		g.mu.Lock()
		n := len(g.frames)
		g.mu.Unlock()
		if n >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if want == 0 {
		// Nothing expected: give a stray frame a moment to show up.
		time.Sleep(200 * time.Millisecond)
	}
	g.ln.Close()
	g.wg.Wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]frame(nil), g.frames...)
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeGzip(t *testing.T, dir, name, content string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// testConfig builds the three-list configuration used by most tests.
func testConfig(t *testing.T, extra string) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	bl1 := writeGzip(t, dir, "bl1.gz", "10.0.0.0/24\n10.0.1.0/24\n")
	wl1 := writeFile(t, dir, "wl1.txt", "10.0.1.0/24\n")
	bl2 := writeFile(t, dir, "bl2.txt", "192.168.1.1\n192.168.1.2 - 192.168.1.3\n")
	src := fmt.Sprintf(`
section setup {
    lists = ["bl1", "wl1", "bl2"]
}
blacklist bl1 {
    message = "bl1 message",
    method = "file",
    file = "%s"
}
whitelist wl1 {
    method = "file",
    file = "%s"
}
blacklist bl2 {
    message = "bl2 message",
    method = "exec",
    file = "cat %s"
}
%s`, bl1, wl1, bl2, extra)
	cfg, err := parse.String(src)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg, dir
}

// load turns a parsed configuration into settings.
func load(t *testing.T, cfg *config.Config) *settings.Settings {
	t.Helper()
	s, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// quietLogger returns a buffer-backed logger for asserting on warnings.
func quietLogger(t *testing.T) (*bytes.Buffer, *slog.Logger) {
	t.Helper()
	var buf bytes.Buffer
	l, _, err := logger.New(logger.Options{Ident: "test", Stderr: &buf})
	if err != nil {
		t.Fatal(err)
	}
	return &buf, l
}

func TestRunSendsCollapsedLists(t *testing.T) {
	_, _ = quietLogger(t)
	cfg, _ := testConfig(t, "")
	g := newFakeGreyd(t)
	fw := dummy.New()

	var debug bytes.Buffer
	o := Options{
		Debug:    true,
		GreyOnly: false,
		Debugf:   func(format string, a ...any) { fmt.Fprintf(&debug, format, a...) },
	}
	if err := Run(context.Background(), load(t, cfg), o, fw, g.dial); err != nil {
		t.Fatalf("Run: %v", err)
	}

	frames := g.received(t, 2)
	want := []frame{
		{name: "bl1", message: "bl1 message", ips: []string{"10.0.0.0/24"}},
		{name: "bl2", message: "bl2 message", ips: []string{"192.168.1.1/32", "192.168.1.2/31"}},
	}
	if !reflect.DeepEqual(frames, want) {
		t.Fatalf("frames = %+v, want %+v", frames, want)
	}

	set := fw.Set(FirewallSet)
	wantSet := []string{"10.0.0.0/24", "192.168.1.1/32", "192.168.1.2/31"}
	if !reflect.DeepEqual(set, wantSet) {
		t.Fatalf("firewall set = %v, want %v", set, wantSet)
	}

	out := debug.String()
	for _, line := range []string{
		"blacklist bl1 2 entries\n",
		"whitelist wl1 1 entries\n",
		"blacklist bl2 2 entries\n",
		"3 entries added to firewall\n",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("debug output missing %q in:\n%s", line, out)
		}
	}
}

func TestRunGreyOnlySkipsFirewall(t *testing.T) {
	_, _ = quietLogger(t)
	cfg, _ := testConfig(t, "")
	g := newFakeGreyd(t)

	if err := Run(context.Background(), load(t, cfg), Options{GreyOnly: true}, nil, g.dial); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := len(g.received(t, 2)); got != 2 {
		t.Fatalf("frames = %d, want 2", got)
	}
}

func TestRunBlacklistModeNeedsFirewall(t *testing.T) {
	_, _ = quietLogger(t)
	cfg, _ := testConfig(t, "")
	g := newFakeGreyd(t)

	err := Run(context.Background(), load(t, cfg), Options{GreyOnly: false}, nil, g.dial)
	if err == nil || !strings.Contains(err.Error(), "could not configure firewall") {
		t.Fatalf("err = %v, want firewall error", err)
	}
}

func TestRunDryrunSendsNothing(t *testing.T) {
	_, _ = quietLogger(t)
	cfg, _ := testConfig(t, "")
	g := newFakeGreyd(t)
	fw := dummy.New()

	dialed := false
	dial := func() (net.Conn, error) { dialed = true; return g.dial() }
	if err := Run(context.Background(), load(t, cfg), Options{Dryrun: true}, fw, dial); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if dialed {
		t.Fatal("dryrun dialled greyd")
	}
	if got := len(g.received(t, 0)); got != 0 {
		t.Fatalf("frames = %d, want 0", got)
	}
	if set := fw.Set(FirewallSet); len(set) != 0 {
		t.Fatalf("firewall set = %v, want empty", set)
	}
}

func TestRunNoLists(t *testing.T) {
	cfg, err := parse.String("section setup { lists = [] }")
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), load(t, cfg), Options{}, nil, nil); err == nil || !strings.Contains(err.Error(), "no lists configured") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunSkipsMissingFileAndUnknownMethod(t *testing.T) {
	logs, lg := quietLogger(t)
	cfg, _ := testConfig(t, fmt.Sprintf(`
section setup {
    lists = ["missing", "bl1", "odd", "nofile", "unconfigured", "bl2"]
}
blacklist missing {
    method = "file",
    file = "%s"
}
blacklist odd {
    method = "carrier-pigeon",
    file = "/dev/null"
}
blacklist nofile {
    method = "file"
}
`, filepath.Join(t.TempDir(), "does-not-exist")))
	g := newFakeGreyd(t)

	if err := Run(context.Background(), load(t, cfg), Options{GreyOnly: true, Log: lg}, nil, g.dial); err != nil {
		t.Fatalf("Run: %v", err)
	}
	frames := g.received(t, 2)
	var names []string
	for _, f := range frames {
		names = append(names, f.name)
	}
	// "missing", "odd" and "nofile" all fail to open and contribute nothing;
	// their (empty) blacklists are not sent since WriteBlacklist skips
	// empty lists.
	if want := []string{"bl1", "bl2"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("frames = %v, want %v", names, want)
	}
	for _, msg := range []string{
		"ignoring list list=missing",
		"unknown method carrier-pigeon",
		"ignoring list list=odd",
		"no file configuration variables set",
		"ignoring list list=nofile",
	} {
		if !strings.Contains(logs.String(), msg) {
			t.Errorf("log missing %q in:\n%s", msg, logs.String())
		}
	}
}

func TestRunParseErrorKeepsEarlierEntries(t *testing.T) {
	logs, lg := quietLogger(t)
	dir := t.TempDir()
	// A truncated address is a syntax error on line 3; the two entries
	// before it survive and parsing stops there, as in the C parser.
	bad := writeFile(t, dir, "bad.txt", "172.16.0.1\n172.16.0.2\n1.2.3\n172.16.0.3\n")
	cfg, err := parse.String(fmt.Sprintf(`
section setup { lists = ["bad"] }
blacklist bad { file = "%s" }
`, bad))
	if err != nil {
		t.Fatal(err)
	}
	g := newFakeGreyd(t)

	if err := Run(context.Background(), load(t, cfg), Options{GreyOnly: true, Log: lg}, nil, g.dial); err != nil {
		t.Fatalf("Run: %v", err)
	}
	frames := g.received(t, 1)
	if len(frames) != 1 {
		t.Fatalf("frames = %+v, want 1", frames)
	}
	if want := []string{"172.16.0.1/32", "172.16.0.2/32"}; !reflect.DeepEqual(frames[0].ips, want) {
		t.Fatalf("ips = %v, want %v", frames[0].ips, want)
	}
	if frames[0].message != DefaultMessage {
		t.Fatalf("message = %q, want default", frames[0].message)
	}
	if !strings.Contains(logs.String(), "blacklist parse error list=bad line=3 col=") {
		t.Fatalf("log missing parse error:\n%s", logs.String())
	}
}

func TestRunDialFailure(t *testing.T) {
	_, _ = quietLogger(t)
	cfg, _ := testConfig(t, "")
	dial := func() (net.Conn, error) { return nil, fmt.Errorf("refused") }
	err := Run(context.Background(), load(t, cfg), Options{GreyOnly: true}, nil, dial)
	if err == nil || !strings.Contains(err.Error(), "could not connect to greyd-config") {
		t.Fatalf("err = %v", err)
	}
}

// fakeCurl writes a shell script that prints its arguments, one per line.
func fakeCurl(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "curl")
	script := "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpenHTTPRunsCurl(t *testing.T) {
	dir := t.TempDir()
	curl := fakeCurl(t, dir)

	for _, tc := range []struct {
		name  string
		proxy string
		want  string
	}{
		{name: "no proxy", want: "-s\nhttp://www.example.org/list.gz\n"},
		{name: "proxy", proxy: "p:1", want: "-s\n--proxy\np:1\nhttp://www.example.org/list.gz\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := ""
			if tc.proxy != "" {
				extra = fmt.Sprintf(",\n    curl_proxy = \"%s\"", tc.proxy)
			}
			cfg, err := parse.String(fmt.Sprintf(`
section setup {
    curl_path = "%s"%s
}
blacklist remote {
    method = "http",
    file = "www.example.org/list.gz"
}
`, curl, extra))
			if err != nil {
				t.Fatal(err)
			}
			rc, err := Open(context.Background(), cfg.Blacklist("remote"), load(t, cfg).Setup)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			data, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			if err := rc.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if string(data) != tc.want {
				t.Fatalf("curl args = %q, want %q", data, tc.want)
			}
		})
	}
}

func TestOpenFTPUsesScheme(t *testing.T) {
	dir := t.TempDir()
	curl := fakeCurl(t, dir)
	cfg, err := parse.String(fmt.Sprintf(`
section setup { curl_path = "%s" }
blacklist remote { method = "ftp", file = "ftp.example.org/list" }
`, curl))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := Open(context.Background(), cfg.Blacklist("remote"), load(t, cfg).Setup)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if !strings.Contains(string(data), "ftp://ftp.example.org/list\n") {
		t.Fatalf("curl args = %q", data)
	}
}

func TestOpenGzipAndPlain(t *testing.T) {
	dir := t.TempDir()
	gz := writeGzip(t, dir, "a.gz", "1.2.3.4\n")
	plain := writeFile(t, dir, "a.txt", "5.6.7.8\n")
	cfg, err := parse.String(fmt.Sprintf(`
blacklist gz { file = "%s" }
blacklist plain { method = "file", file = "%s" }
`, gz, plain))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"gz": "1.2.3.4\n", "plain": "5.6.7.8\n"} {
		rc, err := Open(context.Background(), cfg.Blacklist(name), load(t, cfg).Setup)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || string(data) != want {
			t.Fatalf("%s: read %q, %v; want %q", name, data, err, want)
		}
	}
}

func TestOpenExecSplitsOnSpacesAndTabs(t *testing.T) {
	dir := t.TempDir()
	plain := writeFile(t, dir, "a.txt", "5.6.7.8\n")
	cfg, err := parse.String(fmt.Sprintf("blacklist ex { method = \"exec\", file = \"cat \t %s\" }\n"+
		"blacklist missing { method = \"exec\", file = \"%s\" }\n",
		plain, filepath.Join(dir, "no-such-command")))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := Open(context.Background(), cfg.Blacklist("ex"), load(t, cfg).Setup)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if string(data) != "5.6.7.8\n" {
		t.Fatalf("read %q", data)
	}
	if _, err := Open(context.Background(), cfg.Blacklist("missing"), load(t, cfg).Setup); err == nil {
		t.Fatal("expected error for missing command")
	}
}

func TestDialAny(t *testing.T) {
	g := newFakeGreyd(t)
	port := g.ln.Addr().(*net.TCPAddr).Port
	conn, err := DialAny(port)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDialReservedRefused(t *testing.T) {
	// Nothing listens on this port; the error must not be a bind failure.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	conn, err := DialReserved(port)
	if err == nil {
		// Running as root: the reserved bind succeeded, connect was refused
		// afterwards and reported as an error; a nil error is impossible.
		conn.Close()
		t.Fatal("expected error")
	}
	if os.Geteuid() != 0 && !strings.Contains(err.Error(), "could not bind privileged source port") {
		t.Fatalf("err = %v, want bind failure", err)
	}
}
