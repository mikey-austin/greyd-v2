package monitor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/config/parse"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

// fakeGreyd answers statistics requests on a unix socket.
func fakeGreyd(t *testing.T, path string, counters map[string]int64, bls []string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				m, err := ipc.NewReader(c).Next()
				if err != nil {
					return
				}
				if _, ok := m.(*ipc.StatsRequest); ok {
					_ = ipc.WriteStatsReply(c, counters, bls)
				}
			}()
		}
	}()
}

func testSettings(t *testing.T, sock string) *settings.Settings {
	t.Helper()
	cfg, err := parse.String(fmt.Sprintf("config_socket = %q\nsection monitor { bind_address = \"127.0.0.1\"\nport = 0\ninterval = 1 }\n", sock))
	if err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMetrics(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "g.sock")
	counters := map[string]int64{
		"uptime_seconds": 42, "connections_current": 3, "connections_current_black": 1, "max_cons": 800, "max_cons_black": 700,
		"connections_total": 10, "connections_black_total": 4, "connections_refused_total": 1, "connections_refused_source_total": 2,
		"greylist_tuples_total": 5, "replies_grey_total": 5, "replies_black_total": 4, "proxy_headers_total": 0, "greylisting_enabled": 1,
		"db_entries_grey": 7, "db_entries_white": 8, "db_entries_trapped": 1, "db_entries_spamtrap": 2, "db_entries_domain": 0, "db_scan_age_seconds": 12,
	}
	fakeGreyd(t, sock, counters, []string{"greyd-greytrap=1", "odd name=3"})
	m := New(testSettings(t, sock), nil)

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var sb strings.Builder
		buf := make([]byte, 64<<10)
		for {
			n, err := resp.Body.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, sb.String()
	}

	// Before the first poll: down, no greyd series.
	if code, body := get("/healthz"); code != http.StatusServiceUnavailable {
		t.Fatalf("healthz before poll: %d %q", code, body)
	}
	if _, body := get("/metrics"); !strings.Contains(body, "greyd_up 0\n") || strings.Contains(body, "greyd_connections{") {
		t.Fatalf("metrics before poll:\n%s", body)
	}

	m.Poll(context.Background())
	code, body := get("/metrics")
	if code != 200 {
		t.Fatalf("metrics: %d", code)
	}
	for _, want := range []string{
		"greyd_up 1\n",
		"# TYPE greyd_connections gauge\n",
		`greyd_connections{state="all"} 3`, `greyd_connections{state="black"} 1`,
		`greyd_max_connections{state="black"} 700`,
		`greyd_connections_total{result="accepted"} 10`, `greyd_connections_total{result="refused_source"} 2`,
		`greyd_replies_total{kind="black"} 4`,
		`greyd_db_entries{type="spamtrap"} 2`, "greyd_db_scan_age_seconds 12",
		`greyd_blacklist_entries{name="greyd-greytrap"} 1`, `greyd_blacklist_entries{name="odd name"} 3`,
		`greyd_monitor_polls_total{result="ok"} 1`, "greyd_monitor_build_info{version=",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q in:\n%s", want, body)
		}
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatalf("healthz after poll: %d", code)
	}
	if code, _ := get("/nope"); code != 404 {
		t.Fatalf("unknown path: %d", code)
	}

	// greyd goes away: up drops, last values are no longer reported as
	// live but the failure is counted.
	m.dial = func() (net.Conn, error) { return nil, fmt.Errorf("refused") }
	m.Poll(context.Background())
	if _, body := get("/metrics"); !strings.Contains(body, "greyd_up 0\n") || !strings.Contains(body, `greyd_monitor_polls_total{result="error"} 1`) {
		t.Fatalf("metrics after failure:\n%s", body)
	}
}

func TestLabelValue(t *testing.T) {
	if got := labelValue("a\"b\\c\nd"); got != `"a\"b\\c\nd"` {
		t.Fatalf("labelValue = %s", got)
	}
}

func TestParseFlags(t *testing.T) {
	o, err := ParseFlags([]string{"-F", "-d", "-l", "0.0.0.0", "-p", "9999", "-i", "5", "-f", "/x"})
	if err != nil || !o.Foreground || o.ConfigFile != "/x" || o.Opts.Int("port", "monitor", 0) != 9999 || o.Opts.Int("interval", "monitor", 0) != 5 || o.Opts.Str("bind_address", "monitor", "") != "0.0.0.0" || o.Opts.Int("debug", "", 0) != 1 {
		t.Fatalf("%+v %v", o, err)
	}
	for _, bad := range [][]string{{"-p", "x"}, {"-z"}, {"extra"}} {
		if _, err := ParseFlags(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	var out strings.Builder
	if rc := Run([]string{"-V"}, &out, &out); rc != 0 || !strings.Contains(out.String(), "greyd-monitor") {
		t.Fatalf("-V: %d %q", rc, out.String())
	}
	if rc := Run([]string{"-f", "/nonexistent/greyd.conf"}, &out, &out); rc != 1 {
		t.Fatal("missing config must fail")
	}
}

func TestServeAndShutdown(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "g.sock")
	fakeGreyd(t, sock, map[string]int64{"uptime_seconds": 1}, nil)
	m := New(testSettings(t, sock), nil)
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := m.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.Serve(ctx, ln) }()
	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("index: %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestRunEndToEnd drives Run with a real configuration file and stops it
// with SIGTERM, as the service manager would.
func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "g.sock")
	fakeGreyd(t, sock, map[string]int64{"uptime_seconds": 5}, nil)
	conf := filepath.Join(dir, "greyd.conf")
	if err := os.WriteFile(conf, []byte(fmt.Sprintf("config_socket = %q\nsandbox = 0\ndrop_privs = 0\nsyslog_enable = 0\nlog_to_file = %q\nsection monitor {\n  bind_address = \"127.0.0.1\"\n  port = 0\n  interval = 1\n}\n", sock, filepath.Join(dir, "m.log"))), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	done := make(chan int, 1)
	go func() { done <- Run([]string{"-F", "-d", "-f", conf}, &out, &errb) }()

	// Wait for the listener to appear in the log, then stop the program.
	logPath := filepath.Join(dir, "m.log")
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, _ := os.ReadFile(logPath)
		if strings.Contains(string(b), "greyd-monitor starting") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("monitor did not start: %s / %s", errb.String(), b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("rc=%d stderr=%s", rc, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after SIGTERM")
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "exiting") {
		t.Fatalf("log:\n%s", b)
	}
}
