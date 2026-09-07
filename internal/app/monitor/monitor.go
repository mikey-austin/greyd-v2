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

// Package monitor implements greyd-monitor: it polls a running greyd for
// its counters over the configuration socket and serves them as
// Prometheus metrics.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/cli"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/logger"
	"github.com/mikey-austin/greyd-v2/internal/privs"
	"github.com/mikey-austin/greyd-v2/internal/sandbox"
	"github.com/mikey-austin/greyd-v2/internal/settings"
	"github.com/mikey-austin/greyd-v2/internal/setup"
	"github.com/mikey-austin/greyd-v2/internal/stats"
	"github.com/mikey-austin/greyd-v2/internal/version"
)

const progName = "greyd-monitor"

// Usage is printed on a command line error.
const Usage = "usage: greyd-monitor [-dFV] [-f config] [-l address] [-p port] [-i seconds]\n"

// ErrUsage signals a command line error.
var ErrUsage = errors.New("usage")

// Options are the parsed switches.
type Options struct {
	ConfigFile  string
	Opts        *config.Config
	Foreground  bool
	ShowVersion bool
}

// ParseFlags parses the switches (getopt "dFVf:l:p:i:").
func ParseFlags(args []string) (Options, error) {
	o := Options{ConfigFile: version.DefaultConfig, Opts: config.New()}
	opts, rest, err := cli.Parse("dFVf:l:p:i:", args)
	if err != nil || len(rest) != 0 {
		return o, ErrUsage
	}
	for _, opt := range opts {
		switch opt.Flag {
		case 'd':
			o.Opts.SetInt("debug", "", 1)
		case 'F':
			o.Foreground = true
		case 'V':
			o.ShowVersion = true
		case 'f':
			o.ConfigFile = opt.Arg
		case 'l':
			o.Opts.SetStr("bind_address", "monitor", opt.Arg)
		case 'p', 'i':
			n, err := opt.Int()
			if err != nil {
				return o, ErrUsage
			}
			if opt.Flag == 'p' {
				o.Opts.SetInt("port", "monitor", n)
			} else {
				o.Opts.SetInt("interval", "monitor", n)
			}
		default:
			return o, ErrUsage
		}
	}
	return o, nil
}

// Run is the program entry point.
func Run(args []string, stdout, stderr io.Writer) int {
	o, err := ParseFlags(args)
	if err != nil {
		fmt.Fprint(stderr, Usage)
		return 1
	}
	if o.ShowVersion {
		fmt.Fprintf(stdout, "%s %s\n", progName, version.Version)
		return 0
	}
	cfg := config.New()
	if err := cfg.LoadFile(o.ConfigFile); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}
	cfg.Merge(o.Opts)
	if o.Foreground {
		cfg.SetInt("daemonize", "", 0)
	}
	s, err := settings.Load(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return 1
	}
	if s.Daemonize {
		if err := privs.Daemonize(true); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", progName, err)
			return 1
		}
	}
	log, h, err := logger.New(logger.Options{Ident: progName, Debug: s.Debug, Syslog: s.SyslogEnable, File: s.LogToFile, Stderr: stderr})
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
	}
	defer func() { _ = h.Close() }()
	for _, w := range s.Warnings {
		log.Warn(w)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	m := New(s, log)
	ln, err := m.Listen(ctx)
	if err != nil {
		log.Error("could not listen", "err", err)
		return 1
	}
	if err := dropPrivs(s, log); err != nil {
		log.Error(err.Error())
		_ = ln.Close()
		return 1
	}
	if s.Sandbox {
		p := sandbox.Profile{Role: sandbox.RoleTool, Strict: s.SandboxStrict}
		if s.LogToFile != "" {
			p.WritePaths = []string{filepath.Dir(s.LogToFile)}
		}
		if err := sandbox.Apply(p, log); err != nil && !errors.Is(err, sandbox.ErrUnsupported) {
			log.Warn("sandbox not applied", "err", err)
		}
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if s.LogToFile != "" {
				if err := h.Reopen(s.LogToFile); err != nil {
					log.Warn("could not reopen log file", "err", err)
				}
			}
		}
	}()
	defer signal.Stop(hup)

	log.Info("greyd-monitor starting", "version", version.Version, "listen", ln.Addr().String(), "interval", s.Monitor.Interval)
	if err := m.Serve(ctx, ln); err != nil {
		log.Error("serve failed", "err", err)
		return 1
	}
	log.Info("exiting")
	return 0
}

// dropPrivs switches to the monitor user (or greyd's main user) when
// started as root; the configuration socket admits that user.
func dropPrivs(s *settings.Settings, log *slog.Logger) error {
	if !s.DropPrivs || os.Geteuid() != 0 {
		return nil
	}
	name := s.Monitor.User
	if name == "" {
		name = s.User
	}
	u, err := privs.LookupUser(name)
	if err != nil {
		return err
	}
	if err := privs.Drop(u); err != nil {
		return fmt.Errorf("failed to drop privileges: %w", err)
	}
	log.Debug("running as", "user", name)
	return nil
}

// Monitor polls greyd and renders metrics.
type Monitor struct {
	s    *settings.Settings
	log  *slog.Logger
	dial setup.Dialer
	now  func() time.Time

	mu        sync.Mutex
	last      *ipc.StatsReply
	lastOK    bool
	lastErr   string
	lastAt    time.Time
	lastTook  time.Duration
	pollsOK   int64
	pollsFail int64
}

// New creates a monitor for the configured greyd.
func New(s *settings.Settings, log *slog.Logger) *Monitor {
	return &Monitor{s: s, log: logger.Or(log), dial: stats.Dialer(s), now: time.Now}
}

// Listen binds the metrics address.
func (m *Monitor) Listen(ctx context.Context) (net.Listener, error) {
	lc := net.ListenConfig{}
	return lc.Listen(ctx, "tcp", net.JoinHostPort(m.s.Monitor.BindAddress, strconv.Itoa(m.s.Monitor.Port)))
}

// Poll queries greyd once and records the outcome.
func (m *Monitor) Poll(ctx context.Context) {
	start := m.now()
	reply, err := stats.Query(ctx, m.dial)
	took := m.now().Sub(start)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastAt, m.lastTook = start, took
	if err != nil {
		m.lastOK, m.lastErr = false, err.Error()
		m.pollsFail++
		m.log.Warn("poll failed", "err", err)
		return
	}
	m.last, m.lastOK, m.lastErr = reply, true, ""
	m.pollsOK++
	m.log.Debug("polled greyd", "took", took)
}

// Serve polls on the configured interval and serves HTTP until ctx ends.
func (m *Monitor) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		t := time.NewTimer(0)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			pctx, cancel := context.WithTimeout(ctx, time.Duration(m.s.Monitor.Interval)*time.Second)
			m.Poll(pctx)
			cancel()
			t.Reset(time.Duration(m.s.Monitor.Interval) * time.Second)
		}
	}()
	srv := &http.Server{
		Handler:           m.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Handler serves /metrics, /healthz and a small index.
func (m *Monitor) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var sb strings.Builder
		m.WriteMetrics(&sb)
		_, _ = io.WriteString(w, sb.String())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		ok, msg := m.lastOK, m.lastErr
		m.mu.Unlock()
		if !ok {
			http.Error(w, "greyd unreachable: "+msg, http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><head><title>greyd-monitor</title></head><body><h1>greyd-monitor</h1><p><a href=\"/metrics\">metrics</a> &middot; <a href=\"/healthz\">healthz</a></p></body></html>\n")
	})
	return mux
}

// metric describes how a greyd counter maps to a Prometheus series.
type metric struct {
	name   string
	help   string
	typ    string // gauge or counter
	series []series
}

type series struct {
	counter string // greyd counter name
	labels  string // rendered label set, "" for none
}

// metrics is the mapping from greyd's counter names to metrics. Counters
// missing from a reply (older greyd, no scan yet) are omitted.
var metrics = []metric{
	{"greyd_uptime_seconds", "Seconds since greyd started.", "gauge", []series{{"uptime_seconds", ""}}},
	{"greyd_greylisting_enabled", "Whether greylisting is enabled (0 = blacklist-only mode).", "gauge", []series{{"greylisting_enabled", ""}}},
	{"greyd_connections", "Currently open SMTP connections.", "gauge", []series{{"connections_current", `state="all"`}, {"connections_current_black", `state="black"`}}},
	{"greyd_max_connections", "Configured connection limits.", "gauge", []series{{"max_cons", `state="all"`}, {"max_cons_black", `state="black"`}}},
	{"greyd_connections_total", "Connections accepted or refused since start.", "counter", []series{
		{"connections_total", `result="accepted"`}, {"connections_black_total", `result="accepted_black"`},
		{"connections_refused_total", `result="refused_full"`}, {"connections_refused_source_total", `result="refused_source"`}}},
	{"greyd_greylist_tuples_total", "Envelopes handed to the greylister.", "counter", []series{{"greylist_tuples_total", ""}}},
	{"greyd_replies_total", "Final rejections sent, by kind.", "counter", []series{{"replies_grey_total", `kind="grey"`}, {"replies_black_total", `kind="black"`}}},
	{"greyd_proxy_headers_total", "Accepted PROXY protocol headers.", "counter", []series{{"proxy_headers_total", ""}}},
	{"greyd_db_entries", "Database entries by kind at the last scan.", "gauge", []series{
		{"db_entries_grey", `type="grey"`}, {"db_entries_white", `type="white"`}, {"db_entries_trapped", `type="trapped"`},
		{"db_entries_spamtrap", `type="spamtrap"`}, {"db_entries_domain", `type="domain"`}}},
	{"greyd_db_scan_age_seconds", "Seconds since the greylister last scanned the database.", "gauge", []series{{"db_scan_age_seconds", ""}}},
}

// WriteMetrics renders the exposition text.
func (m *Monitor) WriteMetrics(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	up := 0
	if m.lastOK {
		up = 1
	}
	fmt.Fprintf(w, "# HELP greyd_up Whether the last poll of greyd succeeded.\n# TYPE greyd_up gauge\ngreyd_up %d\n", up)
	fmt.Fprintf(w, "# HELP greyd_monitor_polls_total Polls of greyd by result.\n# TYPE greyd_monitor_polls_total counter\ngreyd_monitor_polls_total{result=\"ok\"} %d\ngreyd_monitor_polls_total{result=\"error\"} %d\n", m.pollsOK, m.pollsFail)
	if !m.lastAt.IsZero() {
		fmt.Fprintf(w, "# HELP greyd_monitor_last_poll_timestamp_seconds When greyd was last polled.\n# TYPE greyd_monitor_last_poll_timestamp_seconds gauge\ngreyd_monitor_last_poll_timestamp_seconds %d\n", m.lastAt.Unix())
		fmt.Fprintf(w, "# HELP greyd_monitor_poll_duration_seconds Duration of the last poll.\n# TYPE greyd_monitor_poll_duration_seconds gauge\ngreyd_monitor_poll_duration_seconds %s\n", strconv.FormatFloat(m.lastTook.Seconds(), 'g', -1, 64))
	}
	fmt.Fprintf(w, "# HELP greyd_monitor_build_info Build information.\n# TYPE greyd_monitor_build_info gauge\ngreyd_monitor_build_info{version=%q} 1\n", version.Version)
	if m.last == nil {
		return
	}
	for _, mt := range metrics {
		var lines []string
		for _, s := range mt.series {
			v, ok := m.last.Counters[s.counter]
			if !ok {
				continue
			}
			if s.labels == "" {
				lines = append(lines, fmt.Sprintf("%s %d", mt.name, v))
			} else {
				lines = append(lines, fmt.Sprintf("%s{%s} %d", mt.name, s.labels, v))
			}
		}
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s\n", mt.name, mt.help, mt.name, mt.typ, strings.Join(lines, "\n"))
	}
	if bls := stats.Blacklists(m.last); len(bls) > 0 {
		fmt.Fprintf(w, "# HELP greyd_blacklist_entries Entries in each loaded blacklist.\n# TYPE greyd_blacklist_entries gauge\n")
		for _, bl := range bls {
			fmt.Fprintf(w, "greyd_blacklist_entries{name=%s} %d\n", labelValue(bl.Name), bl.Entries)
		}
	}
}

// labelValue quotes a label value per the exposition format.
func labelValue(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
