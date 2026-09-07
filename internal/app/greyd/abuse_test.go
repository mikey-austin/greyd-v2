package greyd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/db/memory"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/settings"
	"github.com/mikey-austin/greyd-v2/internal/smtp"
	"github.com/mikey-austin/greyd-v2/internal/stats"
)

// Adversarial clients against a complete in-process greyd: a unix
// configuration socket, the memory database and the dummy firewall. Every
// test starts its own daemon, so they run in parallel.

// abuseDaemon starts a daemon for the named memory database with a unix
// configuration socket and the extra configuration appended.
func abuseDaemon(t *testing.T, name, extra string) (*running, *settings.Settings) {
	t.Helper()
	memory.Reset(name)
	sock := filepath.Join(t.TempDir(), "greyd.sock")
	cfg := testConfig(t, name, fmt.Sprintf("config_socket = %q\n%s", sock, extra))
	return startDaemon(t, cfg, Options{Opts: config.New()}), cfg
}

// counters queries the daemon's statistics over the configuration socket.
func counters(t *testing.T, cfg *settings.Settings) map[string]int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := stats.Query(ctx, stats.Dialer(cfg))
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	return reply.Counters
}

// waitCounters polls the statistics until ok holds.
func waitCounters(t *testing.T, cfg *settings.Settings, timeout time.Duration, ok func(c map[string]int64) bool) map[string]int64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		c := counters(t, cfg)
		if ok(c) {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters did not settle within %v: %v", timeout, c)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// dialFrom connects to addr from the given loopback source address. It
// reports false when the platform cannot bind the source (only 127.0.0.1
// is configured on some systems).
func dialFrom(t *testing.T, addr net.Addr, src string) (net.Conn, *bufio.Reader, bool) {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", addr.String())
	if err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			t.Logf("cannot bind %s: %v", src, err)
			return nil, nil, false
		}
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, bufio.NewReader(conn), true
}

// mustDialFrom is dialFrom for a source address already known to work.
func mustDialFrom(t *testing.T, addr net.Addr, src string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, br, ok := dialFrom(t, addr, src)
	if !ok {
		t.Fatalf("cannot dial from %s", src)
	}
	return conn, br
}

// expectClosed asserts that the peer closed the connection without
// sending anything (a refused connection).
func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	var ne net.Error
	switch {
	case err == nil:
		t.Fatalf("expected the connection to be closed, read %q", buf[:n])
	case errors.As(err, &ne) && ne.Timeout():
		t.Fatal("connection was not closed")
	}
	_ = conn.Close()
}

// expectSilence asserts that nothing arrives within d and the connection
// stays open.
func expectSilence(t *testing.T, conn net.Conn, d time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected silence, got %q, %v", buf[:n], err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
}

// greyDialogue runs a complete greylisted dialogue after the banner and
// returns once the 451 arrived.
func greyDialogue(t *testing.T, conn net.Conn, br *bufio.Reader, helo, from, to string) {
	t.Helper()
	fmt.Fprintf(conn, "EHLO %s\r\n", helo)
	expectLine(t, br, "250 greyd.test")
	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", from)
	expectLine(t, br, "250 OK")
	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", to)
	expectLine(t, br, "250 OK")
	fmt.Fprintf(conn, "DATA\r\n")
	expectLine(t, br, "451 Temporary failure, please try again later.")
}

// tuples lists the greylist tuples in the named memory database.
func tuples(t *testing.T, name string) []core.Tuple {
	t.Helper()
	var out []core.Tuple
	err := memory.Open(name).View(context.Background(), func(tx core.ReadTx) error {
		it, err := tx.Iter(core.IterEntries)
		if err != nil {
			return err
		}
		defer func() { _ = it.Close() }()
		for {
			k, _, ok, err := it.Next()
			if err != nil || !ok {
				return err
			}
			if k.Type == core.KeyTuple {
				out = append(out, k.Tuple)
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// waitTuples polls the database until it holds exactly the wanted tuples.
func waitTuples(t *testing.T, name string, want ...core.Tuple) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := tuples(t, name)
		if len(got) == len(want) {
			missing := false
			for _, w := range want {
				found := false
				for _, g := range got {
					if g == w {
						found = true
					}
				}
				if !found {
					missing = true
				}
			}
			if !missing {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("tuples %+v\nwant %+v", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAbuseSlowlorisDoesNotStarveGoodClient(t *testing.T) {
	t.Parallel()
	const name = "abuse-slowloris"
	r, cfg := abuseDaemon(t, name, "max_cons = 8\nmax_cons_black = 8\n")

	// Six clients read the banner and then trickle one byte of a command
	// every 200ms without ever finishing the line.
	const slowClients = 6
	var slow []net.Conn
	for i := 0; i < slowClients; i++ {
		conn, br := dialSMTP(t, r.d.MainAddr())
		defer conn.Close()
		expectLine(t, br, "220 ")
		slow = append(slow, conn)
	}
	var wg sync.WaitGroup
	writeErrs := make(chan error, slowClients)
	for _, conn := range slow {
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			for _, b := range []byte("EHLO slowloris") {
				time.Sleep(200 * time.Millisecond)
				if _, err := conn.Write([]byte{b}); err != nil {
					writeErrs <- err
					return
				}
			}
		}(conn)
	}

	// Meanwhile a well-behaved client completes a greylisted dialogue.
	start := time.Now()
	good, br := dialSMTP(t, r.d.MainAddr())
	expectLine(t, br, "220 ")
	greyDialogue(t, good, br, "mx.good.example", "sender@good.example", "rcpt@greyd.test")
	_ = good.Close()
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("well-behaved dialogue took %v beside slow clients", took)
	}
	waitTuples(t, name, core.Tuple{IP: "127.0.0.1", Helo: "mx.good.example", From: "sender@good.example", To: "rcpt@greyd.test"})

	wg.Wait()
	close(writeErrs)
	for err := range writeErrs {
		t.Errorf("slow client write: %v", err)
	}

	// The slow clients hold their slots but were not disconnected: the
	// inactivity deadline is smtp.MaxTime, a constant far beyond what a
	// test can wait for, so silence past it is not exercised here.
	t.Logf("read/write inactivity deadline is %v (smtp.MaxTime, not configurable)", smtp.MaxTime)
	for _, conn := range slow {
		expectSilence(t, conn, 100*time.Millisecond)
	}
	c := counters(t, cfg)
	if c["connections_current"] != slowClients || c["connections_total"] != slowClients+1 || c["connections_refused_total"] != 0 || c["connections_refused_source_total"] != 0 {
		t.Fatalf("counters with slow clients attached: %v", c)
	}

	// Their slots are released as soon as they go away.
	for _, conn := range slow {
		_ = conn.Close()
	}
	waitCounters(t, cfg, 5*time.Second, func(c map[string]int64) bool { return c["connections_current"] == 0 })
}

func TestAbuseConnectionExhaustion(t *testing.T) {
	t.Parallel()
	r, cfg := abuseDaemon(t, "abuse-exhaustion", "max_cons = 5\nmax_cons_black = 5\nmax_cons_per_source = 3\n")
	addr := r.d.MainAddr()

	// Three connections from 127.0.0.1 are served; the fourth is closed
	// on accept. Each banner is read before the next dial so that the
	// per-source count has been taken when the next connection arrives.
	var open []net.Conn
	for i := 0; i < 3; i++ {
		conn, br := dialSMTP(t, addr)
		defer conn.Close()
		expectLine(t, br, "220 ")
		open = append(open, conn)
	}
	fourth, _ := dialSMTP(t, addr)
	expectClosed(t, fourth)
	c := waitCounters(t, cfg, 5*time.Second, func(c map[string]int64) bool { return c["connections_refused_source_total"] == 1 })
	if c["connections_refused_total"] != 0 || c["connections_current"] != 3 {
		t.Fatalf("after the per-source refusal: %v", c)
	}

	// Two more from a second loopback address reach max_cons; the next
	// connection, from a third address, is refused for the global limit.
	c2a, br, ok := dialFrom(t, addr, "127.0.0.2")
	if !ok {
		t.Skip("second loopback address unavailable; global limit not exercised")
	}
	expectLine(t, br, "220 ")
	c2b, br := mustDialFrom(t, addr, "127.0.0.2")
	expectLine(t, br, "220 ")
	over, _ := mustDialFrom(t, addr, "127.0.0.3")
	expectClosed(t, over)
	c = waitCounters(t, cfg, 5*time.Second, func(c map[string]int64) bool { return c["connections_refused_total"] == 1 })
	if c["connections_refused_source_total"] != 1 || c["connections_current"] != 5 || c["max_cons"] != 5 {
		t.Fatalf("after the global refusal: %v", c)
	}

	// Closing one connection per source frees a slot for each.
	_ = open[0].Close()
	_ = c2a.Close()
	waitCounters(t, cfg, 5*time.Second, func(c map[string]int64) bool { return c["connections_current"] == 3 })
	again1, br := dialSMTP(t, addr)
	defer again1.Close()
	expectLine(t, br, "220 ")
	again2, br := mustDialFrom(t, addr, "127.0.0.2")
	defer again2.Close()
	expectLine(t, br, "220 ")
	defer c2b.Close()

	// Full again: 127.0.0.2 has two connections (under its per-source
	// limit) so this refusal is the global one.
	over, _ = mustDialFrom(t, addr, "127.0.0.2")
	expectClosed(t, over)
	c = waitCounters(t, cfg, 5*time.Second, func(c map[string]int64) bool { return c["connections_refused_total"] == 2 })
	if c["connections_refused_source_total"] != 1 || c["connections_current"] != 5 {
		t.Fatalf("after the second global refusal: %v", c)
	}
}

func TestAbuseHostileLines(t *testing.T) {
	t.Parallel()
	const name = "abuse-lines"
	r, cfg := abuseDaemon(t, name, "max_line_length = 128\n")
	addr := r.d.MainAddr()

	// A 4 KB line without a newline arrives as 128 byte chunks, each an
	// unrecognised command; the bad command limit ends the connection
	// with the final reply after MaxBadCmd of them. Because the close
	// happens with client bytes still unread the kernel aborts the
	// connection (RST) and replies still queued behind the congestion
	// window can be lost, so the tail is checked through the counters.
	conn, br := dialSMTP(t, addr)
	expectLine(t, br, "220 ")
	if _, err := conn.Write([]byte(strings.Repeat("A", 4096))); err != nil {
		t.Fatal(err)
	}
	bad, final := 0, 0
	for {
		line, err := br.ReadString('\n')
		switch {
		case strings.HasPrefix(line, "500 Command unrecognized"):
			bad++
		case strings.HasPrefix(line, "451 Temporary failure"):
			final++
		case line != "":
			t.Fatalf("unexpected reply %q", line)
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("connection not closed after %d bad commands", bad)
			}
			break
		}
	}
	_ = conn.Close()
	if bad > smtp.MaxBadCmd || final > 1 || (final == 1 && bad != smtp.MaxBadCmd) {
		t.Fatalf("%d unrecognised command replies and %d final replies", bad, final)
	}
	c := waitCounters(t, cfg, 5*time.Second, func(c map[string]int64) bool { return c["connections_current"] == 0 })
	if c["replies_grey_total"] != 1 || c["greylist_tuples_total"] != 0 {
		t.Fatalf("after the oversized line: %v", c)
	}

	// Under the bad command limit the connection survives the junk and
	// the newline, and a normal dialogue follows.
	conn, br = dialSMTP(t, addr)
	expectLine(t, br, "220 ")
	if _, err := conn.Write([]byte(strings.Repeat("B", 2048) + "\r\n")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2048/128+1; i++ {
		expectLine(t, br, "500 Command unrecognized")
	}
	greyDialogue(t, conn, br, "mx.survivor", "s@survivor", "rcpt@greyd.test")
	_ = conn.Close()

	// Bytes after a NUL are invisible: the HELO recorded in the tuple
	// stops at the NUL.
	conn, br = dialSMTP(t, addr)
	expectLine(t, br, "220 ")
	fmt.Fprintf(conn, "HELO mx.nul\x00.evil\r\n")
	expectLine(t, br, "250 greyd.test")
	fmt.Fprintf(conn, "MAIL FROM:<s@nul>\r\n")
	expectLine(t, br, "250 OK")
	fmt.Fprintf(conn, "RCPT TO:<rcpt@greyd.test>\r\n")
	expectLine(t, br, "250 OK")
	fmt.Fprintf(conn, "DATA\r\n")
	expectLine(t, br, "451 ")
	_ = conn.Close()

	// A second command smuggled into MAIL FROM behind a bare CR, a bare
	// LF or a CRLF (in the same write) is part of the MAIL line: it gets
	// no reply and no recipient of its own reaches the greylister.
	want := []core.Tuple{
		{IP: "127.0.0.1", Helo: "mx.survivor", From: "s@survivor", To: "rcpt@greyd.test"},
		{IP: "127.0.0.1", Helo: "mx.nul", From: "s@nul", To: "rcpt@greyd.test"},
	}
	for i, sep := range []string{"\r", "\n", "\r\n"} {
		from := fmt.Sprintf("s%d@inject", i)
		conn, br = dialSMTP(t, addr)
		expectLine(t, br, "220 ")
		fmt.Fprintf(conn, "EHLO mx.inject\r\n")
		expectLine(t, br, "250 greyd.test")
		fmt.Fprintf(conn, "MAIL FROM:<%s>%sRCPT TO:<smuggled@greyd.test>\r\n", from, sep)
		expectLine(t, br, "250 OK")
		// A smuggled RCPT's 250 would be read here instead of the 500.
		fmt.Fprintf(conn, "XYZZY\r\n")
		expectLine(t, br, "500 Command unrecognized")
		fmt.Fprintf(conn, "RCPT TO:<real@greyd.test>\r\n")
		expectLine(t, br, "250 OK")
		fmt.Fprintf(conn, "DATA\r\n")
		expectLine(t, br, "451 ")
		_ = conn.Close()
		want = append(want, core.Tuple{IP: "127.0.0.1", Helo: "mx.inject", From: from, To: "real@greyd.test"})
	}
	waitTuples(t, name, want...)
	if c := counters(t, cfg); c["greylist_tuples_total"] != int64(len(want)) {
		t.Fatalf("greylist_tuples_total %d want %d: %v", c["greylist_tuples_total"], len(want), c)
	}
}

func TestAbusePipeliningBeforeBanner(t *testing.T) {
	t.Parallel()
	const name = "abuse-pipeline"
	r, cfg := abuseDaemon(t, name, "")
	addr := r.d.MainAddr()

	// The whole dialogue is sent before anything is read. greyd, like
	// spamd, takes everything up to the first read containing a newline
	// as one command line: the EHLO is answered, the commands behind it
	// are swallowed with it and never executed, so the pipelining client
	// gets no further reply and no tuple is recorded. (The outcome
	// therefore differs from the non-pipelined dialogue below.)
	conn, br := dialSMTP(t, addr)
	fmt.Fprintf(conn, "EHLO mx.pipe\r\nMAIL FROM:<s@pipe>\r\nRCPT TO:<rcpt@greyd.test>\r\nDATA\r\n")
	expectLine(t, br, "220 greyd.test ESMTP")
	expectLine(t, br, "250 greyd.test")
	expectSilence(t, conn, 500*time.Millisecond)
	if got := tuples(t, name); len(got) != 0 {
		t.Fatalf("pipelined commands recorded tuples %+v", got)
	}
	// The connection is still healthy: it answers a command sent now.
	fmt.Fprintf(conn, "QUIT\r\n")
	expectLine(t, br, "221 greyd.test")
	_ = conn.Close()

	// The same commands one at a time, on a fresh connection, produce the
	// replies in order and the tuple.
	conn, br = dialSMTP(t, addr)
	expectLine(t, br, "220 greyd.test ESMTP")
	greyDialogue(t, conn, br, "mx.pipe", "s@pipe", "rcpt@greyd.test")
	_ = conn.Close()
	waitTuples(t, name, core.Tuple{IP: "127.0.0.1", Helo: "mx.pipe", From: "s@pipe", To: "rcpt@greyd.test"})
	if c := counters(t, cfg); c["greylist_tuples_total"] != 1 || c["replies_grey_total"] != 1 {
		t.Fatalf("counters %v", c)
	}
}

func TestAbuseHalfOpenFlood(t *testing.T) {
	t.Parallel()
	const name = "abuse-flood"
	r, cfg := abuseDaemon(t, name, "max_cons = 300\nmax_cons_black = 300\n")
	addr := r.d.MainAddr()

	const flood = 200
	start := time.Now()
	conns := make([]net.Conn, 0, flood)
	for i := 0; i < flood; i++ {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	// Every connection is accepted, counted and released again.
	c := waitCounters(t, cfg, 10*time.Second, func(c map[string]int64) bool {
		return c["connections_total"] >= flood && c["connections_current"] == 0
	})
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("draining %d half-open connections took %v", flood, took)
	}
	if c["connections_refused_total"] != 0 || c["connections_refused_source_total"] != 0 || c["connections_current_black"] != 0 {
		t.Fatalf("counters after the flood: %v", c)
	}
	if got := tuples(t, name); len(got) != 0 {
		t.Fatalf("half-open connections recorded tuples %+v", got)
	}

	conn, br := dialSMTP(t, addr)
	defer conn.Close()
	expectLine(t, br, "220 ")
	greyDialogue(t, conn, br, "mx.after", "s@after", "rcpt@greyd.test")
	waitTuples(t, name, core.Tuple{IP: "127.0.0.1", Helo: "mx.after", From: "s@after", To: "rcpt@greyd.test"})
}

func TestAbuseProxyProtocol(t *testing.T) {
	t.Parallel()
	const name = "abuse-proxy"
	// Only 127.0.0.1 is a permitted proxy so that a second loopback
	// address can play the non-permitted source.
	r, cfg := abuseDaemon(t, name, "proxy_protocol_enable = 1\nproxy_protocol_permitted_proxies = [ \"127.0.0.1/32\" ]\n")
	addr := r.d.MainAddr()

	v4 := func(cmd, fam byte, addrs []byte) string {
		b := append([]byte(nil), smtp.ProxyV2Signature...)
		b = append(b, 0x20|cmd, fam, byte(len(addrs)>>8), byte(len(addrs)))
		return string(append(b, addrs...))
	}
	block := []byte{192, 0, 2, 10, 192, 0, 2, 25, 0x0f, 0xa0, 0, 25}

	// A v1 header longer than the 107 byte maximum is cut there and
	// rejected as malformed.
	conn, br := dialSMTP(t, addr)
	fmt.Fprintf(conn, "PROXY TCP4 %s\r\n", strings.Repeat("1", 200))
	expectLine(t, br, "451 Temporary failure")
	expectClosed(t, conn)

	// A v2 header declaring an address block beyond the cap is dropped
	// before the block is read, without a reply.
	conn, _ = dialSMTP(t, addr)
	fmt.Fprint(conn, string(smtp.ProxyV2Signature)+"\x21\x11\xff\xff")
	expectClosed(t, conn)

	// A v2 header for UDP is treated like PROXY UNKNOWN.
	conn, br = dialSMTP(t, addr)
	fmt.Fprint(conn, v4(0x01, 0x12, block))
	expectLine(t, br, "451 Temporary failure")
	expectClosed(t, conn)

	// A header from a source that is not a permitted proxy is refused,
	// whatever it says.
	if conn, br, ok := dialFrom(t, addr, "127.0.0.2"); ok {
		fmt.Fprintf(conn, "PROXY TCP4 192.0.2.10 192.0.2.25 4000 25\r\n")
		expectLine(t, br, "451 Temporary failure")
		expectClosed(t, conn)
		conn, br = mustDialFrom(t, addr, "127.0.0.2")
		fmt.Fprint(conn, v4(0x01, 0x11, block))
		expectLine(t, br, "451 Temporary failure")
		expectClosed(t, conn)
	}

	c := waitCounters(t, cfg, 5*time.Second, func(c map[string]int64) bool { return c["connections_current"] == 0 })
	if c["proxy_headers_total"] != 0 {
		t.Fatalf("refused headers were counted: %v", c)
	}
	if got := tuples(t, name); len(got) != 0 {
		t.Fatalf("refused headers recorded tuples %+v", got)
	}

	// The daemon keeps serving: a valid header from the permitted proxy
	// runs the dialogue for the real client behind it.
	conn, br = dialSMTP(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "PROXY TCP4 192.0.2.10 192.0.2.25 4000 25\r\n")
	expectLine(t, br, "220 greyd.test")
	greyDialogue(t, conn, br, "mx.proxied", "s@proxied", "rcpt@greyd.test")
	waitTuples(t, name, core.Tuple{IP: "192.0.2.10", Helo: "mx.proxied", From: "s@proxied", To: "rcpt@greyd.test"})
	if c := counters(t, cfg); c["proxy_headers_total"] != 1 {
		t.Fatalf("proxy_headers_total after a valid header: %v", c)
	}
}

func TestAbuseBlacklistedClientStutters(t *testing.T) {
	t.Parallel()
	const name = "abuse-stutter"
	r, cfg := abuseDaemon(t, name, "stutter = 1\n")
	if cfg.Stutter != 1 || cfg.Grey.Stutter != 0 {
		t.Fatalf("stutter %d grey stutter %d", cfg.Stutter, cfg.Grey.Stutter)
	}
	addr := r.d.MainAddr()

	// Blacklist 127.0.0.1 through the configuration socket, as
	// greyd-setup would.
	cc, err := net.Dial("unix", cfg.ConfigSocket)
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteBlacklist(cc, "abusers", "You (%A) are on the abusers list", []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	_ = cc.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		installed := false
		for _, bl := range r.d.snapshotBlacklists() {
			installed = installed || bl.Name == "abusers"
		}
		if installed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("blacklist was not installed")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The blacklisted client is served one byte per second from the
	// banner onwards. Three bytes are enough to see the stutter; the
	// rejection itself is minutes away at this rate (the smtp package
	// test drives a whole stuttered dialogue against a fake clock).
	black, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer black.Close()
	_ = black.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 16)
	n, err := black.Read(buf)
	if err != nil {
		t.Fatalf("blacklisted read: %v", err)
	}
	if n != 1 || buf[0] != '2' {
		t.Fatalf("blacklisted client received %q in one read; expected a single byte", buf[:n])
	}
	first := time.Now()
	got := []byte{buf[0]}
	for len(got) < 3 {
		if _, err := black.Read(buf[:1]); err != nil {
			t.Fatalf("blacklisted read: %v (have %q)", err, got)
		}
		got = append(got, buf[0])
	}
	if string(got) != "220" {
		t.Fatalf("stuttered banner starts %q", got)
	}
	// Two more bytes at one per second: never much under two seconds.
	if spread := time.Since(first); spread < 1500*time.Millisecond {
		t.Fatalf("three banner bytes arrived within %v: not stuttered", spread)
	}

	// A second, non-blacklisted client is served at full speed alongside.
	good, br, ok := dialFrom(t, addr, "127.0.0.2")
	if !ok {
		t.Skip("second loopback address unavailable; the unaffected client needs one")
	}
	defer good.Close()
	start := time.Now()
	expectLine(t, br, "220 greyd.test")
	greyDialogue(t, good, br, "mx.good", "s@good", "rcpt@greyd.test")
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("non-blacklisted dialogue took %v beside a stuttering client", took)
	}
	waitTuples(t, name, core.Tuple{IP: "127.0.0.2", Helo: "mx.good", From: "s@good", To: "rcpt@greyd.test"})
	c := counters(t, cfg)
	if c["connections_current_black"] != 1 || c["connections_black_total"] != 1 || c["replies_grey_total"] != 1 {
		t.Fatalf("counters %v", c)
	}
	if _, err := os.Stat(cfg.GreydPidfile); err != nil {
		t.Fatalf("daemon pidfile: %v", err)
	}
}
