package smtp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/blacklist"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
)

// Adversarial client behaviour against the bare state machine: hostile
// line framing, oversized input, malformed proxy protocol headers and the
// per-byte stutter given to blacklisted clients. Every connection runs
// over a net.Pipe so the tests are independent of TCP segmentation.

// abuseConn starts a served connection for the client at src.
func abuseConn(t *testing.T, h *harness, src string) (net.Conn, *Conn, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	c := reserveConn(server, netip.MustParseAddrPort(src), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done := make(chan struct{})
	go func() { c.Serve(); close(done) }()
	t.Cleanup(func() { _ = client.Close() })
	return client, c, done
}

// greyMessages decodes every tuple the harness sent to the greylister.
func greyMessages(t *testing.T, h *harness) []*ipc.GreyMessage {
	t.Helper()
	rd := ipc.NewReader(bytes.NewReader(h.greyOut.Bytes()))
	var out []*ipc.GreyMessage
	for {
		m, err := rd.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("grey pipe: %v", err)
		}
		g, ok := m.(*ipc.GreyMessage)
		if !ok {
			t.Fatalf("unexpected message on the grey pipe: %T", m)
		}
		out = append(out, g)
	}
}

// waitClosed waits for the connection goroutine to finish.
func waitClosed(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not close")
	}
}

func TestAbuseOversizedLineIsChunkedAtLimit(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	h.cfg.MaxLineLength = 128

	// A 4 KB line without a newline is consumed in max_line_length sized
	// chunks, each an unrecognised command. Past MaxBadCmd of them the
	// connection receives the final reply and is closed: the bad command
	// limit, not the line, ends the dialogue.
	client, c, done := abuseConn(t, h, "10.10.10.9:5555")
	br := newLineReader(client)
	expect(t, br, "220 ")
	go func() { _, _ = io.WriteString(client, strings.Repeat("A", 4096)) }()
	for i := 0; i < MaxBadCmd; i++ {
		expect(t, br, "500 Command unrecognized")
	}
	expect(t, br, "451 Temporary failure")
	waitClosed(t, done)
	if !c.Closed() {
		t.Fatal("connection must be closed after too many chunks")
	}

	// A 2 KB line stays under the bad command limit (16 chunks plus the
	// empty remainder once the newline arrives); the connection survives
	// and a normal dialogue follows on the same connection.
	client, c, done = abuseConn(t, h, "10.10.10.9:5556")
	br = newLineReader(client)
	expect(t, br, "220 ")
	go func() { _, _ = io.WriteString(client, strings.Repeat("B", 2048)+"\r\n") }()
	for i := 0; i < 2048/128+1; i++ {
		expect(t, br, "500 Command unrecognized")
	}
	send(t, client, "EHLO survivor\r\n")
	expect(t, br, "250 greyd.org")
	send(t, client, "MAIL FROM:<a@b>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "RCPT TO:<c@d>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "DATA\r\n")
	expect(t, br, "451 Temporary failure")
	waitClosed(t, done)
	if c.Helo != "survivor" {
		t.Fatalf("helo %q", c.Helo)
	}
	msgs := greyMessages(t, h)
	if len(msgs) != 1 || msgs[0].Tuple.Helo != "survivor" || msgs[0].Tuple.From != "a@b" || msgs[0].Tuple.To != "c@d" {
		t.Fatalf("grey messages %+v", msgs)
	}
}

func TestAbuseNULTruncatesLine(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	client, c, done := abuseConn(t, h, "10.10.10.9:5555")
	br := newLineReader(client)
	expect(t, br, "220 ")
	send(t, client, "HELO mx.example\x00.evil\r\n")
	expect(t, br, "250 greyd.org")
	if c.Helo != "mx.example" {
		t.Fatalf("helo %q: bytes after a NUL must be ignored", c.Helo)
	}
	send(t, client, "MAIL FROM:<a@b>\x00<evil@x>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "RCPT TO:<c@d>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 ")
	waitClosed(t, done)
	msgs := greyMessages(t, h)
	if len(msgs) != 1 || msgs[0].Tuple.Helo != "mx.example" || msgs[0].Tuple.From != "a@b" || msgs[0].Tuple.To != "c@d" {
		t.Fatalf("grey messages %+v", msgs)
	}
}

func TestAbuseLineTerminatorInjection(t *testing.T) {
	// A MAIL FROM carrying a second command behind a bare CR, a bare LF or
	// a CRLF delivered in the same write is one command: the smuggled RCPT
	// is neither answered nor recorded.
	variants := []struct {
		name, line string
	}{
		{"bare CR", "MAIL FROM:<a@b>\rRCPT TO:<x@y>\r\n"},
		{"bare LF", "MAIL FROM:<a@b>\nRCPT TO:<x@y>\r\n"},
		{"CRLF", "MAIL FROM:<a@b>\r\nRCPT TO:<x@y>\r\n"},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			h := newHarness(t, 100, 100)
			h.cfg.Stutter = 0
			client, c, done := abuseConn(t, h, "10.10.10.9:5555")
			br := newLineReader(client)
			expect(t, br, "220 ")
			send(t, client, "EHLO x\r\n")
			expect(t, br, "250 greyd.org")
			send(t, client, v.line)
			expect(t, br, "250 OK")
			// If the smuggled RCPT had been executed its 250 would be
			// read here instead of the 500 for the probe.
			send(t, client, "XYZZY\r\n")
			expect(t, br, "500 Command unrecognized")
			if c.Mail != "a@b" || c.Rcpt != "" {
				t.Fatalf("mail %q rcpt %q after injection", c.Mail, c.Rcpt)
			}
			send(t, client, "RCPT TO:<real@r>\r\n")
			expect(t, br, "250 OK")
			send(t, client, "QUIT\r\n")
			expect(t, br, "221 ")
			waitClosed(t, done)
			msgs := greyMessages(t, h)
			if len(msgs) != 1 || msgs[0].Tuple.From != "a@b" || msgs[0].Tuple.To != "real@r" {
				t.Fatalf("grey messages %+v", msgs)
			}
		})
	}
}

func TestAbuseProxyHeadersRefused(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	h.cfg.ProxyProtocol = true
	h.cfg.PermittedProxies = blacklist.New("permitted-proxies", "", blacklist.StorageList)
	_ = h.cfg.PermittedProxies.Add("127.0.0.0/8")

	v4 := proxyV2Addrs("192.0.2.10", "192.0.2.25", 4000, 25)
	cases := []struct {
		name  string
		src   string
		hdr   string
		reply bool // a 451 precedes the close
	}{
		{"v1 longer than 107 bytes", "127.0.0.1:5555", "PROXY TCP4 " + strings.Repeat("1", 200) + "\r\n", true},
		{"v2 huge length", "127.0.0.1:5555", string(ProxyV2Signature) + "\x21\x11\xff\xff", false},
		{"v2 udp", "127.0.0.1:5555", string(proxyV2(0x01, 0x12, v4)), true},
		{"non-permitted source", "192.0.2.1:5555", "PROXY TCP4 192.0.2.10 192.0.2.25 4000 25\r\n", true},
		{"v2 from non-permitted source", "192.0.2.1:5555", string(proxyV2(0x01, 0x11, v4)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, c, done := abuseConn(t, h, tc.src)
			go func() { _, _ = io.WriteString(client, tc.hdr) }()
			br := newLineReader(client)
			if tc.reply {
				expect(t, br, "451 Temporary failure")
			}
			waitClosed(t, done)
			if !c.Closed() {
				t.Fatal("connection must be closed")
			}
			if c.SrcAddr != netip.MustParseAddrPort(tc.src).Addr().String() {
				t.Fatalf("source address %q adopted from a refused header", c.SrcAddr)
			}
		})
	}
	if n := h.counters.Totals().ProxyHeaders; n != 0 {
		t.Fatalf("proxy headers counted for refused headers: %d", n)
	}
	if cl, _, _, _ := h.counters.Snapshot(); cl != 0 {
		t.Fatalf("connections left behind: %d", cl)
	}

	// The state machine still serves a well-formed header afterwards.
	client, c, done := abuseConn(t, h, "127.0.0.1:5555")
	br := newLineReader(client)
	send(t, client, "PROXY TCP4 192.0.2.10 192.0.2.25 4000 25\r\n")
	expect(t, br, "220 ")
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 ")
	waitClosed(t, done)
	if c.SrcAddr != "192.0.2.10" || h.counters.Totals().ProxyHeaders != 1 {
		t.Fatalf("good header after abuse: src %q headers %d", c.SrcAddr, h.counters.Totals().ProxyHeaders)
	}
}

// recordingConn records the size of every write on a net.Conn.
type recordingConn struct {
	net.Conn
	mu    sync.Mutex
	sizes []int
}

func (r *recordingConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.sizes = append(r.sizes, len(p))
	r.mu.Unlock()
	return r.Conn.Write(p)
}

func (r *recordingConn) writes() (n, total, largest int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sizes {
		total += s
		if s > largest {
			largest = s
		}
	}
	return len(r.sizes), total, largest
}

func TestAbuseBlacklistedClientStuttersByteByByte(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 1
	h.cfg.GreyStutter = 0 // greylisted clients are served at full speed

	run := func(src string, dialogue func(br *lineReader, w io.Writer)) (*recordingConn, *Conn) {
		client, server := net.Pipe()
		rc := &recordingConn{Conn: server}
		c := reserveConn(rc, netip.MustParseAddrPort(src), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
		done := make(chan struct{})
		go func() { c.Serve(); close(done) }()
		dialogue(newLineReader(client), client)
		waitClosed(t, done)
		_ = client.Close()
		return rc, c
	}
	full := func(final string) func(br *lineReader, w io.Writer) {
		return func(br *lineReader, w io.Writer) {
			expect(t, br, "220 ")
			send(t, w, "HELO x\r\n")
			expect(t, br, "250 greyd.org")
			send(t, w, "MAIL FROM:<a@b>\r\n")
			expect(t, br, "250 OK")
			send(t, w, "RCPT TO:<c@d>\r\n")
			expect(t, br, "250 OK")
			send(t, w, "DATA\r\n")
			expect(t, br, final)
		}
	}

	// Blacklisted: the banner, every intermediate reply and the rejection
	// leave one byte per write, with a stutter interval slept between
	// bytes.
	start := h.clock.Now()
	black, c := run("10.10.10.1:5555", func(br *lineReader, w io.Writer) {
		full("354 End data")(br, w)
		send(t, w, ".\r\n")
		expect(t, br, "450-You (10.10.10.1) are on blacklist 1")
		expect(t, br, "450 You (10.10.10.1) are on blacklist 2")
	})
	if !c.IsBlacklisted() {
		t.Fatal("10.10.10.1 must be blacklisted")
	}
	n, total, largest := black.writes()
	if largest != 1 || n != total {
		t.Fatalf("blacklisted client: %d writes for %d bytes, largest %d", n, total, largest)
	}
	// Six replies: each byte but the last of a reply is followed by a
	// one second sleep.
	if slept := h.clock.Now().Sub(start); slept < time.Duration(total-6)*time.Second {
		t.Fatalf("stutter slept %v for %d bytes", slept, total)
	}

	// Greylisted: whole replies, no sleeping.
	start = h.clock.Now()
	grey, c := run("10.0.0.9:5555", full("451 Temporary failure"))
	if c.IsBlacklisted() {
		t.Fatal("10.0.0.9 must not be blacklisted")
	}
	n, _, largest = grey.writes()
	if n != 5 || largest < 10 {
		t.Fatalf("greylisted client: %d writes, largest %d", n, largest)
	}
	if slept := h.clock.Now().Sub(start); slept != 0 {
		t.Fatalf("greylisted client slept %v", slept)
	}
}

// TestAbuseOverlongV1ProxyHeaderRefused: a first line whose 107-byte prefix
// is a valid v1 header but which has no CRLF within the limit is refused
// as a whole rather than accepted with its tail read as a command.
func TestAbuseOverlongV1ProxyHeaderRefused(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	h.cfg.ProxyProtocol = true
	h.cfg.PermittedProxies = blacklist.New("permitted-proxies", "", blacklist.StorageList)
	_ = h.cfg.PermittedProxies.Add("127.0.0.0/8")
	client, c, done := abuseConn(t, h, "127.0.0.1:5555")
	header := "PROXY TCP4 10.10.10.9 10.0.0.25 4000 25" + strings.Repeat(" ", 200) + "\r\n"
	go func() { _, _ = io.WriteString(client, header) }()
	// Refused like any invalid header: the temporary failure, then close.
	expect(t, newLineReader(client), "451 Temporary failure")
	waitClosed(t, done)
	if !c.Closed() {
		t.Fatal("connection with an overlong v1 header stayed open")
	}
	if c.SrcAddr == "10.10.10.9" {
		t.Fatal("padded header must not be honoured")
	}
	if n := h.counters.Totals().ProxyHeaders; n != 0 {
		t.Fatalf("overlong header counted as accepted: %d", n)
	}
}

// TestReserveConcurrent checks that concurrent reservations never exceed
// the global or per-source limits (the check and the increment are
// atomic), the counters end balanced, and refusals are counted.
func TestReserveConcurrent(t *testing.T) {
	t.Parallel()
	c := NewCounters(50, 50)
	c.MaxConsPerSource = 3
	var wg sync.WaitGroup
	var granted, refused int64
	// Two source addresses, 400 racing attempts.
	for i := 0; i < 400; i++ {
		wg.Add(1)
		src := netip.AddrFrom4([4]byte{10, 0, 0, byte(i % 2)})
		go func() {
			defer wg.Done()
			if c.reserve(src) {
				atomic.AddInt64(&granted, 1)
			} else {
				atomic.AddInt64(&refused, 1)
			}
		}()
	}
	wg.Wait()
	clients, _, maxCons, _ := c.Snapshot()
	// Per-source cap 3 over two sources bounds grants at 6, well under 50.
	if granted != 6 {
		t.Fatalf("granted %d, want 6 (2 sources x cap 3)", granted)
	}
	if clients != int(granted) || clients > maxCons {
		t.Fatalf("clients %d, granted %d, maxCons %d", clients, granted, maxCons)
	}
	if granted+refused != 400 {
		t.Fatalf("granted %d + refused %d != 400", granted, refused)
	}
	if got := c.Totals().RefusedSource; got != refused {
		t.Fatalf("refused_source %d, want %d", got, refused)
	}
	// A global-limit race: 200 attempts from distinct sources, cap 50.
	c2 := NewCounters(50, 50)
	var g2 int64
	for i := 0; i < 200; i++ {
		wg.Add(1)
		src := netip.AddrFrom4([4]byte{10, 1, byte(i / 256), byte(i)})
		go func() {
			defer wg.Done()
			if c2.reserve(src) {
				atomic.AddInt64(&g2, 1)
			}
		}()
	}
	wg.Wait()
	if g2 != 50 {
		t.Fatalf("global cap: granted %d, want 50", g2)
	}
	if cl, _, _, _ := c2.Snapshot(); cl != 50 {
		t.Fatalf("clients %d, want 50", cl)
	}
}
