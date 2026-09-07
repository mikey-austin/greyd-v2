package smtp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/blacklist"
	"github.com/mikey-austin/greyd-v2/internal/config/parse"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

var fixedNow = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// fakeClock lets tests advance time without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Sleep(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func testLists() []*blacklist.Blacklist {
	bl1 := blacklist.New("blacklist_1", "You (%A) are on blacklist 1", blacklist.StorageTrie)
	bl2 := blacklist.New("blacklist_2", "You (%A) are on blacklist 2", blacklist.StorageTrie)
	bl3 := blacklist.New("blacklist_3_with_an_enormously_big_long_long_epic_epicly_long_large_name",
		`Your address %A\nis on blacklist 3`, blacklist.StorageTrie)
	_ = bl1.Add("10.10.10.1/32")
	_ = bl1.Add("10.10.10.2/32")
	_ = bl2.Add("10.10.10.1/32")
	_ = bl2.Add("10.10.10.2/32")
	_ = bl2.Add("2001::fad3:1/128")
	_ = bl3.Add("10.10.10.2/32")
	_ = bl3.Add("10.10.10.3/32")
	_ = bl3.Add("2001::fad3:1/128")
	return []*blacklist.Blacklist{bl1, bl2, bl3}
}

func testConfig(t testing.TB) Config {
	t.Helper()
	cfg, err := parse.String(`hostname = "greyd.org"
banner   = "greyd IP-based SPAM blocker"
section grey {
  enable           = 1,
  traplist_name    = "test traplist",
  traplist_message = "you have been trapped",
  grey_expiry      = 3600,
  stutter          = 15
}`)
	if err != nil {
		t.Fatal(err)
	}
	st, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ConfigFrom(st)
}

type harness struct {
	cfg      Config
	deps     Deps
	counters *Counters
	clock    *fakeClock
	greyOut  *bytes.Buffer
	lists    []*blacklist.Blacklist
}

func newHarness(t testing.TB, maxCons, maxBlack int) *harness {
	h := &harness{cfg: testConfig(t), clock: &fakeClock{now: fixedNow}, greyOut: &bytes.Buffer{}, lists: testLists()}
	h.counters = NewCounters(maxCons, maxBlack)
	h.deps = Deps{
		Blacklists: func() []*blacklist.Blacklist { return h.lists },
		GreyOut:    h.greyOut,
		OrigDst:    func(src, local netip.AddrPort) string { return "10.0.0.25" },
		Now:        h.clock.Now,
		Sleep:      h.clock.Sleep,
	}
	return h
}

// rwBuf is an in-memory ReadWriter: reads come from in, writes go to out.
type rwBuf struct {
	in  *bytes.Buffer
	out *bytes.Buffer
}

func (r *rwBuf) Read(p []byte) (int, error)  { return r.in.Read(p) }
func (r *rwBuf) Write(p []byte) (int, error) { return r.out.Write(p) }

func TestConnInitAndClose(t *testing.T) {
	h := newHarness(t, 4, 4)
	rw := &rwBuf{in: &bytes.Buffer{}, out: &bytes.Buffer{}}
	c := NewConn(rw, netip.MustParseAddrPort("10.10.10.1:1234"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)

	if c.State != StateBannerOut || c.LastState != StateBannerIn {
		t.Fatalf("states %d/%d", c.State, c.LastState)
	}
	if len(c.Lists) != 2 {
		t.Fatalf("blacklist matches %d", len(c.Lists))
	}
	if c.SrcAddr != "10.10.10.1" {
		t.Fatalf("src addr %q", c.SrcAddr)
	}
	if c.ListSummary != "blacklist_1 blacklist_2" {
		t.Fatalf("summary %q", c.ListSummary)
	}
	// "220 greyd.org ESMTP greyd IP-based SPAM blocker; Sun Sep  6 12:00:00 2026\r\n"
	if c.OutRemaining() != 75 {
		t.Fatalf("banner length %d: %q", c.OutRemaining(), c.Out)
	}
	if cl, bl, _, _ := h.counters.Snapshot(); cl != 1 || bl != 1 {
		t.Fatalf("counters %d/%d", cl, bl)
	}

	c.Close()
	if len(c.Lists) != 0 || c.Out != nil || c.ListSummary != "" {
		t.Fatal("close did not release resources")
	}
	if cl, bl, _, _ := h.counters.Snapshot(); cl != 0 || bl != 0 {
		t.Fatalf("counters after close %d/%d", cl, bl)
	}
	c.Close() // idempotent
}

func TestSummaryTruncationAndReply(t *testing.T) {
	h := newHarness(t, 4, 4)
	rw := &rwBuf{in: &bytes.Buffer{}, out: &bytes.Buffer{}}
	c := NewConn(rw, netip.MustParseAddrPort("[2001::fad3:1]:1234"), netip.MustParseAddrPort("[::1]:8025"), h.cfg, h.deps, h.counters)
	if len(c.Lists) != 2 || c.SrcAddr != "2001::fad3:1" {
		t.Fatalf("lists %d src %q", len(c.Lists), c.SrcAddr)
	}
	if c.ListSummary != "blacklist_2 ..." {
		t.Fatalf("summary %q", c.ListSummary)
	}
	if c.OutRemaining() != 75 {
		t.Fatalf("banner length %d", c.OutRemaining())
	}

	c.BuildReply("451")
	// Every line is CRLF terminated however the reply is written.
	want := "451-You (2001::fad3:1) are on blacklist 2\r\n" +
		"451-Your address 2001::fad3:1\r\n" +
		"451 is on blacklist 3\r\n"
	if string(c.Out) != want {
		t.Fatalf("reply %q\nwant %q", c.Out, want)
	}
	if c.OutRemaining() != 97 {
		t.Fatalf("remaining %d", c.OutRemaining())
	}

	// Write without stuttering: clients + tolerance >= max_cons, so the
	// whole buffer goes out at once, CRLF terminated.
	c.HandleWrite()
	if rw.out.String() != want {
		t.Fatalf("unstuttered write %q", rw.out.String())
	}

	// Write with stuttering: one byte at a time, same bytes on the wire.
	rw.out.Reset()
	c.w = false
	c.BuildReply("451")
	h.counters.MaxCons, h.counters.MaxBlack = 100, 100
	for rw.out.Len() < len(want) && !c.Closed() {
		c.HandleWrite()
	}
	if rw.out.String() != want {
		t.Fatalf("stuttered write %q\nwant %q", rw.out.String(), want)
	}
	// Each stuttered byte slept for the stutter interval.
	if h.clock.Now().Sub(fixedNow) < time.Duration(len(want)-1)*time.Second {
		t.Fatalf("stutter did not sleep: advanced %v", h.clock.Now().Sub(fixedNow))
	}
	c.Close()
}

func TestGreylistedReplyIsAlways451(t *testing.T) {
	h := newHarness(t, 100, 100)
	rw := &rwBuf{in: &bytes.Buffer{}, out: &bytes.Buffer{}}
	c := NewConn(rw, netip.MustParseAddrPort("[fa40::fad3:1]:1234"), netip.MustParseAddrPort("[::1]:8025"), h.cfg, h.deps, h.counters)
	if len(c.Lists) != 0 || c.IsBlacklisted() {
		t.Fatal("should not be blacklisted")
	}
	c.BuildReply("551")
	if string(c.Out) != GreyReply {
		t.Fatalf("grey reply %q", c.Out)
	}
	c.Close()
}

// dialogue runs a full SMTP conversation over net.Pipe and returns the
// server's output.
func TestDialogueGreylisted(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	client, server := net.Pipe()
	defer client.Close()

	c := NewConn(server, netip.MustParseAddrPort("10.10.10.9:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done := make(chan struct{})
	go func() { c.Serve(); close(done) }()

	br := newLineReader(client)
	expect(t, br, "220 greyd.org ESMTP greyd IP-based SPAM blocker; ")
	send(t, client, "EHLO greyd.org\r\n")
	expect(t, br, "250 greyd.org")
	send(t, client, "MAIL FROM: <Mikey@greyd.ORG>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "RCPT TO: info@greyd.org\r\n")
	expect(t, br, "250 OK")
	// Greylisted clients are rejected as soon as DATA arrives; the 354
	// is never sent (Con_next_state overwrites it with the reply).
	send(t, client, "DATA\r\n")
	expect(t, br, "451 Temporary failure, please try again later.")
	<-done

	if c.Helo != "greyd.org" || c.Mail != "mikey@greyd.org" || c.Rcpt != "info@greyd.org" {
		t.Fatalf("parsed helo=%q mail=%q rcpt=%q", c.Helo, c.Mail, c.Rcpt)
	}
	m, err := ipc.NewReader(bytes.NewReader(h.greyOut.Bytes())).Next()
	if err != nil {
		t.Fatalf("grey message: %v", err)
	}
	g, ok := m.(*ipc.GreyMessage)
	if !ok || g.DstIP != "10.0.0.25" ||
		g.Tuple != (core.Tuple{IP: "10.10.10.9", Helo: "greyd.org", From: "mikey@greyd.org", To: "info@greyd.org"}) {
		t.Fatalf("grey message content wrong: %s", h.greyOut.String())
	}
	if cl, _, _, _ := h.counters.Snapshot(); cl != 0 {
		t.Fatalf("clients after close %d", cl)
	}
}

func TestDialogueBlacklistedFullMessage(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	h.cfg.ErrorCode = "550"
	client, server := net.Pipe()
	defer client.Close()

	c := NewConn(server, netip.MustParseAddrPort("10.10.10.1:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done := make(chan struct{})
	go func() { c.Serve(); close(done) }()

	br := newLineReader(client)
	expect(t, br, "220 ")
	send(t, client, "HELO x\r\n")
	expect(t, br, "250 greyd.org")
	send(t, client, "MAIL FROM:<a@b.c>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "RCPT TO:<d@e.f>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "NOOP\r\n")
	expect(t, br, "250 OK")
	send(t, client, "BOGUS\r\n")
	expect(t, br, "500 Command unrecognized")
	send(t, client, "DATA\r\n")
	expect(t, br, "354 End data with <CR><LF>.<CR><LF>")
	send(t, client, "Subject: spam\r\n\r\nline one\r\n.\r\n")
	expect(t, br, "550-You (10.10.10.1) are on blacklist 1")
	expect(t, br, "550 You (10.10.10.1) are on blacklist 2")
	<-done
	if h.greyOut.Len() != 0 {
		t.Fatal("blacklisted connections must not be sent to the greylister")
	}
}

func TestQuitAndRset(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	client, server := net.Pipe()
	defer client.Close()
	c := NewConn(server, netip.MustParseAddrPort("10.10.10.9:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done := make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br := newLineReader(client)
	expect(t, br, "220 ")
	send(t, client, "EHLO a\r\n")
	expect(t, br, "250 greyd.org")
	send(t, client, "MAIL FROM:<x@y.z>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "RSET\r\n")
	expect(t, br, "250 OK")
	send(t, client, "MAIL FROM:<x@y.z>\r\n") // accepted again after RSET
	expect(t, br, "250 OK")
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 greyd.org")
	<-done
	if !c.Closed() {
		t.Fatal("connection should be closed after QUIT")
	}
}

func TestTooManyBadCommands(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	client, server := net.Pipe()
	defer client.Close()
	c := NewConn(server, netip.MustParseAddrPort("10.10.10.9:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done := make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br := newLineReader(client)
	expect(t, br, "220 ")
	send(t, client, "EHLO a\r\n")
	expect(t, br, "250 greyd.org")
	for i := 0; i < MaxBadCmd; i++ {
		send(t, client, "XYZZY\r\n")
		expect(t, br, "500 Command unrecognized")
	}
	// The 21st unrecognised command receives the final reply instead.
	send(t, client, "XYZZY\r\n")
	expect(t, br, "451 Temporary failure, please try again later.")
	<-done
}

func TestEmptyHelo(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	client, server := net.Pipe()
	defer client.Close()
	c := NewConn(server, netip.MustParseAddrPort("10.10.10.9:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	go c.Serve()
	br := newLineReader(client)
	expect(t, br, "220 ")
	send(t, client, "HELO\r\n")
	expect(t, br, "501 Syntax: HELO hostname")
	send(t, client, "EHLO   mx.example.org  extra\r\n")
	expect(t, br, "250 greyd.org")
	if c.Helo != "mx.example.org" {
		t.Fatalf("helo %q", c.Helo)
	}
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 greyd.org")
}

func TestClientDisconnectMidDialogue(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	client, server := net.Pipe()
	c := NewConn(server, netip.MustParseAddrPort("10.10.10.9:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done := make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br := newLineReader(client)
	expect(t, br, "220 ")
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not notice disconnect")
	}
	if cl, _, _, _ := h.counters.Snapshot(); cl != 0 {
		t.Fatalf("clients after disconnect %d", cl)
	}
}

func TestGreyStutterCutoff(t *testing.T) {
	h := newHarness(t, 100, 100)
	rw := &rwBuf{in: &bytes.Buffer{}, out: &bytes.Buffer{}}
	c := NewConn(rw, netip.MustParseAddrPort("10.10.10.9:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	if c.Stutter != 1 {
		t.Fatalf("initial stutter %d", c.Stutter)
	}
	// Advance beyond the grey stutter window (15 s in the test config).
	h.clock.Sleep(16 * time.Second)
	c.HandleWrite()
	if c.Stutter != 0 {
		t.Fatal("stutter should stop after grey stutter window")
	}
	if c.OutRemaining() != 0 {
		t.Fatal("whole banner should be written once stutter stops")
	}
	c.Close()

	// With grey.stutter = 0 greylisted connections never stutter.
	h.cfg.GreyStutter = 0
	c = NewConn(rw, netip.MustParseAddrPort("10.10.10.9:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	if c.Stutter != 0 {
		t.Fatal("grey stutter 0 should disable stuttering")
	}
	c.Close()

	// Blacklisted connections abandon stuttering beyond max_black.
	h.cfg.GreyStutter = 15
	h.counters.MaxBlack = 0
	c = NewConn(rw, netip.MustParseAddrPort("10.10.10.1:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	if c.Stutter != 0 {
		t.Fatal("too many black clients should abandon stutter")
	}
	c.Close()
}

func TestProxyProtocol(t *testing.T) {
	cases := []struct {
		line     string
		src, dst string
		err      error
	}{
		{"PROXY TCP4 1.2.3.4 5.6.7.8 1 2", "1.2.3.4", "5.6.7.8", nil},
		{"PROXY TCP6 2001:db8::1 2001:db8::2 1 2", "2001:db8::1", "2001:db8::2", nil},
		{"PROXY   TCP4   1.2.3.4   5.6.7.8   1   2", "1.2.3.4", "5.6.7.8", nil},
		{"PROXY UNKNOWN", "", "", ErrProxyUnknown},
		{"PROXY TCP4 x y 1 2", "", "", ErrProxyInvalid},
		{"PROXY TCP4 2001::1 5.6.7.8 1 2", "", "", ErrProxyInvalid},
		{"PROXY TCP7 1.2.3.4 5.6.7.8 1 2", "", "", ErrProxyInvalid},
		{"PROXY TCP4 1.2.3.4", "", "", ErrProxyInvalid},
		{"HELO", "", "", ErrProxyInvalid},
	}
	for _, tc := range cases {
		src, dst, err := ParseProxyHeader(tc.line)
		if !errors.Is(err, tc.err) {
			t.Fatalf("%q: err %v want %v", tc.line, err, tc.err)
		}
		if err == nil && (src.String() != tc.src || dst.String() != tc.dst) {
			t.Fatalf("%q: %s %s", tc.line, src, dst)
		}
	}
}

func TestProxyProtocolDialogue(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	h.cfg.ProxyProtocol = true
	h.cfg.PermittedProxies = blacklist.New("permitted-proxies", "", blacklist.StorageList)
	_ = h.cfg.PermittedProxies.Add("127.0.0.0/8")

	// Permitted proxy: the real client (blacklisted 10.10.10.1) is used.
	client, server := net.Pipe()
	c := NewConn(server, netip.MustParseAddrPort("127.0.0.1:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	if c.State != StateProxyOut {
		t.Fatalf("initial proxy state %d", c.State)
	}
	done := make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br := newLineReader(client)
	send(t, client, "PROXY TCP4 10.10.10.1 10.0.0.25 4000 25\r\n")
	expect(t, br, "220 greyd.org")
	if c.SrcAddr != "10.10.10.1" || c.DstAddr != "10.0.0.25" {
		t.Fatalf("proxied addresses %q %q", c.SrcAddr, c.DstAddr)
	}
	if !c.IsBlacklisted() || len(c.Lists) != 2 {
		t.Fatal("blacklists must be matched against the proxied client")
	}
	if _, bl, _, _ := h.counters.Snapshot(); bl != 1 {
		t.Fatalf("black clients %d", bl)
	}
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 greyd.org")
	<-done
	_ = client.Close()
	if _, bl, _, _ := h.counters.Snapshot(); bl != 0 {
		t.Fatalf("black clients after close %d", bl)
	}

	// Non-permitted proxy: rejected with the error reply.
	client, server = net.Pipe()
	c = NewConn(server, netip.MustParseAddrPort("192.0.2.1:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done = make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br = newLineReader(client)
	send(t, client, "PROXY TCP4 10.10.10.9 10.0.0.25 4000 25\r\n")
	expect(t, br, "451 Temporary failure")
	<-done
	_ = client.Close()

	// UNKNOWN header: rejected.
	client, server = net.Pipe()
	c = NewConn(server, netip.MustParseAddrPort("127.0.0.1:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done = make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br = newLineReader(client)
	send(t, client, "PROXY UNKNOWN\r\n")
	expect(t, br, "451 Temporary failure")
	<-done
	_ = client.Close()

	// Proxied greylisted client: dst_ip comes from the header, not the
	// firewall lookup.
	client, server = net.Pipe()
	c = NewConn(server, netip.MustParseAddrPort("127.0.0.1:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	done = make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br = newLineReader(client)
	send(t, client, "PROXY TCP4 10.10.10.9 192.0.2.99 4000 25\r\n")
	expect(t, br, "220 ")
	send(t, client, "EHLO a\r\nMAIL FROM:<a@b>\r\n")
	expect(t, br, "250 greyd.org")
	send(t, client, "MAIL FROM:<a@b>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "RCPT TO:<c@d>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 ")
	<-done
	_ = client.Close()
	m, err := ipc.NewReader(bytes.NewReader(h.greyOut.Bytes())).Next()
	if g, ok := m.(*ipc.GreyMessage); err != nil || !ok || g.DstIP != "192.0.2.99" || g.Tuple.IP != "10.10.10.9" {
		t.Fatalf("proxied grey message: %v %s", err, h.greyOut.String())
	}
}

// proxyV2 builds a proxy protocol v2 header.
func proxyV2(cmd, fam byte, addrs []byte) []byte {
	b := append([]byte(nil), ProxyV2Signature...)
	b = append(b, 0x20|cmd, fam, byte(len(addrs)>>8), byte(len(addrs)))
	return append(b, addrs...)
}

// proxyV2Addrs encodes a TCP address block for the given family.
func proxyV2Addrs(src, dst string, sport, dport uint16) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	b := append(s.AsSlice(), d.AsSlice()...)
	return append(b, byte(sport>>8), byte(sport), byte(dport>>8), byte(dport))
}

func TestProxyProtocolV2(t *testing.T) {
	v4 := proxyV2Addrs("1.2.3.4", "5.6.7.8", 4000, 25)
	v6 := proxyV2Addrs("2001:db8::1", "2001:db8::2", 4000, 25)
	tlv := append(append([]byte(nil), v4...), 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef) // PP2_TYPE_CRC32C
	big := proxyV2(0x01, 0x11, make([]byte, MaxProxyV2Length+1))
	cases := []struct {
		name     string
		hdr      []byte
		src, dst string
		local    bool
		err      error
	}{
		{"ipv4", proxyV2(0x01, 0x11, v4), "1.2.3.4", "5.6.7.8", false, nil},
		{"ipv6", proxyV2(0x01, 0x21, v6), "2001:db8::1", "2001:db8::2", false, nil},
		{"tlvs skipped", proxyV2(0x01, 0x11, tlv), "1.2.3.4", "5.6.7.8", false, nil},
		{"local unspec", proxyV2(0x00, 0x00, nil), "", "", true, nil},
		{"local with addresses", proxyV2(0x00, 0x11, v4), "", "", true, nil},
		{"unspec", proxyV2(0x01, 0x00, nil), "", "", false, ErrProxyUnknown},
		{"udp4", proxyV2(0x01, 0x12, v4), "", "", false, ErrProxyUnknown},
		{"udp6", proxyV2(0x01, 0x22, v6), "", "", false, ErrProxyUnknown},
		{"unix stream", proxyV2(0x01, 0x31, make([]byte, 216)), "", "", false, ErrProxyUnknown},
		{"unix dgram", proxyV2(0x01, 0x32, make([]byte, 216)), "", "", false, ErrProxyUnknown},
		{"bad family", proxyV2(0x01, 0x41, v4), "", "", false, ErrProxyInvalid},
		{"bad protocol", proxyV2(0x01, 0x13, v4), "", "", false, ErrProxyInvalid},
		{"bad command", proxyV2(0x02, 0x11, v4), "", "", false, ErrProxyInvalid},
		{"bad version", append(append([]byte(nil), ProxyV2Signature...), 0x10, 0x11, 0x00, 0x0c, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2), "", "", false, ErrProxyInvalid},
		{"bad signature", append([]byte("\r\n\r\n\x00\r\nQUIT\r"), proxyV2(0x01, 0x11, v4)[12:]...), "", "", false, ErrProxyInvalid},
		{"v1 text", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"), "", "", false, ErrProxyInvalid},
		{"empty", nil, "", "", false, ErrProxyInvalid},
		{"truncated signature", ProxyV2Signature[:8], "", "", false, ErrProxyInvalid},
		{"truncated fixed header", proxyV2(0x01, 0x11, v4)[:15], "", "", false, ErrProxyInvalid},
		{"truncated addresses", proxyV2(0x01, 0x11, v4)[:20], "", "", false, ErrProxyInvalid},
		{"short ipv4 block", proxyV2(0x01, 0x11, v4[:8]), "", "", false, ErrProxyInvalid},
		{"short ipv6 block", proxyV2(0x01, 0x21, v6[:32]), "", "", false, ErrProxyInvalid},
		{"trailing bytes", append(proxyV2(0x01, 0x11, v4), 'E', 'H'), "", "", false, ErrProxyInvalid},
		{"length too large", big, "", "", false, ErrProxyInvalid},
	}
	for _, tc := range cases {
		src, dst, local, err := ParseProxyHeaderV2(tc.hdr)
		if !errors.Is(err, tc.err) {
			t.Fatalf("%s: err %v want %v", tc.name, err, tc.err)
		}
		if err != nil {
			continue
		}
		if local != tc.local {
			t.Fatalf("%s: local %v want %v", tc.name, local, tc.local)
		}
		if local && (src.IsValid() || dst.IsValid()) {
			t.Fatalf("%s: LOCAL carried addresses %v %v", tc.name, src, dst)
		}
		if !local && (src.String() != tc.src || dst.String() != tc.dst) {
			t.Fatalf("%s: %s %s", tc.name, src, dst)
		}
	}
}

func TestProxyProtocolV2Dialogue(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	h.cfg.ProxyProtocol = true
	h.cfg.PermittedProxies = blacklist.New("permitted-proxies", "", blacklist.StorageList)
	_ = h.cfg.PermittedProxies.Add("127.0.0.0/8")
	proxy := netip.MustParseAddrPort("127.0.0.1:5555")
	local := netip.MustParseAddrPort("127.0.0.1:8025")

	// Permitted proxy: the real client (blacklisted 10.10.10.1) is used.
	client, server := net.Pipe()
	c := NewConn(server, proxy, local, h.cfg, h.deps, h.counters)
	done := make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br := newLineReader(client)
	hdr := proxyV2(0x01, 0x11, proxyV2Addrs("10.10.10.1", "10.0.0.25", 4000, 25))
	send(t, client, string(hdr))
	expect(t, br, "220 greyd.org")
	if c.SrcAddr != "10.10.10.1" || c.DstAddr != "10.0.0.25" {
		t.Fatalf("proxied addresses %q %q", c.SrcAddr, c.DstAddr)
	}
	if !c.IsBlacklisted() || len(c.Lists) != 2 {
		t.Fatal("blacklists must be matched against the proxied client")
	}
	if _, bl, _, _ := h.counters.Snapshot(); bl != 1 {
		t.Fatalf("black clients %d", bl)
	}
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 greyd.org")
	<-done
	_ = client.Close()
	if _, bl, _, _ := h.counters.Snapshot(); bl != 0 {
		t.Fatalf("black clients after close %d", bl)
	}

	// IPv6 addresses with TLVs, and the header split across writes.
	client, server = net.Pipe()
	c = NewConn(server, proxy, local, h.cfg, h.deps, h.counters)
	done = make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br = newLineReader(client)
	addrs := proxyV2Addrs("2001::fad3:1", "2001:db8::25", 4000, 25)
	addrs = append(addrs, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef)
	hdr = proxyV2(0x01, 0x21, addrs)
	for _, part := range [][]byte{hdr[:5], hdr[5:14], hdr[14:40], hdr[40:]} {
		send(t, client, string(part))
	}
	expect(t, br, "220 greyd.org")
	if c.SrcAddr != "2001::fad3:1" || c.DstAddr != "2001:db8::25" {
		t.Fatalf("proxied addresses %q %q", c.SrcAddr, c.DstAddr)
	}
	if !c.IsBlacklisted() || len(c.Lists) != 2 {
		t.Fatal("blacklists must be matched against the proxied IPv6 client")
	}
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 greyd.org")
	<-done
	_ = client.Close()

	// LOCAL: the connection's own addresses stand, and the dialogue
	// continues with the command that followed the header in the same
	// write (the header is read exactly, the command must not be swallowed
	// with it). The write is asynchronous as the pipe is unbuffered and the
	// banner goes out before the command is consumed.
	client, server = net.Pipe()
	c = NewConn(server, proxy, local, h.cfg, h.deps, h.counters)
	done = make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br = newLineReader(client)
	sent := make(chan error, 1)
	go func() {
		_, err := io.WriteString(client, string(proxyV2(0x00, 0x00, nil))+"EHLO a\r\n")
		sent <- err
	}()
	expect(t, br, "220 greyd.org")
	if err := <-sent; err != nil {
		t.Fatalf("send LOCAL header: %v", err)
	}
	if c.SrcAddr != "127.0.0.1" || c.DstAddr != "" || c.IsBlacklisted() {
		t.Fatalf("LOCAL addresses %q %q black=%v", c.SrcAddr, c.DstAddr, c.IsBlacklisted())
	}
	expect(t, br, "250 greyd.org")
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 greyd.org")
	<-done
	_ = client.Close()

	// Non-permitted proxy: rejected with the error reply.
	client, server = net.Pipe()
	c = NewConn(server, netip.MustParseAddrPort("192.0.2.1:5555"), local, h.cfg, h.deps, h.counters)
	done = make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br = newLineReader(client)
	send(t, client, string(proxyV2(0x01, 0x11, proxyV2Addrs("10.10.10.9", "10.0.0.25", 4000, 25))))
	expect(t, br, "451 Temporary failure")
	<-done
	_ = client.Close()

	// UNSPEC family and a malformed header: rejected.
	for _, hdr := range [][]byte{
		proxyV2(0x01, 0x00, nil),
		proxyV2(0x01, 0x11, proxyV2Addrs("10.10.10.9", "10.0.0.25", 4000, 25)[:8]),
	} {
		client, server = net.Pipe()
		c = NewConn(server, proxy, local, h.cfg, h.deps, h.counters)
		done = make(chan struct{})
		go func() { c.Serve(); close(done) }()
		br = newLineReader(client)
		send(t, client, string(hdr))
		expect(t, br, "451 Temporary failure")
		<-done
		_ = client.Close()
	}

	// An oversized length is refused before the block is read.
	client, server = net.Pipe()
	c = NewConn(server, proxy, local, h.cfg, h.deps, h.counters)
	done = make(chan struct{})
	go func() { c.Serve(); close(done) }()
	hdr = append(append([]byte(nil), ProxyV2Signature...), 0x21, 0x11, 0xff, 0xff)
	send(t, client, string(hdr))
	<-done
	if !c.Closed() {
		t.Fatal("oversized v2 header must close the connection")
	}
	_ = client.Close()

	// Proxied greylisted client: dst_ip comes from the header.
	client, server = net.Pipe()
	c = NewConn(server, proxy, local, h.cfg, h.deps, h.counters)
	done = make(chan struct{})
	go func() { c.Serve(); close(done) }()
	br = newLineReader(client)
	send(t, client, string(proxyV2(0x01, 0x11, proxyV2Addrs("10.10.10.9", "192.0.2.99", 4000, 25))))
	expect(t, br, "220 ")
	send(t, client, "EHLO a\r\n")
	expect(t, br, "250 greyd.org")
	send(t, client, "MAIL FROM:<a@b>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "RCPT TO:<c@d>\r\n")
	expect(t, br, "250 OK")
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 ")
	<-done
	_ = client.Close()
	m, err := ipc.NewReader(bytes.NewReader(h.greyOut.Bytes())).Next()
	if g, ok := m.(*ipc.GreyMessage); err != nil || !ok || g.DstIP != "192.0.2.99" || g.Tuple.IP != "10.10.10.9" {
		t.Fatalf("proxied grey message: %v %s", err, h.greyOut.String())
	}
}

func TestProxyHeaderBounded(t *testing.T) {
	long := "PROXY TCP4 1.1.1.1 2.2.2.2 1 2" + strings.Repeat(" ", MaxProxyHeader)
	if _, _, err := ParseProxyHeader(long); !errors.Is(err, ErrProxyInvalid) {
		t.Fatalf("oversized header: %v", err)
	}
	if _, _, err := ParseProxyHeader("PROXY TCP4 1.1.1.1 2.2.2.2 1 2"); err != nil {
		t.Fatalf("normal header: %v", err)
	}
}

func TestExpandMessage(t *testing.T) {
	cases := map[string]string{
		`Your address %A is listed`: "Your address 1.2.3.4 is listed",
		`line1\nline2`:              "line1\nline2",
		`100%% sure`:                "100% sure",
		`back\\slash`:               `back\slash`,
		`odd \x escape`:             `odd \x escape`,
		`percent %x`:                `percent %x`,
		`trailing \`:                `trailing `,
		`A and n alone`:             `A and n alone`,
		``:                          ``,
	}
	for in, want := range cases {
		if got := ExpandMessage(in, "1.2.3.4"); got != want {
			t.Fatalf("ExpandMessage(%q) = %q want %q", in, got, want)
		}
	}
}

func TestFormatReply(t *testing.T) {
	lists := []*blacklist.Blacklist{
		blacklist.New("a", "first\n", blacklist.StorageTrie),
		blacklist.New("b", `two\nlines`, blacklist.StorageTrie),
	}
	got := FormatReply(lists, "450", "1.1.1.1")
	want := "450-first\n450-two\n450 lines\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if FormatReply(nil, "450", "x") != "" {
		t.Fatal("empty lists")
	}
}

func TestPerSourceLimit(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	h.cfg.MaxConsPerSource = 1
	h.deps.Now = nil
	h.deps.Sleep = nil
	srv := NewServer(h.cfg, h.deps, h.counters)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeListener(ctx, l) }()

	c1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	expect(t, newLineReader(c1), "220 ")
	if h.counters.SourceCount(netip.MustParseAddr("127.0.0.1")) != 1 {
		t.Fatal("source count")
	}
	c2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("second connection from the same source must be dropped")
	}
	_ = c2.Close()
	cancel()
	srv.Shutdown()
}

func TestLineLengthLimit(t *testing.T) {
	h := newHarness(t, 100, 100)
	h.cfg.Stutter = 0
	h.cfg.MaxLineLength = 64
	client, server := net.Pipe()
	defer client.Close()
	c := NewConn(server, netip.MustParseAddrPort("10.10.10.9:5555"), netip.MustParseAddrPort("127.0.0.1:8025"), h.cfg, h.deps, h.counters)
	go c.Serve()
	br := newLineReader(client)
	expect(t, br, "220 ")
	// A 100 byte HELO without a newline is cut at the limit and processed;
	// the remainder is read as the next (unrecognised) command. net.Pipe
	// writes block until read, so send from a goroutine.
	go func() { _, _ = io.WriteString(client, "HELO "+strings.Repeat("a", 95)+"\r\n") }()
	expect(t, br, "250 greyd.org")
	if len(c.Helo) != 64-len("HELO ") {
		t.Fatalf("helo length %d", len(c.Helo))
	}
	expect(t, br, "500 Command unrecognized")
	send(t, client, "QUIT\r\n")
	expect(t, br, "221 ")
}

func TestServerAcceptsAndLimits(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.cfg.Stutter = 0
	// Real time for the network test; sleeps are only used for throttling.
	h.deps.Now = nil
	h.deps.Sleep = nil
	srv := NewServer(h.cfg, h.deps, h.counters)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.ServeListener(ctx, l) }()

	c1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	br := newLineReader(c1)
	expect(t, br, "220 ")

	// The second connection exceeds max_cons and is closed immediately.
	c2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("over-limit connection should be closed without a banner")
	}
	_ = c2.Close()

	send(t, c1, "QUIT\r\n")
	expect(t, br, "221 ")
	cancel()
	if err := <-serveDone; err != nil {
		t.Fatalf("ServeListener: %v", err)
	}
	srv.Shutdown()
}

// helpers

type lineReader struct {
	r   io.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader { return &lineReader{r: r} }

func (l *lineReader) line(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if i := bytes.IndexByte(l.buf, '\n'); i >= 0 {
			s := string(l.buf[:i+1])
			l.buf = l.buf[i+1:]
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for line; have %q", l.buf)
		}
		if nc, ok := l.r.(net.Conn); ok {
			_ = nc.SetReadDeadline(deadline)
		}
		tmp := make([]byte, 512)
		n, err := l.r.Read(tmp)
		l.buf = append(l.buf, tmp[:n]...)
		if err != nil {
			if len(l.buf) > 0 {
				s := string(l.buf)
				l.buf = nil
				return s
			}
			t.Fatalf("read: %v", err)
		}
	}
}

func expect(t *testing.T, br *lineReader, prefix string) {
	t.Helper()
	got := br.line(t)
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("got %q, want prefix %q", got, prefix)
	}
}

func send(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if nc, ok := w.(net.Conn); ok {
		_ = nc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatalf("send %q: %v", s, err)
	}
}
