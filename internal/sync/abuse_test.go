package sync

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/ipc"
)

// Abuse tests: a real receiving engine on loopback is fed replayed,
// misauthenticated, garbage and malformed datagrams from a raw UDP socket
// and must forward nothing but the genuine entries to the grey writer,
// stay responsive and release its goroutines on Stop.

// frameSink is a goroutine-safe grey writer that records forwarded
// frames.
type frameSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *frameSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

// messages decodes every complete frame written so far.
func (s *frameSink) messages(t *testing.T) []ipc.Message {
	t.Helper()
	s.mu.Lock()
	snap := append([]byte(nil), s.buf.Bytes()...)
	s.mu.Unlock()
	r := ipc.NewReader(bytes.NewReader(snap))
	var out []ipc.Message
	for {
		m, err := r.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("decode forwarded frame: %v", err)
			}
			return out
		}
		out = append(out, m)
	}
}

// countIP returns how many forwarded white/trapped/grey frames carry ip.
func (s *frameSink) countIP(t *testing.T, ip string) int {
	t.Helper()
	n := 0
	for _, m := range s.messages(t) {
		switch v := m.(type) {
		case *ipc.AddrMessage:
			if v.IP == ip {
				n++
			}
		case *ipc.GreyMessage:
			if v.Tuple.IP == ip {
				n++
			}
		}
	}
	return n
}

// waitIP polls until at least one frame for ip has been forwarded.
func (s *frameSink) waitIP(t *testing.T, ip string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.countIP(t, ip) > 0 {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return s.countIP(t, ip) > 0
}

// abuseHarness is a keyed receiving engine served in the background plus
// a raw sender socket.
type abuseHarness struct {
	recv   *Engine
	key    Key
	other  Key
	sink   *frameSink
	client *net.UDPConn
	target *net.UDPAddr
	cancel context.CancelFunc
	served chan error
}

func newAbuseHarness(t *testing.T) *abuseHarness {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "greyd.key")
	if err := os.WriteFile(keyPath, []byte("abuse-test-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(dir, "other.key")
	if err := os.WriteFile(otherPath, []byte("some-other-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, ok, err := LoadKey(otherPath)
	if err != nil || !ok {
		t.Fatalf("load other key: %v %v", err, ok)
	}

	cfg := syncCfg()
	cfg.Key = keyPath
	cfg.BindAddress = "127.0.0.1"
	cfg.Port = freePort(t)
	recv, err := New(cfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !recv.Keyed() {
		t.Fatal("receiver must have loaded the key")
	}
	if err := recv.Start(); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	target := recv.LocalAddr().(*net.UDPAddr)

	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, target)
	if err != nil {
		recv.Stop()
		t.Fatal(err)
	}

	h := &abuseHarness{recv: recv, key: recv.key, other: other, sink: &frameSink{}, client: client, target: target, served: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.served <- recv.Serve(ctx, h.sink) }()
	t.Cleanup(func() {
		_ = client.Close()
		h.stop(t)
	})
	return h
}

// stop shuts the receiver down and waits for Serve to return.
func (h *abuseHarness) stop(t *testing.T) {
	t.Helper()
	if h.cancel == nil {
		return
	}
	h.cancel()
	h.cancel = nil
	select {
	case err := <-h.served:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return after Stop")
	}
}

func (h *abuseHarness) send(t *testing.T, pkt []byte) {
	t.Helper()
	if _, err := h.client.Write(pkt); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// probe sends a fresh, valid white entry for ip with the given counter
// and asserts it is forwarded within timeout. Datagrams from one socket
// to one destination stay ordered on loopback, so the receiver has by
// then processed (or the kernel has dropped) everything sent before the
// probe. The probe itself can be dropped when the preceding traffic has
// overflowed the receive buffer, so it is retransmitted until seen; the
// replay window guarantees a duplicate is forwarded at most once, which
// keeps the callers' exact counts valid.
func (h *abuseHarness) probe(t *testing.T, counter uint32, ip string, timeout time.Duration) {
	t.Helper()
	pkt := EncodeAddr(&h.key, counter, TypeWhite, netip.MustParseAddr(ip), 1700000000, 1700003600)
	deadline := time.Now().Add(timeout)
	for {
		h.send(t, pkt)
		if h.sink.waitIP(t, ip, 250*time.Millisecond) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe %s (counter %d) was not forwarded within %v", ip, counter, timeout)
		}
	}
}

// resign recomputes the HMAC of a hand-modified packet so the decoder
// reaches the TLV parser.
func resign(k *Key, pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	for i := range HMACLen {
		out[8+i] = 0
	}
	sign(k, out)
	return out
}

// assertOnlyIPs fails when any forwarded frame carries an address outside
// allowed.
func assertOnlyIPs(t *testing.T, sink *frameSink, allowed map[string]bool) {
	t.Helper()
	for _, m := range sink.messages(t) {
		var ip string
		switch v := m.(type) {
		case *ipc.AddrMessage:
			ip = v.IP
		case *ipc.GreyMessage:
			ip = v.Tuple.IP
		default:
			t.Fatalf("unexpected forwarded frame %T", m)
		}
		if !allowed[ip] {
			t.Fatalf("unexpected entry forwarded for %s", ip)
		}
	}
}

func TestAbuseReplayedPacketForwardedOnce(t *testing.T) {
	h := newAbuseHarness(t)
	pkt := EncodeAddr(&h.key, 100, TypeTrapped, netip.MustParseAddr("192.0.2.50"), 1700000000, 1700086400)
	for range 50 {
		h.send(t, pkt)
	}
	h.probe(t, 101, "192.0.2.51", 5*time.Second)
	if n := h.sink.countIP(t, "192.0.2.50"); n != 1 {
		t.Fatalf("replayed packet forwarded %d times, want exactly 1", n)
	}
	// Same counter under a different entry is still a replay.
	h.send(t, EncodeAddr(&h.key, 100, TypeWhite, netip.MustParseAddr("192.0.2.52"), 1700000000, 1700086400))
	h.probe(t, 102, "192.0.2.53", 5*time.Second)
	if n := h.sink.countIP(t, "192.0.2.52"); n != 0 {
		t.Fatalf("reused counter forwarded %d times, want 0", n)
	}
	assertOnlyIPs(t, h.sink, map[string]bool{"192.0.2.50": true, "192.0.2.51": true, "192.0.2.53": true})
}

func TestAbuseWrongKeyDropped(t *testing.T) {
	h := newAbuseHarness(t)
	var zero Key
	bad := [][]byte{
		EncodeAddr(&h.other, 1, TypeWhite, netip.MustParseAddr("198.51.100.1"), 1700000000, 1700003600),
		EncodeAddr(&zero, 2, TypeTrapped, netip.MustParseAddr("198.51.100.2"), 1700000000, 1700003600),
		EncodeGrey(&h.other, 3, netip.MustParseAddr("198.51.100.3"), "mx.example.org", "a@b.c", "d@e.f", 1700000000),
		EncodeAddr(&h.other, 4, TypeDelWhite, netip.MustParseAddr("198.51.100.4"), 1700000000, 0),
	}
	for range 5 {
		for _, p := range bad {
			h.send(t, p)
		}
	}
	// A correctly keyed packet whose digest bytes were flipped.
	tampered := EncodeAddr(&h.key, 5, TypeWhite, netip.MustParseAddr("198.51.100.5"), 1700000000, 1700003600)
	tampered[9] ^= 0x80
	h.send(t, tampered)

	h.probe(t, 1, "192.0.2.60", 5*time.Second)
	assertOnlyIPs(t, h.sink, map[string]bool{"192.0.2.60": true})
	// Misauthenticated packets must not have consumed the replay window:
	// counters 1..5 were sent under the wrong key and the probe with
	// counter 1 above was accepted.
	if n := h.sink.countIP(t, "192.0.2.60"); n != 1 {
		t.Fatalf("probe forwarded %d times", n)
	}
}

func TestAbuseRandomGarbage(t *testing.T) {
	h := newAbuseHarness(t)
	rng := rand.New(rand.NewPCG(0x5eed, 0xab05e))
	buf := make([]byte, 2000)
	for i := 0; i < 1000; i++ {
		n := rng.IntN(len(buf) + 1)
		for j := range buf[:n] {
			buf[j] = byte(rng.UintN(256))
		}
		// Bias a share of the datagrams towards a plausible header so
		// the parser is exercised past the version check.
		if n >= hdrLen && i%4 == 0 {
			buf[0] = Version
			buf[1] = afInet
			binary.BigEndian.PutUint16(buf[2:], uint16(n))
		}
		h.send(t, buf[:n])
	}
	h.probe(t, 7, "192.0.2.70", 5*time.Second)
	assertOnlyIPs(t, h.sink, map[string]bool{"192.0.2.70": true})
}

func TestAbuseMalformedTLVs(t *testing.T) {
	h := newAbuseHarness(t)
	ip := netip.MustParseAddr("203.0.113.9")
	addr := EncodeAddr(&h.key, 10, TypeWhite, ip, 1700000000, 1700003600)
	grey := EncodeGrey(&h.key, 11, ip, "mx.example.org", "sender@example.org", "rcpt@example.net", 1700000000)

	var cases [][]byte
	// TLV length larger than the packet.
	p := append([]byte(nil), addr...)
	binary.BigEndian.PutUint16(p[hdrLen+2:], 0xfff0)
	cases = append(cases, resign(&h.key, p))
	// TLV length just past the end of the packet.
	p = append([]byte(nil), addr...)
	binary.BigEndian.PutUint16(p[hdrLen+2:], uint16(len(addr)-hdrLen+1))
	cases = append(cases, resign(&h.key, p))
	// Header length claims more than the datagram carries.
	p = append([]byte(nil), addr...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(addr)+40))
	cases = append(cases, resign(&h.key, p))
	// Header length cuts the address TLV in half (and the signature
	// covers only that prefix, so it is well formed up to the TLV).
	p = append([]byte(nil), addr[:hdrLen+8]...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	cases = append(cases, resign(&h.key, p))
	// Only a TLV header remains, no body.
	p = append([]byte(nil), addr[:hdrLen+tlvHdrLen]...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	cases = append(cases, resign(&h.key, p))
	// A single dangling byte after the header.
	p = append([]byte(nil), addr[:hdrLen+1]...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	cases = append(cases, resign(&h.key, p))
	// Address TLV with a length that is not sizeof(struct).
	p = append([]byte(nil), addr...)
	binary.BigEndian.PutUint16(p[hdrLen+2:], addrLen-1)
	cases = append(cases, resign(&h.key, p))
	// TLV length below the TLV header size (would loop forever if trusted).
	p = append([]byte(nil), addr...)
	binary.BigEndian.PutUint16(p[hdrLen+2:], 0)
	cases = append(cases, resign(&h.key, p))
	// Grey TLV whose string lengths exceed the TLV.
	p = append([]byte(nil), grey...)
	binary.BigEndian.PutUint16(p[hdrLen+12:], 0x4000)
	cases = append(cases, resign(&h.key, p))
	// Grey TLV with lengths that sum exactly one byte past the TLV.
	p = append([]byte(nil), grey...)
	tl := int(binary.BigEndian.Uint16(p[hdrLen+2:]))
	binary.BigEndian.PutUint16(p[hdrLen+12:], uint16(tl-greyHdrLen+1))
	binary.BigEndian.PutUint16(p[hdrLen+14:], 0)
	binary.BigEndian.PutUint16(p[hdrLen+16:], 0)
	cases = append(cases, resign(&h.key, p))
	// Grey TLV shorter than its fixed header.
	p = append([]byte(nil), grey...)
	binary.BigEndian.PutUint16(p[hdrLen+2:], greyHdrLen-1)
	cases = append(cases, resign(&h.key, p))
	// Grey TLV truncated by the header length inside the strings.
	p = append([]byte(nil), grey[:hdrLen+greyHdrLen+3]...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	cases = append(cases, resign(&h.key, p))
	// Unknown TLV type before a valid entry.
	p = make([]byte, 0, len(addr)+8)
	p = append(p, addr[:hdrLen]...)
	p = append(p, 0x00, 0x77, 0x00, 0x08, 1, 2, 3, 4)
	p = append(p, addr[hdrLen:]...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	cases = append(cases, resign(&h.key, p))
	// Zero header length and an absurd header length.
	p = append([]byte(nil), addr...)
	binary.BigEndian.PutUint16(p[2:], 0)
	cases = append(cases, resign(&h.key, p))
	p = append([]byte(nil), addr...)
	binary.BigEndian.PutUint16(p[2:], hdrLen-1)
	cases = append(cases, resign(&h.key, p))

	for i, c := range cases {
		if _, err := Decode(&h.key, c); err == nil {
			t.Fatalf("case %d unexpectedly decodes offline", i)
		}
		h.send(t, c)
	}
	h.probe(t, 12, "192.0.2.80", 5*time.Second)
	assertOnlyIPs(t, h.sink, map[string]bool{"192.0.2.80": true})
	if n := h.sink.countIP(t, ip.String()); n != 0 {
		t.Fatalf("malformed packets forwarded %d entries", n)
	}
}

func TestAbuseFloodStaysResponsive(t *testing.T) {
	h := newAbuseHarness(t)
	const flood = 20000
	ip := netip.MustParseAddr("192.0.2.99")
	start := time.Now()
	for c := uint32(1); c <= flood; c++ {
		// Alternate entry kinds so both TLV parsers see the load.
		var pkt []byte
		if c%2 == 0 {
			pkt = EncodeAddr(&h.key, c, TypeWhite, ip, 1700000000, 1700003600)
		} else {
			pkt = EncodeGrey(&h.key, c, ip, "mx.example.org", "s@example.org", "r@example.net", 1700000000)
		}
		if _, err := h.client.Write(pkt); err != nil {
			// Loopback send buffers can fill under a tight loop; back
			// off briefly rather than fail.
			time.Sleep(time.Millisecond)
			if _, err := h.client.Write(pkt); err != nil {
				t.Fatalf("send %d: %v", c, err)
			}
		}
	}
	t.Logf("sent %d packets in %v", flood, time.Since(start))

	// The sender out-runs the receiver, so the kernel queue fills and later
	// datagrams are dropped before the engine sees them. Wait until the
	// backlog is drained (the forwarded count stops moving) so the probe
	// measures the engine, not the socket buffer; a hung receiver still
	// fails through the overall cap.
	drainStart := time.Now()
	last, stable := -1, 0
	for stable < 10 {
		if time.Since(drainStart) > 10*time.Second {
			t.Fatalf("receiver did not drain the flood within 10s (forwarded %d)", last)
		}
		time.Sleep(10 * time.Millisecond)
		n := h.sink.countIP(t, ip.String())
		if n == last {
			stable++
		} else {
			last, stable = n, 0
		}
	}
	t.Logf("flood drained in %v", time.Since(drainStart))

	// A fresh packet after the flood is forwarded within a second.
	h.probe(t, flood+1, "192.0.2.100", time.Second)

	forwarded := h.sink.countIP(t, ip.String())
	t.Logf("receiver forwarded %d of %d flood packets", forwarded, flood)
	if forwarded == 0 {
		t.Fatal("no flood packet was forwarded")
	}
	if forwarded > flood {
		t.Fatalf("forwarded %d entries from %d packets", forwarded, flood)
	}
	assertOnlyIPs(t, h.sink, map[string]bool{ip.String(): true, "192.0.2.100": true})

	// The replay state is one fixed-size record per peer, not per packet.
	h.recv.replayMu.Lock()
	peers := len(h.recv.replay)
	st := h.recv.replay[netip.MustParseAddr("127.0.0.1")]
	h.recv.replayMu.Unlock()
	if peers != 1 {
		t.Fatalf("replay map holds %d peers after a single-source flood, want 1", peers)
	}
	if st == nil || st.hi != flood+1 {
		t.Fatalf("replay state %+v, want hi=%d", st, flood+1)
	}
}

func TestAbuseNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	func() {
		h := newAbuseHarness(t)
		for c := uint32(0); c < 100; c++ {
			h.send(t, EncodeAddr(&h.key, c, TypeWhite, netip.MustParseAddr("192.0.2.1"), 1700000000, 1700003600))
		}
		h.send(t, []byte{1, 2, 3})
		h.probe(t, 100, "192.0.2.2", 5*time.Second)
		_ = h.client.Close()
		h.stop(t)
	}()
	const tolerance = 2
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+tolerance {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	t.Fatalf("goroutines before %d, after %d (tolerance %d):\n%s", before, runtime.NumGoroutine(), tolerance, buf[:n])
}

// TestAbuseSequential runs the whole battery against one engine so state
// from earlier abuse cannot affect later genuine traffic.
func TestAbuseSequential(t *testing.T) {
	h := newAbuseHarness(t)
	rng := rand.New(rand.NewPCG(1, 2))
	good := EncodeAddr(&h.key, 500, TypeTrapped, netip.MustParseAddr("192.0.2.200"), 1700000000, 1700086400)
	for range 50 {
		h.send(t, good)
	}
	for range 200 {
		h.send(t, EncodeAddr(&h.other, 501, TypeWhite, netip.MustParseAddr("192.0.2.201"), 1700000000, 1700086400))
	}
	buf := make([]byte, 2000)
	for range 1000 {
		n := rng.IntN(len(buf) + 1)
		for j := range buf[:n] {
			buf[j] = byte(rng.UintN(256))
		}
		h.send(t, buf[:n])
	}
	trunc := append([]byte(nil), good[:hdrLen+6]...)
	binary.BigEndian.PutUint16(trunc[2:], uint16(len(trunc)))
	h.send(t, resign(&h.key, trunc))
	h.probe(t, 502, "192.0.2.202", 5*time.Second)
	if n := h.sink.countIP(t, "192.0.2.200"); n != 1 {
		t.Fatalf("genuine entry forwarded %d times", n)
	}
	assertOnlyIPs(t, h.sink, map[string]bool{"192.0.2.200": true, "192.0.2.202": true})
	if got := fmt.Sprint(len(h.sink.messages(t))); got != "2" {
		t.Fatalf("forwarded %s frames, want 2", got)
	}
}

// TestReplayTableBounded checks that packets from many distinct sources
// cannot grow the per-peer replay table without bound.
func TestReplayTableBounded(t *testing.T) {
	cfg := syncCfg()
	cfg.ReplayWindow = 64
	e, err := New(cfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxReplayPeers*3; i++ {
		from := &net.UDPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 8025}
		if !e.acceptCounter(from, 1) {
			t.Fatalf("first packet from %v rejected", from)
		}
	}
	e.replayMu.Lock()
	n := len(e.replay)
	e.replayMu.Unlock()
	if n > maxReplayPeers {
		t.Fatalf("replay table holds %d peers, bound is %d", n, maxReplayPeers)
	}
	// A peer that stays active keeps its window: replaying its counter is
	// still refused after the churn.
	busy := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 8025}
	if !e.acceptCounter(busy, 5) || e.acceptCounter(busy, 5) {
		t.Fatal("replay window not applied to a live peer")
	}
}
