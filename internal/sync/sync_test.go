package sync

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

// syncCfg returns sync settings with the documented defaults applied.
func syncCfg() settings.Sync {
	return settings.Sync{Enable: true, Port: DefaultPort, TTL: DefaultTTL, Verify: true, Key: DefaultKey, McastAddress: MulticastAddr, ReplayWindow: 64}
}

func TestGreyRoundTrip(t *testing.T) {
	var k Key
	ip := netip.MustParseAddr("192.0.2.7")
	pkt := EncodeGrey(&k, 5, ip, "mx.example.org", "a@b.c", "d@e.f", 1700000000)

	// 32 header + align16(20 + 6 + 6 + 15) + 4 end
	strings := len("a@b.c") + 1 + len("d@e.f") + 1 + len("mx.example.org") + 1
	want := hdrLen + align(greyHdrLen+strings) + endLen
	if len(pkt) != want {
		t.Fatalf("packet length %d want %d", len(pkt), want)
	}
	if pkt[0] != Version || pkt[1] != afInet || binary.BigEndian.Uint16(pkt[2:]) != uint16(want) || binary.BigEndian.Uint32(pkt[4:]) != 5 {
		t.Fatal("header fields")
	}
	dec, err := Decode(&k, pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Entries) != 1 || dec.Counter != 5 {
		t.Fatalf("decoded %+v", dec)
	}
	e := dec.Entries[0]
	if e.Type != TypeGrey || e.IP != ip || e.Helo != "mx.example.org" || e.From != "a@b.c" || e.To != "d@e.f" || e.Delete {
		t.Fatalf("entry %+v", e)
	}
}

func TestAddrRoundTripAndTypes(t *testing.T) {
	k := Key{}
	copy(k[:], "0123456789abcdef0123456789abcdef01234567")
	ip := netip.MustParseAddr("10.1.2.3")
	for _, tc := range []struct {
		typ uint16
		del bool
	}{{TypeWhite, false}, {TypeDelWhite, true}, {TypeTrapped, false}, {TypeDelTrapped, true}} {
		pkt := EncodeAddr(&k, 1, tc.typ, ip, 100, 200)
		if len(pkt) != hdrLen+addrLen+endLen {
			t.Fatalf("addr packet length %d", len(pkt))
		}
		dec, err := Decode(&k, pkt)
		if err != nil || len(dec.Entries) != 1 {
			t.Fatalf("decode %v %d", err, len(dec.Entries))
		}
		e := dec.Entries[0]
		if e.Type != tc.typ || e.Delete != tc.del || e.IP != ip || e.Expire != 200 {
			t.Fatalf("entry %+v", e)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	var k Key
	good := EncodeAddr(&k, 1, TypeWhite, netip.MustParseAddr("1.2.3.4"), 1, 2)

	// Wrong key.
	other := Key{}
	other[0] = 'x'
	if _, err := Decode(&other, good); err == nil {
		t.Fatal("wrong key must fail")
	}
	// Tampered payload.
	bad := append([]byte(nil), good...)
	bad[len(bad)-5] ^= 0xff
	if _, err := Decode(&k, bad); err == nil {
		t.Fatal("tampered packet must fail")
	}
	// Truncated.
	if _, err := Decode(&k, good[:20]); err == nil {
		t.Fatal("short packet must fail")
	}
	if _, err := Decode(&k, good[:len(good)-1]); err == nil {
		t.Fatal("truncated packet must fail")
	}
	// Wrong version / af.
	bad = append([]byte(nil), good...)
	bad[0] = 1
	if _, err := Decode(&k, bad); err == nil {
		t.Fatal("wrong version must fail")
	}
	bad = append([]byte(nil), good...)
	bad[1] = 10
	if _, err := Decode(&k, bad); err == nil {
		t.Fatal("wrong af must fail")
	}
	// Unknown TLV type (re-signed so the HMAC passes).
	bad = append([]byte(nil), good...)
	binary.BigEndian.PutUint16(bad[hdrLen:], 0x0099)
	for i := range HMACLen {
		bad[8+i] = 0
	}
	sign(&k, bad)
	if _, err := Decode(&k, bad); err == nil {
		t.Fatal("unknown type must fail")
	}
	// Trailing bytes after sh_length are ignored.
	padded := append(append([]byte(nil), good...), 1, 2, 3)
	if _, err := Decode(&k, padded); err != nil {
		t.Fatalf("trailing bytes: %v", err)
	}
}

// TestGoldenLayout checks the byte layout against the C struct
// definitions by hand-building an address packet.
func TestGoldenLayout(t *testing.T) {
	var k Key
	pkt := EncodeAddr(&k, 0x01020304, TypeTrapped, netip.MustParseAddr("192.168.1.2"), 0x11111111, 0x22222222)
	expect := []byte{
		2, 2, 0, 52, // version, af, length (32+16+4)
		1, 2, 3, 4, // counter
	}
	if !bytes.Equal(pkt[:8], expect) {
		t.Fatalf("header %x", pkt[:8])
	}
	if !bytes.Equal(pkt[28:32], []byte{0, 0, 0, 0}) {
		t.Fatalf("pad %x", pkt[28:32])
	}
	tlv := pkt[32:48]
	want := []byte{0, 3, 0, 16, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 192, 168, 1, 2}
	if !bytes.Equal(tlv, want) {
		t.Fatalf("tlv %x want %x", tlv, want)
	}
	if !bytes.Equal(pkt[48:52], []byte{0, 0, 0, 4}) {
		t.Fatalf("end %x", pkt[48:52])
	}
	// The HMAC is over the packet with a zeroed digest field.
	zeroed := append([]byte(nil), pkt...)
	for i := range HMACLen {
		zeroed[8+i] = 0
	}
	sign(&k, zeroed)
	if !bytes.Equal(zeroed[8:28], pkt[8:28]) {
		t.Fatal("hmac mismatch")
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	k, ok, err := LoadKey(filepath.Join(dir, "missing"))
	if err != nil || ok {
		t.Fatalf("missing key: %v %v", err, ok)
	}
	if k != (Key{}) {
		t.Fatal("missing key must be zero")
	}
	path := filepath.Join(dir, "greyd.key")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, ok, err = LoadKey(path)
	if err != nil || !ok {
		t.Fatalf("LoadKey: %v %v", err, ok)
	}
	// sha1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
	if string(k[:40]) != "a9993e364706816aba3e25717850c26c9cd0d89d" || k[40] != 0 {
		t.Fatalf("key %q", k[:])
	}
}

func TestEngineDisabled(t *testing.T) {
	cfg := syncCfg()
	cfg.Enable = false
	e, err := New(cfg, true, nil)
	if err != nil || e != nil {
		t.Fatalf("disabled sync should yield nil engine: %v %v", e, err)
	}
}

func TestReplayWindow(t *testing.T) {
	e, err := New(syncCfg(), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1)}
	accept := func(c uint32) bool { return e.acceptCounter(from, c) }
	for _, c := range []uint32{5, 6, 7} {
		if !accept(c) {
			t.Fatalf("counter %d should be accepted", c)
		}
	}
	if accept(6) {
		t.Fatal("duplicate must be rejected")
	}
	if !accept(4) {
		t.Fatal("out of order within window must be accepted")
	}
	if accept(4) {
		t.Fatal("second delivery within window must be rejected")
	}
	if !accept(1000) {
		t.Fatal("jump ahead must be accepted")
	}
	if accept(900) {
		t.Fatal("stale counter outside the window must be rejected")
	}
	if !accept(0) {
		t.Fatal("small counter after a large one is a peer restart")
	}
	if !accept(1) || accept(1) {
		t.Fatal("window restarts after peer restart")
	}
	// Other peers have independent windows.
	other := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)}
	if !e.acceptCounter(other, 6) {
		t.Fatal("independent peer")
	}
	// Window disabled accepts everything.
	cfg := syncCfg()
	cfg.ReplayWindow = 0
	e2, _ := New(cfg, true, nil)
	if !e2.acceptCounter(from, 1) || !e2.acceptCounter(from, 0) || !e2.acceptCounter(from, 1) {
		t.Fatal("disabled window")
	}
}

func TestEngineUnicastExchange(t *testing.T) {
	// Receiver bound to an explicit loopback address and OS chosen port is
	// not possible through the config (port is fixed), so use two engines
	// on distinct ports.
	recvPort := freePort(t)

	rcfg := syncCfg()
	rcfg.Verify = false
	rcfg.BindAddress = "127.0.0.1"
	rcfg.Port = recvPort
	recv, err := New(rcfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := recv.Start(); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	defer recv.Stop()

	scfg := syncCfg()
	scfg.Verify = false
	scfg.Port = recvPort
	scfg.Hosts = []string{"127.0.0.1"}
	send, err := New(scfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := send.Hosts(); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("hosts %v", got)
	}
	if err := send.Start(); err != nil {
		t.Fatalf("sender start: %v", err)
	}
	defer send.Stop()

	now := time.Unix(1700000000, 0)
	send.White("1.2.3.4", now, now.Add(time.Hour), false)
	send.Trapped("5.6.7.8", now, now.Add(time.Hour), true)
	send.Update(core.Tuple{IP: "9.9.9.9", Helo: "h", From: "f@x", To: "t@y"}, now)

	var out bytes.Buffer
	_ = recv.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 3; i++ {
		if err := recv.Recv(&out); err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
	}
	r := ipc.NewReader(&out)
	m, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	w, ok := m.(*ipc.AddrMessage)
	if !ok || w.Type != ipc.MsgWhite || w.Sync || w.IP != "1.2.3.4" ||
		w.Source != "127.0.0.1" || w.Expires != strconv.FormatInt(now.Add(time.Hour).Unix(), 10) || w.Delete {
		t.Fatalf("white message %s", out.String())
	}
	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := m.(*ipc.AddrMessage); !ok || tr.Type != ipc.MsgTrap || tr.IP != "5.6.7.8" || !tr.Delete {
		t.Fatalf("trap message")
	}
	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := m.(*ipc.GreyMessage); !ok || g.Sync ||
		g.Tuple != (core.Tuple{IP: "9.9.9.9", Helo: "h", From: "f@x", To: "t@y"}) {
		t.Fatalf("grey message")
	}
}

func TestEngineKeyMismatchIsIgnored(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k")
	if err := os.WriteFile(keyPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	recvPort := freePort(t)
	rcfg := syncCfg()
	rcfg.Key = keyPath
	rcfg.BindAddress = "127.0.0.1"
	rcfg.Port = recvPort
	recv, err := New(rcfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if recv.key == (Key{}) || !recv.Keyed() {
		t.Fatal("key should be loaded")
	}
	if err := recv.Start(); err != nil {
		t.Fatal(err)
	}
	defer recv.Stop()

	scfg := syncCfg()
	scfg.Verify = false // zero key: signatures will not match
	scfg.Port = recvPort
	scfg.Hosts = []string{"127.0.0.1"}
	send, err := New(scfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := send.Start(); err != nil {
		t.Fatal(err)
	}
	defer send.Stop()

	send.White("1.2.3.4", time.Now(), time.Now().Add(time.Hour), false)
	var out bytes.Buffer
	_ = recv.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := recv.Recv(&out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("unauthenticated packet must be dropped, got %q", out.String())
	}
}

func TestStartErrors(t *testing.T) {
	cfg := syncCfg()
	cfg.Verify = false
	cfg.Hosts = []string{"no-such-interface-xyz"}
	cfg.BindAddress = "other-iface"
	e, err := New(cfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.iface != "no-such-interface-xyz" {
		t.Fatalf("unresolvable host should become the interface, got %q", e.iface)
	}
	if err := e.Start(); err == nil {
		t.Fatal("mismatched interfaces must fail")
	}

	cfg = syncCfg()
	cfg.Verify = false
	cfg.BindAddress = "no-such-interface-xyz:abc"
	e, _ = New(cfg, true, nil)
	if err := e.Start(); err == nil {
		t.Fatal("invalid ttl must fail")
	}
	cfg.BindAddress = "no-such-interface-xyz"
	e, _ = New(cfg, true, nil)
	if err := e.Start(); err == nil {
		t.Fatal("unknown interface must fail")
	}

	cfg = syncCfg()
	cfg.Key = t.TempDir() // a directory: read error
	if _, err := New(cfg, true, nil); err == nil {
		t.Fatal("unreadable key must fail")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}
