package sync

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

func init() {
	_ = logger.Setup(logger.Options{Ident: "test", Stderr: io.Discard})
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
	entries, err := Decode(&k, pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries %d", len(entries))
	}
	e := entries[0]
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
		entries, err := Decode(&k, pkt)
		if err != nil || len(entries) != 1 {
			t.Fatalf("decode %v %d", err, len(entries))
		}
		e := entries[0]
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
	cfg := config.New()
	e, err := New(cfg)
	if err != nil || e != nil {
		t.Fatalf("disabled sync should yield nil engine: %v %v", e, err)
	}
}

func TestEngineUnicastExchange(t *testing.T) {
	// Receiver bound to an explicit loopback address and OS chosen port is
	// not possible through the config (port is fixed), so use two engines
	// on distinct ports.
	recvPort := freePort(t)

	rcfg := config.New()
	rcfg.SetInt("enable", "sync", 1)
	rcfg.SetInt("verify", "sync", 0)
	rcfg.SetStr("bind_address", "sync", "127.0.0.1")
	rcfg.SetInt("port", "sync", recvPort)
	recv, err := New(rcfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := recv.Start(); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	defer recv.Stop()

	scfg := config.New()
	scfg.SetInt("enable", "sync", 1)
	scfg.SetInt("verify", "sync", 0)
	scfg.SetInt("port", "sync", recvPort)
	scfg.AppendListStr("hosts", "sync", "127.0.0.1")
	send, err := New(scfg)
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
	if m.Int("type", "", 0) != ipc.MsgWhite || m.Int("sync", "", 1) != 0 || m.Str("ip", "", "") != "1.2.3.4" ||
		m.Str("source", "", "") != "127.0.0.1" || m.Str("expires", "", "") != strconv.FormatInt(now.Add(time.Hour).Unix(), 10) || m.Int("delete", "", 1) != 0 {
		t.Fatalf("white message %s", out.String())
	}
	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if m.Int("type", "", 0) != ipc.MsgTrap || m.Str("ip", "", "") != "5.6.7.8" || m.Int("delete", "", 0) != 1 {
		t.Fatalf("trap message")
	}
	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if m.Int("type", "", 0) != ipc.MsgGrey || m.Int("sync", "", 1) != 0 || m.Str("ip", "", "") != "9.9.9.9" ||
		m.Str("helo", "", "") != "h" || m.Str("from", "", "") != "f@x" || m.Str("to", "", "") != "t@y" {
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
	rcfg := config.New()
	rcfg.SetInt("enable", "sync", 1)
	rcfg.SetStr("key", "sync", keyPath)
	rcfg.SetStr("bind_address", "sync", "127.0.0.1")
	rcfg.SetInt("port", "sync", recvPort)
	recv, err := New(rcfg)
	if err != nil {
		t.Fatal(err)
	}
	if recv.key == (Key{}) {
		t.Fatal("key should be loaded")
	}
	if err := recv.Start(); err != nil {
		t.Fatal(err)
	}
	defer recv.Stop()

	scfg := config.New()
	scfg.SetInt("enable", "sync", 1)
	scfg.SetInt("verify", "sync", 0) // zero key: signatures will not match
	scfg.SetInt("port", "sync", recvPort)
	scfg.AppendListStr("hosts", "sync", "127.0.0.1")
	send, err := New(scfg)
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
	cfg := config.New()
	cfg.SetInt("enable", "sync", 1)
	cfg.SetInt("verify", "sync", 0)
	cfg.AppendListStr("hosts", "sync", "no-such-interface-xyz")
	cfg.SetStr("bind_address", "sync", "other-iface")
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.iface != "no-such-interface-xyz" {
		t.Fatalf("unresolvable host should become the interface, got %q", e.iface)
	}
	if err := e.Start(); err == nil {
		t.Fatal("mismatched interfaces must fail")
	}

	cfg = config.New()
	cfg.SetInt("enable", "sync", 1)
	cfg.SetInt("verify", "sync", 0)
	cfg.SetStr("bind_address", "sync", "no-such-interface-xyz:abc")
	e, _ = New(cfg)
	if err := e.Start(); err == nil {
		t.Fatal("invalid ttl must fail")
	}
	cfg.SetStr("bind_address", "sync", "no-such-interface-xyz")
	e, _ = New(cfg)
	if err := e.Start(); err == nil {
		t.Fatal("unknown interface must fail")
	}

	cfg = config.New()
	cfg.SetInt("enable", "sync", 1)
	cfg.SetStr("key", "sync", filepath.Join(t.TempDir())) // a directory: read error
	if _, err := New(cfg); err == nil {
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
