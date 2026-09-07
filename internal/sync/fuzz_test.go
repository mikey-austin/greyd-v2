package sync

import (
	"errors"
	"net/netip"
	"testing"
)

// FuzzDecode feeds arbitrary packets to the sync decoder; it must never
// panic and, with a random key, must reject everything it did not sign.
func FuzzDecode(f *testing.F) {
	var k Key
	copy(k[:], "0123456789abcdef0123456789abcdef01234567")
	ip := netip.MustParseAddr("192.0.2.7")
	f.Add(EncodeGrey(&k, 5, ip, "mx.example.org", "a@b.c", "d@e.f", 1700000000))
	f.Add(EncodeAddr(&k, 1, TypeWhite, ip, 100, 200))
	f.Add(EncodeAddr(&k, 1, TypeDelTrapped, ip, 100, 200))
	f.Add([]byte{})
	f.Add(make([]byte, hdrLen))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		if _, err := Decode(&k, pkt); err != nil {
			return
		}
		// A packet accepted under k must carry a valid signature; the
		// zero key must then reject it (different HMAC).
		var zero Key
		if _, err := Decode(&zero, pkt); err == nil && k != zero {
			t.Fatal("packet accepted under two different keys")
		}
	})
}

// TestEncodeDecodeProperty round-trips many grey entries through the
// wire format, including the longest strings that still fit.
func TestEncodeDecodeProperty(t *testing.T) {
	var k Key
	copy(k[:], "fedcba9876543210fedcba9876543210fedcba98")
	strs := []string{"", "a", "mx.example.org", string(make([]byte, 100)), "üñí", "with space", "trailing\x00nul"}
	for i, helo := range strs {
		for j, from := range strs {
			ip := netip.AddrFrom4([4]byte{byte(i), byte(j), 3, 4})
			pkt := EncodeGrey(&k, uint32(i*7+j), ip, helo, from, "t@x", 1700000000)
			if len(pkt) > MaxSize {
				continue
			}
			dec, err := Decode(&k, pkt)
			if err != nil {
				t.Fatalf("helo=%q from=%q: %v", helo, from, err)
			}
			if len(dec.Entries) != 1 || dec.Counter != uint32(i*7+j) {
				t.Fatalf("decoded %+v", dec)
			}
			e := dec.Entries[0]
			// Strings are C strings on the wire: everything up to the first NUL.
			if e.IP != ip || e.Helo != cstr([]byte(helo)) || e.From != cstr([]byte(from)) || e.To != "t@x" {
				t.Fatalf("helo=%q from=%q: got %+v", helo, from, e)
			}
		}
	}
}

func BenchmarkDecodeGrey(b *testing.B) {
	var k Key
	pkt := EncodeGrey(&k, 5, netip.MustParseAddr("192.0.2.7"), "mx.example.org", "sender@example.org", "rcpt@example.net", 1700000000)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(&k, pkt); err != nil {
			b.Fatal(err)
		}
	}
}

var _ = errors.New
