package blacklist

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/mikey-austin/greyd-golang/internal/ip"
)

// TestCollapseProperty compares Collapse against a brute force model over
// a small address space: an address is listed when it lies in at least one
// black range and in no white range (ranges are half-open, [start, end)).
func TestCollapseProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	const base, span = 0x0a000000, 512
	for iter := 0; iter < 300; iter++ {
		bl := New("p", "m", StorageList)
		var black, white [span]bool
		n := 1 + rng.Intn(8)
		for i := 0; i < n; i++ {
			s := uint32(rng.Intn(span))
			e := uint32(rng.Intn(span))
			if s > e {
				s, e = e, s
			}
			typ := TypeBlack
			if rng.Intn(3) == 0 {
				typ = TypeWhite
			}
			bl.AddRange(base+s, base+e, typ)
			for a := s; a < e; a++ {
				if typ == TypeWhite {
					white[a] = true
				} else {
					black[a] = true
				}
			}
		}
		listed := [span]bool{}
		for _, c := range bl.Collapse() {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				t.Fatal(err)
			}
			lo, hi := ip.CIDRToRange(ip.CIDR{Addr: ip.AddrToUint32(p.Addr()), Bits: uint8(p.Bits())})
			for a := lo; a <= hi; a++ {
				if a < base || a >= base+span {
					t.Fatalf("iteration %d: cidr %s outside the test range", iter, c)
				}
				listed[a-base] = true
			}
		}
		for a := 0; a < span; a++ {
			want := black[a] && !white[a]
			if listed[a] != want {
				t.Fatalf("iteration %d: address %d listed=%v want %v (entries %v)", iter, a, listed[a], want, bl.Entries())
			}
		}
	}
}

func benchList(storage Storage, n int) *Blacklist {
	bl := New("b", "m", storage)
	for i := 0; i < n; i++ {
		_ = bl.Add(fmt.Sprintf("%d.%d.%d.0/24", 1+i%223, (i/223)%256, i%256))
	}
	return bl
}

func BenchmarkMatchTrie(b *testing.B) {
	bl := benchList(StorageTrie, 10000)
	probes := []netip.Addr{netip.MustParseAddr("5.7.9.1"), netip.MustParseAddr("200.1.1.1"), netip.MustParseAddr("2001:db8::1")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		bl.Match(probes[i%len(probes)])
	}
}

func BenchmarkMatchList(b *testing.B) {
	bl := benchList(StorageList, 10000)
	probes := []netip.Addr{netip.MustParseAddr("5.7.9.1"), netip.MustParseAddr("200.1.1.1")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		bl.Match(probes[i%len(probes)])
	}
}
