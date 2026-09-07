package ip

import (
	"math/rand"
	"net/netip"
	"testing"
)

// TestRangeToCIDRsProperty checks that the CIDR decomposition of a range
// covers exactly [start, end], with no overlaps, against netip.
func TestRangeToCIDRsProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	check := func(start, end uint32) {
		t.Helper()
		cidrs := RangeToCIDRs(start, end)
		var total uint64
		prev := uint64(start)
		for i, c := range cidrs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				t.Fatalf("%d-%d: bad cidr %q", start, end, c)
			}
			lo := uint64(AddrToUint32(p.Addr()))
			size := uint64(1) << (32 - p.Bits())
			if lo != prev || (i == 0 && lo != uint64(start)) {
				t.Fatalf("%d-%d: cidr %q does not continue at %d", start, end, c, prev)
			}
			if lo%size != 0 {
				t.Fatalf("%d-%d: cidr %q not aligned", start, end, c)
			}
			prev = lo + size
			total += size
		}
		if total != uint64(end)-uint64(start)+1 {
			t.Fatalf("%d-%d: covers %d addresses via %v", start, end, total, cidrs)
		}
	}
	for _, tc := range [][2]uint32{{0, 0}, {0, 0xffffffff}, {0xffffffff, 0xffffffff}, {1, 2}, {0x0a000000, 0x0a0000ff}, {0xfffffffe, 0xffffffff}} {
		check(tc[0], tc[1])
	}
	for i := 0; i < 20000; i++ {
		a, b := rng.Uint32(), rng.Uint32()
		if a > b {
			a, b = b, a
		}
		if i%3 == 0 {
			b = a + uint32(rng.Intn(5000))
			if b < a {
				b = 0xffffffff
			}
		}
		check(a, b)
	}
}

func BenchmarkRangeToCIDRs(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		RangeToCIDRs(0x0a000001, 0x0afffffe)
	}
}
