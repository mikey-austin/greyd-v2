package smtp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func FuzzParseProxyHeader(f *testing.F) {
	f.Add("PROXY TCP4 192.0.2.1 198.51.100.1 40000 25")
	f.Add("PROXY TCP6 2001:db8::1 2001:db8::2 1 2")
	f.Add("PROXY UNKNOWN")
	f.Add("PROXY TCP4 1.2.3.4")
	f.Add("proxy tcp4 ::1 ::2 1 2")
	f.Fuzz(func(t *testing.T, line string) {
		src, dst, err := ParseProxyHeader(line)
		switch {
		case err == nil:
			if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() {
				t.Fatalf("accepted header with bad addresses: %q -> %v %v", line, src, dst)
			}
			if len(line) > MaxProxyHeader {
				t.Fatalf("accepted oversized header (%d bytes)", len(line))
			}
		case errors.Is(err, ErrProxyInvalid), errors.Is(err, ErrProxyUnknown):
		default:
			t.Fatalf("unexpected error %v", err)
		}
	})
}

// TestParseProxyHeaderRoundTrip is a property test over generated headers.
func TestParseProxyHeaderRoundTrip(t *testing.T) {
	for i := 0; i < 2000; i++ {
		var src, dst netip.Addr
		var proto string
		if i%2 == 0 {
			src = netip.AddrFrom4([4]byte{byte(i), byte(i >> 8), 7, byte(i * 3)})
			dst = netip.AddrFrom4([4]byte{10, byte(i), byte(i >> 4), 1})
			proto = "TCP4"
		} else {
			var a, b [16]byte
			for j := range a {
				a[j] = byte(i * (j + 1))
				b[j] = byte(i ^ (j * 17))
			}
			src, dst = netip.AddrFrom16(a), netip.AddrFrom16(b)
			proto = "TCP6"
		}
		line := fmt.Sprintf("PROXY %s %s %s %d %d", proto, src, dst, i%65536, 25)
		gs, gd, err := ParseProxyHeader(line)
		if err != nil || gs != src || gd != dst {
			t.Fatalf("%q: %v %v %v", line, gs, gd, err)
		}
	}
}

func FuzzExpandMessage(f *testing.F) {
	f.Add("Your address %A has been blocked", "1.2.3.4")
	f.Add("%%A%A%%\\n\\\\", "::1")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, format, addr string) {
		out := ExpandMessage(format, addr)
		// Expansion never grows beyond one address per "%A".
		if max := len(format) + strings.Count(format, "%A")*len(addr); len(out) > max {
			t.Fatalf("%q with %q: %q longer than %d", format, addr, out, max)
		}
		// Without escapes that could neutralise it ("%%A" is a literal
		// percent sign followed by A), every "%A" yields the address.
		if !strings.Contains(format, "\\") && strings.Count(format, "%") == strings.Count(format, "%A") &&
			strings.Contains(format, "%A") && !strings.Contains(out, addr) {
			t.Fatalf("%q with %q: %q lost the address", format, addr, out)
		}
	})
}

func BenchmarkExpandMessage(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ExpandMessage("Your address %A has been blocked\\nby our blacklist, see http://x/%A", "192.0.2.44")
	}
}
