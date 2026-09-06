package ip

import (
	"net/netip"
	"reflect"
	"testing"
)

func stoi(t *testing.T, s string) uint32 {
	t.Helper()
	return AddrToUint32(netip.MustParseAddr(s))
}

func TestCIDRString(t *testing.T) {
	if got := (CIDR{Addr: stoi(t, "192.168.1.0"), Bits: 24}).String(); got != "192.168.1.0/24" {
		t.Fatalf("got %q", got)
	}
	if got := (CIDR{Addr: stoi(t, "192.168.1.100"), Bits: 8}).String(); got != "192.168.1.100/8" {
		t.Fatalf("got %q", got)
	}
}

func TestCIDRToRange(t *testing.T) {
	start, end := CIDRToRange(CIDR{Addr: stoi(t, "10.10.0.0"), Bits: 17})
	if start != stoi(t, "10.10.0.0") || end != stoi(t, "10.10.127.255") {
		t.Fatalf("range %d %d", start, end)
	}
}

func TestRangeToCIDRs(t *testing.T) {
	got := RangeToCIDRs(stoi(t, "192.168.0.1"), stoi(t, "192.168.0.25"))
	want := []string{"192.168.0.1/32", "192.168.0.2/31", "192.168.0.4/30", "192.168.0.8/29", "192.168.0.16/29", "192.168.0.24/31"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := RangeToCIDRs(stoi(t, "10.0.0.0"), stoi(t, "10.0.0.39")); !reflect.DeepEqual(got, []string{"10.0.0.0/27", "10.0.0.32/29"}) {
		t.Fatalf("got %v", got)
	}
	if got := RangeToCIDRs(0xffffff00, 0xffffffff); !reflect.DeepEqual(got, []string{"255.255.255.0/24"}) {
		t.Fatalf("top of space got %v", got)
	}
	if got := RangeToCIDRs(5, 4); got != nil {
		t.Fatalf("inverted range got %v", got)
	}
}

func TestCheckAddr(t *testing.T) {
	cases := map[string]int{
		"123224jhjj":               -1,
		"1.2.3.4":                  4,
		"2001::fad3:1":             6,
		"fe80::2c0:8cff:fe01:2345": 6,
		"":                         -1,
		"1.2.3.4/32":               -1,
	}
	for in, want := range cases {
		if got := CheckAddr(in); got != want {
			t.Fatalf("CheckAddr(%q) = %d want %d", in, got, want)
		}
	}
}

func TestParsePrefix(t *testing.T) {
	p, err := ParsePrefix("192.168.12.1/24")
	if err != nil || p.String() != "192.168.12.0/24" {
		t.Fatalf("got %v %v", p, err)
	}
	p, err = ParsePrefix("1.2.3.4")
	if err != nil || p.String() != "1.2.3.4/32" {
		t.Fatalf("bare v4 got %v %v", p, err)
	}
	p, err = ParsePrefix("::1")
	if err != nil || p.String() != "::1/128" {
		t.Fatalf("bare v6 got %v %v", p, err)
	}
	p, err = ParsePrefix("2001:2acd::beef:a322/64")
	if err != nil || p.String() != "2001:2acd::/64" {
		t.Fatalf("v6 got %v %v", p, err)
	}
	for _, bad := range []string{"1.2.3.4/0", "1.2.3.4/33", "x/8", "1.2.3.4/x", "2001::1/129"} {
		if _, err := ParsePrefix(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

func TestUint32Conversions(t *testing.T) {
	a := netip.MustParseAddr("192.168.12.1")
	if AddrToUint32(a) != 0xC0A80C01 {
		t.Fatal("AddrToUint32")
	}
	if Uint32ToAddr(0xC0A80C01) != a {
		t.Fatal("Uint32ToAddr")
	}
	if AddrToUint32(netip.MustParseAddr("::1")) != 0 {
		t.Fatal("v6 should be 0")
	}
	if FamilyOf(netip.MustParseAddr("::ffff:1.2.3.4")) != 4 {
		t.Fatal("mapped v4 family")
	}
}
