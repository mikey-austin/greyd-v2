package blacklist

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/mikey-austin/greyd-golang/internal/ip"
)

func stoi(s string) uint32 { return ip.AddrToUint32(netip.MustParseAddr(s)) }

func TestAddRangeEntries(t *testing.T) {
	bl := New("Test List", "You have been blacklisted", StorageList)
	if bl.Name != "Test List" || bl.Message != "You have been blacklisted" || bl.Count != 0 {
		t.Fatal("init")
	}
	a1 := stoi("192.168.1.0")
	b1 := stoi("192.168.1.100")
	bl.AddRange(a1, b1, TypeBlack)
	if bl.Count != 2 {
		t.Fatalf("Count = %d", bl.Count)
	}
	e := bl.Entries()
	if e[0] != [3]int64{int64(a1), 1, 0} || e[1] != [3]int64{int64(b1), -1, 0} {
		t.Fatalf("entries %v", e)
	}
	bl.AddRange(a1, b1, TypeWhite)
	e = bl.Entries()
	if e[2] != [3]int64{int64(a1), 0, 1} || e[3] != [3]int64{int64(b1), 0, -1} {
		t.Fatalf("white entries %v", e)
	}
	bl.AddRange(b1, a1, TypeBlack) // ignored
	if bl.Count != 4 {
		t.Fatal("inverted range must be ignored")
	}
}

func TestCollapse(t *testing.T) {
	bl := New("Test List", "msg", StorageList)
	if bl.Collapse() != nil {
		t.Fatal("empty collapse should be nil")
	}
	bl.AddRange(stoi("10.0.0.0"), stoi("10.0.0.20")+1, TypeBlack)
	bl.AddRange(stoi("10.0.0.10"), stoi("10.0.0.50")+1, TypeBlack)
	bl.AddRange(stoi("10.0.0.40"), stoi("10.0.0.60")+1, TypeWhite)
	got := bl.Collapse()
	want := []string{"10.0.0.0/27", "10.0.0.32/29"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	// A region entirely covered by a whitelist disappears; disjoint regions
	// are both returned.
	bl = New("x", "y", StorageList)
	bl.AddRange(stoi("1.1.1.0"), stoi("1.1.1.255")+1, TypeBlack)
	bl.AddRange(stoi("1.1.1.0"), stoi("1.1.1.255")+1, TypeWhite)
	bl.AddRange(stoi("2.2.2.2"), stoi("2.2.2.2")+1, TypeBlack)
	if got := bl.Collapse(); !reflect.DeepEqual(got, []string{"2.2.2.2/32"}) {
		t.Fatalf("got %v", got)
	}

	// Duplicated ranges collapse into one block.
	bl = New("x", "y", StorageList)
	bl.AddRange(stoi("3.3.3.0"), stoi("3.3.3.255")+1, TypeBlack)
	bl.AddRange(stoi("3.3.3.0"), stoi("3.3.3.255")+1, TypeBlack)
	if got := bl.Collapse(); !reflect.DeepEqual(got, []string{"3.3.3.0/24"}) {
		t.Fatalf("got %v", got)
	}
}

func TestTrieMatching(t *testing.T) {
	bl := New("Test List", "msg", StorageTrie)
	if err := bl.Add("192.168.12.1/24"); err != nil {
		t.Fatal(err)
	}
	if err := bl.Add("10.20.1.3/16"); err != nil {
		t.Fatal(err)
	}
	if bl.Count != 2 {
		t.Fatalf("Count = %d", bl.Count)
	}
	cases := map[string]bool{
		"192.168.12.35": true,
		"192.168.14.35": false,
		"10.20.105.23":  true,
		"10.0.0.45":     false,
	}
	for a, want := range cases {
		if got := bl.Match(netip.MustParseAddr(a)); got != want {
			t.Fatalf("Match(%s) = %v", a, got)
		}
	}
	if err := bl.Add("fe80::0202:b3ff:fe1e:2201/120"); err != nil {
		t.Fatal(err)
	}
	if err := bl.Add("2010:2acd::beef:a322/64"); err != nil {
		t.Fatal(err)
	}
	if bl.Count != 4 {
		t.Fatal("Count after v6")
	}
	if !bl.Match(netip.MustParseAddr("fe80::0202:b3ff:fe1e:22a2")) {
		t.Fatal("v6 should match")
	}
	if bl.Match(netip.MustParseAddr("fe80::0202:0a00:002d:22a2")) {
		t.Fatal("v6 should not match")
	}
	if !bl.Match(netip.MustParseAddr("2010:2acd::1")) {
		t.Fatal("v6 /64 should match")
	}
	if bl.Match(netip.MustParseAddr("::ffff:192.168.14.35")) {
		t.Fatal("mapped v4 should follow v4 rules")
	}
	if !bl.Match(netip.MustParseAddr("::ffff:192.168.12.35")) {
		t.Fatal("mapped v4 should match v4 prefix")
	}
	if err := bl.Add("not an address"); err == nil {
		t.Fatal("invalid address must error")
	}
	if err := bl.Add("1.2.3.4"); err != nil || !bl.Match(netip.MustParseAddr("1.2.3.4")) || bl.Match(netip.MustParseAddr("1.2.3.5")) {
		t.Fatal("bare address should be a host prefix")
	}
	var nilbl *Blacklist
	if nilbl.Match(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("nil blacklist never matches")
	}
}

func TestListStorageMatch(t *testing.T) {
	bl := New("permitted-proxies", "", StorageList)
	_ = bl.Add("127.0.0.0/24")
	_ = bl.Add("::1/128")
	if !bl.Match(netip.MustParseAddr("127.0.0.5")) || bl.Match(netip.MustParseAddr("127.0.1.5")) {
		t.Fatal("v4 list match")
	}
	if !bl.Match(netip.MustParseAddr("::1")) || bl.Match(netip.MustParseAddr("::2")) {
		t.Fatal("v6 list match")
	}
}

func TestTrie(t *testing.T) {
	tr := NewTrie()
	if !tr.Insert(netip.MustParsePrefix("10.0.0.0/8")) || tr.Insert(netip.MustParsePrefix("10.0.0.0/8")) {
		t.Fatal("duplicate insert should return false")
	}
	if !tr.Insert(netip.MustParsePrefix("10.1.0.0/16")) {
		t.Fatal("more specific insert")
	}
	if tr.Len() != 2 {
		t.Fatal("Len")
	}
	if !tr.Contains(netip.MustParseAddr("10.1.2.3")) || !tr.Contains(netip.MustParseAddr("10.9.9.9")) || tr.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Fatal("contains")
	}
	if tr.Contains(netip.MustParseAddr("::1")) {
		t.Fatal("no v6 root")
	}
	tr.Insert(netip.MustParsePrefix("2001:db8::/32"))
	if !tr.Contains(netip.MustParseAddr("2001:db8::1")) || tr.Contains(netip.MustParseAddr("2001:db9::1")) {
		t.Fatal("v6 contains")
	}
	tr.Insert(netip.MustParsePrefix("1.2.3.4/32"))
	if !tr.Contains(netip.MustParseAddr("1.2.3.4")) || tr.Contains(netip.MustParseAddr("1.2.3.5")) {
		t.Fatal("host prefix")
	}
}
