package ipfw

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

// synPacket builds a fake-Ethernet + IPv4/IPv6 + TCP record as ipfw0
// emits it.
func synPacket(src, dst netip.Addr, dport uint16, flags byte) []byte {
	var pkt []byte
	eth := make([]byte, 14)
	if src.Is4() {
		binary.BigEndian.PutUint16(eth[12:], etherTypeIPv4)
		ip := make([]byte, 20)
		ip[0] = 0x45
		ip[9] = tcpProto
		copy(ip[12:16], src.AsSlice())
		copy(ip[16:20], dst.AsSlice())
		pkt = append(eth, ip...)
	} else {
		binary.BigEndian.PutUint16(eth[12:], etherTypeIPv6)
		ip := make([]byte, 40)
		ip[0] = 0x60
		ip[6] = tcpProto
		copy(ip[8:24], src.AsSlice())
		copy(ip[24:40], dst.AsSlice())
		pkt = append(eth, ip...)
	}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 5 << 4
	tcp[13] = flags
	return append(pkt, tcp...)
}

func TestParseRecord(t *testing.T) {
	local := func(a netip.Addr) bool {
		return a == netip.MustParseAddr("192.0.2.10") || a == netip.MustParseAddr("2001:db8::10")
	}
	remote4, local4 := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("192.0.2.10")
	remote6, local6 := netip.MustParseAddr("2001:db8:1::7"), netip.MustParseAddr("2001:db8::10")

	cases := []struct {
		name     string
		pkt      []byte
		outbound bool
		want     string
		ok       bool
	}{
		{"inbound v4", synPacket(remote4, local4, 25, tcpFlagSYN), false, "198.51.100.7", true},
		{"inbound v6", synPacket(remote6, local6, 25, tcpFlagSYN), false, "2001:db8:1::7", true},
		{"outbound tracked", synPacket(local4, remote4, 25, tcpFlagSYN), true, "198.51.100.7", true},
		{"outbound untracked", synPacket(local4, remote4, 25, tcpFlagSYN), false, "", false},
		{"syn-ack ignored", synPacket(remote4, local4, 25, tcpFlagSYN|tcpFlagACK), true, "", false},
		{"other port", synPacket(remote4, local4, 587, tcpFlagSYN), true, "", false},
		{"not tcp", func() []byte { p := synPacket(remote4, local4, 25, tcpFlagSYN); p[14+9] = 17; return p }(), true, "", false},
		{"truncated", synPacket(remote4, local4, 25, tcpFlagSYN)[:30], true, "", false},
		{"short", []byte{1, 2, 3}, true, "", false},
		{"bad ethertype", func() []byte { p := synPacket(remote4, local4, 25, tcpFlagSYN); p[12] = 0x88; return p }(), true, "", false},
	}
	for _, tc := range cases {
		got, ok := ParseRecord(tc.pkt, tc.outbound, local)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: got %q %v, want %q %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
	// Without a locality oracle everything counts as outbound.
	if got, ok := ParseRecord(synPacket(remote4, local4, 25, tcpFlagSYN), true, nil); !ok || got != "192.0.2.10" {
		t.Fatalf("nil isLocal: %q %v", got, ok)
	}
}

func TestReplacePlan(t *testing.T) {
	plan := ReplacePlan("greyd-whitelist", []string{"10.0.0.0/8", "", "192.0.2.1/32"})
	if len(plan) != 6 {
		t.Fatalf("%d steps", len(plan))
	}
	if !plan[0].IgnoreErr || strings.Join(plan[0].Args, " ") != "-q table greyd-whitelist_new destroy" {
		t.Fatalf("step 0: %+v", plan[0])
	}
	if plan[2].Stdin != "table greyd-whitelist_new add 10.0.0.0/8\ntable greyd-whitelist_new add 192.0.2.1/32\n" {
		t.Fatalf("stdin %q", plan[2].Stdin)
	}
	if strings.Join(plan[4].Args, " ") != "-q table greyd-whitelist swap greyd-whitelist_new" || plan[4].IgnoreErr {
		t.Fatalf("swap: %+v", plan[4])
	}
	if !strings.Contains(Describe(plan), "<<< 2 lines") {
		t.Fatalf("describe: %s", Describe(plan))
	}
	for name, ok := range map[string]bool{"greyd-whitelist": true, "a.b_c-1": true, "": false, "bad name": false, "semi;colon": false, strings.Repeat("x", 60): false} {
		if ValidTableName(name) != ok {
			t.Errorf("ValidTableName(%q) = %v", name, !ok)
		}
	}
}
