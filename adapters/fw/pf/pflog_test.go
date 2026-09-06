/*
 * Copyright (c) 2014-2026 Mikey Austin <mikey@greyd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package pf

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

const (
	pfDrop  = 1
	af6Test = 24 // OpenBSD AF_INET6
	flagSYN = 0x02
	flagACK = 0x10
)

// pflogHeader builds a pfloghdr of the given declared length, padded to
// the aligned size the kernel prepends (and never shorter than the dir
// field so a bogus declared length can be tested).
func pflogHeader(length int, af, action, dir byte, ifname string) []byte {
	h := make([]byte, max(align(length, pflogAlign), pflogOffDir+1))
	h[pflogOffLength] = byte(length)
	h[pflogOffAf] = af
	h[pflogOffAction] = action
	h[3] = 0 // reason
	copy(h[pflogOffIfname:pflogOffIfname+pflogIfnameLen], ifname)
	copy(h[20:36], "rules")
	h[pflogOffDir] = dir
	return h
}

func tcpHeader(sport, dport uint16, flags byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 5 << 4 // data offset
	tcp[13] = flags
	return tcp
}

func ipv4Packet(src, dst string, dport uint16, flags byte, proto byte) []byte {
	tcp := tcpHeader(40000, dport, flags)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = proto
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	return append(ip, tcp...)
}

func ipv6Packet(src, dst string, dport uint16, flags byte) []byte {
	tcp := tcpHeader(40000, dport, flags)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
	ip[6] = 6 // TCP
	ip[7] = 64
	s := netip.MustParseAddr(src).As16()
	d := netip.MustParseAddr(dst).As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	return append(ip, tcp...)
}

func record(hdr, ip []byte) []byte { return append(append([]byte{}, hdr...), ip...) }

func TestParseRecordIPv4(t *testing.T) {
	syn := ipv4Packet("192.0.2.5", "198.51.100.9", 25, flagSYN, 6)

	tests := []struct {
		name          string
		pkt           []byte
		trackOutbound bool
		netIf         string
		wantAddr      string
		wantOK        bool
	}{
		{
			name:     "inbound SYN returns source",
			pkt:      record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), syn),
			wantAddr: "192.0.2.5", wantOK: true,
		},
		{
			name:          "outbound with track_outbound returns destination",
			pkt:           record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_OUT, "em0"), syn),
			trackOutbound: true,
			wantAddr:      "198.51.100.9", wantOK: true,
		},
		{
			name: "outbound without track_outbound ignored",
			pkt:  record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_OUT, "em0"), syn),
		},
		{
			name: "blocked packet ignored",
			pkt:  record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, pfDrop, PF_IN, "em0"), syn),
		},
		{
			name: "SYN+ACK ignored",
			pkt:  record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), ipv4Packet("192.0.2.5", "198.51.100.9", 25, flagSYN|flagACK, 6)),
		},
		{
			name: "pure ACK ignored",
			pkt:  record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), ipv4Packet("192.0.2.5", "198.51.100.9", 25, flagACK, 6)),
		},
		{
			name: "submission port ignored",
			pkt:  record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), ipv4Packet("192.0.2.5", "198.51.100.9", 587, flagSYN, 6)),
		},
		{
			name: "UDP ignored",
			pkt:  record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), ipv4Packet("192.0.2.5", "198.51.100.9", 25, flagSYN, 17)),
		},
		{
			name:  "net_if mismatch ignored",
			pkt:   record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), syn),
			netIf: "em1",
		},
		{
			name:     "net_if match accepted",
			pkt:      record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), syn),
			netIf:    "em0",
			wantAddr: "192.0.2.5", wantOK: true,
		},
		{
			name:     "FreeBSD 61 byte header",
			pkt:      record(pflogHeader(PflogHdrLenFreeBSD, AF_INET, PF_PASS, PF_IN, "igb0"), syn),
			wantAddr: "192.0.2.5", wantOK: true,
		},
		{
			name:     "FreeBSD 14 69 byte header",
			pkt:      record(pflogHeader(69, AF_INET, PF_PASS, PF_IN, "igb0"), syn),
			wantAddr: "192.0.2.5", wantOK: true,
		},
		{
			name: "header length below minimum",
			pkt:  record(pflogHeader(44, AF_INET, PF_PASS, PF_IN, "em0"), syn),
		},
		{
			name: "truncated after header",
			pkt:  record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), syn)[:110],
		},
		{
			name: "truncated inside header",
			pkt:  pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0")[:80],
		},
		{
			name: "empty",
			pkt:  nil,
		},
		{
			name: "unknown address family",
			pkt:  record(pflogHeader(PflogHdrLenOpenBSD, 99, PF_PASS, PF_IN, "em0"), syn),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok := ParseRecord(tc.pkt, tc.trackOutbound, tc.netIf, af6Test)
			if ok != tc.wantOK || addr != tc.wantAddr {
				t.Fatalf("ParseRecord = (%q, %v), want (%q, %v)", addr, ok, tc.wantAddr, tc.wantOK)
			}
		})
	}
}

func TestParseRecordIPv6(t *testing.T) {
	syn := ipv6Packet("2001:db8::5", "2001:db8:1::25", 25, flagSYN)
	hdr := pflogHeader(PflogHdrLenOpenBSD, af6Test, PF_PASS, PF_IN, "em0")

	addr, ok := ParseRecord(record(hdr, syn), false, "", af6Test)
	if !ok || addr != "2001:db8::5" {
		t.Fatalf("inbound v6 = (%q, %v)", addr, ok)
	}

	// The outbound destination when tracking.
	hdr[pflogOffDir] = PF_OUT
	addr, ok = ParseRecord(record(hdr, syn), true, "", af6Test)
	if !ok || addr != "2001:db8:1::25" {
		t.Fatalf("outbound v6 = (%q, %v)", addr, ok)
	}

	// The af value is per OS: with FreeBSD's AF_INET6 the OpenBSD header
	// value is not recognised.
	hdr[pflogOffDir] = PF_IN
	if _, ok := ParseRecord(record(hdr, syn), false, "", 28); ok {
		t.Fatal("expected mismatched AF_INET6 to be ignored")
	}

	// Non-SYN.
	if _, ok := ParseRecord(record(hdr, ipv6Packet("2001:db8::5", "2001:db8:1::25", 25, flagACK)), false, "", af6Test); ok {
		t.Fatal("expected v6 ACK to be ignored")
	}
}

func TestAFInet6For(t *testing.T) {
	for goos, want := range map[string]int{"openbsd": 24, "freebsd": 28, "netbsd": 24, "dragonfly": 28, "linux": defaultAF6} {
		if got := AFInet6For(goos); got != want {
			t.Errorf("AFInet6For(%q) = %d, want %d", goos, got, want)
		}
	}
}

// bpfRecord encodes one bpf_hdr plus packet for the layout, padded to the
// layout's alignment as the kernel does.
func bpfRecord(l BPFLayout, pkt []byte) []byte {
	hdrlen := align(l.CaplenOffset+10, l.Alignment)
	rec := make([]byte, align(hdrlen+len(pkt), l.Alignment))
	binary.NativeEndian.PutUint32(rec[l.CaplenOffset:], uint32(len(pkt)))
	binary.NativeEndian.PutUint32(rec[l.CaplenOffset+4:], uint32(len(pkt)+100))
	binary.NativeEndian.PutUint16(rec[l.CaplenOffset+8:], uint16(hdrlen))
	copy(rec[hdrlen:], pkt)
	return rec
}

func TestBPFRecords(t *testing.T) {
	layouts := map[string]BPFLayout{
		"default (timeval 16, align 4)":    DefaultBPFLayout,
		"openbsd (bpf_timeval 8, align 4)": {CaplenOffset: 8, Alignment: 4},
		"freebsd (timeval 16, align 8)":    {CaplenOffset: 16, Alignment: 8},
	}
	for name, l := range layouts {
		t.Run(name, func(t *testing.T) {
			a := []byte{1, 2, 3, 4, 5}
			b := []byte{9, 8, 7, 6, 5, 4, 3}
			buf := append(bpfRecord(l, a), bpfRecord(l, b)...)

			var got [][]byte
			l.Records(buf, func(pkt []byte) { got = append(got, append([]byte(nil), pkt...)) })
			if len(got) != 2 || string(got[0]) != string(a) || string(got[1]) != string(b) {
				t.Fatalf("Records delivered %v, want [%v %v]", got, a, b)
			}

			// A truncated final record is dropped without panicking.
			got = nil
			l.Records(buf[:len(buf)-3], func(pkt []byte) { got = append(got, pkt) })
			if len(got) != 1 {
				t.Fatalf("truncated buffer delivered %d records, want 1", len(got))
			}
		})
	}

	// BPFRecords uses the default layout.
	n := 0
	BPFRecords(bpfRecord(DefaultBPFLayout, []byte{1}), func([]byte) { n++ })
	if n != 1 {
		t.Fatalf("BPFRecords delivered %d records, want 1", n)
	}
	BPFRecords(nil, func([]byte) { t.Fatal("unexpected record from empty buffer") })
}

// TestBPFRecordsEndToEnd feeds pflog records through the bpf walker and
// the pflog parser together.
func TestBPFRecordsEndToEnd(t *testing.T) {
	l := BPFLayout{CaplenOffset: 8, Alignment: 4}
	in := record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_IN, "em0"), ipv4Packet("192.0.2.5", "198.51.100.9", 25, flagSYN, 6))
	blocked := record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, pfDrop, PF_IN, "em0"), ipv4Packet("192.0.2.6", "198.51.100.9", 25, flagSYN, 6))
	out := record(pflogHeader(PflogHdrLenOpenBSD, AF_INET, PF_PASS, PF_OUT, "em0"), ipv4Packet("198.51.100.9", "203.0.113.7", 25, flagSYN, 6))
	buf := append(append(bpfRecord(l, in), bpfRecord(l, blocked)...), bpfRecord(l, out)...)

	var addrs []string
	l.Records(buf, func(pkt []byte) {
		if a, ok := ParseRecord(pkt, true, "", af6Test); ok {
			addrs = append(addrs, a)
		}
	})
	if len(addrs) != 2 || addrs[0] != "192.0.2.5" || addrs[1] != "203.0.113.7" {
		t.Fatalf("addresses = %v", addrs)
	}
}
