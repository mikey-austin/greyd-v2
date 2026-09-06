/*
 * Copyright (C) 2014-2026  Mikey Austin <mikey@greyd.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package netfilter

import (
	"net/netip"
	"testing"
)

// ipv4Packet builds a minimal IPv4 header (plus trailing payload bytes).
func ipv4Packet(src, dst string) []byte {
	p := make([]byte, ipv4HeaderLen+8)
	p[0] = 0x45 // version 4, IHL 5
	p[9] = 6    // TCP
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

// ipv6Packet builds a minimal IPv6 header (plus trailing payload bytes).
func ipv6Packet(src, dst string) []byte {
	p := make([]byte, ipv6HeaderLen+8)
	p[0] = 0x60 // version 6
	p[6] = 6    // next header TCP
	s := netip.MustParseAddr(src).As16()
	d := netip.MustParseAddr(dst).As16()
	copy(p[8:24], s[:])
	copy(p[24:40], d[:])
	return p
}

func TestAddrFromPacketIPv4(t *testing.T) {
	p := ipv4Packet("192.0.2.10", "198.51.100.25")
	if got, ok := addrFromPacket(p, true); !ok || got != "192.0.2.10" {
		t.Fatalf("source: got %q, %v", got, ok)
	}
	if got, ok := addrFromPacket(p, false); !ok || got != "198.51.100.25" {
		t.Fatalf("destination: got %q, %v", got, ok)
	}
	// Exactly a header, no payload, is still enough.
	if got, ok := addrFromPacket(p[:ipv4HeaderLen], true); !ok || got != "192.0.2.10" {
		t.Fatalf("header only: got %q, %v", got, ok)
	}
}

func TestAddrFromPacketIPv6(t *testing.T) {
	p := ipv6Packet("2001:db8::1", "2001:db8:ffff::25")
	if got, ok := addrFromPacket(p, true); !ok || got != "2001:db8::1" {
		t.Fatalf("source: got %q, %v", got, ok)
	}
	if got, ok := addrFromPacket(p, false); !ok || got != "2001:db8:ffff::25" {
		t.Fatalf("destination: got %q, %v", got, ok)
	}
	if got, ok := addrFromPacket(p[:ipv6HeaderLen], false); !ok || got != "2001:db8:ffff::25" {
		t.Fatalf("header only: got %q, %v", got, ok)
	}
}

func TestAddrFromPacketTruncated(t *testing.T) {
	v4 := ipv4Packet("192.0.2.10", "198.51.100.25")
	v6 := ipv6Packet("2001:db8::1", "2001:db8::2")
	cases := map[string][]byte{
		"empty":        nil,
		"ipv4 short":   v4[:ipv4HeaderLen-1],
		"ipv4 version": v4[:1],
		"ipv6 short":   v6[:ipv6HeaderLen-1],
		"ipv6 version": v6[:1],
	}
	for name, p := range cases {
		if got, ok := addrFromPacket(p, true); ok || got != "" {
			t.Errorf("%s: expected failure, got %q, %v", name, got, ok)
		}
	}
}

func TestAddrFromPacketBadVersion(t *testing.T) {
	for _, v := range []byte{0x00, 0x10, 0x50, 0x70, 0xf0} {
		p := ipv6Packet("2001:db8::1", "2001:db8::2")
		p[0] = v
		if got, ok := addrFromPacket(p, true); ok || got != "" {
			t.Errorf("version nibble %#x: expected failure, got %q, %v", v>>4, got, ok)
		}
	}
}
