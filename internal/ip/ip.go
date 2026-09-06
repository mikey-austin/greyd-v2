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

// Package ip provides IPv4 range/CIDR arithmetic and address helpers.
package ip

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// CIDR is an IPv4 network in host byte order.
type CIDR struct {
	Addr uint32
	Bits uint8
}

// String renders the network as "a.b.c.d/n".
func (c CIDR) String() string {
	return fmt.Sprintf("%s/%d", Uint32ToAddr(c.Addr), c.Bits)
}

// Uint32ToAddr converts a host order IPv4 integer to an address.
func Uint32ToAddr(a uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
}

// AddrToUint32 converts an IPv4 address to a host order integer. Non-IPv4
// addresses yield 0.
func AddrToUint32(a netip.Addr) uint32 {
	a = a.Unmap()
	if !a.Is4() {
		return 0
	}
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// CIDRToRange returns the first and last address of the network. The
// address is not masked, matching the C implementation.
func CIDRToRange(c CIDR) (start, end uint32) {
	start = c.Addr
	end = c.Addr + (uint32(1) << (32 - c.Bits)) - 1
	return
}

// RangeToCIDRs decomposes an inclusive address range into the minimal list
// of CIDR networks, rendered as strings.
func RangeToCIDRs(start, end uint32) []string {
	var out []string
	for end >= start {
		maxsize := maxBlock(start, 32)
		diff := maxDiff(start, end)
		if diff > maxsize {
			maxsize = diff
		}
		out = append(out, CIDR{Addr: start, Bits: maxsize}.String())
		step := uint32(1) << (32 - maxsize)
		if start+step < start {
			break // wrapped past 255.255.255.255
		}
		start += step
	}
	return out
}

func maxDiff(a, b uint32) uint8 {
	b++
	for bits := uint8(0); bits < 32; bits++ {
		m := imask(bits)
		if (a & m) != (b & m) {
			return bits
		}
	}
	return 32
}

func maxBlock(addr uint32, bits uint8) uint8 {
	for bits > 0 {
		m := imask(bits - 1)
		if (addr & m) != addr {
			return bits
		}
		bits--
	}
	return bits
}

func imask(b uint8) uint32 {
	if b == 0 {
		return 0
	}
	return 0xffffffff << (32 - b)
}

// CheckAddr reports the address family of a textual IP address: 4, 6 or -1
// when the string is not a numeric address.
func CheckAddr(s string) int {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return -1
	}
	return FamilyOf(a)
}

// FamilyOf returns 4 or 6.
func FamilyOf(a netip.Addr) int {
	if a.Unmap().Is4() {
		return 4
	}
	return 6
}

// ParsePrefix parses "addr/bits" or a bare address (treated as a host
// prefix). A prefix length of zero is rejected, as in the C implementation.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	i := strings.LastIndex(s, "/")
	a, err := netip.ParseAddr(s[:i])
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	a = a.Unmap()
	bits, err := strconv.Atoi(s[i+1:])
	if err != nil || bits <= 0 || bits > a.BitLen() {
		return netip.Prefix{}, fmt.Errorf("invalid prefix length %q", s)
	}
	return netip.PrefixFrom(a, bits).Masked(), nil
}
