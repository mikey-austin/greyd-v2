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

package smtp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// ErrProxyUnknown is returned for a "PROXY UNKNOWN" header.
var ErrProxyUnknown = errors.New("UNKNOWN proxy protocol header")

// ErrProxyInvalid is returned for a malformed header.
var ErrProxyInvalid = errors.New("invalid proxy protocol header")

// MaxProxyHeader is the longest proxy protocol v1 header including the
// CRLF (from the specification).
const MaxProxyHeader = 107

// Proxy protocol v2 (binary) constants.
const (
	// ProxyV2HeaderLen is the fixed part of a v2 header: the signature,
	// the version/command and family/protocol bytes and the 16-bit length
	// of the address block that follows.
	ProxyV2HeaderLen = 16
	// MaxProxyV2Length caps the declared length of the address block
	// (addresses plus TLVs); the specification's largest address block is
	// 216 bytes and real TLV sets are small.
	MaxProxyV2Length = 512

	proxyV2Version   = 0x20
	proxyV2CmdLocal  = 0x00
	proxyV2CmdProxy  = 0x01
	proxyV2Unspec    = 0x00
	proxyV2TCPv4     = 0x11
	proxyV2UDPv4     = 0x12
	proxyV2TCPv6     = 0x21
	proxyV2UDPv6     = 0x22
	proxyV2UnixStrm  = 0x31
	proxyV2UnixDgram = 0x32
	proxyV2AddrLen4  = 12 // 2 x 4-byte address + 2 x 2-byte port
	proxyV2AddrLen6  = 36 // 2 x 16-byte address + 2 x 2-byte port
)

// ProxyV2Signature opens every proxy protocol v2 header.
var ProxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// ParseProxyHeader parses a proxy protocol v1 line
// ("PROXY TCP4 src dst sport dport") and returns the canonical source and
// destination addresses. Ports are not validated, as in the C code.
func ParseProxyHeader(line string) (src, dst netip.Addr, err error) {
	if len(line) > MaxProxyHeader {
		return src, dst, ErrProxyInvalid
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "PROXY") {
		return src, dst, ErrProxyInvalid
	}
	var want4 bool
	switch fields[1] {
	case "UNKNOWN":
		return src, dst, ErrProxyUnknown
	case "TCP4":
		want4 = true
	case "TCP6":
		want4 = false
	default:
		return src, dst, ErrProxyInvalid
	}
	if len(fields) < 4 {
		return src, dst, ErrProxyInvalid
	}
	src, err = parseFamily(fields[2], want4)
	if err != nil {
		return src, dst, err
	}
	dst, err = parseFamily(fields[3], want4)
	if err != nil {
		return src, dst, err
	}
	return src, dst, nil
}

func parseFamily(s string, want4 bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, ErrProxyInvalid
	}
	if a.Is4() != want4 {
		return netip.Addr{}, ErrProxyInvalid
	}
	return a, nil
}

// ParseProxyHeaderV2 parses a complete proxy protocol v2 (binary) header:
// the signature, a version/command byte, a family/protocol byte, the
// big-endian length of the address block and the block itself. Any TLVs
// after the addresses are skipped. A LOCAL command (a health check from
// the proxy itself) sets local and carries no addresses: the caller keeps
// the connection's own. UNSPEC, UDP and unix socket families are reported
// as ErrProxyUnknown, like a v1 "PROXY UNKNOWN" line; everything else
// that does not fit the specification is ErrProxyInvalid. Ports are not
// validated, as for v1.
func ParseProxyHeaderV2(b []byte) (src, dst netip.Addr, local bool, err error) {
	if len(b) < ProxyV2HeaderLen || !bytes.HasPrefix(b, ProxyV2Signature) {
		return src, dst, false, ErrProxyInvalid
	}
	verCmd, fam := b[12], b[13]
	length := int(binary.BigEndian.Uint16(b[14:16]))
	if verCmd&0xf0 != proxyV2Version || length > MaxProxyV2Length || len(b) != ProxyV2HeaderLen+length {
		return src, dst, false, ErrProxyInvalid
	}
	switch verCmd & 0x0f {
	case proxyV2CmdLocal:
		// The address block, whatever its family, is to be ignored.
		return src, dst, true, nil
	case proxyV2CmdProxy:
	default:
		return src, dst, false, ErrProxyInvalid
	}
	addrs := b[ProxyV2HeaderLen:]
	switch fam {
	case proxyV2TCPv4:
		if len(addrs) < proxyV2AddrLen4 {
			return src, dst, false, ErrProxyInvalid
		}
		src = netip.AddrFrom4([4]byte(addrs[0:4]))
		dst = netip.AddrFrom4([4]byte(addrs[4:8]))
	case proxyV2TCPv6:
		if len(addrs) < proxyV2AddrLen6 {
			return src, dst, false, ErrProxyInvalid
		}
		src = netip.AddrFrom16([16]byte(addrs[0:16]))
		dst = netip.AddrFrom16([16]byte(addrs[16:32]))
	case proxyV2Unspec, proxyV2UDPv4, proxyV2UDPv6, proxyV2UnixStrm, proxyV2UnixDgram:
		return src, dst, false, ErrProxyUnknown
	default:
		return src, dst, false, ErrProxyInvalid
	}
	return src, dst, false, nil
}
