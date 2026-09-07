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

// Package ipfw is the FreeBSD firewall driver: whitelists live in ipfw
// lookup tables replaced atomically through ipfw(8), connections are
// tracked by reading the ipfw0 log interface with bpf(4), and the
// original destination of a redirected connection is the socket's own
// address, because ipfw fwd does not rewrite the packet.
//
// The ipfw control socket checks privileges on every call, so the process
// holding this driver keeps them (core.PrivilegeKeeper).
//
// Configuration (section "firewall"): ipfw_path (default /sbin/ipfw),
// ipfw_log_if (default ipfw0), net_if (interface whose addresses count as
// local for direction detection; default all interfaces) and
// track_outbound.
package ipfw

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// DriverName is the configuration driver value.
const DriverName = "ipfw"

// Defaults for the "firewall" section.
const (
	DefaultIpfwPath = "/sbin/ipfw"
	DefaultLogIf    = "ipfw0"
	// DefaultTrackOutbound mirrors the other drivers.
	DefaultTrackOutbound = 1
)

// TableSuffix names the staging table used for an atomic swap.
const TableSuffix = "_new"

// Step is one ipfw invocation of a table replacement plan; Stdin is fed
// to ipfw when non-empty and IgnoreErr marks best-effort steps.
type Step struct {
	Args      []string
	Stdin     string
	IgnoreErr bool
}

// ReplacePlan is the sequence of ipfw commands that replaces the contents
// of table set with cidrs atomically: the entries are loaded into a
// staging table which is then swapped with the live one, so readers never
// see an empty or partial table.
func ReplacePlan(set string, cidrs []string) []Step {
	tmp := set + TableSuffix
	var sb strings.Builder
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		sb.WriteString("table ")
		sb.WriteString(tmp)
		sb.WriteString(" add ")
		sb.WriteString(c)
		sb.WriteByte('\n')
	}
	return []Step{
		{Args: []string{"-q", "table", tmp, "destroy"}, IgnoreErr: true},
		{Args: []string{"-q", "table", tmp, "create", "type", "addr"}},
		{Args: []string{"-q", "/dev/stdin"}, Stdin: sb.String()},
		{Args: []string{"-q", "table", set, "create", "type", "addr"}, IgnoreErr: true},
		{Args: []string{"-q", "table", set, "swap", tmp}},
		{Args: []string{"-q", "table", tmp, "destroy"}, IgnoreErr: true},
	}
}

// ValidTableName reports whether ipfw accepts set as a table name (up to
// 63 characters of letters, digits, '_', '-' and '.').
func ValidTableName(set string) bool {
	if set == "" || len(set) > 63-len(TableSuffix) {
		return false
	}
	for i := 0; i < len(set); i++ {
		c := set[i]
		ok := c == '_' || c == '-' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}

// Log records on the ipfw0 interface carry a fake Ethernet header
// (DLT_EN10MB) in front of the IP packet.
const (
	etherHdrLen   = 14
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	smtpPort      = 25
	tcpProto      = 6
	tcpFlagSYN    = 0x02
	tcpFlagACK    = 0x10
)

// ParseRecord extracts the address to whitelist from one logged packet:
// the source of a TCP SYN to port 25 addressed to a local address
// (inbound), or, with trackOutbound, the destination of a SYN to port 25
// leaving the host. isLocal decides which addresses are ours. Anything
// else, including SYN/ACKs and packets too short to hold their headers,
// yields ok = false.
func ParseRecord(pkt []byte, trackOutbound bool, isLocal func(netip.Addr) bool) (addr string, ok bool) {
	if len(pkt) < etherHdrLen {
		return "", false
	}
	var src, dst netip.Addr
	var tcp []byte
	ip := pkt[etherHdrLen:]
	switch binary.BigEndian.Uint16(pkt[12:14]) {
	case etherTypeIPv4:
		if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != tcpProto {
			return "", false
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl {
			return "", false
		}
		src = netip.AddrFrom4([4]byte(ip[12:16]))
		dst = netip.AddrFrom4([4]byte(ip[16:20]))
		tcp = ip[ihl:]
	case etherTypeIPv6:
		if len(ip) < 40 || ip[0]>>4 != 6 || ip[6] != tcpProto {
			return "", false
		}
		src = netip.AddrFrom16([16]byte(ip[8:24]))
		dst = netip.AddrFrom16([16]byte(ip[24:40]))
		tcp = ip[40:]
	default:
		return "", false
	}
	if len(tcp) < 14 {
		return "", false
	}
	dport := binary.BigEndian.Uint16(tcp[2:4])
	flags := tcp[13]
	if dport != smtpPort || flags&tcpFlagSYN == 0 || flags&tcpFlagACK != 0 {
		return "", false
	}
	if isLocal != nil && isLocal(dst) {
		return src.String(), true
	}
	if trackOutbound {
		return dst.String(), true
	}
	return "", false
}

// Describe renders a plan for logs and tests.
func Describe(p []Step) string {
	var sb strings.Builder
	for _, s := range p {
		fmt.Fprintf(&sb, "ipfw %s", strings.Join(s.Args, " "))
		if s.Stdin != "" {
			fmt.Fprintf(&sb, " <<< %d lines", strings.Count(s.Stdin, "\n"))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
