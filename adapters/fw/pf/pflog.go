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

// Package pf is the PF firewall driver (drivers/pf.c). This file holds the
// portable pflog(4) and bpf(4) record parsing so it can be unit tested on
// any platform; the privileged parts live in the BSD-only files.
package pf

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"runtime"
)

// PF constants shared by every PF implementation (net/pfvar.h).
const (
	PF_PASS = 0 // enum { PF_PASS, PF_DROP, ... }
	PF_IN   = 1 // enum { PF_INOUT, PF_IN, PF_OUT, ... }
	PF_OUT  = 2

	// AF_INET is 2 on every BSD.
	AF_INET = 2

	// MIN_PFLOG_HDRLEN is the smallest pfloghdr the C driver accepted; it
	// covers everything up to and including the dir byte.
	MIN_PFLOG_HDRLEN = 45

	// pflogAlign is the alignment applied to pfloghdr.length to find the
	// start of the IP packet (BPF_WORDALIGN in the C driver; the pflog
	// header lengths in use, 61, 69 and 100, align identically under 4 or
	// 8 byte alignment).
	pflogAlign = 4

	// Offsets into struct pfloghdr that are common to the OpenBSD (100
	// byte), FreeBSD (61 or 69 byte) and DragonFly (61 byte) variants.
	pflogOffLength = 0
	pflogOffAf     = 1
	pflogOffAction = 2
	pflogOffIfname = 4
	pflogIfnameLen = 16 // IFNAMSIZ
	pflogOffDir    = 60

	// PflogHdrLenOpenBSD is sizeof(struct pfloghdr) on OpenBSD, which
	// appends rewritten/naf/pad, saddr, daddr, sport and dport.
	PflogHdrLenOpenBSD = 100
	// PflogHdrLenFreeBSD is PFLOG_REAL_HDRLEN on FreeBSD < 14 and
	// DragonFly (offsetof(struct pfloghdr, pad)); the kernel prepends the
	// header rounded up to BPF_WORDALIGN, 64 bytes. Newer FreeBSD reports
	// 69 (ridentifier and reserve appended) padded to 72.
	PflogHdrLenFreeBSD = 61
)

// af6ByGOOS is the value of AF_INET6 per operating system, which unlike
// AF_INET is not uniform across the BSDs.
var af6ByGOOS = map[string]int{
	"openbsd":   24,
	"freebsd":   28,
	"netbsd":    24,
	"dragonfly": 28,
}

// defaultAF6 is used on systems not in af6ByGOOS (tests on Linux); it is
// the OpenBSD value as OpenBSD is PF's home.
const defaultAF6 = 24

// AFInet6 returns AF_INET6 for the running operating system.
func AFInet6() int { return AFInet6For(runtime.GOOS) }

// AFInet6For returns AF_INET6 for the named GOOS, with a default for
// systems that do not run PF.
func AFInet6For(goos string) int {
	if v, ok := af6ByGOOS[goos]; ok {
		return v
	}
	return defaultAF6
}

func align(n, a int) int { return (n + a - 1) &^ (a - 1) }

// ParseRecord inspects one pflog(4) record (a pfloghdr followed by the
// logged IP packet, as delivered on a DLT_PFLOG bpf device) and returns
// the address greylogd should whitelist, applying the filter the C driver
// expressed through libpcap: "ip and port 25 and action pass and
// tcp[13]&0x12=0x2" plus "and on <netIf>" when configured. Both IPv4 and
// IPv6 are handled (af6 is the platform's AF_INET6 value). Inbound
// packets yield the source address; outbound packets yield the
// destination address when trackOutbound is set.
func ParseRecord(pkt []byte, trackOutbound bool, netIf string, af6 int) (addr string, ok bool) {
	if len(pkt) < MIN_PFLOG_HDRLEN {
		return "", false
	}
	hdrLen := int(pkt[pflogOffLength])
	if hdrLen < MIN_PFLOG_HDRLEN {
		return "", false
	}
	hdrLen = align(hdrLen, pflogAlign)
	if hdrLen > len(pkt) {
		return "", false
	}
	if pkt[pflogOffAction] != PF_PASS {
		return "", false
	}
	if netIf != "" {
		name := pkt[pflogOffIfname : pflogOffIfname+pflogIfnameLen]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		if string(name) != netIf {
			return "", false
		}
	}
	dir := pkt[pflogOffDir]
	if dir != PF_IN && (dir != PF_OUT || !trackOutbound) {
		return "", false
	}

	var src, dst netip.Addr
	var tcp []byte
	ip := pkt[hdrLen:]
	switch int(pkt[pflogOffAf]) {
	case AF_INET:
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return "", false
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl || ip[9] != 6 /* IPPROTO_TCP */ {
			return "", false
		}
		src = netip.AddrFrom4([4]byte(ip[12:16]))
		dst = netip.AddrFrom4([4]byte(ip[16:20]))
		tcp = ip[ihl:]
	case af6:
		if len(ip) < 40 || ip[0]>>4 != 6 || ip[6] != 6 /* next header TCP */ {
			return "", false
		}
		src = netip.AddrFrom16([16]byte(ip[8:24]))
		dst = netip.AddrFrom16([16]byte(ip[24:40]))
		tcp = ip[40:]
	default:
		return "", false
	}

	// Destination port and flags (offset 13: CWR ECE URG ACK PSH RST SYN FIN).
	if len(tcp) < 14 {
		return "", false
	}
	if binary.BigEndian.Uint16(tcp[2:4]) != 25 {
		return "", false
	}
	if tcp[13]&0x12 != 0x02 {
		return "", false
	}

	if dir == PF_IN {
		return src.String(), true
	}
	return dst.String(), true
}

// BPFLayout describes struct bpf_hdr for a platform: the offset of
// bh_caplen (which follows the platform's bpf timestamp) and
// BPF_ALIGNMENT, the alignment applied to bh_hdrlen + bh_caplen to find
// the next record. bh_datalen and bh_hdrlen follow bh_caplen at +4 and +8.
type BPFLayout struct {
	CaplenOffset int
	Alignment    int
}

// Records walks a bpf(4) read buffer and calls f with each captured
// packet. Malformed records terminate the walk.
func (l BPFLayout) Records(buf []byte, f func(pkt []byte)) {
	minHdr := l.CaplenOffset + 10
	for len(buf) >= minHdr {
		caplen := int(binary.NativeEndian.Uint32(buf[l.CaplenOffset:]))
		hdrlen := int(binary.NativeEndian.Uint16(buf[l.CaplenOffset+8:]))
		if hdrlen < minHdr || hdrlen+caplen > len(buf) {
			return
		}
		f(buf[hdrlen : hdrlen+caplen])
		next := align(hdrlen+caplen, l.Alignment)
		if next > len(buf) {
			return
		}
		buf = buf[next:]
	}
}

// DefaultBPFLayout is the 64-bit struct timeval layout (16 byte timestamp)
// with 4 byte alignment. OpenBSD uses an 8 byte bpf_timeval; FreeBSD,
// NetBSD and DragonFly align to sizeof(long). The BSD build derives the
// native layout from golang.org/x/sys/unix.BpfHdr instead.
var DefaultBPFLayout = BPFLayout{CaplenOffset: 16, Alignment: 4}

// BPFRecords walks buf using DefaultBPFLayout.
func BPFRecords(buf []byte, f func(pkt []byte)) { DefaultBPFLayout.Records(buf, f) }
