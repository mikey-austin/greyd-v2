//go:build freebsd || dragonfly

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
	"unsafe"

	"golang.org/x/sys/unix"
)

// bpfAlignment is BPF_ALIGNMENT from FreeBSD and DragonFly <net/bpf.h>:
// sizeof(long).
const bpfAlignment = unsafe.Sizeof(uintptr(0))

// lockBpf issues BIOCLOCK so the descriptor cannot be reconfigured after
// privileges are dropped.
func lockBpf(fd int) error { return unix.IoctlSetInt(fd, unix.BIOCLOCK, 0) }

// pfiocNatlook is struct pfioc_natlook from FreeBSD <net/pfvar.h> and
// DragonFly <net/pf/pfvar.h> (identical):
//
//	struct pf_addr saddr, daddr, rsaddr, rdaddr;   (16 bytes each)
//	u_int16_t sport, dport, rsport, rdport;
//	sa_family_t af; u_int8_t proto; u_int8_t direction;
//
// 75 bytes padded to 76. Ports are kept as byte pairs because PF expects
// them in network order.
type pfiocNatlook struct {
	Saddr, Daddr, Rsaddr, Rdaddr pfAddr
	Sport, Dport, Rsport, Rdport [2]byte
	Af, Proto, Direction         uint8
	_                            [1]byte
}

// Compile-time check that the Go layout has the C size (76).
var _ = [1]struct{}{}[unsafe.Sizeof(pfiocNatlook{})-76]

// diocNatlook is DIOCNATLOOK = _IOWR('D', 23, struct pfioc_natlook),
// which <sys/ioccom.h> encodes as IOC_INOUT | (size & IOCPARM_MASK) << 16
// | 'D' << 8 | 23 = 0xC04C4417 for the 76 byte struct.
const diocNatlook = iocInOut | (uint(unsafe.Sizeof(pfiocNatlook{}))&iocParmMask)<<16 | 'D'<<8 | 23

// Compile-time check of the expected request number.
var _ = [1]struct{}{}[diocNatlook-0xC04C4417]

// natlook performs DIOCNATLOOK for the connection src -> proxy seen from
// the outbound direction and returns the original destination.
func natlook(pfdev int, src, proxy netip.AddrPort) (netip.AddrPort, error) {
	pnl := pfiocNatlook{
		Saddr:     toPfAddr(src.Addr()),
		Daddr:     toPfAddr(proxy.Addr()),
		Proto:     unix.IPPROTO_TCP,
		Direction: PF_OUT,
	}
	binary.BigEndian.PutUint16(pnl.Sport[:], src.Port())
	binary.BigEndian.PutUint16(pnl.Dport[:], proxy.Port())
	v4 := src.Addr().Is4()
	if v4 {
		pnl.Af = unix.AF_INET
	} else {
		pnl.Af = unix.AF_INET6
	}
	if err := ioctlPtr(pfdev, diocNatlook, unsafe.Pointer(&pnl)); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(fromPfAddr(pnl.Rdaddr, v4), binary.BigEndian.Uint16(pnl.Rdport[:])), nil
}
