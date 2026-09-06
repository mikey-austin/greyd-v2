//go:build netbsd

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
	"errors"
	"net/netip"
	"unsafe"
)

// bpfAlignment is BPF_ALIGNMENT from NetBSD <net/bpf.h>: sizeof(long).
const bpfAlignment = unsafe.Sizeof(uintptr(0))

// lockBpf is a no-op: NetBSD's bpf(4) has no BIOCLOCK.
func lockBpf(int) error { return nil }

// errNoNatlook is returned on systems without a PF DIOCNATLOOK; the
// caller falls back to the proxy address. NetBSD ships npf rather than PF
// (the npf driver is not ported yet).
var errNoNatlook = errors.New("nat lookup not supported on this platform")

func natlook(int, netip.AddrPort, netip.AddrPort) (netip.AddrPort, error) {
	return netip.AddrPort{}, errNoNatlook
}
