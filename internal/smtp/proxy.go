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
	"errors"
	"net/netip"
	"strings"
)

// ErrProxyUnknown is returned for a "PROXY UNKNOWN" header.
var ErrProxyUnknown = errors.New("UNKNOWN proxy protocol header")

// ErrProxyInvalid is returned for a malformed header.
var ErrProxyInvalid = errors.New("invalid proxy protocol header")

// ParseProxyHeader parses a proxy protocol v1 line
// ("PROXY TCP4 src dst sport dport") and returns the canonical source and
// destination addresses. Ports are not validated, as in the C code.
func ParseProxyHeader(line string) (src, dst netip.Addr, err error) {
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
