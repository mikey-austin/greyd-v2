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

import "net/netip"

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
)

// addrFromPacket extracts the source (wantSource) or destination address
// from the IP header at the start of an NFLOG packet payload. The address
// family is taken from the version nibble, as the kernel delivers both
// IPv4 and IPv6 packets to the same NFLOG group. It returns false when the
// payload is too short or is not an IP packet (log_callback).
func addrFromPacket(payload []byte, wantSource bool) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	switch payload[0] >> 4 {
	case 4:
		if len(payload) < ipv4HeaderLen {
			return "", false
		}
		var a [4]byte
		if wantSource {
			copy(a[:], payload[12:16])
		} else {
			copy(a[:], payload[16:20])
		}
		return netip.AddrFrom4(a).String(), true
	case 6:
		if len(payload) < ipv6HeaderLen {
			return "", false
		}
		var a [16]byte
		if wantSource {
			copy(a[:], payload[8:24])
		} else {
			copy(a[:], payload[24:40])
		}
		return netip.AddrFrom16(a).String(), true
	}
	return "", false
}
