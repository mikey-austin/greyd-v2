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

// Package sync implements the spamd compatible UDP/multicast
// synchronisation protocol (version 2) used to share greylist, whitelist
// and trapped entries between greyd and spamd hosts. The wire format is
// byte for byte that of sync.c.
package sync

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // spamd sync protocol
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
)

// Protocol constants (sync.h).
const (
	Version       = 2
	MulticastAddr = "224.0.1.241"
	DefaultTTL    = 1
	DefaultKey    = "/etc/greyd/greyd.key"
	DefaultPort   = 8025
	HMACLen       = 20
	MaxSize       = 1408
	afInet        = 2
	alignBytes    = 15
)

// TLV types.
const (
	TypeEnd        uint16 = 0x0000
	TypeGrey       uint16 = 0x0001
	TypeWhite      uint16 = 0x0002
	TypeTrapped    uint16 = 0x0003
	TypeDelWhite   uint16 = 0x0004
	TypeDelTrapped uint16 = 0x0005
)

const (
	hdrLen     = 32 // version, af, length, counter, hmac[20], pad[4]
	tlvHdrLen  = 4
	// greyHdrLen is sizeof(struct spam_synctlv_grey), which is packed:
	// type, length, timestamp, ip, fromlen, tolen, helolen. The strings
	// follow immediately.
	greyHdrLen = 18
	addrLen    = 16 // type, length, timestamp, expire, ip
	endLen     = 4
)

// Key is the HMAC key: the lower case hex SHA1 digest of the key file
// followed by a NUL, or all zeros when no key file is configured. The C
// implementation passes the whole 41 byte buffer to HMAC, so the layout
// matters for interoperability.
type Key [sha1.Size*2 + 1]byte

// LoadKey computes the key from the named file. ok is false when the file
// does not exist, in which case the zero key is returned.
func LoadKey(path string) (k Key, ok bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return k, false, nil
		}
		return k, false, err
	}
	defer func() { _ = f.Close() }()
	h := sha1.New() //nolint:gosec // the spamd sync protocol authenticates with HMAC-SHA1
	if _, err := io.Copy(h, f); err != nil {
		return k, false, err
	}
	hex.Encode(k[:sha1.Size*2], h.Sum(nil))
	return k, true, nil
}

func align(n int) int { return (n + alignBytes) &^ alignBytes }

func sign(k *Key, pkt []byte) {
	mac := hmac.New(sha1.New, k[:])
	mac.Write(pkt)
	copy(pkt[8:8+HMACLen], mac.Sum(nil))
}

// EncodeGrey builds a packet carrying one greylist tuple.
func EncodeGrey(k *Key, counter uint32, ip netip.Addr, helo, from, to string, now uint32) []byte {
	fromB := append([]byte(from), 0)
	toB := append([]byte(to), 0)
	heloB := append([]byte(helo), 0)
	sglen := greyHdrLen + len(fromB) + len(toB) + len(heloB)
	padlen := align(sglen) - sglen
	total := hdrLen + sglen + padlen + endLen

	pkt := make([]byte, total)
	putHeader(pkt, counter, total)

	p := pkt[hdrLen:]
	binary.BigEndian.PutUint16(p[0:], TypeGrey)
	binary.BigEndian.PutUint16(p[2:], uint16(sglen+padlen))
	binary.BigEndian.PutUint32(p[4:], now)
	copy(p[8:12], ip4(ip))
	binary.BigEndian.PutUint16(p[12:], uint16(len(fromB)))
	binary.BigEndian.PutUint16(p[14:], uint16(len(toB)))
	binary.BigEndian.PutUint16(p[16:], uint16(len(heloB)))
	off := greyHdrLen
	off += copy(p[off:], fromB)
	off += copy(p[off:], toB)
	off += copy(p[off:], heloB)
	off += padlen
	putEnd(p[off:])

	sign(k, pkt)
	return pkt
}

// EncodeAddr builds a packet carrying one white/trapped (or deletion)
// entry.
func EncodeAddr(k *Key, counter uint32, typ uint16, ip netip.Addr, now, expire uint32) []byte {
	total := hdrLen + addrLen + endLen
	pkt := make([]byte, total)
	putHeader(pkt, counter, total)
	p := pkt[hdrLen:]
	binary.BigEndian.PutUint16(p[0:], typ)
	binary.BigEndian.PutUint16(p[2:], addrLen)
	binary.BigEndian.PutUint32(p[4:], now)
	binary.BigEndian.PutUint32(p[8:], expire)
	copy(p[12:16], ip4(ip))
	putEnd(p[addrLen:])
	sign(k, pkt)
	return pkt
}

func putHeader(pkt []byte, counter uint32, total int) {
	pkt[0] = Version
	pkt[1] = afInet
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	binary.BigEndian.PutUint32(pkt[4:], counter)
}

func putEnd(p []byte) {
	binary.BigEndian.PutUint16(p[0:], TypeEnd)
	binary.BigEndian.PutUint16(p[2:], endLen)
}

func ip4(a netip.Addr) []byte {
	a = a.Unmap()
	if !a.Is4() {
		return []byte{0, 0, 0, 0}
	}
	b := a.As4()
	return b[:]
}

// Entry is a decoded synchronisation record.
type Entry struct {
	Type   uint16
	IP     netip.Addr
	Helo   string
	From   string
	To     string
	Expire uint32
	// Delete is set for TypeDelWhite and TypeDelTrapped.
	Delete bool
}

// ErrTruncated is returned for malformed, truncated or unauthenticated
// packets.
var ErrTruncated = errors.New("truncated or invalid packet")

// Packet is a decoded, authenticated synchronisation packet.
type Packet struct {
	Counter uint32
	Entries []Entry
}

// Decode validates and parses a packet.
func Decode(k *Key, pkt []byte) (Packet, error) {
	if len(pkt) < hdrLen || pkt[0] != Version || pkt[1] != afInet {
		return Packet{}, ErrTruncated
	}
	length := int(binary.BigEndian.Uint16(pkt[2:]))
	if len(pkt) < length || length < hdrLen {
		return Packet{}, ErrTruncated
	}
	pkt = pkt[:length]
	out := Packet{Counter: binary.BigEndian.Uint32(pkt[4:])}

	var got [HMACLen]byte
	copy(got[:], pkt[8:8+HMACLen])
	buf := make([]byte, length)
	copy(buf, pkt)
	for i := range HMACLen {
		buf[8+i] = 0
	}
	mac := hmac.New(sha1.New, k[:])
	mac.Write(buf)
	if !hmac.Equal(got[:], mac.Sum(nil)) {
		return Packet{}, ErrTruncated
	}

	p := buf[hdrLen:]
	for len(p) > 0 {
		if len(p) < tlvHdrLen {
			return Packet{}, ErrTruncated
		}
		typ := binary.BigEndian.Uint16(p[0:])
		tl := int(binary.BigEndian.Uint16(p[2:]))
		if tl < tlvHdrLen || len(p) < tl {
			return Packet{}, ErrTruncated
		}

		switch typ {
		case TypeGrey:
			if tl < greyHdrLen {
				return Packet{}, ErrTruncated
			}
			fromLen := int(binary.BigEndian.Uint16(p[12:]))
			toLen := int(binary.BigEndian.Uint16(p[14:]))
			heloLen := int(binary.BigEndian.Uint16(p[16:]))
			if greyHdrLen+fromLen+toLen+heloLen > tl {
				return Packet{}, ErrTruncated
			}
			s := p[greyHdrLen:]
			out.Entries = append(out.Entries, Entry{
				Type: typ,
				IP:   netip.AddrFrom4([4]byte(p[8:12])),
				From: cstr(s[:fromLen]),
				To:   cstr(s[fromLen : fromLen+toLen]),
				Helo: cstr(s[fromLen+toLen : fromLen+toLen+heloLen]),
			})

		case TypeWhite, TypeDelWhite, TypeTrapped, TypeDelTrapped:
			if tl != addrLen {
				return Packet{}, ErrTruncated
			}
			out.Entries = append(out.Entries, Entry{
				Type:   typ,
				IP:     netip.AddrFrom4([4]byte(p[12:16])),
				Expire: binary.BigEndian.Uint32(p[8:]),
				Delete: typ == TypeDelWhite || typ == TypeDelTrapped,
			})

		case TypeEnd:
			return out, nil

		default:
			return out, ErrTruncated
		}
		p = p[tl:]
	}
	return out, nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
