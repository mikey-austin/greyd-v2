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

// Package kv contains the pieces shared by key/value style stores (memory,
// bolt): the key and data encodings and the database scan algorithm
// ported from the Berkeley DB driver.
package kv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ip"
)

// Bucket names a logical table.
type Bucket string

const (
	// BucketEntries holds IP and tuple keyed entries.
	BucketEntries Bucket = "entries"
	// BucketSpamtraps holds spamtrap addresses.
	BucketSpamtraps Bucket = "spamtraps"
	// BucketDomains holds permitted domains.
	BucketDomains Bucket = "domains"
)

// BucketFor returns the bucket a key type lives in.
func BucketFor(t core.KeyType) Bucket {
	switch t {
	case core.KeyMail:
		return BucketSpamtraps
	case core.KeyDomain, core.KeyDomainPart:
		return BucketDomains
	default:
		return BucketEntries
	}
}

// EncodeKey serialises a key as type byte followed by NUL separated
// fields.
func EncodeKey(k core.Key) []byte {
	var b bytes.Buffer
	b.WriteByte(byte(k.Type))
	if k.Type == core.KeyTuple {
		b.WriteString(k.Tuple.IP)
		b.WriteByte(0)
		b.WriteString(k.Tuple.Helo)
		b.WriteByte(0)
		b.WriteString(k.Tuple.From)
		b.WriteByte(0)
		b.WriteString(k.Tuple.To)
	} else {
		b.WriteString(k.Str)
	}
	return b.Bytes()
}

// DecodeKey reverses EncodeKey.
func DecodeKey(b []byte) (core.Key, error) {
	if len(b) == 0 {
		return core.Key{}, fmt.Errorf("empty key")
	}
	k := core.Key{Type: core.KeyType(b[0])}
	rest := string(b[1:])
	if k.Type == core.KeyTuple {
		parts := strings.SplitN(rest, "\x00", 4)
		if len(parts) != 4 {
			return core.Key{}, fmt.Errorf("malformed tuple key")
		}
		k.Tuple = core.Tuple{IP: parts[0], Helo: parts[1], From: parts[2], To: parts[3]}
	} else {
		k.Str = rest
	}
	return k, nil
}

// EncodeData serialises the counters as five big-endian int64 values.
func EncodeData(d core.Data) []byte {
	b := make([]byte, 40)
	binary.BigEndian.PutUint64(b[0:], uint64(d.First))
	binary.BigEndian.PutUint64(b[8:], uint64(d.Pass))
	binary.BigEndian.PutUint64(b[16:], uint64(d.Expire))
	binary.BigEndian.PutUint64(b[24:], uint64(int64(d.BCount)))
	binary.BigEndian.PutUint64(b[32:], uint64(int64(d.PCount)))
	return b
}

// DecodeData reverses EncodeData.
func DecodeData(b []byte) (core.Data, error) {
	if len(b) != 40 {
		return core.Data{}, fmt.Errorf("malformed data value of %d bytes", len(b))
	}
	return core.Data{
		First:  int64(binary.BigEndian.Uint64(b[0:])),
		Pass:   int64(binary.BigEndian.Uint64(b[8:])),
		Expire: int64(binary.BigEndian.Uint64(b[16:])),
		BCount: int(int64(binary.BigEndian.Uint64(b[24:]))),
		PCount: int(int64(binary.BigEndian.Uint64(b[32:]))),
	}, nil
}

// DomainMatches reports whether a permitted domain entry matches the
// recipient address (suffix match, as the SQL drivers' LIKE '%' || domain).
func DomainMatches(domain, addr string) bool {
	return strings.HasSuffix(strings.ToLower(addr), strings.ToLower(domain))
}

// Ops is the subset of store operations the scan needs.
type Ops interface {
	Iter(types core.IterTypes) (core.Iterator, error)
	Put(k core.Key, d core.Data) error
	Get(k core.Key) (core.Data, bool, error)
}

// Scan implements Store.Scan for key/value stores (port of bdb.c
// Mod_scan_db, with the SQL drivers' rule of not whitelisting a tuple whose
// address already has an address-keyed entry):
//
//   - entries with expire <= now (other than spamtraps and domains) are
//     deleted;
//   - address-keyed greytrap entries populate the traplist;
//   - tuples whose pass time has arrived are re-keyed by address with a
//     fresh white expiry and removed, unless the address already has an
//     entry;
//   - address-keyed white entries populate the whitelists.
func Scan(ops Ops, now, whiteExp int64) (core.ScanResult, error) {
	var res core.ScanResult
	seen := map[string]bool{}

	it, err := ops.Iter(core.IterEntries)
	if err != nil {
		return res, err
	}
	defer it.Close()

	addWhite := func(addr string) {
		if seen[addr] {
			return
		}
		seen[addr] = true
		if ip.CheckAddr(addr) == 6 {
			res.WhitelistV6 = append(res.WhitelistV6, addr)
		} else {
			res.Whitelist = append(res.Whitelist, addr)
		}
	}

	for {
		k, d, ok, err := it.Next()
		if err != nil {
			return res, err
		}
		if !ok {
			break
		}

		switch {
		case d.Expire <= now && d.PCount > core.PCountSpamtrap:
			if err := it.DeleteCurrent(); err != nil {
				return res, err
			}

		case d.PCount == core.PCountTrapped && k.Type == core.KeyIP:
			res.Traplist = append(res.Traplist, k.Str)

		case d.PCount >= 0 && d.Pass <= now:
			switch k.Type {
			case core.KeyTuple:
				state, err := core.AddrState(ops, k.Tuple.IP)
				if err != nil {
					return res, err
				}
				if state != 0 {
					// Trapped or already whitelisted: leave the tuple alone.
					continue
				}
				d.Expire = now + whiteExp
				if err := ops.Put(core.IPKey(k.Tuple.IP), d); err != nil {
					return res, err
				}
				if err := it.DeleteCurrent(); err != nil {
					return res, err
				}
				addWhite(k.Tuple.IP)
			case core.KeyIP:
				addWhite(k.Str)
			}
		}
	}
	return res, nil
}
