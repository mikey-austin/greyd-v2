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

// Package blacklist manages named lists of network blocks with a rejection
// message. Two storage strategies exist: a radix trie for fast membership
// tests of live connections (used by greyd), and a list of range
// boundaries which can be collapsed into non-overlapping CIDR blocks
// (used by greyd-setup when merging blacklists and whitelists).
package blacklist

import (
	"net/netip"
	"sort"

	"github.com/mikey-austin/greyd-v2/internal/ip"
)

// Storage selects the internal representation.
type Storage int

const (
	// StorageList keeps range boundaries for Collapse and a simple slice of
	// prefixes for Match.
	StorageList Storage = 0
	// StorageTrie keeps prefixes in a radix trie for fast Match.
	StorageTrie Storage = 1
)

// Type marks a range as black (listed) or white (excluded).
type Type int

const (
	TypeWhite Type = 0
	TypeBlack Type = 1
)

type rangeEntry struct {
	addr  uint32
	black int8
	white int8
}

// Blacklist is a named list of addresses with a rejection message.
type Blacklist struct {
	Name    string
	Message string
	// Count is the number of entries added (two per range, as in C).
	Count int

	storage  Storage
	trie     *Trie
	prefixes []netip.Prefix
	ranges   []rangeEntry
}

// New creates an empty blacklist.
func New(name, message string, s Storage) *Blacklist {
	b := &Blacklist{Name: name, Message: message, storage: s}
	if s == StorageTrie {
		b.trie = NewTrie()
	}
	return b
}

// Storage returns the storage strategy.
func (b *Blacklist) Storage() Storage { return b.storage }

// Add inserts a single network given as "addr/bits" or a bare address.
func (b *Blacklist) Add(cidr string) error {
	p, err := ip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	b.Count++
	if b.storage == StorageTrie {
		b.trie.Insert(p)
	} else {
		b.prefixes = append(b.prefixes, p)
	}
	return nil
}

// Match reports whether the address is on the list.
func (b *Blacklist) Match(a netip.Addr) bool {
	if b == nil {
		return false
	}
	a = a.Unmap()
	if b.storage == StorageTrie {
		return b.trie.Contains(a)
	}
	for _, p := range b.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// AddRange records an IPv4 range [start, end) of the given type for later
// collapsing. Ranges with start > end are ignored. Two boundary entries are
// recorded, as in the C implementation.
func (b *Blacklist) AddRange(start, end uint32, t Type) {
	if start > end {
		return
	}
	if t == TypeWhite {
		b.ranges = append(b.ranges,
			rangeEntry{addr: start, white: 1},
			rangeEntry{addr: end, white: -1})
	} else {
		b.ranges = append(b.ranges,
			rangeEntry{addr: start, black: 1},
			rangeEntry{addr: end, black: -1})
	}
	b.Count += 2
}

// Entries returns the raw range boundary entries (addr, black, white) in
// insertion order; used by tests.
func (b *Blacklist) Entries() [][3]int64 {
	out := make([][3]int64, len(b.ranges))
	for i, e := range b.ranges {
		out[i] = [3]int64{int64(e.addr), int64(e.black), int64(e.white)}
	}
	return out
}

// Collapse merges the recorded ranges, removing overlaps and any regions
// covered by white ranges, and returns the resulting CIDR blocks. It
// returns nil when no ranges were recorded.
func (b *Blacklist) Collapse() []string {
	if len(b.ranges) == 0 {
		return nil
	}
	entries := make([]rangeEntry, len(b.ranges))
	copy(entries, b.ranges)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].addr < entries[j].addr })

	var (
		cidrs         []string
		bs, ws        int
		state, bstart uint32
		lastState     uint32
		i             int
		n             = len(entries)
	)
	for i < n {
		lastState = state
		addr := entries[i].addr
		for {
			bs += int(entries[i].black)
			ws += int(entries[i].white)
			i++
			if i >= n || entries[i].addr != addr {
				break
			}
		}

		if state == 1 && bs == 0 {
			state = 0
		} else if state == 0 && bs > 0 {
			state = 1
		}
		if ws > 0 {
			state = 0
		}

		if lastState == 0 && state == 1 {
			// Start of a blacklisted region.
			bstart = addr
		}
		if lastState == 1 && state == 0 {
			// End of a blacklisted region (exclusive end).
			cidrs = append(cidrs, ip.RangeToCIDRs(bstart, addr-1)...)
		}
	}
	return cidrs
}
