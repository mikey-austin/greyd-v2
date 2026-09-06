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

package blacklist

import "net/netip"

// Trie is a binary radix trie over network prefixes, one per address
// family. It answers "is this address covered by any inserted prefix" in
// O(prefix length) time, replacing the PATRICIA trie of the C version.
type Trie struct {
	roots map[int]*node
	count int
}

type node struct {
	kids     [2]*node
	terminal bool
}

// NewTrie creates an empty trie.
func NewTrie() *Trie {
	return &Trie{roots: make(map[int]*node)}
}

// Insert adds a prefix. Inserting a prefix already present is a no-op and
// returns false.
func (t *Trie) Insert(p netip.Prefix) bool {
	p = p.Masked()
	fam := p.Addr().BitLen()
	root := t.roots[fam]
	if root == nil {
		root = &node{}
		t.roots[fam] = root
	}
	n := root
	b := p.Addr().AsSlice()
	for i := 0; i < p.Bits(); i++ {
		bit := (b[i/8] >> (7 - uint(i%8))) & 1
		if n.kids[bit] == nil {
			n.kids[bit] = &node{}
		}
		n = n.kids[bit]
	}
	if n.terminal {
		return false
	}
	n.terminal = true
	t.count++
	return true
}

// Contains reports whether the address is covered by an inserted prefix.
func (t *Trie) Contains(a netip.Addr) bool {
	a = a.Unmap()
	n := t.roots[a.BitLen()]
	if n == nil {
		return false
	}
	b := a.AsSlice()
	for i := 0; i < a.BitLen(); i++ {
		if n.terminal {
			return true
		}
		bit := (b[i/8] >> (7 - uint(i%8))) & 1
		n = n.kids[bit]
		if n == nil {
			return false
		}
	}
	return n.terminal
}

// Len returns the number of distinct prefixes inserted.
func (t *Trie) Len() int { return t.count }
