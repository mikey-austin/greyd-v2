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

package spamdlist

import (
	"errors"
	"fmt"
	"io"

	"github.com/mikey-austin/greyd-v2/internal/blacklist"
	"github.com/mikey-austin/greyd-v2/internal/ip"
)

// Error is a positioned parse error.
type Error struct {
	Line, Col int
}

func (e *Error) Error() string {
	return fmt.Sprintf("parse error at line %d col %d", e.Line, e.Col)
}

// Grammar (spamd_parser.h):
//
//	blacklist : entry entries EOF | EOF ;
//	entries   : EOL entry entries | ;
//	entry     : address | address / INT6 | address - address ;
//	address   : number . number . number . number ;
//	number    : INT6 | INT8 ;
type parser struct {
	s     *Scanner
	curr  Token
	bl    *blacklist.Blacklist
	typ   blacklist.Type
	limit int
	count int
}

// ErrTooManyEntries is returned when a list exceeds the entry limit given
// to ParseLimited; entries up to the limit are kept.
var ErrTooManyEntries = errors.New("too many entries in list")

// Parse reads the list from r and adds every entry as a range of the given
// type to bl. Entries preceding a syntax error are kept.
func Parse(r io.Reader, bl *blacklist.Blacklist, t blacklist.Type) error {
	return ParseLimited(r, bl, t, 0)
}

// ParseLimited is Parse with a cap on the number of entries accepted
// (0 = unlimited), bounding memory use on a hostile feed.
func ParseLimited(r io.Reader, bl *blacklist.Blacklist, t blacklist.Type, maxEntries int) error {
	p := &parser{s: NewScanner(r), bl: bl, typ: t, limit: maxEntries}
	p.advance()
	p.accept(TokEOL)
	if p.curr.Kind == TokEOF {
		return nil
	}
	for {
		if p.limit > 0 && p.count >= p.limit {
			return ErrTooManyEntries
		}
		if err := p.entry(); err != nil {
			return err
		}
		p.count++
		if !p.accept(TokEOL) {
			if p.curr.Kind == TokEOF {
				return nil
			}
			return p.errorf()
		}
		if p.curr.Kind == TokEOF {
			return nil
		}
	}
}

func (p *parser) errorf() error {
	line, col := p.s.Pos()
	return &Error{Line: line, Col: col}
}

func (p *parser) advance() { p.curr = p.s.Next() }

// accept consumes the current token when it matches. Consecutive EOLs are
// swallowed together.
func (p *parser) accept(k TokenKind) bool {
	if p.curr.Kind != k {
		return false
	}
	if k == TokEOL {
		for p.curr.Kind == TokEOL {
			p.advance()
		}
	} else {
		p.advance()
	}
	return true
}

func (p *parser) entry() error {
	start, err := p.address()
	if err != nil {
		return err
	}
	var end uint32
	switch {
	case p.accept(TokSlash):
		if p.curr.Kind != TokInt6 {
			return p.errorf()
		}
		bits := uint8(p.curr.Val)
		p.advance()
		_, last := ip.CIDRToRange(ip.CIDR{Addr: start, Bits: bits})
		end = last + 1
	case p.accept(TokDash):
		last, err := p.address()
		if err != nil {
			return err
		}
		end = last + 1
	default:
		end = start + 1
	}
	p.bl.AddRange(start, end, p.typ)
	return nil
}

func (p *parser) address() (uint32, error) {
	var addr uint32
	for i := 0; i < 4; i++ {
		if p.curr.Kind != TokInt6 && p.curr.Kind != TokInt8 {
			return 0, p.errorf()
		}
		addr = addr<<8 | uint32(p.curr.Val)
		p.advance()
		if i < 3 && !p.accept(TokDot) {
			return 0, p.errorf()
		}
	}
	return addr, nil
}
