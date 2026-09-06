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

// Package spamdlist parses spamd-style address lists: one IPv4 address,
// CIDR block or "start - end" range per line, with '#' comments. The
// scanner reproduces the quirks of the C lexer, notably that digit runs
// above 255 are split into several tokens, which is why it is hand written
// rather than generated.
package spamdlist

import (
	"bufio"
	"compress/gzip"
	"io"
)

// TokenKind identifies a token.
type TokenKind int

const (
	TokEOF TokenKind = iota
	TokEOL
	// TokInt6 is an integer <= 63 (valid as a prefix length and as an octet).
	TokInt6
	// TokInt8 is an integer in 64..255.
	TokInt8
	TokDot
	TokDash
	TokSlash
)

const (
	maxInt6 = 63
	maxInt8 = 255
)

// Token is a scanned token with its integer value when applicable.
type Token struct {
	Kind TokenKind
	Val  int
}

// Scanner tokenizes a list.
type Scanner struct {
	br      *bufio.Reader
	line    int
	col     int
	prevCol int
	eof     bool
}

// NewScanner creates a scanner over r.
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{br: bufio.NewReader(r)}
}

// Pos returns the current line (0-based, as in the C lexer) and column.
func (s *Scanner) Pos() (line, col int) { return s.line, s.col }

func (s *Scanner) getc() (byte, bool) {
	c, err := s.br.ReadByte()
	if err != nil {
		return 0, false
	}
	s.prevCol = s.col
	if c == '\n' {
		s.line++
		s.col = 0
	} else {
		s.col++
	}
	return c, true
}

func (s *Scanner) ungetc(c byte) {
	if c == '\n' {
		s.line--
		s.col = s.prevCol
	} else if s.col > 0 {
		s.col--
	}
	_ = s.br.UnreadByte()
}

// Next returns the next token. Unknown characters end the stream, as in
// the C implementation.
func (s *Scanner) Next() Token {
	for {
		if s.eof {
			return Token{Kind: TokEOF}
		}
		c, ok := s.getc()
		if !ok {
			s.eof = true
			return Token{Kind: TokEOF}
		}

		if c >= '0' && c <= '9' {
			i := int(c - '0')
			for {
				d, ok := s.getc()
				if !ok {
					s.eof = true
					break
				}
				if d < '0' || d > '9' {
					s.ungetc(d)
					break
				}
				j := i*10 + int(d-'0')
				if j > maxInt8 {
					s.ungetc(d)
					break
				}
				i = j
			}
			if i <= maxInt6 {
				return Token{Kind: TokInt6, Val: i}
			}
			return Token{Kind: TokInt8, Val: i}
		}

		switch c {
		case ' ', '\t', '\r':
			continue
		case '#':
			for {
				d, ok := s.getc()
				if !ok {
					s.eof = true
					break
				}
				if d == '\n' {
					s.ungetc(d)
					break
				}
			}
			continue
		case '\n':
			return Token{Kind: TokEOL}
		case '.':
			return Token{Kind: TokDot}
		case '-':
			return Token{Kind: TokDash}
		case '/':
			return Token{Kind: TokSlash}
		default:
			s.eof = true
			return Token{Kind: TokEOF}
		}
	}
}

// OpenMaybeGzip returns a reader yielding the uncompressed contents of r,
// which may or may not be gzip compressed.
func OpenMaybeGzip(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		return gz, nil
	}
	return br, nil
}
