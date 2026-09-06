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

// Package ipc implements the message format exchanged between the greyd
// processes, over the configuration socket and on the trap pipe. A message
// is a sequence of greyd.conf(5) assignments terminated by a line holding
// only "%%". The wire format is identical to that of the C implementation.
package ipc

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// Terminator is the line that ends a message.
const Terminator = "%%"

// DefaultMaxFrame bounds a frame body; larger frames are rejected.
const DefaultMaxFrame = 64 << 20

// ErrFrameTooLarge is returned when a frame exceeds the reader's limit.
var ErrFrameTooLarge = errors.New("frame too large")

// Reader extracts framed messages from a byte stream.
type Reader struct {
	br       *bufio.Reader
	maxFrame int
}

// NewReader wraps r with the default frame limit.
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReader(r), maxFrame: DefaultMaxFrame}
}

// SetMaxFrame bounds the accepted frame body size in bytes.
func (r *Reader) SetMaxFrame(n int) {
	if n > 0 {
		r.maxFrame = n
	}
}

// NextRaw returns the body of the next message without its terminator. At
// the end of the stream a final unterminated body is returned as a message
// (as a C parser hitting EOF would complete it); once the stream is
// exhausted io.EOF is returned.
func (r *Reader) NextRaw() (string, error) {
	var sb strings.Builder
	for {
		line, err := r.br.ReadString('\n')
		if len(line) > 0 {
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == Terminator {
				return sb.String(), nil
			}
			if sb.Len()+len(line) > r.maxFrame {
				return "", ErrFrameTooLarge
			}
			sb.WriteString(line)
		}
		if err != nil {
			if err == io.EOF {
				if sb.Len() == 0 {
					return "", io.EOF
				}
				return sb.String(), nil
			}
			return "", err
		}
	}
}

// Next returns the next frame decoded into a typed message. Decoding
// errors (*SyntaxError, *IncompleteError, ErrUnknownMessage) apply to that
// frame only; the reader continues with the following one.
func (r *Reader) Next() (Message, error) {
	body, err := r.NextRaw()
	if err != nil {
		return nil, err
	}
	return Decode(body)
}
