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
	"io"
	"strings"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/config/parse"
)

// Terminator is the line that ends a message.
const Terminator = "%%"

// Reader extracts framed messages from a byte stream.
type Reader struct {
	br *bufio.Reader
}

// NewReader wraps r.
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReader(r)}
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

// Next returns the next message parsed into a configuration. Values live in
// the default section. A syntax error is returned as a *parse.Error and the
// reader may continue with the following message.
func (r *Reader) Next() (*config.Config, error) {
	body, err := r.NextRaw()
	if err != nil {
		return nil, err
	}
	return parse.String(body)
}
