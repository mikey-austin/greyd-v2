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

// Package core defines the greyd domain model and the ports (interfaces)
// implemented by database, firewall and SPF adapters. It has no
// dependencies on any adapter.
package core

import "strings"

// MaxMail is the maximum length of an email address or HELO name,
// including the terminating NUL of the C implementation (GREY_MAX_MAIL).
const MaxMail = 1024

// Tuple identifies a greylist entry: connecting IP, HELO name, envelope
// sender and envelope recipient.
type Tuple struct {
	IP   string
	Helo string
	From string
	To   string
}

// NormalizeEmail strips angle brackets, backslashes and double quotes from
// an address and lower-cases it, as normalize_email_addr did. The result is
// truncated to MaxMail-1 bytes.
func NormalizeEmail(addr string) string {
	var sb strings.Builder
	sb.Grow(len(addr))
	for i := 0; i < len(addr) && sb.Len() < MaxMail-1; i++ {
		c := addr[i]
		switch c {
		case '\\', '"', '<', '>':
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		sb.WriteByte(c)
	}
	return sb.String()
}
