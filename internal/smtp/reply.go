/*
 * Copyright (c) 2014-2026 Mikey Austin <mikey@greyd.org>
 * Copyright (c) 2002-2007 Bob Beck.  All rights reserved.
 * Copyright (c) 2002 Theo de Raadt.  All rights reserved.
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

package smtp

import (
	"strings"

	"github.com/mikey-austin/greyd-v2/internal/blacklist"
)

// GreyReply is the temporary failure given to greylisted connections.
const GreyReply = "451 Temporary failure, please try again later.\r\n"

// ExpandMessage expands a blacklist rejection message: "\n" (backslash n)
// becomes a newline, "%A" the connecting address, and a doubled escape
// character ("\\" or "%%") yields the character once. Any other escaped
// character is emitted with its escape. A trailing lone escape character is
// dropped. This ports the escape handling of Con_append_error_string.
func ExpandMessage(format, srcAddr string) string {
	var sb strings.Builder
	sb.Grow(len(format) + len(srcAddr))
	var saved byte
	for i := 0; i < len(format); i++ {
		c := format[i]
		switch c {
		case '\\', '%':
			if saved == 0 {
				saved = c
			} else {
				sb.WriteByte(saved)
				saved = 0
			}
		case 'A', 'n':
			if saved == '\\' && c == 'n' {
				sb.WriteByte('\n')
				saved = 0
				continue
			}
			if saved == '%' && c == 'A' {
				sb.WriteString(srcAddr)
				saved = 0
				continue
			}
			fallthrough
		default:
			if saved != 0 {
				sb.WriteByte(saved)
				saved = 0
			}
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// FormatReply renders the rejection messages of the matched blacklists as
// an SMTP multi-line reply: every line is prefixed with the error code, a
// dash for continuation lines and a space for the final line. Lines end
// with a bare newline; the stuttering writer adds carriage returns.
func FormatReply(lists []*blacklist.Blacklist, code, srcAddr string) string {
	var lines []string
	for _, bl := range lists {
		text := ExpandMessage(bl.Message, srcAddr)
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		parts := strings.Split(text, "\n")
		lines = append(lines, parts[:len(parts)-1]...)
	}
	var sb strings.Builder
	for i, l := range lines {
		sb.WriteString(code)
		if i == len(lines)-1 {
			sb.WriteByte(' ')
		} else {
			sb.WriteByte('-')
		}
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// SummarizeLists returns a space separated list of the matched blacklist
// names, truncated with " ..." when it would exceed 80 characters.
func SummarizeLists(lists []*blacklist.Blacklist) string {
	if len(lists) == 0 {
		return ""
	}
	limit := BLSummarySize - len(BLSummaryEtc)
	var sb strings.Builder
	for i, bl := range lists {
		if sb.Len()+len(bl.Name)+1 >= limit {
			sb.WriteString(BLSummaryEtc)
			break
		}
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(bl.Name)
	}
	return sb.String()
}
