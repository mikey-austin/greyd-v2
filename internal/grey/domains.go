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

package grey

import (
	"bufio"
	"errors"
	"os"
	"strings"

	"github.com/mikey-austin/greyd-golang/internal/core"
)

// ErrTooManyDomains is returned when the permitted domains file holds more
// entries than allowed; the entries read so far are returned with it.
var ErrTooManyDomains = errors.New("too many permitted domains")

// LoadDomains reads the permitted domains file: one domain suffix per
// line, blank lines and '#' comments ignored, surrounding whitespace
// trimmed. Lines that do not fit the C buffer (GREY_MAX_MAIL) are skipped,
// as Grey_load_domains did. maxDomains caps the count (0 = unlimited).
func LoadDomains(path string, maxDomains int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) >= core.MaxMail-1 {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if maxDomains > 0 && len(out) >= maxDomains {
			return out, ErrTooManyDomains
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// domainMatches reports whether the recipient address ends with the
// domain suffix, case insensitively.
func domainMatches(domain, to string) bool {
	if len(domain) > len(to) {
		return false
	}
	return strings.EqualFold(to[len(to)-len(domain):], domain)
}
