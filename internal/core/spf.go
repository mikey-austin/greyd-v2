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

package core

// SPFResult is the outcome of an SPF check.
type SPFResult int

const (
	// SPFNone covers none and neutral results.
	SPFNone SPFResult = iota
	SPFPass
	SPFSoftFail
	SPFFail
	// SPFError covers temporary and permanent errors.
	SPFError
)

func (r SPFResult) String() string {
	switch r {
	case SPFNone:
		return "none"
	case SPFPass:
		return "pass"
	case SPFSoftFail:
		return "softfail"
	case SPFFail:
		return "fail"
	default:
		return "error"
	}
}

// SPFChecker validates the envelope sender of a greylist tuple.
type SPFChecker interface {
	// Check evaluates the sender policy for the connecting ip, HELO name
	// and MAIL FROM address.
	Check(ip, helo, from string) (SPFResult, error)
}
