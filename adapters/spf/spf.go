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

// Package spf adapts a pure Go SPF implementation to the core.SPFChecker
// port, replacing libspf2.
package spf

import (
	"context"
	"fmt"
	"net"
	"time"

	gospf "blitiri.com.ar/go/spf"

	"github.com/mikey-austin/greyd-golang/internal/core"
)

// Timeout bounds a single SPF evaluation.
const Timeout = 20 * time.Second

// Checker implements core.SPFChecker.
type Checker struct {
	// check is the evaluation function (overridable in tests).
	check func(ctx context.Context, ip net.IP, helo, from string) (gospf.Result, error)
}

// New creates a checker using the system resolver.
func New() *Checker {
	return &Checker{check: func(ctx context.Context, ip net.IP, helo, from string) (gospf.Result, error) {
		return gospf.CheckHostWithSender(ip, helo, from, gospf.WithContext(ctx))
	}}
}

// Check evaluates the sender policy for the MAIL FROM address.
func (c *Checker) Check(ip, helo, from string) (core.SPFResult, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return core.SPFError, fmt.Errorf("invalid address %q", ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	res, err := c.check(ctx, addr, helo, from)
	return MapResult(res), err
}

// MapResult converts a library result to the core result, following the
// libspf2 mapping of grey.c: pass, neutral/none, softfail, fail and
// everything else an error.
func MapResult(r gospf.Result) core.SPFResult {
	switch r {
	case gospf.Pass:
		return core.SPFPass
	case gospf.Neutral, gospf.None:
		return core.SPFNone
	case gospf.SoftFail:
		return core.SPFSoftFail
	case gospf.Fail:
		return core.SPFFail
	default:
		return core.SPFError
	}
}
