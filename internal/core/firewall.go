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

import (
	"context"
	"net/netip"

	"github.com/mikey-austin/greyd-golang/internal/config"
)

// Family is an IP address family.
type Family int

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

// Firewall is the firewall port (firewall.h FW_handle_T).
type Firewall interface {
	// Open initialises the handle; called before privileges are dropped.
	Open() error
	Close() error

	// Replace atomically replaces the contents of the named set or table
	// with the supplied CIDR blocks and returns the number added.
	Replace(set string, cidrs []string, af Family) (int, error)

	// StartLogCapture prepares the connection tracking machinery used by
	// greylogd.
	StartLogCapture() error
	EndLogCapture() error
	// CaptureLog blocks until log entries arrive, the driver's internal
	// timeout elapses (returning an empty slice) or ctx is done. Each entry
	// is the address to whitelist.
	CaptureLog(ctx context.Context) ([]string, error)

	// LookupOrigDst returns the destination of a connection before it was
	// redirected (DNAT) to greyd. Drivers that cannot know return proxy.
	LookupOrigDst(src, proxy netip.AddrPort) (netip.AddrPort, error)
}

// FirewallFactory constructs a firewall driver from the "firewall"
// configuration section.
type FirewallFactory func(cfg *config.Config) (Firewall, error)
