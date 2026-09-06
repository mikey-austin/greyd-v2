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

// Package dummy is a firewall driver that does nothing, for testing and
// for deployments where the firewall is managed elsewhere (fw_dummy.c).
package dummy

import (
	"context"
	"net/netip"
	"sync"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

// DriverName is the configuration driver value.
const DriverName = "dummy"

func init() {
	core.RegisterFirewall(DriverName, func(*config.Config) (core.Firewall, error) { return New(), nil })
}

// Firewall records the sets it was asked to replace so tests can inspect
// them.
type Firewall struct {
	mu   sync.Mutex
	sets map[string][]string
}

// New creates a dummy firewall.
func New() *Firewall { return &Firewall{sets: make(map[string][]string)} }

func (f *Firewall) Open() error  { return nil }
func (f *Firewall) Close() error { return nil }

// Replace remembers the CIDRs and returns their count.
func (f *Firewall) Replace(set string, cidrs []string, _ core.Family) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets[set] = append([]string(nil), cidrs...)
	return len(cidrs), nil
}

// Set returns the last contents given to Replace for a set.
func (f *Firewall) Set(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sets[name]...)
}

func (f *Firewall) StartLogCapture() error { return nil }
func (f *Firewall) EndLogCapture() error   { return nil }

// CaptureLog never produces entries; it returns when ctx is done.
func (f *Firewall) CaptureLog(ctx context.Context) ([]string, error) {
	<-ctx.Done()
	return nil, nil
}

// LookupOrigDst defaults to the proxy address.
func (f *Firewall) LookupOrigDst(_, proxy netip.AddrPort) (netip.AddrPort, error) {
	return proxy, nil
}
