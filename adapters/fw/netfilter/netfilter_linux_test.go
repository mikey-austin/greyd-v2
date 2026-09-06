//go:build linux

/*
 * Copyright (C) 2014-2026  Mikey Austin <mikey@greyd.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package netfilter

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

func TestRegistered(t *testing.T) {
	if !slices.Contains(core.FirewallDrivers(), DriverName) {
		t.Fatalf("driver %q not registered: %v", DriverName, core.FirewallDrivers())
	}
}

func TestParseOptionsDefaults(t *testing.T) {
	cfg := config.New()
	cfg.SetStr("driver", "firewall", "greyd_netfilter.so")
	got := parseOptions(cfg)
	want := options{
		maxElements:   200000,
		hashSize:      1048576,
		trackOutbound: true,
		inboundGroup:  155,
		outboundGroup: 255,
		dropPrivs:     true,
	}
	if got != want {
		t.Fatalf("defaults: got %+v, want %+v", got, want)
	}
}

func TestParseOptionsConfigured(t *testing.T) {
	cfg := config.New()
	cfg.SetInt("drop_privs", "", 0)
	cfg.SetInt("max_elements", "firewall", 5000)
	cfg.SetInt("hash_size", "firewall", 4096)
	cfg.SetInt("track_outbound", "firewall", 0)
	cfg.SetInt("inbound_group", "firewall", 10)
	cfg.SetInt("outbound_group", "firewall", 20)
	got := parseOptions(cfg)
	want := options{
		maxElements:   5000,
		hashSize:      4096,
		trackOutbound: false,
		inboundGroup:  10,
		outboundGroup: 20,
		dropPrivs:     false,
	}
	if got != want {
		t.Fatalf("configured: got %+v, want %+v", got, want)
	}
}

func TestStartLogCaptureGroupClash(t *testing.T) {
	cfg := config.New()
	cfg.SetInt("drop_privs", "", 0)
	cfg.SetInt("inbound_group", "firewall", 42)
	cfg.SetInt("outbound_group", "firewall", 42)
	fw := New(cfg)
	err := fw.StartLogCapture()
	if err == nil {
		_ = fw.EndLogCapture()
		t.Fatal("expected an error for identical NFLOG groups")
	}
	if err.Error() != "inbound and outbound NFLOG groups must not be the same" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCaptureLogNotStarted(t *testing.T) {
	cfg := config.New()
	cfg.SetInt("drop_privs", "", 0)
	fw := New(cfg)
	if _, err := fw.CaptureLog(context.Background()); err == nil {
		t.Fatal("expected an error before StartLogCapture")
	}
	if err := fw.EndLogCapture(); err != nil {
		t.Fatalf("EndLogCapture without capture: %v", err)
	}
}

func TestCaptureLogDrainsQueue(t *testing.T) {
	cfg := config.New()
	cfg.SetInt("drop_privs", "", 0)
	fw := New(cfg)
	fw.entries = make(chan string, 8)
	fw.entries <- "192.0.2.1"
	fw.entries <- "2001:db8::1"

	got, err := fw.CaptureLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "2001:db8::1"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := fw.CaptureLog(ctx); err != context.DeadlineExceeded {
		t.Fatalf("expected context deadline error, got %v", err)
	}
}

func TestCidrEntry(t *testing.T) {
	e, err := cidrEntry("192.0.2.0/24", core.IPv4)
	if err != nil || e.CIDR != 24 || e.IP.String() != "192.0.2.0" {
		t.Fatalf("v4 prefix: %+v, %v", e, err)
	}
	e, err = cidrEntry("192.0.2.7", core.IPv4)
	if err != nil || e.CIDR != 32 || e.IP.String() != "192.0.2.7" {
		t.Fatalf("v4 host: %+v, %v", e, err)
	}
	e, err = cidrEntry("2001:db8::/32", core.IPv6)
	if err != nil || e.CIDR != 32 || len(e.IP) != 16 {
		t.Fatalf("v6 prefix: %+v, %v", e, err)
	}
	e, err = cidrEntry("2001:db8::1", core.IPv6)
	if err != nil || e.CIDR != 128 {
		t.Fatalf("v6 host: %+v, %v", e, err)
	}
	for _, bad := range []string{"nonsense", "192.0.2.0/33", "2001:db8::/32 "} {
		if _, err := cidrEntry(bad, core.IPv4); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
	if _, err := cidrEntry("192.0.2.0/24", core.IPv6); err == nil {
		t.Error("v4 prefix in v6 set: expected error")
	}
}

// TestReplaceIntegration talks to the kernel; run as root with
// GREYD_TEST_ROOT=1 (for example inside a container with CAP_NET_ADMIN).
func TestReplaceIntegration(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("GREYD_TEST_ROOT") == "" {
		t.Skip("requires root and GREYD_TEST_ROOT=1")
	}
	const set = "greyd-test"
	cfg := config.New()
	cfg.SetInt("drop_privs", "", 0)
	fw := New(cfg)
	if err := fw.Open(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = netlink.IpsetDestroy(set)
		_ = fw.Close()
	}()

	n, err := fw.Replace(set, []string{"192.0.2.0/24", "198.51.100.7"}, core.IPv4)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if n != 2 {
		t.Fatalf("Replace returned %d, want 2", n)
	}
	res, err := netlink.IpsetList(set)
	if err != nil {
		t.Fatalf("IpsetList: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("set holds %d entries, want 2: %+v", len(res.Entries), res.Entries)
	}
	if _, err := netlink.IpsetList(set + stageSuffix); err == nil {
		t.Fatalf("staging set %s still exists", set+stageSuffix)
	}

	// A second replace swaps in the new contents.
	if n, err = fw.Replace(set, []string{"203.0.113.0/24"}, core.IPv4); err != nil || n != 1 {
		t.Fatalf("second Replace: %d, %v", n, err)
	}
	res, err = netlink.IpsetList(set)
	if err != nil {
		t.Fatalf("IpsetList: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].IP.String() != "203.0.113.0" || res.Entries[0].CIDR != 24 {
		t.Fatalf("unexpected contents after second replace: %+v", res.Entries)
	}

	if _, err := fw.Replace(set, []string{"not-a-cidr"}, core.IPv4); err == nil {
		t.Fatal("expected error for invalid cidr")
	}
	if err := netlink.IpsetDestroy(set); err != nil {
		t.Fatalf("IpsetDestroy: %v", err)
	}
}
