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

// Package netfilter is the GNU/Linux firewall driver (drivers/netfilter.c):
// ipset management over netlink, NFLOG packet capture for greylogd and
// conntrack original-destination lookups. On other operating systems the
// package is empty and registers no driver, so that programs blank-importing
// adapters/fw/all still build.
//
// The C driver linked libipset, libnetfilter_conntrack and
// libnetfilter_log; this port speaks netlink directly through
// github.com/vishvananda/netlink, github.com/ti-mo/conntrack and
// github.com/florianl/go-nflog. CAP_NET_ADMIN is retained across the
// privilege drop with kernel.org/pub/linux/libs/security/libcap/cap.
package netfilter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/ti-mo/conntrack"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

// DriverName is the configuration driver value.
const DriverName = "netfilter"

// Defaults and constants from netfilter.c.
const (
	defaultMaxElements  = 200000
	defaultHashSize     = 1024 * 1024
	defaultInboundGroup = 155
	defaultOutboundGrp  = 255
	stageSuffix         = "-stage"

	// nflogBufsize is the number of bytes of each logged packet copied to
	// userspace; only the IP header is needed.
	nflogBufsize = 1024
	// nflogTimeout is the maximum time, in 1/100 s, a packet may be queued
	// in the kernel before it is pushed to userspace.
	nflogTimeout = 150
	// logCapTimeout bounds a single CaptureLog call (LOG_CAP_TIMEOUT).
	logCapTimeout = 10 * time.Second
	// entryQueue is the number of captured addresses buffered between the
	// NFLOG receive goroutines and CaptureLog.
	entryQueue = 1024
)

func init() {
	core.RegisterFirewall(DriverName, func(cfg *config.Config, opts core.FirewallOptions) (core.Firewall, error) {
		return New(cfg, opts), nil
	})
}

// options are the driver settings from the "firewall" section.
type options struct {
	maxElements   uint32
	hashSize      uint32
	trackOutbound bool
	inboundGroup  uint16
	outboundGroup uint16
	dropPrivs     bool
}

func parseOptions(cfg *config.Config) options {
	return options{
		maxElements:   uint32(cfg.Int("max_elements", "firewall", defaultMaxElements)),
		hashSize:      uint32(cfg.Int("hash_size", "firewall", defaultHashSize)),
		trackOutbound: cfg.Bool("track_outbound", "firewall", true),
		inboundGroup:  uint16(cfg.Int("inbound_group", "firewall", defaultInboundGroup)),
		outboundGroup: uint16(cfg.Int("outbound_group", "firewall", defaultOutboundGrp)),
		dropPrivs:     cfg.Bool("drop_privs", "", true),
	}
}

// Firewall is the netfilter driver.
type Firewall struct {
	opts options
	log  *slog.Logger

	mu      sync.Mutex
	logs    []*nflog.Nflog
	cancel  context.CancelFunc
	entries chan string
}

// New creates a netfilter firewall from the configuration; call Open
// before use. A nil opts.Log discards diagnostics.
func New(cfg *config.Config, opts core.FirewallOptions) *Firewall {
	return &Firewall{opts: parseOptions(cfg), log: logger.Or(opts.Log)}
}

// Open prepares the handle while the process is still privileged. Netlink
// sockets are opened per operation, so all that is needed is to arrange for
// CAP_NET_ADMIN to survive the coming uid change (Mod_fw_open).
func (f *Firewall) Open(context.Context) error {
	if !f.opts.dropPrivs {
		return nil
	}
	caps := cap.GetProc()
	if err := caps.SetFlag(cap.Permitted, true, cap.NET_ADMIN); err != nil {
		f.log.Warn("netfilter: cap set flag", "err", err)
	} else if err := caps.SetProc(); err != nil {
		f.log.Warn("netfilter: cap set proc", "err", err)
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_KEEPCAPS: %w", err)
	}
	return nil
}

// Close releases the handle and, when privileges were dropped, clears every
// capability the process still holds (Mod_fw_close).
func (f *Firewall) Close() error {
	_ = f.EndLogCapture()
	if !f.opts.dropPrivs {
		return nil
	}
	var errs []error
	if err := cap.NewSet().SetProc(); err != nil {
		errs = append(errs, fmt.Errorf("clear capabilities: %w", err))
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		errs = append(errs, fmt.Errorf("prctl PR_SET_KEEPCAPS: %w", err))
	}
	return errors.Join(errs...)
}

// raiseCaps makes CAP_NET_ADMIN effective before a netlink operation once
// privileges have been dropped (set_effective_caps). Failure is logged and
// the operation proceeds; the kernel will then report EPERM.
func (f *Firewall) raiseCaps() {
	if !f.opts.dropPrivs {
		return
	}
	caps := cap.NewSet()
	if err := caps.SetFlag(cap.Permitted, true, cap.NET_ADMIN); err != nil {
		f.log.Warn("netfilter: cap set flag", "err", err)
		return
	}
	if err := caps.SetFlag(cap.Effective, true, cap.NET_ADMIN); err != nil {
		f.log.Warn("netfilter: cap set flag", "err", err)
		return
	}
	if err := caps.SetProc(); err != nil {
		f.log.Warn("netfilter: could not raise CAP_NET_ADMIN", "err", err)
	}
}

func ipsetFamily(af core.Family) uint8 {
	if af == core.IPv6 {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

// ipsetCreate creates a hash:net set with unlimited entry timeout, ignoring
// an already existing set (IPSET_OPT_EXIST).
//
// The hash_size option is read but not applied: netlink.IpsetCreateOptions
// in github.com/vishvananda/netlink v1.3.1 exposes no IPSET_ATTR_HASHSIZE
// field, so the kernel default (1024, grown on demand) is used.
func (f *Firewall) ipsetCreate(name string, family uint8) error {
	var timeout uint32
	return netlink.IpsetCreate(name, "hash:net", netlink.IpsetCreateOptions{
		Replace:     true,
		Family:      family,
		MaxElements: f.opts.maxElements,
		Timeout:     &timeout,
	})
}

// cidrEntry converts a CIDR string (a bare address is a host route) into
// an ipset entry.
func cidrEntry(cidr string, af core.Family) (*netlink.IPSetEntry, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		addr, aerr := netip.ParseAddr(cidr)
		if aerr != nil {
			return nil, err
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if prefix.Addr().Is4() != (af == core.IPv4) {
		return nil, fmt.Errorf("address family mismatch")
	}
	return &netlink.IPSetEntry{
		IP:      prefix.Addr().AsSlice(),
		CIDR:    uint8(prefix.Bits()),
		Replace: true,
	}, nil
}

// Replace builds the new contents in a staging set and swaps it in
// atomically (Mod_fw_replace). Each ipset netlink request is a blocking
// syscall that cannot itself be interrupted, so ctx is checked between
// requests; when it is done the staging set is destroyed and the live set
// left untouched.
func (f *Firewall) Replace(ctx context.Context, set string, cidrs []string, af core.Family) (int, error) {
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	stage := set + stageSuffix
	family := ipsetFamily(af)

	f.raiseCaps()

	// A staging set left behind by a crashed run would otherwise keep its
	// stale entries.
	_ = netlink.IpsetDestroy(stage)
	if err := f.ipsetCreate(stage, family); err != nil {
		return -1, fmt.Errorf("ipset create %s: %w", stage, err)
	}

	added := 0
	for _, cidr := range cidrs {
		if cidr == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			_ = netlink.IpsetDestroy(stage)
			return -1, err
		}
		entry, err := cidrEntry(cidr, af)
		if err == nil {
			err = netlink.IpsetAdd(stage, entry)
		}
		if err != nil {
			_ = netlink.IpsetDestroy(stage)
			return -1, fmt.Errorf("invalid cidr %s: %w", cidr, err)
		}
		added++
	}

	if err := ctx.Err(); err != nil {
		_ = netlink.IpsetDestroy(stage)
		return -1, err
	}

	// Make sure the live set exists so that the swap has a partner; an
	// existing set is left alone.
	if err := f.ipsetCreate(set, family); err != nil {
		f.log.Warn("netfilter: ipset create", "set", set, "err", err)
	}

	if err := netlink.IpsetSwap(set, stage); err != nil {
		_ = netlink.IpsetDestroy(stage)
		return -1, fmt.Errorf("ipset swap %s <-> %s: %w", set, stage, err)
	}
	// After the swap the old contents live under the staging name.
	if err := netlink.IpsetDestroy(stage); err != nil {
		return -1, fmt.Errorf("ipset destroy %s: %w", stage, err)
	}
	return added, nil
}

// StartLogCapture binds the NFLOG groups (Mod_fw_start_log_capture). A
// single group receives both IPv4 and IPv6 packets. The receive goroutines
// run until EndLogCapture is called or ctx is done, whichever comes first.
func (f *Firewall) StartLogCapture(ctx context.Context) error {
	if f.opts.trackOutbound && f.opts.inboundGroup == f.opts.outboundGroup {
		return errors.New("inbound and outbound NFLOG groups must not be the same")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.entries != nil {
		return errors.New("log capture already started")
	}

	f.raiseCaps()

	ctx, cancel := context.WithCancel(ctx)
	entries := make(chan string, entryQueue)

	var logs []*nflog.Nflog
	fail := func(err error) error {
		cancel()
		for _, l := range logs {
			_ = l.Close()
		}
		return err
	}

	in, err := f.openGroup(ctx, f.opts.inboundGroup, true, entries)
	if err != nil {
		return fail(err)
	}
	logs = append(logs, in)

	if f.opts.trackOutbound {
		out, err := f.openGroup(ctx, f.opts.outboundGroup, false, entries)
		if err != nil {
			return fail(err)
		}
		logs = append(logs, out)
	}

	f.logs = logs
	f.cancel = cancel
	f.entries = entries
	return nil
}

// openGroup opens an NFLOG group and starts delivering the source
// (inbound) or destination (outbound) address of each logged packet on
// entries (setup_nflog_group + log_callback).
func (f *Firewall) openGroup(ctx context.Context, group uint16, inbound bool, entries chan<- string) (*nflog.Nflog, error) {
	nf, err := nflog.Open(&nflog.Config{
		Group:    group,
		Copymode: nflog.CopyPacket,
		Bufsize:  nflogBufsize,
		Timeout:  nflogTimeout,
		Logger:   nflogLogger{log: f.log},
	})
	if err != nil {
		return nil, fmt.Errorf("nflog open group %d: %w", group, err)
	}

	direction := "out"
	if inbound {
		direction = "in"
	}
	hook := func(attr nflog.Attribute) int {
		if attr.Payload == nil {
			return 0
		}
		payload := *attr.Payload
		saddr, sok := addrFromPacket(payload, true)
		daddr, dok := addrFromPacket(payload, false)
		if !sok || !dok {
			f.log.Warn("netfilter: invalid IP payload length", "len", len(payload))
			return 0
		}
		f.log.Debug("packet received", "direction", direction, "saddr", saddr, "daddr", daddr)
		addr := daddr
		if inbound {
			addr = saddr
		}
		select {
		case entries <- addr:
		default:
			f.log.Warn("netfilter: log capture queue full, dropping entry", "addr", addr)
		}
		return 0
	}
	errFunc := func(err error) int {
		if ctx.Err() != nil {
			return 1
		}
		f.log.Warn("netfilter: nflog receive", "group", group, "err", err)
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, hook, errFunc); err != nil {
		_ = nf.Close()
		return nil, fmt.Errorf("nflog bind group %d: %w", group, err)
	}
	return nf, nil
}

// EndLogCapture unbinds the NFLOG groups (Mod_fw_end_log_capture).
func (f *Firewall) EndLogCapture() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.entries == nil {
		return nil
	}
	f.cancel()
	var errs []error
	for _, l := range f.logs {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	f.logs = nil
	f.cancel = nil
	f.entries = nil
	return errors.Join(errs...)
}

// CaptureLog waits up to logCapTimeout for logged addresses and returns
// everything queued by then; nil on timeout (Mod_fw_capture_log). It
// returns ctx.Err() when ctx is done first.
func (f *Firewall) CaptureLog(ctx context.Context) ([]string, error) {
	f.mu.Lock()
	entries := f.entries
	f.mu.Unlock()
	if entries == nil {
		return nil, errors.New("log capture not started")
	}

	f.raiseCaps()

	timer := time.NewTimer(logCapTimeout)
	defer timer.Stop()

	var out []string
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, nil
	case addr := <-entries:
		out = append(out, addr)
	}
	for {
		select {
		case addr := <-entries:
			out = append(out, addr)
		default:
			return out, nil
		}
	}
}

// LookupOrigDst asks conntrack for the destination the client connected
// to before the DNAT redirect (Mod_fw_lookup_orig_dst). The reply tuple of
// the tracked connection is fully known: the proxy answers from its own
// address and port to the client's address and port. The original
// destination address is taken from the returned flow; the port is the
// proxy's, as in conntrack_callback. On any failure the proxy address is
// returned, as in C.
//
// conntrack.Conn exposes no deadline, so the connection is closed when ctx
// is done, which unblocks a pending query; ctx.Err() is then returned.
func (f *Firewall) LookupOrigDst(ctx context.Context, src, proxy netip.AddrPort) (netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return proxy, err
	}
	f.raiseCaps()

	srcAddr := src.Addr().Unmap()
	proxyAddr := proxy.Addr().Unmap()
	if !srcAddr.IsValid() || !proxyAddr.IsValid() || srcAddr.Is4() != proxyAddr.Is4() {
		return proxy, nil
	}

	c, err := conntrack.Dial(nil)
	if err != nil {
		f.log.Debug("netfilter: conntrack dial", "err", err)
		return proxy, nil
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()

	var flow conntrack.Flow
	flow.TupleReply = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      proxyAddr,
			DestinationAddress: srcAddr,
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        unix.IPPROTO_TCP,
			SourcePort:      proxy.Port(),
			DestinationPort: src.Port(),
		},
	}

	got, err := c.Get(flow)
	if cerr := ctx.Err(); cerr != nil {
		return proxy, cerr
	}
	if err != nil {
		f.log.Debug("netfilter: conntrack lookup", "src", src, "proxy", proxy, "err", err)
		return proxy, nil
	}
	origDst := got.TupleOrig.IP.DestinationAddress
	if !origDst.IsValid() {
		return proxy, nil
	}
	return netip.AddrPortFrom(origDst, proxy.Port()), nil
}

// nflogLogger routes the library's internal messages to the greyd log.
type nflogLogger struct{ log *slog.Logger }

func (l nflogLogger) Debugf(format string, args ...any) {
	l.log.Debug("nflog: " + fmt.Sprintf(format, args...))
}

func (l nflogLogger) Errorf(format string, args ...any) {
	l.log.Warn("nflog: " + fmt.Sprintf(format, args...))
}
