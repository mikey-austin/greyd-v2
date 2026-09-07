//go:build freebsd

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

package ipfw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/mikey-austin/greyd-v2/adapters/fw/pf"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/logger"
)

func init() {
	core.RegisterFirewall(DriverName, "FreeBSD ipfw: lookup tables via ipfw(8), ipfw0 log capture, fwd redirects", func(cfg *config.Config, opts core.FirewallOptions) (core.Firewall, error) {
		return New(cfg, opts), nil
	})
}

// captureTimeout bounds one bpf read so CaptureLog notices ctx.
const captureTimeout = time.Second

// localRefresh is how often the local address list is re-read.
const localRefresh = time.Minute

// Firewall drives ipfw(8) and the ipfw0 log interface.
type Firewall struct {
	ipfwPath      string
	logIf         string
	netIf         string
	trackOutbound bool
	log           *slog.Logger

	bpf    int
	bpfBuf []byte
	layout pf.BPFLayout

	mu        sync.Mutex
	local     map[netip.Addr]bool
	localRead time.Time
}

// New reads the "firewall" section options.
func New(cfg *config.Config, opts core.FirewallOptions) *Firewall {
	return &Firewall{
		log:           logger.Or(opts.Log),
		ipfwPath:      cfg.Str("ipfw_path", "firewall", DefaultIpfwPath),
		logIf:         cfg.Str("ipfw_log_if", "firewall", DefaultLogIf),
		netIf:         cfg.Str("net_if", "firewall", ""),
		trackOutbound: cfg.Int("track_outbound", "firewall", DefaultTrackOutbound) != 0,
		bpf:           -1,
		layout: pf.BPFLayout{
			CaplenOffset: int(unsafe.Offsetof(unix.BpfHdr{}.Caplen)),
			Alignment:    int(unsafe.Sizeof(uintptr(0))),
		},
	}
}

// KeepPrivileges implements core.PrivilegeKeeper: the ipfw control socket
// checks PRIV_NETINET_IPFW on every operation.
func (f *Firewall) KeepPrivileges() bool { return true }

// Open checks that ipfw is usable.
func (f *Firewall) Open(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, f.ipfwPath, "list").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s list: %w: %s", f.ipfwPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Close releases the log capture, if any.
func (f *Firewall) Close() error { return f.EndLogCapture() }

// Replace loads cidrs into a staging table and swaps it with set.
func (f *Firewall) Replace(ctx context.Context, set string, cidrs []string, _ core.Family) (int, error) {
	if !ValidTableName(set) {
		return 0, fmt.Errorf("invalid ipfw table name %q", set)
	}
	n := 0
	for _, c := range cidrs {
		if c != "" {
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	for _, step := range ReplacePlan(set, cidrs) {
		cmd := exec.CommandContext(ctx, f.ipfwPath, step.Args...)
		if step.Stdin != "" {
			cmd.Stdin = strings.NewReader(step.Stdin)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if step.IgnoreErr {
				continue
			}
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return 0, fmt.Errorf("%s %s: %w: %s", f.ipfwPath, strings.Join(step.Args, " "), err, msg)
			}
			return 0, fmt.Errorf("%s %s: %w", f.ipfwPath, strings.Join(step.Args, " "), err)
		}
	}
	return n, nil
}

type ifreq struct {
	Name [unix.IFNAMSIZ]byte
	_    [16]byte
}

// StartLogCapture attaches a bpf descriptor to the ipfw log interface.
func (f *Firewall) StartLogCapture(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(f.logIf) >= unix.IFNAMSIZ {
		return fmt.Errorf("ipfw_log_if %q is too long", f.logIf)
	}
	fd, err := openBpf()
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	if err := f.setupBpf(fd); err != nil {
		_ = unix.Close(fd)
		return err
	}
	f.bpf = fd
	return nil
}

func (f *Firewall) setupBpf(fd int) error {
	var ifr ifreq
	copy(ifr.Name[:], f.logIf)
	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fmt.Errorf("failed to initialize: BIOCSETIF %s: %w (does the interface exist? ifconfig %s create)", f.logIf, err, f.logIf)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return fmt.Errorf("failed to initialize: BIOCIMMEDIATE: %w", err)
	}
	blen, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil {
		return fmt.Errorf("failed to initialize: BIOCGBLEN: %w", err)
	}
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return fmt.Errorf("failed to initialize: BIOCGDLT: %w", err)
	}
	if dlt != unix.DLT_EN10MB {
		return fmt.Errorf("invalid datalink type %d on %s (want DLT_EN10MB)", dlt, f.logIf)
	}
	tv := unix.NsecToTimeval(captureTimeout.Nanoseconds())
	if err := ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fmt.Errorf("failed to initialize: BIOCSRTIMEOUT: %w", err)
	}
	if err := unix.IoctlSetInt(fd, unix.BIOCLOCK, 0); err != nil {
		return fmt.Errorf("failed to initialize: BIOCLOCK: %w", err)
	}
	f.bpfBuf = make([]byte, blen)
	return nil
}

func openBpf() (int, error) {
	paths := []string{"/dev/bpf"}
	for i := 0; i < 10; i++ {
		paths = append(paths, fmt.Sprintf("/dev/bpf%d", i))
	}
	var firstErr error
	for _, p := range paths {
		fd, err := unix.Open(p, unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", p, err)
		}
	}
	return -1, firstErr
}

// EndLogCapture closes the bpf descriptor.
func (f *Firewall) EndLogCapture() error {
	if f.bpf < 0 {
		return nil
	}
	err := unix.Close(f.bpf)
	f.bpf = -1
	f.bpfBuf = nil
	return err
}

// CaptureLog performs one bpf read and returns the addresses of the
// logged SMTP connections it contained.
func (f *Firewall) CaptureLog(ctx context.Context) ([]string, error) {
	if f.bpf < 0 {
		return nil, errors.New("log capture not started")
	}
	for {
		if ctx.Err() != nil {
			return nil, nil
		}
		n, err := unix.Read(f.bpf, f.bpfBuf)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return nil, nil
			}
			return nil, fmt.Errorf("bpf read: %w", err)
		}
		if n == 0 {
			return nil, nil
		}
		isLocal := f.isLocal
		var addrs []string
		f.layout.Records(f.bpfBuf[:n], func(pkt []byte) {
			addr, ok := ParseRecord(pkt, f.trackOutbound, isLocal)
			if !ok {
				return
			}
			f.log.Debug("packet received", "addr", addr)
			addrs = append(addrs, addr)
		})
		return addrs, nil
	}
}

// isLocal reports whether a is one of this host's addresses (or of net_if
// when configured), refreshing the list periodically.
func (f *Firewall) isLocal(a netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.local == nil || time.Since(f.localRead) > localRefresh {
		f.local = localAddrs(f.netIf)
		f.localRead = time.Now()
	}
	return f.local[a.Unmap()]
}

func localAddrs(ifName string) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	var addrs []net.Addr
	if ifName != "" {
		if ifi, err := net.InterfaceByName(ifName); err == nil {
			addrs, _ = ifi.Addrs()
		}
	} else {
		addrs, _ = net.InterfaceAddrs()
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out[ip.Unmap()] = true
			}
		}
	}
	return out
}

// LookupOrigDst returns proxy: ipfw fwd delivers the packet to the local
// socket without rewriting its destination, so the address the connection
// arrived on is the original one.
func (f *Firewall) LookupOrigDst(ctx context.Context, _, proxy netip.AddrPort) (netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return proxy, err
	}
	return proxy, nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}
