//go:build openbsd || freebsd || netbsd || dragonfly

/*
 * Copyright (c) 2014-2026 Mikey Austin <mikey@greyd.org>
 * Copyright (c) 2004-2006 Bob Beck.  All rights reserved.
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

package pf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

// DriverName is the configuration driver value.
const DriverName = "pf"

const (
	defaultPfdevPath     = "/dev/pf"
	defaultPfctlPath     = "/sbin/pfctl"
	defaultPflogIf       = "pflog0"
	defaultTrackOutbound = 1

	// captureTimeout is PCAPTIMO: the bpf read timeout, after which
	// CaptureLog returns with no entries so the caller can check for
	// shutdown.
	captureTimeout = 500 * time.Millisecond

	// bpfDevices is the number of /dev/bpfN nodes tried after /dev/bpf.
	bpfDevices = 10
)

func init() {
	core.RegisterFirewall(DriverName, func(cfg *config.Config, opts core.FirewallOptions) (core.Firewall, error) {
		return New(cfg, opts), nil
	})
}

// Firewall drives PF through /dev/pf, pfctl(8) and a bpf(4) device bound
// to the pflog(4) interface.
type Firewall struct {
	pfdevPath     string
	pfctlPath     string
	pflogIf       string
	netIf         string
	trackOutbound bool
	log           *slog.Logger

	pfdev  *os.File
	bpf    int // -1 when no capture is active
	bpfBuf []byte
	layout BPFLayout
}

// New reads the "firewall" section options; nothing is opened until Open.
// A nil opts.Log discards diagnostics.
func New(cfg *config.Config, opts core.FirewallOptions) *Firewall {
	return &Firewall{
		log:           logger.Or(opts.Log),
		pfdevPath:     cfg.Str("pfdev_path", "firewall", defaultPfdevPath),
		pfctlPath:     cfg.Str("pfctl_path", "firewall", defaultPfctlPath),
		pflogIf:       cfg.Str("pflog_if", "firewall", defaultPflogIf),
		netIf:         cfg.Str("net_if", "firewall", ""),
		trackOutbound: cfg.Int("track_outbound", "firewall", defaultTrackOutbound) != 0,
		bpf:           -1,
		layout:        nativeBPFLayout,
	}
}

// nativeBPFLayout is struct bpf_hdr as generated for this platform by
// golang.org/x/sys/unix, plus the platform's BPF_ALIGNMENT (bpfAlignment,
// defined per OS alongside the natlook code).
var nativeBPFLayout = BPFLayout{
	CaplenOffset: int(unsafe.Offsetof(unix.BpfHdr{}.Caplen)),
	Alignment:    int(bpfAlignment),
}

// Open opens the PF device read-write (Mod_fw_open).
func (f *Firewall) Open(context.Context) error {
	dev, err := os.OpenFile(f.pfdevPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("could not open %s: %w", f.pfdevPath, err)
	}
	f.pfdev = dev
	return nil
}

// Close releases the PF device.
func (f *Firewall) Close() error {
	if f.pfdev == nil {
		return nil
	}
	err := f.pfdev.Close()
	f.pfdev = nil
	return err
}

// Replace atomically replaces the contents of a PF table by feeding the
// CIDRs to "pfctl -T replace -f -" (Mod_fw_replace). The C driver handed
// pfctl its already open descriptor as /dev/fd/N; the device path is
// passed instead, which behaves identically for a privileged caller and
// does not depend on fdescfs. pfctl is killed when ctx is done.
func (f *Firewall) Replace(ctx context.Context, set string, cidrs []string, _ core.Family) (int, error) {
	if len(cidrs) == 0 {
		return 0, nil
	}
	var in strings.Builder
	n := 0
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		in.WriteString(c)
		in.WriteByte('\n')
		n++
	}
	if n == 0 {
		return 0, nil
	}

	cmd := exec.CommandContext(ctx, f.pfctlPath, "-p", f.pfdevPath, "-q", "-t", set, "-T", "replace", "-f", "-")
	cmd.Stdin = strings.NewReader(in.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return 0, fmt.Errorf("%s: %w", f.pfctlPath, cerr)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return 0, fmt.Errorf("%s returned status %d: %s", f.pfctlPath, exitErr.ExitCode(), msg)
			}
			return 0, fmt.Errorf("%s returned status %d", f.pfctlPath, exitErr.ExitCode())
		}
		return 0, fmt.Errorf("%s: %w", f.pfctlPath, err)
	}
	return n, nil
}

// ifreq is struct ifreq: the interface name followed by the platform's
// ifr_ifru union, whose size is recovered from the BIOCSETIF encoding
// (IOCPARM_LEN) so it is right on every BSD (32 bytes, 144 on NetBSD).
type ifreq struct {
	Name [unix.IFNAMSIZ]byte
	_    [((unix.BIOCSETIF >> 16) & 0x1fff) - unix.IFNAMSIZ]byte
}

// StartLogCapture opens a bpf device on the pflog interface in immediate
// mode with a read timeout (Mod_fw_start_log_capture; the pcap filter is
// applied in userland by ParseRecord).
func (f *Firewall) StartLogCapture(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(f.pflogIf) >= unix.IFNAMSIZ {
		return fmt.Errorf("pflog_if %q is too long", f.pflogIf)
	}
	fd, err := openBpf()
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	if err := f.setupBpf(fd); err != nil {
		unix.Close(fd)
		return err
	}
	f.bpf = fd
	return nil
}

func (f *Firewall) setupBpf(fd int) error {
	var ifr ifreq
	copy(ifr.Name[:], f.pflogIf)
	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fmt.Errorf("failed to initialize: BIOCSETIF %s: %w", f.pflogIf, err)
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
	if dlt != unix.DLT_PFLOG {
		return fmt.Errorf("invalid datalink type %d on %s (want DLT_PFLOG)", dlt, f.pflogIf)
	}
	tv := unix.NsecToTimeval(captureTimeout.Nanoseconds())
	if err := ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fmt.Errorf("failed to initialize: BIOCSRTIMEOUT: %w", err)
	}
	if err := lockBpf(fd); err != nil {
		return fmt.Errorf("BIOCLOCK: %w", err)
	}
	f.bpfBuf = make([]byte, blen)
	return nil
}

// openBpf opens the first available bpf device: the /dev/bpf clone device
// on modern systems, else /dev/bpf0 .. /dev/bpf9.
func openBpf() (int, error) {
	paths := []string{"/dev/bpf"}
	for i := 0; i < bpfDevices; i++ {
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

// EndLogCapture closes the bpf device.
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
// logged SMTP connections it contained (Mod_fw_capture_log). It returns
// nil when the read timeout elapsed without packets or ctx is done.
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
			return nil, nil // timeout
		}
		var addrs []string
		f.layout.Records(f.bpfBuf[:n], func(pkt []byte) {
			if len(pkt) < MIN_PFLOG_HDRLEN {
				f.log.Warn("invalid pflog header length, packet dropped", "len", len(pkt), "min", MIN_PFLOG_HDRLEN)
				return
			}
			addr, ok := ParseRecord(pkt, f.trackOutbound, f.netIf, unix.AF_INET6)
			if !ok {
				return
			}
			dir := "out"
			if pkt[pflogOffDir] == PF_IN {
				dir = "in"
			}
			f.log.Debug("packet received", "direction", dir, "addr", addr)
			addrs = append(addrs, addr)
		})
		return addrs, nil
	}
}

// LookupOrigDst asks PF for the pre-rdr destination of the connection
// from src to proxy (Mod_fw_lookup_orig_dst). Any failure, including the
// absence of a matching state, falls back to the proxy address. The
// DIOCNATLOOK ioctl does not block, so ctx is only checked beforehand.
func (f *Firewall) LookupOrigDst(ctx context.Context, src, proxy netip.AddrPort) (netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return proxy, err
	}
	if f.pfdev == nil {
		return proxy, nil
	}
	s, p := src.Addr().Unmap(), proxy.Addr().Unmap()
	if s.Is4() != p.Is4() {
		f.log.Debug("pf natlook: address family mismatch", "src", src, "proxy", proxy)
		return proxy, nil
	}
	orig, err := natlook(int(f.pfdev.Fd()), netip.AddrPortFrom(s, src.Port()), netip.AddrPortFrom(p, proxy.Port()))
	if err != nil {
		f.log.Debug("pf natlook failed", "src", src, "proxy", proxy, "err", err)
		return proxy, nil
	}
	return orig, nil
}

// ioctlPtr issues an ioctl whose argument is a pointer to a struct. The
// generic Syscall path is used because x/sys exposes no exported
// struct-pointer ioctl; on OpenBSD 7.5+ the syscall package reroutes
// SYS_IOCTL to the libc stub.
func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}

// <sys/ioccom.h> request encoding: direction bits | (size & IOCPARM_MASK)
// << 16 | group << 8 | num.
const (
	iocInOut    uint = 0xC0000000 // IOC_INOUT = IOC_IN | IOC_OUT
	iocParmMask uint = 0x1fff     // IOCPARM_MASK
)

// pfAddr is struct pf_addr: a 16 byte union holding an IPv4 address in
// its first four bytes or an IPv6 address.
type pfAddr [16]byte

func toPfAddr(a netip.Addr) pfAddr {
	var out pfAddr
	if a.Is4() {
		b := a.As4()
		copy(out[:4], b[:])
	} else {
		out = a.As16()
	}
	return out
}

func fromPfAddr(a pfAddr, v4 bool) netip.Addr {
	if v4 {
		return netip.AddrFrom4([4]byte(a[:4]))
	}
	return netip.AddrFrom16(a)
}
