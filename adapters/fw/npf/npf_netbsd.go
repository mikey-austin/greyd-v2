//go:build netbsd

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

package npf

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

	"github.com/mikey-austin/greyd-v2/adapters/fw/pf"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/logger"
)

func init() {
	core.RegisterFirewall(DriverName, "NetBSD NPF: tables via npfctl, npflog capture", func(cfg *config.Config, opts core.FirewallOptions) (core.Firewall, error) {
		return New(cfg, opts), nil
	})
}

// captureTimeout bounds one bpf read so CaptureLog notices ctx.
const captureTimeout = time.Second

// Firewall drives npfctl(8) and the npflog interface.
type Firewall struct {
	npfctlPath    string
	logIf         string
	netIf         string
	trackOutbound bool
	log           *slog.Logger

	bpf    int
	bpfBuf []byte
	layout pf.BPFLayout
}

// New reads the "firewall" section options.
func New(cfg *config.Config, opts core.FirewallOptions) *Firewall {
	return &Firewall{
		log:           logger.Or(opts.Log),
		npfctlPath:    cfg.Str("npfctl_path", "firewall", DefaultNpfctlPath),
		logIf:         cfg.Str("npflog_if", "firewall", DefaultLogIf),
		netIf:         cfg.Str("net_if", "firewall", ""),
		trackOutbound: cfg.Int("track_outbound", "firewall", DefaultTrackOutbound) != 0,
		bpf:           -1,
		layout: pf.BPFLayout{
			CaplenOffset: int(unsafe.Offsetof(unix.BpfHdr{}.Caplen)),
			Alignment:    int(unsafe.Sizeof(uintptr(0))),
		},
	}
}

// KeepPrivileges implements core.PrivilegeKeeper: npfctl opens /dev/npf,
// which only root may.
func (f *Firewall) KeepPrivileges() bool { return true }

// Open checks that npfctl can talk to the kernel.
func (f *Firewall) Open(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, f.npfctlPath, "stats").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s stats: %w: %s", f.npfctlPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Close releases the log capture, if any.
func (f *Firewall) Close() error { return f.EndLogCapture() }

// Replace loads cidrs into the named table with "npfctl table NAME
// replace FILE", which swaps the contents in one step.
func (f *Firewall) Replace(ctx context.Context, set string, cidrs []string, _ core.Family) (int, error) {
	if !ValidTableName(set) {
		return 0, fmt.Errorf("invalid npf table name %q", set)
	}
	body := ReplaceFile(cidrs)
	if body == "" {
		return 0, nil
	}
	tmp, err := os.CreateTemp("", "greyd-npf-*.txt")
	if err != nil {
		return 0, fmt.Errorf("npf table file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return 0, fmt.Errorf("npf table file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("npf table file: %w", err)
	}
	cmd := exec.CommandContext(ctx, f.npfctlPath, "table", set, "replace", tmp.Name())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return 0, fmt.Errorf("%s table %s replace: %w: %s", f.npfctlPath, set, err, msg)
		}
		return 0, fmt.Errorf("%s table %s replace: %w", f.npfctlPath, set, err)
	}
	return strings.Count(body, "\n"), nil
}

type ifreq struct {
	Name [unix.IFNAMSIZ]byte
	_    [16]byte
}

// StartLogCapture attaches a bpf descriptor to the npflog interface.
func (f *Firewall) StartLogCapture(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(f.logIf) >= unix.IFNAMSIZ {
		return fmt.Errorf("npflog_if %q is too long", f.logIf)
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
		return fmt.Errorf("failed to initialize: BIOCSETIF %s: %w (ifconfig %s create?)", f.logIf, err, f.logIf)
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
	// npflog attaches with DLT_NPFLOG, which NetBSD defines as DLT_PFLOG.
	if dlt != unix.DLT_PFLOG {
		return fmt.Errorf("invalid datalink type %d on %s (want DLT_PFLOG)", dlt, f.logIf)
	}
	tv := unix.NsecToTimeval(captureTimeout.Nanoseconds())
	if err := ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fmt.Errorf("failed to initialize: BIOCSRTIMEOUT: %w", err)
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
// logged SMTP connections it contained; npflog records carry the pflog
// header, so the pf parser applies.
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
		var addrs []string
		f.layout.Records(f.bpfBuf[:n], func(pkt []byte) {
			if len(pkt) < pf.MIN_PFLOG_HDRLEN {
				return
			}
			addr, ok := pf.ParseRecord(pkt, f.trackOutbound, f.netIf, unix.AF_INET6)
			if !ok {
				return
			}
			f.log.Debug("packet received", "addr", addr)
			addrs = append(addrs, addr)
		})
		return addrs, nil
	}
}

// LookupOrigDst returns proxy: NPF offers no lookup of a redirected
// connection's original destination without libnpf's private
// interfaces.
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
