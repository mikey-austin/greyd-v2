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

package greyd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/user"
	"sync"

	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ip"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/privs"
	"github.com/mikey-austin/greyd-v2/internal/procs"
	"github.com/mikey-austin/greyd-v2/internal/sandbox"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

// Names of the descriptors passed to the firewall child.
const (
	fdFwIn     = "fwin"     // main -> fw: nat lookups
	fdNatOut   = "natout"   // fw -> main: nat answers
	fdGreyFwIn = "greyfwin" // grey -> fw: whitelist replace requests
)

// fwFiles are the firewall child's pipe ends.
type fwFiles struct {
	fwIn     *os.File
	natOut   *os.File
	greyFwIn *os.File
}

func (f fwFiles) closeAll() {
	for _, x := range []*os.File{f.fwIn, f.natOut, f.greyFwIn} {
		if x != nil {
			_ = x.Close()
		}
	}
}

func inheritedFwFiles() (fwFiles, error) {
	var f fwFiles
	var err error
	if f.fwIn, err = procs.InheritedFile(fdFwIn); err != nil {
		return f, err
	}
	if f.natOut, err = procs.InheritedFile(fdNatOut); err != nil {
		return f, err
	}
	if f.greyFwIn, err = procs.InheritedFile(fdGreyFwIn); err != nil {
		return f, err
	}
	return f, nil
}

// runFwChild is the firewall process (Greyd_start_fw_child): it holds the
// firewall handle, answers NAT lookups from the main process and applies
// whitelist updates from the greylister. It runs as the main user, chrooted
// unless the pf driver is in use.
func runFwChild(ctx context.Context, s *settings.Settings, files fwFiles, log *slog.Logger) error {
	defer files.closeAll()

	fw, err := core.OpenFirewall(ctx, s.Raw(), core.FirewallOptions{Log: log})
	if err != nil {
		return err
	}
	defer func() { _ = fw.Close() }()

	if err := dropMainPrivs(s, driverIsPF(s), log); err != nil {
		return err
	}
	if s.Sandbox {
		// pf needs pfctl and ioctl on /dev/pf; netfilter only netlink.
		pf := driverIsPF(s)
		applySandbox(sandbox.Profile{Role: sandbox.RoleFirewall, Exec: pf, Devices: pf, Strict: s.SandboxStrict}, log)
	}

	h := &fwHandler{fw: fw, out: files.natOut, log: log}
	// handle serves one pipe until it closes or ctx ends.
	handle := func(r io.Reader) {
		rd := ipc.NewReader(r)
		for {
			m, err := rd.Next()
			if err != nil {
				if errors.Is(err, io.EOF) || ctx.Err() != nil {
					return
				}
				log.Warn("firewall process: bad message", "err", err)
				continue
			}
			h.process(ctx, m)
		}
	}

	done := make(chan struct{}, 2)
	go func() { handle(files.fwIn); done <- struct{}{} }()
	go func() { handle(files.greyFwIn); done <- struct{}{} }()

	select {
	case <-ctx.Done():
	case <-done:
		// One pipe closed: the parent is going away.
	}
	log.Info("stopping firewall process")
	return nil
}

// driverIsPF reports whether the configured firewall driver is pf, which
// needs filesystem access (pfctl) and so is not chrooted (WITH_PF in C).
func driverIsPF(s *settings.Settings) bool {
	return core.NormalizeDriver(s.Firewall.Driver) == "pf"
}

// dropMainPrivs chroots (unless skipChroot) and switches to the main user
// according to the configuration.
func dropMainPrivs(s *settings.Settings, skipChroot bool, log *slog.Logger) error {
	// The user database is not reachable from inside the jail, so the
	// lookup must precede the chroot.
	var u *user.User
	if s.DropPrivs {
		var err error
		if u, err = privs.LookupUser(s.User); err != nil {
			return err
		}
	}
	return confine(!skipChroot && s.Chroot, s.ChrootDir, s.DropPrivs, u, log, nil)
}

// fwHandler serialises requests against the firewall handle.
type fwHandler struct {
	mu  sync.Mutex
	fw  core.Firewall
	out io.Writer
	log *slog.Logger
}

// process handles one request (Greyd_process_fw_message).
func (h *fwHandler) process(ctx context.Context, m ipc.Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch m := m.(type) {
	case *ipc.NATRequest:
		h.lookup(ctx, m)
	case *ipc.ReplaceRequest:
		h.replace(ctx, m)
	default:
		h.log.Debug("firewall process: ignoring unexpected message")
	}
}

func (h *fwHandler) lookup(ctx context.Context, m *ipc.NATRequest) {
	if m.SrcPort == 0 || m.ProxyPort == 0 {
		h.log.Debug("nat lookup: expecting non-zero src & proxy ports")
		return
	}
	srcAddr, err1 := netip.ParseAddr(m.Src)
	proxyAddr, err2 := netip.ParseAddr(m.Proxy)
	if err1 != nil || err2 != nil {
		h.log.Debug("nat lookup: bad addresses", "src", m.Src, "proxy", m.Proxy)
		return
	}
	dst := ""
	res, err := h.fw.LookupOrigDst(ctx, netip.AddrPortFrom(srcAddr, m.SrcPort), netip.AddrPortFrom(proxyAddr, m.ProxyPort))
	if err == nil && res.IsValid() {
		dst = res.Addr().Unmap().String()
	} else if err != nil {
		h.log.Debug("nat lookup failed", "err", err)
	}
	if h.out != nil {
		if err := ipc.WriteDst(h.out, dst); err != nil {
			h.log.Debug("dnat lookup: write failed", "err", err)
		}
	}
}

func (h *fwHandler) replace(ctx context.Context, m *ipc.ReplaceRequest) {
	var addrs []string
	for _, a := range m.IPs {
		if ip.CheckAddr(a) != -1 {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return
	}
	if _, err := h.fw.Replace(ctx, m.Set, addrs, core.Family(m.AF)); err != nil {
		h.log.Warn("firewall replace failed", "set", m.Set, "err", err)
	}
}
