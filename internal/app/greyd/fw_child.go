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
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ip"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/privs"
	"github.com/mikey-austin/greyd-golang/internal/procs"
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
func runFwChild(ctx context.Context, cfg *config.Config, files fwFiles) error {
	defer files.closeAll()

	fw, err := core.OpenFirewall(cfg)
	if err != nil {
		return err
	}
	defer fw.Close()

	if err := dropMainPrivs(cfg, driverIsPF(cfg)); err != nil {
		return err
	}

	var fwMu sync.Mutex
	handle := func(r io.Reader) error {
		rd := ipc.NewReader(r)
		for {
			m, err := rd.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				if ctx.Err() != nil {
					return nil
				}
				logger.Warning("firewall process: parse error: %v", err)
				continue
			}
			fwMu.Lock()
			processFwMessage(m, fw, files.natOut)
			fwMu.Unlock()
		}
	}

	errc := make(chan error, 2)
	go func() { errc <- handle(files.fwIn) }()
	go func() { errc <- handle(files.greyFwIn) }()

	select {
	case <-ctx.Done():
		logger.Info("stopping firewall process")
	case err := <-errc:
		if err != nil {
			return err
		}
		// One pipe closed: the parent is going away.
		logger.Info("stopping firewall process")
	}
	return nil
}

// driverIsPF reports whether the configured firewall driver is pf, which
// needs filesystem access (pfctl) and so is not chrooted (WITH_PF in C).
func driverIsPF(cfg *config.Config) bool {
	sec := cfg.Section("firewall")
	if sec == nil {
		return false
	}
	return core.NormalizeDriver(sec.Str("driver", "")) == "pf"
}

// dropMainPrivs chroots (unless skipChroot) and switches to the main user
// according to the configuration.
func dropMainPrivs(cfg *config.Config, skipChroot bool) error {
	mainUser := cfg.Str("user", "", MainUser)
	dropPrivs := cfg.Bool("drop_privs", "", true)
	if !skipChroot && cfg.Bool("chroot", "", DefaultChroot == 1) {
		if err := privs.Chroot(cfg.Str("chroot_dir", "", ChrootDir)); err != nil {
			return err
		}
	}
	if dropPrivs {
		u, err := privs.LookupUser(mainUser)
		if err != nil {
			return err
		}
		if err := privs.Drop(u); err != nil {
			return fmt.Errorf("failed to drop privileges: %w", err)
		}
	}
	return nil
}

// processFwMessage handles one request (Greyd_process_fw_message).
func processFwMessage(m *config.Config, fw core.Firewall, out io.Writer) {
	typ := m.Str("type", "", "")
	switch typ {
	case ipc.TypeNAT:
		src := m.Str("src", "", "")
		proxy := m.Str("proxy", "", "")
		srcPort := m.Int("src_port", "", 0)
		proxyPort := m.Int("proxy_port", "", 0)
		if srcPort == 0 || proxyPort == 0 {
			logger.Debug("nat lookup: expecting non-zero src & proxy ports")
			return
		}
		srcAddr, err1 := netip.ParseAddr(src)
		proxyAddr, err2 := netip.ParseAddr(proxy)
		if err1 != nil || err2 != nil {
			logger.Debug("nat lookup: bad addresses %q %q", src, proxy)
			return
		}
		dst := ""
		res, err := fw.LookupOrigDst(netip.AddrPortFrom(srcAddr, uint16(srcPort)), netip.AddrPortFrom(proxyAddr, uint16(proxyPort)))
		if err == nil && res.IsValid() {
			dst = res.Addr().Unmap().String()
		} else if err != nil {
			logger.Debug("nat lookup failed: %v", err)
		}
		if out != nil {
			if err := ipc.WriteDst(out, dst); err != nil {
				logger.Debug("dnat lookup: write failed: %v", err)
			}
		}

	case ipc.TypeReplace:
		name := m.Str("name", "", "")
		af := core.Family(m.Int("af", "", int(core.IPv4)))
		var addrs []string
		for _, a := range m.StrList("ips", "") {
			if ip.CheckAddr(a) != -1 {
				addrs = append(addrs, a)
			}
		}
		if len(addrs) > 0 {
			if _, err := fw.Replace(name, addrs, af); err != nil {
				logger.Warning("firewall replace %s failed: %v", name, err)
			}
		}
	}
}
