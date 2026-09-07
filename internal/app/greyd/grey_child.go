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
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/spf"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/grey"
	"github.com/mikey-austin/greyd-v2/internal/privs"
	"github.com/mikey-austin/greyd-v2/internal/procs"
	"github.com/mikey-austin/greyd-v2/internal/sandbox"
	"github.com/mikey-austin/greyd-v2/internal/settings"
	gsync "github.com/mikey-austin/greyd-v2/internal/sync"
)

// Names of the descriptors passed to the greylister child.
const (
	fdGreyIn  = "greyin"  // main -> grey: tuples and sync updates
	fdTrapOut = "trapout" // grey -> main: traplist configuration
	fdFwOut   = "fwout"   // grey -> fw: whitelist replace requests
)

// greyFiles are the greylister child's pipe ends.
type greyFiles struct {
	greyIn  *os.File
	trapOut *os.File
	fwOut   *os.File
}

func (f greyFiles) closeAll() {
	for _, x := range []*os.File{f.greyIn, f.trapOut, f.fwOut} {
		if x != nil {
			_ = x.Close()
		}
	}
}

func inheritedGreyFiles() (greyFiles, error) {
	var f greyFiles
	var err error
	if f.greyIn, err = procs.InheritedFile(fdGreyIn); err != nil {
		return f, err
	}
	if f.trapOut, err = procs.InheritedFile(fdTrapOut); err != nil {
		return f, err
	}
	if f.fwOut, err = procs.InheritedFile(fdFwOut); err != nil {
		return f, err
	}
	return f, nil
}

// spfFactory builds the SPF checker; replaced in tests.
var spfFactory = func() core.SPFChecker { return spf.New() }

// scanInterval is the database scan period; replaced in tests.
var scanInterval = grey.ScanInterval

// greySandboxProfile is what the greylister still needs once running:
// the resolver configuration for SPF lookups, the database directory and
// the log file's directory.
func greySandboxProfile(s *settings.Settings, store core.Store) sandbox.Profile {
	p := sandbox.Profile{Role: sandbox.RoleGrey, ReadPaths: []string{"/etc"}, Strict: s.SandboxStrict}
	// DNS for SPF (TCP fallback) and the database server, if any.
	p.ConnectPorts = append([]uint16{53}, s.DatabasePorts()...)
	p.WritePaths = append(p.WritePaths, core.WritablePaths(store)...)
	if s.LogToFile != "" {
		p.WritePaths = append(p.WritePaths, filepath.Dir(s.LogToFile))
	}
	return p
}

// lockedStore serialises access to a single store handle shared by the
// greylister's reader and scanner goroutines. Every driver's View/Update
// is then called one at a time, which is safe for all of them (including
// the sqlite driver's single pinned connection).
type lockedStore struct {
	core.Store
	mu sync.Mutex
}

func (l *lockedStore) View(ctx context.Context, fn func(core.ReadTx) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Store.View(ctx, fn)
}

func (l *lockedStore) Update(ctx context.Context, fn func(core.Tx) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Store.Update(ctx, fn)
}

// runGreyChild is the greylisting process (Grey_start): a reader goroutine
// consumes messages from the main process and a scanner goroutine
// periodically expires and whitelists entries. Both run as the grey user
// with their own database handles.
func runGreyChild(ctx context.Context, s *settings.Settings, files greyFiles, log *slog.Logger) error {
	defer files.closeAll()

	var pw *user.User
	if s.DropPrivs {
		var err error
		if pw, err = privs.LookupUser(s.Grey.User); err != nil {
			return err
		}
	}
	opts := core.StoreOptions{User: pw, Hostname: s.Hostname, Log: log}

	// One store handle, shared by the reader and scanner goroutines. A
	// single handle is required by drivers that allow only one opener of a
	// database (bolt takes an exclusive file lock), and avoids
	// same-process contention for the others; lockedStore serialises the
	// two goroutines' transactions so the shared handle is used safely.
	base, err := core.OpenStore(s.Raw(), opts)
	if err != nil {
		return fmt.Errorf("could not create db handle: %w", err)
	}
	store := &lockedStore{Store: base}

	// The greylister only sends sync messages; the main process receives.
	var syncer grey.Syncer
	if sendOnly := s.WithoutSyncBind(); len(sendOnly.Sync.Hosts) > 0 {
		eng, err := gsync.New(sendOnly.Sync, sendOnly.Grey.Enable, log)
		if err != nil {
			log.Warn("could not start sync engine", "err", err)
		} else if eng != nil {
			if err := eng.Start(); err != nil {
				log.Warn("could not start sync engine", "err", err)
			} else {
				syncer = eng
				defer eng.Stop()
			}
		}
	}

	if s.DropPrivs {
		if err := privs.SwitchUser(pw); err != nil {
			if !errors.Is(err, privs.ErrCannotSwitch) {
				return fmt.Errorf("failed to drop privileges: %w", err)
			}
			log.Warn("running unprivileged: continuing as the current user", "wanted", pw.Username)
		}
	}

	if err := store.Open(ctx, core.OpenRW); err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	var checker core.SPFChecker
	if s.SPF.Enable {
		checker = spfFactory()
	}

	startup := time.Now()
	reader, err := grey.New(grey.Options{Settings: s, Store: store, Syncer: syncer, SPF: checker, Startup: startup, Log: log})
	if err != nil {
		return err
	}
	scanner, err := grey.New(grey.Options{Settings: s, Store: store, TrapOut: files.trapOut, FwOut: files.fwOut, Startup: startup, Log: log})
	if err != nil {
		return err
	}
	if s.Sandbox {
		applySandbox(greySandboxProfile(s, base), log)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errc := make(chan error, 2)
	go func() {
		err := reader.RunReader(ctx, files.greyIn)
		if err != nil {
			log.Warn("grey reader stopped", "err", err)
		}
		errc <- err
	}()
	go func() {
		errc <- scanner.RunScanner(ctx, scanInterval)
	}()

	select {
	case <-ctx.Done():
	case <-errc:
	}
	log.Info("exiting")
	cancel()
	// Unblock the reader's pipe read.
	_ = files.greyIn.Close()
	<-errc
	return nil
}
