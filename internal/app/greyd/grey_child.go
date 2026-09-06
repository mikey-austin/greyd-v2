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
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"time"

	"github.com/mikey-austin/greyd-golang/adapters/spf"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/grey"
	"github.com/mikey-austin/greyd-golang/internal/privs"
	"github.com/mikey-austin/greyd-golang/internal/procs"
	"github.com/mikey-austin/greyd-golang/internal/settings"
	gsync "github.com/mikey-austin/greyd-golang/internal/sync"
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

	readerStore, err := core.OpenStore(s.Raw(), opts)
	if err != nil {
		return fmt.Errorf("could not create db handle: %w", err)
	}
	scannerStore, err := core.OpenStore(s.Raw(), opts)
	if err != nil {
		return fmt.Errorf("could not create db handle: %w", err)
	}

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
		if err := privs.Drop(pw); err != nil {
			return fmt.Errorf("failed to drop privileges: %w", err)
		}
	}

	if err := readerStore.Open(ctx, core.OpenRW); err != nil {
		return err
	}
	defer readerStore.Close()
	if err := scannerStore.Open(ctx, core.OpenRW); err != nil {
		return err
	}
	defer scannerStore.Close()

	var checker core.SPFChecker
	if s.SPF.Enable {
		checker = spfFactory()
	}

	startup := time.Now()
	reader, err := grey.New(grey.Options{Settings: s, Store: readerStore, Syncer: syncer, SPF: checker, Startup: startup, Log: log})
	if err != nil {
		return err
	}
	scanner, err := grey.New(grey.Options{Settings: s, Store: scannerStore, TrapOut: files.trapOut, FwOut: files.fwOut, Startup: startup, Log: log})
	if err != nil {
		return err
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
