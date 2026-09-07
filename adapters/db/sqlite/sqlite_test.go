//go:build !dragonfly

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

package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-v2/adapters/db/sqlcommon"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/core"
)

var ctx = context.Background()

func testConfig(t *testing.T, dir string) *config.Config {
	t.Helper()
	cfg := config.New()
	cfg.SetStr("driver", "database", DriverName)
	cfg.SetStr("path", "database", dir)
	cfg.SetStr("db_name", "database", "test.sqlite")
	return cfg
}

func openMode(t *testing.T, dir string, mode core.OpenMode) *Store {
	t.Helper()
	s, err := New(testConfig(t, dir), core.StoreOptions{Hostname: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Open(ctx, mode); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	return openMode(t, dir, core.OpenRW)
}

func TestConformance(t *testing.T) {
	dbtest.RunConformance(t, func(t *testing.T) core.Store {
		return openStore(t, filepath.Join(t.TempDir(), "db"))
	})
}

func TestCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing", "..", "created")
	dir = filepath.Clean(dir)
	s := openStore(t, dir)
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("path not created: %v", err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("path mode = %o want 700", st.Mode().Perm())
	}
	if _, err := os.Stat(s.Path()); err != nil {
		t.Fatalf("database file not created: %v", err)
	}
	if s.Path() != filepath.Join(dir, "test.sqlite") {
		t.Fatalf("Path() = %s", s.Path())
	}
}

func TestMissingParentFails(t *testing.T) {
	_, err := New(testConfig(t, filepath.Join(t.TempDir(), "a", "b")), core.StoreOptions{})
	if err == nil {
		t.Fatal("expected mkdir failure for missing parent")
	}
}

func TestOpenTwiceIsNoop(t *testing.T) {
	s := openStore(t, t.TempDir())
	if err := core.Put(ctx, s, core.IPKey("1.1.1.1"), core.Data{First: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Open(ctx, core.OpenRO); err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if _, found, err := core.Get(ctx, s, core.IPKey("1.1.1.1")); err != nil || !found {
		t.Fatalf("entry lost across reopen: %v %v", found, err)
	}
	// The second Open did not turn the store read-only.
	if err := core.Put(ctx, s, core.IPKey("1.1.1.2"), core.Data{}); err != nil {
		t.Fatalf("Put after no-op reopen: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := core.Put(ctx, s, core.IPKey("1.1.1.1"), core.Data{}); !errors.Is(err, core.ErrNotOpen) {
		t.Fatalf("Put on a closed store = %v, want ErrNotOpen", err)
	}
	if err := s.View(ctx, func(core.ReadTx) error { return nil }); !errors.Is(err, core.ErrNotOpen) {
		t.Fatalf("View on a closed store = %v, want ErrNotOpen", err)
	}
}

func TestUnopenedStore(t *testing.T) {
	s, err := New(testConfig(t, t.TempDir()), core.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(core.Tx) error { return nil }); !errors.Is(err, core.ErrNotOpen) {
		t.Fatalf("Update before Open = %v, want ErrNotOpen", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close of an unopened store: %v", err)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	if err := core.Put(ctx, s, core.MailKey("trap@x.org"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openStore(t, dir)
	if _, found, err := core.Get(ctx, s2, core.MailKey("trap@x.org")); err != nil || !found {
		t.Fatalf("data did not persist: %v %v", found, err)
	}
}

func TestReadOnly(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	if err := core.Put(ctx, s, core.IPKey("5.5.5.5"), core.Data{First: 7}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	ro := openMode(t, dir, core.OpenRO)
	if d, found, err := core.Get(ctx, ro, core.IPKey("5.5.5.5")); err != nil || !found || d.First != 7 {
		t.Fatalf("Get in RO = %+v %v %v", d, found, err)
	}
	called := false
	err := ro.Update(ctx, func(core.Tx) error {
		called = true
		return nil
	})
	if !errors.Is(err, core.ErrReadOnly) {
		t.Fatalf("Update on a read-only store = %v, want ErrReadOnly", err)
	}
	if called {
		t.Fatal("Update must not run fn on a read-only store")
	}
	if err := core.Put(ctx, ro, core.IPKey("6.6.6.6"), core.Data{}); !errors.Is(err, core.ErrReadOnly) {
		t.Fatalf("Put on a read-only store = %v, want ErrReadOnly", err)
	}
	// The read-only store is still usable for reads afterwards.
	if _, found, err := core.Get(ctx, ro, core.IPKey("6.6.6.6")); err != nil || found {
		t.Fatalf("Get after refused write = %v %v", found, err)
	}
}

func TestRegisteredFactory(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	s, err := core.OpenStore(cfg, core.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*Store); !ok {
		t.Fatalf("factory returned %T", s)
	}
	if err := s.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := core.Put(ctx, s, core.DomainKey("x.org"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := core.Get(ctx, s, core.DomainPartKey("a@x.org")); !found {
		t.Fatal("domain part lookup")
	}
}

func TestIteratorNoCurrent(t *testing.T) {
	s := openStore(t, t.TempDir())
	err := s.View(ctx, func(tx core.ReadTx) error {
		it, err := tx.Iter(core.IterAll)
		if err != nil {
			return err
		}
		defer it.Close()
		if err := it.DeleteCurrent(); !errors.Is(err, sqlcommon.ErrNoCurrent) {
			t.Fatalf("DeleteCurrent before Next = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBusyRetry(t *testing.T) {
	var slept []time.Duration
	sleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { sleep = time.Sleep })

	dir := t.TempDir()
	a := openStore(t, dir)
	b := openStore(t, dir)

	err := a.Update(ctx, func(tx core.Tx) error {
		if err := tx.Put(core.IPKey("1.1.1.1"), core.Data{First: 1}); err != nil {
			return err
		}
		// b cannot start an immediate transaction while a holds the
		// lock; every retry is exhausted first.
		called := false
		err := b.Update(ctx, func(core.Tx) error {
			called = true
			return nil
		})
		if err == nil {
			t.Fatal("Update on a locked database must succeed only after a commits")
		}
		if called {
			t.Fatal("fn ran without a transaction")
		}
		if len(slept) != maxRetry {
			t.Fatalf("slept %d times, want %d", len(slept), maxRetry)
		}
		for _, d := range slept {
			if d != retryDelay {
				t.Fatalf("slept %v want %v", d, retryDelay)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The failed begin left b usable, and the lock is gone now.
	slept = nil
	if err := core.Put(ctx, b, core.IPKey("2.2.2.2"), core.Data{First: 2}); err != nil {
		t.Fatalf("Update after the lock was released: %v", err)
	}
	if len(slept) != 0 {
		t.Fatalf("unexpected retries: %d", len(slept))
	}
	if _, found, err := core.Get(ctx, b, core.IPKey("1.1.1.1")); err != nil || !found {
		t.Fatalf("committed entry not visible: %v %v", found, err)
	}
	if _, found, err := core.Get(ctx, a, core.IPKey("2.2.2.2")); err != nil || !found {
		t.Fatalf("b's entry not visible to a: %v %v", found, err)
	}
}
