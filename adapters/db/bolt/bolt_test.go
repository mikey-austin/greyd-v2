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

package bolt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mikey-austin/greyd-golang/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-golang/adapters/db/kv"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

var ctx = context.Background()

func newConfig(dir string) *config.Config {
	cfg := config.New()
	cfg.SetStr("driver", "database", DriverName)
	cfg.SetStr("path", "database", dir)
	cfg.SetStr("db_name", "database", "test.db")
	return cfg
}

// newStore constructs an unopened store through the registered factory.
func newStore(t *testing.T, dir string) core.Store {
	t.Helper()
	s, err := core.OpenStore(newConfig(dir), core.StoreOptions{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s
}

// openStore constructs and opens a store, closing it at the end of the test.
func openStore(t *testing.T, dir string, mode core.OpenMode) core.Store {
	t.Helper()
	s := newStore(t, dir)
	if err := s.Open(ctx, mode); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestConformance(t *testing.T) {
	dbtest.RunConformance(t, func(t *testing.T) core.Store {
		return openStore(t, t.TempDir(), core.OpenRW)
	})
}

func TestFactoryCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "greyd")
	s := newStore(t, dir)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !fi.IsDir() {
		t.Fatal("path is not a directory")
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("directory mode = %o want 700", perm)
	}
	if got := s.(*Store).Path(); got != filepath.Join(dir, "test.db") {
		t.Fatalf("Path = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "test.db")); !os.IsNotExist(err) {
		t.Fatalf("factory must not create the file: %v", err)
	}

	// An existing directory is fine; a missing parent is not.
	if _, err := core.OpenStore(newConfig(dir), core.StoreOptions{}); err != nil {
		t.Fatalf("existing directory: %v", err)
	}
	if _, err := core.OpenStore(newConfig(filepath.Join(dir, "a", "b")), core.StoreOptions{}); err == nil {
		t.Fatal("missing parent directory should fail")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	want := core.Data{First: 1, Pass: 2, Expire: 3, BCount: 4, PCount: 5}
	tuple := core.Tuple{IP: "1.2.3.4", Helo: "h", From: "f@x.org", To: "t@y.org"}
	keys := []core.Key{core.IPKey("1.2.3.4"), core.TupleKey(tuple), core.MailKey("trap@x.org"), core.DomainKey("y.org")}

	s := newStore(t, dir)
	if err := s.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if err := core.Put(ctx, s, k, want); err != nil {
			t.Fatalf("Put(%+v): %v", k, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := openStore(t, dir, core.OpenRW)
	for _, k := range keys {
		got, found, err := core.Get(ctx, s2, k)
		if err != nil || !found || got != want {
			t.Fatalf("Get(%+v) after reopen = %+v %v %v", k, got, found, err)
		}
	}
	if _, found, _ := core.Get(ctx, s2, core.DomainPartKey("r@sub.y.org")); !found {
		t.Fatal("domain part lookup after reopen")
	}
}

func TestReadOnly(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	if err := s.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	if err := core.Put(ctx, s, core.IPKey("5.5.5.5"), core.Data{First: 7}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	ro := openStore(t, dir, core.OpenRO)

	d, found, err := core.Get(ctx, ro, core.IPKey("5.5.5.5"))
	if err != nil || !found || d.First != 7 {
		t.Fatalf("Get in RO = %+v %v %v", d, found, err)
	}
	if err := core.Put(ctx, ro, core.IPKey("6.6.6.6"), core.Data{}); !errors.Is(err, core.ErrReadOnly) {
		t.Fatalf("Put on a read-only store = %v, want ErrReadOnly", err)
	}
	if _, err := core.Del(ctx, ro, core.IPKey("5.5.5.5")); !errors.Is(err, core.ErrReadOnly) {
		t.Fatalf("Del on a read-only store = %v, want ErrReadOnly", err)
	}
	called := false
	err = ro.Update(ctx, func(core.Tx) error {
		called = true
		return nil
	})
	if !errors.Is(err, core.ErrReadOnly) {
		t.Fatalf("Update on a read-only store = %v, want ErrReadOnly", err)
	}
	if called {
		t.Fatal("Update must not run fn on a read-only store")
	}

	// Reads and iteration work in a read transaction.
	err = ro.View(ctx, func(tx core.ReadTx) error {
		if _, found, err := tx.Get(core.IPKey("5.5.5.5")); err != nil || !found {
			t.Fatalf("Get in RO tx = %v %v", found, err)
		}
		if n := countEntries(t, tx); n != 1 {
			t.Fatalf("RO iteration count = %d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View RO: %v", err)
	}
	if _, found, _ := core.Get(ctx, ro, core.IPKey("6.6.6.6")); found {
		t.Fatal("rejected write must not be visible")
	}
}

func TestOpenReadOnlyMissingFile(t *testing.T) {
	s := newStore(t, t.TempDir())
	if err := s.Open(ctx, core.OpenRO); err == nil {
		s.Close()
		t.Fatal("read-only open of a missing file should fail")
	}
}

func TestUnopenedStore(t *testing.T) {
	s := newStore(t, t.TempDir())
	if err := core.Put(ctx, s, core.IPKey("1.1.1.1"), core.Data{}); !errors.Is(err, core.ErrNotOpen) {
		t.Fatalf("Put before Open = %v, want ErrNotOpen", err)
	}
	if err := s.View(ctx, func(core.ReadTx) error { return nil }); !errors.Is(err, core.ErrNotOpen) {
		t.Fatalf("View before Open = %v, want ErrNotOpen", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close of an unopened store: %v", err)
	}
}

func TestOpenCancelledContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	s := newStore(t, t.TempDir())
	if err := s.Open(cancelled, core.OpenRW); !errors.Is(err, context.Canceled) {
		s.Close()
		t.Fatalf("Open with cancelled context = %v", err)
	}
}

func TestIteratorNoCurrent(t *testing.T) {
	s := openStore(t, t.TempDir(), core.OpenRW)
	if err := core.Put(ctx, s, core.IPKey("1.1.1.1"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	err := s.Update(ctx, func(tx core.Tx) error {
		it, err := tx.Iter(core.IterEntries)
		if err != nil {
			return err
		}
		defer it.Close()
		if err := it.DeleteCurrent(); !errors.Is(err, kv.ErrNoCurrent) {
			t.Fatalf("DeleteCurrent before Next = %v", err)
		}
		if err := it.ReplaceCurrent(core.Data{}); !errors.Is(err, kv.ErrNoCurrent) {
			t.Fatalf("ReplaceCurrent before Next = %v", err)
		}
		for {
			if _, _, ok, err := it.Next(); err != nil || !ok {
				break
			}
		}
		if err := it.DeleteCurrent(); !errors.Is(err, kv.ErrNoCurrent) {
			t.Fatalf("DeleteCurrent after the end = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _ := core.Get(ctx, s, core.IPKey("1.1.1.1")); !found {
		t.Fatal("entry must survive")
	}
}

func TestCloseDiscardsNothingCommitted(t *testing.T) {
	// A failed Update leaves no trace on disk after a reopen.
	dir := t.TempDir()
	s := newStore(t, dir)
	if err := s.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err := s.Update(ctx, func(tx core.Tx) error {
		if err := tx.Put(core.IPKey("9.9.9.9"), core.Data{}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Update = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openStore(t, dir, core.OpenRW)
	if _, found, _ := core.Get(ctx, s2, core.IPKey("9.9.9.9")); found {
		t.Fatal("rolled back write survived Close")
	}
}

func countEntries(t *testing.T, tx core.ReadTx) int {
	t.Helper()
	it, err := tx.Iter(core.IterAll)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	n := 0
	for {
		_, _, ok, err := it.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return n
		}
		n++
	}
}
