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
	"os"
	"path/filepath"
	"testing"

	"github.com/mikey-austin/greyd-golang/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

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

func TestConformance(t *testing.T) {
	dbtest.RunConformance(t, func(t *testing.T) core.Store {
		s := newStore(t, t.TempDir())
		if err := s.Open(core.OpenRW); err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { s.Close() })
		return s
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

	s := newStore(t, dir)
	if err := s.Open(core.OpenRW); err != nil {
		t.Fatal(err)
	}
	for _, k := range []core.Key{core.IPKey("1.2.3.4"), core.TupleKey(tuple), core.MailKey("trap@x.org"), core.DomainKey("y.org")} {
		if err := s.Put(k, want); err != nil {
			t.Fatalf("Put(%+v): %v", k, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := newStore(t, dir)
	if err := s2.Open(core.OpenRW); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for _, k := range []core.Key{core.IPKey("1.2.3.4"), core.TupleKey(tuple), core.MailKey("trap@x.org"), core.DomainKey("y.org")} {
		got, found, err := s2.Get(k)
		if err != nil || !found || got != want {
			t.Fatalf("Get(%+v) after reopen = %+v %v %v", k, got, found, err)
		}
	}
	if _, found, _ := s2.Get(core.DomainPartKey("r@sub.y.org")); !found {
		t.Fatal("domain part lookup after reopen")
	}
}

func TestReadOnly(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	if err := s.Open(core.OpenRW); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(core.IPKey("5.5.5.5"), core.Data{First: 7}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	ro := newStore(t, dir)
	if err := ro.Open(core.OpenRO); err != nil {
		t.Fatalf("Open RO: %v", err)
	}
	defer ro.Close()

	d, found, err := ro.Get(core.IPKey("5.5.5.5"))
	if err != nil || !found || d.First != 7 {
		t.Fatalf("Get in RO = %+v %v %v", d, found, err)
	}
	if err := ro.Put(core.IPKey("6.6.6.6"), core.Data{}); err == nil {
		t.Fatal("Put on a read-only store must fail")
	}
	if _, err := ro.Del(core.IPKey("5.5.5.5")); err == nil {
		t.Fatal("Del on a read-only store must fail")
	}

	// An explicit transaction is a read transaction: reads work, writes
	// fail and Commit releases it.
	if err := ro.Begin(); err != nil {
		t.Fatalf("Begin RO: %v", err)
	}
	if _, found, err := ro.Get(core.IPKey("5.5.5.5")); err != nil || !found {
		t.Fatalf("Get in RO tx = %v %v", found, err)
	}
	if err := ro.Put(core.IPKey("6.6.6.6"), core.Data{}); err == nil {
		t.Fatal("Put in a read-only transaction must fail")
	}
	if n := countEntries(t, ro); n != 1 {
		t.Fatalf("RO iteration count = %d", n)
	}
	if err := ro.Commit(); err != nil {
		t.Fatalf("Commit RO: %v", err)
	}
	if err := ro.Commit(); err != core.ErrNotInTransaction {
		t.Fatalf("second Commit = %v", err)
	}
	if _, found, _ := ro.Get(core.IPKey("6.6.6.6")); found {
		t.Fatal("rejected write must not be visible")
	}
}

func TestOpenReadOnlyMissingFile(t *testing.T) {
	s := newStore(t, t.TempDir())
	if err := s.Open(core.OpenRO); err == nil {
		s.Close()
		t.Fatal("read-only open of a missing file should fail")
	}
}

func TestUnopenedStore(t *testing.T) {
	s := newStore(t, t.TempDir())
	if err := s.Put(core.IPKey("1.1.1.1"), core.Data{}); err == nil {
		t.Fatal("Put before Open must fail")
	}
	if err := s.Begin(); err == nil {
		t.Fatal("Begin before Open must fail")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close of an unopened store: %v", err)
	}
}

func TestCloseRollsBackTransaction(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	if err := s.Open(core.OpenRW); err != nil {
		t.Fatal(err)
	}
	if err := s.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(core.IPKey("9.9.9.9"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := newStore(t, dir)
	if err := s2.Open(core.OpenRW); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, found, _ := s2.Get(core.IPKey("9.9.9.9")); found {
		t.Fatal("uncommitted write survived Close")
	}
}

func countEntries(t *testing.T, s core.Store) int {
	t.Helper()
	it, err := s.Iter(core.IterAll)
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
