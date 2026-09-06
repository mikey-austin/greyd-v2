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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-golang/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

func testConfig(t *testing.T, dir string) *config.Config {
	t.Helper()
	cfg := config.New()
	cfg.SetStr("driver", "database", DriverName)
	cfg.SetStr("path", "database", dir)
	cfg.SetStr("db_name", "database", "test.sqlite")
	return cfg
}

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := New(testConfig(t, dir), core.StoreOptions{Hostname: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Open(core.OpenRW); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
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
	if err := s.Put(core.IPKey("1.1.1.1"), core.Data{First: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Open(core.OpenRO); err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if _, found, err := s.Get(core.IPKey("1.1.1.1")); err != nil || !found {
		t.Fatalf("entry lost across reopen: %v %v", found, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.Put(core.IPKey("1.1.1.1"), core.Data{}); err == nil {
		t.Fatal("Put on a closed store must fail")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	if err := s.Put(core.MailKey("trap@x.org"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openStore(t, dir)
	if _, found, err := s2.Get(core.MailKey("trap@x.org")); err != nil || !found {
		t.Fatalf("data did not persist: %v %v", found, err)
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
	if err := s.Open(core.OpenRW); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Put(core.DomainKey("x.org"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.Get(core.DomainPartKey("a@x.org")); !found {
		t.Fatal("domain part lookup")
	}
}

func TestBusyRetry(t *testing.T) {
	var slept []time.Duration
	sleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { sleep = time.Sleep })

	dir := t.TempDir()
	a := openStore(t, dir)
	b := openStore(t, dir)

	if err := a.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := a.Put(core.IPKey("1.1.1.1"), core.Data{First: 1}); err != nil {
		t.Fatal(err)
	}

	// b cannot start an immediate transaction while a holds the lock.
	err := b.Begin()
	if err == nil {
		t.Fatal("Begin on a locked database must fail")
	}
	if errors.Is(err, core.ErrInTransaction) {
		t.Fatalf("unexpected error %v", err)
	}
	if len(slept) != maxRetry {
		t.Fatalf("slept %d times, want %d", len(slept), maxRetry)
	}
	for _, d := range slept {
		if d != retryDelay {
			t.Fatalf("slept %v want %v", d, retryDelay)
		}
	}
	if b.InTxn() {
		t.Fatal("failed Begin left the store in a transaction")
	}

	if err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	slept = nil
	if err := b.Begin(); err != nil {
		t.Fatalf("Begin after the lock was released: %v", err)
	}
	if len(slept) != 0 {
		t.Fatalf("unexpected retries: %d", len(slept))
	}
	if _, found, err := b.Get(core.IPKey("1.1.1.1")); err != nil || !found {
		t.Fatalf("committed entry not visible: %v %v", found, err)
	}
	if err := b.Rollback(); err != nil {
		t.Fatal(err)
	}
}
