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
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/mikey-austin/greyd-v2/internal/core"
)

// The golden fixture pins the on-disk format: a database written by the
// driver at a known point in time, containing one entry of every kind with
// fixed timestamps. TestGoldenFixture must keep passing against the
// committed file; if it fails after a change to the schema, to package
// sqlcommon or to this driver, the change broke compatibility with
// existing databases (and with databases written by the C driver, which
// share the schema).
//
// Regenerate (only when a format change is intended) with
//
//	GREYD_UPDATE_GOLDEN=1 go test ./adapters/db/sqlite -run TestUpdateGolden
const (
	goldenDir  = "testdata/golden"
	goldenName = "greyd.sqlite"
	// goldenMaxSize bounds the fixture so it stays a small committed file.
	goldenMaxSize = 32 << 10
)

// goldenEntry pairs a key with the data the driver returns for it.
type goldenEntry struct {
	k core.Key
	d core.Data
}

// goldenEntries is the fixture's content. Spamtraps and domains carry no
// counters in the SQL schema; the driver synthesises the -2 and -3
// sentinels for them.
func goldenEntries() []goldenEntry {
	const now = int64(1700000000)
	return []goldenEntry{
		{
			k: core.TupleKey(core.Tuple{IP: "192.0.2.10", Helo: "mx.example.org", From: "sender@example.org", To: "rcpt@example.net"}),
			d: core.Data{First: now, Pass: now + 14400, Expire: now + 14400, BCount: 1},
		},
		{
			k: core.IPKey("198.51.100.7"),
			d: core.Data{First: now - 1000000, Pass: now - 999100, Expire: now + 2110400, BCount: 2, PCount: 5},
		},
		{
			k: core.IPKey("203.0.113.99"),
			d: core.Data{First: now, Pass: now + 86400, Expire: now + 86400, BCount: 1, PCount: core.PCountTrapped},
		},
		{k: core.MailKey("trap@example.net"), d: core.Data{PCount: core.PCountSpamtrap}},
		{k: core.DomainKey("example.net"), d: core.Data{PCount: core.PCountDomain}},
	}
}

func entryLess(a, b goldenEntry) bool {
	return fmt.Sprintf("%d %q %q", a.k.Type, a.k.Str, a.k.Tuple) < fmt.Sprintf("%d %q %q", b.k.Type, b.k.Str, b.k.Tuple)
}

// TestUpdateGolden rewrites the fixture. It is a no-op unless
// GREYD_UPDATE_GOLDEN=1 is set.
func TestUpdateGolden(t *testing.T) {
	if os.Getenv("GREYD_UPDATE_GOLDEN") != "1" {
		t.Skip("set GREYD_UPDATE_GOLDEN=1 to regenerate the fixture")
	}
	if err := os.MkdirAll(goldenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(goldenDir, goldenName)
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}

	cfg := testConfig(t, goldenDir)
	cfg.SetStr("db_name", "database", goldenName)
	s, err := New(cfg, core.StoreOptions{Hostname: "golden"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	err = s.Update(ctx, func(tx core.Tx) error {
		for _, e := range goldenEntries() {
			if err := tx.Put(e.k, e.d); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The driver uses the default rollback journal, so nothing is left
	// beside the file once it is closed; shrink the pages so the fixture
	// stays small (the page size is a per-file property SQLite reads back
	// from the header, so the driver is unaffected).
	if err := compactSQLite(path); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			t.Fatalf("leftover %s next to the fixture", path+suffix)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > goldenMaxSize {
		t.Fatalf("fixture is %d bytes, over the %d byte cap", fi.Size(), goldenMaxSize)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", path, fi.Size())
}

// compactSQLite rewrites the file with 1 KiB pages, checkpointing any
// journal in the process.
func compactSQLite(path string) error {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return err
	}
	defer db.Close()
	for _, stmt := range []string{"PRAGMA journal_mode=DELETE", "PRAGMA page_size=1024", "VACUUM"} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

// copyFixture copies the committed file into a temporary directory so the
// test never opens the file in the tree.
func copyFixture(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(goldenDir, goldenName))
	if err != nil {
		t.Fatalf("golden fixture missing (run with GREYD_UPDATE_GOLDEN=1 to create it): %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, goldenName), src, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openGolden(t *testing.T, dir string, mode core.OpenMode) *Store {
	t.Helper()
	cfg := testConfig(t, dir)
	cfg.SetStr("db_name", "database", goldenName)
	s, err := New(cfg, core.StoreOptions{Hostname: "golden"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(ctx, mode); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func listAll(t *testing.T, s core.Store) []goldenEntry {
	t.Helper()
	var got []goldenEntry
	err := s.View(ctx, func(tx core.ReadTx) error {
		it, err := tx.Iter(core.IterAll)
		if err != nil {
			return err
		}
		defer it.Close()
		for {
			k, d, ok, err := it.Next()
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			got = append(got, goldenEntry{k: k, d: d})
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return entryLess(got[i], got[j]) })
	return got
}

// TestGoldenFixture opens the committed database read-only and checks that
// it decodes to exactly the entries it was written with.
func TestGoldenFixture(t *testing.T) {
	dir := copyFixture(t)
	s := openGolden(t, dir, core.OpenRO)

	want := goldenEntries()
	sort.Slice(want, func(i, j int) bool { return entryLess(want[i], want[j]) })
	got := listAll(t, s)
	if len(got) != len(want) {
		t.Fatalf("fixture holds %d entries, want %d:\n got %+v\nwant %+v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
	for _, e := range want {
		d, found, err := core.Get(ctx, s, e.k)
		if err != nil {
			t.Fatalf("Get %+v: %v", e.k, err)
		}
		if !found || d != e.d {
			t.Errorf("Get %+v = %+v %v, want %+v", e.k, d, found, e.d)
		}
	}
	if _, found, err := core.Get(ctx, s, core.DomainPartKey("someone@example.net")); err != nil || !found {
		t.Fatalf("DomainPart lookup: %v %v", found, err)
	}
	if err := core.Put(ctx, s, core.IPKey("1.1.1.1"), core.Data{}); !errors.Is(err, core.ErrReadOnly) {
		t.Fatalf("Put on read-only fixture = %v, want ErrReadOnly", err)
	}
	// Reading must not have created a journal or changed the file.
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Stat(filepath.Join(dir, goldenName+suffix)); err == nil {
			t.Fatalf("read-only open left %s behind", goldenName+suffix)
		}
	}
}

// TestGoldenFixtureWritable checks that a database in the committed format
// can still be opened read-write and modified, as an upgrade would.
func TestGoldenFixtureWritable(t *testing.T) {
	dir := copyFixture(t)
	s := openGolden(t, dir, core.OpenRW)
	if err := core.Put(ctx, s, core.IPKey("2001:db8::1"), core.Data{First: 1, Pass: 1, Expire: 1 << 40}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := listAll(t, s); len(got) != len(goldenEntries())+1 {
		t.Fatalf("after Put: %d entries", len(got))
	}
	var res core.ScanResult
	err := s.Update(ctx, func(tx core.Tx) error {
		var err error
		res, err = tx.Scan(1700000000, 3110400)
		return err
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Whitelist) != 1 || res.Whitelist[0] != "198.51.100.7" || len(res.Traplist) != 1 || res.Traplist[0] != "203.0.113.99" || len(res.WhitelistV6) != 1 {
		t.Fatalf("Scan of the fixture: %+v", res)
	}
}
