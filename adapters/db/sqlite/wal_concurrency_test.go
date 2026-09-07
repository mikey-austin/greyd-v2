//go:build !dragonfly

package sqlite

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mikey-austin/greyd-v2/internal/core"
)

// TestWALConcurrentReader confirms a read-only open can read a live WAL
// database that a read-write open created and still holds, mirroring
// greydb/greyd-monitor reading while the greylister writes.
func TestWALConcurrentReader(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	cfg.SetStr("db_name", "database", "live.sqlite")

	writer, err := New(cfg, core.StoreOptions{Hostname: "w"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Open(ctx, core.OpenRW); err != nil {
		t.Fatalf("writer open: %v", err)
	}
	defer writer.Close()
	if err := core.Put(ctx, writer, core.IPKey("10.0.0.1"), core.Data{First: 1, Pass: 2, Expire: 3, PCount: 4}); err != nil {
		t.Fatalf("writer put: %v", err)
	}

	// The write-ahead log must now exist beside the file.
	if _, err := os.Stat(filepath.Join(dir, "live.sqlite-wal")); err != nil {
		t.Fatalf("expected -wal sidecar for a read-write open: %v", err)
	}

	reader, err := New(cfg, core.StoreOptions{Hostname: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Open(ctx, core.OpenRO); err != nil {
		t.Fatalf("reader open on live WAL db: %v", err)
	}
	defer reader.Close()
	d, found, err := core.Get(ctx, reader, core.IPKey("10.0.0.1"))
	if err != nil || !found {
		t.Fatalf("reader get: %v found=%v", err, found)
	}
	if d.PCount != 4 {
		t.Fatalf("reader got %+v", d)
	}

	// A write committed after the reader opened is visible to a fresh read.
	if err := core.Put(ctx, writer, core.IPKey("10.0.0.2"), core.Data{PCount: 7}); err != nil {
		t.Fatalf("writer second put: %v", err)
	}
	if d, found, err := core.Get(ctx, reader, core.IPKey("10.0.0.2")); err != nil || !found || d.PCount != 7 {
		t.Fatalf("reader second get: %+v found=%v err=%v", d, found, err)
	}
}
