//go:build !dragonfly

package sqlite

import (
	"testing"

	"github.com/mikey-austin/greyd-v2/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/core"
)

// BenchmarkScan measures the expiry/whitelisting pass over a populated
// database file; see dbtest.RunScanBenchmark for the population and the
// GREYD_BENCH_ENTRIES override.
func BenchmarkScan(b *testing.B) {
	cfg := config.New()
	cfg.SetStr("driver", "database", DriverName)
	cfg.SetStr("path", "database", b.TempDir())
	cfg.SetStr("db_name", "database", "bench.sqlite")
	s, err := New(cfg, core.StoreOptions{Hostname: "bench"})
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Open(ctx, core.OpenRW); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	dbtest.RunScanBenchmark(b, s)
}
