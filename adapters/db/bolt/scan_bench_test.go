package bolt

import (
	"testing"

	"github.com/mikey-austin/greyd-v2/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-v2/internal/core"
)

// BenchmarkScan measures the expiry/whitelisting pass over a populated
// database file; see dbtest.RunScanBenchmark for the population and the
// GREYD_BENCH_ENTRIES override.
func BenchmarkScan(b *testing.B) {
	s, err := core.OpenStore(newConfig(b.TempDir()), core.StoreOptions{})
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Open(ctx, core.OpenRW); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	dbtest.RunScanBenchmark(b, s)
}
