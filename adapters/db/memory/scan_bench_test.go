package memory

import (
	"context"
	"testing"

	"github.com/mikey-austin/greyd-v2/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-v2/internal/core"
)

// BenchmarkScan measures the expiry/whitelisting pass over a populated
// store; see dbtest.RunScanBenchmark for the population and the
// GREYD_BENCH_ENTRIES override.
func BenchmarkScan(b *testing.B) {
	s := New()
	if err := s.Open(context.Background(), core.OpenRW); err != nil {
		b.Fatal(err)
	}
	dbtest.RunScanBenchmark(b, s)
}
