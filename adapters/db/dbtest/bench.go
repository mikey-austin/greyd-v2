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

package dbtest

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/core"
)

// DefaultBenchEntries is the population of the scan benchmark unless
// GREYD_BENCH_ENTRIES overrides it.
const DefaultBenchEntries = 200000

// BenchEntriesEnv names the environment variable overriding the size.
const BenchEntriesEnv = "GREYD_BENCH_ENTRIES"

// Shape of the benchmark population: the expiry of entry i lies in bucket
// i % benchBuckets, one bucket per benchStep of simulated time, so that
// advancing the clock by benchStep between scans expires one bucket
// (a tenth of the entries) per scan. One grey tuple in benchRetried has
// already been retried and is whitelisted by the first scan instead.
const (
	benchBuckets = 10
	benchStep    = int64(3600)
	benchRetried = 50
	// benchRetriedOffset selects the retried tuple within each run of
	// benchRetried: index 1 is a grey tuple (1 mod 5 < 3) in bucket 1, so
	// the first scan whitelists it before its expiry bucket comes up.
	benchRetriedOffset = 1
	benchBase          = int64(1700000000)
	benchWhiteExp      = int64(3110400)
	benchGreyOutOf5    = 3 // three entries in five are grey tuples, two are white
)

// BenchEntries returns the population size for the scan benchmark.
func BenchEntries(b *testing.B) int {
	b.Helper()
	v := os.Getenv(BenchEntriesEnv)
	if v == "" {
		return DefaultBenchEntries
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		b.Fatalf("%s=%q: want a positive integer", BenchEntriesEnv, v)
	}
	return n
}

// RunScanBenchmark measures Tx.Scan on s, which must be open read-write
// and empty. The store is populated with BenchEntries entries (three
// fifths grey tuples, two fifths white addresses) whose expiries are
// spread over benchBuckets steps; every iteration advances the simulated
// clock by one step so roughly a tenth of the entries expire per scan, and
// after benchBuckets scans, when everything has expired, the store is
// emptied and repopulated with the timer stopped. Population and clearing
// are excluded from the timing.
func RunScanBenchmark(b *testing.B, s core.Store) {
	b.Helper()
	ctx := context.Background()
	n := BenchEntries(b)

	populate := func() {
		b.StopTimer()
		start := time.Now()
		if err := clearStore(ctx, s); err != nil {
			b.Fatalf("clear: %v", err)
		}
		if err := populateStore(ctx, s, n); err != nil {
			b.Fatalf("populate: %v", err)
		}
		b.Logf("populated %d entries in %s", n, time.Since(start).Round(time.Millisecond))
		b.StartTimer()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		step := i % benchBuckets
		if step == 0 {
			populate()
		}
		now := benchBase + int64(step+1)*benchStep
		var res core.ScanResult
		err := s.Update(ctx, func(tx core.Tx) error {
			var err error
			res, err = tx.Scan(now, benchWhiteExp)
			return err
		})
		if err != nil {
			b.Fatalf("scan: %v", err)
		}
		if len(res.Whitelist) == 0 {
			b.Fatal("scan returned an empty whitelist")
		}
	}
	b.ReportMetric(float64(n), "entries/scan")
	b.ReportMetric(float64(n)/benchBuckets, "expired/scan")
}

// populateStore inserts n entries in one transaction.
func populateStore(ctx context.Context, s core.Store, n int) error {
	return s.Update(ctx, func(tx core.Tx) error {
		for i := 0; i < n; i++ {
			ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
			expire := benchBase + int64(i%benchBuckets+1)*benchStep
			d := core.Data{First: benchBase - 60, Pass: expire, Expire: expire, BCount: 1}
			var k core.Key
			if i%5 < benchGreyOutOf5 {
				k = core.TupleKey(core.Tuple{IP: ip, Helo: "mx.example.org", From: "sender@example.org", To: fmt.Sprintf("user%d@example.net", i)})
				if i%benchRetried == benchRetriedOffset {
					d.Pass = benchBase
					d.BCount = 2
				}
			} else {
				k = core.IPKey(ip)
				d.Pass = benchBase - 60
				d.PCount = 3
			}
			if err := tx.Put(k, d); err != nil {
				return err
			}
		}
		return nil
	})
}

// clearStore deletes every entry.
func clearStore(ctx context.Context, s core.Store) error {
	return s.Update(ctx, func(tx core.Tx) error {
		it, err := tx.Iter(core.IterAll)
		if err != nil {
			return err
		}
		defer func() { _ = it.Close() }()
		for {
			_, _, ok, err := it.Next()
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			if err := it.DeleteCurrent(); err != nil {
				return err
			}
		}
	})
}
