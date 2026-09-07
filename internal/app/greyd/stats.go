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

package greyd

import (
	"fmt"
	"sync"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/ipc"
)

// scanStats keeps the latest database counts sent by the greylister.
type scanStats struct {
	mu   sync.Mutex
	last *ipc.ScanStats
}

func (s *scanStats) set(m *ipc.ScanStats) {
	s.mu.Lock()
	s.last = m
	s.mu.Unlock()
}

func (s *scanStats) get() *ipc.ScanStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// statsCounters assembles the counters answered on the configuration
// socket. Names are stable: greyd-monitor maps them to metrics.
func (d *daemon) statsCounters(now time.Time) (map[string]int64, []string) {
	clients, black, maxCons, maxBlack := d.counters.Snapshot()
	t := d.counters.Totals()
	c := map[string]int64{
		"uptime_seconds":                   int64(now.Sub(d.started).Seconds()),
		"connections_current":              int64(clients),
		"connections_current_black":        int64(black),
		"max_cons":                         int64(maxCons),
		"max_cons_black":                   int64(maxBlack),
		"connections_total":                t.Accepted,
		"connections_black_total":          t.AcceptedBlack,
		"connections_refused_total":        t.RefusedFull,
		"connections_refused_source_total": t.RefusedSource,
		"greylist_tuples_total":            t.GreyTuples,
		"replies_grey_total":               t.RepliesGrey,
		"replies_black_total":              t.RepliesBlack,
		"proxy_headers_total":              t.ProxyHeaders,
		"greylisting_enabled":              0,
	}
	if d.greylist {
		c["greylisting_enabled"] = 1
	}
	if sc := d.scan.get(); sc != nil {
		c["db_entries_grey"] = sc.Grey
		c["db_entries_white"] = sc.White
		c["db_entries_trapped"] = sc.Trapped
		c["db_entries_spamtrap"] = sc.Spamtrap
		c["db_entries_domain"] = sc.Domain
		c["db_scan_age_seconds"] = now.Unix() - sc.At
	}
	var bls []string
	for _, bl := range d.snapshotBlacklists() {
		bls = append(bls, fmt.Sprintf("%s=%d", bl.Name, bl.Count))
	}
	return c, bls
}
