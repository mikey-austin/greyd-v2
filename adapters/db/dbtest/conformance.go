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

// Package dbtest is a conformance suite that every database driver must
// pass. It encodes the semantics the greylisting engine relies on.
package dbtest

import (
	"errors"
	"sort"
	"testing"

	"github.com/mikey-austin/greyd-golang/internal/core"
)

// OpenFunc returns a freshly opened, empty, read-write store. Any cleanup
// must be registered with t.Cleanup.
type OpenFunc func(t *testing.T) core.Store

// RunConformance runs every scenario against the driver.
func RunConformance(t *testing.T, open OpenFunc) {
	t.Helper()
	t.Run("PutGetDel", func(t *testing.T) { testPutGetDel(t, open(t)) })
	t.Run("Iterate", func(t *testing.T) { testIterate(t, open(t)) })
	t.Run("DomainPart", func(t *testing.T) { testDomainPart(t, open(t)) })
	t.Run("Scan", func(t *testing.T) { testScan(t, open(t)) })
	t.Run("Transactions", func(t *testing.T) { testTransactions(t, open(t)) })
	t.Run("IteratorMutation", func(t *testing.T) { testIteratorMutation(t, open(t)) })
	t.Run("ReopenNoop", func(t *testing.T) { testReopen(t, open(t)) })
}

var (
	tupleA = core.Tuple{IP: "1.2.3.4", Helo: "mx.example.org", From: "m@jackiemclean.net", To: "r@domain1.com"}
	tupleB = core.Tuple{IP: "1.2.4.4", Helo: "mx.example.org", From: "m@jackiemclean.net", To: "r@domain1.com"}
)

func mustPut(t *testing.T, s core.Store, k core.Key, d core.Data) {
	t.Helper()
	if err := s.Put(k, d); err != nil {
		t.Fatalf("Put(%+v): %v", k, err)
	}
}

func mustGet(t *testing.T, s core.Store, k core.Key) (core.Data, bool) {
	t.Helper()
	d, found, err := s.Get(k)
	if err != nil {
		t.Fatalf("Get(%+v): %v", k, err)
	}
	return d, found
}

func testPutGetDel(t *testing.T, s core.Store) {
	want := core.Data{First: 1, Pass: 2, Expire: 3, BCount: 4, PCount: 5}
	mustPut(t, s, core.IPKey("1.2.3.4"), want)
	got, found := mustGet(t, s, core.IPKey("1.2.3.4"))
	if !found || got != want {
		t.Fatalf("Get IP = %+v %v", got, found)
	}
	if _, found := mustGet(t, s, core.IPKey("9.9.9.9")); found {
		t.Fatal("missing IP should not be found")
	}

	// Overwrite.
	want.BCount = 40
	mustPut(t, s, core.IPKey("1.2.3.4"), want)
	if got, _ := mustGet(t, s, core.IPKey("1.2.3.4")); got != want {
		t.Fatalf("overwrite = %+v", got)
	}

	td := core.Data{First: 10, Pass: 20, Expire: 30, BCount: 1, PCount: 0}
	mustPut(t, s, core.TupleKey(tupleA), td)
	got, found = mustGet(t, s, core.TupleKey(tupleA))
	if !found || got != td {
		t.Fatalf("Get tuple = %+v %v", got, found)
	}
	other := tupleA
	other.To = "x@y.z"
	if _, found := mustGet(t, s, core.TupleKey(other)); found {
		t.Fatal("different tuple must not match")
	}
	// A tuple never matches an address key of another address.
	if _, found := mustGet(t, s, core.IPKey("9.9.9.9")); found {
		t.Fatal("unrelated IP key found")
	}

	mustPut(t, s, core.MailKey("trap@domain3.com"), core.Data{})
	if _, found := mustGet(t, s, core.MailKey("trap@domain3.com")); !found {
		t.Fatal("spamtrap not found")
	}
	if _, found := mustGet(t, s, core.MailKey("other@domain3.com")); found {
		t.Fatal("other spamtrap found")
	}
	mustPut(t, s, core.DomainKey("domain1.com"), core.Data{})
	if _, found := mustGet(t, s, core.DomainKey("domain1.com")); !found {
		t.Fatal("domain not found")
	}

	found, err := s.Del(core.IPKey("1.2.3.4"))
	if err != nil || !found {
		t.Fatalf("Del = %v %v", found, err)
	}
	if _, found := mustGet(t, s, core.IPKey("1.2.3.4")); found {
		t.Fatal("deleted IP still present")
	}
	found, err = s.Del(core.IPKey("1.2.3.4"))
	if err != nil || found {
		t.Fatalf("second Del = %v %v", found, err)
	}
	if found, err := s.Del(core.TupleKey(tupleA)); err != nil || !found {
		t.Fatalf("Del tuple = %v %v", found, err)
	}
	if found, err := s.Del(core.MailKey("trap@domain3.com")); err != nil || !found {
		t.Fatalf("Del mail = %v %v", found, err)
	}
	if found, err := s.Del(core.DomainKey("domain1.com")); err != nil || !found {
		t.Fatalf("Del domain = %v %v", found, err)
	}
	if n := count(t, s, core.IterAll); n != 0 {
		t.Fatalf("expected empty store, got %d entries", n)
	}
}

type counts struct {
	ip, tuple, mail, domain int
}

func tally(t *testing.T, s core.Store, types core.IterTypes) (counts, map[string]core.Data) {
	t.Helper()
	it, err := s.Iter(types)
	if err != nil {
		t.Fatalf("Iter: %v", err)
	}
	defer it.Close()
	var c counts
	seen := map[string]core.Data{}
	for {
		k, d, ok, err := it.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if !ok {
			break
		}
		switch k.Type {
		case core.KeyIP:
			c.ip++
			seen["ip:"+k.Str] = d
		case core.KeyTuple:
			c.tuple++
			seen["tuple:"+k.Tuple.IP+"|"+k.Tuple.Helo+"|"+k.Tuple.From+"|"+k.Tuple.To] = d
		case core.KeyMail:
			c.mail++
			seen["mail:"+k.Str] = d
		case core.KeyDomain:
			c.domain++
			seen["domain:"+k.Str] = d
		default:
			t.Fatalf("unexpected key type %d", k.Type)
		}
	}
	return c, seen
}

func count(t *testing.T, s core.Store, types core.IterTypes) int {
	c, _ := tally(t, s, types)
	return c.ip + c.tuple + c.mail + c.domain
}

func testIterate(t *testing.T, s core.Store) {
	mustPut(t, s, core.TupleKey(tupleA), core.Data{First: 1, Pass: 2, Expire: 3, BCount: 4, PCount: 0})
	mustPut(t, s, core.TupleKey(tupleB), core.Data{First: 5, Pass: 6, Expire: 7, BCount: 8, PCount: 0})
	mustPut(t, s, core.TupleKey(tupleB), core.Data{First: 5, Pass: 6, Expire: 7, BCount: 9, PCount: 0}) // duplicate
	mustPut(t, s, core.IPKey("4.3.2.1"), core.Data{First: 9, Pass: 10, Expire: 11, BCount: 12, PCount: 13})
	mustPut(t, s, core.IPKey("2001::1"), core.Data{First: 9, Pass: 10, Expire: 11, BCount: 12, PCount: 13})
	mustPut(t, s, core.MailKey("trap@domain3.com"), core.Data{})
	mustPut(t, s, core.DomainKey("domain1.com"), core.Data{})

	c, seen := tally(t, s, core.IterAll)
	if c != (counts{ip: 2, tuple: 2, mail: 1, domain: 1}) {
		t.Fatalf("counts = %+v", c)
	}
	if d := seen["tuple:1.2.4.4|mx.example.org|m@jackiemclean.net|r@domain1.com"]; d.BCount != 9 {
		t.Fatalf("tuple B data %+v", d)
	}
	if d := seen["ip:4.3.2.1"]; d != (core.Data{First: 9, Pass: 10, Expire: 11, BCount: 12, PCount: 13}) {
		t.Fatalf("ip data %+v", d)
	}
	if _, ok := seen["mail:trap@domain3.com"]; !ok {
		t.Fatal("spamtrap missing from iteration")
	}
	if _, ok := seen["domain:domain1.com"]; !ok {
		t.Fatal("domain missing from iteration")
	}

	if c, _ := tally(t, s, core.IterEntries); c != (counts{ip: 2, tuple: 2}) {
		t.Fatalf("entries counts = %+v", c)
	}
	if c, _ := tally(t, s, core.IterSpamtraps); c != (counts{mail: 1}) {
		t.Fatalf("spamtrap counts = %+v", c)
	}
	if c, _ := tally(t, s, core.IterDomains); c != (counts{domain: 1}) {
		t.Fatalf("domain counts = %+v", c)
	}
	if c, _ := tally(t, s, core.IterSpamtraps|core.IterDomains); c != (counts{mail: 1, domain: 1}) {
		t.Fatalf("spamtrap+domain counts = %+v", c)
	}
}

func testDomainPart(t *testing.T, s core.Store) {
	mustPut(t, s, core.DomainKey("domain1.com"), core.Data{})
	mustPut(t, s, core.DomainKey("greyd@domain3.com"), core.Data{})
	cases := map[string]bool{
		"x@sub.domain1.com":  true,
		"r@domain1.com":      true,
		"greyd@domain3.com":  true,
		"other@domain3.com":  false,
		"x@domain1.com.evil": false,
		"trap@willbetrapped": false,
		"":                   false,
	}
	for addr, want := range cases {
		_, found := mustGet(t, s, core.DomainPartKey(addr))
		if found != want {
			t.Fatalf("DomainPart(%q) = %v want %v", addr, found, want)
		}
	}
	if _, found := mustGet(t, s, core.DomainPartKey("x@domain1.com")); !found {
		t.Fatal("domain part after delete setup")
	}
	if _, err := s.Del(core.DomainKey("domain1.com")); err != nil {
		t.Fatal(err)
	}
	if _, found := mustGet(t, s, core.DomainPartKey("x@domain1.com")); found {
		t.Fatal("deleted domain still matches")
	}
}

func testScan(t *testing.T, s core.Store) {
	const now, whiteExp = 1000, 500
	trapIP := "10.0.0.3"

	mustPut(t, s, core.IPKey("10.0.0.1"), core.Data{First: 1, Pass: 1, Expire: 2000, BCount: 0, PCount: 3})
	mustPut(t, s, core.IPKey("10.0.0.2"), core.Data{First: 1, Pass: 1, Expire: 900, BCount: 0, PCount: 3})
	mustPut(t, s, core.IPKey(trapIP), core.Data{First: 1, Pass: 2000, Expire: 2000, BCount: 1, PCount: core.PCountTrapped})
	mustPut(t, s, core.IPKey("10.0.0.4"), core.Data{First: 1, Pass: 500, Expire: 500, BCount: 1, PCount: core.PCountTrapped})
	mustPut(t, s, core.IPKey("2001::1"), core.Data{First: 1, Pass: 1, Expire: 2000, BCount: 0, PCount: 0})

	tA := core.Tuple{IP: "10.0.0.5", Helo: "h", From: "f@x.org", To: "t@y.org"}
	tB := core.Tuple{IP: "10.0.0.6", Helo: "h", From: "f@x.org", To: "t@y.org"}
	tC := core.Tuple{IP: trapIP, Helo: "h", From: "f@x.org", To: "t@y.org"}
	tD := core.Tuple{IP: "10.0.0.1", Helo: "h", From: "f@x.org", To: "t@y.org"}
	tE := core.Tuple{IP: "10.0.0.7", Helo: "h", From: "f@x.org", To: "t@y.org"}
	mustPut(t, s, core.TupleKey(tA), core.Data{First: 1, Pass: 900, Expire: 2000, BCount: 2, PCount: 0})
	mustPut(t, s, core.TupleKey(tB), core.Data{First: 1, Pass: 1500, Expire: 2000, BCount: 1, PCount: 0})
	mustPut(t, s, core.TupleKey(tC), core.Data{First: 1, Pass: 900, Expire: 2000, BCount: 1, PCount: 0})
	mustPut(t, s, core.TupleKey(tD), core.Data{First: 1, Pass: 900, Expire: 2000, BCount: 1, PCount: 0})
	mustPut(t, s, core.TupleKey(tE), core.Data{First: 1, Pass: 900, Expire: 950, BCount: 1, PCount: 0}) // expired grey
	mustPut(t, s, core.MailKey("trap@x.org"), core.Data{PCount: core.PCountSpamtrap})
	mustPut(t, s, core.DomainKey("d.com"), core.Data{PCount: core.PCountDomain})

	if err := s.Begin(); err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(now, whiteExp)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	sort.Strings(res.Whitelist)
	if want := []string{"10.0.0.1", "10.0.0.5"}; !equal(res.Whitelist, want) {
		t.Fatalf("Whitelist = %v want %v", res.Whitelist, want)
	}
	if want := []string{"2001::1"}; !equal(res.WhitelistV6, want) {
		t.Fatalf("WhitelistV6 = %v want %v", res.WhitelistV6, want)
	}
	if want := []string{trapIP}; !equal(res.Traplist, want) {
		t.Fatalf("Traplist = %v want %v", res.Traplist, want)
	}

	if _, found := mustGet(t, s, core.IPKey("10.0.0.2")); found {
		t.Fatal("expired white entry not deleted")
	}
	if _, found := mustGet(t, s, core.IPKey("10.0.0.4")); found {
		t.Fatal("expired trap entry not deleted")
	}
	if _, found := mustGet(t, s, core.TupleKey(tE)); found {
		t.Fatal("expired grey entry not deleted")
	}
	d, found := mustGet(t, s, core.IPKey("10.0.0.5"))
	if !found || d.Expire != now+whiteExp || d.BCount != 2 || d.PCount != 0 || d.First != 1 {
		t.Fatalf("whitelisted tuple A = %+v %v", d, found)
	}
	if _, found := mustGet(t, s, core.TupleKey(tA)); found {
		t.Fatal("whitelisted tuple A still present as tuple")
	}
	if _, found := mustGet(t, s, core.TupleKey(tB)); !found {
		t.Fatal("tuple B (pass in future) must remain")
	}
	if _, found := mustGet(t, s, core.TupleKey(tC)); !found {
		t.Fatal("tuple C (trapped address) must remain")
	}
	if _, found := mustGet(t, s, core.TupleKey(tD)); !found {
		t.Fatal("tuple D (already white address) must remain")
	}
	if d, found := mustGet(t, s, core.IPKey("10.0.0.1")); !found || d.PCount != 3 || d.Expire != 2000 {
		t.Fatalf("existing white entry modified: %+v %v", d, found)
	}
	if d, found := mustGet(t, s, core.IPKey(trapIP)); !found || d.PCount != core.PCountTrapped {
		t.Fatal("trap entry modified")
	}
	if _, found := mustGet(t, s, core.MailKey("trap@x.org")); !found {
		t.Fatal("spamtrap must survive scan")
	}
	if _, found := mustGet(t, s, core.DomainKey("d.com")); !found {
		t.Fatal("domain must survive scan")
	}
	if c, _ := tally(t, s, core.IterAll); c != (counts{ip: 4, tuple: 3, mail: 1, domain: 1}) {
		t.Fatalf("post-scan counts = %+v", c)
	}

	// A second scan is idempotent.
	res2, err := s.Scan(now, whiteExp)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(res2.Whitelist)
	if !equal(res2.Whitelist, res.Whitelist) || !equal(res2.Traplist, res.Traplist) {
		t.Fatalf("second scan differs: %+v", res2)
	}
}

func testTransactions(t *testing.T, s core.Store) {
	if err := s.Commit(); !errors.Is(err, core.ErrNotInTransaction) && err == nil {
		t.Fatal("Commit outside transaction must fail")
	}
	if err := s.Rollback(); err == nil {
		t.Fatal("Rollback outside transaction must fail")
	}
	if err := s.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := s.Begin(); err == nil {
		t.Fatal("nested Begin must fail")
	}
	mustPut(t, s, core.IPKey("7.7.7.7"), core.Data{First: 1})
	if _, found := mustGet(t, s, core.IPKey("7.7.7.7")); !found {
		t.Fatal("value invisible inside its own transaction")
	}
	if err := s.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, found := mustGet(t, s, core.IPKey("7.7.7.7")); found {
		t.Fatal("rolled back value still present")
	}

	if err := s.Begin(); err != nil {
		t.Fatal(err)
	}
	mustPut(t, s, core.IPKey("8.8.8.8"), core.Data{First: 2})
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, found := mustGet(t, s, core.IPKey("8.8.8.8")); !found {
		t.Fatal("committed value missing")
	}

	// Deletion rolls back too.
	if err := s.Begin(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Del(core.IPKey("8.8.8.8")); err != nil {
		t.Fatal(err)
	}
	if err := s.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, found := mustGet(t, s, core.IPKey("8.8.8.8")); !found {
		t.Fatal("rolled back delete lost the entry")
	}
}

func testIteratorMutation(t *testing.T, s core.Store) {
	for i, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		mustPut(t, s, core.IPKey(ip), core.Data{First: int64(i + 1), Expire: 100, BCount: 1})
	}
	if err := s.Begin(); err != nil {
		t.Fatal(err)
	}
	it, err := s.Iter(core.IterEntries)
	if err != nil {
		t.Fatal(err)
	}
	for {
		k, d, ok, err := it.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		switch k.Str {
		case "2.2.2.2":
			d.BCount = 99
			if err := it.ReplaceCurrent(d); err != nil {
				t.Fatalf("ReplaceCurrent: %v", err)
			}
		case "3.3.3.3":
			if err := it.DeleteCurrent(); err != nil {
				t.Fatalf("DeleteCurrent: %v", err)
			}
		}
	}
	if err := it.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if d, found := mustGet(t, s, core.IPKey("2.2.2.2")); !found || d.BCount != 99 || d.First != 2 {
		t.Fatalf("replaced entry = %+v %v", d, found)
	}
	if _, found := mustGet(t, s, core.IPKey("3.3.3.3")); found {
		t.Fatal("deleted entry still present")
	}
	if n := count(t, s, core.IterEntries); n != 2 {
		t.Fatalf("count = %d", n)
	}
}

func testReopen(t *testing.T, s core.Store) {
	if err := s.Open(core.OpenRW); err != nil {
		t.Fatalf("second Open: %v", err)
	}
	mustPut(t, s, core.IPKey("1.1.1.1"), core.Data{First: 1})
	if _, found := mustGet(t, s, core.IPKey("1.1.1.1")); !found {
		t.Fatal("store unusable after reopen")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
