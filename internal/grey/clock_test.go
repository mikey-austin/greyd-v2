package grey

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/db/memory"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
)

// Clock boundary tests. All arithmetic in the engine and the scan is on
// Unix seconds, and the comparisons mirror the C implementation:
//
//   - a retried tuple is marked passable only when first + pass_time < now
//     (grey.c process_grey, strict);
//   - the scan removes entries with expire <= now (bdb.c Mod_scan_db);
//   - the scan whitelists tuples with pass <= now.
//
// These tests pin the exact second on each side of those boundaries.

// The rig's expiries are short and distinct so a mistake in one cannot be
// masked by another.
const (
	clockPassTime  = 300
	clockGreyExp   = 3600
	clockWhiteExp  = 7200
	clockTrapExp   = 900
	clockTrapAddr  = "trap@example.org"
	clockRigConfig = "section grey { pass_time = 300, grey_expiry = 3600, white_expiry = 7200, trap_expiry = 900 }"
)

var clockT0 = time.Unix(1_700_000_000, 0).UTC()

var clockTuple = core.Tuple{IP: "10.1.2.3", Helo: "mx.example.net", From: "a@example.net", To: "b@example.org"}

type clockRig struct {
	t       *testing.T
	now     time.Time
	store   core.Store
	g       *Greylister
	trapOut bytes.Buffer
	fwOut   bytes.Buffer
}

func newClockRig(t *testing.T, start time.Time, conf string) *clockRig {
	t.Helper()
	r := &clockRig{t: t, now: start, store: memory.New()}
	if err := core.Put(ctx, r.store, core.MailKey(clockTrapAddr), core.Data{}); err != nil {
		t.Fatal(err)
	}
	g, err := New(Options{
		Settings: loadSettings(t, conf),
		Store:    r.store,
		TrapOut:  &r.trapOut,
		FwOut:    &r.fwOut,
		Startup:  start.Add(-time.Hour),
		Now:      func() time.Time { return r.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.g = g
	return r
}

// at moves the engine's clock.
func (r *clockRig) at(t time.Time) *clockRig { r.now = t; return r }

// grey delivers a tuple as the SMTP handler would.
func (r *clockRig) grey(gt core.Tuple) {
	r.t.Helper()
	if err := r.g.processGrey(ctx, gt, true, ""); err != nil {
		r.t.Fatal(err)
	}
}

// trap delivers a tuple addressed to the spamtrap, greytrapping its IP.
func (r *clockRig) trap(ip string) {
	r.t.Helper()
	gt := clockTuple
	gt.IP, gt.To = ip, clockTrapAddr
	r.grey(gt)
}

// white applies an explicit whitelist entry (greydb -a / sync).
func (r *clockRig) white(ip string, expire int64) {
	r.t.Helper()
	if err := r.g.processNonGrey(ctx, false, ip, "test", fmt.Sprint(expire), true, false); err != nil {
		r.t.Fatal(err)
	}
}

type scanOutput struct {
	whitelist []string // IPv4 replace request, nil when no frame was sent
	traplist  []string // traplist blacklist, nil when no frame was sent
}

// scan runs one scan at the current clock and returns what reached the
// firewall and trap pipes for that scan only.
func (r *clockRig) scan() scanOutput {
	r.t.Helper()
	r.fwOut.Reset()
	r.trapOut.Reset()
	if err := r.g.ScanOnce(ctx); err != nil {
		r.t.Fatal(err)
	}
	var out scanOutput
	for m := range clockFrames(r.t, &r.fwOut) {
		if rr, ok := m.(*ipc.ReplaceRequest); ok && rr.AF == int(core.IPv4) {
			out.whitelist = append([]string{}, rr.IPs...)
		}
	}
	for m := range clockFrames(r.t, &r.trapOut) {
		if bl, ok := m.(*ipc.BlacklistMessage); ok {
			// WriteBlacklist appends the host mask to bare addresses.
			out.traplist = []string{}
			for _, a := range bl.IPs {
				out.traplist = append(out.traplist, strings.TrimSuffix(a, "/32"))
			}
		}
	}
	return out
}

func clockFrames(t *testing.T, buf *bytes.Buffer) func(yield func(ipc.Message) bool) {
	return func(yield func(ipc.Message) bool) {
		rd := ipc.NewReader(bytes.NewReader(buf.Bytes()))
		for {
			m, err := rd.Next()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				t.Fatalf("pipe frame: %v", err)
			}
			if !yield(m) {
				return
			}
		}
	}
}

func (r *clockRig) has(k core.Key) bool {
	r.t.Helper()
	_, found := mustGet(r.t, r.store, k)
	return found
}

func (r *clockRig) data(k core.Key) core.Data {
	r.t.Helper()
	d, found := mustGet(r.t, r.store, k)
	if !found {
		r.t.Fatalf("entry %+v missing", k)
	}
	return d
}

// mustHave and mustNotHave assert presence with a message naming the
// boundary that was crossed.
func (r *clockRig) mustHave(k core.Key, why string) {
	r.t.Helper()
	if !r.has(k) {
		r.t.Fatalf("%s: entry %v/%q%v should exist at %d", why, k.Type, k.Str, k.Tuple, r.now.Unix())
	}
}

func (r *clockRig) mustNotHave(k core.Key, why string) {
	r.t.Helper()
	if r.has(k) {
		r.t.Fatalf("%s: entry %v/%q%v should be gone at %d", why, k.Type, k.Str, k.Tuple, r.now.Unix())
	}
}

func sec(n int64) time.Duration { return time.Duration(n) * time.Second }

// TestClockPassTimeBoundary: a retry exactly pass_time seconds after the
// first attempt is still too early (strict comparison, as in C); one
// second later it is whitelisted by the next scan.
func TestClockPassTimeBoundary(t *testing.T) {
	cases := []struct {
		name   string
		offset int64 // retry at first + pass_time + offset
		white  bool
	}{
		{"one second before pass_time", -1, false},
		{"exactly pass_time", 0, false},
		{"one second after pass_time", 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newClockRig(t, clockT0, clockRigConfig)
			r.grey(clockTuple)
			tk := core.TupleKey(clockTuple)
			d := r.data(tk)
			if d.First != clockT0.Unix() || d.Pass != clockT0.Unix()+clockGreyExp || d.Expire != d.Pass || d.BCount != 1 {
				t.Fatalf("new tuple %+v", d)
			}

			retry := clockT0.Add(sec(clockPassTime + tc.offset))
			r.at(retry).grey(clockTuple)
			d = r.data(tk)
			if d.BCount != 2 {
				t.Fatalf("retry must count a block: %+v", d)
			}
			if got := d.Pass == retry.Unix(); got != tc.white {
				t.Fatalf("pass marked=%v want %v: %+v", got, tc.white, d)
			}
			if !tc.white && d.Pass != clockT0.Unix()+clockGreyExp {
				t.Fatalf("early retry must leave pass at the expiry: %+v", d)
			}

			out := r.scan()
			ipk := core.IPKey(clockTuple.IP)
			if tc.white {
				r.mustNotHave(tk, "whitelisted tuple must be re-keyed")
				r.mustHave(ipk, "whitelisted address")
				w := r.data(ipk)
				if w.Expire != retry.Unix()+clockWhiteExp || w.First != clockT0.Unix() || w.Pass != retry.Unix() || w.PCount != 0 {
					t.Fatalf("white entry %+v", w)
				}
				if !slices.Contains(out.whitelist, clockTuple.IP) {
					t.Fatalf("firewall whitelist %v must contain %s", out.whitelist, clockTuple.IP)
				}
			} else {
				r.mustHave(tk, "tuple retried too early stays grey")
				r.mustNotHave(ipk, "tuple retried too early is not whitelisted")
				if out.whitelist != nil {
					t.Fatalf("no whitelist should be pushed, got %v", out.whitelist)
				}
			}
			if out.traplist != nil {
				t.Fatalf("no traplist expected, got %v", out.traplist)
			}
		})
	}
}

// TestClockGreyExpiryBoundary: a tuple that is never retried is deleted by
// the first scan at or after first + grey_expiry, and must never be
// whitelisted at that moment even though pass == expire.
func TestClockGreyExpiryBoundary(t *testing.T) {
	cases := []struct {
		name    string
		offset  int64
		present bool
	}{
		{"one second before grey_expiry", -1, true},
		{"exactly grey_expiry", 0, false},
		{"one second after grey_expiry", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newClockRig(t, clockT0, clockRigConfig)
			r.grey(clockTuple)
			tk := core.TupleKey(clockTuple)

			out := r.at(clockT0.Add(sec(clockGreyExp + tc.offset))).scan()
			if tc.present {
				r.mustHave(tk, "grey entry before grey_expiry")
			} else {
				r.mustNotHave(tk, "grey entry at grey_expiry")
			}
			// pass == expire on a never-retried tuple: expiry wins over
			// whitelisting on the boundary second.
			r.mustNotHave(core.IPKey(clockTuple.IP), "never-retried tuple must not be whitelisted")
			if out.whitelist != nil {
				t.Fatalf("no whitelist should be pushed, got %v", out.whitelist)
			}
		})
	}
}

// TestClockWhiteExpiryBoundary covers both ways a white entry is created:
// by the scan re-keying a retried tuple (expire = scan time + white_expiry)
// and by an explicit whitelist message carrying its own expiry.
func TestClockWhiteExpiryBoundary(t *testing.T) {
	t.Run("from retried tuple", func(t *testing.T) {
		for _, offset := range []int64{-1, 0, 1} {
			r := newClockRig(t, clockT0, clockRigConfig)
			r.grey(clockTuple)
			retry := clockT0.Add(sec(clockPassTime + 1))
			r.at(retry).grey(clockTuple)
			out := r.scan()
			ipk := core.IPKey(clockTuple.IP)
			if !slices.Contains(out.whitelist, clockTuple.IP) {
				t.Fatalf("setup: expected whitelist push, got %v", out.whitelist)
			}
			whiteUntil := retry.Unix() + clockWhiteExp
			if d := r.data(ipk); d.Expire != whiteUntil {
				t.Fatalf("white expiry %d want %d", d.Expire, whiteUntil)
			}

			out = r.at(time.Unix(whiteUntil+offset, 0)).scan()
			present := offset < 0
			if present {
				r.mustHave(ipk, fmt.Sprintf("white entry at white_expiry%+d", offset))
				if !slices.Contains(out.whitelist, clockTuple.IP) {
					t.Fatalf("offset %+d: firewall whitelist %v must still contain %s", offset, out.whitelist, clockTuple.IP)
				}
			} else {
				r.mustNotHave(ipk, fmt.Sprintf("white entry at white_expiry%+d", offset))
				if slices.Contains(out.whitelist, clockTuple.IP) {
					t.Fatalf("offset %+d: expired address still pushed: %v", offset, out.whitelist)
				}
			}
		}
	})

	t.Run("from explicit entry", func(t *testing.T) {
		const ip = "10.9.9.9"
		expire := clockT0.Unix() + 500
		for _, offset := range []int64{-1, 0, 1} {
			r := newClockRig(t, clockT0, clockRigConfig)
			r.white(ip, expire)
			out := r.at(time.Unix(expire+offset, 0)).scan()
			ipk := core.IPKey(ip)
			if offset < 0 {
				r.mustHave(ipk, "explicit white entry before its expiry")
				if !slices.Contains(out.whitelist, ip) {
					t.Fatalf("offset %+d: whitelist %v must contain %s", offset, out.whitelist, ip)
				}
			} else {
				r.mustNotHave(ipk, "explicit white entry at its expiry")
				if slices.Contains(out.whitelist, ip) {
					t.Fatalf("offset %+d: expired address still pushed: %v", offset, out.whitelist)
				}
			}
		}
	})
}

// TestClockTrapExpiryBoundary: a greytrapped address is on the traplist
// until trap_expiry has elapsed and is removed on the boundary second.
func TestClockTrapExpiryBoundary(t *testing.T) {
	const ip = "10.7.7.7"
	for _, offset := range []int64{-1, 0, 1} {
		r := newClockRig(t, clockT0, clockRigConfig)
		r.trap(ip)
		ipk := core.IPKey(ip)
		d := r.data(ipk)
		if d.PCount != core.PCountTrapped || d.Expire != clockT0.Unix()+clockTrapExp || d.Pass != d.Expire {
			t.Fatalf("trap entry %+v", d)
		}

		out := r.at(clockT0.Add(sec(clockTrapExp + offset))).scan()
		if offset < 0 {
			r.mustHave(ipk, "trapped entry before trap_expiry")
			if !slices.Contains(out.traplist, ip) {
				t.Fatalf("offset %+d: traplist %v must contain %s", offset, out.traplist, ip)
			}
		} else {
			r.mustNotHave(ipk, "trapped entry at trap_expiry")
			if out.traplist != nil {
				t.Fatalf("offset %+d: expired trap still on traplist %v", offset, out.traplist)
			}
		}
		// A trapped address is never whitelisted, whatever the clock says.
		if out.whitelist != nil {
			t.Fatalf("offset %+d: trapped address pushed to the whitelist: %v", offset, out.whitelist)
		}
	}
}

// TestClockStepsBackward: an NTP correction of an hour between the first
// attempt and the retry must neither whitelist the tuple early nor delete
// anything; once the clock has caught up the normal pass_time applies.
func TestClockStepsBackward(t *testing.T) {
	r := newClockRig(t, clockT0, clockRigConfig)
	// An old white entry (pass time two hours ago) and a fresh one.
	r.at(clockT0.Add(-2*time.Hour)).white("10.9.9.8", clockT0.Unix()+clockWhiteExp)
	r.at(clockT0)
	r.grey(clockTuple)
	r.trap("10.7.7.7")
	r.white("10.9.9.9", clockT0.Unix()+clockWhiteExp)
	tk := core.TupleKey(clockTuple)

	// The clock jumps back an hour; a retry that is pass_time+1 seconds
	// later by the (wrong) clock is far too early in real terms as
	// measured against first, and must not pass.
	back := clockT0.Add(-time.Hour)
	retry := back.Add(sec(clockPassTime + 1))
	r.at(retry).grey(clockTuple)
	d := r.data(tk)
	if d.BCount != 2 || d.Pass != clockT0.Unix()+clockGreyExp {
		t.Fatalf("retry with the clock behind must not mark the tuple passable: %+v", d)
	}
	out := r.scan()
	r.mustHave(tk, "grey entry with the clock behind")
	r.mustHave(core.IPKey("10.7.7.7"), "trapped entry with the clock behind")
	r.mustHave(core.IPKey("10.9.9.9"), "white entry with the clock behind")
	r.mustHave(core.IPKey("10.9.9.8"), "old white entry with the clock behind")
	r.mustNotHave(core.IPKey(clockTuple.IP), "tuple with the clock behind")
	// Nothing is deleted, but the whitelist pushed to the firewall only
	// carries entries whose pass time is not in the (stepped back) clock's
	// future: the fresh white entry drops out of the firewall set until
	// the clock passes T0 again. This mirrors bdb.c Mod_scan_db
	// (gd.pcount >= 0 && gd.pass <= now) and is the documented cost of a
	// backwards step, not an expiry bug.
	if !slices.Equal(out.whitelist, []string{"10.9.9.8"}) || !slices.Equal(out.traplist, []string{"10.7.7.7"}) {
		t.Fatalf("scan with the clock behind: whitelist %v traplist %v", out.whitelist, out.traplist)
	}
	// Once the clock is back at T0 both white entries are pushed again.
	out = r.at(clockT0).scan()
	slices.Sort(out.whitelist)
	if !slices.Equal(out.whitelist, []string{"10.9.9.8", "10.9.9.9"}) {
		t.Fatalf("scan after the clock recovered: whitelist %v", out.whitelist)
	}

	// Even a full hour of retries by the wrong clock does not pass while
	// first + pass_time is still in the future of that clock.
	r.at(clockT0.Add(sec(clockPassTime))).grey(clockTuple)
	if d := r.data(tk); d.Pass != clockT0.Unix()+clockGreyExp {
		t.Fatalf("retry exactly at pass_time after the clock recovered must not pass: %+v", d)
	}
	// One second after the corrected clock reaches pass_time it passes.
	late := clockT0.Add(sec(clockPassTime + 1))
	r.at(late).grey(clockTuple)
	out = r.scan()
	r.mustNotHave(tk, "tuple retried after pass_time on the corrected clock")
	r.mustHave(core.IPKey(clockTuple.IP), "whitelisted after the clock recovered")
	if !slices.Contains(out.whitelist, clockTuple.IP) {
		t.Fatalf("whitelist %v", out.whitelist)
	}
	// Its white expiry is anchored to the (recovered) scan time.
	if d := r.data(core.IPKey(clockTuple.IP)); d.Expire != late.Unix()+clockWhiteExp {
		t.Fatalf("white expiry %d want %d", d.Expire, late.Unix()+clockWhiteExp)
	}
	// And the tuple's expiry was never extended by the backwards step:
	// a never-retried second tuple made at T0 still dies at T0+grey_exp.
	other := clockTuple
	other.From = "other@example.net"
	r.at(clockT0).grey(other)
	r.at(back).scan()
	r.mustHave(core.TupleKey(other), "second tuple with the clock behind")
	r.at(clockT0.Add(sec(clockGreyExp))).scan()
	r.mustNotHave(core.TupleKey(other), "second tuple at grey_expiry")
}

// TestClockStepsForwardDay: a clock jump of a day expires everything whose
// expiry is a day or less, including a trap whose trap_expiry is exactly
// one day, and leaves the long-lived white entry.
func TestClockStepsForwardDay(t *testing.T) {
	const day = 24 * 60 * 60
	conf := fmt.Sprintf("section grey { pass_time = %d, grey_expiry = %d, white_expiry = %d, trap_expiry = %d }",
		clockPassTime, clockGreyExp, 36*day, day)
	r := newClockRig(t, clockT0, conf)
	r.grey(clockTuple)
	r.trap("10.7.7.7")
	// A retried tuple that the next scan will whitelist.
	white := clockTuple
	white.IP = "10.8.8.8"
	r.grey(white)
	r.at(clockT0.Add(sec(clockPassTime + 1))).grey(white)
	out := r.scan()
	if !slices.Equal(out.whitelist, []string{"10.8.8.8"}) || !slices.Equal(out.traplist, []string{"10.7.7.7"}) {
		t.Fatalf("setup scan: whitelist %v traplist %v", out.whitelist, out.traplist)
	}

	// One second short of the day the trap is still there.
	out = r.at(clockT0.Add(sec(day - 1))).scan()
	r.mustHave(core.IPKey("10.7.7.7"), "trap one second before a day")
	r.mustNotHave(core.TupleKey(clockTuple), "grey tuple after a day minus one second")
	if !slices.Equal(out.traplist, []string{"10.7.7.7"}) {
		t.Fatalf("traplist %v", out.traplist)
	}

	// The clock jumps to exactly a day after start.
	out = r.at(clockT0.Add(sec(day))).scan()
	r.mustNotHave(core.IPKey("10.7.7.7"), "trap at exactly a day")
	r.mustNotHave(core.TupleKey(clockTuple), "grey tuple after a day")
	r.mustHave(core.IPKey("10.8.8.8"), "white entry after a day")
	if out.traplist != nil || !slices.Equal(out.whitelist, []string{"10.8.8.8"}) {
		t.Fatalf("after a day: whitelist %v traplist %v", out.whitelist, out.traplist)
	}

	// A tuple first seen just before the jump is unaffected by it: it is
	// neither whitelisted (never retried) nor expired before its time.
	fresh := clockTuple
	fresh.IP = "10.6.6.6"
	before := clockT0.Add(sec(day - 10))
	r.at(before).grey(fresh)
	out = r.at(clockT0.Add(sec(day))).scan()
	r.mustHave(core.TupleKey(fresh), "tuple made ten seconds before the jump")
	r.mustNotHave(core.IPKey("10.6.6.6"), "tuple made before the jump is not whitelisted")
	if slices.Contains(out.whitelist, "10.6.6.6") {
		t.Fatalf("whitelist %v", out.whitelist)
	}
}

// TestClockDST: with the process time zone set to one that observes DST,
// times constructed on either side of the spring-forward transition give
// the same results as the plain UTC run with the same Unix seconds. The
// wall clock skips an hour at 02:00 CET on 2026-03-29; nothing in the
// engine may notice.
func TestClockDST(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Skipf("time zone database unavailable: %v", err)
	}
	// Sanity check the zone data: 01:59:59 CET and 03:00:00 CEST are one
	// second apart.
	if d := time.Date(2026, 3, 29, 3, 0, 0, 0, loc).Sub(time.Date(2026, 3, 29, 1, 59, 59, 0, loc)); d != time.Second {
		t.Fatalf("expected the 2026 spring transition at 02:00, got a gap of %v", d)
	}
	prev := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = prev })

	// 01:45:00 CET is 15 minutes before the gap; pass_time (5 minutes)
	// after it is 01:50:00 CET, and grey_expiry (an hour) after it reads
	// 03:45:00 CEST on the wall clock.
	start := time.Date(2026, 3, 29, 1, 45, 0, 0, loc)
	if got := time.Date(2026, 3, 29, 3, 45, 0, 0, loc); got.Sub(start) != sec(clockGreyExp) {
		t.Fatalf("03:45 CEST should be one real hour after 01:45 CET, got %v", got.Sub(start))
	}

	type step struct {
		name  string
		at    time.Time
		grey  bool // deliver the tuple; otherwise scan
		other core.Tuple
	}
	tupleAcross := clockTuple
	tupleAcross.IP = "10.5.5.5"
	steps := []step{
		{"first attempt before the gap", start, true, core.Tuple{}},
		{"retry exactly pass_time later", time.Date(2026, 3, 29, 1, 50, 0, 0, loc), true, core.Tuple{}},
		{"scan before the gap", time.Date(2026, 3, 29, 1, 59, 59, 0, loc), false, core.Tuple{}},
		{"second tuple one second before the gap", time.Date(2026, 3, 29, 1, 59, 59, 0, loc), true, tupleAcross},
		{"retry across the gap, fifteen real minutes later", time.Date(2026, 3, 29, 3, 0, 0, 0, loc), true, core.Tuple{}},
		{"second tuple retried one second after the gap", time.Date(2026, 3, 29, 3, 0, 0, 0, loc), true, tupleAcross},
		{"scan after the gap", time.Date(2026, 3, 29, 3, 5, 0, 0, loc), false, core.Tuple{}},
		{"scan one second before grey_expiry of the second tuple", time.Date(2026, 3, 29, 3, 59, 58, 0, loc), false, core.Tuple{}},
		{"scan at grey_expiry of the second tuple", time.Date(2026, 3, 29, 3, 59, 59, 0, loc), false, core.Tuple{}},
		{"scan at white_expiry", time.Date(2026, 3, 29, 3, 5, 0, 0, loc).Add(sec(clockWhiteExp)), false, core.Tuple{}},
	}

	type snapshot struct {
		out   scanOutput
		tuple core.Data
		white core.Data
		found [2]bool
	}
	run := func(t *testing.T, r *clockRig) []snapshot {
		t.Helper()
		var snaps []snapshot
		for _, s := range steps {
			r.at(s.at)
			var snap snapshot
			switch {
			case s.grey && s.other != (core.Tuple{}):
				r.grey(s.other)
			case s.grey:
				r.grey(clockTuple)
			default:
				snap.out = r.scan()
			}
			snap.tuple, snap.found[0] = mustGet(t, r.store, core.TupleKey(clockTuple))
			snap.white, snap.found[1] = mustGet(t, r.store, core.IPKey(clockTuple.IP))
			snaps = append(snaps, snap)
		}
		return snaps
	}

	// The reference run uses the same instants expressed in UTC.
	utc := newClockRig(t, start.UTC(), clockRigConfig)
	for i := range steps {
		steps[i].at = steps[i].at.UTC()
	}
	want := run(t, utc)
	for i := range steps {
		steps[i].at = steps[i].at.In(loc)
	}
	got := run(t, newClockRig(t, start, clockRigConfig))

	for i, s := range steps {
		if got[i].found != want[i].found || got[i].tuple != want[i].tuple || got[i].white != want[i].white ||
			!slices.Equal(got[i].out.whitelist, want[i].out.whitelist) || !slices.Equal(got[i].out.traplist, want[i].out.traplist) {
			t.Fatalf("step %q: local %+v\nutc   %+v", s.name, got[i], want[i])
		}
	}

	// And the outcome itself is the one the boundaries dictate.
	//  - retry exactly pass_time later did not pass;
	if got[1].tuple.Pass != start.Unix()+clockGreyExp {
		t.Fatalf("retry exactly at pass_time passed: %+v", got[1].tuple)
	}
	//  - the scan before the gap pushed nothing;
	if got[2].out.whitelist != nil {
		t.Fatalf("scan before the gap pushed %v", got[2].out.whitelist)
	}
	//  - the retry across the gap passed and the scan after it whitelisted
	//    the address, with the white expiry anchored to that scan;
	if !got[6].found[1] || got[6].found[0] || !slices.Contains(got[6].out.whitelist, clockTuple.IP) {
		t.Fatalf("scan after the gap: %+v", got[6])
	}
	if got[6].white.Expire != steps[6].at.Unix()+clockWhiteExp {
		t.Fatalf("white expiry %d want %d", got[6].white.Expire, steps[6].at.Unix()+clockWhiteExp)
	}
	//  - the second tuple, retried one real second after creation, sits
	//    on both sides of the gap but is one second old, not an hour;
	local := newClockRig(t, start, clockRigConfig)
	local.at(steps[3].at).grey(tupleAcross)
	local.at(steps[5].at).grey(tupleAcross)
	if d := local.data(core.TupleKey(tupleAcross)); d.BCount != 2 || d.Pass != steps[3].at.Unix()+clockGreyExp {
		t.Fatalf("tuple retried across the gap after one second must not pass: %+v", d)
	}
	local.at(steps[7].at).scan()
	local.mustHave(core.TupleKey(tupleAcross), "second tuple one second before its grey_expiry")
	local.at(steps[8].at).scan()
	local.mustNotHave(core.TupleKey(tupleAcross), "second tuple at its grey_expiry")
	//  - and the white entry goes exactly when white_expiry elapses.
	if got[9].found[1] || slices.Contains(got[9].out.whitelist, clockTuple.IP) {
		t.Fatalf("white entry still present at white_expiry: %+v", got[9])
	}
}
