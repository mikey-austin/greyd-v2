package grey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/db/memory"
	"github.com/mikey-austin/greyd-v2/internal/config/parse"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

var ctx = context.Background()

const testConf = `drop_privs = 0
section grey {
  db_permitted_domains = 1,
  permitted_domains = "testdata/permitted_domains.txt",
  traplist_name    = "test traplist",
  traplist_message = "you have been trapped",
  grey_expiry      = 3600,
  low_prio_mx      = "192.179.21.3"
}
section firewall {
  driver = "dummy"
}
section database {
  driver = "memory",
  name   = "grey-test"
}`

func loadSettings(t *testing.T, src string) *settings.Settings {
	t.Helper()
	cfg, err := parse.String(src)
	if err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type tally struct {
	entries, white, grey, trapped, spamtrap            int
	whitePassed, whiteBlocked, greyPassed, greyBlocked int
}

func tallyStore(t *testing.T, s core.Store) tally {
	t.Helper()
	var ta tally
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
			ta.entries++
			switch k.Type {
			case core.KeyIP:
				if d.PCount == core.PCountTrapped {
					ta.trapped++
				} else {
					ta.white++
					ta.whitePassed += d.PCount
					ta.whiteBlocked += d.BCount
				}
			case core.KeyTuple:
				ta.grey++
				ta.greyPassed += d.PCount
				ta.greyBlocked += d.BCount
			case core.KeyMail:
				ta.spamtrap++
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return ta
}

func writeGrey(w io.Writer, dst, ip, helo, from, to string) {
	_ = ipc.WriteGrey(w, dst, ip, helo, from, to)
}

func writeAddr(w io.Writer, typ int, source, ip string, expires int64) {
	fmt.Fprintf(w, "type = %d\nip = \"%s\"\nsource = \"%s\"\nexpires = \"%d\"\n%%%%\n", typ, ip, source, expires)
}

func newTestGreylister(t *testing.T, store core.Store, now time.Time, trapOut, fwOut io.Writer) *Greylister {
	t.Helper()
	g, err := New(Options{
		Settings: loadSettings(t, testConf),
		Store:    store,
		TrapOut:  trapOut,
		FwOut:    fwOut,
		Startup:  now.Add(-120 * time.Second),
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func mustGet(t *testing.T, s core.Store, k core.Key) (core.Data, bool) {
	t.Helper()
	d, found, err := core.Get(ctx, s, k)
	if err != nil {
		t.Fatal(err)
	}
	return d, found
}

func TestGreylisterSetup(t *testing.T) {
	g := newTestGreylister(t, memory.New(), time.Now(), nil, nil)
	c := g.Config()
	if c.TraplistName != "test traplist" || c.TraplistMessage != "you have been trapped" {
		t.Fatalf("names %q %q", c.TraplistName, c.TraplistMessage)
	}
	if c.LowPrioMX != "192.179.21.3" {
		t.Fatalf("low prio mx %q", c.LowPrioMX)
	}
	if !reflect.DeepEqual(g.Domains, []string{"domain4.com", "domain2.com"}) {
		t.Fatalf("domains %v", g.Domains)
	}
	if c.GreyExpiry != 3600 || c.WhiteExpiry != WhiteExp || c.TrapExpiry != TrapExp || c.PassTime != PassTime {
		t.Fatal("expiries")
	}
	if c.WhitelistName != WhiteName || c.WhitelistNameIPv6 != WhiteNameV6 {
		t.Fatal("whitelist names")
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("missing settings must error")
	}
}

func TestLowPrioMXFallbackToDefaultSection(t *testing.T) {
	s := loadSettings(t, "low_prio_mx = \"1.1.1.1\"\n")
	g, err := New(Options{Settings: s, Store: memory.New()})
	if err != nil || g.Config().LowPrioMX != "1.1.1.1" {
		t.Fatalf("fallback %q %v", g.Config().LowPrioMX, err)
	}
}

func TestLoadDomains(t *testing.T) {
	d, err := LoadDomains("testdata/permitted_domains.txt", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, []string{"domain4.com", "domain2.com"}) {
		t.Fatalf("domains %v", d)
	}
	if _, err := LoadDomains("testdata/missing", 0); err == nil {
		t.Fatal("missing file must error")
	}
	d, err = LoadDomains("testdata/permitted_domains.txt", 1)
	if !errors.Is(err, ErrTooManyDomains) || len(d) != 1 {
		t.Fatalf("cap: %v %v", d, err)
	}
	if !domainMatches("@greyd.org", "beardedclams@greyd.org") || !domainMatches("obtuse.com", "stacy@snouts.obtuse.com") ||
		domainMatches("@greyd.org", "peter@bugs.greyd.org") || !domainMatches("Domain.COM", "x@domain.com") {
		t.Fatal("domainMatches")
	}
	// Over-limit files are warned about and leave Domains empty.
	dir := t.TempDir()
	big := filepath.Join(dir, "d.txt")
	_ = os.WriteFile(big, []byte("a.com\nb.com\nc.com\n"), 0o644)
	s := loadSettings(t, fmt.Sprintf("section grey { permitted_domains = %q, max_domains = 2 }", big))
	g, _ := New(Options{Settings: s, Store: memory.New()})
	if len(g.Domains) != 0 {
		t.Fatalf("domains over the cap must not be partially loaded: %v", g.Domains)
	}
}

// TestReaderScenario ports test_grey.c.
func TestReaderScenario(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := memory.New()
	for _, k := range []core.Key{core.MailKey("trap@domain3.com"), core.DomainKey("greyd@domain3.com"), core.DomainKey("domain1.com")} {
		if err := core.Put(ctx, store, k, core.Data{}); err != nil {
			t.Fatal(err)
		}
	}

	var trapOut, fwOut bytes.Buffer
	g := newTestGreylister(t, store, now, &trapOut, &fwOut)

	var in bytes.Buffer
	exp := now.Unix() + 3600
	for range 2 {
		writeGrey(&in, "2.3.4.5", "1.2.3.4", "jackiemclean.net", "m@jackiemclean.net", "r@domain1.com")
		writeGrey(&in, "2.3.1.5", "1.2.4.4", "jackiemclean.net", "m@jackiemclean.net", "r@domain1.com")
		writeGrey(&in, "2.3.2.5", "1.2.2.4", "jackiemclean.net", "m@jackiemclean.net", "r@domain1.com")
	}
	for range 2 {
		writeAddr(&in, ipc.MsgWhite, "2.3.4.5", "4.3.2.1", exp)
		writeAddr(&in, ipc.MsgWhite, "2.3.4.6", "4.3.2.2", exp)
		writeAddr(&in, ipc.MsgWhite, "2.3.4.7", "4.3.2.3", exp)
	}
	for range 2 {
		writeAddr(&in, ipc.MsgTrap, "3.2.4.5", "3.4.2.1", exp)
		writeAddr(&in, ipc.MsgTrap, "3.2.4.6", "3.4.2.2", exp)
		writeAddr(&in, ipc.MsgTrap, "3.2.4.7", "3.4.3.2", exp)
	}
	writeAddr(&in, ipc.MsgWhite, "8.8.8.3", "7.7.6.5", now.Unix()-3600)
	writeAddr(&in, ipc.MsgTrap, "8.8.8.5", "7.7.6.6", now.Unix()-120)
	writeGrey(&in, "2.3.2.5", "1.2.2.4", "jackiemclean.net", "m@jackiemclean.net", "trap@domain3.com")
	writeGrey(&in, "2.3.2.5", "1.2.2.4", "jackiemclean.net", "m@jackiemclean.net", "trap@willbetrapped.com")
	writeAddr(&in, ipc.MsgWhite, "2.3.4.7", "1.2.3.4", exp)
	writeGrey(&in, "192.179.21.3", "1.2.2.34", "jackiemclean.net", "m@jackiemclean.net", "notrap@domain4.com")
	// A malformed frame is skipped, not fatal.
	in.WriteString("==\n%%\n")
	// An incomplete frame is skipped too.
	in.WriteString("type = 1\nip = \"9.9.9.9\"\n%%\n")

	if err := g.RunReader(ctx, &in); err != nil {
		t.Fatalf("RunReader: %v", err)
	}

	got := tallyStore(t, store)
	want := tally{entries: 17, white: 5, grey: 3, trapped: 6, spamtrap: 1, whitePassed: 3, whiteBlocked: 0, greyPassed: 0, greyBlocked: 6}
	if got != want {
		t.Fatalf("after reader: %+v\nwant %+v", got, want)
	}
	if d, _, _ := core.Get(ctx, store, core.IPKey("1.2.2.34")); d.PCount != core.PCountTrapped {
		t.Fatal("low priority MX hit should be trapped")
	}

	// Simulate conditions for the scan.
	tk := core.TupleKey(core.Tuple{IP: "1.2.2.4", Helo: "jackiemclean.net", From: "m@jackiemclean.net", To: "r@domain1.com"})
	d, found := mustGet(t, store, tk)
	if !found {
		t.Fatal("tuple 1.2.2.4 missing")
	}
	d.Expire = now.Unix() - 120
	_ = core.Put(ctx, store, tk, d)
	tk.Tuple.IP = "1.2.4.4"
	d, found = mustGet(t, store, tk)
	if !found {
		t.Fatal("tuple 1.2.4.4 missing")
	}
	d.Pass = now.Unix() - 60
	_ = core.Put(ctx, store, tk, d)

	if err := g.ScanOnce(ctx); err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}

	m, err := ipc.NewReader(&fwOut).Next()
	if err != nil {
		t.Fatalf("whitelist message: %v", err)
	}
	rr, ok := m.(*ipc.ReplaceRequest)
	if !ok || rr.Set != WhiteName || rr.AF != 4 {
		t.Fatalf("whitelist frame %+v", m)
	}
	wl := append([]string(nil), rr.IPs...)
	sort.Strings(wl)
	if !reflect.DeepEqual(wl, []string{"1.2.3.4", "1.2.4.4", "4.3.2.1", "4.3.2.2", "4.3.2.3"}) {
		t.Fatalf("whitelist ips %v", wl)
	}

	m, err = ipc.NewReader(&trapOut).Next()
	if err != nil {
		t.Fatalf("traplist message: %v", err)
	}
	bl, ok := m.(*ipc.BlacklistMessage)
	if !ok || bl.Name != "test traplist" || bl.Message != "you have been trapped" || len(bl.IPs) != 5 {
		t.Fatalf("traplist frame %+v", m)
	}

	got = tallyStore(t, store)
	want = tally{entries: 14, white: 5, grey: 1, trapped: 5, spamtrap: 1, whitePassed: 3, whiteBlocked: 2, greyPassed: 0, greyBlocked: 2}
	if got != want {
		t.Fatalf("after scan: %+v\nwant %+v", got, want)
	}
}

func TestPassTimeAndSync(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := memory.New()
	rec := &recSyncer{}
	g, err := New(Options{Settings: loadSettings(t, "section grey { pass_time = 100 }"), Store: store, Syncer: rec, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	gt := core.Tuple{IP: "5.5.5.5", Helo: "h", From: "f@x.org", To: "t@y.org"}
	if err := g.processGrey(ctx, gt, true, ""); err != nil {
		t.Fatal(err)
	}
	d, _ := mustGet(t, store, core.TupleKey(gt))
	if d.BCount != 1 || d.Pass != d.Expire || d.Pass != now.Unix()+GreyExp {
		t.Fatalf("new entry %+v", d)
	}
	if len(rec.updates) != 1 {
		t.Fatalf("sync updates %d", len(rec.updates))
	}
	now = now.Add(50 * time.Second)
	if err := g.processGrey(ctx, gt, true, ""); err != nil {
		t.Fatal(err)
	}
	d, _ = mustGet(t, store, core.TupleKey(gt))
	if d.BCount != 2 || d.Pass == now.Unix() {
		t.Fatalf("early retry %+v", d)
	}
	now = now.Add(60 * time.Second)
	if err := g.processGrey(ctx, gt, true, ""); err != nil {
		t.Fatal(err)
	}
	d, _ = mustGet(t, store, core.TupleKey(gt))
	if d.BCount != 3 || d.Pass != now.Unix() {
		t.Fatalf("late retry %+v", d)
	}
	if err := g.processGrey(ctx, gt, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(rec.updates) != 3 {
		t.Fatalf("sync updates %d", len(rec.updates))
	}
	_ = core.Put(ctx, store, core.MailKey("trap@z.org"), core.Data{})
	gt.To = "trap@z.org"
	if err := g.processGrey(ctx, gt, true, ""); err != nil {
		t.Fatal(err)
	}
	if len(rec.trapped) != 1 || rec.trapped[0] != "5.5.5.5" {
		t.Fatalf("sync trapped %v", rec.trapped)
	}
}

func TestSPFHandling(t *testing.T) {
	now := time.Unix(1700000000, 0)
	gt := core.Tuple{IP: "6.6.6.6", Helo: "h", From: "f@x.org", To: "t@y.org"}

	run := func(res core.SPFResult, conf string) (core.Store, *Greylister) {
		store := memory.New()
		g, err := New(Options{Settings: loadSettings(t, conf), Store: store, SPF: fakeSPF{res: res}, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		if err := g.processGrey(ctx, gt, true, ""); err != nil {
			t.Fatal(err)
		}
		return store, g
	}
	state := func(s core.Store) int {
		st := -1
		_ = s.View(ctx, func(tx core.ReadTx) error {
			var err error
			st, err = core.AddrState(tx, gt.IP)
			return err
		})
		return st
	}
	hasTuple := func(s core.Store) bool { _, f := mustGet(t, s, core.TupleKey(gt)); return f }

	if s, _ := run(core.SPFFail, ""); state(s) != 1 {
		t.Fatal("SPF fail must trap")
	}
	if s, _ := run(core.SPFSoftFail, ""); state(s) != 1 {
		t.Fatal("SPF softfail must trap by default")
	}
	if s, _ := run(core.SPFSoftFail, "section spf { trap_on_softfail = 0 }"); !hasTuple(s) {
		t.Fatal("softfail with trapping disabled must greylist")
	}
	if s, _ := run(core.SPFPass, ""); !hasTuple(s) {
		t.Fatal("pass without whitelist_on_pass must greylist")
	}
	s, g := run(core.SPFPass, "section spf { whitelist_on_pass = 1 }")
	if state(s) != 2 {
		t.Fatal("pass with whitelist_on_pass must whitelist")
	}
	if d, _ := mustGet(t, s, core.IPKey(gt.IP)); d.Expire != now.Unix()+g.Config().WhiteExpiry {
		t.Fatalf("white expiry %+v", d)
	}
	if s, _ := run(core.SPFNone, ""); !hasTuple(s) {
		t.Fatal("none must greylist")
	}
	if s, _ := run(core.SPFFail, "section spf { enable = 0 }"); !hasTuple(s) {
		t.Fatal("spf disabled must greylist")
	}
	store := memory.New()
	_ = core.Put(ctx, store, core.MailKey(gt.To), core.Data{})
	g, _ = New(Options{Settings: loadSettings(t, "section spf { whitelist_on_pass = 1 }"), Store: store, SPF: fakeSPF{res: core.SPFPass}, Now: func() time.Time { return now }})
	if err := g.processGrey(ctx, gt, true, ""); err != nil {
		t.Fatal(err)
	}
	if state(store) != 1 {
		t.Fatal("spamtrap must win over SPF pass")
	}
}

func TestNonGreyEdgeCases(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := memory.New()
	g, _ := New(Options{Settings: loadSettings(t, ""), Store: store, Now: func() time.Time { return now }})

	if err := g.processNonGrey(ctx, false, "1.1.1.1", "src", "abc", true, false); err != nil {
		t.Fatal(err)
	}
	if _, found := mustGet(t, store, core.IPKey("1.1.1.1")); found {
		t.Fatal("bad expiry must not create an entry")
	}
	if err := g.processNonGrey(ctx, false, "1.1.1.1", "src", "", true, true); err != nil {
		t.Fatal(err)
	}
	if err := g.processNonGrey(ctx, true, "1.1.1.1", "src", "12345", true, false); err != nil {
		t.Fatal(err)
	}
	d, found := mustGet(t, store, core.IPKey("1.1.1.1"))
	if !found || d.PCount != core.PCountTrapped || d.Pass != 12345 || d.Expire != 12345 || d.First != now.Unix() {
		t.Fatalf("trap entry %+v", d)
	}
	if err := g.processNonGrey(ctx, true, "1.1.1.1", "src", "0", true, true); err != nil {
		t.Fatal(err)
	}
	if _, found := mustGet(t, store, core.IPKey("1.1.1.1")); found {
		t.Fatal("entry should be deleted")
	}
	if err := g.ProcessMessage(ctx, &ipc.DstReply{}); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("unknown type: %v", err)
	}
	// A cancelled context aborts processing.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := g.processNonGrey(cctx, false, "2.2.2.2", "src", "99", true, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: %v", err)
	}
}

func TestRunScannerAndIPv6(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := memory.New()
	_ = core.Put(ctx, store, core.IPKey("2001::1"), core.Data{First: 1, Pass: 1, Expire: now.Unix() + 100})
	_ = core.Put(ctx, store, core.IPKey("1.1.1.1"), core.Data{First: 1, Pass: 1, Expire: now.Unix() + 100})
	fwOut, trapOut := &syncBuf{}, &syncBuf{}
	g, _ := New(Options{Settings: loadSettings(t, "enable_ipv6 = 1\n"), Store: store, FwOut: fwOut, TrapOut: trapOut, Now: func() time.Time { return now }})

	rctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- g.RunScanner(rctx, time.Hour) }()
	deadline := time.Now().Add(5 * time.Second)
	for fwOut.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r := ipc.NewReader(bytes.NewReader(fwOut.Bytes()))
	var names []string
	for range 2 {
		m, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, m.(*ipc.ReplaceRequest).Set)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{WhiteName, WhiteNameV6}) {
		t.Fatalf("frames %v", names)
	}
	// An empty traplist is not sent; the scan statistics are.
	tm, err := ipc.NewReader(bytes.NewReader(trapOut.Bytes())).Next()
	if err != nil {
		t.Fatalf("trap pipe: %v", err)
	}
	sc, ok := tm.(*ipc.ScanStats)
	if !ok || sc.White != 2 || sc.At == 0 {
		t.Fatalf("expected scan statistics with two white entries on the trap pipe, got %+v", tm)
	}
	if _, err := ipc.NewReader(bytes.NewReader(trapOut.Bytes()[len(trapOut.Bytes()):])).Next(); err == nil {
		t.Fatal("unexpected extra trap pipe frame")
	}
	if !strings.Contains(string(fwOut.Bytes()), "2001::1") {
		t.Fatal("v6 whitelist missing")
	}
}

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuf) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

type recSyncer struct {
	updates []core.Tuple
	trapped []string
	white   []string
}

func (r *recSyncer) Update(t core.Tuple, _ time.Time)          { r.updates = append(r.updates, t) }
func (r *recSyncer) White(ip string, _, _ time.Time, _ bool)   { r.white = append(r.white, ip) }
func (r *recSyncer) Trapped(ip string, _, _ time.Time, _ bool) { r.trapped = append(r.trapped, ip) }

type fakeSPF struct{ res core.SPFResult }

func (f fakeSPF) Check(_, _, _ string) (core.SPFResult, error) { return f.res, nil }
