package grey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-golang/adapters/db/memory"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/config/parse"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

func init() {
	_ = logger.Setup(logger.Options{Ident: "test", Stderr: io.Discard})
}

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

type tally struct {
	entries, white, grey, trapped, spamtrap            int
	whitePassed, whiteBlocked, greyPassed, greyBlocked int
}

func tallyStore(t *testing.T, s core.Store) tally {
	t.Helper()
	it, err := s.Iter(core.IterAll)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	var ta tally
	for {
		k, d, ok, err := it.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
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
	return ta
}

func writeGrey(w io.Writer, dst, ip, helo, from, to string) {
	_ = ipc.WriteGrey(w, dst, ip, helo, from, to)
}

func writeAddr(w io.Writer, typ int, source, ip string, expires int64) {
	fmt.Fprintf(w, "type = %d\nip = \"%s\"\nsource = \"%s\"\nexpires = \"%d\"\n%%%%\n", typ, ip, source, expires)
}

func newTestGreylister(t *testing.T, store core.Store, now time.Time, trapOut, fwOut io.Writer) (*Greylister, *config.Config) {
	t.Helper()
	cfg, err := parse.String(testConf)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(Options{
		Config:  cfg,
		Store:   store,
		TrapOut: trapOut,
		FwOut:   fwOut,
		Startup: now.Add(-120 * time.Second),
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, cfg
}

func TestGreylisterSetup(t *testing.T) {
	store := memory.New()
	g, _ := newTestGreylister(t, store, time.Now(), nil, nil)
	if g.TraplistName != "test traplist" || g.TraplistMsg != "you have been trapped" {
		t.Fatalf("names %q %q", g.TraplistName, g.TraplistMsg)
	}
	if g.LowPrioMX != "192.179.21.3" {
		t.Fatalf("low prio mx %q", g.LowPrioMX)
	}
	if !reflect.DeepEqual(g.Domains, []string{"domain4.com", "domain2.com"}) {
		t.Fatalf("domains %v", g.Domains)
	}
	if g.GreyExp != 3600 || g.WhiteExp != WhiteExp || g.TrapExp != TrapExp || g.PassTime != PassTime {
		t.Fatal("expiries")
	}
	if g.WhitelistName != WhiteName || g.WhitelistNameV6 != WhiteNameV6 {
		t.Fatal("whitelist names")
	}
}

func TestLowPrioMXFallbackToDefaultSection(t *testing.T) {
	cfg := config.New()
	cfg.SetStr("low_prio_mx", "", "1.1.1.1")
	g, err := New(Options{Config: cfg, Store: memory.New()})
	if err != nil || g.LowPrioMX != "1.1.1.1" {
		t.Fatalf("fallback %q %v", g.LowPrioMX, err)
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("missing config must error")
	}
}

func TestLoadDomains(t *testing.T) {
	d, err := LoadDomains("testdata/permitted_domains.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, []string{"domain4.com", "domain2.com"}) {
		t.Fatalf("domains %v", d)
	}
	if _, err := LoadDomains("testdata/missing"); err == nil {
		t.Fatal("missing file must error")
	}
	if !domainMatches("@greyd.org", "beardedclams@greyd.org") || !domainMatches("obtuse.com", "stacy@snouts.obtuse.com") ||
		domainMatches("@greyd.org", "peter@bugs.greyd.org") || !domainMatches("Domain.COM", "x@domain.com") {
		t.Fatal("domainMatches")
	}
}

// TestReaderScenario ports test_grey.c.
func TestReaderScenario(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := memory.New()
	if err := store.Put(core.MailKey("trap@domain3.com"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(core.DomainKey("greyd@domain3.com"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(core.DomainKey("domain1.com"), core.Data{}); err != nil {
		t.Fatal(err)
	}

	var trapOut, fwOut bytes.Buffer
	g, _ := newTestGreylister(t, store, now, &trapOut, &fwOut)

	var in bytes.Buffer
	exp := now.Unix() + 3600
	// Grey entries and duplicates.
	for range 2 {
		writeGrey(&in, "2.3.4.5", "1.2.3.4", "jackiemclean.net", "m@jackiemclean.net", "r@domain1.com")
		writeGrey(&in, "2.3.1.5", "1.2.4.4", "jackiemclean.net", "m@jackiemclean.net", "r@domain1.com")
		writeGrey(&in, "2.3.2.5", "1.2.2.4", "jackiemclean.net", "m@jackiemclean.net", "r@domain1.com")
	}
	// White entries and duplicates.
	for range 2 {
		writeAddr(&in, ipc.MsgWhite, "2.3.4.5", "4.3.2.1", exp)
		writeAddr(&in, ipc.MsgWhite, "2.3.4.6", "4.3.2.2", exp)
		writeAddr(&in, ipc.MsgWhite, "2.3.4.7", "4.3.2.3", exp)
	}
	// Trap entries and duplicates.
	for range 2 {
		writeAddr(&in, ipc.MsgTrap, "3.2.4.5", "3.4.2.1", exp)
		writeAddr(&in, ipc.MsgTrap, "3.2.4.6", "3.4.2.2", exp)
		writeAddr(&in, ipc.MsgTrap, "3.2.4.7", "3.4.3.2", exp)
	}
	// Expired white and trap.
	writeAddr(&in, ipc.MsgWhite, "8.8.8.3", "7.7.6.5", now.Unix()-3600)
	writeAddr(&in, ipc.MsgTrap, "8.8.8.5", "7.7.6.6", now.Unix()-120)
	// Explicit spamtrap in a permitted domain: trapped.
	writeGrey(&in, "2.3.2.5", "1.2.2.4", "jackiemclean.net", "m@jackiemclean.net", "trap@domain3.com")
	// Domain not permitted: trapped.
	writeGrey(&in, "2.3.2.5", "1.2.2.4", "jackiemclean.net", "m@jackiemclean.net", "trap@willbetrapped.com")
	// White entry with the same ip as an existing grey entry.
	writeAddr(&in, ipc.MsgWhite, "2.3.4.7", "1.2.3.4", exp)
	// Hit to the low priority MX.
	writeGrey(&in, "192.179.21.3", "1.2.2.34", "jackiemclean.net", "m@jackiemclean.net", "notrap@domain4.com")
	// A parse error stops the reader.
	in.WriteString("==\n")

	err := g.RunReader(context.Background(), &in)
	var pe *parse.Error
	if !errors.As(err, &pe) {
		t.Fatalf("expected parse error to stop the reader, got %v", err)
	}

	got := tallyStore(t, store)
	want := tally{entries: 17, white: 5, grey: 3, trapped: 6, spamtrap: 1, whitePassed: 3, whiteBlocked: 0, greyPassed: 0, greyBlocked: 6}
	if got != want {
		t.Fatalf("after reader: %+v\nwant %+v", got, want)
	}
	if st, _ := core.AddrState(store, "1.2.2.34"); st != 1 {
		t.Fatal("low priority MX hit should be trapped")
	}

	// Simulate conditions for the scan.
	tk := core.TupleKey(core.Tuple{IP: "1.2.2.4", Helo: "jackiemclean.net", From: "m@jackiemclean.net", To: "r@domain1.com"})
	d, found, _ := store.Get(tk)
	if !found {
		t.Fatal("tuple 1.2.2.4 missing")
	}
	d.Expire = now.Unix() - 120
	_ = store.Put(tk, d)
	tk.Tuple.IP = "1.2.4.4"
	d, found, _ = store.Get(tk)
	if !found {
		t.Fatal("tuple 1.2.4.4 missing")
	}
	d.Pass = now.Unix() - 60
	_ = store.Put(tk, d)

	if err := g.ScanOnce(); err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}

	m, err := ipc.NewReader(&fwOut).Next()
	if err != nil {
		t.Fatalf("whitelist message: %v", err)
	}
	if m.Str("type", "", "") != ipc.TypeReplace || m.Str("name", "", "") != WhiteName || m.Int("af", "", 0) != 4 {
		t.Fatalf("whitelist frame %+v", fwOut.String())
	}
	wl := m.StrList("ips", "")
	sort.Strings(wl)
	if !reflect.DeepEqual(wl, []string{"1.2.3.4", "1.2.4.4", "4.3.2.1", "4.3.2.2", "4.3.2.3"}) {
		t.Fatalf("whitelist ips %v", wl)
	}

	m, err = ipc.NewReader(&trapOut).Next()
	if err != nil {
		t.Fatalf("traplist message: %v", err)
	}
	if m.Str("name", "", "_") != "test traplist" || m.Str("message", "", "_") != "you have been trapped" {
		t.Fatalf("traplist frame %s", trapOut.String())
	}
	ips := m.StrList("ips", "")
	if len(ips) != 5 {
		t.Fatalf("traplist ips %v", ips)
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
	cfg, _ := parse.String("section grey { pass_time = 100 }")
	g, err := New(Options{Config: cfg, Store: store, Syncer: rec, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	gt := core.Tuple{IP: "5.5.5.5", Helo: "h", From: "f@x.org", To: "t@y.org"}
	if err := g.processGrey(gt, true, ""); err != nil {
		t.Fatal(err)
	}
	d, _, _ := store.Get(core.TupleKey(gt))
	if d.BCount != 1 || d.Pass != d.Expire || d.Pass != now.Unix()+GreyExp {
		t.Fatalf("new entry %+v", d)
	}
	if len(rec.updates) != 1 {
		t.Fatalf("sync updates %d", len(rec.updates))
	}
	// Retry before pass_time: pass unchanged.
	now = now.Add(50 * time.Second)
	if err := g.processGrey(gt, true, ""); err != nil {
		t.Fatal(err)
	}
	d, _, _ = store.Get(core.TupleKey(gt))
	if d.BCount != 2 || d.Pass == now.Unix() {
		t.Fatalf("early retry %+v", d)
	}
	// Retry after pass_time: pass = now.
	now = now.Add(60 * time.Second)
	if err := g.processGrey(gt, true, ""); err != nil {
		t.Fatal(err)
	}
	d, _, _ = store.Get(core.TupleKey(gt))
	if d.BCount != 3 || d.Pass != now.Unix() {
		t.Fatalf("late retry %+v", d)
	}
	// Messages from sync are not re-broadcast.
	if err := g.processGrey(gt, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(rec.updates) != 3 {
		t.Fatalf("sync updates %d", len(rec.updates))
	}

	// A trapped message announces a trapped entry.
	_ = store.Put(core.MailKey("trap@z.org"), core.Data{})
	gt.To = "trap@z.org"
	if err := g.processGrey(gt, true, ""); err != nil {
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
		cfg, _ := parse.String(conf)
		g, err := New(Options{Config: cfg, Store: store, SPF: fakeSPF{res: res}, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		if err := g.processGrey(gt, true, ""); err != nil {
			t.Fatal(err)
		}
		return store, g
	}

	store, _ := run(core.SPFFail, "")
	if st, _ := core.AddrState(store, gt.IP); st != 1 {
		t.Fatal("SPF fail must trap")
	}
	store, _ = run(core.SPFSoftFail, "")
	if st, _ := core.AddrState(store, gt.IP); st != 1 {
		t.Fatal("SPF softfail must trap by default")
	}
	store, _ = run(core.SPFSoftFail, "section spf { trap_on_softfail = 0 }")
	if _, found, _ := store.Get(core.TupleKey(gt)); !found {
		t.Fatal("softfail with trapping disabled must greylist")
	}
	store, _ = run(core.SPFPass, "")
	if _, found, _ := store.Get(core.TupleKey(gt)); !found {
		t.Fatal("pass without whitelist_on_pass must greylist")
	}
	store, g := run(core.SPFPass, "section spf { whitelist_on_pass = 1 }")
	if st, _ := core.AddrState(store, gt.IP); st != 2 {
		t.Fatal("pass with whitelist_on_pass must whitelist")
	}
	d, _, _ := store.Get(core.IPKey(gt.IP))
	if d.Expire != now.Unix()+g.WhiteExp {
		t.Fatalf("white expiry %+v", d)
	}
	store, _ = run(core.SPFNone, "")
	if _, found, _ := store.Get(core.TupleKey(gt)); !found {
		t.Fatal("none must greylist")
	}
	store, _ = run(core.SPFFail, "section spf { enable = 0 }")
	if _, found, _ := store.Get(core.TupleKey(gt)); !found {
		t.Fatal("spf disabled must greylist")
	}
	// Spamtrap takes precedence over SPF.
	store = memory.New()
	_ = store.Put(core.MailKey(gt.To), core.Data{})
	cfg, _ := parse.String("section spf { whitelist_on_pass = 1 }")
	g, _ = New(Options{Config: cfg, Store: store, SPF: fakeSPF{res: core.SPFPass}, Now: func() time.Time { return now }})
	if err := g.processGrey(gt, true, ""); err != nil {
		t.Fatal(err)
	}
	if st, _ := core.AddrState(store, gt.IP); st != 1 {
		t.Fatal("spamtrap must win over SPF pass")
	}
}

func TestNonGreyEdgeCases(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := memory.New()
	cfg := config.New()
	g, _ := New(Options{Config: cfg, Store: store, Now: func() time.Time { return now }})

	// Bad expiry is ignored.
	if err := g.processNonGrey(false, "1.1.1.1", "src", "abc", true, false); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(core.IPKey("1.1.1.1")); found {
		t.Fatal("bad expiry must not create an entry")
	}
	// Deletion of a missing entry is fine, even with a bad expiry.
	if err := g.processNonGrey(false, "1.1.1.1", "src", "", true, true); err != nil {
		t.Fatal(err)
	}
	// Add then delete.
	if err := g.processNonGrey(true, "1.1.1.1", "src", "12345", true, false); err != nil {
		t.Fatal(err)
	}
	d, found, _ := store.Get(core.IPKey("1.1.1.1"))
	if !found || d.PCount != core.PCountTrapped || d.Pass != 12345 || d.Expire != 12345 || d.First != now.Unix() {
		t.Fatalf("trap entry %+v", d)
	}
	if err := g.processNonGrey(true, "1.1.1.1", "src", "0", true, true); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(core.IPKey("1.1.1.1")); found {
		t.Fatal("entry should be deleted")
	}

	// Unknown message type.
	m, _ := parse.String("type = 42\n")
	if err := g.ProcessMessage(m); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("unknown type: %v", err)
	}
	// Incomplete grey message is ignored.
	m, _ = parse.String("type = 1\nip = \"1.2.3.4\"\n")
	if err := g.ProcessMessage(m); err != nil {
		t.Fatal(err)
	}
}

func TestRunScannerAndIPv6(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := memory.New()
	_ = store.Put(core.IPKey("2001::1"), core.Data{First: 1, Pass: 1, Expire: now.Unix() + 100})
	_ = store.Put(core.IPKey("1.1.1.1"), core.Data{First: 1, Pass: 1, Expire: now.Unix() + 100})
	fwOut, trapOut := &syncBuf{}, &syncBuf{}
	cfg, _ := parse.String("enable_ipv6 = 1\n")
	g, _ := New(Options{Config: cfg, Store: store, FwOut: fwOut, TrapOut: trapOut, Now: func() time.Time { return now }})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.RunScanner(ctx, time.Hour) }()
	deadline := time.Now().Add(5 * time.Second)
	for fwOut.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r := ipc.NewReader(bytes.NewReader(fwOut.Bytes()))
	m1, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{m1.Str("name", "", ""), m2.Str("name", "", "")}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{WhiteName, WhiteNameV6}) {
		t.Fatalf("frames %v", names)
	}
	if trapOut.Len() != 0 {
		t.Fatal("empty traplist must not be sent")
	}
}

// syncBuf is a goroutine safe bytes.Buffer.
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
