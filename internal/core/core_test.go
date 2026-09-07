package core

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-golang/internal/config"
)

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"<Mikey@greyd.ORG>":       "mikey@greyd.org",
		"info@greyd.org":          "info@greyd.org",
		`"quoted"\@x.org`:         "quoted@x.org",
		"<a<b>c>":                 "abc",
		"":                        "",
		strings.Repeat("a", 2000): strings.Repeat("a", MaxMail-1),
	}
	for in, want := range cases {
		if got := NormalizeEmail(in); got != want {
			t.Fatalf("NormalizeEmail(%q) = %q want %q", in, got, want)
		}
	}
}

func TestNormalizeDriver(t *testing.T) {
	cases := map[string]string{
		"sqlite":                                 "sqlite",
		"/usr/lib/greyd/greyd_sqlite.so":         "sqlite",
		"greyd_netfilter.la":                     "netfilter",
		"../drivers/greyd_bdb.la":                "bolt",
		"greyd_bdb_sql.so":                       "bolt",
		"greyd_fw_dummy.so":                      "dummy",
		"/usr/local/lib/greyd/greyd_pf.so":       "pf",
		"  MySQL ":                               "mysql",
		"@libdir@/@PACKAGE@/greyd_postgresql.so": "postgresql",
	}
	for in, want := range cases {
		if got := NormalizeDriver(in); got != want {
			t.Fatalf("NormalizeDriver(%q) = %q want %q", in, got, want)
		}
	}
}

type fakeStore struct {
	Store
	data map[string]Data
}

func (f *fakeStore) Get(k Key) (Data, bool, error) {
	d, ok := f.data[k.Str]
	return d, ok, nil
}

func (f *fakeStore) View(_ context.Context, fn func(ReadTx) error) error { return fn(f) }
func (f *fakeStore) Iter(IterTypes) (Iterator, error)                    { return nil, nil }

type fakeFW struct {
	opened bool
	fail   bool
}

func (f *fakeFW) Open(context.Context) error {
	if f.fail {
		return errors.New("nope")
	}
	f.opened = true
	return nil
}
func (f *fakeFW) Close() error                                                   { return nil }
func (f *fakeFW) Replace(context.Context, string, []string, Family) (int, error) { return 0, nil }
func (f *fakeFW) StartLogCapture(context.Context) error                          { return nil }
func (f *fakeFW) EndLogCapture() error                                           { return nil }
func (f *fakeFW) CaptureLog(context.Context) ([]string, error)                   { return nil, nil }
func (f *fakeFW) LookupOrigDst(_ context.Context, _, p netip.AddrPort) (netip.AddrPort, error) {
	return p, nil
}

func TestRegistry(t *testing.T) {
	RegisterStore("teststore", "test store", func(cfg *config.Config, o StoreOptions) (Store, error) {
		return &fakeStore{data: map[string]Data{"1.2.3.4": {PCount: PCountTrapped}, "5.6.7.8": {PCount: 3}}}, nil
	})
	fw := &fakeFW{}
	RegisterFirewall("testfw", "test firewall", func(cfg *config.Config, _ FirewallOptions) (Firewall, error) { return fw, nil })
	RegisterFirewall("badfw", "failing firewall", func(cfg *config.Config, _ FirewallOptions) (Firewall, error) { return &fakeFW{fail: true}, nil })

	if !contains(StoreDrivers(), "teststore") || !contains(FirewallDrivers(), "testfw") {
		t.Fatal("drivers not listed")
	}

	cfg := config.New()
	if _, err := OpenStore(cfg, StoreOptions{}); err == nil || !strings.Contains(err.Error(), "database configuration") {
		t.Fatalf("missing section: %v", err)
	}
	cfg.SetStr("driver", "database", "greyd_teststore.so")
	s, err := OpenStore(cfg, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fs := s.(*fakeStore)
	if st, _ := AddrState(fs, "1.2.3.4"); st != 1 {
		t.Fatalf("trapped state %d", st)
	}
	if st, _ := AddrState(fs, "5.6.7.8"); st != 2 {
		t.Fatalf("white state %d", st)
	}
	if st, _ := AddrState(fs, "9.9.9.9"); st != 0 {
		t.Fatalf("missing state %d", st)
	}
	cfg.SetStr("driver", "database", "nosuch")
	if _, err := OpenStore(cfg, StoreOptions{}); err == nil || !strings.Contains(err.Error(), "unknown database driver") {
		t.Fatalf("unknown driver: %v", err)
	}

	ctx := context.Background()
	if _, err := OpenFirewall(ctx, cfg, FirewallOptions{}); err == nil {
		t.Fatal("missing firewall section should fail")
	}
	cfg.SetStr("driver", "firewall", "testfw")
	got, err := OpenFirewall(ctx, cfg, FirewallOptions{})
	if err != nil || got != fw || !fw.opened {
		t.Fatalf("OpenFirewall: %v", err)
	}
	cfg.SetStr("driver", "firewall", "badfw")
	if _, err := OpenFirewall(ctx, cfg, FirewallOptions{}); err == nil {
		t.Fatal("failing Open must propagate")
	}
	cfg.SetStr("driver", "firewall", "")
	if _, err := OpenFirewall(ctx, cfg, FirewallOptions{}); err == nil {
		t.Fatal("empty driver must fail")
	}
	// Single-operation helpers run through View.
	if d, found, err := Get(ctx, s, IPKey("5.6.7.8")); err != nil || !found || d.PCount != 3 {
		t.Fatalf("Get helper: %+v %v %v", d, found, err)
	}
}

func TestSPFResultString(t *testing.T) {
	if SPFPass.String() != "pass" || SPFError.String() != "error" || SPFNone.String() != "none" ||
		SPFFail.String() != "fail" || SPFSoftFail.String() != "softfail" {
		t.Fatal("String()")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
