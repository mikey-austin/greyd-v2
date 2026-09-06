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

type fakeFW struct {
	opened bool
	fail   bool
}

func (f *fakeFW) Open() error {
	if f.fail {
		return errors.New("nope")
	}
	f.opened = true
	return nil
}
func (f *fakeFW) Close() error                                              { return nil }
func (f *fakeFW) Replace(string, []string, Family) (int, error)             { return 0, nil }
func (f *fakeFW) StartLogCapture() error                                    { return nil }
func (f *fakeFW) EndLogCapture() error                                      { return nil }
func (f *fakeFW) CaptureLog(context.Context) ([]string, error)              { return nil, nil }
func (f *fakeFW) LookupOrigDst(_, p netip.AddrPort) (netip.AddrPort, error) { return p, nil }

func TestRegistry(t *testing.T) {
	RegisterStore("teststore", func(cfg *config.Config, o StoreOptions) (Store, error) {
		return &fakeStore{data: map[string]Data{"1.2.3.4": {PCount: PCountTrapped}, "5.6.7.8": {PCount: 3}}}, nil
	})
	fw := &fakeFW{}
	RegisterFirewall("testfw", func(cfg *config.Config) (Firewall, error) { return fw, nil })
	RegisterFirewall("badfw", func(cfg *config.Config) (Firewall, error) { return &fakeFW{fail: true}, nil })

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
	if st, _ := AddrState(s, "1.2.3.4"); st != 1 {
		t.Fatalf("trapped state %d", st)
	}
	if st, _ := AddrState(s, "5.6.7.8"); st != 2 {
		t.Fatalf("white state %d", st)
	}
	if st, _ := AddrState(s, "9.9.9.9"); st != 0 {
		t.Fatalf("missing state %d", st)
	}
	cfg.SetStr("driver", "database", "nosuch")
	if _, err := OpenStore(cfg, StoreOptions{}); err == nil || !strings.Contains(err.Error(), "unknown database driver") {
		t.Fatalf("unknown driver: %v", err)
	}

	if _, err := OpenFirewall(cfg); err == nil {
		t.Fatal("missing firewall section should fail")
	}
	cfg.SetStr("driver", "firewall", "testfw")
	got, err := OpenFirewall(cfg)
	if err != nil || got != fw || !fw.opened {
		t.Fatalf("OpenFirewall: %v", err)
	}
	cfg.SetStr("driver", "firewall", "badfw")
	if _, err := OpenFirewall(cfg); err == nil {
		t.Fatal("failing Open must propagate")
	}
	cfg.SetStr("driver", "firewall", "")
	if _, err := OpenFirewall(cfg); err == nil {
		t.Fatal("empty driver must fail")
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
