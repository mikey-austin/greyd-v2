package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/mikey-austin/greyd-golang/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-golang/adapters/db/kv"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

func TestConformance(t *testing.T) {
	dbtest.RunConformance(t, func(t *testing.T) core.Store {
		s := New()
		if err := s.Open(context.Background(), core.OpenRW); err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestNamedDatabasesShare(t *testing.T) {
	Reset("shared")
	ctx := context.Background()
	a := Open("shared")
	b := Open("shared")
	if err := core.Put(ctx, a, core.IPKey("1.1.1.1"), core.Data{First: 1}); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := core.Get(ctx, b, core.IPKey("1.1.1.1")); !found {
		t.Fatal("named databases should share data")
	}
	Reset("shared")
	if _, found, _ := core.Get(ctx, Open("shared"), core.IPKey("1.1.1.1")); found {
		t.Fatal("Reset should drop data")
	}
	if _, found, _ := core.Get(ctx, New(), core.IPKey("1.1.1.1")); found {
		t.Fatal("New() must be private")
	}
	// Read-only stores refuse writes.
	ro := Open("shared")
	_ = ro.Open(ctx, core.OpenRO)
	if err := core.Put(ctx, ro, core.IPKey("2.2.2.2"), core.Data{}); !errors.Is(err, core.ErrReadOnly) {
		t.Fatalf("read-only Put: %v", err)
	}
}

func TestRegisteredFactory(t *testing.T) {
	cfg := config.New()
	cfg.SetStr("driver", "database", DriverName)
	cfg.SetStr("name", "database", "factory-test")
	Reset("factory-test")
	s, err := core.OpenStore(cfg, core.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Put(context.Background(), s, core.MailKey("t@x.org"), core.Data{}); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := core.Get(context.Background(), Open("factory-test"), core.MailKey("t@x.org")); !found {
		t.Fatal("factory should open the named database")
	}
}

func TestCodecRoundTrip(t *testing.T) {
	keys := []core.Key{
		core.IPKey("1.2.3.4"),
		core.MailKey("a@b.c"),
		core.DomainKey("b.c"),
		core.TupleKey(core.Tuple{IP: "1.2.3.4", Helo: "h", From: "f", To: "t"}),
		core.TupleKey(core.Tuple{IP: "1.2.3.4", Helo: "", From: "", To: ""}),
	}
	for _, k := range keys {
		got, err := kv.DecodeKey(kv.EncodeKey(k))
		if err != nil || got != k {
			t.Fatalf("key round trip %+v -> %+v (%v)", k, got, err)
		}
	}
	d := core.Data{First: -1, Pass: 1 << 40, Expire: 3, BCount: -5, PCount: core.PCountDomain}
	got, err := kv.DecodeData(kv.EncodeData(d))
	if err != nil || got != d {
		t.Fatalf("data round trip %+v -> %+v (%v)", d, got, err)
	}
	if _, err := kv.DecodeKey(nil); err == nil {
		t.Fatal("empty key must fail")
	}
	if _, err := kv.DecodeData([]byte{1, 2}); err == nil {
		t.Fatal("short data must fail")
	}
	if _, err := kv.DecodeKey([]byte{byte(core.KeyTuple), 'a'}); err == nil {
		t.Fatal("malformed tuple key must fail")
	}
	if kv.BucketFor(core.KeyDomainPart) != kv.BucketDomains || kv.BucketFor(core.KeyIP) != kv.BucketEntries {
		t.Fatal("BucketFor")
	}
}
