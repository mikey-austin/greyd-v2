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

package postgresql

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mikey-austin/greyd-golang/adapters/db/dbtest"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

// dsnEnv names the variable holding a postgres:// URL of a throw-away
// database (see packages/docker/docker-compose.test.yml).
const dsnEnv = "GREYD_TEST_POSTGRESQL_DSN"

var ctx = context.Background()

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("%s not set", dsnEnv)
	}
	c, err := pgconn.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("%s: %v", dsnEnv, err)
	}
	cfg := config.New()
	cfg.SetStr("driver", "database", DriverName)
	cfg.SetStr("host", "database", c.Host)
	cfg.SetInt("port", "database", int(c.Port))
	cfg.SetStr("name", "database", c.Database)
	cfg.SetStr("user", "database", c.User)
	cfg.SetStr("pass", "database", c.Password)
	return cfg
}

func openEmpty(t *testing.T) core.Store {
	t.Helper()
	s, err := core.OpenStore(testConfig(t), core.StoreOptions{Hostname: "conformance"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(ctx, core.OpenRW); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	for _, table := range []string{"entries", "spamtraps", "domains"} {
		if _, err := s.(*Store).Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	return s
}

func TestConformance(t *testing.T) {
	dbtest.RunConformance(t, openEmpty)
}

func TestHostScoping(t *testing.T) {
	s := openEmpty(t)
	other := New(testConfig(t), core.StoreOptions{Hostname: "other-host"})
	if err := other.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	// Expired rows of another host survive this host's scan; the
	// whitelist select is not scoped.
	if err := core.Put(ctx, other, core.IPKey("10.9.9.9"), core.Data{Expire: 10, PCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := core.Put(ctx, s, core.IPKey("10.9.9.8"), core.Data{Expire: 10, PCount: 1}); err != nil {
		t.Fatal(err)
	}
	var res core.ScanResult
	err := s.Update(ctx, func(tx core.Tx) error {
		var err error
		res, err = tx.Scan(1000, 100)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _ := core.Get(ctx, s, core.IPKey("10.9.9.9")); !found {
		t.Fatal("scan deleted another host's row")
	}
	if _, found, _ := core.Get(ctx, s, core.IPKey("10.9.9.8")); found {
		t.Fatal("scan kept an expired row of this host")
	}
	if len(res.Whitelist) != 1 || res.Whitelist[0] != "10.9.9.9" {
		t.Fatalf("Whitelist = %v", res.Whitelist)
	}
}

func TestReadOnly(t *testing.T) {
	s := openEmpty(t)
	if err := core.Put(ctx, s, core.IPKey("5.5.5.5"), core.Data{First: 7}); err != nil {
		t.Fatal(err)
	}
	ro := New(testConfig(t), core.StoreOptions{Hostname: "conformance"})
	if err := ro.Open(ctx, core.OpenRO); err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if d, found, err := core.Get(ctx, ro, core.IPKey("5.5.5.5")); err != nil || !found || d.First != 7 {
		t.Fatalf("Get in RO = %+v %v %v", d, found, err)
	}
	if err := ro.Update(ctx, func(core.Tx) error { return nil }); !errors.Is(err, core.ErrReadOnly) {
		t.Fatalf("Update on a read-only store = %v, want ErrReadOnly", err)
	}
}

func TestOpenTwiceIsNoop(t *testing.T) {
	s := openEmpty(t)
	if err := s.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.View(ctx, func(core.ReadTx) error { return nil }); !errors.Is(err, core.ErrNotOpen) {
		t.Fatalf("View on a closed store = %v, want ErrNotOpen", err)
	}
}

func TestConnString(t *testing.T) {
	cfg := config.New()
	if got, want := New(cfg, core.StoreOptions{}).ConnString(), "host='localhost' port='5432' dbname='greyd'"; got != want {
		t.Fatalf("defaults = %q want %q", got, want)
	}
	cfg.SetStr("socket", "database", "/var/run/postgresql/.s.PGSQL.5432")
	cfg.SetStr("user", "database", "u")
	cfg.SetStr("pass", "database", "it's")
	got := New(cfg, core.StoreOptions{}).ConnString()
	want := `host='/var/run/postgresql' port='5432' dbname='greyd' user='u' password='it\'s'`
	if got != want {
		t.Fatalf("socket config = %q want %q", got, want)
	}
	cfg.SetStr("socket", "database", "/tmp")
	if got := New(cfg, core.StoreOptions{}).ConnString(); got[:11] != "host='/tmp'" {
		t.Fatalf("socket dir = %q", got)
	}
}
