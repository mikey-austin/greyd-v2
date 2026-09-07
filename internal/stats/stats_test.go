package stats

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/db/memory"
	"github.com/mikey-austin/greyd-v2/internal/config/parse"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

func TestSummarize(t *testing.T) {
	memory.Reset("stats-summary")
	s := memory.Open("stats-summary")
	ctx := context.Background()
	if err := s.Open(ctx, core.OpenRW); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	puts := []struct {
		k core.Key
		d core.Data
	}{
		{core.TupleKey(core.Tuple{IP: "1.1.1.1", Helo: "h", From: "f", To: "t"}), core.Data{First: now, Pass: now + 60, Expire: now + 3600, BCount: 1}},
		{core.TupleKey(core.Tuple{IP: "1.1.1.2", Helo: "h", From: "f", To: "t"}), core.Data{First: now, Pass: now + 60, Expire: now + 3600, BCount: 1}},
		{core.IPKey("2.2.2.2"), core.Data{First: now, Pass: now, Expire: now + 3600, PCount: 1}},
		{core.IPKey("3.3.3.3"), core.Data{First: now, Pass: now, Expire: now + 3600, PCount: core.PCountTrapped}},
		{core.MailKey("trap@example.org"), core.Data{PCount: core.PCountSpamtrap}},
		{core.DomainKey("example.org"), core.Data{PCount: core.PCountDomain}},
	}
	for _, p := range puts {
		if err := core.Put(ctx, s, p.k, p.d); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Summarize(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if c != (Counts{Grey: 2, White: 1, Trapped: 1, Spamtrap: 1, Domain: 1}) {
		t.Fatalf("counts %+v", c)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Summarize(cctx, s); err == nil {
		t.Fatal("cancelled context must fail")
	}
}

func fakeGreyd(t *testing.T, path string, reply func(net.Conn)) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); reply(c) }()
		}
	}()
}

func TestQueryFormatAndDialer(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "g.sock")
	fakeGreyd(t, sock, func(c net.Conn) {
		m, err := ipc.NewReader(c).Next()
		if err != nil {
			return
		}
		if _, ok := m.(*ipc.StatsRequest); ok {
			_ = ipc.WriteStatsReply(c, map[string]int64{"uptime_seconds": 7, "connections_total": 3}, []string{"bl=2", "greyd-greytrap=0"})
		}
	})
	cfg, err := parse.String("config_socket = \"" + sock + "\"\n")
	if err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := Query(context.Background(), Dialer(s))
	if err != nil {
		t.Fatal(err)
	}
	if reply.Counters["uptime_seconds"] != 7 || len(reply.Blacklists) != 2 {
		t.Fatalf("reply %+v", reply)
	}
	bls := Blacklists(reply)
	if bls[0] != (Blacklist{Name: "bl", Entries: 2}) || bls[1].Name != "greyd-greytrap" {
		t.Fatalf("blacklists %+v", bls)
	}
	var out strings.Builder
	Format(&out, reply)
	if !strings.HasPrefix(out.String(), "connections_total") || !strings.Contains(out.String(), "blacklist bl") {
		t.Fatalf("format:\n%s", out.String())
	}

	// A TCP configuration port gets the reserved-port dialer.
	cfg2, _ := parse.String("config_port = 8026\n")
	s2, _ := settings.Load(cfg2)
	if Dialer(s2) == nil {
		t.Fatal("nil dialer")
	}

	// Error paths: no answer, wrong answer, unreachable.
	silent := filepath.Join(dir, "silent.sock")
	fakeGreyd(t, silent, func(c net.Conn) { _, _ = ipc.NewReader(c).Next() })
	if _, err := Query(context.Background(), func() (net.Conn, error) { return net.Dial("unix", silent) }); err == nil || !strings.Contains(err.Error(), "without answering") {
		t.Fatalf("silent: %v", err)
	}
	wrong := filepath.Join(dir, "wrong.sock")
	fakeGreyd(t, wrong, func(c net.Conn) { _, _ = ipc.NewReader(c).Next(); _ = ipc.WriteDst(c, "x") })
	if _, err := Query(context.Background(), func() (net.Conn, error) { return net.Dial("unix", wrong) }); err == nil || !strings.Contains(err.Error(), "unexpected reply") {
		t.Fatalf("wrong: %v", err)
	}
	if _, err := Query(context.Background(), func() (net.Conn, error) { return nil, errors.New("refused") }); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("refused: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)
	if _, err := Query(ctx, func() (net.Conn, error) { return net.Dial("unix", silent) }); err == nil {
		t.Fatal("expired context must fail")
	}
}
