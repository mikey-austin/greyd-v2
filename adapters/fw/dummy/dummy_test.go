package dummy

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/core"
)

func TestDummy(t *testing.T) {
	cfg := config.New()
	cfg.SetStr("driver", "firewall", "greyd_fw_dummy.so")
	ctx := context.Background()
	fw, err := core.OpenFirewall(ctx, cfg, core.FirewallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := fw.Replace(ctx, "greyd-whitelist", []string{"1.1.1.1", "2.2.2.2/31"}, core.IPv4)
	if err != nil || n != 2 {
		t.Fatalf("Replace = %d %v", n, err)
	}
	if got := fw.(*Firewall).Set("greyd-whitelist"); len(got) != 2 || got[1] != "2.2.2.2/31" {
		t.Fatalf("Set = %v", got)
	}
	proxy := netip.MustParseAddrPort("10.0.0.1:8025")
	dst, err := fw.LookupOrigDst(ctx, netip.MustParseAddrPort("1.2.3.4:5"), proxy)
	if err != nil || dst != proxy {
		t.Fatalf("LookupOrigDst = %v %v", dst, err)
	}
	if err := fw.StartLogCapture(ctx); err != nil {
		t.Fatal(err)
	}
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	entries, err := fw.CaptureLog(tctx)
	if err != nil || entries != nil {
		t.Fatalf("CaptureLog = %v %v", entries, err)
	}
	if err := fw.EndLogCapture(); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
}
