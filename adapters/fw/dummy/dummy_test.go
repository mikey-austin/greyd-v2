package dummy

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

func TestDummy(t *testing.T) {
	cfg := config.New()
	cfg.SetStr("driver", "firewall", "greyd_fw_dummy.so")
	fw, err := core.OpenFirewall(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := fw.Replace("greyd-whitelist", []string{"1.1.1.1", "2.2.2.2/31"}, core.IPv4)
	if err != nil || n != 2 {
		t.Fatalf("Replace = %d %v", n, err)
	}
	if got := fw.(*Firewall).Set("greyd-whitelist"); len(got) != 2 || got[1] != "2.2.2.2/31" {
		t.Fatalf("Set = %v", got)
	}
	proxy := netip.MustParseAddrPort("10.0.0.1:8025")
	dst, err := fw.LookupOrigDst(netip.MustParseAddrPort("1.2.3.4:5"), proxy)
	if err != nil || dst != proxy {
		t.Fatalf("LookupOrigDst = %v %v", dst, err)
	}
	if err := fw.StartLogCapture(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	entries, err := fw.CaptureLog(ctx)
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
