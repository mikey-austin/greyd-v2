package spf

import (
	"context"
	"errors"
	"net"
	"testing"

	gospf "blitiri.com.ar/go/spf"

	"github.com/mikey-austin/greyd-golang/internal/core"
)

func TestMapResult(t *testing.T) {
	cases := map[gospf.Result]core.SPFResult{
		gospf.Pass:      core.SPFPass,
		gospf.Neutral:   core.SPFNone,
		gospf.None:      core.SPFNone,
		gospf.SoftFail:  core.SPFSoftFail,
		gospf.Fail:      core.SPFFail,
		gospf.TempError: core.SPFError,
		gospf.PermError: core.SPFError,
	}
	for in, want := range cases {
		if got := MapResult(in); got != want {
			t.Fatalf("MapResult(%s) = %s want %s", in, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	c := &Checker{check: func(ctx context.Context, ip net.IP, helo, from string) (gospf.Result, error) {
		if ip.String() != "1.2.3.4" || helo != "mx" || from != "a@b" {
			t.Fatalf("unexpected args %s %s %s", ip, helo, from)
		}
		return gospf.SoftFail, nil
	}}
	res, err := c.Check("1.2.3.4", "mx", "a@b")
	if err != nil || res != core.SPFSoftFail {
		t.Fatalf("Check = %s %v", res, err)
	}
	if res, err := c.Check("bogus", "mx", "a@b"); err == nil || res != core.SPFError {
		t.Fatal("invalid address must error")
	}
	c = &Checker{check: func(context.Context, net.IP, string, string) (gospf.Result, error) {
		return gospf.PermError, errors.New("boom")
	}}
	if res, err := c.Check("1.2.3.4", "mx", "a@b"); err == nil || res != core.SPFError {
		t.Fatal("library error must surface")
	}
	var _ core.SPFChecker = New()
}
