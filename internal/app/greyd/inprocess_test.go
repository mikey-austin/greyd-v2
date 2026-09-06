package greyd

import (
	"context"
	"log/slog"
	"os"
	"sync"

	"github.com/mikey-austin/greyd-golang/internal/settings"
)

// startChildrenInProcess runs the firewall and greylister roles as
// goroutines over real pipes, so the whole daemon can be exercised in one
// unprivileged test process.
func startChildrenInProcess(ctx context.Context, cfg *settings.Settings, log *slog.Logger) (*children, error) {
	fwR, fwW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	natR, natW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	greyFwR, greyFwW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	greyR, greyW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	trapR, trapW, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	cctx, cancel := context.WithCancel(ctx)
	exited := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = runFwChild(cctx, cfg, fwFiles{fwIn: fwR, natOut: natW, greyFwIn: greyFwR}, log)
		if ctx.Err() == nil {
			once.Do(func() { close(exited) })
		}
	}()
	go func() {
		defer wg.Done()
		_ = runGreyChild(cctx, cfg, greyFiles{greyIn: greyR, trapOut: trapW, fwOut: greyFwW}, log)
		if ctx.Err() == nil {
			once.Do(func() { close(exited) })
		}
	}()

	stop := func() {
		cancel()
		wg.Wait()
	}
	return &children{
		files:  mainFiles{greyOut: greyW, fwOut: fwW, natIn: natR, trapIn: trapR},
		exited: exited,
		stop:   stop,
	}, nil
}
