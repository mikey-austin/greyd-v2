package greyd

import (
	"context"
	"os"
	"sync"

	"github.com/mikey-austin/greyd-golang/internal/config"
)

// startChildrenInProcess runs the firewall and greylister roles as
// goroutines over real pipes, so the whole daemon can be exercised in one
// unprivileged test process.
func startChildrenInProcess(ctx context.Context, cfg *config.Config) (*children, error) {
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
		_ = runFwChild(cctx, cfg, fwFiles{fwIn: fwR, natOut: natW, greyFwIn: greyFwR})
		if ctx.Err() == nil {
			once.Do(func() { close(exited) })
		}
	}()
	go func() {
		defer wg.Done()
		_ = runGreyChild(cctx, cfg, greyFiles{greyIn: greyR, trapOut: trapW, fwOut: greyFwW})
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
