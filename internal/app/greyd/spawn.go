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

package greyd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/procs"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

// spawnChildren re-executes the binary as the firewall and greylister
// roles, passing the pipe ends as inherited descriptors.
func spawnChildren(ctx context.Context, _ *settings.Settings, log *slog.Logger) (*children, error) {
	fwR, fwW, err := os.Pipe() // main -> fw
	if err != nil {
		return nil, fmt.Errorf("firewall pipe: %w", err)
	}
	natR, natW, err := os.Pipe() // fw -> main
	if err != nil {
		return nil, fmt.Errorf("firewall nat pipe: %w", err)
	}
	greyFwR, greyFwW, err := os.Pipe() // grey -> fw
	if err != nil {
		return nil, fmt.Errorf("grey firewall pipe: %w", err)
	}
	greyR, greyW, err := os.Pipe() // main -> grey
	if err != nil {
		return nil, fmt.Errorf("grey pipe: %w", err)
	}
	trapR, trapW, err := os.Pipe() // grey -> main
	if err != nil {
		return nil, fmt.Errorf("trap pipe: %w", err)
	}

	fwCmd, err := procs.Spawn{Role: RoleFirewall, Files: map[string]*os.File{
		fdFwIn: fwR, fdNatOut: natW, fdGreyFwIn: greyFwR,
	}}.Start()
	if err != nil {
		return nil, fmt.Errorf("fork firewall failed: %w", err)
	}
	greyCmd, err := procs.Spawn{Role: RoleGrey, Files: map[string]*os.File{
		fdGreyIn: greyR, fdTrapOut: trapW, fdFwOut: greyFwW,
	}}.Start()
	if err != nil {
		_ = fwCmd.Process.Kill()
		return nil, fmt.Errorf("fork greylister: %w", err)
	}

	// The parent keeps only its own ends.
	for _, f := range []*os.File{fwR, natW, greyFwR, greyFwW, greyR, trapW} {
		_ = f.Close()
	}

	exited := make(chan struct{})
	var once sync.Once
	waitFor := func(c *exec.Cmd, name string) {
		err := c.Wait()
		if ctx.Err() == nil {
			log.Warn("child process exited", "role", name, "err", err)
			once.Do(func() { close(exited) })
		}
	}
	go waitFor(fwCmd, "firewall")
	go waitFor(greyCmd, "greylister")

	stop := func() {
		for _, c := range []*exec.Cmd{fwCmd, greyCmd} {
			if c.Process != nil {
				_ = c.Process.Signal(syscall.SIGTERM)
			}
		}
		deadline := time.After(5 * time.Second)
		done := make(chan struct{})
		go func() {
			for _, c := range []*exec.Cmd{fwCmd, greyCmd} {
				_, _ = c.Process.Wait()
			}
			close(done)
		}()
		select {
		case <-done:
		case <-deadline:
			for _, c := range []*exec.Cmd{fwCmd, greyCmd} {
				_ = c.Process.Kill()
			}
		}
	}

	reload := func() {
		for _, c := range []*exec.Cmd{fwCmd, greyCmd} {
			if c.Process != nil {
				_ = c.Process.Signal(syscall.SIGHUP)
			}
		}
	}

	return &children{
		files:  mainFiles{greyOut: greyW, fwOut: fwW, natIn: natR, trapIn: trapR},
		exited: exited,
		stop:   stop,
		reload: reload,
	}, nil
}
