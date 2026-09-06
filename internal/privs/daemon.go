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

package privs

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// EnvDaemonized marks a process that has already been detached.
const EnvDaemonized = "GREYD_DAEMONIZED"

// Daemonize detaches from the controlling terminal, equivalent to
// daemon(nochdir, 0). Go cannot fork, so the binary re-executes itself with
// the same arguments in a new session, with standard descriptors pointing
// at /dev/null; the parent then exits. In the detached child the function
// returns nil. Inherited descriptors (used by child roles) are preserved
// because the re-exec happens before any pipe is created.
func Daemonize(nochdir bool) error {
	if os.Getenv(EnvDaemonized) == "1" {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	defer devnull.Close()

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), EnvDaemonized+"=1")
	cmd.Stdin = devnull
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if !nochdir {
		cmd.Dir = "/"
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	os.Exit(0)
	return nil
}
