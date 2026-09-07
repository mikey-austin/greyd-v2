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

// Package procs starts privilege separated helper processes. The C daemon
// forks; Go re-executes its own binary with a role marker in the
// environment and passes pipes as inherited descriptors. Each child
// receives the parent's command line, so configuration is parsed
// identically in every process.
package procs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// EnvRole names the role a child process must assume.
const EnvRole = "GREYD_ROLE"

const envFDPrefix = "GREYD_FD_"

// Role returns the role assigned to this process, or "" for the parent.
func Role() string { return os.Getenv(EnvRole) }

// Spawn describes a child process to start.
type Spawn struct {
	// Role is stored in EnvRole.
	Role string
	// Files are passed as inherited descriptors, addressed by name.
	Files map[string]*os.File
	// Env holds extra environment entries (KEY=VALUE).
	Env []string
	// Args overrides os.Args[1:] when non-nil.
	Args []string
	// Stdout/Stderr default to the parent's.
	Stdout, Stderr *os.File
}

// Start launches the child. The returned command has been started; the
// caller should Wait on it (or reap it on shutdown).
func (s Spawn) Start() (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := s.Args
	if args == nil {
		args = os.Args[1:]
	}
	cmd := exec.CommandContext(context.Background(), exe, args...)

	names := make([]string, 0, len(s.Files))
	for n := range s.Files {
		names = append(names, n)
	}
	sort.Strings(names)

	env := append([]string{}, os.Environ()...)
	env = filterEnv(env, EnvRole, envFDPrefix)
	env = filterEnv(env, "LISTEN_PID", "LISTEN_")
	env = append(env, EnvRole+"="+s.Role)
	for i, n := range names {
		cmd.ExtraFiles = append(cmd.ExtraFiles, s.Files[n])
		env = append(env, fmt.Sprintf("%s%s=%d", envFDPrefix, strings.ToUpper(n), 3+i))
	}
	env = append(env, s.Env...)
	cmd.Env = env

	cmd.Stdin = nil
	if s.Stdout != nil {
		cmd.Stdout = s.Stdout
	} else {
		cmd.Stdout = os.Stdout
	}
	if s.Stderr != nil {
		cmd.Stderr = s.Stderr
	} else {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s child: %w", s.Role, err)
	}
	return cmd, nil
}

// InheritedFile returns the descriptor passed under name by the parent.
func InheritedFile(name string) (*os.File, error) {
	v := os.Getenv(envFDPrefix + strings.ToUpper(name))
	if v == "" {
		return nil, fmt.Errorf("no inherited descriptor %q", name)
	}
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("bad inherited descriptor %q=%q", name, v)
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, fmt.Errorf("inherited descriptor %q (%d) is invalid", name, fd)
	}
	return f, nil
}

func filterEnv(env []string, exact, prefix string) []string {
	out := env[:0]
	for _, e := range env {
		k := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			k = e[:i]
		}
		if k == exact || strings.HasPrefix(k, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}
