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

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

// ProbeResult is one probe outcome: "ok", "denied" or "error: ...".
type ProbeResult struct {
	Name   string
	Result string
}

// Probe applies p to the calling process and then attempts the
// operations a confined greyd process must not be able to perform (and a
// few it must), reporting each outcome. It is meant for a throwaway
// process (greyd --sandbox-probe): the confinement cannot be undone.
// readPath and writePath are a file the profile should be able to read and
// a directory it should be able to write to; either may be empty.
func Probe(p Profile, readPath, writePath string, log *slog.Logger) ([]ProbeResult, error) {
	// Where the sandbox can only confine the calling thread (cgo builds),
	// keep every probe on that thread so the report is still truthful.
	runtime.LockOSThread()
	if err := Apply(p, log); err != nil {
		return nil, err
	}
	var out []ProbeResult
	add := func(name string, err error) {
		out = append(out, ProbeResult{Name: name, Result: classify(err)})
	}
	if readPath != "" {
		_, err := os.ReadFile(readPath)
		add("read-allowed", err)
	}
	_, err := os.ReadFile("/etc/passwd")
	add("read-etc-passwd", err)
	_, err = os.ReadDir("/")
	add("list-root", err)
	if writePath != "" {
		f := filepath.Join(writePath, fmt.Sprintf(".greyd-probe-%d", os.Getpid()))
		err := os.WriteFile(f, []byte("probe"), 0o600)
		_ = os.Remove(f)
		add("write-allowed", err)
	}
	f := filepath.Join(os.TempDir(), fmt.Sprintf(".greyd-probe-%d", os.Getpid()))
	err = os.WriteFile(f, []byte("probe"), 0o600)
	_ = os.Remove(f)
	add("write-tmp", err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	add("exec", exec.CommandContext(ctx, "/bin/true").Run())
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.DialContext(ctx, "tcp", "127.0.0.1:9")
	if c != nil {
		_ = c.Close()
	}
	add("tcp-connect", err)
	// Landlock lets any confined process bind port 0 (an ephemeral port),
	// so the check uses a fixed one.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:48025")
	if ln != nil {
		_ = ln.Close()
	}
	add("tcp-bind", err)
	uc, err := lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if uc != nil {
		_ = uc.Close()
	}
	add("udp-bind", err)
	add("chroot", syscall.Chroot("/"))
	add("setuid-root", syscall.Setuid(0))
	platformProbes(add)
	return out, nil
}

// classify maps an error to the probe vocabulary. Permission failures of
// any kind count as denied; connection refused on tcp-connect means the
// connect itself was allowed.
func classify(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES), errors.Is(err, os.ErrPermission):
		return "denied"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "ok"
	}
	msg := err.Error()
	if strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted") {
		return "denied"
	}
	return "error: " + msg
}

// WriteProbe prints results as sorted "name=result" lines.
func WriteProbe(w io.Writer, rs []ProbeResult) {
	sorted := append([]ProbeResult(nil), rs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, r := range sorted {
		fmt.Fprintf(w, "%s=%s\n", r.Name, r.Result)
	}
}
