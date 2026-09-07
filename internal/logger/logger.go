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

// Package logger provides the log/slog handler used by the greyd programs.
// Records go to syslog (facility daemon), optionally to a log file
// (log_to_file) and always to standard error, in the line format of the C
// implementation ("ident[pid]: message key=value ..."). Libraries receive
// a *slog.Logger; nothing in this package is global.
package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// Options configure a handler.
type Options struct {
	// Ident is the program name prefixed to every line.
	Ident string
	// Debug enables debug level records.
	Debug bool
	// Syslog enables the syslog sink.
	Syslog bool
	// File, when non-empty, is appended to (log_to_file).
	File string
	// Stderr receives every record; defaults to os.Stderr. Use io.Discard
	// to silence it.
	Stderr io.Writer
}

// Severity levels, numerically compatible with syslog priorities.
type Severity int

const (
	SevCrit    Severity = 2
	SevErr     Severity = 3
	SevWarning Severity = 4
	SevInfo    Severity = 6
	SevDebug   Severity = 7
)

// syslogSink abstracts the platform syslog connection so tests can stub it.
type syslogSink interface {
	Write(sev Severity, msg string) error
	Close() error
}

// openSyslog is replaced by the platform implementation.
var openSyslog = func(ident string) (syslogSink, error) { return nil, nil }

// Handler is a slog.Handler writing greyd style lines to the sinks.
type Handler struct {
	ident string
	debug bool

	mu     *sync.Mutex
	sysl   syslogSink
	file   *os.File
	stderr io.Writer

	// pre holds attributes added with With, already prefixed with the
	// groups open at the time.
	pre    []preAttr
	groups []string
}

type preAttr struct {
	prefix string
	attr   slog.Attr
}

// New creates a logger. Failing to reach syslog is not fatal: a warning is
// written to stderr and the remaining sinks are used.
func New(o Options) (*slog.Logger, *Handler, error) {
	h := &Handler{ident: o.Ident, debug: o.Debug, mu: &sync.Mutex{}, stderr: o.Stderr}
	if h.ident == "" {
		h.ident = "greyd"
	}
	if h.stderr == nil {
		h.stderr = os.Stderr
	}
	if o.Syslog {
		s, err := openSyslog(h.ident)
		if err != nil {
			_, _ = fmt.Fprintf(h.stderr, "%s: syslog unavailable: %v\n", h.ident, err)
		} else {
			h.sysl = s
		}
	}
	if err := h.Reopen(o.File); err != nil {
		return nil, nil, err
	}
	return slog.New(h), h, nil
}

// Reopen (re)opens the log file; an empty path closes it.
func (h *Handler) Reopen(file string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file != nil {
		_ = h.file.Close()
		h.file = nil
	}
	if file == "" {
		return nil
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644) //nolint:gosec // log files are conventionally world readable
	if err != nil {
		return fmt.Errorf("open log file %s: %w", file, err)
	}
	h.file = f
	return nil
}

// Close releases the sinks.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sysl != nil {
		_ = h.sysl.Close()
		h.sysl = nil
	}
	if h.file != nil {
		_ = h.file.Close()
		h.file = nil
	}
	return nil
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(_ context.Context, l slog.Level) bool {
	return h.debug || l > slog.LevelDebug
}

// Handle implements slog.Handler.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	var b bytes.Buffer
	b.WriteString(r.Message)
	prefix := h.prefix()
	for _, p := range h.pre {
		writeAttr(&b, p.prefix, p.attr)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, prefix, a)
		return true
	})
	msg := b.String()

	sev := severity(r.Level)
	line := fmt.Sprintf("%s[%d]: %s\n", h.ident, os.Getpid(), msg)

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sysl != nil {
		_ = h.sysl.Write(sev, msg)
	}
	if h.file != nil {
		writeLocked(h.file, line)
	}
	if h.stderr != nil {
		_, _ = io.WriteString(h.stderr, line)
	}
	return nil
}

func writeAttr(b *bytes.Buffer, prefix string, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, g := range a.Value.Group() {
			writeAttr(b, prefix+a.Key+".", g)
		}
		return
	}
	b.WriteByte(' ')
	b.WriteString(prefix)
	b.WriteString(a.Key)
	b.WriteByte('=')
	v := a.Value.Resolve().String()
	if needsQuote(v) {
		b.WriteString(strconv.Quote(v))
	} else {
		b.WriteString(v)
	}
}

func needsQuote(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == '"' || c == '=' || c > 0x7e {
			return true
		}
	}
	return false
}

func severity(l slog.Level) Severity {
	switch {
	case l >= slog.LevelError+4:
		return SevCrit
	case l >= slog.LevelError:
		return SevErr
	case l >= slog.LevelWarn:
		return SevWarning
	case l >= slog.LevelInfo:
		return SevInfo
	default:
		return SevDebug
	}
}

func (h *Handler) prefix() string {
	p := ""
	for _, g := range h.groups {
		p += g + "."
	}
	return p
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.pre = append([]preAttr{}, h.pre...)
	prefix := h.prefix()
	for _, a := range attrs {
		c.pre = append(c.pre, preAttr{prefix: prefix, attr: a})
	}
	return &c
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.groups = append(append([]string{}, h.groups...), name)
	return &c
}

// LevelCrit is the level used for fatal conditions (mapped to LOG_CRIT).
const LevelCrit = slog.LevelError + 4

// writeLocked appends a line to the file while holding an exclusive fcntl
// lock over the whole file, so several greyd processes can share one log.
func writeLocked(f *os.File, line string) {
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLKW, &lock); err != nil {
		return
	}
	_, _ = f.WriteString(line)
	lock.Type = unix.F_UNLCK
	_ = unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lock)
}

// Discard returns a logger that drops everything (tests, nil defaults).
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Or returns l when non-nil, otherwise a discarding logger.
func Or(l *slog.Logger) *slog.Logger {
	if l == nil {
		return Discard()
	}
	return l
}
