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

// Package logger implements the program-wide logging facility. Messages go
// to syslog (facility daemon), optionally to a log file, and always to
// standard error, mirroring log.c and failures.c of the C implementation.
package logger

import (
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Severity levels, numerically compatible with syslog priorities.
type Severity int

const (
	SevCrit    Severity = 2
	SevErr     Severity = 3
	SevWarning Severity = 4
	SevInfo    Severity = 6
	SevDebug   Severity = 7
)

// Options configures the logger.
type Options struct {
	// Ident is the program name prefixed to every message.
	Ident string
	// Debug enables debug level messages.
	Debug bool
	// Syslog enables the syslog sink.
	Syslog bool
	// File, when non-empty, is appended to (log_to_file).
	File string
	// Stderr receives every message; defaults to os.Stderr.
	Stderr io.Writer
}

// syslogSink abstracts the platform syslog connection so tests can stub it.
type syslogSink interface {
	Write(sev Severity, msg string) error
	Close() error
}

var (
	mu       sync.Mutex
	ident    = "greyd"
	debug    bool
	sysl     syslogSink
	logFile  *os.File
	stderr   io.Writer = os.Stderr
	exitFunc           = os.Exit
	// openSyslog is a hook replaced by the platform implementation.
	openSyslog = func(ident string) (syslogSink, error) { return nil, nil }
)

// Setup initialises the logging system. It may be called more than once;
// later calls replace earlier settings.
func Setup(o Options) error {
	mu.Lock()
	defer mu.Unlock()

	if o.Ident != "" {
		ident = o.Ident
	}
	debug = o.Debug
	if o.Stderr != nil {
		stderr = o.Stderr
	} else {
		stderr = os.Stderr
	}

	if sysl != nil {
		_ = sysl.Close()
		sysl = nil
	}
	if o.Syslog {
		s, err := openSyslog(ident)
		if err != nil {
			return fmt.Errorf("openlog: %w", err)
		}
		sysl = s
	}

	return reinitLocked(o.File)
}

// Reinit re-opens the log file (used by child processes after re-exec, as
// Log_reinit is used after fork in the C implementation).
func Reinit(file string) error {
	mu.Lock()
	defer mu.Unlock()
	return reinitLocked(file)
}

func reinitLocked(file string) error {
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
	if file == "" {
		return nil
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", file, err)
	}
	logFile = f
	return nil
}

// SetExit replaces the process exit function used by Fatal (tests only).
func SetExit(f func(int)) {
	mu.Lock()
	defer mu.Unlock()
	exitFunc = f
}

// Debugging reports whether debug output is enabled.
func Debugging() bool {
	mu.Lock()
	defer mu.Unlock()
	return debug
}

// Debug logs a message which is suppressed unless debugging is enabled.
func Debug(format string, a ...any) { write(SevDebug, format, a...) }

// Info logs an informational message.
func Info(format string, a ...any) { write(SevInfo, format, a...) }

// Warning logs a warning message.
func Warning(format string, a ...any) { write(SevWarning, format, a...) }

// Error logs an error message.
func Error(format string, a ...any) { write(SevErr, format, a...) }

// Fatal logs a critical message and terminates the process with status 1,
// like i_critical in the C implementation.
func Fatal(format string, a ...any) {
	write(SevCrit, format, a...)
	mu.Lock()
	f := exitFunc
	mu.Unlock()
	f(1)
}

func write(sev Severity, format string, a ...any) {
	mu.Lock()
	defer mu.Unlock()

	if sev == SevDebug && !debug {
		return
	}
	msg := fmt.Sprintf(format, a...)

	if sysl != nil {
		_ = sysl.Write(sev, msg)
	}

	line := fmt.Sprintf("%s[%d]: %s\n", ident, os.Getpid(), msg)
	if logFile != nil {
		writeLocked(logFile, line)
	}
	if stderr != nil {
		_, _ = io.WriteString(stderr, line)
	}
}

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
