package logger

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLineFormatAndDebugGating(t *testing.T) {
	var buf bytes.Buffer
	log, _, err := New(Options{Ident: "test", Stderr: &buf})
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("hidden")
	log.Info("hi", "n", 1, "addr", "1.2.3.4", "text", "has space")
	want := fmt.Sprintf("test[%d]: hi n=1 addr=1.2.3.4 text=\"has space\"\n", os.Getpid())
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}

	buf.Reset()
	log, _, _ = New(Options{Ident: "test", Debug: true, Stderr: &buf})
	log.Debug("shown")
	if !strings.Contains(buf.String(), "shown") {
		t.Fatalf("debug line missing: %q", buf.String())
	}
}

func TestGroupsAndAttrs(t *testing.T) {
	var buf bytes.Buffer
	log, _, _ := New(Options{Ident: "t", Stderr: &buf})
	log = log.With("proc", "grey").WithGroup("tuple")
	log.Warn("x", "ip", "1.1.1.1", slog.Group("g", slog.Int("a", 1)))
	if !strings.Contains(buf.String(), "x proc=grey tuple.ip=1.1.1.1 tuple.g.a=1") {
		t.Fatalf("got %q", buf.String())
	}
}

func TestFileSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "greyd.log")
	log, h, err := New(Options{Ident: "test", File: path, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	log.Warn("careful")
	if err := h.Reopen(path); err != nil {
		t.Fatal(err)
	}
	log.Warn("again")
	_ = h.Close()
	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "careful") != 1 || strings.Count(string(data), "again") != 1 {
		t.Fatalf("log file %q", data)
	}
	if _, _, err := New(Options{File: filepath.Join(t.TempDir(), "no", "dir", "x")}); err == nil {
		t.Fatal("unopenable file must error")
	}
}

func TestSyslogSink(t *testing.T) {
	var got []string
	openSyslog = func(ident string) (syslogSink, error) { return &stubSyslog{got: &got}, nil }
	defer func() { openSyslog = func(string) (syslogSink, error) { return nil, nil } }()
	log, _, _ := New(Options{Ident: "test", Syslog: true, Stderr: &bytes.Buffer{}})
	log.Info("to syslog")
	log.Error("bad")
	log.Log(context.Background(), LevelCrit, "fatal")
	if len(got) != 3 || got[0] != "6:to syslog" || got[1] != "3:bad" || got[2] != "2:fatal" {
		t.Fatalf("syslog got %v", got)
	}
}

func TestSyslogUnavailableIsNotFatal(t *testing.T) {
	openSyslog = func(string) (syslogSink, error) { return nil, fmt.Errorf("no syslog") }
	defer func() { openSyslog = func(string) (syslogSink, error) { return nil, nil } }()
	var buf bytes.Buffer
	log, _, err := New(Options{Ident: "test", Syslog: true, Stderr: &buf})
	if err != nil || log == nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.Contains(buf.String(), "syslog unavailable") {
		t.Fatalf("warning missing: %q", buf.String())
	}
}

func TestOrAndDiscard(t *testing.T) {
	if Or(nil) == nil || Discard() == nil {
		t.Fatal("helpers")
	}
	l := Discard()
	if Or(l) != l {
		t.Fatal("Or must return the given logger")
	}
}

type stubSyslog struct{ got *[]string }

func (s *stubSyslog) Write(sev Severity, msg string) error {
	*s.got = append(*s.got, fmt.Sprintf("%d:%s", sev, msg))
	return nil
}
func (s *stubSyslog) Close() error { return nil }
