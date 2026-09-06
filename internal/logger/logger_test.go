package logger

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugSuppressedByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := Setup(Options{Ident: "test", Stderr: &buf}); err != nil {
		t.Fatal(err)
	}
	Debug("hidden")
	Info("hi %d", 1)
	want := fmt.Sprintf("test[%d]: hi 1\n", os.Getpid())
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
}

func TestDebugEnabled(t *testing.T) {
	var buf bytes.Buffer
	if err := Setup(Options{Ident: "test", Debug: true, Stderr: &buf}); err != nil {
		t.Fatal(err)
	}
	Debug("shown")
	if !strings.Contains(buf.String(), "shown") {
		t.Fatalf("debug line missing: %q", buf.String())
	}
	if !Debugging() {
		t.Fatal("Debugging() should be true")
	}
}

func TestFileSink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "greyd.log")
	var buf bytes.Buffer
	if err := Setup(Options{Ident: "test", File: path, Stderr: &buf}); err != nil {
		t.Fatal(err)
	}
	Warning("careful")
	if err := Reinit(path); err != nil {
		t.Fatal(err)
	}
	Warning("again")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "careful") != 1 || strings.Count(string(data), "again") != 1 {
		t.Fatalf("unexpected log file contents: %q", data)
	}
}

func TestFatalExits(t *testing.T) {
	var buf bytes.Buffer
	if err := Setup(Options{Ident: "test", Stderr: &buf}); err != nil {
		t.Fatal(err)
	}
	code := -1
	SetExit(func(c int) { code = c })
	defer SetExit(os.Exit)
	Fatal("boom %s", "x")
	if code != 1 {
		t.Fatalf("exit code %d", code)
	}
	if !strings.Contains(buf.String(), "boom x") {
		t.Fatalf("message missing: %q", buf.String())
	}
}

func TestSyslogSink(t *testing.T) {
	var got []string
	openSyslog = func(ident string) (syslogSink, error) {
		return &stubSyslog{got: &got}, nil
	}
	defer func() { openSyslog = func(string) (syslogSink, error) { return nil, nil } }()
	var buf bytes.Buffer
	if err := Setup(Options{Ident: "test", Syslog: true, Stderr: &buf}); err != nil {
		t.Fatal(err)
	}
	Info("to syslog")
	if len(got) != 1 || got[0] != "6:to syslog" {
		t.Fatalf("syslog got %v", got)
	}
}

type stubSyslog struct{ got *[]string }

func (s *stubSyslog) Write(sev Severity, msg string) error {
	*s.got = append(*s.got, fmt.Sprintf("%d:%s", sev, msg))
	return nil
}
func (s *stubSyslog) Close() error { return nil }
