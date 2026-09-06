package ipc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-golang/internal/config/parse"
)

func TestWriteBlacklist(t *testing.T) {
	var buf bytes.Buffer
	err := WriteBlacklist(&buf, "greyd-blacklist", "Your IP %A", []string{"1.2.3.4", "10.0.0.0/8", "2001::1"})
	if err != nil {
		t.Fatal(err)
	}
	want := "name=\"greyd-blacklist\"\nmessage=\"Your IP %A\"\nips=[\"1.2.3.4/32\",\"10.0.0.0/8\",\"2001::1/128\"]\n%%\n"
	if buf.String() != want {
		t.Fatalf("got %q\nwant %q", buf.String(), want)
	}
	buf.Reset()
	if err := WriteBlacklist(&buf, "x", "y", nil); err != nil || buf.Len() != 0 {
		t.Fatal("empty list must write nothing")
	}
}

func TestReaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGrey(&buf, "10.0.0.1", "1.2.3.4", "mx.example.org", "a@b.c", "d@e.f"); err != nil {
		t.Fatal(err)
	}
	if err := WriteAddr(&buf, MsgWhite, "4.3.2.1", "127.0.0.1", 1234, true); err != nil {
		t.Fatal(err)
	}
	r := NewReader(&buf)

	m, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if m.Int("type", "", 0) != MsgGrey || m.Str("dst_ip", "", "") != "10.0.0.1" ||
		m.Str("ip", "", "") != "1.2.3.4" || m.Str("helo", "", "") != "mx.example.org" ||
		m.Str("from", "", "") != "a@b.c" || m.Str("to", "", "") != "d@e.f" {
		t.Fatalf("grey message mismatch")
	}
	if m.Int("sync", "", 1) != 1 {
		t.Fatal("grey message must not carry sync")
	}

	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if m.Int("type", "", 0) != MsgWhite || m.Int("sync", "", 1) != 0 || m.Str("ip", "", "") != "4.3.2.1" ||
		m.Str("source", "", "") != "127.0.0.1" || m.Str("expires", "", "") != "1234" || m.Int("delete", "", 0) != 1 {
		t.Fatalf("addr message mismatch")
	}

	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestReaderParseErrorThenContinue(t *testing.T) {
	src := "==\n%%\ntype = 2\n%%\n"
	r := NewReader(strings.NewReader(src))
	_, err := r.Next()
	var pe *parse.Error
	if !errors.As(err, &pe) {
		t.Fatalf("expected parse error, got %v", err)
	}
	m, err := r.Next()
	if err != nil || m.Int("type", "", 0) != 2 {
		t.Fatalf("second frame: %v", err)
	}
}

func TestReaderUnterminatedFinalFrame(t *testing.T) {
	r := NewReader(strings.NewReader("a = 1\n"))
	m, err := r.Next()
	if err != nil || m.Int("a", "", 0) != 1 {
		t.Fatalf("final frame: %v", err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
	r = NewReader(strings.NewReader(""))
	if _, err := r.Next(); err != io.EOF {
		t.Fatal("empty stream should be EOF")
	}
}

func TestReaderCRLFTerminator(t *testing.T) {
	r := NewReader(strings.NewReader("a = 1\r\n%%\r\nb = 2\r\n%%\r\n"))
	m, err := r.Next()
	if err != nil || m.Int("a", "", 0) != 1 {
		t.Fatalf("frame 1: %v", err)
	}
	m, err = r.Next()
	if err != nil || m.Int("b", "", 0) != 2 {
		t.Fatalf("frame 2: %v", err)
	}
}

func TestFirewallMessages(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteReplace(&buf, "greyd-whitelist", 4, []string{"1.1.1.1", "2.2.2.2"}); err != nil {
		t.Fatal(err)
	}
	want := "type=\"replace\"\nname=\"greyd-whitelist\"\naf=4\nips=[\"1.1.1.1\",\"2.2.2.2\"]\n%%\n"
	if buf.String() != want {
		t.Fatalf("replace got %q", buf.String())
	}
	m, err := NewReader(&buf).Next()
	if err != nil || m.Str("type", "", "") != TypeReplace || len(m.StrList("ips", "")) != 2 || m.Int("af", "", 0) != 4 {
		t.Fatalf("replace decode: %v", err)
	}

	buf.Reset()
	if err := WriteNAT(&buf, "1.2.3.4", 4321, "10.0.0.1", 8025); err != nil {
		t.Fatal(err)
	}
	m, err = NewReader(&buf).Next()
	if err != nil || m.Str("type", "", "") != TypeNAT || m.Int("src_port", "", 0) != 4321 ||
		m.Str("proxy", "", "") != "10.0.0.1" || m.Int("proxy_port", "", 0) != 8025 {
		t.Fatalf("nat decode: %v", err)
	}

	buf.Reset()
	if err := WriteDst(&buf, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "dst=\"192.0.2.1\"\n%%\n" {
		t.Fatalf("dst got %q", buf.String())
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize(`a"b\c`); got != "abc" {
		t.Fatalf("Sanitize = %q", got)
	}
	var buf bytes.Buffer
	if err := WriteGreyFromSync(&buf, "1.2.3.4", `he"lo`, "f", "t"); err != nil {
		t.Fatal(err)
	}
	m, err := NewReader(&buf).Next()
	if err != nil || m.Str("helo", "", "") != "helo" || m.Int("sync", "", 1) != 0 {
		t.Fatalf("sanitized grey: %v", err)
	}
}

func TestMessageBuilder(t *testing.T) {
	m := &Message{}
	m.Int("type", 1).Str("s", "v").StrList("l", []string{"a", "b"})
	if string(m.Bytes()) != "type = 1\ns = \"v\"\nl=[\"a\",\"b\"]\n%%\n" {
		t.Fatalf("got %q", m.Bytes())
	}
}
