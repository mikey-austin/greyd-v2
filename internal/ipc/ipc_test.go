package ipc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-golang/internal/core"
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
	m, err := NewReader(&buf).Next()
	if err != nil {
		t.Fatal(err)
	}
	bl, ok := m.(*BlacklistMessage)
	if !ok || bl.Name != "greyd-blacklist" || bl.Message != "Your IP %A" || len(bl.IPs) != 3 || bl.IPs[2] != "2001::1/128" {
		t.Fatalf("decoded %+v", m)
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
	if err := WriteGreyFromSync(&buf, "9.9.9.9", "h", "f", "t"); err != nil {
		t.Fatal(err)
	}
	r := NewReader(&buf)

	m, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	g, ok := m.(*GreyMessage)
	if !ok || g.Tuple != (core.Tuple{IP: "1.2.3.4", Helo: "mx.example.org", From: "a@b.c", To: "d@e.f"}) || g.DstIP != "10.0.0.1" || !g.Sync {
		t.Fatalf("grey message %+v", m)
	}

	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	a, ok := m.(*AddrMessage)
	if !ok || a.Type != MsgWhite || a.Sync || a.IP != "4.3.2.1" || a.Source != "127.0.0.1" || a.Expires != "1234" || !a.Delete {
		t.Fatalf("addr message %+v", m)
	}

	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := m.(*GreyMessage); !ok || g.Sync || g.Tuple.IP != "9.9.9.9" {
		t.Fatalf("sync grey message %+v", m)
	}

	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestReaderDecodeErrorThenContinue(t *testing.T) {
	src := "==\n%%\ntype = 2\nip = \"1.1.1.1\"\nsource = \"s\"\nexpires = \"5\"\n%%\ntype = 1\nip = \"2.2.2.2\"\n%%\ntype = 9\n%%\nfoo = 1\n%%\n"
	r := NewReader(strings.NewReader(src))
	_, err := r.Next()
	var se *SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("expected syntax error, got %v", err)
	}
	m, err := r.Next()
	if err != nil || m.(*AddrMessage).Type != MsgTrap {
		t.Fatalf("second frame: %v", err)
	}
	_, err = r.Next()
	var ie *IncompleteError
	if !errors.As(err, &ie) || ie.Field != "helo" {
		t.Fatalf("incomplete grey: %v", err)
	}
	if _, err = r.Next(); !errors.Is(err, ErrUnknownMessage) {
		t.Fatalf("unknown type: %v", err)
	}
	if _, err = r.Next(); !errors.Is(err, ErrUnknownMessage) {
		t.Fatalf("unclassifiable: %v", err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestReaderUnterminatedFinalFrameAndLimits(t *testing.T) {
	r := NewReader(strings.NewReader("dst=\"1.1.1.1\"\n"))
	m, err := r.Next()
	if err != nil || m.(*DstReply).Dst != "1.1.1.1" {
		t.Fatalf("final frame: %v", err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
	if _, err := NewReader(strings.NewReader("")).Next(); err != io.EOF {
		t.Fatal("empty stream should be EOF")
	}
	r = NewReader(strings.NewReader("a = 1\r\n%%\r\ndst=\"x\"\r\n%%\r\n"))
	if _, err := r.Next(); !errors.Is(err, ErrUnknownMessage) {
		t.Fatalf("frame 1: %v", err)
	}
	if m, err := r.Next(); err != nil || m.(*DstReply).Dst != "x" {
		t.Fatalf("frame 2 (CRLF): %v", err)
	}
	r = NewReader(strings.NewReader(strings.Repeat("x", 100) + "\n%%\n"))
	r.SetMaxFrame(50)
	if _, err := r.Next(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("frame limit: %v", err)
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
	if err != nil {
		t.Fatal(err)
	}
	if rr, ok := m.(*ReplaceRequest); !ok || rr.Set != "greyd-whitelist" || rr.AF != 4 || len(rr.IPs) != 2 {
		t.Fatalf("replace decode: %+v", m)
	}

	buf.Reset()
	if err := WriteNAT(&buf, "1.2.3.4", 4321, "10.0.0.1", 8025); err != nil {
		t.Fatal(err)
	}
	m, err = NewReader(&buf).Next()
	if err != nil {
		t.Fatal(err)
	}
	if nr, ok := m.(*NATRequest); !ok || nr.Src != "1.2.3.4" || nr.SrcPort != 4321 || nr.Proxy != "10.0.0.1" || nr.ProxyPort != 8025 {
		t.Fatalf("nat decode: %+v", m)
	}

	buf.Reset()
	if err := WriteDst(&buf, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "dst=\"192.0.2.1\"\n%%\n" {
		t.Fatalf("dst got %q", buf.String())
	}
}

func TestDecodeSyntax(t *testing.T) {
	// Multi-line quoted strings and escapes as produced by greyd-setup from
	// the sample configuration.
	body := "name=\"uatraps\"\nmessage=\"Your address %A has sent mail to a ualberta.ca spamtrap\\\\n\n   within the last 24 hours\"\nips=[ 1, \"2.2.2.2/32\" , \"3.3.3.3/32\" ]\n# comment\n"
	m, err := Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	bl := m.(*BlacklistMessage)
	if !strings.Contains(bl.Message, "spamtrap\\n\n   within") || len(bl.IPs) != 3 || bl.IPs[0] != "1" {
		t.Fatalf("decoded %+v", bl)
	}
	if _, err := Decode(`x = "a\"b"; dst = "q"`); err != nil {
		t.Fatalf("escaped quote: %v", err)
	}
	for _, bad := range []string{`dst = `, `dst = "unterminated`, `= 1`, `dst = @`, `ips = [ "a"`, `dst = "x\`} {
		_, err := Decode(bad)
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Fatalf("%q: expected syntax error, got %v", bad, err)
		}
	}
	// Names are case insensitive; later assignments win.
	m, err = Decode("DST = \"a\"\ndst = \"b\"\n")
	if err != nil || m.(*DstReply).Dst != "b" {
		t.Fatalf("case/override: %v %+v", err, m)
	}
	// A NAT request with ports out of range keeps zero ports.
	m, _ = Decode("type=\"nat\"\nsrc=\"1.1.1.1\"\nsrc_port=70000\nproxy=\"2.2.2.2\"\nproxy_port=25\n")
	if nr := m.(*NATRequest); nr.SrcPort != 0 || nr.ProxyPort != 25 {
		t.Fatalf("nat ports %+v", nr)
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
	if err != nil || m.(*GreyMessage).Tuple.Helo != "helo" || m.(*GreyMessage).Sync {
		t.Fatalf("sanitized grey: %v", err)
	}
}

func TestMessageBuilder(t *testing.T) {
	b := &Builder{}
	b.Int("type", 1).Str("s", "v").StrList("l", []string{"a", "b"})
	if string(b.Bytes()) != "type = 1\ns = \"v\"\nl=[\"a\",\"b\"]\n%%\n" {
		t.Fatalf("got %q", b.Bytes())
	}
}
