package spamdlist

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-golang/internal/blacklist"
)

func TestScanner(t *testing.T) {
	src := "# This is a comment \n" +
		"192.168.12.1              # Trailing comment \n" +
		"192.12.2.0 - 192.12.2.255 # IP range \n" +
		"114.23.44.22/24           # CIDR notation \n" +
		"123455"
	s := NewScanner(strings.NewReader(src))
	type tk struct {
		k TokenKind
		v int
	}
	want := []tk{
		{TokEOL, 0},
		{TokInt8, 192}, {TokDot, 0}, {TokInt8, 168}, {TokDot, 0}, {TokInt6, 12}, {TokDot, 0}, {TokInt6, 1}, {TokEOL, 0},
		{TokInt8, 192}, {TokDot, 0}, {TokInt6, 12}, {TokDot, 0}, {TokInt6, 2}, {TokDot, 0}, {TokInt6, 0}, {TokDash, 0},
		{TokInt8, 192}, {TokDot, 0}, {TokInt6, 12}, {TokDot, 0}, {TokInt6, 2}, {TokDot, 0}, {TokInt8, 255}, {TokEOL, 0},
		{TokInt8, 114}, {TokDot, 0}, {TokInt6, 23}, {TokDot, 0}, {TokInt6, 44}, {TokDot, 0}, {TokInt6, 22}, {TokSlash, 0}, {TokInt6, 24}, {TokEOL, 0},
		{TokInt8, 123}, {TokInt6, 45}, {TokInt6, 5}, {TokEOF, 0},
	}
	for i, w := range want {
		got := s.Next()
		if got.Kind != w.k || (w.k == TokInt6 || w.k == TokInt8) && got.Val != w.v {
			t.Fatalf("token %d: got %+v want %+v", i, got, w)
		}
	}
	if s.Next().Kind != TokEOF {
		t.Fatal("EOF should be sticky")
	}
}

func TestScannerUnknownCharEndsStream(t *testing.T) {
	s := NewScanner(strings.NewReader("1.2.3.4\n2001:db8::/32\n5.6.7.8\n"))
	kinds := []TokenKind{}
	for {
		tok := s.Next()
		kinds = append(kinds, tok.Kind)
		if tok.Kind == TokEOF {
			break
		}
	}
	// 1 . 2 . 3 . 4 EOL 200 1 EOF  (':' terminates)
	want := []TokenKind{TokInt6, TokDot, TokInt6, TokDot, TokInt6, TokDot, TokInt6, TokEOL, TokInt8, TokInt6, TokEOF}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("got %v", kinds)
	}
}

func parseInto(t *testing.T, src string, typ blacklist.Type) (*blacklist.Blacklist, error) {
	t.Helper()
	bl := blacklist.New("test", "msg", blacklist.StorageList)
	err := Parse(strings.NewReader(src), bl, typ)
	return bl, err
}

func TestParse(t *testing.T) {
	src := "\n# comment\n192.168.20.0/24\n192.168.21.0 - 192.168.21.255 text ignored? no, only comments\n"
	// The trailing text after the range is not valid in the grammar; the C
	// parser errors there too, so use a clean source for the success case.
	src = "\n# comment\n192.168.20.0/24\n192.168.21.0 - 192.168.21.255\n\n192.168.23.1 # single\n"
	bl, err := parseInto(t, src, blacklist.TypeBlack)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if bl.Count != 6 {
		t.Fatalf("Count = %d", bl.Count)
	}
	got := bl.Collapse()
	want := []string{"192.168.20.0/23", "192.168.23.1/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestParseEmptyAndEOFForms(t *testing.T) {
	for _, src := range []string{"", "\n\n", "# only a comment", "1.2.3.4", "1.2.3.4\n"} {
		bl, err := parseInto(t, src, blacklist.TypeBlack)
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		if strings.Contains(src, "1.2.3.4") && bl.Count != 2 {
			t.Fatalf("%q: Count %d", src, bl.Count)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []string{
		"1.2.3\n",         // short address
		"1.2.3.4/300\n",   // prefix must be INT6
		"1.2.3.4 - 5.6\n", // short end address
		"1.2.3.4 5.6.7.8\n",
	}
	for _, src := range cases {
		_, err := parseInto(t, src, blacklist.TypeBlack)
		var pe *Error
		if !errors.As(err, &pe) {
			t.Fatalf("%q: expected *Error, got %v", src, err)
		}
	}
	// An unknown character silently ends the stream (C lexer behaviour).
	bl, err := parseInto(t, "1.2.3.4\nabc\n", blacklist.TypeBlack)
	if err != nil || bl.Count != 2 {
		t.Fatalf("unknown char: %v count %d", err, bl.Count)
	}
	// Entries before the error are retained.
	bl, err = parseInto(t, "1.1.1.1\n2.2.2.2\n1.2.3\n", blacklist.TypeBlack)
	if err == nil || bl.Count != 4 {
		t.Fatalf("partial parse: %v count %d", err, bl.Count)
	}
}

func TestWhitelistType(t *testing.T) {
	bl := blacklist.New("t", "m", blacklist.StorageList)
	if err := Parse(strings.NewReader("10.0.0.0/8\n"), bl, blacklist.TypeBlack); err != nil {
		t.Fatal(err)
	}
	if err := Parse(strings.NewReader("10.1.0.0/16\n"), bl, blacklist.TypeWhite); err != nil {
		t.Fatal(err)
	}
	got := bl.Collapse()
	if len(got) == 0 || got[0] != "10.0.0.0/16" {
		t.Fatalf("got %v", got)
	}
	for _, c := range got {
		if c == "10.1.0.0/16" {
			t.Fatal("whitelisted block must be removed")
		}
	}
}

func TestOpenMaybeGzip(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte("1.2.3.4\n"))
	_ = w.Close()

	r, err := OpenMaybeGzip(&gz)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(r)
	if string(data) != "1.2.3.4\n" {
		t.Fatalf("gzip content %q", data)
	}

	r, err = OpenMaybeGzip(strings.NewReader("5.6.7.8\n"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(r)
	if string(data) != "5.6.7.8\n" {
		t.Fatalf("plain content %q", data)
	}

	r, err = OpenMaybeGzip(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := io.ReadAll(r); len(data) != 0 {
		t.Fatal("empty")
	}
}

func TestScannerPos(t *testing.T) {
	s := NewScanner(strings.NewReader("1.2\n3"))
	for s.Next().Kind != TokEOL {
	}
	line, col := s.Pos()
	if line != 1 || col != 0 {
		t.Fatalf("pos after EOL = %d,%d", line, col)
	}
}
