package ipc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-golang/internal/core"
)

// FuzzDecode checks the frame codec never panics and only reports the
// documented error kinds.
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"type = 1\nip = \"1.2.3.4\"\nhelo = \"h\"\nfrom = \"f\"\nto = \"t\"\n",
		"type = 2\nip = \"1.1.1.1\"\nsource = \"s\"\nexpires = \"5\"\ndelete = 1\n",
		"name=\"bl\"\nmessage=\"m %A\"\nips=[\"10.0.0.0/8\", 1]\n",
		"type=\"replace\"\nname=\"w\"\naf=6\nips=[\"::1/128\"]\n",
		"type=\"nat\"\nsrc=\"1.1.1.1\"\nsrc_port=1\nproxy=\"2.2.2.2\"\nproxy_port=25\n",
		"dst=\"1.1.1.1\"\n", "x = \"a\\\"b\"", "= 1", "ips = [ \"a\"", "# only a comment\n", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		m, err := Decode(body)
		if err == nil {
			if m == nil {
				t.Fatal("nil message without error")
			}
			return
		}
		var se *SyntaxError
		var ie *IncompleteError
		if !errors.As(err, &se) && !errors.As(err, &ie) && !errors.Is(err, ErrUnknownMessage) {
			t.Fatalf("unexpected error kind %T: %v", err, err)
		}
	})
}

// FuzzReader feeds arbitrary streams through the frame reader.
func FuzzReader(f *testing.F) {
	f.Add("dst=\"x\"\n%%\ntype = 9\n%%\n", 4096)
	f.Add(strings.Repeat("x", 200)+"\n%%\n", 64)
	f.Add("%%\n%%\n%%", 1024)
	f.Fuzz(func(t *testing.T, stream string, max int) {
		r := NewReader(strings.NewReader(stream))
		if max > 0 {
			r.SetMaxFrame(max)
		}
		for i := 0; i < 1000; i++ {
			_, err := r.Next()
			if errors.Is(err, io.EOF) {
				return
			}
		}
		t.Fatal("reader did not reach EOF")
	})
}

// TestWriteDecodeRoundTrip is a property test over the writers and Decode.
func TestWriteDecodeRoundTrip(t *testing.T) {
	strs := []string{"", "a", "with space", `quo"te`, `back\slash`, "multi\nline", "üñí", strings.Repeat("z", 3000), "%%", "#hash"}
	var buf bytes.Buffer
	for _, helo := range strs {
		for _, from := range strs {
			buf.Reset()
			if err := WriteGrey(&buf, "10.0.0.1", "1.2.3.4", helo, from, "to@x"); err != nil {
				t.Fatal(err)
			}
			m, err := NewReader(&buf).Next()
			if err != nil {
				t.Fatalf("helo=%q from=%q: %v", helo, from, err)
			}
			g := m.(*GreyMessage)
			want := core.Tuple{IP: "1.2.3.4", Helo: Sanitize(helo), From: Sanitize(from), To: "to@x"}
			if g.Tuple != want || g.DstIP != "10.0.0.1" {
				t.Fatalf("helo=%q from=%q: got %+v", helo, from, g)
			}
		}
	}
	// Blacklist names and messages come from greyd.conf and are written
	// verbatim (their escape sequences are for the receiving parser, as in
	// the C implementation), so quotes and backslashes are out of scope.
	for _, name := range strs {
		if strings.ContainsAny(name, "\"\\") {
			continue
		}
		buf.Reset()
		if err := WriteBlacklist(&buf, name, name, []string{"1.2.3.4", "10.0.0.0/8"}); err != nil {
			t.Fatal(err)
		}
		m, err := NewReader(&buf).Next()
		if err != nil {
			t.Fatalf("name=%q: %v", name, err)
		}
		bl := m.(*BlacklistMessage)
		if bl.Name != name || bl.Message != name || len(bl.IPs) != 2 {
			t.Fatalf("name=%q: got %+v", name, bl)
		}
	}
}

func BenchmarkDecodeGrey(b *testing.B) {
	var buf bytes.Buffer
	_ = WriteGrey(&buf, "10.0.0.1", "192.0.2.44", "mx.example.org", "sender@example.org", "rcpt@example.net")
	body := strings.TrimSuffix(buf.String(), "%%\n")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(body); err != nil {
			b.Fatal(err)
		}
	}
}
