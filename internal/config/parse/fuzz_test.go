package parse

import (
	"errors"
	"os"
	"testing"
)

// FuzzString feeds arbitrary text to the ANTLR based configuration
// parser; it must return a configuration or an *Error, never panic. The
// runtime is not goroutine safe, so this fuzz test must not be parallel.
func FuzzString(f *testing.F) {
	f.Add("hostname = \"h\"\nport = 8025\nsection grey { enable = 1 }\nblacklist b { file = \"x\" }\n")
	f.Add("include \"/nonexistent\"\n")
	f.Add("a = [ 1, \"two\", 3 ]\n# comment\nsection s {\n}\n")
	f.Add("x = \"unterminated\n")
	f.Add("section { }")
	f.Add("")
	f.Fuzz(func(t *testing.T, src string) {
		cfg, err := String(src)
		if err != nil {
			var perr *Error
			if !errors.As(err, &perr) {
				t.Fatalf("unexpected error %T: %v", err, err)
			}
			return
		}
		if cfg == nil {
			t.Fatal("nil config without error")
		}
	})
}

func BenchmarkParseSampleConfig(b *testing.B) {
	src, err := os.ReadFile("../../../etc/greyd.conf.in")
	if err != nil {
		b.Skip("sample configuration not available")
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		if _, err := String(string(src)); err != nil {
			b.Fatal(err)
		}
	}
}
