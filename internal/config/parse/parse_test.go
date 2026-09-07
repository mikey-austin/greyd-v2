package parse

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-v2/internal/config"
)

const parserSrc = "test_var_1    =  12345 # This is a comment \n" +
	"# This is another comment followed by a new line \n" +
	"section section_1 {\n" +
	"    test_var_2 = \"long \\\"string\\\"\", # A \"quoted\" string literal\n" +
	"    test_var_3 = 12,\n" +
	"    test_var_4 = [ 1234, \"a string\" ]\n" +
	"} \n" +
	"include \"testdata/config_test1.conf\"\n" +
	"blacklist blacklist_1 {\n" +
	"    ips = [ 222, \"another string\" ],\n" +
	"}\n" +
	"whitelist whitelist_1 {\n" +
	"    ips = [ 0, 1, 2 ]\n" +
	"    limit = 55\n" +
	"}\n"

func TestParseString(t *testing.T) {
	cfg, err := String(parserSrc)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if got := cfg.Int("test_var_1", "", 0); got != 12345 {
		t.Fatalf("test_var_1 = %d", got)
	}
	s := cfg.Section("section_1")
	if s == nil {
		t.Fatal("section_1 missing")
	}
	if got := s.Str("test_var_2", ""); got != `long "string"` {
		t.Fatalf("test_var_2 = %q", got)
	}
	if got := s.Int("test_var_3", 0); got != 12 {
		t.Fatalf("test_var_3 = %d", got)
	}
	if l := s.List("test_var_4"); len(l) != 2 || l[0].Int != 1234 || l[1].Str != "a string" {
		t.Fatalf("test_var_4 = %+v", l)
	}
	bl := cfg.Blacklist("blacklist_1")
	if bl == nil {
		t.Fatal("blacklist missing")
	}
	if l := bl.List("ips"); len(l) != 2 || l[0].Int != 222 || l[1].Str != "another string" {
		t.Fatalf("blacklist ips = %+v", l)
	}
	wl := cfg.Whitelist("whitelist_1")
	if wl == nil {
		t.Fatal("whitelist missing")
	}
	l := wl.List("ips")
	if len(l) != 3 {
		t.Fatalf("whitelist ips size %d", len(l))
	}
	for i, v := range l {
		if v.Int != i {
			t.Fatalf("whitelist ips[%d] = %d", i, v.Int)
		}
	}
	if got := wl.Int("limit", 0); got != 55 {
		t.Fatalf("limit = %d", got)
	}
	if got := cfg.PendingIncludes(); !reflect.DeepEqual(got, []string{"testdata/config_test1.conf"}) {
		t.Fatalf("includes = %v", got)
	}
}

// The lexer fixture from the C test-suite contains a section without a
// name; the C parser rejects it too, so we only expect a positioned error.
func TestLexerFixtureIsRejectedAtSection(t *testing.T) {
	data, err := os.ReadFile("testdata/config_lexer_test1.conf")
	if err != nil {
		t.Fatal(err)
	}
	_, err = String(string(data))
	var pe *Error
	if !errors.As(err, &pe) || pe.Line != 9 {
		t.Fatalf("expected error on line 9, got %v", err)
	}
}

func TestSyntaxVariants(t *testing.T) {
	cases := []struct {
		name string
		src  string
		chk  func(t *testing.T, c *config.Config)
	}{
		{"case insensitive keyword and lowercased names", "Section GREY { Enable = 1 }", func(t *testing.T, c *config.Config) {
			if c.Int("enable", "grey", 0) != 1 {
				t.Fatal("grey.enable")
			}
		}},
		{"empty list", "x = []", func(t *testing.T, c *config.Config) {
			if l := c.List("x", ""); l == nil || len(l) != 0 {
				t.Fatalf("x = %v", l)
			}
		}},
		{"trailing comma", "x = [1, 2,]", func(t *testing.T, c *config.Config) {
			if len(c.List("x", "")) != 2 {
				t.Fatal("x size")
			}
		}},
		{"multi-line list", "x = [\n 1,\n 2\n]\n", func(t *testing.T, c *config.Config) {
			if len(c.List("x", "")) != 2 {
				t.Fatal("x size")
			}
		}},
		{"semicolon separators", "a = 1; b = 2", func(t *testing.T, c *config.Config) {
			if c.Int("a", "", 0) != 1 || c.Int("b", "", 0) != 2 {
				t.Fatal("a/b")
			}
		}},
		{"comma separated section assignments on one line", "section s { a = 1, b = 2 }", func(t *testing.T, c *config.Config) {
			if c.Int("a", "s", 0) != 1 || c.Int("b", "s", 0) != 2 {
				t.Fatal("s.a/s.b")
			}
		}},
		{"multi-line string", "message = \"line one\\\\n\n   line two\"\n", func(t *testing.T, c *config.Config) {
			want := "line one\\n\n   line two"
			if got := c.Str("message", "", ""); got != want {
				t.Fatalf("message = %q want %q", got, want)
			}
		}},
		{"section replaces existing", "section s { a = 1 }\nsection s { b = 2 }\n", func(t *testing.T, c *config.Config) {
			if c.Section("s").Get("a") != nil || c.Int("b", "s", 0) != 2 {
				t.Fatal("section not replaced")
			}
		}},
		{"leading and trailing newlines and comments", "\n\n# c\n\na = 1\n\n# end\n", func(t *testing.T, c *config.Config) {
			if c.Int("a", "", 0) != 1 {
				t.Fatal("a")
			}
		}},
		{"empty input", "", func(t *testing.T, c *config.Config) {
			if c.Section(config.DefaultSection) == nil {
				t.Fatal("default section must exist")
			}
		}},
		{"escaped backslash", `x = "a\\b"`, func(t *testing.T, c *config.Config) {
			if got := c.Str("x", "", ""); got != `a\b` {
				t.Fatalf("x = %q", got)
			}
		}},
		{"windows line endings", "a = 1\r\nb = 2\r\n", func(t *testing.T, c *config.Config) {
			if c.Int("a", "", 0) != 1 || c.Int("b", "", 0) != 2 {
				t.Fatal("a/b")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := String(tc.src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			tc.chk(t, c)
		})
	}
}

func TestSyntaxErrors(t *testing.T) {
	cases := []struct {
		src  string
		line int
	}{
		{"foo = @\n", 1},
		{"a = 1\nsection { }\n", 2},
		{"a = \"unterminated\n", 1},
		{"a = [1, 2\n", 2},
		{"x = 99999999999999999999\n", 1},
		{"a = 1\nb = 2 c = 3\n", 2},
	}
	for _, tc := range cases {
		_, err := String(tc.src)
		var pe *Error
		if !errors.As(err, &pe) {
			t.Fatalf("%q: expected *Error, got %v", tc.src, err)
		}
		if pe.Line != tc.line {
			t.Fatalf("%q: line %d, want %d (%v)", tc.src, pe.Line, tc.line, pe)
		}
		if !strings.Contains(pe.Error(), "line ") {
			t.Fatalf("error text %q", pe.Error())
		}
	}
}

func TestLoadFileWithIncludes(t *testing.T) {
	cfg := config.New()
	if err := cfg.LoadFile("testdata/config_test1.conf"); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	// config_test1 sets limit = 10, config_test2 overrides to 25.
	if got := cfg.Int("limit", "", 0); got != 25 {
		t.Fatalf("limit = %d", got)
	}
	if got := cfg.Str("another_global", "", ""); got != "this is overwritten" {
		t.Fatalf("another_global = %q", got)
	}
	if got := cfg.Str("ip_address", "", ""); got != "1.2.3.4" {
		t.Fatalf("ip_address = %q", got)
	}
	if got := cfg.Str("storage_driver", "storage", ""); got != "MySQL" {
		t.Fatalf("storage_driver = %q", got)
	}
	if got := cfg.Int("db_port", "storage", 0); got != 3306 {
		t.Fatalf("db_port = %d", got)
	}
	if got := cfg.Int("port", "cache", 0); got != 11211 {
		t.Fatalf("cache.port = %d", got)
	}
	for _, f := range []string{"testdata/config_test1.conf", "testdata/config_test2.conf", "testdata/config_test3.conf"} {
		if !cfg.Processed(f) {
			t.Fatalf("%s not processed", f)
		}
	}
	if len(cfg.PendingIncludes()) != 0 {
		t.Fatal("includes left in queue")
	}
}

func TestLoadFileErrors(t *testing.T) {
	cfg := config.New()
	if err := cfg.LoadFile("testdata/does-not-exist.conf"); err == nil {
		t.Fatal("expected error for missing file")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.conf")
	if err := os.WriteFile(bad, []byte("a = 1\nb = @\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := cfg.LoadFile(bad)
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("expected parse error with line, got %v", err)
	}
}

func TestReader(t *testing.T) {
	cfg, err := Reader(strings.NewReader("a = 1\n"))
	if err != nil || cfg.Int("a", "", 0) != 1 {
		t.Fatalf("Reader: %v", err)
	}
}
