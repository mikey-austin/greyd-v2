package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSectionGetters(t *testing.T) {
	s := NewSection("section 1")
	s.SetStr("variable 1", "value 1")
	s.SetInt("variable 2", 123)

	if got := s.Str("variable 1", "x"); got != "value 1" {
		t.Fatalf("Str = %q", got)
	}
	if got := s.Int("variable 2", 0); got != 123 {
		t.Fatalf("Int = %d", got)
	}
	// Wrong type and missing values yield the default.
	if got := s.Int("variable 1", 7); got != 7 {
		t.Fatalf("Int wrong type = %d", got)
	}
	if got := s.Str("variable 2", "def"); got != "def" {
		t.Fatalf("Str wrong type = %q", got)
	}
	if got := s.Str("missing", "def"); got != "def" {
		t.Fatalf("Str missing = %q", got)
	}
	if s.List("variable 1") != nil {
		t.Fatal("List of non-list should be nil")
	}
	if got := s.Keys(); !reflect.DeepEqual(got, []string{"variable 1", "variable 2"}) {
		t.Fatalf("Keys = %v", got)
	}
	s.Delete("variable 1")
	if s.Get("variable 1") != nil || len(s.Keys()) != 1 {
		t.Fatal("Delete failed")
	}
	// Overwrite keeps a single key.
	s.SetInt("variable 2", 5)
	if len(s.Keys()) != 1 || s.Int("variable 2", 0) != 5 {
		t.Fatal("overwrite failed")
	}
}

func TestValueClone(t *testing.T) {
	l := ListValue(IntValue(1), StrValue("a"), ListValue(IntValue(2)))
	c := l.Clone()
	c.List[1].Str = "b"
	c.List[2].List[0].Int = 3
	if l.List[1].Str != "a" || l.List[2].List[0].Int != 2 {
		t.Fatal("clone is not deep")
	}
	if got := l.Strings(); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("Strings = %v", got)
	}
	if got := StrValue("x").Strings(); !reflect.DeepEqual(got, []string{"x"}) {
		t.Fatalf("Strings scalar = %v", got)
	}
	var nilv *Value
	if nilv.Clone() != nil || nilv.Strings() != nil {
		t.Fatal("nil value handling")
	}
}

func TestConfigSectionsAndGetters(t *testing.T) {
	c := New()
	s1 := NewSection("section 1")
	s1.SetStr("variable 1", "value 1")
	s1.SetInt("variable 2", 123)
	c.AddSection(s1)

	if s := c.Section("section 1"); s == nil || s.Name != "section 1" {
		t.Fatal("section fetch failed")
	}
	if c.Section("this section doesn't exist") != nil {
		t.Fatal("expected nil section")
	}
	if got := c.Str("variable 1", "section 1", ""); got != "value 1" {
		t.Fatalf("Str = %q", got)
	}
	if got := c.Int("variable 2", "section 1", 0); got != 123 {
		t.Fatalf("Int = %d", got)
	}
	if got := c.Int("nope", "nosection", 42); got != 42 {
		t.Fatalf("missing section default = %d", got)
	}
	if c.List("variable 1", "section 1") != nil {
		t.Fatal("List should be nil")
	}

	// Default section through the empty name.
	c.SetInt("limit", "", 10)
	if got := c.Int("limit", DefaultSection, 0); got != 10 {
		t.Fatalf("default section Int = %d", got)
	}
	if !c.Bool("limit", "", false) || c.Bool("other", "", false) {
		t.Fatal("Bool")
	}
	c.SetStr("name", "new", "v")
	if c.Section("new") == nil {
		t.Fatal("SetStr should create section")
	}
	c.Delete("name", "new")
	if c.Section("new").Get("name") != nil {
		t.Fatal("Delete failed")
	}
	c.Delete("x", "absent") // no panic

	c.AppendListStr("hosts", "sync", "a")
	c.AppendListStr("hosts", "sync", "b")
	if got := c.StrList("hosts", "sync"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("StrList = %v", got)
	}
	if len(c.List("hosts", "sync")) != 2 {
		t.Fatal("List size")
	}
	if got := c.SectionNames(); !reflect.DeepEqual(got, []string{"section 1", DefaultSection, "new", "sync"}) {
		t.Fatalf("SectionNames = %v", got)
	}

	bl := NewSection("nixspam")
	c.AddBlacklist(bl)
	wl := NewSection("friends")
	c.AddWhitelist(wl)
	if c.Blacklist("nixspam") != bl || c.Whitelist("friends") != wl || c.Blacklist("friends") != nil {
		t.Fatal("blacklist/whitelist storage")
	}
}

func TestMerge(t *testing.T) {
	c := New()
	c.SetInt("port", "", 8025)
	c.SetStr("driver", "database", "sqlite")

	from := New()
	from.SetInt("port", "", 25)
	from.SetStr("hostname", "", "mx")
	from.AppendListStr("hosts", "sync", "eth0")
	from.AddBlacklist(NewSection("bl"))

	c.Merge(from)
	if c.Int("port", "", 0) != 25 || c.Str("hostname", "", "") != "mx" {
		t.Fatal("default section not merged")
	}
	if c.Str("driver", "database", "") != "sqlite" {
		t.Fatal("existing values lost")
	}
	if got := c.StrList("hosts", "sync"); !reflect.DeepEqual(got, []string{"eth0"}) {
		t.Fatalf("new section not created: %v", got)
	}
	if c.Blacklist("bl") != nil {
		t.Fatal("blacklists must not merge")
	}
	// Merged values are clones.
	from.List("hosts", "sync")[0].Str = "changed"
	if c.StrList("hosts", "sync")[0] != "eth0" {
		t.Fatal("merge must clone values")
	}
	c.Merge(nil) // no panic
}

func TestAddInclude(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"b.conf", "a.conf", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x = 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := New()
	c.MarkProcessed(filepath.Join(dir, "b.conf"))
	c.AddInclude(filepath.Join(dir, "*.conf"))
	if got := c.PendingIncludes(); !reflect.DeepEqual(got, []string{filepath.Join(dir, "a.conf")}) {
		t.Fatalf("PendingIncludes = %v", got)
	}
	c.AddInclude(filepath.Join(dir, "none/*.conf")) // no matches, no error
	if len(c.PendingIncludes()) != 1 {
		t.Fatal("unexpected queue growth")
	}
	p, ok := c.popInclude()
	if !ok || p != filepath.Join(dir, "a.conf") {
		t.Fatalf("popInclude = %q %v", p, ok)
	}
	if _, ok := c.popInclude(); ok {
		t.Fatal("queue should be empty")
	}
	if !c.Processed(filepath.Join(dir, "b.conf")) {
		t.Fatal("Processed")
	}
}

func TestExpandTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	if got := expandTilde("~/x.conf"); got != home+"/x.conf" {
		t.Fatalf("expandTilde = %q", got)
	}
	if got := expandTilde("/etc/x"); got != "/etc/x" {
		t.Fatalf("expandTilde = %q", got)
	}
}
