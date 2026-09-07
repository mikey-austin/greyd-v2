package settings

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/config/parse"
)

// expectedWarnings lists, per corpus file, the warnings a sample is allowed
// (and required) to produce. Files not listed must load without warnings.
var expectedWarnings = map[string][]string{
	// Syntax examples from the manual use a placeholder option name.
	"doc-conf5-syntax.conf": {`unknown variable "variable" in section default`},
	// The C implementation read low_prio_mx from the default section.
	"legacy-low-prio-mx.conf": {"low_prio_mx belongs in the grey section"},
}

// TestCorpusLoads parses and loads every configuration in
// testdata/configs (see the README there for their origins).
func TestCorpusLoads(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "configs", "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 10 {
		t.Fatalf("corpus too small: %d files", len(files))
	}
	seen := map[string]bool{}
	for _, path := range files {
		name := filepath.Base(path)
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := parse.String(string(src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			s, err := Load(cfg)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			got := append([]string(nil), s.Warnings...)
			want := append([]string(nil), expectedWarnings[name]...)
			sort.Strings(got)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("warnings\n got: %q\nwant: %q", got, want)
			}
		})
	}
	for name := range expectedWarnings {
		if !seen[name] {
			t.Errorf("expectedWarnings names %s, which is not in the corpus", name)
		}
	}
}

// TestShippedSamplesMatchTemplates checks that the corpus copies of this
// repository's etc/*.conf.in templates are still the templates with the
// placeholders substituted, so an edit to a template shows up here.
func TestShippedSamplesMatchTemplates(t *testing.T) {
	placeholders := strings.NewReplacer(
		"@libdir@", "/usr/lib",
		"@PACKAGE@", "greyd",
		"@localstatedir@", "/var",
		"@sysconfdir@", "/etc",
		"@CURL@", "/usr/bin/curl",
		"@GREYD_PIDFILE@", "/var/empty/greyd/greyd.pid",
		"@GREYLOGD_PIDFILE@", "/var/empty/greylogd/greylogd.pid",
	)
	for tmpl, corpus := range map[string]string{
		"greyd.conf.in":        "go-etc-greyd.conf",
		"greyd.docker.conf.in": "go-etc-greyd.docker.conf",
	} {
		want, err := os.ReadFile(filepath.Join("..", "..", "etc", tmpl))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join("testdata", "configs", corpus))
		if err != nil {
			t.Fatal(err)
		}
		if placeholders.Replace(string(want)) != string(got) {
			t.Errorf("%s no longer matches etc/%s: regenerate it (see testdata/configs/README.md)", corpus, tmpl)
		}
	}
}

// docSections maps the "## ..." headings of greyd.conf.5.md that
// introduce options to the configuration section their options live in.
// Headings that carry no options are not listed; an option under an
// unlisted heading fails the test so the map is kept current.
var docSections = map[string]string{
	"GENERAL OPTIONS":         config.DefaultSection,
	"FIREWALL SECTION":        "firewall",
	"DATABASE SECTION":        "database",
	"GREY SECTION":            "grey",
	"SYNCHRONISATION SECTION": "sync",
	"SPF SECTION":             "spf",
	"MONITOR SECTION":         "monitor",
	"SETUP SECTION":           "setup",
	"BLACKLIST CONFIGURATION": "blacklist",
}

// undocumentedOptions lists options the loader accepts that greyd.conf.5.md
// does not describe yet, by section; remove an entry once it is documented.
var undocumentedOptions = map[string]map[string]bool{}

// driverSections are the sections whose options are read by the adapters
// from the raw configuration rather than decoded into a struct.
var driverSections = map[string]bool{"firewall": true, "database": true}

type docOption struct {
	section, name, typ string
	line               int
}

var (
	docHeadingRe = regexp.MustCompile(`^## (.+?)\s*$`)
	docOptionRe  = regexp.MustCompile(`^\* \*\*([A-Za-z0-9_]+)\*\* = \*([a-z]+)\*:`)
)

// readDocOptions extracts every "* **name** = *type*:" entry of the
// manual together with the section of the heading above it.
func readDocOptions(t *testing.T) []docOption {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "doc", "greyd.conf.5.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var (
		opts    []docOption
		heading string
		lineNo  int
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if m := docHeadingRe.FindStringSubmatch(line); m != nil {
			heading = m[1]
			continue
		}
		m := docOptionRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		sec, ok := docSections[heading]
		if !ok {
			t.Errorf("greyd.conf.5.md:%d: option %s under heading %q, which docSections does not map to a section", lineNo, m[1], heading)
			continue
		}
		opts = append(opts, docOption{section: sec, name: m[1], typ: m[2], line: lineNo})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(opts) < 40 {
		t.Fatalf("only %d documented options found; has the manual's format changed?", len(opts))
	}
	return opts
}

// typedSectionOptions returns the variable names the loader knows for
// each section decoded into a struct, straight from the struct tags.
func typedSectionOptions(t *testing.T) map[string]map[string]bool {
	t.Helper()
	targets := map[string]any{
		config.DefaultSection: &Global{},
		"grey":                &Grey{},
		"sync":                &Sync{},
		"spf":                 &SPF{},
		"setup":               &Setup{},
		"monitor":             &Monitor{},
		"firewall":            &Firewall{},
		"database":            &Database{},
	}
	out := map[string]map[string]bool{}
	for name, dst := range targets {
		known, err := decode(dst, nil)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = known
	}
	// low_prio_mx is additionally accepted in the default section for
	// compatibility with the C implementation.
	out[config.DefaultSection]["low_prio_mx"] = true
	return out
}

var (
	// cfg.Str("max_elements", "firewall", ...) and friends in the adapters.
	rawOptionRe = regexp.MustCompile(`\.(?:Str|Int|Bool|List|StrList)\(\s*"([A-Za-z0-9_]+)"\s*,\s*"(firewall|database)"`)
	// section.Str("message", ...) in internal/setup, reading list definitions.
	listFieldRe = regexp.MustCompile(`\bsection\.(?:Str|Int|List)\(\s*"([A-Za-z0-9_]+)"`)
)

// sourceReadOptions scans the non-test Go sources of the repository for
// the driver options read from the firewall and database sections and
// the fields read from blacklist/whitelist definitions. Every file is
// read as text, so options of drivers built only on other platforms are
// included.
func sourceReadOptions(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{"firewall": {}, "database": {}, "blacklist": {}}
	for _, root := range []string{"adapters", "internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join("..", "..", root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range rawOptionRe.FindAllStringSubmatch(string(src), -1) {
				out[m[2]][m[1]] = true
			}
			if strings.Contains(filepath.ToSlash(path), "/internal/setup/") {
				for _, m := range listFieldRe.FindAllStringSubmatch(string(src), -1) {
					out["blacklist"][m[1]] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for sec, opts := range out {
		if len(opts) == 0 {
			t.Fatalf("no options read from the %s section found in the sources; has the scan pattern gone stale?", sec)
		}
	}
	return out
}

// TestDocumentedOptionsAreKnown checks that every option documented in
// greyd.conf.5.md is one the loader accepts in its section (for the typed
// sections) or one an adapter reads (for the driver sections and list
// definitions), and the reverse: every option the code knows is
// documented. The first direction is what a user hits when following the
// manual; the loader would warn "unknown variable" for a typed section.
func TestDocumentedOptionsAreKnown(t *testing.T) {
	docs := readDocOptions(t)
	typed := typedSectionOptions(t)
	read := sourceReadOptions(t)

	known := func(sec string) map[string]bool {
		out := map[string]bool{}
		for k := range typed[sec] {
			out[k] = true
		}
		for k := range read[sec] {
			out[k] = true
		}
		return out
	}

	documented := map[string]map[string]bool{}
	for _, o := range docs {
		if documented[o.section] == nil {
			documented[o.section] = map[string]bool{}
		}
		documented[o.section][o.name] = true
		if !known(o.section)[o.name] {
			what := "the loader would warn about it as unknown"
			if driverSections[o.section] || o.section == "blacklist" {
				what = "no driver or tool reads it"
			}
			t.Errorf("greyd.conf.5.md:%d: documented option %q in section %s: %s", o.line, o.name, o.section, what)
		}
		switch o.typ {
		case "boolean", "number", "string", "list":
		default:
			t.Errorf("greyd.conf.5.md:%d: option %q has unexpected type %q", o.line, o.name, o.typ)
		}
	}

	// Reverse direction: everything the code accepts is in the manual.
	for sec, opts := range typed {
		for name := range opts {
			if sec == config.DefaultSection && name == "low_prio_mx" {
				continue // documented in the grey section, accepted here for compatibility
			}
			if !documented[sec][name] && !undocumentedOptions[sec][name] {
				t.Errorf("option %q of section %s is accepted by the loader but not documented in greyd.conf.5.md", name, sec)
			}
		}
	}
	for sec, opts := range read {
		for name := range opts {
			if !documented[sec][name] {
				t.Errorf("option %q of section %s is read by the code but not documented in greyd.conf.5.md", name, sec)
			}
		}
	}
}

// TestDocumentedOptionsLoadCleanly loads a configuration that sets every
// documented option of the typed sections to a value of its documented
// type and checks the loader reports no unknown variables. This exercises
// the same path a user's file takes, complementing the tag based check.
func TestDocumentedOptionsLoadCleanly(t *testing.T) {
	var sb strings.Builder
	perSection := map[string][]docOption{}
	var order []string
	for _, o := range readDocOptions(t) {
		if driverSections[o.section] || o.section == "blacklist" {
			continue
		}
		if _, ok := perSection[o.section]; !ok {
			order = append(order, o.section)
		}
		perSection[o.section] = append(perSection[o.section], o)
	}
	value := func(o docOption) string {
		switch o.typ {
		case "boolean":
			return "1"
		case "number":
			switch o.name {
			case "stutter", "ttl":
				return "1" // capped at 10, 100 and 255 by the validator
			}
			// Large enough for every minimum the validator imposes.
			return "8192"
		case "list":
			return `[ "a", "b" ]`
		default:
			if o.name == "error_code" {
				return `"550"`
			}
			return `"x"`
		}
	}
	for _, sec := range order {
		if sec != config.DefaultSection {
			fmt.Fprintf(&sb, "section %s {\n", sec)
		}
		for _, o := range perSection[sec] {
			fmt.Fprintf(&sb, "  %s = %s\n", o.name, value(o))
		}
		if sec != config.DefaultSection {
			sb.WriteString("}\n")
		}
	}
	cfg, err := parse.String(sb.String())
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, sb.String())
	}
	s, err := Load(cfg)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, sb.String())
	}
	for _, w := range s.Warnings {
		if strings.HasPrefix(w, "unknown variable") {
			t.Errorf("documented option rejected: %s", w)
		}
	}
}
