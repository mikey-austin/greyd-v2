/*
 * Copyright (c) 2014-2026 Mikey Austin <mikey@greyd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultSection is the name of the section holding variables assigned
// outside of any explicit section.
const DefaultSection = "default"

// Config is the main configuration table.
type Config struct {
	sections   map[string]*Section
	blacklists map[string]*Section
	whitelists map[string]*Section
	order      []string
	processed  map[string]bool
	includes   []string
}

// New creates an empty configuration.
func New() *Config {
	return &Config{
		sections:   make(map[string]*Section),
		blacklists: make(map[string]*Section),
		whitelists: make(map[string]*Section),
		processed:  make(map[string]bool),
	}
}

// AddSection adds (or replaces) a section.
func (c *Config) AddSection(s *Section) {
	if _, exists := c.sections[s.Name]; !exists {
		c.order = append(c.order, s.Name)
	}
	c.sections[s.Name] = s
}

// AddBlacklist adds (or replaces) a blacklist definition.
func (c *Config) AddBlacklist(s *Section) { c.blacklists[s.Name] = s }

// AddWhitelist adds (or replaces) a whitelist definition.
func (c *Config) AddWhitelist(s *Section) { c.whitelists[s.Name] = s }

// Section returns the named section or nil. An empty name selects the
// default section.
func (c *Config) Section(name string) *Section {
	if name == "" {
		name = DefaultSection
	}
	return c.sections[name]
}

// Blacklist returns the named blacklist definition or nil.
func (c *Config) Blacklist(name string) *Section { return c.blacklists[name] }

// Whitelist returns the named whitelist definition or nil.
func (c *Config) Whitelist(name string) *Section { return c.whitelists[name] }

// BlacklistNames returns the blacklist definition names, sorted.
func (c *Config) BlacklistNames() []string { return sortedKeys(c.blacklists) }

// WhitelistNames returns the whitelist definition names, sorted.
func (c *Config) WhitelistNames() []string { return sortedKeys(c.whitelists) }

func sortedKeys(m map[string]*Section) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SectionNames returns the section names in insertion order.
func (c *Config) SectionNames() []string {
	out := make([]string, len(c.order))
	copy(out, c.order)
	return out
}

// section returns the named section, creating it when create is set.
func (c *Config) section(name string, create bool) *Section {
	if name == "" {
		name = DefaultSection
	}
	s := c.sections[name]
	if s == nil && create {
		s = NewSection(name)
		c.AddSection(s)
	}
	return s
}

// Int returns an integer variable from the named section (empty selects
// the default section), or def when missing.
func (c *Config) Int(varname, section string, def int) int {
	s := c.section(section, false)
	if s == nil {
		return def
	}
	return s.Int(varname, def)
}

// Str returns a string variable, or def when missing.
func (c *Config) Str(varname, section string, def string) string {
	s := c.section(section, false)
	if s == nil {
		return def
	}
	return s.Str(varname, def)
}

// Bool interprets an integer variable as a boolean (non-zero is true).
func (c *Config) Bool(varname, section string, def bool) bool {
	d := 0
	if def {
		d = 1
	}
	return c.Int(varname, section, d) != 0
}

// List returns the elements of a list variable, or nil when missing.
func (c *Config) List(varname, section string) []*Value {
	s := c.section(section, false)
	if s == nil {
		return nil
	}
	return s.List(varname)
}

// StrList returns the string elements of a list variable.
func (c *Config) StrList(varname, section string) []string {
	s := c.section(section, false)
	if s == nil {
		return nil
	}
	return s.Get(varname).Strings()
}

// SetInt sets an integer variable, creating the section if required.
func (c *Config) SetInt(varname, section string, v int) {
	c.section(section, true).SetInt(varname, v)
}

// SetStr sets a string variable, creating the section if required.
func (c *Config) SetStr(varname, section string, v string) {
	c.section(section, true).SetStr(varname, v)
}

// Delete removes a variable from a section if it exists.
func (c *Config) Delete(varname, section string) {
	if s := c.section(section, false); s != nil {
		s.Delete(varname)
	}
}

// AppendListStr appends a string to a list variable, creating the section
// and the list when they do not exist.
func (c *Config) AppendListStr(varname, section, str string) {
	s := c.section(section, true)
	v := s.Get(varname)
	if v == nil || v.Type != TypeList {
		v = ListValue()
		s.Set(varname, v)
	}
	v.List = append(v.List, StrValue(str))
}

// Merge copies every section variable of from into c, overriding existing
// values. Blacklists, whitelists and includes are not merged.
func (c *Config) Merge(from *Config) {
	if c == nil || from == nil {
		return
	}
	for _, name := range from.SectionNames() {
		src := from.sections[name]
		dst := c.section(name, true)
		for _, k := range src.Keys() {
			dst.Set(k, src.Get(k).Clone())
		}
	}
}

// AddInclude expands the supplied pattern (shell globbing and a leading
// "~") and queues every matching file that has not yet been processed.
func (c *Config) AddInclude(pattern string) {
	pattern = expandTilde(pattern)
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return
	}
	sort.Strings(matches)
	for _, m := range matches {
		if !c.processed[m] {
			c.includes = append(c.includes, m)
		}
	}
}

// MarkProcessed records that a file has been loaded.
func (c *Config) MarkProcessed(path string) { c.processed[path] = true }

// Processed reports whether a file has been loaded.
func (c *Config) Processed(path string) bool { return c.processed[path] }

// PendingIncludes returns the queued include files.
func (c *Config) PendingIncludes() []string {
	out := make([]string, len(c.includes))
	copy(out, c.includes)
	return out
}

// popInclude dequeues the next include file.
func (c *Config) popInclude() (string, bool) {
	if len(c.includes) == 0 {
		return "", false
	}
	p := c.includes[0]
	c.includes = c.includes[1:]
	return p, true
}

func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return home + p[1:]
		}
	}
	return p
}
