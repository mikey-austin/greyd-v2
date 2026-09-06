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

// Section is a named group of configuration variables.
type Section struct {
	Name  string
	vars  map[string]*Value
	order []string
}

// NewSection creates an empty section.
func NewSection(name string) *Section {
	return &Section{Name: name, vars: make(map[string]*Value)}
}

// Get returns the raw value for varname, or nil when it is not set.
func (s *Section) Get(varname string) *Value {
	if s == nil {
		return nil
	}
	return s.vars[varname]
}

// Set stores a value, replacing any existing one.
func (s *Section) Set(varname string, v *Value) {
	if _, exists := s.vars[varname]; !exists {
		s.order = append(s.order, varname)
	}
	s.vars[varname] = v
}

// Delete removes a variable if present.
func (s *Section) Delete(varname string) {
	if _, exists := s.vars[varname]; !exists {
		return
	}
	delete(s.vars, varname)
	for i, k := range s.order {
		if k == varname {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// SetInt stores an integer value.
func (s *Section) SetInt(varname string, i int) { s.Set(varname, IntValue(i)) }

// SetStr stores a string value.
func (s *Section) SetStr(varname, val string) { s.Set(varname, StrValue(val)) }

// Int returns the integer value of varname, or def when it is missing or
// not an integer.
func (s *Section) Int(varname string, def int) int {
	v := s.Get(varname)
	if v == nil || v.Type != TypeInt {
		return def
	}
	return v.Int
}

// Str returns the string value of varname, or def when it is missing or not
// a string.
func (s *Section) Str(varname string, def string) string {
	v := s.Get(varname)
	if v == nil || v.Type != TypeStr {
		return def
	}
	return v.Str
}

// List returns the elements of a list variable, or nil when it is missing
// or not a list.
func (s *Section) List(varname string) []*Value {
	v := s.Get(varname)
	if v == nil || v.Type != TypeList {
		return nil
	}
	return v.List
}

// Keys returns the variable names in insertion order.
func (s *Section) Keys() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}
