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

// Package config implements the greyd configuration model: a set of named
// sections holding integer, string and list values, plus separately kept
// blacklist and whitelist definitions and the include file queue. The
// on-disk syntax is parsed by the parse sub-package.
package config

// ValueType identifies the kind of data held by a Value.
type ValueType int

const (
	// TypeInt is an integer value.
	TypeInt ValueType = 1
	// TypeStr is a string value.
	TypeStr ValueType = 2
	// TypeList is a list of integer and string values.
	TypeList ValueType = 3
)

// Value is a single configuration value.
type Value struct {
	Type ValueType
	Int  int
	Str  string
	List []*Value
}

// IntValue creates an integer value.
func IntValue(i int) *Value { return &Value{Type: TypeInt, Int: i} }

// StrValue creates a string value.
func StrValue(s string) *Value { return &Value{Type: TypeStr, Str: s} }

// ListValue creates a list value holding the supplied elements.
func ListValue(vals ...*Value) *Value {
	l := &Value{Type: TypeList, List: make([]*Value, 0, len(vals))}
	l.List = append(l.List, vals...)
	return l
}

// Clone returns a deep copy of the value.
func (v *Value) Clone() *Value {
	if v == nil {
		return nil
	}
	c := &Value{Type: v.Type, Int: v.Int, Str: v.Str}
	if v.Type == TypeList {
		c.List = make([]*Value, len(v.List))
		for i, e := range v.List {
			c.List[i] = e.Clone()
		}
	}
	return c
}

// Strings returns the string elements of a list value (non-string elements
// are skipped). For a string value a single element slice is returned.
func (v *Value) Strings() []string {
	if v == nil {
		return nil
	}
	switch v.Type {
	case TypeStr:
		return []string{v.Str}
	case TypeList:
		out := make([]string, 0, len(v.List))
		for _, e := range v.List {
			if e != nil && e.Type == TypeStr {
				out = append(out, e.Str)
			}
		}
		return out
	}
	return nil
}
