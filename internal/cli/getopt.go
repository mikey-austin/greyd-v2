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

// Package cli implements the getopt(3) style option parsing shared by the
// four programs, so that the switches keep the exact semantics of the C
// implementation: single dash, bundled flags (-dvF), an argument either
// attached (-fFILE) or separate (-f FILE), and "--" ending the options.
package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Opt is one parsed option.
type Opt struct {
	Flag byte
	// Arg is set for options declared with a trailing ':' in the spec.
	Arg string
}

// ErrUsage wraps every parse error so callers can print their usage text.
var ErrUsage = errors.New("usage")

// UnknownOptionError reports a flag not in the spec.
type UnknownOptionError struct{ Flag byte }

func (e *UnknownOptionError) Error() string { return fmt.Sprintf("invalid option -- '%c'", e.Flag) }
func (e *UnknownOptionError) Unwrap() error { return ErrUsage }

// MissingArgError reports an option given without its argument.
type MissingArgError struct{ Flag byte }

func (e *MissingArgError) Error() string {
	return fmt.Sprintf("option requires an argument -- '%c'", e.Flag)
}
func (e *MissingArgError) Unwrap() error { return ErrUsage }

// Parse splits args according to spec (for example "adtTDf:Y:"). It
// returns the options in order and the remaining positional arguments.
func Parse(spec string, args []string) (opts []Opt, rest []string, err error) {
	takesArg := map[byte]bool{}
	for i := 0; i < len(spec); i++ {
		c := spec[i]
		if c == ':' {
			continue
		}
		takesArg[c] = i+1 < len(spec) && spec[i+1] == ':'
	}

	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if len(a) < 2 || a[0] != '-' {
			break
		}
		for j := 1; j < len(a); j++ {
			c := a[j]
			needs, ok := takesArg[c]
			if !ok {
				return nil, nil, &UnknownOptionError{Flag: c}
			}
			if !needs {
				opts = append(opts, Opt{Flag: c})
				continue
			}
			var val string
			if j+1 < len(a) {
				val = a[j+1:]
			} else if i+1 < len(args) {
				i++
				val = args[i]
			} else {
				return nil, nil, &MissingArgError{Flag: c}
			}
			opts = append(opts, Opt{Flag: c, Arg: val})
			break
		}
	}
	return opts, args[i:], nil
}

// Int parses an integer option argument.
func (o Opt) Int() (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(o.Arg))
	if err != nil {
		return 0, fmt.Errorf("invalid number for -%c: %q: %w", o.Flag, o.Arg, ErrUsage)
	}
	return n, nil
}
