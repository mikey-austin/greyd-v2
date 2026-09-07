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

// Package parse turns greyd.conf(5) text into a config.Config using the
// ANTLR generated parser. Importing this package installs it as the
// config package's parser, enabling Config.LoadFile.
package parse

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/antlr4-go/antlr/v4"

	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/config/grammar"
)

// Error describes a syntax error with its position (1-based line, 0-based
// column as reported by ANTLR).
type Error struct {
	Line, Col int
	Msg       string
}

func (e *Error) Error() string {
	return fmt.Sprintf("line %d col %d: %s", e.Line, e.Col, e.Msg)
}

func init() {
	config.Parser = Into
}

// parseMu serialises parses: the ANTLR runtime shares adaptive prediction
// state between parser instances and is not safe for concurrent use.
var parseMu sync.Mutex

// errorListener records the first syntax error.
type errorListener struct {
	*antlr.DefaultErrorListener
	err *Error
}

func (l *errorListener) SyntaxError(_ antlr.Recognizer, _ any, line, column int, msg string, _ antlr.RecognitionException) {
	if l.err == nil {
		l.err = &Error{Line: line, Col: column, Msg: msg}
	}
}

// String parses src into a fresh configuration.
func String(src string) (*config.Config, error) {
	cfg := config.New()
	if err := Into(cfg, src); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Reader parses everything from r into a fresh configuration.
func Reader(r io.Reader) (*config.Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return String(string(data))
}

// Into parses src and applies the statements to cfg. Assignments outside
// of a section go into the default section, which is created if missing.
// A section, blacklist or whitelist definition replaces any existing one
// of the same name, matching the behaviour of the C parser.
func Into(cfg *config.Config, src string) error {
	parseMu.Lock()
	defer parseMu.Unlock()

	el := &errorListener{DefaultErrorListener: antlr.NewDefaultErrorListener()}

	input := antlr.NewInputStream(src)
	lexer := grammar.NewGreydConfLexer(input)
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(el)

	stream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	parser := grammar.NewGreydConfParser(stream)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(el)

	tree := parser.Config()
	if el.err != nil {
		return el.err
	}

	if cfg.Section(config.DefaultSection) == nil {
		cfg.AddSection(config.NewSection(config.DefaultSection))
	}

	b := &builder{cfg: cfg}
	if err := b.config(tree.(*grammar.ConfigContext)); err != nil {
		return err
	}
	return nil
}

type builder struct {
	cfg *config.Config
}

func (b *builder) config(ctx *grammar.ConfigContext) error {
	for _, st := range ctx.AllStatement() {
		if err := b.statement(st.(*grammar.StatementContext)); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) statement(ctx *grammar.StatementContext) error {
	switch {
	case ctx.Assignment() != nil:
		return b.assignment(ctx.Assignment().(*grammar.AssignmentContext), b.cfg.Section(config.DefaultSection))
	case ctx.Section() != nil:
		return b.section(ctx.Section().(*grammar.SectionContext))
	case ctx.Include() != nil:
		b.cfg.AddInclude(unquote(ctx.Include().STRING().GetText()))
		return nil
	}
	return nil
}

func (b *builder) assignment(ctx *grammar.AssignmentContext, sec *config.Section) error {
	name := strings.ToLower(ctx.NAME().GetText())
	v, err := b.value(ctx.Value())
	if err != nil {
		return err
	}
	sec.Set(name, v)
	return nil
}

func (b *builder) section(ctx *grammar.SectionContext) error {
	name := strings.ToLower(ctx.NAME().GetText())
	sec := config.NewSection(name)

	st := ctx.SectionType().(*grammar.SectionTypeContext)
	switch {
	case st.BLACKLIST() != nil:
		b.cfg.AddBlacklist(sec)
	case st.WHITELIST() != nil:
		b.cfg.AddWhitelist(sec)
	default:
		b.cfg.AddSection(sec)
	}

	for _, a := range ctx.AllAssignment() {
		if err := b.assignment(a.(*grammar.AssignmentContext), sec); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) value(ctx grammar.IValueContext) (*config.Value, error) {
	switch v := ctx.(type) {
	case *grammar.IntValueContext:
		tok := v.INT().GetSymbol()
		i, err := strconv.Atoi(tok.GetText())
		if err != nil {
			return nil, &Error{Line: tok.GetLine(), Col: tok.GetColumn(), Msg: "integer out of range"}
		}
		return config.IntValue(i), nil
	case *grammar.StrValueContext:
		return config.StrValue(unquote(v.STRING().GetText())), nil
	case *grammar.ListValueContext:
		l := v.List().(*grammar.ListContext)
		out := config.ListValue()
		for _, e := range l.AllValue() {
			ev, err := b.value(e)
			if err != nil {
				return nil, err
			}
			out.List = append(out.List, ev)
		}
		return out, nil
	}
	return nil, &Error{Msg: "unknown value type"}
}

// unquote strips the surrounding quotes and processes escapes the way the C
// lexer did: a backslash is dropped and the following character kept.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if !strings.Contains(s, "\\") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && !esc {
			esc = true
			continue
		}
		sb.WriteByte(c)
		esc = false
	}
	return sb.String()
}
