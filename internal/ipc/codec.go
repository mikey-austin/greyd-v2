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

package ipc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mikey-austin/greyd-golang/internal/core"
)

// Message is a decoded frame. The concrete types below cover every frame
// exchanged between the greyd processes, greyd-setup and greyd's
// configuration socket.
type Message interface{ isMessage() }

// GreyMessage carries a greylist tuple to the greylister (type = 1).
type GreyMessage struct {
	Tuple core.Tuple
	// DstIP is the pre-DNAT destination ("" when unknown).
	DstIP string
	// Sync is false for entries relayed from other hosts.
	Sync bool
}

// AddrMessage carries a white (type = 3) or trapped (type = 2) address.
type AddrMessage struct {
	Type    int
	IP      string
	Source  string
	Expires string
	Sync    bool
	Delete  bool
}

// BlacklistMessage carries a blacklist definition (configuration socket
// and trap pipe).
type BlacklistMessage struct {
	Name    string
	Message string
	IPs     []string
}

// ReplaceRequest asks the firewall process to replace a set.
type ReplaceRequest struct {
	Set string
	AF  int
	IPs []string
}

// NATRequest asks the firewall process for an original destination.
type NATRequest struct {
	Src       string
	SrcPort   uint16
	Proxy     string
	ProxyPort uint16
}

// DstReply answers a NATRequest.
type DstReply struct {
	Dst string
}

// StatsRequest asks greyd for its counters (configuration socket).
type StatsRequest struct{}

// StatsReply answers a StatsRequest: integer counters by name plus the
// loaded blacklists as "name=entries".
type StatsReply struct {
	Counters   map[string]int64
	Blacklists []string
}

// ScanStats is sent by the greylister to the main process after each
// database scan with the entry counts it found.
type ScanStats struct {
	At       int64
	Grey     int64
	White    int64
	Trapped  int64
	Spamtrap int64
	Domain   int64
}

func (*GreyMessage) isMessage()      {}
func (*AddrMessage) isMessage()      {}
func (*BlacklistMessage) isMessage() {}
func (*ReplaceRequest) isMessage()   {}
func (*NATRequest) isMessage()       {}
func (*DstReply) isMessage()         {}
func (*StatsRequest) isMessage()     {}
func (*StatsReply) isMessage()       {}
func (*ScanStats) isMessage()        {}

// ErrUnknownMessage is returned when a frame matches no message type.
var ErrUnknownMessage = errors.New("unknown message")

// IncompleteError reports a recognised message missing a field.
type IncompleteError struct{ Field string }

func (e *IncompleteError) Error() string { return "message missing field " + e.Field }

// SyntaxError reports malformed frame text.
type SyntaxError struct {
	Pos int
	Msg string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("frame syntax error at byte %d: %s", e.Pos, e.Msg)
}

// value is one decoded assignment.
type value struct {
	isInt bool
	n     int
	s     string
	list  []string
	isLst bool
}

// fields is the assignment table of a frame.
type fields map[string]value

func (f fields) str(name string) (string, bool) {
	v, ok := f[name]
	if !ok || v.isLst {
		return "", false
	}
	if v.isInt {
		return strconv.Itoa(v.n), true
	}
	return v.s, true
}

func (f fields) integer(name string) (int, bool) {
	v, ok := f[name]
	if !ok || !v.isInt {
		return 0, false
	}
	return v.n, true
}

func (f fields) strings(name string) ([]string, bool) {
	v, ok := f[name]
	if !ok {
		return nil, false
	}
	if v.isLst {
		return v.list, true
	}
	if !v.isInt {
		return []string{v.s}, true
	}
	return nil, false
}

// Decode parses a frame body into a typed message. The syntax is the
// subset of greyd.conf used on the wire: "name = 1", name = "text",
// name=[ "a", "b" ], with '#' comments; quoted strings may span lines and a
// backslash escapes the following character (as the config lexer did).
func Decode(body string) (Message, error) {
	f, err := parseFields(body)
	if err != nil {
		return nil, err
	}
	return classify(f)
}

func classify(f fields) (Message, error) {
	need := func(name string) (string, error) {
		s, ok := f.str(name)
		if !ok {
			return "", &IncompleteError{Field: name}
		}
		return s, nil
	}
	syncFlag := true
	if n, ok := f.integer("sync"); ok {
		syncFlag = n != 0
	}

	if n, ok := f.integer("type"); ok {
		switch n {
		case MsgGrey:
			var m GreyMessage
			var err error
			if m.Tuple.IP, err = need("ip"); err != nil {
				return nil, err
			}
			if m.Tuple.Helo, err = need("helo"); err != nil {
				return nil, err
			}
			if m.Tuple.From, err = need("from"); err != nil {
				return nil, err
			}
			if m.Tuple.To, err = need("to"); err != nil {
				return nil, err
			}
			m.DstIP, _ = f.str("dst_ip")
			m.Sync = syncFlag
			return &m, nil
		case MsgTrap, MsgWhite:
			m := AddrMessage{Type: n, Sync: syncFlag}
			var err error
			if m.IP, err = need("ip"); err != nil {
				return nil, err
			}
			if m.Source, err = need("source"); err != nil {
				return nil, err
			}
			if m.Expires, err = need("expires"); err != nil {
				return nil, err
			}
			if d, ok := f.integer("delete"); ok {
				m.Delete = d != 0
			}
			return &m, nil
		default:
			return nil, fmt.Errorf("%w: type %d", ErrUnknownMessage, n)
		}
	}

	if typ, ok := f.str("type"); ok {
		switch typ {
		case TypeStats:
			return &StatsRequest{}, nil
		case TypeStatsReply:
			m := StatsReply{Counters: map[string]int64{}}
			for name, v := range f {
				if v.isInt && name != "type" {
					m.Counters[name] = int64(v.n)
				}
			}
			m.Blacklists, _ = f.strings("blacklists")
			return &m, nil
		case TypeScanStats:
			var m ScanStats
			for name, dst := range map[string]*int64{"at": &m.At, "grey": &m.Grey, "white": &m.White, "trapped": &m.Trapped, "spamtrap": &m.Spamtrap, "domain": &m.Domain} {
				if n, ok := f.integer(name); ok {
					*dst = int64(n)
				}
			}
			return &m, nil
		case TypeReplace:
			m := ReplaceRequest{AF: int(core.IPv4)}
			m.Set, _ = f.str("name")
			if af, ok := f.integer("af"); ok {
				m.AF = af
			}
			m.IPs, _ = f.strings("ips")
			return &m, nil
		case TypeNAT:
			var m NATRequest
			m.Src, _ = f.str("src")
			m.Proxy, _ = f.str("proxy")
			if p, ok := f.integer("src_port"); ok && p >= 0 && p <= 65535 {
				m.SrcPort = uint16(p)
			}
			if p, ok := f.integer("proxy_port"); ok && p >= 0 && p <= 65535 {
				m.ProxyPort = uint16(p)
			}
			return &m, nil
		default:
			return nil, fmt.Errorf("%w: type %q", ErrUnknownMessage, typ)
		}
	}

	if _, ok := f["ips"]; ok {
		var m BlacklistMessage
		var err error
		if m.Name, err = need("name"); err != nil {
			return nil, err
		}
		if m.Message, err = need("message"); err != nil {
			return nil, err
		}
		ips, ok := f.strings("ips")
		if !ok {
			return nil, &IncompleteError{Field: "ips"}
		}
		m.IPs = ips
		return &m, nil
	}

	if dst, ok := f.str("dst"); ok {
		return &DstReply{Dst: dst}, nil
	}
	return nil, ErrUnknownMessage
}

type scanner struct {
	src string
	pos int
}

func parseFields(body string) (fields, error) {
	sc := &scanner{src: body}
	f := fields{}
	for {
		sc.skipSpace()
		if sc.eof() {
			return f, nil
		}
		name, err := sc.name()
		if err != nil {
			return nil, err
		}
		sc.skipSpace()
		if !sc.consume('=') {
			return nil, sc.errorf("expected '=' after %q", name)
		}
		sc.skipSpace()
		v, err := sc.value()
		if err != nil {
			return nil, err
		}
		f[strings.ToLower(name)] = v
	}
}

func (sc *scanner) eof() bool { return sc.pos >= len(sc.src) }

func (sc *scanner) errorf(format string, a ...any) error {
	return &SyntaxError{Pos: sc.pos, Msg: fmt.Sprintf(format, a...)}
}

func (sc *scanner) skipSpace() {
	for !sc.eof() {
		switch sc.src[sc.pos] {
		case ' ', '\t', '\r', '\n', ';', ',':
			sc.pos++
		case '#':
			for !sc.eof() && sc.src[sc.pos] != '\n' {
				sc.pos++
			}
		default:
			return
		}
	}
}

func (sc *scanner) consume(c byte) bool {
	if !sc.eof() && sc.src[sc.pos] == c {
		sc.pos++
		return true
	}
	return false
}

func isNameChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (sc *scanner) name() (string, error) {
	start := sc.pos
	for !sc.eof() && isNameChar(sc.src[sc.pos]) {
		sc.pos++
	}
	if start == sc.pos {
		return "", sc.errorf("expected a variable name")
	}
	return sc.src[start:sc.pos], nil
}

func (sc *scanner) value() (value, error) {
	if sc.eof() {
		return value{}, sc.errorf("expected a value")
	}
	switch c := sc.src[sc.pos]; c {
	case '"':
		s, err := sc.quoted()
		return value{s: s}, err
	case '[':
		sc.pos++
		v := value{isLst: true, list: []string{}}
		for {
			sc.skipSpace()
			if sc.consume(']') {
				return v, nil
			}
			if sc.eof() {
				return value{}, sc.errorf("unterminated list")
			}
			if sc.src[sc.pos] == '"' {
				s, err := sc.quoted()
				if err != nil {
					return value{}, err
				}
				v.list = append(v.list, s)
			} else if n, ok := sc.number(); ok {
				v.list = append(v.list, strconv.Itoa(n))
			} else {
				return value{}, sc.errorf("unexpected character %q in list", sc.src[sc.pos])
			}
		}
	default:
		if n, ok := sc.number(); ok {
			return value{isInt: true, n: n}, nil
		}
		return value{}, sc.errorf("unexpected character %q", c)
	}
}

func (sc *scanner) number() (int, bool) {
	start := sc.pos
	for !sc.eof() && sc.src[sc.pos] >= '0' && sc.src[sc.pos] <= '9' {
		sc.pos++
	}
	if start == sc.pos {
		return 0, false
	}
	n, err := strconv.Atoi(sc.src[start:sc.pos])
	if err != nil {
		sc.pos = start
		return 0, false
	}
	return n, true
}

// quoted reads a double quoted string; a backslash is dropped and the
// following character kept, matching the config lexer.
func (sc *scanner) quoted() (string, error) {
	sc.pos++ // opening quote
	var sb strings.Builder
	for !sc.eof() {
		c := sc.src[sc.pos]
		sc.pos++
		switch c {
		case '\\':
			if sc.eof() {
				return "", sc.errorf("dangling escape")
			}
			sb.WriteByte(sc.src[sc.pos])
			sc.pos++
		case '"':
			return sb.String(), nil
		default:
			sb.WriteByte(c)
		}
	}
	return "", sc.errorf("unterminated string")
}
