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
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/mikey-austin/greyd-v2/internal/ip"
)

// Message types sent to the greylister (grey.h GREY_MSG_*).
const (
	MsgGrey  = 1
	MsgTrap  = 2
	MsgWhite = 3
)

// Firewall request types (greyd.c MSG_TYPE_*).
const (
	TypeNAT     = "nat"
	TypeReplace = "replace"
)

// Statistics message types (additions of the Go port).
const (
	TypeStats      = "stats"
	TypeStatsReply = "stats_reply"
	TypeScanStats  = "scan_stats"
)

// Builder builds a framed message.
type Builder struct {
	b strings.Builder
}

// Int appends an integer assignment.
func (m *Builder) Int(name string, v int) *Builder {
	fmt.Fprintf(&m.b, "%s = %d\n", name, v)
	return m
}

// Str appends a string assignment. The value is written verbatim, as the C
// implementation does, so that blacklist messages keep their escape
// sequences for the receiving parser.
func (m *Builder) Str(name, v string) *Builder {
	fmt.Fprintf(&m.b, "%s = \"%s\"\n", name, v)
	return m
}

// SafeStr appends a string assignment after removing characters that would
// corrupt the frame (double quotes and backslashes).
func (m *Builder) SafeStr(name, v string) *Builder {
	return m.Str(name, Sanitize(v))
}

// StrList appends a list of strings.
func (m *Builder) StrList(name string, vals []string) *Builder {
	m.b.WriteString(name)
	m.b.WriteString("=[")
	for i, v := range vals {
		if i > 0 {
			m.b.WriteByte(',')
		}
		m.b.WriteByte('"')
		m.b.WriteString(v)
		m.b.WriteByte('"')
	}
	m.b.WriteString("]\n")
	return m
}

// Bytes returns the framed message including its terminator.
func (m *Builder) Bytes() []byte {
	return []byte(m.b.String() + Terminator + "\n")
}

// Send writes the framed message to w.
func (m *Builder) Send(w io.Writer) error {
	_, err := w.Write(m.Bytes())
	return err
}

// Sanitize strips double quotes and backslashes from a value.
func Sanitize(v string) string {
	if !strings.ContainsAny(v, "\"\\") {
		return v
	}
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' {
			return -1
		}
		return r
	}, v)
}

// WriteBlacklist sends a blacklist definition (name, rejection message and
// CIDR list) in the format understood by greyd's configuration socket and
// trap pipe (Greyd_send_config). Nothing is written for an empty list.
// Addresses without a prefix length get /32 or /128 appended.
func WriteBlacklist(w io.Writer, name, message string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "name=\"%s\"\nmessage=\"%s\"\nips=[", name, message)
	for i, addr := range ips {
		if i > 0 {
			sb.WriteByte(',')
		}
		if strings.Contains(addr, "/") {
			fmt.Fprintf(&sb, "\"%s\"", addr)
		} else {
			bits := 128
			if ip.CheckAddr(addr) == 4 {
				bits = 32
			}
			fmt.Fprintf(&sb, "\"%s/%d\"", addr, bits)
		}
	}
	sb.WriteString("]\n" + Terminator + "\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

// WriteGrey sends a greylist tuple from the main process to the greylister
// (con.c).
func WriteGrey(w io.Writer, dstIP, ipAddr, helo, from, to string) error {
	m := &Builder{}
	m.Int("type", MsgGrey).SafeStr("dst_ip", dstIP).SafeStr("ip", ipAddr).
		SafeStr("helo", helo).SafeStr("from", from).SafeStr("to", to)
	return m.Send(w)
}

// WriteGreyFromSync forwards a greylist tuple received over the sync
// protocol (sync.c); sync = 0 stops it being re-broadcast.
func WriteGreyFromSync(w io.Writer, ipAddr, helo, from, to string) error {
	m := &Builder{}
	m.Int("type", MsgGrey).Int("sync", 0).SafeStr("ip", ipAddr).
		SafeStr("helo", helo).SafeStr("from", from).SafeStr("to", to)
	return m.Send(w)
}

// WriteAddr forwards a white or trapped entry received over the sync
// protocol to the greylister.
func WriteAddr(w io.Writer, msgType int, ipAddr, source string, expires uint32, del bool) error {
	d := 0
	if del {
		d = 1
	}
	m := &Builder{}
	m.Int("type", msgType).Int("sync", 0).SafeStr("ip", ipAddr).SafeStr("source", source).
		Str("expires", fmt.Sprintf("%d", expires)).Int("delete", d)
	return m.Send(w)
}

// WriteReplace asks the firewall process to replace the contents of a set.
func WriteReplace(w io.Writer, set string, af int, ips []string) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "type=\"%s\"\nname=\"%s\"\naf=%d\n", TypeReplace, Sanitize(set), af)
	sb.WriteString("ips=[")
	for i, a := range ips {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "\"%s\"", Sanitize(a))
	}
	sb.WriteString("]\n" + Terminator + "\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

// WriteNAT asks the firewall process for the original destination of a
// redirected connection.
func WriteNAT(w io.Writer, src string, srcPort uint16, proxy string, proxyPort uint16) error {
	s := fmt.Sprintf("type=\"%s\"\nsrc=\"%s\"\nsrc_port=%d\nproxy=\"%s\"\nproxy_port=%d\n%s\n",
		TypeNAT, Sanitize(src), srcPort, Sanitize(proxy), proxyPort, Terminator)
	_, err := io.WriteString(w, s)
	return err
}

// WriteDst is the firewall process' answer to a NAT lookup.
func WriteDst(w io.Writer, dst string) error {
	_, err := fmt.Fprintf(w, "dst=\"%s\"\n%s\n", Sanitize(dst), Terminator)
	return err
}

// WriteStatsRequest asks greyd for its counters.
func WriteStatsRequest(w io.Writer) error {
	return (&Builder{}).Str("type", TypeStats).Send(w)
}

// WriteStatsReply sends counters (sorted by name) and blacklists.
func WriteStatsReply(w io.Writer, counters map[string]int64, blacklists []string) error {
	m := (&Builder{}).Str("type", TypeStatsReply)
	names := make([]string, 0, len(counters))
	for n := range counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&m.b, "%s = %d\n", n, counters[n])
	}
	if len(blacklists) > 0 {
		m.StrList("blacklists", blacklists)
	}
	return m.Send(w)
}

// WriteScanStats reports the entry counts of a database scan.
func WriteScanStats(w io.Writer, s ScanStats) error {
	m := (&Builder{}).Str("type", TypeScanStats)
	fmt.Fprintf(&m.b, "at = %d\ngrey = %d\nwhite = %d\ntrapped = %d\nspamtrap = %d\ndomain = %d\n", s.At, s.Grey, s.White, s.Trapped, s.Spamtrap, s.Domain)
	return m.Send(w)
}
