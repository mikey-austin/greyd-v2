/*
 * Copyright (c) 2014-2026 Mikey Austin <mikey@greyd.org>
 * Copyright (c) 2002-2007 Bob Beck.  All rights reserved.
 * Copyright (c) 2002 Theo de Raadt.  All rights reserved.
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

// Package smtp implements the fake SMTP server side of greyd: the tarpit
// state machine that stutters at blacklisted hosts, greylists unknown
// hosts and reports greylist tuples to the greylisting engine. It ports
// con.c to a goroutine-per-connection model with identical externally
// observable behaviour.
package smtp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/blacklist"
	"github.com/mikey-austin/greyd-v2/internal/logger"
	"github.com/mikey-austin/greyd-v2/internal/settings"
)

// Constants from con.h and constants.h.
const (
	BLSummarySize   = 80
	BLSummaryEtc    = " ..."
	BufSize         = 8192
	DefaultMax      = 800
	DefaultGreyStut = 10
	DefaultStutter  = 1
	ClientTolerance = 5
	DefaultErrCode  = "450"
	MaxBadCmd       = 20
	DefaultBanner   = "greyd IP-based SPAM blocker"
	// MaxTime is the inactivity limit for a read or a write.
	MaxTime = 400 * time.Second
)

// State machine states.
const (
	StateProxyIn   = -3
	StateProxyOut  = -2
	StateBannerIn  = -1
	StateBannerOut = 0
	StateHeloIn    = 1
	StateHeloOut   = 2
	StateMailIn    = 3
	StateMailOut   = 4
	StateRcptIn    = 5
	StateRcptOut   = 6
	StateDataIn    = 50
	StateDataOut   = 60
	StateMessage   = 70
	StateReply     = 98
	StateClose     = 99
)

// Config is the snapshot of configuration used by connections.
type Config struct {
	Hostname      string
	Banner        string
	ErrorCode     string
	Greylist      bool
	GreyStutter   int
	Stutter       int
	Verbose       bool
	Window        int
	ProxyProtocol bool
	// PermittedProxies is consulted when ProxyProtocol is enabled.
	PermittedProxies *blacklist.Blacklist
	// MaxLineLength caps a command line; longer input is treated as a
	// complete line (the C buffer was 8191 bytes).
	MaxLineLength int
	// MaxConsPerSource caps concurrent connections from one address (0 =
	// unlimited).
	MaxConsPerSource int
}

// ConfigFrom extracts the connection settings.
func ConfigFrom(s *settings.Settings) Config {
	return Config{
		Hostname:         s.Hostname,
		Banner:           s.Banner,
		ErrorCode:        s.ErrorCode,
		Greylist:         s.Grey.Enable,
		GreyStutter:      s.Grey.Stutter,
		Stutter:          s.Stutter,
		Verbose:          s.Verbose,
		Window:           s.Window,
		ProxyProtocol:    s.ProxyProtocolEnable,
		MaxLineLength:    s.MaxLineLength,
		MaxConsPerSource: s.MaxConsPerSource,
	}
}

func (c Config) lineLimit() int {
	if c.MaxLineLength <= 0 {
		return BufSize - 1
	}
	return c.MaxLineLength
}

// Deps are the collaborators of a connection.
type Deps struct {
	// Blacklists returns the current blacklists (a snapshot).
	Blacklists func() []*blacklist.Blacklist
	// GreyOut receives greylist tuples; nil when greylisting is disabled.
	GreyOut io.Writer
	// OrigDst looks up the original destination of a redirected
	// connection; it returns "" when unknown.
	OrigDst func(src, local netip.AddrPort) string
	// Now and Sleep are overridable for tests.
	Now   func() time.Time
	Sleep func(time.Duration)
	// Log receives connection events; nil discards them.
	Log *slog.Logger
}

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Deps) sleep(t time.Duration) {
	if d.Sleep != nil {
		d.Sleep(t)
		return
	}
	time.Sleep(t)
}

// Counters tracks the connection totals shared by all connections.
type Counters struct {
	mu           sync.Mutex
	Clients      int
	BlackClients int
	MaxCons      int
	MaxBlack     int
	perSource    map[netip.Addr]int

	// Cumulative totals since start (see Totals).
	accepted, acceptedBlack, refusedFull, refusedSource atomic.Int64
	greyTuples, repliesGrey, repliesBlack, proxyHeaders atomic.Int64
}

// Totals are the cumulative connection statistics.
type Totals struct {
	// Accepted counts connections handed to the state machine;
	// AcceptedBlack those of them that matched a blacklist on arrival.
	Accepted, AcceptedBlack int64
	// RefusedFull and RefusedSource count connections closed on accept
	// for the global and the per-source limit.
	RefusedFull, RefusedSource int64
	// GreyTuples counts envelopes sent to the greylister.
	GreyTuples int64
	// RepliesGrey and RepliesBlack count final rejections by kind.
	RepliesGrey, RepliesBlack int64
	// ProxyHeaders counts accepted PROXY protocol headers.
	ProxyHeaders int64
}

// Totals returns the cumulative statistics.
func (c *Counters) Totals() Totals {
	return Totals{
		Accepted: c.accepted.Load(), AcceptedBlack: c.acceptedBlack.Load(),
		RefusedFull: c.refusedFull.Load(), RefusedSource: c.refusedSource.Load(),
		GreyTuples: c.greyTuples.Load(), RepliesGrey: c.repliesGrey.Load(), RepliesBlack: c.repliesBlack.Load(),
		ProxyHeaders: c.proxyHeaders.Load(),
	}
}

// CountRefused records a connection closed on accept.
func (c *Counters) CountRefused(perSource bool) {
	if perSource {
		c.refusedSource.Add(1)
	} else {
		c.refusedFull.Add(1)
	}
}

// NewCounters creates counters with the given limits.
func NewCounters(maxCons, maxBlack int) *Counters {
	return &Counters{MaxCons: maxCons, MaxBlack: maxBlack, perSource: make(map[netip.Addr]int)}
}

func (c *Counters) add(src netip.Addr, black bool) (clients, blackClients int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Clients++
	c.accepted.Add(1)
	if black {
		c.BlackClients++
		c.acceptedBlack.Add(1)
	}
	if src.IsValid() {
		c.perSource[src]++
	}
	return c.Clients, c.BlackClients
}

func (c *Counters) remove(src netip.Addr, black bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Clients--
	if black {
		c.BlackClients--
	}
	if src.IsValid() {
		if c.perSource[src] <= 1 {
			delete(c.perSource, src)
		} else {
			c.perSource[src]--
		}
	}
}

// SourceCount returns the number of live connections from an address.
func (c *Counters) SourceCount(src netip.Addr) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.perSource[src]
}

// Snapshot returns the current totals.
func (c *Counters) Snapshot() (clients, blackClients, maxCons, maxBlack int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Clients, c.BlackClients, c.MaxCons, c.MaxBlack
}

// WithinMax reports whether there is headroom to stutter (clients + 5 <
// max_cons).
func (c *Counters) WithinMax() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Clients+ClientTolerance < c.MaxCons
}

// Full reports whether no further connections may be accepted.
func (c *Counters) Full() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Clients >= c.MaxCons
}

// Conn is a single client connection.
type Conn struct {
	rw       io.ReadWriter
	nc       net.Conn // rw when it is a net.Conn (deadlines, SO_RCVBUF)
	cfg      Config
	deps     Deps
	counters *Counters

	State     int
	LastState int

	Src     netip.AddrPort
	Local   netip.AddrPort
	SrcAddr string
	DstAddr string
	Helo    string
	Mail    string
	Rcpt    string

	Lists       []*blacklist.Blacklist
	ListSummary string
	Stutter     int

	start time.Time

	in      []byte // accumulated input
	InBuf   string // last complete input line(s), trailing CR/LF removed
	proxyV2 []byte // a binary proxy protocol header awaiting NextState

	Out    []byte
	outPos int
	seenCR bool

	badCmd    int
	dataBody  bool
	dataLines int

	// r and w mirror the C flags: a read or a write is pending.
	r, w   bool
	closed bool
	black  bool

	log *slog.Logger
}

// NewConn initialises a connection for the client at src accepted on the
// local address local (Con_init). The first state transition is performed:
// the banner is queued, or the proxy protocol header is awaited.
func NewConn(rw io.ReadWriter, src, local netip.AddrPort, cfg Config, deps Deps, counters *Counters) *Conn {
	c := &Conn{rw: rw, cfg: cfg, deps: deps, counters: counters, Src: src, Local: local}
	if nc, ok := rw.(net.Conn); ok {
		c.nc = nc
	}
	c.SrcAddr = src.Addr().Unmap().String()
	c.log = logger.Or(deps.Log).With("client", c.SrcAddr)
	c.start = deps.now()
	c.matchBlacklists()

	_, black := counters.add(src.Addr().Unmap(), c.black)
	if c.black {
		c.ListSummary = SummarizeLists(c.Lists)
		// Abandon stuttering if there are too many blacklisted connections.
		if cfg.Greylist && black > counters.MaxBlack {
			c.Stutter = 0
		}
	}

	c.outPos = 0
	if cfg.ProxyProtocol {
		c.State = StateProxyIn
	} else {
		c.State = StateBannerIn
	}
	c.NextState()
	return c
}

// matchBlacklists sets Lists, black and the initial stutter for SrcAddr.
func (c *Conn) matchBlacklists() {
	c.Lists = nil
	addr := c.Src.Addr()
	if c.cfg.ProxyProtocol && c.SrcAddr != "" {
		if a, err := netip.ParseAddr(c.SrcAddr); err == nil {
			addr = a
		}
	}
	if c.deps.Blacklists != nil {
		for _, bl := range c.deps.Blacklists() {
			if bl.Match(addr) {
				c.Lists = append(c.Lists, blacklist.New(bl.Name, bl.Message, blacklist.StorageTrie))
			}
		}
	}
	c.black = len(c.Lists) > 0

	// Greylisted connections with the grey stutter disabled don't stutter.
	if c.cfg.Greylist && c.cfg.GreyStutter == 0 && !c.black {
		c.Stutter = 0
	} else {
		c.Stutter = c.cfg.Stutter
	}
}

// IsBlacklisted reports whether the client matched any blacklist.
func (c *Conn) IsBlacklisted() bool { return c.black }

// Closed reports whether the connection has been closed.
func (c *Conn) Closed() bool { return c.closed }

// Close closes the connection and releases its counters (Con_close).
func (c *Conn) Close() {
	if c.closed {
		return
	}
	c.closed = true
	if cl, ok := c.rw.(io.Closer); ok {
		_ = cl.Close()
	}
	elapsed := int64(c.deps.now().Sub(c.start).Seconds())
	if c.black {
		c.log.Info("disconnected", "seconds", elapsed, "lists", c.ListSummary)
	} else {
		c.log.Info("disconnected", "seconds", elapsed)
	}
	c.counters.remove(c.Src.Addr().Unmap(), c.black)
	c.Lists = nil
	c.ListSummary = ""
	c.Out = nil
	c.outPos = 0
}

// Serve drives the connection until it is closed.
func (c *Conn) Serve() {
	for !c.closed {
		switch {
		case c.w:
			c.HandleWrite()
		case c.r:
			c.HandleRead()
		default:
			if c.State == StateClose {
				c.Close()
				return
			}
			// Nothing pending: the state machine is stuck; bail out.
			c.Close()
			return
		}
	}
}

// OutRemaining returns the number of bytes still to be written.
func (c *Conn) OutRemaining() int { return len(c.Out) - c.outPos }

// setOut queues a reply.
func (c *Conn) setOut(s string) {
	c.Out = crlf(s)
	c.outPos = 0
	c.seenCR = false
	c.w = true
}

// crlf terminates every line with CRLF. Replies are assembled with bare
// newlines (the multi-line blacklist messages in particular); the C code
// inserted the CR while stuttering byte by byte, which left bare LFs in
// replies written in one piece.
func crlf(s string) []byte {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && (i == 0 || s[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, s[i])
	}
	return out
}

// setRead prepares for a new input line.
func (c *Conn) setRead() {
	c.in = c.in[:0]
	c.r = true
}

// HandleRead reads client input until a line terminator arrives or the
// buffer is full, then advances the state machine (Con_handle_read). The
// first read of a proxied connection is the proxy protocol header, which
// may be binary.
func (c *Conn) HandleRead() {
	if c.closed || !c.r {
		return
	}
	if c.State == StateProxyOut {
		c.readProxyHeader()
		return
	}
	limit := c.cfg.lineLimit()
	buf := make([]byte, limit)
	for len(c.in) < limit {
		n, ok := c.readChunk(buf[:limit-len(c.in)])
		if !ok {
			return
		}
		if bytes.IndexByte(buf[:n], '\n') >= 0 {
			break
		}
	}
	c.finishLine()
}

// readProxyHeader reads the proxy protocol header that must open a proxied
// connection. The first bytes decide the version: a version 2 header
// starts with a fixed binary signature and declares its own length, and is
// read exactly (so nothing of the SMTP dialogue behind it is consumed) and
// left in proxyV2 for NextState; anything else is read as a version 1
// text line, bounded by MaxProxyHeader, into InBuf.
func (c *Conn) readProxyHeader() {
	limit := min(c.cfg.lineLimit(), MaxProxyHeader)
	buf := make([]byte, max(limit, ProxyV2HeaderLen+MaxProxyV2Length))

	// Read until the input either matches the whole v2 signature or
	// diverges from it.
	for len(c.in) < len(ProxyV2Signature) && bytes.HasPrefix(ProxyV2Signature, c.in) {
		if _, ok := c.readChunk(buf[:len(ProxyV2Signature)-len(c.in)]); !ok {
			return
		}
	}
	if !bytes.HasPrefix(c.in, ProxyV2Signature) {
		// Version 1: a text line.
		for len(c.in) < limit && bytes.IndexByte(c.in, '\n') < 0 {
			if _, ok := c.readChunk(buf[:limit-len(c.in)]); !ok {
				return
			}
		}
		if bytes.IndexByte(c.in, '\n') < 0 {
			// The specification requires the CRLF within 107 bytes; a
			// longer first line is not a PROXY header, however its
			// prefix parses. Hand the state machine an unparsable line
			// so the usual invalid-header reply and close follow.
			c.in = append(c.in[:0], "PROXY OVERLONG"...)
		}
		c.finishLine()
		return
	}

	// Version 2: the fixed header, then exactly the declared address block.
	for len(c.in) < ProxyV2HeaderLen {
		if _, ok := c.readChunk(buf[:ProxyV2HeaderLen-len(c.in)]); !ok {
			return
		}
	}
	total := ProxyV2HeaderLen + int(binary.BigEndian.Uint16(c.in[14:16]))
	if total > ProxyV2HeaderLen+MaxProxyV2Length {
		c.log.Warn("proxy protocol v2 header too long", "length", total-ProxyV2HeaderLen)
		c.Close()
		return
	}
	for len(c.in) < total {
		if _, ok := c.readChunk(buf[:total-len(c.in)]); !ok {
			return
		}
	}
	c.proxyV2 = append([]byte(nil), c.in...)
	c.InBuf = ""
	c.r = false
	c.NextState()
}

// readChunk performs one read into buf, appending what arrived to in. On
// an error or end of file the connection is closed and false returned.
func (c *Conn) readChunk(buf []byte) (n int, ok bool) {
	if c.nc != nil {
		_ = c.nc.SetReadDeadline(time.Now().Add(MaxTime))
	}
	n, err := c.rw.Read(buf)
	if n > 0 {
		c.in = append(c.in, buf[:n]...)
	}
	if err != nil {
		if !errors.Is(err, io.EOF) {
			c.log.Warn("connection read error", "err", err)
		}
		c.Close()
		return n, false
	}
	if n == 0 {
		c.Close()
		return n, false
	}
	return n, true
}

// finishLine turns the accumulated input into InBuf and advances the
// state machine.
func (c *Conn) finishLine() {
	// The C implementation handled the buffer as a string, so anything
	// after a NUL was invisible to it; do the same rather than carry NULs
	// into database keys.
	line := c.in
	if i := bytes.IndexByte(line, 0); i >= 0 {
		line = line[:i]
	}
	// Replace trailing new lines with nothing.
	for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == '\n') {
		line = line[:len(line)-1]
	}
	c.InBuf = string(line)
	c.r = false
	c.NextState()
}

// HandleWrite writes the queued reply, one byte at a time while stuttering,
// then advances the state machine once everything is out
// (Con_handle_write).
func (c *Conn) HandleWrite() {
	if c.closed || !c.w {
		return
	}
	now := c.deps.now()

	// Greylisted connections stop stuttering after the initial delay.
	if c.Stutter > 0 && c.cfg.Greylist && !c.black && now.Sub(c.start) > time.Duration(c.cfg.GreyStutter)*time.Second {
		c.Stutter = 0
	}

	if c.OutRemaining() > 0 {
		if c.nc != nil {
			_ = c.nc.SetWriteDeadline(time.Now().Add(MaxTime))
		}
		if c.Out[c.outPos] == '\n' && !c.seenCR {
			// We must write a \r before a \n.
			if _, err := c.rw.Write([]byte{'\r'}); err != nil {
				c.log.Warn("connection write error", "err", err)
				c.Close()
				return
			}
		}
		c.seenCR = c.Out[c.outPos] == '\r'

		toWrite := c.OutRemaining()
		if c.counters.WithinMax() && c.Stutter > 0 {
			toWrite = 1
		}
		n, err := c.rw.Write(c.Out[c.outPos : c.outPos+toWrite])
		if err != nil || n == 0 {
			c.log.Warn("connection write error", "err", err)
			c.Close()
			return
		}
		c.outPos += n
	}

	if c.OutRemaining() == 0 {
		c.w = false
		c.NextState()
		return
	}
	if c.Stutter > 0 {
		c.deps.sleep(time.Duration(c.Stutter) * time.Second)
	}
}

// BuildReply queues the final rejection: the expanded blacklist messages
// for blacklisted clients, or the generic temporary failure (always 451)
// for greylisted ones (Con_build_reply).
func (c *Conn) BuildReply(code string) {
	if c.black {
		c.counters.repliesBlack.Add(1)
		c.setOut(FormatReply(c.Lists, code, c.SrcAddr))
		return
	}
	c.counters.repliesGrey.Add(1)
	c.setOut(GreyReply)
}

// setWindow adjusts the socket receive buffer (the "window" option).
func (c *Conn) setWindow() {
	if c.cfg.Window <= 0 || c.nc == nil {
		return
	}
	sc, ok := c.nc.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	var serr error
	_ = raw.Control(func(fd uintptr) {
		serr = setRcvBuf(fd, c.cfg.Window)
	})
	if serr != nil {
		c.log.Debug("setsockopt failed", "window", c.cfg.Window, "err", serr)
	}
}
