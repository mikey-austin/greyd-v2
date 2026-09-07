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

package smtp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
)

// match reports whether the input starts with the command (case
// insensitive).
func match(in, cmd string) bool {
	return len(in) >= len(cmd) && strings.EqualFold(in[:len(cmd)], cmd)
}

// getHelo extracts the HELO/EHLO argument: the first token after the
// command.
func getHelo(in string) string {
	if len(in) < 4 {
		return ""
	}
	f := strings.Fields(in[4:])
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// getAddr extracts the argument of MAIL FROM:/RCPT TO: as the first token
// after the colon (set_log in con.c).
func getAddr(in string) string {
	i := strings.IndexByte(in, ':')
	if i < 0 {
		return ""
	}
	f := strings.Fields(in[i+1:])
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// NextState advances the state machine based on the current state and the
// last input line (Con_next_state).
func (c *Conn) NextState() {
	if c.closed {
		return
	}
	now := c.deps.now()
	hostname := c.cfg.Hostname

	if match(c.InBuf, "QUIT") && c.State < StateClose {
		c.setOut(fmt.Sprintf("221 %s\r\n", hostname))
		c.LastState = c.State
		c.State = StateClose
		return
	}

	if match(c.InBuf, "RSET") && c.State > StateHeloOut && c.State < StateDataIn {
		c.setOut("250 OK\r\n")
		c.LastState = c.State
		c.State = StateHeloOut
		return
	}

	st := c.State
	for {
		switch st {
		case StateProxyIn:
			c.LastState = c.State
			c.State = StateProxyOut
			c.setRead()
			return

		case StateProxyOut:
			if c.applyProxyHeader() {
				st = StateBannerIn
				continue
			}
			st = StateReply
			continue

		case StateBannerIn:
			c.setOut(fmt.Sprintf("220 %s ESMTP %s; %s\r\n", hostname, c.cfg.Banner, now.Format("Mon Jan _2 15:04:05 2006")))
			c.LastState = c.State
			c.State = StateBannerOut
			return

		case StateBannerOut:
			c.LastState = c.State
			c.State = StateHeloIn
			c.setRead()
			return

		case StateHeloIn:
			if match(c.InBuf, "HELO") || match(c.InBuf, "EHLO") {
				next := StateHeloOut
				c.Helo = getHelo(c.InBuf)
				if c.Helo == "" {
					next = StateBannerOut
					cmd := "EHLO"
					if match(c.InBuf, "HELO") {
						cmd = "HELO"
					}
					c.setOut(fmt.Sprintf("501 Syntax: %s hostname\r\n", cmd))
				} else {
					c.setOut(fmt.Sprintf("250 %s\r\n", hostname))
				}
				c.LastState = c.State
				c.State = next
				return
			}
			st = StateMailIn
			continue

		case StateHeloOut:
			// Sent 250 Hello, wait for input.
			c.LastState = c.State
			c.State = StateMailIn
			c.setRead()
			return

		case StateMailIn:
			if match(c.InBuf, "MAIL") {
				c.Mail = core.NormalizeEmail(getAddr(c.InBuf))
				c.setOut("250 OK\r\n")
				c.LastState = c.State
				c.State = StateMailOut
				return
			}
			st = StateRcptIn
			continue

		case StateMailOut:
			// Sent 250 Sender ok.
			c.LastState = c.State
			c.State = StateRcptIn
			c.setRead()
			return

		case StateRcptIn:
			if match(c.InBuf, "RCPT") {
				c.Rcpt = core.NormalizeEmail(getAddr(c.InBuf))
				c.setOut("250 OK\r\n")
				c.LastState = c.State
				c.State = StateRcptOut

				if c.Mail != "" && c.Rcpt != "" {
					kind := "GREY"
					if c.black {
						kind = "BLACK"
					}
					c.log.Debug("envelope", "kind", kind, "from", c.Mail, "to", c.Rcpt)
					if c.cfg.Greylist && !c.black && c.deps.GreyOut != nil {
						// Send this information to the greylister.
						c.lookupOrigDst()
						if err := ipc.WriteGrey(c.deps.GreyOut, c.DstAddr, c.SrcAddr, c.Helo, c.Mail, c.Rcpt); err != nil {
							c.log.Warn("could not send grey entry", "err", err)
						} else {
							c.counters.greyTuples.Add(1)
						}
					}
				} else {
					c.log.Debug("incomplete sender and/or recipient; not sending to greylister")
				}
				return
			}
			st = StateDataIn
			continue

		case StateRcptOut:
			// Sent 250.
			c.LastState = c.State
			c.State = StateRcptIn
			c.setRead()
			return

		case StateDataIn:
			if match(c.InBuf, "DATA") {
				c.setOut("354 End data with <CR><LF>.<CR><LF>\r\n")
				c.State = StateDataOut
				c.setWindow()
				c.in = c.in[:0]
				if c.cfg.Greylist && !c.black {
					c.LastState = c.State
					c.State = StateReply
					st = StateReply
					continue
				}
				return
			}
			if match(c.InBuf, "NOOP") {
				c.setOut("250 OK\r\n")
			} else {
				c.setOut("500 Command unrecognized\r\n")
				c.badCmd++
				if c.badCmd > MaxBadCmd {
					c.LastState = c.State
					c.State = StateReply
					st = StateReply
					continue
				}
			}
			c.State = c.LastState
			c.in = c.in[:0]
			return

		case StateDataOut:
			// Sent 354.
			c.LastState = c.State
			c.State = StateMessage
			c.setRead()
			return

		case StateMessage:
			// Process the message body.
			for _, line := range strings.Split(c.InBuf, "\n") {
				line = strings.TrimSuffix(line, "\r")
				if line == "." {
					c.LastState = c.State
					c.State = StateReply
					st = StateReply
					goto reply
				}
				if c.dataBody {
					c.dataLines++
					if c.dataLines >= 10 {
						c.LastState = c.State
						c.State = StateReply
						st = StateReply
						goto reply
					}
				}
				if !c.dataBody && line == "" {
					c.dataBody = true
				}
				if c.cfg.Verbose && c.dataBody && line != "" {
					c.log.Info("body", "line", line)
				} else if c.cfg.Verbose && (match(line, "FROM:") || match(line, "TO:") || match(line, "SUBJECT:")) {
					c.log.Info("header", "line", line)
				}
			}
			c.setRead()
			return
		reply:
			continue

		case StateReply:
			c.BuildReply(c.cfg.ErrorCode)
			c.LastState = c.State
			c.State = StateClose
			return

		case StateClose:
			c.Close()
			return

		default:
			c.log.Error("illegal state", "state", st)
			c.Close()
			return
		}
	}
}

// allowProxy checks the TCP peer against the permitted upstream proxies.
func (c *Conn) allowProxy() bool {
	if c.cfg.PermittedProxies != nil && c.cfg.PermittedProxies.Match(c.Src.Addr()) {
		return true
	}
	c.log.Warn("rejecting unknown proxy", "proxy", c.Src.Addr().Unmap())
	return false
}

// applyProxyHeader checks the proxy protocol header read by HandleRead
// (a v2 binary header in proxyV2, otherwise a v1 line in InBuf) against
// the permitted proxies, and adopts the real client addresses it carries.
// It reports whether the dialogue may proceed.
func (c *Conn) applyProxyHeader() bool {
	hdr := c.proxyV2
	c.proxyV2 = nil
	if hdr == nil && !match(c.InBuf, "PROXY") {
		return false
	}
	if !c.allowProxy() {
		return false
	}
	var (
		src, dst netip.Addr
		local    bool
		err      error
	)
	if hdr != nil {
		src, dst, local, err = ParseProxyHeaderV2(hdr)
	} else {
		src, dst, err = ParseProxyHeader(c.InBuf)
	}
	switch {
	case err == nil:
		c.counters.proxyHeaders.Add(1)
		if local {
			// A LOCAL command (e.g. a health check): the connection's
			// own addresses stand.
			c.log.Debug("LOCAL proxy protocol header; using the connection addresses")
			return true
		}
		c.SrcAddr = src.String()
		c.DstAddr = dst.String()
		c.rematchAfterProxy()
		return true
	case errors.Is(err, ErrProxyUnknown):
		c.log.Debug("UNKNOWN proxy protocol header encountered; refusing to continue")
	default:
		c.log.Warn("invalid proxy protocol header", "err", err)
	}
	return false
}

// rematchAfterProxy re-evaluates the blacklists for the real client
// address learned from the proxy protocol header and fixes up the
// counters. The C implementation matched only the proxy's address; the
// real client is the useful one to check.
func (c *Conn) rematchAfterProxy() {
	wasBlack := c.black
	c.matchBlacklists()
	if c.black != wasBlack {
		c.counters.mu.Lock()
		if c.black {
			c.counters.BlackClients++
		} else {
			c.counters.BlackClients--
		}
		black := c.counters.BlackClients
		maxBlack := c.counters.MaxBlack
		c.counters.mu.Unlock()
		if c.black && c.cfg.Greylist && black > maxBlack {
			c.Stutter = 0
		}
	}
	c.ListSummary = ""
	if c.black {
		c.ListSummary = SummarizeLists(c.Lists)
	}
}

// lookupOrigDst fills DstAddr with the pre-redirection destination unless
// the proxy protocol already supplied it.
func (c *Conn) lookupOrigDst() {
	if c.cfg.ProxyProtocol {
		return
	}
	c.DstAddr = ""
	if c.deps.OrigDst != nil {
		c.DstAddr = c.deps.OrigDst(c.Src, c.Local)
	}
}
