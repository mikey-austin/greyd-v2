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

package smtp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/logger"
)

// Server accepts SMTP connections and runs a Conn per client.
type Server struct {
	cfg      Config
	deps     Deps
	counters *Counters

	mu    sync.Mutex
	conns map[*Conn]struct{}
	wg    sync.WaitGroup
}

// NewServer creates a server.
func NewServer(cfg Config, deps Deps, counters *Counters) *Server {
	return &Server{cfg: cfg, deps: deps, counters: counters, conns: make(map[*Conn]struct{})}
}

// ServeListener accepts connections until ctx is done or the listener
// fails (Con_accept). Descriptor exhaustion throttles accepting for one
// second; connections beyond max_cons are closed immediately.
func (s *Server) ServeListener(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
				s.deps.sleep(time.Second)
				continue
			}
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ECONNABORTED) {
				continue
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}

		if s.counters.Full() {
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.Handle(conn)
		}()
	}
}

// Handle runs a single accepted connection to completion.
func (s *Server) Handle(conn net.Conn) {
	src := addrPortOf(conn.RemoteAddr())
	local := addrPortOf(conn.LocalAddr())
	c := NewConn(conn, src, local, s.cfg, s.deps, s.counters)

	clients, black, _, _ := s.counters.Snapshot()
	if c.black {
		logger.Info("%s: connected (%d/%d), lists: %s", c.SrcAddr, clients, black, c.ListSummary)
	} else {
		logger.Info("%s: connected (%d/%d)", c.SrcAddr, clients, black)
	}

	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()

	c.Serve()

	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// Shutdown closes every active connection and waits for their goroutines.
func (s *Server) Shutdown() {
	s.mu.Lock()
	for c := range s.conns {
		if cl, ok := c.rw.(net.Conn); ok {
			_ = cl.Close()
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func addrPortOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.AddrPort()
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap
	}
	return netip.AddrPort{}
}
