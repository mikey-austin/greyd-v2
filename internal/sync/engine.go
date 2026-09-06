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

package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

type host struct {
	name string
	addr *net.UDPAddr
}

// Engine sends and receives synchronisation messages.
type Engine struct {
	cfg       *config.Config
	port      int
	key       Key
	counter   atomic.Uint32
	hosts     []host
	iface     string
	sendMcast bool
	conn      *net.UDPConn
	syncIn    netip.Addr   // address of the multicast interface
	syncOut   *net.UDPAddr // multicast destination
	greyOK    bool
}

// New creates an engine from the sync configuration section. It returns
// nil, nil when synchronisation is disabled (sync.enable = 0).
func New(cfg *config.Config) (*Engine, error) {
	if !cfg.Bool("enable", "sync", false) {
		return nil, nil
	}
	e := &Engine{cfg: cfg, port: cfg.Int("port", "sync", DefaultPort)}
	e.greyOK = cfg.Bool("enable", "grey", true)

	for _, h := range cfg.StrList("hosts", "sync") {
		if err := e.AddHost(h); err != nil {
			// Not a host address, so treat it as an interface name.
			e.iface = h
		}
	}

	if cfg.Bool("verify", "sync", true) {
		path := cfg.Str("key", "sync", DefaultKey)
		k, _, err := LoadKey(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read sync key: %w", err)
		}
		e.key = k
	}
	return e, nil
}

// AddHost adds a unicast target; the name must resolve to an IPv4
// address.
func (e *Engine) AddHost(name string) error {
	ips, err := net.LookupIP(name)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			h := host{name: name, addr: &net.UDPAddr{IP: v4, Port: e.port}}
			e.hosts = append(e.hosts, h)
			logger.Debug("added spam sync host %s (address %s, port %d)", name, v4, e.port)
			return nil
		}
	}
	return errors.New("no IPv4 address")
}

// Hosts returns the configured unicast target names.
func (e *Engine) Hosts() []string {
	out := make([]string, len(e.hosts))
	for i, h := range e.hosts {
		out[i] = h.name
	}
	return out
}

// Start opens the socket and joins the multicast group when an interface
// is configured (Sync_start).
func (e *Engine) Start() error {
	bindAddr := e.cfg.Str("bind_address", "sync", "")
	if e.iface != "" {
		e.sendMcast = true
	}

	bindIP := net.IPv4zero
	if bindAddr != "" {
		if ip := net.ParseIP(bindAddr); ip != nil && ip.To4() != nil {
			bindIP = ip.To4()
		} else {
			// Not an address: it names the multicast interface.
			if e.iface == "" {
				e.iface = bindAddr
			} else if bindAddr != e.iface {
				return fmt.Errorf("multicast interface %s does not match %s", bindAddr, e.iface)
			}
		}
	}

	port := e.port
	if bindAddr == "" && e.iface == "" {
		port = 0
	}

	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(bindIP.String(), strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	e.conn = pc.(*net.UDPConn)

	if e.iface == "" {
		// Don't use multicast messages.
		return nil
	}

	ifName := e.iface
	ttl := e.cfg.Int("ttl", "sync", DefaultTTL)
	if i := strings.IndexByte(ifName, ':'); i >= 0 {
		t, err := strconv.Atoi(ifName[i+1:])
		if err != nil || t <= 0 || t > 255 {
			_ = e.conn.Close()
			return fmt.Errorf("invalid multicast ttl %s", ifName[i+1:])
		}
		ttl = t
		ifName = ifName[:i]
	}

	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		_ = e.conn.Close()
		return fmt.Errorf("interface %s: %w", ifName, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		_ = e.conn.Close()
		return fmt.Errorf("interface %s addresses: %w", ifName, err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			e.syncIn, _ = netip.AddrFromSlice(ipn.IP.To4())
			break
		}
	}
	if !e.syncIn.IsValid() {
		_ = e.conn.Close()
		return fmt.Errorf("interface %s has no IPv4 address", ifName)
	}

	mcast := net.ParseIP(e.cfg.Str("mcast_address", "sync", MulticastAddr))
	if mcast == nil || mcast.To4() == nil {
		_ = e.conn.Close()
		return fmt.Errorf("invalid mcast_address")
	}
	e.syncOut = &net.UDPAddr{IP: mcast.To4(), Port: e.port}

	p := ipv4.NewPacketConn(e.conn)
	if err := p.JoinGroup(ifi, &net.UDPAddr{IP: mcast}); err != nil {
		_ = e.conn.Close()
		return fmt.Errorf("failed to add multicast membership to %s: %w", mcast, err)
	}
	if err := p.SetMulticastTTL(ttl); err != nil {
		_ = p.LeaveGroup(ifi, &net.UDPAddr{IP: mcast})
		_ = e.conn.Close()
		return fmt.Errorf("failed to set multicast ttl to %d: %w", ttl, err)
	}
	if err := p.SetMulticastInterface(ifi); err != nil {
		logger.Warning("failed to set multicast interface %s: %v", ifName, err)
	}

	mode := "receive "
	if e.sendMcast {
		mode = ""
	}
	logger.Debug("using multicast spam sync %smode (ttl %d, group %s, port %d)", mode, ttl, mcast, e.port)
	return nil
}

// Stop closes the socket.
func (e *Engine) Stop() {
	if e != nil && e.conn != nil {
		_ = e.conn.Close()
		e.conn = nil
	}
}

// LocalAddr returns the bound socket address (tests).
func (e *Engine) LocalAddr() net.Addr {
	if e.conn == nil {
		return nil
	}
	return e.conn.LocalAddr()
}

// Recv reads one packet and forwards its entries to the greylister
// (Sync_recv). It returns net.ErrClosed once the socket is closed.
func (e *Engine) Recv(greyOut io.Writer) error {
	buf := make([]byte, MaxSize)
	n, from, err := e.conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	if n < 1 {
		return nil
	}
	if e.syncIn.IsValid() {
		if fa, ok := netip.AddrFromSlice(from.IP.To4()); ok && fa == e.syncIn {
			return nil // our own multicast
		}
	}
	src := from.IP.String()

	entries, err := Decode(&e.key, buf[:n])
	if err != nil {
		logger.Debug("%s (sync): truncated or invalid packet", src)
		return nil
	}
	logger.Debug("%s (sync): received packet of %d bytes", src, n)

	for _, ent := range entries {
		switch ent.Type {
		case TypeGrey:
			logger.Debug("%s (sync): received grey entry from %s to %s, helo %s ip %s",
				src, ent.From, ent.To, ent.Helo, ent.IP)
			if e.greyOK && greyOut != nil {
				if err := ipc.WriteGreyFromSync(greyOut, ent.IP.String(), ent.Helo, ent.From, ent.To); err != nil {
					return err
				}
			}
		case TypeWhite, TypeDelWhite:
			logger.Debug("%s (sync): received white entry ip %s (%s)", src, ent.IP, addDel(ent.Delete))
			if e.greyOK && greyOut != nil {
				if err := ipc.WriteAddr(greyOut, ipc.MsgWhite, ent.IP.String(), src, ent.Expire, ent.Delete); err != nil {
					return err
				}
			}
		case TypeTrapped, TypeDelTrapped:
			logger.Debug("%s (sync): received trapped entry ip %s (%s)", src, ent.IP, addDel(ent.Delete))
			if e.greyOK && greyOut != nil {
				if err := ipc.WriteAddr(greyOut, ipc.MsgTrap, ent.IP.String(), src, ent.Expire, ent.Delete); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func addDel(del bool) string {
	if del {
		return "deletion"
	}
	return "addition"
}

// Serve receives packets until ctx is done.
func (e *Engine) Serve(ctx context.Context, greyOut io.Writer) error {
	go func() {
		<-ctx.Done()
		e.Stop()
	}()
	for {
		if err := e.Recv(greyOut); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

// Update announces a greylist tuple (Sync_update).
func (e *Engine) Update(t core.Tuple, now time.Time) {
	ip, err := netip.ParseAddr(t.IP)
	if err != nil {
		return
	}
	logger.Debug("sync grey update helo %s ip %s from %s to %s", t.Helo, t.IP, t.From, t.To)
	pkt := EncodeGrey(&e.key, e.counter.Add(1)-1, ip, t.Helo, t.From, t.To, uint32(now.Unix()))
	e.send(pkt)
}

// White announces a whitelist addition or deletion (Sync_white).
func (e *Engine) White(ip string, now, expire time.Time, del bool) {
	typ := TypeWhite
	if del {
		typ = TypeDelWhite
	}
	e.sendAddr(ip, now, expire, typ)
}

// Trapped announces a greytrap addition or deletion (Sync_trapped).
func (e *Engine) Trapped(ip string, now, expire time.Time, del bool) {
	typ := TypeTrapped
	if del {
		typ = TypeDelTrapped
	}
	e.sendAddr(ip, now, expire, typ)
}

func (e *Engine) sendAddr(ipStr string, now, expire time.Time, typ uint16) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return
	}
	var name string
	switch typ {
	case TypeWhite:
		name = "white"
	case TypeDelWhite:
		name = "deletion of white"
	case TypeTrapped:
		name = "trapped"
	case TypeDelTrapped:
		name = "deletion of trapped"
	}
	logger.Debug("sync %s %s", name, ipStr)
	pkt := EncodeAddr(&e.key, e.counter.Add(1)-1, typ, ip, uint32(now.Unix()), uint32(expire.Unix()))
	e.send(pkt)
}

func (e *Engine) send(pkt []byte) {
	if e.conn == nil {
		return
	}
	if e.sendMcast && e.syncOut != nil {
		logger.Debug("sending multicast sync message")
		if _, err := e.conn.WriteToUDP(pkt, e.syncOut); err != nil {
			logger.Warning("sendmsg: %v", err)
		}
	}
	for _, h := range e.hosts {
		logger.Debug("sending sync message to %s (%s)", h.name, h.addr.IP)
		if _, err := e.conn.WriteToUDP(pkt, h.addr); err != nil {
			logger.Warning("sendmsg: %v", err)
		}
	}
}
