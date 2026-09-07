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

// Package stats gathers greyd's operational counters: the database entry
// counts (from a store) and the daemon counters (over the configuration
// socket), for greyd --stats, greydb -s and greyd-monitor.
package stats

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/settings"
	"github.com/mikey-austin/greyd-v2/internal/setup"
)

// Counts are the database entry counts by kind.
type Counts struct {
	Grey, White, Trapped, Spamtrap, Domain int64
}

// Summarize counts the entries of a store by kind in one read
// transaction. The store must be open.
func Summarize(ctx context.Context, s core.Store) (Counts, error) {
	var c Counts
	err := s.View(ctx, func(tx core.ReadTx) error {
		it, err := tx.Iter(core.IterAll)
		if err != nil {
			return err
		}
		defer func() { _ = it.Close() }()
		for {
			k, d, ok, err := it.Next()
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			switch {
			case k.Type == core.KeyTuple:
				c.Grey++
			case k.Type == core.KeyMail || d.PCount == core.PCountSpamtrap:
				c.Spamtrap++
			case k.Type == core.KeyDomain || k.Type == core.KeyDomainPart || d.PCount == core.PCountDomain:
				c.Domain++
			case d.PCount == core.PCountTrapped:
				c.Trapped++
			default:
				c.White++
			}
		}
	})
	return c, err
}

// Dialer connects to greyd's configuration socket as configured: the
// unix socket when config_socket is set (peer credentials decide access),
// otherwise the loopback port from a reserved source port (root only).
func Dialer(s *settings.Settings) setup.Dialer {
	if sock := s.ConfigSocket; sock != "" {
		return func() (net.Conn, error) { return setup.DialUnix(sock) }
	}
	port := s.ConfigPort
	return func() (net.Conn, error) { return setup.DialReserved(port) }
}

// queryTimeout bounds one statistics exchange.
const queryTimeout = 10 * time.Second

// Query asks a running greyd for its counters.
func Query(ctx context.Context, dial setup.Dialer) (*ipc.StatsReply, error) {
	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("could not connect to greyd: %w", err)
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(queryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err := ipc.WriteStatsRequest(conn); err != nil {
		return nil, fmt.Errorf("could not send request: %w", err)
	}
	m, err := ipc.NewReader(conn).Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("greyd closed the connection without answering (older greyd, or the peer was not authorised)")
		}
		return nil, fmt.Errorf("could not read reply: %w", err)
	}
	reply, ok := m.(*ipc.StatsReply)
	if !ok {
		return nil, errors.New("unexpected reply from greyd")
	}
	return reply, nil
}

// Blacklist is a parsed "name=entries" element of a StatsReply.
type Blacklist struct {
	Name    string
	Entries int64
}

// Blacklists parses the blacklist list of a reply.
func Blacklists(r *ipc.StatsReply) []Blacklist {
	out := make([]Blacklist, 0, len(r.Blacklists))
	for _, e := range r.Blacklists {
		name, n, _ := strings.Cut(e, "=")
		v, _ := strconv.ParseInt(n, 10, 64)
		out = append(out, Blacklist{Name: name, Entries: v})
	}
	return out
}

// Format writes a reply as sorted "name value" lines, blacklists last.
func Format(w io.Writer, r *ipc.StatsReply) {
	names := make([]string, 0, len(r.Counters))
	for n := range r.Counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "%-32s %d\n", n, r.Counters[n])
	}
	for _, bl := range Blacklists(r) {
		fmt.Fprintf(w, "%-32s %d\n", "blacklist "+bl.Name, bl.Entries)
	}
}
