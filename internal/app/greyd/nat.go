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

package greyd

import (
	"net/netip"
	"time"

	"github.com/mikey-austin/greyd-v2/internal/ipc"
)

// natLookupTimeout bounds a firewall NAT lookup (DNAT_LOOKUP_TIMEOUT).
const natLookupTimeout = time.Second

// lookupOrigDst asks the firewall process for the pre-DNAT destination of
// a connection (Con_get_orig_dst). Requests are serialised because the
// pipes carry one exchange at a time.
func (d *daemon) lookupOrigDst(src, local netip.AddrPort) string {
	if d.files.fwOut == nil || d.files.natIn == nil {
		return ""
	}
	d.natMu.Lock()
	defer d.natMu.Unlock()

	if err := ipc.WriteNAT(d.files.fwOut, src.Addr().Unmap().String(), src.Port(), local.Addr().Unmap().String(), local.Port()); err != nil {
		return ""
	}
	_ = d.files.natIn.SetReadDeadline(time.Now().Add(natLookupTimeout))
	m, err := d.natReader.Next()
	_ = d.files.natIn.SetReadDeadline(time.Time{})
	if err != nil {
		d.log.Warn("original destination lookup failed", "err", err)
		return ""
	}
	reply, ok := m.(*ipc.DstReply)
	if !ok {
		d.log.Warn("unexpected reply to original destination lookup")
		return ""
	}
	return reply.Dst
}
