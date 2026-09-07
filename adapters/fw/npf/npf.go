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

// Package npf is the NetBSD firewall driver: whitelists live in NPF
// tables (declared in npf.conf as dynamic ipset or lpm tables) that are
// replaced through npfctl(8), connections are tracked by reading the
// npflog(4) interface with bpf(4), whose records have the pflog layout,
// and original destination lookups return the proxy address (NPF has no
// public lookup call the way PF has DIOCNATLOOK; use greyd's low priority
// MX trap only where connections are not redirected).
//
// npfctl needs the NPF device, which only root may open, so the process
// holding this driver keeps its privileges (core.PrivilegeKeeper).
//
// Configuration (section "firewall"): npfctl_path (default
// /sbin/npfctl), npflog_if (default npflog0), net_if and track_outbound
// as for the pf driver.
package npf

import "strings"

// DriverName is the configuration driver value.
const DriverName = "npf"

// Defaults for the "firewall" section.
const (
	DefaultNpfctlPath    = "/sbin/npfctl"
	DefaultLogIf         = "npflog0"
	DefaultTrackOutbound = 1
)

// ReplaceFile renders the table contents npfctl expects from "table
// <name> replace <file>": one address or prefix per line.
func ReplaceFile(cidrs []string) string {
	var sb strings.Builder
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		sb.WriteString(c)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// ValidTableName reports whether name is usable as an NPF table name:
// letters, digits, '_', '-' and '.'; up to 31 characters.
func ValidTableName(name string) bool {
	if name == "" || len(name) > 31 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c == '_' || c == '-' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}
