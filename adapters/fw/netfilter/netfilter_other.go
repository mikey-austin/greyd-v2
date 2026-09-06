//go:build !linux

/*
 * Copyright (C) 2014-2026  Mikey Austin <mikey@greyd.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

// Package netfilter is the GNU/Linux firewall driver (drivers/netfilter.c):
// ipset management over netlink, NFLOG packet capture for greylogd and
// conntrack original-destination lookups. On other operating systems the
// package is empty and registers no driver, so that programs blank-importing
// adapters/fw/all still build.
package netfilter
