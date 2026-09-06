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

package core

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/mikey-austin/greyd-golang/internal/config"
)

var (
	regMu     sync.RWMutex
	stores    = map[string]StoreFactory{}
	firewalls = map[string]FirewallFactory{}
)

// RegisterStore makes a database driver available under name. Adapters
// call it from init().
func RegisterStore(name string, f StoreFactory) {
	regMu.Lock()
	defer regMu.Unlock()
	stores[name] = f
}

// RegisterFirewall makes a firewall driver available under name.
func RegisterFirewall(name string, f FirewallFactory) {
	regMu.Lock()
	defer regMu.Unlock()
	firewalls[name] = f
}

// StoreDrivers lists the registered database driver names.
func StoreDrivers() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	return sortedKeys(stores)
}

// FirewallDrivers lists the registered firewall driver names.
func FirewallDrivers() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	return sortedKeys(firewalls)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NormalizeDriver maps a configured driver value to a driver name. The C
// implementation loaded shared objects, so existing configuration files
// contain values such as "/usr/lib/greyd/greyd_sqlite.so"; the basename is
// taken, a "greyd_" prefix and a ".so"/".la" suffix are removed and the
// Berkeley DB drivers map to the bolt replacement.
func NormalizeDriver(v string) string {
	v = strings.TrimSpace(v)
	v = path.Base(v)
	v = strings.TrimSuffix(v, ".so")
	v = strings.TrimSuffix(v, ".la")
	v = strings.TrimPrefix(v, "greyd_")
	v = strings.ToLower(v)
	switch v {
	case "bdb", "bdb_sql":
		return "bolt"
	case "fw_dummy":
		return "dummy"
	}
	return v
}

// OpenStore constructs the configured database driver. The store is not
// yet opened (Store.Open must be called), mirroring DB_init/DB_open.
func OpenStore(cfg *config.Config, opts StoreOptions) (Store, error) {
	sec := cfg.Section("database")
	if sec == nil {
		return nil, fmt.Errorf("could not find database configuration")
	}
	raw := sec.Str("driver", "")
	if raw == "" {
		return nil, fmt.Errorf("no database driver configured")
	}
	name := NormalizeDriver(raw)
	regMu.RLock()
	f, ok := stores[name]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown database driver %q (available: %s)", raw, strings.Join(StoreDrivers(), ", "))
	}
	return f(cfg, opts)
}

// OpenFirewall constructs and opens the configured firewall driver
// (FW_open).
func OpenFirewall(cfg *config.Config) (Firewall, error) {
	sec := cfg.Section("firewall")
	if sec == nil {
		return nil, fmt.Errorf("could not find firewall configuration")
	}
	raw := sec.Str("driver", "")
	if raw == "" {
		return nil, fmt.Errorf("no firewall driver configured")
	}
	name := NormalizeDriver(raw)
	regMu.RLock()
	f, ok := firewalls[name]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown firewall driver %q (available: %s)", raw, strings.Join(FirewallDrivers(), ", "))
	}
	fw, err := f(cfg)
	if err != nil {
		return nil, err
	}
	if err := fw.Open(); err != nil {
		return nil, fmt.Errorf("could not obtain firewall handle: %w", err)
	}
	return fw, nil
}
