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
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/mikey-austin/greyd-golang/internal/config"
)

// DriverInfo describes a compiled-in driver.
type DriverInfo struct {
	Name        string
	Description string
}

// registry is a named, sorted set of driver factories.
type registry[F any] struct {
	mu      sync.RWMutex
	entries map[string]registryEntry[F]
}

type registryEntry[F any] struct {
	info DriverInfo
	new  F
}

func newRegistry[F any]() *registry[F] {
	return &registry[F]{entries: map[string]registryEntry[F]{}}
}

func (r *registry[F]) register(name, description string, f F) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[name] = registryEntry[F]{info: DriverInfo{Name: name, Description: description}, new: f}
}

func (r *registry[F]) lookup(name string) (F, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[name]
	return e.new, ok
}

func (r *registry[F]) infos() []DriverInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]DriverInfo, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *registry[F]) names() []string {
	infos := r.infos()
	out := make([]string, len(infos))
	for i, d := range infos {
		out[i] = d.Name
	}
	return out
}

var (
	stores    = newRegistry[StoreFactory]()
	firewalls = newRegistry[FirewallFactory]()
)

// RegisterStore makes a database driver available under name. Adapters
// call it from init(); the description is shown by greyd --drivers.
func RegisterStore(name, description string, f StoreFactory) {
	stores.register(name, description, f)
}

// RegisterFirewall makes a firewall driver available under name.
func RegisterFirewall(name, description string, f FirewallFactory) {
	firewalls.register(name, description, f)
}

// StoreDrivers lists the registered database driver names.
func StoreDrivers() []string { return stores.names() }

// FirewallDrivers lists the registered firewall driver names.
func FirewallDrivers() []string { return firewalls.names() }

// StoreDriverInfos lists the registered database drivers.
func StoreDriverInfos() []DriverInfo { return stores.infos() }

// FirewallDriverInfos lists the registered firewall drivers.
func FirewallDriverInfos() []DriverInfo { return firewalls.infos() }

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

// configuredDriver reads the driver name of a section.
func configuredDriver(cfg *config.Config, section, what string) (raw, name string, err error) {
	sec := cfg.Section(section)
	if sec == nil {
		return "", "", fmt.Errorf("could not find %s configuration", what)
	}
	raw = sec.Str("driver", "")
	if raw == "" {
		return "", "", fmt.Errorf("no %s driver configured", what)
	}
	return raw, NormalizeDriver(raw), nil
}

// OpenStore constructs the configured database driver. The store is not
// yet opened (Store.Open must be called), mirroring DB_init/DB_open.
func OpenStore(cfg *config.Config, opts StoreOptions) (Store, error) {
	raw, name, err := configuredDriver(cfg, "database", "database")
	if err != nil {
		return nil, err
	}
	f, ok := stores.lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown database driver %q (available: %s)", raw, strings.Join(StoreDrivers(), ", "))
	}
	return f(cfg, opts)
}

// OpenFirewall constructs and opens the configured firewall driver
// (FW_open).
func OpenFirewall(ctx context.Context, cfg *config.Config, opts FirewallOptions) (Firewall, error) {
	raw, name, err := configuredDriver(cfg, "firewall", "firewall")
	if err != nil {
		return nil, err
	}
	f, ok := firewalls.lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown firewall driver %q (available: %s)", raw, strings.Join(FirewallDrivers(), ", "))
	}
	fw, err := f(cfg, opts)
	if err != nil {
		return nil, err
	}
	if err := fw.Open(ctx); err != nil {
		return nil, fmt.Errorf("could not obtain firewall handle: %w", err)
	}
	return fw, nil
}

// FilesystemUser is implemented by stores that keep files on disk, so a
// sandbox can leave their directories writable.
type FilesystemUser interface {
	// WritablePaths lists the directories the store writes to.
	WritablePaths() []string
}

// WritablePaths returns the directories a store needs, if it says.
func WritablePaths(s Store) []string {
	if fu, ok := s.(FilesystemUser); ok {
		return fu.WritablePaths()
	}
	return nil
}
