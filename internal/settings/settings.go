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

// Package settings is the typed view of greyd.conf(5). It decodes the
// generic configuration model into one struct per section with the
// defaults, units and validation rules of the C implementation in a single
// place, and reports unknown variables so typos are caught at load time.
package settings

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/mikey-austin/greyd-v2/internal/config"
)

// Global holds the variables of the default section.
type Global struct {
	Debug        bool   `conf:"debug" def:"0"`
	Verbose      bool   `conf:"verbose" def:"0"`
	Daemonize    bool   `conf:"daemonize" def:"1"`
	SyslogEnable bool   `conf:"syslog_enable" def:"1"`
	LogToFile    string `conf:"log_to_file"`

	User      string `conf:"user" def:"greyd"`
	DropPrivs bool   `conf:"drop_privs" def:"1"`
	Chroot    bool   `conf:"chroot" def:"1"`
	ChrootDir string `conf:"chroot_dir" def:"/var/empty"`
	SetRlimit bool   `conf:"setrlimit" def:"1"`
	// Sandbox confines each process after it has dropped privileges
	// (Landlock and seccomp on Linux, pledge on OpenBSD).
	Sandbox bool `conf:"sandbox" def:"1"`
	// SandboxStrict replaces the seccomp deny list with an allow list of
	// the system calls the Go runtime and the drivers are known to use.
	SandboxStrict bool `conf:"sandbox_strict" def:"0"`

	MaxCons      int `conf:"max_cons" def:"800"`
	MaxConsBlack int `conf:"max_cons_black" def:"800"`
	// MaxConsPerSource caps concurrent connections from one address; 0
	// disables the limit (not present in the C implementation).
	MaxConsPerSource int `conf:"max_cons_per_source" def:"0"`
	// MaxLineLength caps an SMTP command line in bytes.
	MaxLineLength int `conf:"max_line_length" def:"8191"`

	Hostname        string `conf:"hostname"`
	BindAddress     string `conf:"bind_address"`
	BindAddressIPv6 string `conf:"bind_address_ipv6"`
	EnableIPv6      bool   `conf:"enable_ipv6" def:"0"`
	Port            int    `conf:"port" def:"8025"`
	ConfigPort      int    `conf:"config_port" def:"8026"`
	// ConfigSocket is a unix domain socket path for configuration
	// connections; when set it is used instead of the loopback TCP port.
	ConfigSocket string `conf:"config_socket"`
	// MaxConfigFrame caps a blacklist frame on the configuration socket
	// in bytes.
	MaxConfigFrame int `conf:"max_config_frame" def:"67108864"`

	GreydPidfile    string `conf:"greyd_pidfile"`
	GreylogdPidfile string `conf:"greylogd_pidfile"`

	Stutter   int    `conf:"stutter" def:"1"`
	Window    int    `conf:"window" def:"0"`
	Banner    string `conf:"banner" def:"greyd IP-based SPAM blocker"`
	ErrorCode string `conf:"error_code" def:"450"`

	ProxyProtocolEnable           bool     `conf:"proxy_protocol_enable" def:"0"`
	ProxyProtocolPermittedProxies []string `conf:"proxy_protocol_permitted_proxies"`
}

// Grey holds the greylisting engine variables.
type Grey struct {
	Enable             bool   `conf:"enable" def:"1"`
	User               string `conf:"user" def:"greydb"`
	TraplistName       string `conf:"traplist_name" def:"greyd-greytrap"`
	TraplistMessage    string `conf:"traplist_message" def:"Your address %A has mailed to spamtraps here"`
	WhitelistName      string `conf:"whitelist_name" def:"greyd-whitelist"`
	WhitelistNameIPv6  string `conf:"whitelist_name_ipv6" def:"greyd-whitelist-ipv6"`
	LowPrioMX          string `conf:"low_prio_mx"`
	Stutter            int    `conf:"stutter" def:"10"`
	PermittedDomains   string `conf:"permitted_domains"`
	DBPermittedDomains bool   `conf:"db_permitted_domains" def:"0"`
	PassTime           int64  `conf:"pass_time" def:"1500"`
	GreyExpiry         int64  `conf:"grey_expiry" def:"14400"`
	WhiteExpiry        int64  `conf:"white_expiry" def:"3110400"`
	TrapExpiry         int64  `conf:"trap_expiry" def:"86400"`
	// MaxDomains caps the number of permitted domains loaded from the file.
	MaxDomains int `conf:"max_domains" def:"100000"`
}

// Sync holds the synchronisation variables.
type Sync struct {
	Enable       bool     `conf:"enable" def:"0"`
	Hosts        []string `conf:"hosts"`
	BindAddress  string   `conf:"bind_address"`
	Port         int      `conf:"port" def:"8025"`
	TTL          int      `conf:"ttl" def:"1"`
	Verify       bool     `conf:"verify" def:"1"`
	Key          string   `conf:"key" def:"/etc/greyd/greyd.key"`
	McastAddress string   `conf:"mcast_address" def:"224.0.1.241"`
	// ReplayWindow is how many counters behind the highest seen a packet
	// may be before it is rejected as a replay.
	ReplayWindow int `conf:"replay_window" def:"64"`
}

// SPF holds the SPF validation variables.
type SPF struct {
	Enable          bool `conf:"enable" def:"1"`
	TrapOnSoftfail  bool `conf:"trap_on_softfail" def:"1"`
	WhitelistOnPass bool `conf:"whitelist_on_pass" def:"0"`
}

// Monitor holds the greyd-monitor variables.
type Monitor struct {
	BindAddress string `conf:"bind_address" def:"127.0.0.1"`
	Port        int    `conf:"port" def:"9143"`
	// Interval is the number of seconds between polls of greyd.
	Interval int `conf:"interval" def:"30"`
	// User is the account greyd-monitor runs as when started by root;
	// empty means the main greyd user, which the configuration socket
	// admits.
	User string `conf:"user"`
}

// Setup holds the greyd-setup variables.
type Setup struct {
	Lists     []string `conf:"lists"`
	CurlPath  string   `conf:"curl_path" def:"/bin/curl"`
	CurlProxy string   `conf:"curl_proxy"`
	// MaxEntries caps the number of address ranges accepted from one list.
	MaxEntries int `conf:"max_entries" def:"10000000"`
}

// Firewall holds the variables common to firewall drivers; drivers read
// their own options from Raw.
type Firewall struct {
	Driver string `conf:"driver"`
	Raw    *config.Section
}

// Database holds the variables common to database drivers; drivers read
// their own options from Raw.
type Database struct {
	Driver string `conf:"driver"`
	Raw    *config.Section
}

// Settings is the typed configuration.
type Settings struct {
	Global
	Grey     Grey
	Sync     Sync
	SPF      SPF
	Setup    Setup
	Monitor  Monitor
	Firewall Firewall
	Database Database

	// Blacklists and Whitelists are the list definitions used by
	// greyd-setup, by name.
	Blacklists map[string]*config.Section
	Whitelists map[string]*config.Section

	// Warnings collected while loading (unknown variables, deprecated
	// placements).
	Warnings []string

	// raw is the configuration the settings were decoded from.
	raw *config.Config
}

// Raw returns the underlying generic configuration (for driver factories
// and tests).
func (s *Settings) Raw() *config.Config { return s.raw }

// sections lists the known sections and the struct decoded from each.
var sectionNames = []string{config.DefaultSection, "grey", "sync", "spf", "setup", "monitor", "firewall", "database"}

// Load decodes cfg. Validation failures are returned as an error; unknown
// variables only produce Warnings.
func Load(cfg *config.Config) (*Settings, error) {
	s := &Settings{raw: cfg}
	targets := map[string]any{
		config.DefaultSection: &s.Global,
		"grey":                &s.Grey,
		"sync":                &s.Sync,
		"spf":                 &s.SPF,
		"setup":               &s.Setup,
		"monitor":             &s.Monitor,
		"firewall":            &s.Firewall,
		"database":            &s.Database,
	}
	for _, name := range sectionNames {
		sec := cfg.Section(name)
		known, err := decode(targets[name], sec)
		if err != nil {
			return nil, fmt.Errorf("section %s: %w", name, err)
		}
		// Driver sections carry driver specific options.
		if sec != nil && name != "firewall" && name != "database" {
			for _, k := range sec.Keys() {
				if !known[k] {
					s.Warnings = append(s.Warnings, fmt.Sprintf("unknown variable %q in section %s", k, name))
				}
			}
		}
	}
	s.Firewall.Raw = cfg.Section("firewall")
	s.Database.Raw = cfg.Section("database")

	// The C code read low_prio_mx from the default section; keep accepting it.
	if s.Grey.LowPrioMX == "" {
		if v := cfg.Str("low_prio_mx", "", ""); v != "" {
			s.Grey.LowPrioMX = v
			s.Warnings = append(s.Warnings, "low_prio_mx belongs in the grey section")
		}
	}
	// Remove the resulting false unknown-variable warning.
	s.Warnings = filterOut(s.Warnings, fmt.Sprintf("unknown variable %q in section %s", "low_prio_mx", config.DefaultSection))

	s.Blacklists = map[string]*config.Section{}
	s.Whitelists = map[string]*config.Section{}
	for _, n := range cfg.BlacklistNames() {
		s.Blacklists[n] = cfg.Blacklist(n)
	}
	for _, n := range cfg.WhitelistNames() {
		s.Whitelists[n] = cfg.Whitelist(n)
	}

	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func filterOut(list []string, drop string) []string {
	out := list[:0]
	for _, w := range list {
		if w != drop {
			out = append(out, w)
		}
	}
	return out
}

// decode fills the tagged fields of dst from sec (which may be nil) and
// returns the set of variable names it knows.
func decode(dst any, sec *config.Section) (map[string]bool, error) {
	known := map[string]bool{}
	rv := reflect.ValueOf(dst).Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		name := f.Tag.Get("conf")
		if name == "" {
			continue
		}
		known[name] = true
		fv := rv.Field(i)
		def, hasDef := f.Tag.Lookup("def")
		var val *config.Value
		if sec != nil {
			val = sec.Get(name)
		}
		if err := setField(fv, f, val, def, hasDef); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return known, nil
}

func setField(fv reflect.Value, f reflect.StructField, val *config.Value, def string, hasDef bool) error {
	switch fv.Kind() {
	case reflect.Bool:
		n := 0
		if hasDef {
			n, _ = strconv.Atoi(def)
		}
		if val != nil {
			if val.Type != config.TypeInt {
				return errors.New("expected 0 or 1")
			}
			n = val.Int
		}
		fv.SetBool(n != 0)
	case reflect.Int, reflect.Int64:
		n := 0
		if hasDef {
			n, _ = strconv.Atoi(def)
		}
		if val != nil {
			if val.Type != config.TypeInt {
				return errors.New("expected a number")
			}
			n = val.Int
		}
		fv.SetInt(int64(n))
	case reflect.String:
		s := def
		if val != nil {
			if val.Type != config.TypeStr {
				return errors.New("expected a string")
			}
			s = val.Str
		}
		fv.SetString(s)
	case reflect.Slice:
		if val != nil {
			if val.Type != config.TypeList && val.Type != config.TypeStr {
				return errors.New("expected a list")
			}
			fv.Set(reflect.ValueOf(val.Strings()))
		}
	default:
		return fmt.Errorf("unsupported field type %s for %s", fv.Kind(), f.Name)
	}
	return nil
}

// Validate checks value ranges and cross-field constraints.
func (s *Settings) Validate() error {
	var errs []error
	check := func(ok bool, format string, a ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, a...))
		}
	}
	port := func(name string, p int) {
		check(p >= 0 && p <= 65535, "%s must be between 0 and 65535, got %d", name, p)
	}

	port("port", s.Port)
	port("config_port", s.ConfigPort)
	port("sync.port", s.Sync.Port)
	port("monitor.port", s.Monitor.Port)
	check(s.Monitor.Interval > 0, "monitor.interval must be positive, got %d", s.Monitor.Interval)
	check(s.ErrorCode == "450" || s.ErrorCode == "550", "error_code must be \"450\" or \"550\", got %q", s.ErrorCode)
	check(s.MaxCons > 0, "max_cons must be positive, got %d", s.MaxCons)
	check(s.MaxConsBlack >= 0, "max_cons_black must not be negative, got %d", s.MaxConsBlack)
	check(s.MaxConsPerSource >= 0, "max_cons_per_source must not be negative, got %d", s.MaxConsPerSource)
	check(s.MaxLineLength >= 64 && s.MaxLineLength <= 65536, "max_line_length must be between 64 and 65536, got %d", s.MaxLineLength)
	check(s.MaxConfigFrame >= 1024, "max_config_frame must be at least 1024, got %d", s.MaxConfigFrame)
	check(s.Stutter >= 0 && s.Stutter <= 10, "stutter must be between 0 and 10, got %d", s.Stutter)
	check(s.Window >= 0, "window must not be negative, got %d", s.Window)
	check(!s.Chroot || s.ChrootDir != "", "chroot_dir must be set when chroot is enabled")
	check(!s.ProxyProtocolEnable || len(s.ProxyProtocolPermittedProxies) > 0,
		"proxy_protocol_permitted_proxies must list the upstream proxies when proxy_protocol_enable is set")

	check(s.Grey.Stutter >= 0 && s.Grey.Stutter <= 100, "grey.stutter must be between 0 and 100, got %d", s.Grey.Stutter)
	check(s.Grey.PassTime >= 0, "grey.pass_time must not be negative")
	check(s.Grey.GreyExpiry > 0, "grey.grey_expiry must be positive")
	check(s.Grey.WhiteExpiry > 0, "grey.white_expiry must be positive")
	check(s.Grey.TrapExpiry > 0, "grey.trap_expiry must be positive")
	check(s.Grey.MaxDomains > 0, "grey.max_domains must be positive")

	check(s.Sync.TTL >= 1 && s.Sync.TTL <= 255, "sync.ttl must be between 1 and 255, got %d", s.Sync.TTL)
	check(s.Sync.ReplayWindow >= 0, "sync.replay_window must not be negative")
	check(s.Setup.MaxEntries > 0, "setup.max_entries must be positive")

	if len(errs) == 0 {
		return nil
	}
	return &ValidationError{Errs: errs}
}

// ValidationError aggregates every failed check.
type ValidationError struct{ Errs []error }

func (e *ValidationError) Error() string {
	msgs := make([]string, len(e.Errs))
	for i, err := range e.Errs {
		msgs[i] = err.Error()
	}
	return "invalid configuration: " + strings.Join(msgs, "; ")
}

func (e *ValidationError) Unwrap() []error { return e.Errs }

// WithoutSyncBind returns a shallow copy whose sync engine only sends
// (used by the greylister and the tools, which never receive).
func (s *Settings) WithoutSyncBind() *Settings {
	c := *s
	c.Sync.BindAddress = ""
	return &c
}

// WithoutSyncHosts returns a shallow copy whose sync engine only receives
// (used by the main greyd process).
func (s *Settings) WithoutSyncHosts() *Settings {
	c := *s
	c.Sync.Hosts = nil
	return &c
}

// DatabasePorts lists the TCP ports the configured database driver
// connects to (empty for embedded stores), for sandbox network rules.
func (s *Settings) DatabasePorts() []uint16 {
	var def int
	switch strings.ToLower(strings.TrimSpace(s.Database.Driver)) {
	case "mysql", "greyd_mysql":
		def = 3306
	case "postgresql", "postgres", "greyd_postgresql":
		def = 5432
	default:
		return nil
	}
	port := def
	if s.Database.Raw != nil {
		port = s.Database.Raw.Int("port", def)
	}
	if port <= 0 || port > 65535 {
		return nil
	}
	return []uint16{uint16(port)}
}
