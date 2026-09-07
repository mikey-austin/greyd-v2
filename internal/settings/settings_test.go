package settings

import (
	"errors"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-v2/internal/config/parse"
)

func TestDefaults(t *testing.T) {
	cfg, err := parse.String("")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Daemonize || !s.DropPrivs || !s.Chroot || s.ChrootDir != "/var/empty" || s.Port != 8025 || s.ConfigPort != 8026 ||
		s.MaxCons != 800 || s.Stutter != 1 || s.ErrorCode != "450" || s.Banner != "greyd IP-based SPAM blocker" || s.User != "greyd" {
		t.Fatalf("global defaults %+v", s.Global)
	}
	if !s.Grey.Enable || s.Grey.User != "greydb" || s.Grey.PassTime != 1500 || s.Grey.GreyExpiry != 14400 ||
		s.Grey.WhiteExpiry != 3110400 || s.Grey.TrapExpiry != 86400 || s.Grey.Stutter != 10 || s.Grey.TraplistName != "greyd-greytrap" {
		t.Fatalf("grey defaults %+v", s.Grey)
	}
	if s.Sync.Enable || s.Sync.Port != 8025 || s.Sync.TTL != 1 || !s.Sync.Verify || s.Sync.Key != "/etc/greyd/greyd.key" || s.Sync.McastAddress != "224.0.1.241" {
		t.Fatalf("sync defaults %+v", s.Sync)
	}
	if !s.SPF.Enable || !s.SPF.TrapOnSoftfail || s.SPF.WhitelistOnPass {
		t.Fatalf("spf defaults %+v", s.SPF)
	}
	if s.Setup.CurlPath != "/bin/curl" || len(s.Setup.Lists) != 0 {
		t.Fatalf("setup defaults %+v", s.Setup)
	}
	if len(s.Warnings) != 0 {
		t.Fatalf("warnings %v", s.Warnings)
	}
}

func TestLoadValues(t *testing.T) {
	cfg, err := parse.String(`
debug = 1
port = 2525
hostname = "mx"
proxy_protocol_enable = 1
proxy_protocol_permitted_proxies = [ "127.0.0.0/8", "::1" ]
low_prio_mx = "10.0.0.9"
section grey { enable = 0, pass_time = 60, permitted_domains = "/tmp/pd" }
section sync { enable = 1, hosts = [ "eth0:2", "a.example.org" ], bind_address = "eth0" }
section spf { whitelist_on_pass = 1 }
section setup { lists = [ "nixspam" ], curl_proxy = "p:1" }
section firewall { driver = "netfilter", max_elements = 5 }
section database { driver = "sqlite", path = "/tmp" }
blacklist nixspam { message = "m", method = "file", file = "/tmp/x" }
whitelist friends { method = "file", file = "/tmp/y" }
`)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Debug || s.Port != 2525 || s.Hostname != "mx" || !s.ProxyProtocolEnable || len(s.ProxyProtocolPermittedProxies) != 2 {
		t.Fatalf("global %+v", s.Global)
	}
	if s.Grey.Enable || s.Grey.PassTime != 60 || s.Grey.PermittedDomains != "/tmp/pd" || s.Grey.LowPrioMX != "10.0.0.9" {
		t.Fatalf("grey %+v", s.Grey)
	}
	if !s.Sync.Enable || len(s.Sync.Hosts) != 2 || s.Sync.BindAddress != "eth0" {
		t.Fatalf("sync %+v", s.Sync)
	}
	if !s.SPF.WhitelistOnPass || s.Setup.CurlProxy != "p:1" || s.Setup.Lists[0] != "nixspam" {
		t.Fatal("spf/setup")
	}
	if s.Firewall.Driver != "netfilter" || s.Firewall.Raw.Int("max_elements", 0) != 5 || s.Database.Driver != "sqlite" || s.Database.Raw.Str("path", "") != "/tmp" {
		t.Fatal("driver sections")
	}
	if s.Blacklists["nixspam"] == nil || s.Whitelists["friends"] == nil {
		t.Fatal("lists")
	}
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "low_prio_mx belongs in the grey section") {
		t.Fatalf("warnings %v", s.Warnings)
	}
	if s.Raw() != cfg {
		t.Fatal("Raw")
	}
	c := s.WithoutSyncBind()
	if c.Sync.BindAddress != "" || s.Sync.BindAddress != "eth0" {
		t.Fatal("WithoutSyncBind must copy")
	}
	c = s.WithoutSyncHosts()
	if c.Sync.Hosts != nil || len(s.Sync.Hosts) != 2 {
		t.Fatal("WithoutSyncHosts must copy")
	}
}

func TestUnknownVariablesWarn(t *testing.T) {
	cfg, _ := parse.String("sutter = 1\nsection grey { pass_tim = 5 }\nsection firewall { anything = 1 }\n")
	s, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Warnings) != 2 {
		t.Fatalf("warnings %v", s.Warnings)
	}
	for _, w := range s.Warnings {
		if !strings.Contains(w, "unknown variable") {
			t.Fatalf("warning %q", w)
		}
	}
}

func TestTypeErrors(t *testing.T) {
	for _, src := range []string{`port = "x"`, `hostname = 5`, `debug = "yes"`, `section sync { hosts = 3 }`} {
		cfg, err := parse.String(src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Load(cfg); err == nil {
			t.Fatalf("%q should fail", src)
		}
	}
}

func TestValidation(t *testing.T) {
	cases := []string{
		`port = 70000`,
		`error_code = "451"`,
		`max_cons = 0`,
		`stutter = 11`,
		`chroot = 1
chroot_dir = ""`,
		`proxy_protocol_enable = 1`,
		`section grey { grey_expiry = 0 }`,
		`section sync { ttl = 300 }`,
		`max_line_length = 10`,
	}
	for _, src := range cases {
		cfg, err := parse.String(src)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Load(cfg)
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("%q: expected validation error, got %v", src, err)
		}
	}
	// Several problems are reported together.
	cfg, _ := parse.String("port = 70000\nmax_cons = 0\n")
	_, err := Load(cfg)
	var ve *ValidationError
	if !errors.As(err, &ve) || len(ve.Errs) != 2 || !strings.Contains(err.Error(), "port must be") {
		t.Fatalf("aggregate: %v", err)
	}
}
