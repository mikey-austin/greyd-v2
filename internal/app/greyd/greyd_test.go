package greyd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mikey-austin/greyd-golang/adapters/db/all"
	"github.com/mikey-austin/greyd-golang/adapters/db/memory"
	_ "github.com/mikey-austin/greyd-golang/adapters/fw/all"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/config/parse"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/version"
)

func init() {
	_ = logger.Setup(logger.Options{Ident: "test", Stderr: io.Discard})
	spfFactory = func() core.SPFChecker { return nil }
	scanInterval = 100 * time.Millisecond
}

func TestParseFlags(t *testing.T) {
	o, err := ParseFlags([]string{"-f", "/tmp/x.conf", "-G", "25:4:864", "-b", "-5", "-Y", "a", "-Y", "b", "-y", "eth0", "-dvF6", "-h", "mx", "-l", "127.0.0.1", "-L", "::1", "-p", "1025", "-P", "/tmp/p", "-s", "2", "-S", "20", "-M", "10.0.0.1", "-n", "banner", "-w", "10", "-B", "50", "-c", "100"}, 800)
	if err != nil {
		t.Fatal(err)
	}
	c := o.Opts
	checks := map[string]int{
		"pass_time|grey": 1500, "grey_expiry|grey": 14400, "white_expiry|grey": 3110400,
		"enable|grey": 0, "debug|": 1, "verbose|": 1, "daemonize|": 0, "enable_ipv6|": 1,
		"port|": 1025, "stutter|": 2, "stutter|grey": 20, "window|": 10, "max_cons_black|": 50, "max_cons|": 100,
	}
	for k, want := range checks {
		parts := strings.SplitN(k, "|", 2)
		if got := c.Int(parts[0], parts[1], -1); got != want {
			t.Fatalf("%s = %d want %d", k, got, want)
		}
	}
	strs := map[string]string{
		"error_code|": "550", "hostname|": "mx", "bind_address|": "127.0.0.1", "bind_address_ipv6|": "::1",
		"greyd_pidfile|": "/tmp/p", "low_prio_mx|grey": "10.0.0.1", "banner|": "banner", "bind_address|sync": "eth0",
	}
	for k, want := range strs {
		parts := strings.SplitN(k, "|", 2)
		if got := c.Str(parts[0], parts[1], ""); got != want {
			t.Fatalf("%s = %q want %q", k, got, want)
		}
	}
	if o.ConfigFile != "/tmp/x.conf" || o.SyncSend != 2 || o.SyncRecv != 1 || len(c.StrList("hosts", "sync")) != 2 {
		t.Fatalf("options %+v", o)
	}
	if o2, _ := ParseFlags(nil, 800); o2.ConfigFile != version.DefaultConfig {
		t.Fatal("default config file")
	}
	if o4, _ := ParseFlags([]string{"-4"}, 800); o4.Opts.Str("error_code", "", "") != "450" {
		t.Fatal("-4")
	}
	for _, bad := range [][]string{{"-s", "11"}, {"-S", "101"}, {"-w", "0"}, {"-G", "1:2"}, {"-x"}, {"-c", "900"}, {"-B", "900"}, {"-f"}, {"positional"}, {"-p", "abc"}} {
		if _, err := ParseFlags(bad, 800); err == nil {
			t.Fatalf("%v should fail", bad)
		}
	}
}

func TestPermittedProxies(t *testing.T) {
	bl := permittedProxies([]string{"127.0.0.0/8", "bogus", "::1"})
	if !bl.Match(mustAddr("127.0.0.5")) || !bl.Match(mustAddr("::1")) || bl.Match(mustAddr("10.0.0.1")) {
		t.Fatal("permitted proxies")
	}
	if permittedProxies(nil).Match(mustAddr("127.0.0.1")) {
		t.Fatal("empty list must match nothing")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func testConfig(t *testing.T, dbName string, extra string) *config.Config {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	dir := t.TempDir()
	src := fmt.Sprintf(`
hostname = "greyd.test"
daemonize = 0
drop_privs = 0
chroot = 0
setrlimit = 0
syslog_enable = 0
bind_address = "127.0.0.1"
port = 0
config_port = 0
stutter = 0
user = %q
greyd_pidfile = %q
section grey {
  user = %q
  stutter = 0
}
section firewall {
  driver = "dummy"
}
section database {
  driver = "memory"
  name = %q
}
%s`, me.Username, filepath.Join(dir, "greyd.pid"), me.Username, dbName, extra)
	cfg, err := parse.String(src)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

type running struct {
	d    *daemon
	done chan error
	stop func()
}

func startDaemon(t *testing.T, cfg *config.Config, o Options) *running {
	t.Helper()
	d, err := newDaemon(cfg, o, 800)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.bind(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, startChildrenInProcess) }()
	r := &running{d: d, done: done}
	var once sync.Once
	r.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("serve: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("daemon did not stop")
			}
		})
	}
	t.Cleanup(r.stop)
	return r
}

func dialSMTP(t *testing.T, addr net.Addr) (net.Conn, *bufio.Reader) {
	t.Helper()
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		conn, err = net.Dial("tcp", addr.String())
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, bufio.NewReader(conn)
}

func expectLine(t *testing.T, br *bufio.Reader, prefix string) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v (have %q)", err, line)
	}
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("got %q want prefix %q", line, prefix)
	}
	return line
}

func TestGreylistedDialogueEndToEnd(t *testing.T) {
	memory.Reset("e2e")
	cfg := testConfig(t, "e2e", "")
	r := startDaemon(t, cfg, Options{Opts: config.New()})

	conn, br := dialSMTP(t, r.d.MainAddr())
	defer conn.Close()
	expectLine(t, br, "220 greyd.test ESMTP greyd IP-based SPAM blocker; ")
	fmt.Fprintf(conn, "EHLO mx.example.org\r\n")
	expectLine(t, br, "250 greyd.test")
	fmt.Fprintf(conn, "MAIL FROM:<Sender@Example.ORG>\r\n")
	expectLine(t, br, "250 OK")
	fmt.Fprintf(conn, "RCPT TO:<rcpt@greyd.test>\r\n")
	expectLine(t, br, "250 OK")
	fmt.Fprintf(conn, "DATA\r\n")
	expectLine(t, br, "451 Temporary failure, please try again later.")

	// The greylister recorded the tuple; the dst_ip came from the dummy
	// firewall's NAT lookup (which returns the local address).
	store := memory.Open("e2e")
	tuple := core.Tuple{IP: "127.0.0.1", Helo: "mx.example.org", From: "sender@example.org", To: "rcpt@greyd.test"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		d, found, _ := store.Get(core.TupleKey(tuple))
		if found {
			if d.BCount != 1 || d.PCount != 0 {
				t.Fatalf("tuple data %+v", d)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("grey tuple not recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Pidfile exists while running.
	if _, err := os.Stat(cfg.Str("greyd_pidfile", "", "")); err != nil {
		t.Fatalf("pidfile: %v", err)
	}
	r.stop()
	if _, err := os.Stat(cfg.Str("greyd_pidfile", "", "")); !os.IsNotExist(err) {
		t.Fatal("pidfile should be removed on shutdown")
	}
}

func TestTraplistFlowsBackToMain(t *testing.T) {
	memory.Reset("trap")
	// Pre-load a greytrapped address so the first scan sends a traplist.
	store := memory.Open("trap")
	now := time.Now().Unix()
	_ = store.Put(core.IPKey("127.0.0.1"), core.Data{First: now, Pass: now + 86400, Expire: now + 86400, BCount: 1, PCount: core.PCountTrapped})

	cfg := testConfig(t, "trap", `
section grey {
  user = "`+currentUser(t)+`"
  traplist_name = "greyd-greytrap"
  traplist_message = "Your address %A has mailed to spamtraps here"
}`)
	r := startDaemon(t, cfg, Options{Opts: config.New()})

	// Wait for the scanner to push the traplist to the main process.
	deadline := time.Now().Add(5 * time.Second)
	for len(r.d.snapshotBlacklists()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("traplist never arrived")
		}
		time.Sleep(20 * time.Millisecond)
	}
	bls := r.d.snapshotBlacklists()
	if bls[0].Name != "greyd-greytrap" || !bls[0].Match(mustAddr("127.0.0.1")) {
		t.Fatalf("blacklist %+v", bls[0])
	}

	// A connection from the trapped address is now blacklisted and gets
	// the traplist message.
	conn, br := dialSMTP(t, r.d.MainAddr())
	defer conn.Close()
	expectLine(t, br, "220 ")
	fmt.Fprintf(conn, "HELO x\r\nMAIL FROM:<a@b>\r\n")
	expectLine(t, br, "250 greyd.test")
	fmt.Fprintf(conn, "MAIL FROM:<a@b>\r\n")
	expectLine(t, br, "250 OK")
	fmt.Fprintf(conn, "RCPT TO:<c@d>\r\n")
	expectLine(t, br, "250 OK")
	fmt.Fprintf(conn, "DATA\r\n")
	expectLine(t, br, "354 End data")
	fmt.Fprintf(conn, "hi\r\n.\r\n")
	expectLine(t, br, "450 Your address 127.0.0.1 has mailed to spamtraps here")
}

func TestConfigSocketRejectsUnprivilegedPort(t *testing.T) {
	memory.Reset("cfgsock")
	cfg := testConfig(t, "cfgsock", "")
	r := startDaemon(t, cfg, Options{Opts: config.New()})

	conn, err := net.Dial("tcp", r.d.CfgAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = ipc.WriteBlacklist(conn, "evil", "msg", []string{"1.2.3.4"})
	// The daemon closes the connection without installing anything.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the rejected config connection to be closed")
	}
	_ = conn.Close()
	time.Sleep(50 * time.Millisecond)
	for _, bl := range r.d.snapshotBlacklists() {
		if bl.Name == "evil" {
			t.Fatal("unprivileged blacklist installed")
		}
	}

	// Installing through the same code path used by the config socket
	// works and replaces same-named lists.
	m, _ := parse.String("name=\"bl\"\nmessage=\"m %A\"\nips=[\"10.0.0.0/8\"]\n")
	r.d.addBlacklist(m)
	m, _ = parse.String("name=\"bl\"\nmessage=\"m2 %A\"\nips=[\"11.0.0.0/8\"]\n")
	r.d.addBlacklist(m)
	bls := r.d.snapshotBlacklists()
	if len(bls) != 1 || bls[0].Message != "m2 %A" || bls[0].Match(mustAddr("10.1.1.1")) || !bls[0].Match(mustAddr("11.1.1.1")) {
		t.Fatalf("replace blacklist %+v", bls)
	}
	// Incomplete frames are ignored.
	m, _ = parse.String("name=\"x\"\n")
	r.d.addBlacklist(m)
	if len(r.d.snapshotBlacklists()) != 1 {
		t.Fatal("incomplete frame installed")
	}
}

func TestMaxBlackValidation(t *testing.T) {
	cfg := testConfig(t, "mb", "max_cons = 10\nmax_cons_black = 20\n")
	if _, err := newDaemon(cfg, Options{Opts: config.New()}, 800); err == nil {
		t.Fatal("max_cons_black > max_cons must fail")
	}
	cfg = testConfig(t, "mb2", "max_cons = 10\nmax_cons_black = 20\nsection grey { enable = 0 }\n")
	d, err := newDaemon(cfg, Options{Opts: config.New()}, 800)
	if err != nil || d.maxBlack != 10 {
		t.Fatalf("blacklist-only mode: %v %d", err, d.maxBlack)
	}
	cfg = testConfig(t, "mb3", "max_cons = 5000\n")
	d, err = newDaemon(cfg, Options{Opts: config.New()}, 800)
	if err != nil || d.maxCons != 800 {
		t.Fatalf("max files clamp: %v %d", err, d.maxCons)
	}
}

func TestBindErrors(t *testing.T) {
	cfg := testConfig(t, "bind", "bind_address = \"not-an-ip\"\n")
	d, err := newDaemon(cfg, Options{Opts: config.New()}, 800)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.bind(); err == nil {
		d.closeListeners()
		t.Fatal("invalid bind_address must fail")
	}
}

func TestBlacklistOnlyMode(t *testing.T) {
	memory.Reset("bonly")
	cfg := testConfig(t, "bonly", "section grey { enable = 0 }\n")
	r := startDaemon(t, cfg, Options{Opts: config.New()})
	m, _ := parse.String("name=\"local\"\nmessage=\"blocked %A\"\nips=[\"127.0.0.0/8\"]\n")
	r.d.addBlacklist(m)

	conn, br := dialSMTP(t, r.d.MainAddr())
	defer conn.Close()
	expectLine(t, br, "220 ")
	fmt.Fprintf(conn, "HELO x\r\n")
	expectLine(t, br, "250 greyd.test")
	fmt.Fprintf(conn, "DATA\r\n")
	expectLine(t, br, "354 End data")
	fmt.Fprintf(conn, ".\r\n")
	expectLine(t, br, "450 blocked 127.0.0.1")
}

func currentUser(t *testing.T) string {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	return me.Username
}
