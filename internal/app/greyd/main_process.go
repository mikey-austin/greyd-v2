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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mikey-austin/greyd-golang/internal/blacklist"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	"github.com/mikey-austin/greyd-golang/internal/privs"
	"github.com/mikey-austin/greyd-golang/internal/procs"
	"github.com/mikey-austin/greyd-golang/internal/smtp"
	gsync "github.com/mikey-austin/greyd-golang/internal/sync"
	"github.com/mikey-austin/greyd-golang/internal/version"
)

// natLookupTimeout bounds a firewall NAT lookup (DNAT_LOOKUP_TIMEOUT).
const natLookupTimeout = time.Second

// cfgConnTimeout bounds reading a blacklist from a configuration
// connection.
const cfgConnTimeout = 30 * time.Second

// mainFiles are the parent's pipe ends.
type mainFiles struct {
	greyOut *os.File // -> grey child
	fwOut   *os.File // -> fw child (nat requests)
	natIn   *os.File // <- fw child (nat answers)
	trapIn  *os.File // <- grey child (traplist)
}

func (f mainFiles) closeAll() {
	for _, x := range []*os.File{f.greyOut, f.fwOut, f.natIn, f.trapIn} {
		if x != nil {
			_ = x.Close()
		}
	}
}

// children is what a child starter returns: the parent's pipe ends plus a
// function that terminates the children and waits for them.
type children struct {
	files mainFiles
	// exited is closed when a child exits unexpectedly.
	exited <-chan struct{}
	stop   func()
}

// childStarter launches the firewall and greylister roles; spawnChildren
// re-executes the binary, tests run them in-process.
type childStarter func(ctx context.Context, cfg *config.Config) (*children, error)

// daemon is the main process state (struct Greyd_state).
type daemon struct {
	cfg      *config.Config
	opts     Options
	maxFiles int
	maxCons  int
	maxBlack int
	greylist bool

	mainLn  net.Listener
	main6Ln net.Listener
	cfgLn   net.Listener

	blMu   sync.Mutex
	blMap  map[string]*blacklist.Blacklist
	blList []*blacklist.Blacklist

	proxies  *blacklist.Blacklist
	counters *smtp.Counters

	natMu     sync.Mutex
	natReader *ipc.Reader

	files   mainFiles
	pidfile *privs.Pidfile
	chroot  string
}

// newDaemon validates the configuration and computes the connection
// limits (the first part of main()).
func newDaemon(cfg *config.Config, o Options, maxFiles int) (*daemon, error) {
	d := &daemon{cfg: cfg, opts: o, maxFiles: maxFiles, blMap: make(map[string]*blacklist.Blacklist)}

	d.maxCons = min(cfg.Int("max_cons", "", smtp.DefaultMax), maxFiles)
	d.maxBlack = min(cfg.Int("max_cons_black", "", smtp.DefaultMax), maxFiles)
	d.greylist = cfg.Bool("enable", "grey", greylistEnabled)

	if cfg.Bool("proxy_protocol_enable", "", false) {
		logger.Info("proxy protocol enabled")
		d.proxies = permittedProxies(cfg.StrList("proxy_protocol_permitted_proxies", ""))
	}

	if !d.greylist {
		d.maxBlack = d.maxCons
	} else if d.maxBlack > d.maxCons {
		return nil, fmt.Errorf("Max black cons (%d) must not exceed total max cons (%d)\n%s", d.maxBlack, d.maxCons, Usage)
	}

	if cfg.Bool("setrlimit", "", setrlimitDef == 1) {
		if err := privs.SetMaxFiles(d.maxCons + 15); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// permittedProxies builds the allow list of upstream proxies
// (Greyd_set_proxy_protocol_permitted_proxies).
func permittedProxies(cidrs []string) *blacklist.Blacklist {
	bl := blacklist.New("permitted-proxies", "permitted upstream proxies", blacklist.StorageList)
	if len(cidrs) == 0 {
		logger.Warning("no permitted proxies configured, refusing to serve requests")
		return bl
	}
	for _, c := range cidrs {
		if err := bl.Add(c); err != nil {
			logger.Warning("ignoring invalid permitted proxy %q: %v", c, err)
			continue
		}
		logger.Info("allowing upstream proxy -> %s", c)
	}
	return bl
}

func reuseAddr(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return serr
}

// bind creates the listening sockets while still privileged.
func (d *daemon) bind() error {
	cfg := d.cfg
	lc := net.ListenConfig{Control: reuseAddr}
	port := cfg.Int("port", "", DefaultPort)
	cfgPort := cfg.Int("config_port", "", DefaultCfgPort)

	bindAddr := cfg.Str("bind_address", "", "")
	if bindAddr != "" {
		if a, err := netip.ParseAddr(bindAddr); err != nil || !a.Is4() {
			return fmt.Errorf("inet_pton: invalid bind_address %q", bindAddr)
		}
	}
	ln, err := lc.Listen(context.Background(), "tcp4", net.JoinHostPort(bindAddr, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	d.mainLn = ln

	if cfg.Bool("enable_ipv6", "", false) {
		bind6 := cfg.Str("bind_address_ipv6", "", "")
		if bind6 != "" {
			if a, err := netip.ParseAddr(bind6); err != nil || !a.Is6() {
				_ = ln.Close()
				return fmt.Errorf("inet_pton: invalid bind_address_ipv6 %q", bind6)
			}
		}
		ln6, err := lc.Listen(context.Background(), "tcp6", net.JoinHostPort(bind6, strconv.Itoa(port)))
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("bind IPv6: %w", err)
		}
		d.main6Ln = ln6
	}

	cfgLn, err := lc.Listen(context.Background(), "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfgPort)))
	if err != nil {
		d.closeListeners()
		return fmt.Errorf("bind local: %w", err)
	}
	d.cfgLn = cfgLn
	return nil
}

func (d *daemon) closeListeners() {
	for _, l := range []net.Listener{d.mainLn, d.main6Ln, d.cfgLn} {
		if l != nil {
			_ = l.Close()
		}
	}
}

// MainAddr returns the SMTP listener address (tests).
func (d *daemon) MainAddr() net.Addr { return d.mainLn.Addr() }

// CfgAddr returns the configuration listener address (tests).
func (d *daemon) CfgAddr() net.Addr { return d.cfgLn.Addr() }

// serve runs the daemon until ctx is done (the rest of main()).
func (d *daemon) serve(ctx context.Context, start childStarter) error {
	cfg := d.cfg
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mainUser := cfg.Str("user", "", MainUser)
	dropPrivs := cfg.Bool("drop_privs", "", true)
	var pw *user.User
	if dropPrivs {
		var err error
		if pw, err = privs.LookupUser(mainUser); err != nil {
			return err
		}
	}

	pidPath := cfg.Str("greyd_pidfile", "", version.GreydPidfile)
	pf, err := privs.WritePidfile(pidPath, pw)
	if err != nil {
		if errors.Is(err, privs.ErrAlreadyRunning) {
			return fmt.Errorf("it appears greyd is already running...")
		}
		return fmt.Errorf("could not write pidfile %s: %w", pidPath, err)
	}
	d.pidfile = pf

	var kids *children
	if d.greylist {
		kids, err = start(ctx, cfg)
		if err != nil {
			return err
		}
		d.files = kids.files
		d.natReader = ipc.NewReader(d.files.natIn)

		// Ensure that the grey connections outweigh the blacklisted.
		if d.maxBlack >= d.maxCons {
			d.maxBlack = d.maxCons - 100
		}
		if d.maxBlack < 0 {
			logger.Warning("maximum blacklisted connections is 0")
			d.maxBlack = 0
		}
	}
	d.counters = smtp.NewCounters(d.maxCons, d.maxBlack)

	// We only receive sync messages in this process; the greylister sends.
	cfg.Delete("hosts", "sync")
	syncRecv := d.opts.SyncRecv > 0 || cfg.Str("bind_address", "sync", "") != ""
	var syncer *gsync.Engine
	if d.opts.SyncSend > 0 || syncRecv {
		eng, err := gsync.New(cfg)
		switch {
		case err != nil:
			logger.Warning("could not start sync engine: %v", err)
		case eng == nil:
			logger.Warning("sync disabled by configuration")
		default:
			if err := eng.Start(); err != nil {
				logger.Warning("could not start sync engine: %v", err)
			} else {
				syncer = eng
			}
		}
	}

	if cfg.Bool("chroot", "", DefaultChroot == 1) {
		d.chroot = cfg.Str("chroot_dir", "", ChrootDir)
		if err := privs.Chroot(d.chroot); err != nil {
			return err
		}
	}
	if dropPrivs {
		if err := privs.Drop(pw); err != nil {
			return fmt.Errorf("failed to drop privileges: %w", err)
		}
	}

	logger.Warning("listening for incoming connections")
	if d.main6Ln != nil {
		logger.Warning("listening for incoming IPv6 connections")
	}

	smtpCfg := smtp.ConfigFrom(cfg)
	smtpCfg.PermittedProxies = d.proxies
	deps := smtp.Deps{Blacklists: d.snapshotBlacklists}
	if d.greylist {
		deps.GreyOut = d.files.greyOut
		deps.OrigDst = d.lookupOrigDst
	}
	srv := smtp.NewServer(smtpCfg, deps, d.counters)

	var wg sync.WaitGroup
	fatal := make(chan error, 8)
	run := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil && ctx.Err() == nil {
				fatal <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	run("main socket", func() error { return srv.ServeListener(ctx, d.mainLn) })
	if d.main6Ln != nil {
		run("main IPv6 socket", func() error { return srv.ServeListener(ctx, d.main6Ln) })
	}
	run("config socket", func() error { return d.serveConfig(ctx) })
	if d.greylist {
		run("trap pipe", func() error { return d.readTrapPipe(ctx) })
	}
	if syncer != nil && syncRecv {
		run("syncer", func() error { return syncer.Serve(ctx, d.files.greyOut) })
	}

	var exited <-chan struct{}
	if kids != nil {
		exited = kids.exited
	}
	select {
	case <-ctx.Done():
	case err := <-fatal:
		logger.Warning("%v", err)
	case <-exited:
		logger.Warning("child process exited")
	}

	logger.Debug("stopping main process")
	cancel()
	d.closeListeners()
	srv.Shutdown()
	if syncer != nil {
		syncer.Stop()
	}
	if kids != nil {
		kids.stop()
	}
	d.files.closeAll()
	wg.Wait()
	if err := d.pidfile.Close(d.chroot); err != nil {
		logger.Warning("%v", err)
	}
	return nil
}

// snapshotBlacklists returns the current blacklists in configuration
// order.
func (d *daemon) snapshotBlacklists() []*blacklist.Blacklist {
	d.blMu.Lock()
	defer d.blMu.Unlock()
	out := make([]*blacklist.Blacklist, len(d.blList))
	copy(out, d.blList)
	return out
}

// addBlacklist installs a blacklist received on the configuration socket
// or the trap pipe, replacing any existing one of the same name
// (Greyd_process_config).
func (d *daemon) addBlacklist(m *config.Config) {
	sec := m.Section(config.DefaultSection)
	if sec == nil || sec.Get("name") == nil || sec.Get("message") == nil || sec.Get("ips") == nil {
		return
	}
	name := sec.Str("name", "")
	msg := sec.Str("message", "")
	ips := sec.Get("ips").Strings()
	if sec.Get("ips").Type != config.TypeList {
		return
	}
	bl := blacklist.New(name, msg, blacklist.StorageTrie)
	for _, a := range ips {
		if err := bl.Add(a); err != nil {
			logger.Debug("blacklist %s: ignoring %q: %v", name, a, err)
		}
	}

	d.blMu.Lock()
	defer d.blMu.Unlock()
	if old, ok := d.blMap[name]; ok {
		for i, b := range d.blList {
			if b == old {
				d.blList[i] = bl
				break
			}
		}
	} else {
		d.blList = append(d.blList, bl)
	}
	d.blMap[name] = bl
	logger.Debug("loaded blacklist %s with %d entries", name, bl.Count)
}

// serveConfig accepts configuration connections one at a time. Only
// connections from a privileged source port are accepted.
func (d *daemon) serveConfig(ctx context.Context) error {
	for {
		conn, err := d.cfgLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
				time.Sleep(time.Second)
				continue
			}
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ECONNABORTED) {
				continue
			}
			return err
		}
		d.handleConfigConn(conn)
	}
}

func (d *daemon) handleConfigConn(conn net.Conn) {
	defer conn.Close()
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.Port >= IPPortReserved {
		logger.Debug("rejecting configuration connection from unprivileged port")
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(cfgConnTimeout))
	m, err := ipc.NewReader(conn).Next()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			logger.Warning("configuration connection: %v", err)
		}
		return
	}
	d.addBlacklist(m)
}

// readTrapPipe installs traplists sent by the greylister.
func (d *daemon) readTrapPipe(ctx context.Context) error {
	rd := ipc.NewReader(d.files.trapIn)
	for {
		m, err := rd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			logger.Warning("trap pipe: %v", err)
			continue
		}
		d.addBlacklist(m)
	}
}

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
		logger.Warning("poll original dst: %v", err)
		return ""
	}
	return m.Str("dst", "", "")
}

// spawnChildren re-executes the binary as the firewall and greylister
// roles, passing the pipe ends as inherited descriptors.
func spawnChildren(ctx context.Context, cfg *config.Config) (*children, error) {
	mk := func() (*os.File, *os.File, error) { return os.Pipe() }

	fwR, fwW, err := mk() // main -> fw
	if err != nil {
		return nil, fmt.Errorf("firewall pipe: %w", err)
	}
	natR, natW, err := mk() // fw -> main
	if err != nil {
		return nil, fmt.Errorf("firewall nat pipe: %w", err)
	}
	greyFwR, greyFwW, err := mk() // grey -> fw
	if err != nil {
		return nil, fmt.Errorf("grey firewall pipe: %w", err)
	}
	greyR, greyW, err := mk() // main -> grey
	if err != nil {
		return nil, fmt.Errorf("grey pipe: %w", err)
	}
	trapR, trapW, err := mk() // grey -> main
	if err != nil {
		return nil, fmt.Errorf("trap pipe: %w", err)
	}

	fwCmd, err := procs.Spawn{Role: RoleFirewall, Files: map[string]*os.File{
		fdFwIn: fwR, fdNatOut: natW, fdGreyFwIn: greyFwR,
	}}.Start()
	if err != nil {
		return nil, fmt.Errorf("fork firewall failed: %w", err)
	}
	greyCmd, err := procs.Spawn{Role: RoleGrey, Files: map[string]*os.File{
		fdGreyIn: greyR, fdTrapOut: trapW, fdFwOut: greyFwW,
	}}.Start()
	if err != nil {
		_ = fwCmd.Process.Kill()
		return nil, fmt.Errorf("fork greylister: %w", err)
	}

	// The parent keeps only its own ends.
	for _, f := range []*os.File{fwR, natW, greyFwR, greyFwW, greyR, trapW} {
		_ = f.Close()
	}

	exited := make(chan struct{})
	var once sync.Once
	waitFor := func(c *exec.Cmd, name string) {
		err := c.Wait()
		if ctx.Err() == nil {
			logger.Warning("%s process exited: %v", name, err)
			once.Do(func() { close(exited) })
		}
	}
	go waitFor(fwCmd, "firewall")
	go waitFor(greyCmd, "greylister")

	stop := func() {
		for _, c := range []*exec.Cmd{fwCmd, greyCmd} {
			if c.Process != nil {
				_ = c.Process.Signal(syscall.SIGTERM)
			}
		}
		deadline := time.After(5 * time.Second)
		done := make(chan struct{})
		go func() {
			for _, c := range []*exec.Cmd{fwCmd, greyCmd} {
				_, _ = c.Process.Wait()
			}
			close(done)
		}()
		select {
		case <-done:
		case <-deadline:
			for _, c := range []*exec.Cmd{fwCmd, greyCmd} {
				_ = c.Process.Kill()
			}
		}
	}

	return &children{
		files:  mainFiles{greyOut: greyW, fwOut: fwW, natIn: natR, trapIn: trapR},
		exited: exited,
		stop:   stop,
	}, nil
}
