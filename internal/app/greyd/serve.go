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
	"log/slog"
	"os/user"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mikey-austin/greyd-v2/internal/ipc"
	"github.com/mikey-austin/greyd-v2/internal/privs"
	"github.com/mikey-austin/greyd-v2/internal/sandbox"
	"github.com/mikey-austin/greyd-v2/internal/smtp"
	gsync "github.com/mikey-austin/greyd-v2/internal/sync"
	"github.com/mikey-austin/greyd-v2/internal/version"
)

// serve runs the daemon until ctx is done (the rest of main()). The
// phases are: privileged setup (pidfile, children, sync sockets),
// confinement (chroot and privilege drop), the service loops, and an
// orderly shutdown.
func (d *daemon) serve(ctx context.Context, start childStarter) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pw, err := d.lookupMainUser()
	if err != nil {
		return err
	}
	if err := d.writePidfile(pw); err != nil {
		return err
	}
	kids, err := d.startChildren(ctx, start)
	if err != nil {
		return err
	}
	if kids != nil && kids.reload != nil {
		d.reload = kids.reload
	}
	d.counters = smtp.NewCounters(d.maxCons, d.maxBlack)
	syncer, syncRecv := d.startSync()

	if err := d.confine(pw); err != nil {
		return err
	}
	d.sandbox()

	d.log.Warn("listening for incoming connections")
	if d.main6Ln != nil {
		d.log.Warn("listening for incoming IPv6 connections")
	}

	srv := d.newSMTPServer()
	loops := newLoopGroup(ctx)
	loops.run("main socket", func() error { return srv.ServeListener(ctx, d.mainLn) })
	if d.main6Ln != nil {
		loops.run("main IPv6 socket", func() error { return srv.ServeListener(ctx, d.main6Ln) })
	}
	loops.run("config socket", func() error { return d.serveConfig(ctx) })
	if d.greylist {
		loops.run("trap pipe", func() error { return d.readTrapPipe(ctx) })
	}
	if syncer != nil && syncRecv {
		loops.run("syncer", func() error { return syncer.Serve(ctx, d.files.greyOut) })
	}

	var exited <-chan struct{}
	if kids != nil {
		exited = kids.exited
	}
	select {
	case <-ctx.Done():
	case err := <-loops.fatal:
		d.log.Warn(err.Error())
	case <-exited:
		d.log.Warn("child process exited")
	}

	d.shutdown(cancel, srv, syncer, kids, loops)
	return nil
}

// lookupMainUser resolves the unprivileged user before any chroot hides
// the user database.
func (d *daemon) lookupMainUser() (*user.User, error) {
	if !d.s.DropPrivs {
		return nil, nil
	}
	return privs.LookupUser(d.s.User)
}

func (d *daemon) writePidfile(pw *user.User) error {
	path := d.s.GreydPidfile
	if path == "" {
		path = version.GreydPidfile
	}
	pf, err := privs.WritePidfile(path, pw)
	if err != nil {
		if errors.Is(err, privs.ErrAlreadyRunning) {
			return errors.New("it appears greyd is already running")
		}
		return fmt.Errorf("could not write pidfile %s: %w", path, err)
	}
	d.pidfile = pf
	return nil
}

// startChildren launches the firewall and greylister processes when
// greylisting is enabled and rebalances the connection limits.
func (d *daemon) startChildren(ctx context.Context, start childStarter) (*children, error) {
	if !d.greylist {
		return nil, nil
	}
	kids, err := start(ctx, d.s, d.log)
	if err != nil {
		return nil, err
	}
	d.files = kids.files
	d.natReader = ipc.NewReader(d.files.natIn)

	// Ensure that the grey connections outweigh the blacklisted.
	if d.maxBlack >= d.maxCons {
		d.maxBlack = d.maxCons - 100
	}
	if d.maxBlack < 0 {
		d.log.Warn("maximum blacklisted connections is 0")
		d.maxBlack = 0
	}
	return kids, nil
}

// startSync brings up the sync engine in receive-only mode; the
// greylister sends. It reports whether the engine listens.
func (d *daemon) startSync() (*gsync.Engine, bool) {
	s := d.s.WithoutSyncHosts()
	syncRecv := d.opts.SyncRecv > 0 || s.Sync.BindAddress != ""
	if d.opts.SyncSend == 0 && !syncRecv {
		return nil, false
	}
	eng, err := gsync.New(s.Sync, s.Grey.Enable, d.log)
	switch {
	case err != nil:
		d.log.Warn("could not start sync engine", "err", err)
		return nil, syncRecv
	case eng == nil:
		d.log.Warn("sync disabled by configuration")
		return nil, syncRecv
	}
	if err := eng.Start(); err != nil {
		d.log.Warn("could not start sync engine", "err", err)
		return nil, syncRecv
	}
	return eng, syncRecv
}

// confine chroots and drops privileges according to the configuration.
// Started without root (socket activation as the service user) the
// chroot is skipped with a warning and the user must already match.
func (d *daemon) confine(pw *user.User) error {
	return confine(d.s.Chroot, d.s.ChrootDir, d.s.DropPrivs, pw, d.log, &d.chroot)
}

// confine is shared by the main and firewall processes.
func confine(chroot bool, dir string, dropPrivs bool, pw *user.User, log *slog.Logger, applied *string) error {
	if chroot {
		if err := privs.Chroot(dir); err != nil {
			if privs.Privileged() {
				return err
			}
			log.Warn("running unprivileged: chroot skipped", "dir", dir, "err", err)
		} else if applied != nil {
			*applied = dir
		}
	}
	if dropPrivs {
		if err := privs.SwitchUser(pw); err != nil {
			if !errors.Is(err, privs.ErrCannotSwitch) {
				return fmt.Errorf("failed to drop privileges: %w", err)
			}
			log.Warn("running unprivileged: continuing as the current user", "wanted", pw.Username)
		}
	}
	return nil
}

// sandbox confines the main process: it only needs its sockets and
// pipes, plus the pidfile and configuration socket to remove at exit when
// not chrooted.
func (d *daemon) sandbox() {
	if !d.s.Sandbox {
		return
	}
	p := sandbox.Profile{Role: sandbox.RoleMain, Strict: d.s.SandboxStrict}
	// The pidfile (and the configuration socket) are removed at exit, so
	// their directories stay writable: as seen from inside the chroot
	// when there is one, otherwise as given.
	if dir, ok := insideChroot(d.pidfile.Path(), d.chroot); ok {
		p.WritePaths = append(p.WritePaths, dir)
	}
	if d.s.ConfigSocket != "" {
		if dir, ok := insideChroot(d.s.ConfigSocket, d.chroot); ok {
			p.WritePaths = append(p.WritePaths, dir)
		}
	}
	applySandbox(p, d.log)
}

// insideChroot returns the directory of path as the process now sees it:
// unchanged without a chroot, made relative to the new root when path
// lies under it, and not at all (false) when the chroot hides it.
func insideChroot(path, chroot string) (string, bool) {
	if chroot == "" {
		return filepath.Dir(path), true
	}
	rel := strings.TrimPrefix(path, strings.TrimSuffix(chroot, "/"))
	if rel == path || !strings.HasPrefix(rel, "/") {
		return "", false
	}
	return filepath.Dir(rel), true
}

// applySandbox applies a profile, treating an unsupported platform as a
// debug event and any other failure as a warning: greyd keeps serving mail
// without the extra confinement.
func applySandbox(p sandbox.Profile, log *slog.Logger) {
	err := sandbox.Apply(p, log)
	switch {
	case err == nil:
	case errors.Is(err, sandbox.ErrUnsupported):
		log.Debug("sandbox unavailable on this platform", "role", p.Role.String())
	default:
		log.Warn("sandbox not applied", "role", p.Role.String(), "err", err)
	}
}

func (d *daemon) newSMTPServer() *smtp.Server {
	cfg := smtp.ConfigFrom(d.s)
	cfg.PermittedProxies = d.proxies
	deps := smtp.Deps{Blacklists: d.snapshotBlacklists, Log: d.log}
	if d.greylist {
		deps.GreyOut = d.files.greyOut
		deps.OrigDst = d.lookupOrigDst
	}
	return smtp.NewServer(cfg, deps, d.counters)
}

// shutdown stops everything in dependency order and waits for the loops.
func (d *daemon) shutdown(cancel context.CancelFunc, srv *smtp.Server, syncer *gsync.Engine, kids *children, loops *loopGroup) {
	d.log.Debug("stopping main process")
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
	loops.wait()
	if err := d.pidfile.Close(d.chroot); err != nil {
		d.log.Warn(err.Error())
	}
}

// loopGroup runs the service loops and reports the first failure that
// happens before shutdown.
type loopGroup struct {
	ctx   context.Context
	wg    sync.WaitGroup
	fatal chan error
}

func newLoopGroup(ctx context.Context) *loopGroup {
	return &loopGroup{ctx: ctx, fatal: make(chan error, 8)}
}

func (g *loopGroup) run(name string, f func() error) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if err := f(); err != nil && g.ctx.Err() == nil {
			g.fatal <- fmt.Errorf("%s: %w", name, err)
		}
	}()
}

func (g *loopGroup) wait() { g.wg.Wait() }
