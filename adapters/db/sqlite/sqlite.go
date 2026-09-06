//go:build !dragonfly

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

// Package sqlite implements the "sqlite" database driver (port of
// drivers/sqlite.c) on top of the pure Go modernc.org/sqlite library.
//
// Configuration (section "database"): "path" is the directory holding the
// database file (default /var/db/greyd, created mode 0700 when missing)
// and "db_name" the file name (default greyd.sqlite).
//
// Every transaction runs on one pinned connection: Update issues BEGIN
// IMMEDIATE and retries while another process holds the database lock;
// View issues a plain BEGIN. Nested transactions (View or Update called
// from within a transaction function) are not supported.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/mikey-austin/greyd-golang/adapters/db/sqlcommon"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
	msqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// DriverName is the configuration driver value.
const DriverName = "sqlite"

const (
	defaultPath = "/var/db/greyd"
	defaultDB   = "greyd.sqlite"
	// A busy database is retried this many times, sleeping retryDelay in
	// between, before BEGIN/COMMIT give up (MAX_RETRY/RETRY_SECS).
	maxRetry   = 20
	retryDelay = 5 * time.Second
)

// sleep is the retry delay function; tests replace it.
var sleep = time.Sleep

func init() {
	core.RegisterStore(DriverName, func(cfg *config.Config, opts core.StoreOptions) (core.Store, error) {
		return New(cfg, opts)
	})
}

// dialect is the SQLite flavour of the shared statements.
var dialect = sqlcommon.Dialect{
	Quote:      '`',
	PinnedConn: true,
	Begin:      "BEGIN IMMEDIATE",
	UpsertEntry: "INSERT OR REPLACE INTO entries " +
		"(`ip`, `helo`, `from`, `to`, `first`, `pass`, `expire`, `bcount`, `pcount`) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
	InsertSpamtrap: "INSERT OR IGNORE INTO spamtraps(`address`) VALUES (?)",
	InsertDomain:   "INSERT OR IGNORE INTO domains(`domain`) VALUES (?)",
	DomainPart:     "SELECT 1 FROM domains WHERE ? LIKE '%' || `domain`",
	ScanWhitelist: "UPDATE OR REPLACE entries " +
		"SET `helo` = '', `from` = '', `to` = '', `expire` = ? " +
		"WHERE `from` <> '' AND `to` <> '' AND `pcount` >= 0 AND `pass` <= ? " +
		"AND `ip` NOT IN (SELECT `ip` FROM entries WHERE `from` = '' AND `to` = '')",
}

// schema is created on every open (CREATE TABLE IF NOT EXISTS).
var schema = []string{
	"CREATE TABLE IF NOT EXISTS spamtraps(" +
		"`address` VARCHAR(1024), " +
		"PRIMARY KEY(`address`))",
	"CREATE TABLE IF NOT EXISTS domains(" +
		"`domain` VARCHAR(1024), " +
		"PRIMARY KEY(`domain`))",
	"CREATE TABLE IF NOT EXISTS entries(" +
		"`ip` VARCHAR(46), " +
		"`helo` VARCHAR(1024), " +
		"`from` VARCHAR(1024), " +
		"`to` VARCHAR(1024), " +
		"`first` UNSIGNED BIGINT, " +
		"`pass` UNSIGNED BIGINT, " +
		"`expire` UNSIGNED BIGINT, " +
		"`bcount` INTEGER, " +
		"`pcount` INTEGER, " +
		"PRIMARY KEY (`ip`, `helo`, `from`, `to`))",
}

// Store is an SQLite backed core.Store.
type Store struct {
	*sqlcommon.Store
	path string
	log  *slog.Logger
}

// New creates the store and its directory (Mod_db_init). The database is
// opened by Open.
func New(cfg *config.Config, opts core.StoreOptions) (*Store, error) {
	dir := cfg.Str("path", "database", defaultPath)
	name := cfg.Str("db_name", "database", defaultDB)

	if err := os.Mkdir(dir, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("sqlite3 db path: %w", err)
		}
	} else if opts.User != nil {
		// The directory has just been created: ensure the correct
		// ownership.
		uid, err1 := strconv.Atoi(opts.User.Uid)
		gid, err2 := strconv.Atoi(opts.User.Gid)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("invalid uid/gid for %s", opts.User.Username)
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return nil, fmt.Errorf("chown %s failed: %w", dir, err)
		}
	}

	log := logger.Or(opts.Log)
	s := &Store{
		Store: sqlcommon.NewStore(dialect, opts.Hostname, log),
		path:  filepath.Join(dir, name),
		log:   log,
	}
	s.TxnRetry = s.retryBusy
	return s, nil
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Open opens the database file and ensures the schema exists. It is a
// no-op on an open store. A store opened read-only refuses Update.
func (s *Store) Open(ctx context.Context, mode core.OpenMode) error {
	if s.Opened() {
		return nil
	}
	db, err := sql.Open("sqlite", s.path)
	if err != nil {
		return fmt.Errorf("could not open %s: %w", s.path, err)
	}
	// Transactions are plain BEGIN/COMMIT statements, so everything has
	// to run on the one pinned connection.
	db.SetMaxOpenConns(1)
	if err := s.Attach(ctx, db, mode, schema); err != nil {
		return fmt.Errorf("could not open %s: %w", s.path, err)
	}
	return nil
}

// retryBusy runs a BEGIN/COMMIT statement, retrying while the database is
// locked by another process.
func (s *Store) retryBusy(run func() error) error {
	for retries := 0; ; retries++ {
		err := run()
		if err == nil || !isBusy(err) || retries >= maxRetry {
			return err
		}
		s.log.Warn("db busy, retrying", "path", s.path, "delay", retryDelay,
			"try", retries+1, "max", maxRetry)
		sleep(retryDelay)
	}
}

// isBusy reports whether err is SQLITE_BUSY (any extended code).
func isBusy(err error) bool {
	var se *msqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_BUSY
}
