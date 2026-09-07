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

// Package postgresql implements the "postgresql" database driver (port of
// drivers/postgresql.c) using github.com/jackc/pgx/v5/stdlib.
//
// Configuration (section "database"): host (localhost), port (5432), name
// (greyd), user, pass and socket (a unix socket directory or socket file,
// used as the host when set). The tables of postgresql_schema.sql are
// created when missing. Rows in entries are tagged with the greyd
// hostname so several instances can share one database.
//
// Transactions come from database/sql's BeginTx on the connection pool
// (BEGIN, READ ONLY for View). Nested transactions (View or Update called
// from within a transaction function) are not supported.
package postgresql

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	"github.com/mikey-austin/greyd-v2/adapters/db/sqlcommon"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/core"
	"github.com/mikey-austin/greyd-v2/internal/logger"
)

// DriverName is the configuration driver value.
const DriverName = "postgresql"

const (
	defaultHost = "localhost"
	defaultPort = 5432
	defaultDB   = "greyd"
)

//go:embed postgresql_schema.sql
var schemaSQL string

func init() {
	core.RegisterStore(DriverName, "PostgreSQL server", func(cfg *config.Config, opts core.StoreOptions) (core.Store, error) {
		return New(cfg, opts), nil
	})
}

// dialect is the PostgreSQL flavour of the shared statements.
var dialect = sqlcommon.Dialect{
	NumberedParams: true,
	Quote:          '"',
	HostScoped:     true,
	UpsertEntry: "INSERT INTO entries " +
		"(`ip`, `helo`, `from`, `to`, `first`, `pass`, `expire`, `bcount`, `pcount`, `greyd_host`) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
		"ON CONFLICT (`ip`, `helo`, `from`, `to`) DO UPDATE SET " +
		"`first` = EXCLUDED.`first`, `pass` = EXCLUDED.`pass`, `expire` = EXCLUDED.`expire`, " +
		"`bcount` = EXCLUDED.`bcount`, `pcount` = EXCLUDED.`pcount`, `greyd_host` = EXCLUDED.`greyd_host`",
	InsertSpamtrap: "INSERT INTO spamtraps(`address`) VALUES (?) ON CONFLICT (`address`) DO NOTHING",
	InsertDomain:   "INSERT INTO domains(`domain`) VALUES (?) ON CONFLICT (`domain`) DO NOTHING",
	DomainPart:     "SELECT 1 FROM domains WHERE ? LIKE ('%' || `domain`)",
	ScanWhitelist: "UPDATE entries " +
		"SET `helo` = '', `from` = '', `to` = '', `expire` = ? " +
		"FROM entries e LEFT JOIN entries g " +
		"ON g.`ip` = e.`ip` AND g.`to` = '' AND g.`from` = '' " +
		"WHERE e.`ip` = entries.`ip` AND e.`helo` = entries.`helo` " +
		"AND e.`from` = entries.`from` AND e.`to` = entries.`to` " +
		"AND e.`from` <> '' AND e.`to` <> '' AND e.`pcount` >= 0 " +
		"AND e.`pass` <= ? AND e.`greyd_host`=? " +
		"AND g.`ip` IS NULL",
}

// Store is a PostgreSQL backed core.Store.
type Store struct {
	*sqlcommon.Store
	cfg *config.Config
}

// New creates the store; the connection is made by Open.
func New(cfg *config.Config, opts core.StoreOptions) *Store {
	return &Store{Store: sqlcommon.NewStore(dialect, opts.Hostname, logger.Or(opts.Log)), cfg: cfg}
}

// ConnString builds the libpq style connection string from the "database"
// section.
func (s *Store) ConnString() string {
	host := s.cfg.Str("host", "database", defaultHost)
	if socket := s.cfg.Str("socket", "database", ""); socket != "" {
		// libpq wants the directory holding the socket; accept the
		// socket file itself too.
		if strings.HasPrefix(filepath.Base(socket), ".s.PGSQL.") {
			socket = filepath.Dir(socket)
		}
		host = socket
	}
	params := []struct{ k, v string }{
		{"host", host},
		{"port", strconv.Itoa(s.cfg.Int("port", "database", defaultPort))},
		{"dbname", s.cfg.Str("name", "database", defaultDB)},
		{"user", s.cfg.Str("user", "database", "")},
		{"password", s.cfg.Str("pass", "database", "")},
	}
	var parts []string
	for _, p := range params {
		if p.v != "" {
			parts = append(parts, p.k+"="+quoteParam(p.v))
		}
	}
	return strings.Join(parts, " ")
}

// quoteParam single-quotes a connection string value.
func quoteParam(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(v) + "'"
}

// Open connects and ensures the schema exists. It is a no-op on an open
// store. A store opened read-only refuses Update.
func (s *Store) Open(ctx context.Context, mode core.OpenMode) error {
	if s.Opened() {
		return nil
	}
	db, err := sql.Open("pgx", s.ConnString())
	if err != nil {
		return fmt.Errorf("could not connect to postgresql: %w", err)
	}
	if err := s.Attach(ctx, db, mode, sqlcommon.SplitStatements(schemaSQL)); err != nil {
		return fmt.Errorf("could not connect to postgresql: %w", err)
	}
	return nil
}
