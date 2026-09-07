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

// Package mysql implements the "mysql" database driver (port of
// drivers/mysql.c) using github.com/go-sql-driver/mysql.
//
// Configuration (section "database"): host (localhost), port (3306), name
// (greyd), user, pass and socket (a unix socket path, used instead of
// host/port when set). The tables of mysql_schema.sql are created when
// missing. Rows in entries are tagged with the greyd hostname so several
// instances can share one database.
//
// Transactions come from database/sql's BeginTx on the connection pool
// (START TRANSACTION, READ ONLY for View). Nested transactions (View or
// Update called from within a transaction function) are not supported.
package mysql

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"net"
	"strconv"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/mikey-austin/greyd-golang/adapters/db/sqlcommon"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

// DriverName is the configuration driver value.
const DriverName = "mysql"

const (
	defaultHost = "localhost"
	defaultPort = 3306
	defaultDB   = "greyd"
)

//go:embed mysql_schema.sql
var schemaSQL string

func init() {
	core.RegisterStore(DriverName, "MySQL / MariaDB server", func(cfg *config.Config, opts core.StoreOptions) (core.Store, error) {
		return New(cfg, opts), nil
	})
}

// dialect is the MySQL flavour of the shared statements.
var dialect = sqlcommon.Dialect{
	Quote:      '`',
	HostScoped: true,
	UpsertEntry: "INSERT INTO entries " +
		"(`ip`, `helo`, `from`, `to`, `first`, `pass`, `expire`, `bcount`, `pcount`, `greyd_host`) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
		"ON DUPLICATE KEY UPDATE " +
		"`first` = VALUES(`first`), `pass` = VALUES(`pass`), `expire` = VALUES(`expire`), " +
		"`bcount` = VALUES(`bcount`), `pcount` = VALUES(`pcount`), `greyd_host` = VALUES(`greyd_host`)",
	InsertSpamtrap: "INSERT IGNORE INTO spamtraps(`address`) VALUES (?)",
	InsertDomain:   "INSERT IGNORE INTO domains(`domain`) VALUES (?)",
	DomainPart:     "SELECT 1 FROM domains WHERE ? LIKE CONCAT('%', `domain`)",
	ScanWhitelist: "UPDATE IGNORE entries e LEFT JOIN entries g " +
		"ON g.`ip`=e.`ip` AND g.`to`='' AND g.`from`='' " +
		"SET e.`helo` = '', e.`from` = '', e.`to` = '', e.`expire` = ? " +
		"WHERE e.`from` <> '' AND e.`to` <> '' AND e.`pcount` >= 0 " +
		"AND g.`ip` IS NULL AND e.`pass` <= ? " +
		"AND e.`greyd_host`=?",
}

// Store is a MySQL backed core.Store.
type Store struct {
	*sqlcommon.Store
	cfg *config.Config
}

// New creates the store; the connection is made by Open.
func New(cfg *config.Config, opts core.StoreOptions) *Store {
	return &Store{Store: sqlcommon.NewStore(dialect, opts.Hostname, logger.Or(opts.Log)), cfg: cfg}
}

// Config builds the client configuration from the "database" section.
func (s *Store) Config() *gomysql.Config {
	c := gomysql.NewConfig()
	host := s.cfg.Str("host", "database", defaultHost)
	port := s.cfg.Int("port", "database", defaultPort)
	c.DBName = s.cfg.Str("name", "database", defaultDB)
	c.User = s.cfg.Str("user", "database", "")
	c.Passwd = s.cfg.Str("pass", "database", "")
	if socket := s.cfg.Str("socket", "database", ""); socket != "" {
		c.Net = "unix"
		c.Addr = socket
	} else {
		c.Net = "tcp"
		c.Addr = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return c
}

// Open connects and ensures the schema exists. It is a no-op on an open
// store. A store opened read-only refuses Update.
func (s *Store) Open(ctx context.Context, mode core.OpenMode) error {
	if s.Opened() {
		return nil
	}
	c := s.Config()
	connector, err := gomysql.NewConnector(c)
	if err != nil {
		return fmt.Errorf("could not connect to mysql %s: %w", c.Addr, err)
	}
	if err := s.Attach(ctx, sql.OpenDB(connector), mode, sqlcommon.SplitStatements(schemaSQL)); err != nil {
		return fmt.Errorf("could not connect to mysql %s: %w", c.Addr, err)
	}
	return nil
}
