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

// Package sqlcommon holds the parts shared by the SQL database drivers
// (sqlite, mysql, postgresql): the statement text that is identical across
// the C drivers, the row to key/data mapping (populate_key/populate_val),
// the transaction plumbing, the iterator and the scan algorithm. The
// drivers only supply a Dialect and the connection.
//
// Transactions are driven in one of two ways, selected by the dialect:
// on a single pinned connection with BEGIN/COMMIT/ROLLBACK issued as plain
// statements (sqlite, so the driver can retry a busy database exactly as
// the C driver did), or through database/sql's BeginTx on the connection
// pool (mysql, postgresql).
package sqlcommon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

// ErrNoCurrent is returned by iterator mutations before the first Next or
// after the end.
var ErrNoCurrent = errors.New("iterator has no current entry")

// Dialect describes one SQL flavour. Statement templates are written with
// "?" placeholders and backtick quoted identifiers; SQL rewrites them for
// the dialect, so a template must not contain either character inside a
// string literal.
type Dialect struct {
	// NumberedParams rewrites "?" into "$1", "$2", ... (PostgreSQL).
	NumberedParams bool
	// Quote is the identifier quote character (` or ").
	Quote byte
	// HostScoped is set when entries rows carry a greyd_host column
	// (MySQL, PostgreSQL). Every entries insert then stores the hostname
	// and Scan's delete and whitelisting statements only touch rows of
	// this host.
	HostScoped bool

	// PinnedConn makes the store hold a single connection for its whole
	// life and drive transactions with Begin, "COMMIT" and "ROLLBACK"
	// issued as plain statements, which lets the driver retry them
	// (sqlite's busy handling). Otherwise transactions come from
	// database/sql's BeginTx on the connection pool, read-only ones for
	// View.
	PinnedConn bool
	// Begin starts a write transaction in PinnedConn mode ("BEGIN
	// IMMEDIATE"); read transactions use a plain BEGIN.
	Begin string

	// UpsertEntry inserts or replaces an entries row. Parameters: ip,
	// helo, from, to, first, pass, expire, bcount, pcount and, when
	// HostScoped, greyd_host.
	UpsertEntry string
	// InsertSpamtrap and InsertDomain insert a row unless it exists.
	// One parameter each.
	InsertSpamtrap string
	InsertDomain   string
	// DomainPart returns at least one row when a permitted domain is a
	// suffix of the single address parameter.
	DomainPart string
	// ScanWhitelist converts grey tuples whose pass time has come into
	// address rows, unless the address already has one. Parameters: the
	// new expiry, now and, when HostScoped, greyd_host.
	ScanWhitelist string
}

// SQL rewrites a statement template for the dialect.
func (d Dialect) SQL(tmpl string) string {
	var sb strings.Builder
	sb.Grow(len(tmpl) + 8)
	n := 0
	for i := 0; i < len(tmpl); i++ {
		switch c := tmpl[i]; c {
		case '?':
			if d.NumberedParams {
				n++
				sb.WriteByte('$')
				sb.WriteString(strconv.Itoa(n))
			} else {
				sb.WriteByte(c)
			}
		case '`':
			sb.WriteByte(d.Quote)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// Statement templates shared by the three C drivers.
const (
	tmplGetEntry = "SELECT `first`, `pass`, `expire`, `bcount`, `pcount` FROM entries " +
		"WHERE `ip`=? AND `helo`=? AND `from`=? AND `to`=? LIMIT 1"
	tmplGetSpamtrap = "SELECT 1 FROM spamtraps WHERE `address`=? LIMIT 1"
	tmplGetDomain   = "SELECT 1 FROM domains WHERE `domain`=? LIMIT 1"

	tmplDelEntry    = "DELETE FROM entries WHERE `ip`=? AND `helo`=? AND `from`=? AND `to`=?"
	tmplDelSpamtrap = "DELETE FROM spamtraps WHERE `address`=?"
	tmplDelDomain   = "DELETE FROM domains WHERE `domain`=?"

	// %s are replaced by "1=1" or "1=0" depending on the requested types.
	tmplIter = "SELECT `ip`, `helo`, `from`, `to`, `first`, `pass`, `expire`, `bcount`, `pcount` " +
		"FROM entries WHERE %s " +
		"UNION SELECT `address`, '', '', '', 0, 0, 0, 0, -2 FROM spamtraps WHERE %s " +
		"UNION SELECT `domain`, '', '', '', 0, 0, 0, 0, -3 FROM domains WHERE %s"

	tmplScanDelete     = "DELETE FROM entries WHERE `expire` <= ?"
	tmplScanDeleteHost = tmplScanDelete + " AND `greyd_host`=?"

	tmplScanSelect = "SELECT `ip`, NULL, NULL FROM entries " +
		"WHERE `to`='' AND `from`='' AND `ip` NOT LIKE '%:%' AND `pcount` >= 0 " +
		"UNION SELECT NULL, `ip`, NULL FROM entries " +
		"WHERE `to`='' AND `from`='' AND `ip` LIKE '%:%' AND `pcount` >= 0 " +
		"UNION SELECT NULL, NULL, `ip` FROM entries " +
		"WHERE `to`='' AND `from`='' AND `pcount` < 0"
)

// statements holds the dialect specific text of every statement.
type statements struct {
	begin, upsertEntry, insertSpamtrap, insertDomain string
	getEntry, getSpamtrap, getDomain, domainPart     string
	delEntry, delSpamtrap, delDomain                 string
	iter                                             string
	scanDelete, scanWhitelist, scanSelect            string
}

// execer is what a transaction (or, outside one, a connection or pool)
// executes statements through; *sql.DB, *sql.Conn and *sql.Tx satisfy it.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Store implements the transactional part of core.Store on top of a
// *sql.DB. Drivers embed it and add Open, which connects and calls Attach.
// A Store is not safe for concurrent use and does not support nested
// transactions: calling View or Update from within a transaction function
// is an error in PinnedConn mode and undefined otherwise.
type Store struct {
	dialect Dialect
	host    string
	stmts   statements
	log     *slog.Logger
	// TxnRetry, when set, wraps the BEGIN and COMMIT statements of
	// PinnedConn mode so a driver can retry them (sqlite's busy
	// handling).
	TxnRetry func(run func() error) error

	db *sql.DB
	// conn is the pinned connection in PinnedConn mode, nil otherwise.
	conn     *sql.Conn
	readOnly bool
}

// NewStore prepares the statements of a dialect. hostname is stored in
// greyd_host when the dialect is HostScoped; log receives diagnostics (nil
// discards them).
func NewStore(d Dialect, hostname string, log *slog.Logger) *Store {
	s := &Store{dialect: d, host: hostname, log: logger.Or(log)}
	s.stmts = statements{
		begin:          d.Begin,
		upsertEntry:    d.SQL(d.UpsertEntry),
		insertSpamtrap: d.SQL(d.InsertSpamtrap),
		insertDomain:   d.SQL(d.InsertDomain),
		getEntry:       d.SQL(tmplGetEntry),
		getSpamtrap:    d.SQL(tmplGetSpamtrap),
		getDomain:      d.SQL(tmplGetDomain),
		domainPart:     d.SQL(d.DomainPart),
		delEntry:       d.SQL(tmplDelEntry),
		delSpamtrap:    d.SQL(tmplDelSpamtrap),
		delDomain:      d.SQL(tmplDelDomain),
		iter:           d.SQL(tmplIter),
		scanDelete:     d.SQL(tmplScanDelete),
		scanWhitelist:  d.SQL(d.ScanWhitelist),
		scanSelect:     d.SQL(tmplScanSelect),
	}
	if d.HostScoped {
		s.stmts.scanDelete = d.SQL(tmplScanDeleteHost)
	}
	return s
}

// Dialect returns the store's dialect.
func (s *Store) Dialect() Dialect { return s.dialect }

// Hostname returns the greyd_host value.
func (s *Store) Hostname() string { return s.host }

// Log returns the store's logger.
func (s *Store) Log() *slog.Logger { return s.log }

// Opened reports whether Attach has been called.
func (s *Store) Opened() bool { return s.db != nil }

// Attach takes ownership of db, verifies it can be reached (pinning one
// connection in PinnedConn mode) and runs the schema statements. mode is
// remembered so that Update refuses to run on a read-only store. On
// failure db is closed.
func (s *Store) Attach(ctx context.Context, db *sql.DB, mode core.OpenMode, schema []string) error {
	if s.db != nil {
		db.Close()
		return errors.New("store already attached")
	}
	var (
		run  execer = db
		conn *sql.Conn
	)
	if s.dialect.PinnedConn {
		c, err := db.Conn(ctx)
		if err != nil {
			db.Close()
			return fmt.Errorf("connect: %w", err)
		}
		conn, run = c, c
	} else if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("connect: %w", err)
	}
	for _, stmt := range schema {
		if _, err := run.ExecContext(ctx, stmt); err != nil {
			if conn != nil {
				conn.Close()
			}
			db.Close()
			return fmt.Errorf("db schema init failed: %w", err)
		}
	}
	s.db, s.conn, s.readOnly = db, conn, mode == core.OpenRO
	return nil
}

// Close releases the connection(s). Closing an unopened store is a no-op.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	var first error
	if s.conn != nil {
		first = s.conn.Close()
	}
	if err := s.db.Close(); err != nil && first == nil {
		first = err
	}
	s.db, s.conn, s.readOnly = nil, nil, false
	return first
}

// Exec runs a statement outside any transaction (schema maintenance,
// tests). It must not be called from within a View or Update function.
func (s *Store) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if s.db == nil {
		return nil, core.ErrNotOpen
	}
	if s.conn != nil {
		return s.conn.ExecContext(ctx, query, args...)
	}
	return s.db.ExecContext(ctx, query, args...)
}

// View runs fn in a read-only transaction, which is always rolled back
// afterwards.
func (s *Store) View(ctx context.Context, fn func(core.ReadTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.db == nil {
		return core.ErrNotOpen
	}
	h, err := s.begin(ctx, true)
	if err != nil {
		return err
	}
	defer s.rollback(h)
	return fn(&tx{s: s, ctx: ctx, run: h, readOnly: true})
}

// Update runs fn in a read-write transaction, committing when fn returns
// nil and rolling back otherwise.
func (s *Store) Update(ctx context.Context, fn func(core.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.db == nil {
		return core.ErrNotOpen
	}
	if s.readOnly {
		return core.ErrReadOnly
	}
	h, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	if err := fn(&tx{s: s, ctx: ctx, run: h}); err != nil {
		s.rollback(h)
		return err
	}
	if err := h.commit(); err != nil {
		s.rollback(h)
		return fmt.Errorf("db txn commit failed: %w", err)
	}
	return nil
}

// txHandle is an open transaction of either engine.
type txHandle interface {
	execer
	commit() error
	// rollback discards the transaction; a transaction that is already
	// finished is not an error.
	rollback() error
}

func (s *Store) begin(ctx context.Context, readOnly bool) (txHandle, error) {
	if s.conn == nil {
		t, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
		if err != nil {
			return nil, fmt.Errorf("db txn start failed: %w", err)
		}
		return poolTx{t}, nil
	}
	stmt := "BEGIN"
	if !readOnly {
		stmt = s.stmts.begin
	}
	if err := s.runTxnStmt(ctx, stmt); err != nil {
		return nil, fmt.Errorf("db txn start failed: %w", err)
	}
	return connTx{s: s, ctx: ctx, conn: s.conn}, nil
}

func (s *Store) rollback(h txHandle) {
	if err := h.rollback(); err != nil {
		s.log.Warn("db txn rollback failed", "err", err)
	}
}

// runTxnStmt executes a transaction control statement on the pinned
// connection, through TxnRetry when set.
func (s *Store) runTxnStmt(ctx context.Context, stmt string) error {
	run := func() error {
		_, err := s.conn.ExecContext(ctx, stmt)
		return err
	}
	if s.TxnRetry != nil {
		return s.TxnRetry(run)
	}
	return run()
}

// poolTx is a database/sql transaction.
type poolTx struct{ *sql.Tx }

func (p poolTx) commit() error { return p.Commit() }

func (p poolTx) rollback() error {
	if err := p.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return err
	}
	return nil
}

// connTx is a transaction driven by plain statements on the pinned
// connection.
type connTx struct {
	s    *Store
	ctx  context.Context
	conn *sql.Conn
}

func (c connTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.conn.ExecContext(ctx, query, args...)
}

func (c connTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return c.conn.QueryContext(ctx, query, args...)
}

func (c connTx) commit() error { return c.s.runTxnStmt(c.ctx, "COMMIT") }

// rollback ignores the caller's cancellation: the connection is reused, so
// the transaction must end even when the context has expired.
func (c connTx) rollback() error {
	_, err := c.conn.ExecContext(context.WithoutCancel(c.ctx), "ROLLBACK")
	return err
}

// tx implements core.Tx; a read-only one refuses writes.
type tx struct {
	s        *Store
	ctx      context.Context
	run      execer
	readOnly bool
}

func (t *tx) exec(query string, args ...any) (sql.Result, error) {
	if t.readOnly {
		return nil, core.ErrReadOnly
	}
	return t.run.ExecContext(t.ctx, query, args...)
}

func (t *tx) query(query string, args ...any) (*sql.Rows, error) {
	return t.run.QueryContext(t.ctx, query, args...)
}

// Put stores an entry.
func (t *tx) Put(k core.Key, d core.Data) error {
	var err error
	switch k.Type {
	case core.KeyMail:
		_, err = t.exec(t.s.stmts.insertSpamtrap, k.Str)
	case core.KeyDomain:
		_, err = t.exec(t.s.stmts.insertDomain, k.Str)
	case core.KeyIP:
		_, err = t.exec(t.s.stmts.upsertEntry, t.entryArgs(k.Str, "", "", "", d)...)
	case core.KeyTuple:
		tp := k.Tuple
		_, err = t.exec(t.s.stmts.upsertEntry, t.entryArgs(tp.IP, tp.Helo, tp.From, tp.To, d)...)
	default:
		return fmt.Errorf("put: unsupported key type %d", k.Type)
	}
	return err
}

func (t *tx) entryArgs(ip, helo, from, to string, d core.Data) []any {
	args := []any{ip, helo, from, to, d.First, d.Pass, d.Expire, d.BCount, d.PCount}
	if t.s.dialect.HostScoped {
		args = append(args, t.s.host)
	}
	return args
}

// Get looks an entry up.
func (t *tx) Get(k core.Key) (core.Data, bool, error) {
	var (
		rows *sql.Rows
		err  error
		// Spamtraps and domains carry no counters; the C drivers
		// synthesise 0, 0, 0, 0, -2 / -3.
		fixed *core.Data
	)
	switch k.Type {
	case core.KeyDomainPart:
		rows, err = t.query(t.s.stmts.domainPart, k.Str)
		fixed = &core.Data{PCount: core.PCountDomain}
	case core.KeyDomain:
		rows, err = t.query(t.s.stmts.getDomain, k.Str)
		fixed = &core.Data{PCount: core.PCountDomain}
	case core.KeyMail:
		rows, err = t.query(t.s.stmts.getSpamtrap, k.Str)
		fixed = &core.Data{PCount: core.PCountSpamtrap}
	case core.KeyIP:
		rows, err = t.query(t.s.stmts.getEntry, k.Str, "", "", "")
	case core.KeyTuple:
		tp := k.Tuple
		rows, err = t.query(t.s.stmts.getEntry, tp.IP, tp.Helo, tp.From, tp.To)
	default:
		return core.Data{}, false, fmt.Errorf("get: unsupported key type %d", k.Type)
	}
	if err != nil {
		return core.Data{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return core.Data{}, false, rows.Err()
	}
	if fixed != nil {
		return *fixed, true, rows.Err()
	}
	var d core.Data
	if err := rows.Scan(&d.First, &d.Pass, &d.Expire, &d.BCount, &d.PCount); err != nil {
		return core.Data{}, false, err
	}
	return d, true, rows.Err()
}

// Del removes an entry and reports whether a row was deleted.
func (t *tx) Del(k core.Key) (bool, error) {
	var (
		res sql.Result
		err error
	)
	switch k.Type {
	case core.KeyMail:
		res, err = t.exec(t.s.stmts.delSpamtrap, k.Str)
	case core.KeyDomain:
		res, err = t.exec(t.s.stmts.delDomain, k.Str)
	case core.KeyIP:
		res, err = t.exec(t.s.stmts.delEntry, k.Str, "", "", "")
	case core.KeyTuple:
		tp := k.Tuple
		res, err = t.exec(t.s.stmts.delEntry, tp.IP, tp.Helo, tp.From, tp.To)
	default:
		return false, fmt.Errorf("del: unsupported key type %d", k.Type)
	}
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Iter returns an iterator over the requested entry kinds. The result set
// is read into memory before the iterator is handed out so that
// ReplaceCurrent/DeleteCurrent can execute statements on the same
// transaction while iterating.
func (t *tx) Iter(types core.IterTypes) (core.Iterator, error) {
	enabled := func(it core.IterTypes) string {
		if types&it != 0 {
			return "1=1"
		}
		return "1=0"
	}
	q := fmt.Sprintf(t.s.stmts.iter,
		enabled(core.IterEntries), enabled(core.IterSpamtraps), enabled(core.IterDomains))
	rows, err := t.query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	it := &iterator{t: t, pos: -1}
	for rows.Next() {
		var (
			ip, helo, from, to sql.NullString
			d                  core.Data
		)
		if err := rows.Scan(&ip, &helo, &from, &to, &d.First, &d.Pass, &d.Expire, &d.BCount, &d.PCount); err != nil {
			return nil, err
		}
		it.rows = append(it.rows, entry{
			k: rowKey(ip.String, helo.String, from.String, to.String, d.PCount),
			d: d,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return it, nil
}

// rowKey maps an iterator row to a key (populate_key): empty helo, from and
// to columns mark a non-grey row, whose pcount then tells spamtraps (-2)
// and permitted domains (-3) from addresses.
func rowKey(ip, helo, from, to string, pcount int) core.Key {
	if helo == "" && from == "" && to == "" {
		switch pcount {
		case core.PCountSpamtrap:
			return core.MailKey(ip)
		case core.PCountDomain:
			return core.DomainKey(ip)
		default:
			return core.IPKey(ip)
		}
	}
	return core.TupleKey(core.Tuple{IP: ip, Helo: helo, From: from, To: to})
}

type entry struct {
	k core.Key
	d core.Data
}

type iterator struct {
	t    *tx
	rows []entry
	pos  int
}

func (it *iterator) Next() (core.Key, core.Data, bool, error) {
	if it.pos+1 >= len(it.rows) {
		it.pos = len(it.rows)
		return core.Key{}, core.Data{}, false, nil
	}
	it.pos++
	e := it.rows[it.pos]
	return e.k, e.d, true, nil
}

func (it *iterator) current() (core.Key, error) {
	if it.pos < 0 || it.pos >= len(it.rows) {
		return core.Key{}, ErrNoCurrent
	}
	return it.rows[it.pos].k, nil
}

func (it *iterator) ReplaceCurrent(d core.Data) error {
	k, err := it.current()
	if err != nil {
		return err
	}
	return it.t.Put(k, d)
}

func (it *iterator) DeleteCurrent() error {
	k, err := it.current()
	if err != nil {
		return err
	}
	_, err = it.t.Del(k)
	return err
}

func (it *iterator) Close() error {
	it.rows = nil
	return nil
}

// Scan runs the three statements of Mod_scan_db: delete expired rows,
// convert grey tuples whose pass time has come into address rows, then
// collect the IPv4 and IPv6 whitelists and the traplist.
//
// The MySQL and PostgreSQL C drivers compared against the database clock
// (UNIX_TIMESTAMP(), EXTRACT(EPOCH FROM now())); the port binds the now
// argument everywhere so all drivers agree with the caller's clock.
func (t *tx) Scan(now, whiteExp int64) (core.ScanResult, error) {
	var res core.ScanResult
	if t.readOnly {
		return res, core.ErrReadOnly
	}

	args := []any{now}
	if t.s.dialect.HostScoped {
		args = append(args, t.s.host)
	}
	if _, err := t.exec(t.s.stmts.scanDelete, args...); err != nil {
		return res, fmt.Errorf("delete expired entries: %w", err)
	}

	args = []any{now + whiteExp, now}
	if t.s.dialect.HostScoped {
		args = append(args, t.s.host)
	}
	if _, err := t.exec(t.s.stmts.scanWhitelist, args...); err != nil {
		return res, fmt.Errorf("update db entries: %w", err)
	}

	rows, err := t.query(t.s.stmts.scanSelect)
	if err != nil {
		return res, fmt.Errorf("fetch white/trap entries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var white, white6, trap sql.NullString
		if err := rows.Scan(&white, &white6, &trap); err != nil {
			return res, err
		}
		switch {
		case white.Valid:
			res.Whitelist = append(res.Whitelist, white.String)
		case white6.Valid:
			res.WhitelistV6 = append(res.WhitelistV6, white6.String)
		case trap.Valid:
			res.Traplist = append(res.Traplist, trap.String)
		}
	}
	return res, rows.Err()
}

// SplitStatements breaks a schema file into individual statements,
// dropping "--" comment lines and empty statements, so drivers whose
// connection does not accept multiple statements per call can run them
// one by one.
func SplitStatements(schema string) []string {
	var sb strings.Builder
	for _, line := range strings.Split(schema, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	var out []string
	for _, stmt := range strings.Split(sb.String(), ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}
