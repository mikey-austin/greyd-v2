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
// the iterator and the scan algorithm. The drivers only supply a Dialect
// and the connection.
//
// All statements run on one pinned connection so that BEGIN/COMMIT issued
// as plain statements scope the work that follows, exactly as the C drivers
// did with their single handle.
package sqlcommon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mikey-austin/greyd-golang/internal/core"
)

// ErrNotOpen is returned when a store is used before Open.
var ErrNotOpen = errors.New("database not open")

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

	// Begin starts a transaction ("BEGIN IMMEDIATE", "START TRANSACTION",
	// "BEGIN"). Commit and rollback are COMMIT and ROLLBACK everywhere.
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

// Conn is the subset of *sql.Conn the store executes through.
type Conn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
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

// Store implements the transactional and data operations of core.Store on
// top of a Conn. Drivers embed it and add Open/Close.
type Store struct {
	dialect Dialect
	host    string
	stmts   statements
	// TxnRetry, when set, wraps the BEGIN and COMMIT statements so a
	// driver can retry them (sqlite's busy handling).
	TxnRetry func(run func() error) error

	db    *sql.DB
	conn  *sql.Conn
	inTxn bool
}

// NewStore prepares the statements of a dialect. hostname is stored in
// greyd_host when the dialect is HostScoped.
func NewStore(d Dialect, hostname string) *Store {
	s := &Store{dialect: d, host: hostname}
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

// Opened reports whether Attach has been called.
func (s *Store) Opened() bool { return s.conn != nil }

// InTxn reports whether a transaction is open.
func (s *Store) InTxn() bool { return s.inTxn }

// Conn returns the pinned connection, or nil before Attach.
func (s *Store) Conn() Conn {
	if s.conn == nil {
		return nil
	}
	return s.conn
}

// Attach takes ownership of db, pins a single connection for the life of
// the store and runs the schema statements on it. On failure db is
// closed.
func (s *Store) Attach(db *sql.DB, schema []string) error {
	if s.conn != nil {
		db.Close()
		return errors.New("store already attached")
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		db.Close()
		return fmt.Errorf("connect: %w", err)
	}
	for _, stmt := range schema {
		if _, err := conn.ExecContext(context.Background(), stmt); err != nil {
			conn.Close()
			db.Close()
			return fmt.Errorf("db schema init failed: %w", err)
		}
	}
	s.db = db
	s.conn = conn
	return nil
}

// Close releases the connection. An open transaction is rolled back by the
// server when the connection goes away, as in the C drivers.
func (s *Store) Close() error {
	if s.conn == nil {
		return nil
	}
	var first error
	if s.inTxn {
		_, first = s.conn.ExecContext(context.Background(), "ROLLBACK")
	}
	if err := s.conn.Close(); err != nil && first == nil {
		first = err
	}
	if err := s.db.Close(); err != nil && first == nil {
		first = err
	}
	s.conn, s.db, s.inTxn = nil, nil, false
	return first
}

func (s *Store) exec(query string, args ...any) (sql.Result, error) {
	if s.conn == nil {
		return nil, ErrNotOpen
	}
	return s.conn.ExecContext(context.Background(), query, args...)
}

func (s *Store) query(query string, args ...any) (*sql.Rows, error) {
	if s.conn == nil {
		return nil, ErrNotOpen
	}
	return s.conn.QueryContext(context.Background(), query, args...)
}

func (s *Store) runTxnStmt(stmt string) error {
	run := func() error {
		_, err := s.exec(stmt)
		return err
	}
	if s.TxnRetry != nil {
		return s.TxnRetry(run)
	}
	return run()
}

// Begin starts a transaction.
func (s *Store) Begin() error {
	if s.conn == nil {
		return ErrNotOpen
	}
	if s.inTxn {
		return core.ErrInTransaction
	}
	if err := s.runTxnStmt(s.stmts.begin); err != nil {
		return fmt.Errorf("db txn start failed: %w", err)
	}
	s.inTxn = true
	return nil
}

// Commit commits the transaction.
func (s *Store) Commit() error {
	if s.conn == nil {
		return ErrNotOpen
	}
	if !s.inTxn {
		return core.ErrNotInTransaction
	}
	if err := s.runTxnStmt("COMMIT"); err != nil {
		return fmt.Errorf("db txn commit failed: %w", err)
	}
	s.inTxn = false
	return nil
}

// Rollback aborts the transaction.
func (s *Store) Rollback() error {
	if s.conn == nil {
		return ErrNotOpen
	}
	if !s.inTxn {
		return core.ErrNotInTransaction
	}
	if _, err := s.exec("ROLLBACK"); err != nil {
		return fmt.Errorf("db txn rollback failed: %w", err)
	}
	s.inTxn = false
	return nil
}

// Put stores an entry.
func (s *Store) Put(k core.Key, d core.Data) error {
	var err error
	switch k.Type {
	case core.KeyMail:
		_, err = s.exec(s.stmts.insertSpamtrap, k.Str)
	case core.KeyDomain:
		_, err = s.exec(s.stmts.insertDomain, k.Str)
	case core.KeyIP:
		_, err = s.exec(s.stmts.upsertEntry, s.entryArgs(k.Str, "", "", "", d)...)
	case core.KeyTuple:
		t := k.Tuple
		_, err = s.exec(s.stmts.upsertEntry, s.entryArgs(t.IP, t.Helo, t.From, t.To, d)...)
	default:
		return fmt.Errorf("put: unsupported key type %d", k.Type)
	}
	return err
}

func (s *Store) entryArgs(ip, helo, from, to string, d core.Data) []any {
	args := []any{ip, helo, from, to, d.First, d.Pass, d.Expire, d.BCount, d.PCount}
	if s.dialect.HostScoped {
		args = append(args, s.host)
	}
	return args
}

// Get looks an entry up.
func (s *Store) Get(k core.Key) (core.Data, bool, error) {
	if s.conn == nil {
		return core.Data{}, false, ErrNotOpen
	}
	var (
		rows *sql.Rows
		err  error
		// Spamtraps and domains carry no counters; the C drivers
		// synthesise 0, 0, 0, 0, -2 / -3.
		fixed *core.Data
	)
	switch k.Type {
	case core.KeyDomainPart:
		rows, err = s.query(s.stmts.domainPart, k.Str)
		fixed = &core.Data{PCount: core.PCountDomain}
	case core.KeyDomain:
		rows, err = s.query(s.stmts.getDomain, k.Str)
		fixed = &core.Data{PCount: core.PCountDomain}
	case core.KeyMail:
		rows, err = s.query(s.stmts.getSpamtrap, k.Str)
		fixed = &core.Data{PCount: core.PCountSpamtrap}
	case core.KeyIP:
		rows, err = s.query(s.stmts.getEntry, k.Str, "", "", "")
	case core.KeyTuple:
		t := k.Tuple
		rows, err = s.query(s.stmts.getEntry, t.IP, t.Helo, t.From, t.To)
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
func (s *Store) Del(k core.Key) (bool, error) {
	var (
		res sql.Result
		err error
	)
	switch k.Type {
	case core.KeyMail:
		res, err = s.exec(s.stmts.delSpamtrap, k.Str)
	case core.KeyDomain:
		res, err = s.exec(s.stmts.delDomain, k.Str)
	case core.KeyIP:
		res, err = s.exec(s.stmts.delEntry, k.Str, "", "", "")
	case core.KeyTuple:
		t := k.Tuple
		res, err = s.exec(s.stmts.delEntry, t.IP, t.Helo, t.From, t.To)
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
// connection while iterating.
func (s *Store) Iter(types core.IterTypes) (core.Iterator, error) {
	enabled := func(t core.IterTypes) string {
		if types&t != 0 {
			return "1=1"
		}
		return "1=0"
	}
	q := fmt.Sprintf(s.stmts.iter,
		enabled(core.IterEntries), enabled(core.IterSpamtraps), enabled(core.IterDomains))
	rows, err := s.query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	it := &iterator{s: s, pos: -1}
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
	s    *Store
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
	return it.s.Put(k, d)
}

func (it *iterator) DeleteCurrent() error {
	k, err := it.current()
	if err != nil {
		return err
	}
	_, err = it.s.Del(k)
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
func (s *Store) Scan(now, whiteExp int64) (core.ScanResult, error) {
	var res core.ScanResult

	args := []any{now}
	if s.dialect.HostScoped {
		args = append(args, s.host)
	}
	if _, err := s.exec(s.stmts.scanDelete, args...); err != nil {
		return res, fmt.Errorf("delete expired entries: %w", err)
	}

	args = []any{now + whiteExp, now}
	if s.dialect.HostScoped {
		args = append(args, s.host)
	}
	if _, err := s.exec(s.stmts.scanWhitelist, args...); err != nil {
		return res, fmt.Errorf("update db entries: %w", err)
	}

	rows, err := s.query(s.stmts.scanSelect)
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
