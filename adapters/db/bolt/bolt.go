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

// Package bolt implements the database port on top of bbolt, a pure Go
// embedded key/value store. It replaces the Berkeley DB driver (bdb.c) of
// the C implementation: one file under the configured "path" directory
// holding the entries, spamtraps and domains buckets, with the key and
// value encodings and the scan algorithm shared with the memory driver
// through package kv.
//
// View and Update map directly onto bbolt's read and write transactions.
// bbolt allows one writer at a time, so calling Update from within a
// transaction function is not supported (it would block forever).
package bolt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	bbolt "go.etcd.io/bbolt"

	"github.com/mikey-austin/greyd-golang/adapters/db/kv"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

// DriverName is the configuration driver value.
const DriverName = "bolt"

const (
	// DefaultPath is the default database directory.
	DefaultPath = "/var/db/greyd"
	// DefaultDBName is the default database file name within the path.
	DefaultDBName = "greyd.db"

	// lockTimeout bounds how long Open waits for the file lock held by
	// another process before failing instead of hanging.
	lockTimeout = 5 * time.Second
)

// errStop ends a ForEach walk early.
var errStop = errors.New("stop")

func init() {
	core.RegisterStore(DriverName, func(cfg *config.Config, opts core.StoreOptions) (core.Store, error) {
		return New(cfg, opts)
	})
}

// New prepares a store from the "database" configuration section
// (Mod_db_init): the directory is created with mode 0700 when missing and,
// when it was just created, chowned to the database user. The file itself
// is opened by Open.
func New(cfg *config.Config, opts core.StoreOptions) (*Store, error) {
	dir := cfg.Str("path", "database", DefaultPath)
	name := cfg.Str("db_name", "database", DefaultDBName)

	if err := os.Mkdir(dir, 0o700); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("db environment path %s: %w", dir, err)
		}
	} else if opts.User != nil {
		uid, err := strconv.Atoi(opts.User.Uid)
		if err != nil {
			return nil, fmt.Errorf("invalid uid %q: %w", opts.User.Uid, err)
		}
		gid, err := strconv.Atoi(opts.User.Gid)
		if err != nil {
			return nil, fmt.Errorf("invalid gid %q: %w", opts.User.Gid, err)
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return nil, fmt.Errorf("chown %s failed: %w", dir, err)
		}
	}

	return &Store{path: filepath.Join(dir, name), log: logger.Or(opts.Log)}, nil
}

// Store is a bbolt backed core.Store. It is not safe for concurrent use.
type Store struct {
	path string
	log  *slog.Logger
	db   *bbolt.DB
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Open opens the database file, creating it and the buckets in read-write
// mode. Opening an already open store is a no-op.
func (s *Store) Open(ctx context.Context, mode core.OpenMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.db != nil {
		return nil
	}
	opts := *bbolt.DefaultOptions
	opts.Timeout = lockTimeout
	opts.ReadOnly = mode == core.OpenRO

	db, err := bbolt.Open(s.path, 0o600, &opts)
	if err != nil {
		return fmt.Errorf("open %s: %w", s.path, err)
	}
	if !opts.ReadOnly {
		err := db.Update(func(tx *bbolt.Tx) error {
			for _, b := range []kv.Bucket{kv.BucketEntries, kv.BucketSpamtraps, kv.BucketDomains} {
				if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
					return fmt.Errorf("create bucket %s: %w", b, err)
				}
			}
			return nil
		})
		if err != nil {
			db.Close()
			return err
		}
	}
	s.db = db
	return nil
}

// Close closes the file. Closing an unopened store is a no-op.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// View runs fn in a read transaction.
func (s *Store) View(ctx context.Context, fn func(core.ReadTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.db == nil {
		return core.ErrNotOpen
	}
	btx, err := s.db.Begin(false)
	if err != nil {
		return err
	}
	defer s.rollback(btx)
	return fn(&tx{btx: btx})
}

// Update runs fn in a write transaction, committing when fn returns nil
// and rolling back otherwise. A store opened read-only refuses it.
func (s *Store) Update(ctx context.Context, fn func(core.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.db == nil {
		return core.ErrNotOpen
	}
	if s.db.IsReadOnly() {
		return core.ErrReadOnly
	}
	btx, err := s.db.Begin(true)
	if err != nil {
		return err
	}
	if err := fn(&tx{btx: btx}); err != nil {
		s.rollback(btx)
		return err
	}
	// A failed Commit rolls the transaction back itself.
	return btx.Commit()
}

func (s *Store) rollback(btx *bbolt.Tx) {
	if err := btx.Rollback(); err != nil {
		s.log.Warn("bolt rollback failed", "err", err, "path", s.path)
	}
}

// bucket returns the named bucket, which is nil only for a read-only open
// of a file that was never initialised.
func bucket(btx *bbolt.Tx, b kv.Bucket) *bbolt.Bucket {
	return btx.Bucket([]byte(b))
}

func mustBucket(btx *bbolt.Tx, b kv.Bucket) (*bbolt.Bucket, error) {
	bk := bucket(btx, b)
	if bk == nil {
		return nil, fmt.Errorf("bolt: bucket %s does not exist", b)
	}
	return bk, nil
}

// tx implements core.Tx over a bbolt transaction; a read transaction
// refuses writes.
type tx struct {
	btx *bbolt.Tx
}

func (t *tx) Put(k core.Key, d core.Data) error {
	if !t.btx.Writable() {
		return core.ErrReadOnly
	}
	bk, err := mustBucket(t.btx, kv.BucketFor(k.Type))
	if err != nil {
		return err
	}
	return bk.Put(kv.EncodeKey(k), kv.EncodeData(d))
}

func (t *tx) Get(k core.Key) (core.Data, bool, error) {
	bk := bucket(t.btx, kv.BucketFor(k.Type))
	if bk == nil {
		return core.Data{}, false, nil
	}
	if k.Type == core.KeyDomainPart {
		err := bk.ForEach(func(raw, _ []byte) error {
			dk, err := kv.DecodeKey(raw)
			if err != nil {
				return err
			}
			if kv.DomainMatches(dk.Str, k.Str) {
				return errStop
			}
			return nil
		})
		switch {
		case errors.Is(err, errStop):
			return core.Data{PCount: core.PCountDomain}, true, nil
		case err != nil:
			return core.Data{}, false, err
		default:
			return core.Data{}, false, nil
		}
	}
	v := bk.Get(kv.EncodeKey(k))
	if v == nil {
		return core.Data{}, false, nil
	}
	d, err := kv.DecodeData(v)
	if err != nil {
		return core.Data{}, false, err
	}
	return d, true, nil
}

func (t *tx) Del(k core.Key) (bool, error) {
	if !t.btx.Writable() {
		return false, core.ErrReadOnly
	}
	bk, err := mustBucket(t.btx, kv.BucketFor(k.Type))
	if err != nil {
		return false, err
	}
	ek := kv.EncodeKey(k)
	if bk.Get(ek) == nil {
		return false, nil
	}
	return true, bk.Delete(ek)
}

// Iter snapshots the keys of the selected buckets. Entries are looked up
// again on Next so that deletions made during the walk are honoured and
// no bbolt cursor is held while the buckets are mutated.
func (t *tx) Iter(types core.IterTypes) (core.Iterator, error) {
	it := &iterator{t: t, pos: -1}
	for _, sel := range []struct {
		t core.IterTypes
		b kv.Bucket
	}{{core.IterEntries, kv.BucketEntries}, {core.IterSpamtraps, kv.BucketSpamtraps}, {core.IterDomains, kv.BucketDomains}} {
		if types&sel.t == 0 {
			continue
		}
		bk := bucket(t.btx, sel.b)
		if bk == nil {
			continue
		}
		if err := bk.ForEach(func(k, _ []byte) error {
			it.keys = append(it.keys, append([]byte(nil), k...))
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return it, nil
}

func (t *tx) Scan(now, whiteExp int64) (core.ScanResult, error) {
	if !t.btx.Writable() {
		return core.ScanResult{}, core.ErrReadOnly
	}
	return kv.Scan(t, now, whiteExp)
}

type iterator struct {
	t    *tx
	keys [][]byte
	pos  int
	curr core.Key
	has  bool
}

func (it *iterator) Next() (core.Key, core.Data, bool, error) {
	for {
		it.pos++
		if it.pos >= len(it.keys) {
			it.has = false
			return core.Key{}, core.Data{}, false, nil
		}
		raw := it.keys[it.pos]
		k, err := kv.DecodeKey(raw)
		if err != nil {
			return core.Key{}, core.Data{}, false, err
		}
		bk := bucket(it.t.btx, kv.BucketFor(k.Type))
		if bk == nil {
			continue
		}
		v := bk.Get(raw)
		if v == nil {
			continue // deleted since the snapshot was taken
		}
		d, err := kv.DecodeData(v)
		if err != nil {
			return core.Key{}, core.Data{}, false, err
		}
		it.curr = k
		it.has = true
		return k, d, true, nil
	}
}

func (it *iterator) ReplaceCurrent(d core.Data) error {
	if !it.has {
		return kv.ErrNoCurrent
	}
	return it.t.Put(it.curr, d)
}

func (it *iterator) DeleteCurrent() error {
	if !it.has {
		return kv.ErrNoCurrent
	}
	_, err := it.t.Del(it.curr)
	return err
}

func (it *iterator) Close() error {
	it.keys = nil
	it.has = false
	return nil
}
