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
package bolt

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	bbolt "go.etcd.io/bbolt"

	"github.com/mikey-austin/greyd-golang/adapters/db/kv"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
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

var (
	errNotOpen   = errors.New("bolt: database not open")
	errNoCurrent = errors.New("bolt: iterator has no current entry")
	// errStop ends a ForEach walk early.
	errStop = errors.New("stop")
)

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

	return &Store{path: filepath.Join(dir, name)}, nil
}

// Store is a bbolt backed core.Store. It is not safe for concurrent use.
type Store struct {
	path string
	db   *bbolt.DB
	// tx is the explicit transaction opened by Begin, nil otherwise.
	tx *bbolt.Tx
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Open opens the database file, creating it and the buckets in read-write
// mode. Opening an already open store is a no-op.
func (s *Store) Open(mode core.OpenMode) error {
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

// Close rolls back any open transaction and closes the file.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	if s.tx != nil {
		_ = s.tx.Rollback()
		s.tx = nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Begin starts an explicit transaction: writable unless the store was
// opened read-only.
func (s *Store) Begin() error {
	if s.db == nil {
		return errNotOpen
	}
	if s.tx != nil {
		return core.ErrInTransaction
	}
	tx, err := s.db.Begin(!s.db.IsReadOnly())
	if err != nil {
		return err
	}
	s.tx = tx
	return nil
}

// Commit finishes the explicit transaction. A read-only transaction has
// nothing to write and is simply released.
func (s *Store) Commit() error {
	if s.tx == nil {
		return core.ErrNotInTransaction
	}
	tx := s.tx
	s.tx = nil
	if !tx.Writable() {
		return tx.Rollback()
	}
	return tx.Commit()
}

// Rollback discards the explicit transaction.
func (s *Store) Rollback() error {
	if s.tx == nil {
		return core.ErrNotInTransaction
	}
	tx := s.tx
	s.tx = nil
	return tx.Rollback()
}

// update runs fn inside the explicit transaction when there is one,
// otherwise in a short writable transaction of its own.
func (s *Store) update(fn func(tx *bbolt.Tx) error) error {
	if s.db == nil {
		return errNotOpen
	}
	if s.tx != nil {
		return fn(s.tx)
	}
	return s.db.Update(fn)
}

// view is the read-only counterpart of update.
func (s *Store) view(fn func(tx *bbolt.Tx) error) error {
	if s.db == nil {
		return errNotOpen
	}
	if s.tx != nil {
		return fn(s.tx)
	}
	return s.db.View(fn)
}

// bucket returns the named bucket, which is nil only for a read-only open
// of a file that was never initialised.
func bucket(tx *bbolt.Tx, b kv.Bucket) *bbolt.Bucket {
	return tx.Bucket([]byte(b))
}

func mustBucket(tx *bbolt.Tx, b kv.Bucket) (*bbolt.Bucket, error) {
	bk := bucket(tx, b)
	if bk == nil {
		return nil, fmt.Errorf("bolt: bucket %s does not exist", b)
	}
	return bk, nil
}

func (s *Store) Put(k core.Key, d core.Data) error {
	return s.update(func(tx *bbolt.Tx) error {
		bk, err := mustBucket(tx, kv.BucketFor(k.Type))
		if err != nil {
			return err
		}
		return bk.Put(kv.EncodeKey(k), kv.EncodeData(d))
	})
}

func (s *Store) Get(k core.Key) (core.Data, bool, error) {
	var (
		d     core.Data
		found bool
	)
	err := s.view(func(tx *bbolt.Tx) error {
		bk := bucket(tx, kv.BucketFor(k.Type))
		if bk == nil {
			return nil
		}
		if k.Type == core.KeyDomainPart {
			err := bk.ForEach(func(raw, _ []byte) error {
				dk, err := kv.DecodeKey(raw)
				if err != nil {
					return err
				}
				if kv.DomainMatches(dk.Str, k.Str) {
					d = core.Data{PCount: core.PCountDomain}
					found = true
					return errStop
				}
				return nil
			})
			if errors.Is(err, errStop) {
				return nil
			}
			return err
		}
		v := bk.Get(kv.EncodeKey(k))
		if v == nil {
			return nil
		}
		var err error
		d, err = kv.DecodeData(v)
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return core.Data{}, false, err
	}
	return d, found, nil
}

func (s *Store) Del(k core.Key) (bool, error) {
	var found bool
	err := s.update(func(tx *bbolt.Tx) error {
		bk, err := mustBucket(tx, kv.BucketFor(k.Type))
		if err != nil {
			return err
		}
		ek := kv.EncodeKey(k)
		if bk.Get(ek) == nil {
			return nil
		}
		found = true
		return bk.Delete(ek)
	})
	return found && err == nil, err
}

// Iter snapshots the keys of the selected buckets. Entries are looked up
// again on Next so that deletions made during the walk are honoured and
// no bbolt cursor is held while the buckets are mutated.
func (s *Store) Iter(types core.IterTypes) (core.Iterator, error) {
	it := &iterator{s: s, pos: -1}
	err := s.view(func(tx *bbolt.Tx) error {
		for _, sel := range []struct {
			t core.IterTypes
			b kv.Bucket
		}{{core.IterEntries, kv.BucketEntries}, {core.IterSpamtraps, kv.BucketSpamtraps}, {core.IterDomains, kv.BucketDomains}} {
			if types&sel.t == 0 {
				continue
			}
			bk := bucket(tx, sel.b)
			if bk == nil {
				continue
			}
			if err := bk.ForEach(func(k, _ []byte) error {
				it.keys = append(it.keys, append([]byte(nil), k...))
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return it, nil
}

func (s *Store) Scan(now, whiteExp int64) (core.ScanResult, error) {
	return kv.Scan(s, now, whiteExp)
}

type iterator struct {
	s    *Store
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
		var (
			d  core.Data
			ok bool
		)
		err = it.s.view(func(tx *bbolt.Tx) error {
			bk := bucket(tx, kv.BucketFor(k.Type))
			if bk == nil {
				return nil
			}
			v := bk.Get(raw)
			if v == nil {
				return nil // deleted since the snapshot was taken
			}
			var err error
			d, err = kv.DecodeData(v)
			if err != nil {
				return err
			}
			ok = true
			return nil
		})
		if err != nil {
			return core.Key{}, core.Data{}, false, err
		}
		if !ok {
			continue
		}
		it.curr = k
		it.has = true
		return k, d, true, nil
	}
}

func (it *iterator) ReplaceCurrent(d core.Data) error {
	if !it.has {
		return errNoCurrent
	}
	return it.s.Put(it.curr, d)
}

func (it *iterator) DeleteCurrent() error {
	if !it.has {
		return errNoCurrent
	}
	_, err := it.s.Del(it.curr)
	return err
}

func (it *iterator) Close() error {
	it.keys = nil
	it.has = false
	return nil
}
