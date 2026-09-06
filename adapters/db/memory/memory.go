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

// Package memory implements an in-process database driver. Stores created
// with the same "name" configuration value within one process share their
// data, so the greylister and greydb style tooling can cooperate in tests
// and in single-process deployments. Data does not survive a restart.
package memory

import (
	"sort"
	"sync"

	"github.com/mikey-austin/greyd-golang/adapters/db/kv"
	"github.com/mikey-austin/greyd-golang/internal/config"
	"github.com/mikey-austin/greyd-golang/internal/core"
)

// DriverName is the configuration driver value.
const DriverName = "memory"

func init() {
	core.RegisterStore(DriverName, func(cfg *config.Config, _ core.StoreOptions) (core.Store, error) {
		return Open(cfg.Str("name", "database", "default")), nil
	})
}

// database is the shared state behind stores of the same name.
type database struct {
	mu      sync.Mutex
	buckets map[kv.Bucket]map[string][]byte
}

var (
	dbsMu sync.Mutex
	dbs   = map[string]*database{}
)

func lookupDB(name string) *database {
	dbsMu.Lock()
	defer dbsMu.Unlock()
	db := dbs[name]
	if db == nil {
		db = newDatabase()
		dbs[name] = db
	}
	return db
}

func newDatabase() *database {
	return &database{buckets: map[kv.Bucket]map[string][]byte{
		kv.BucketEntries:   {},
		kv.BucketSpamtraps: {},
		kv.BucketDomains:   {},
	}}
}

// Reset drops all data of the named database (tests).
func Reset(name string) {
	dbsMu.Lock()
	defer dbsMu.Unlock()
	delete(dbs, name)
}

// Store is a handle onto a named in-memory database.
type Store struct {
	db       *database
	inTxn    bool
	snapshot map[kv.Bucket]map[string][]byte
}

// Open returns a handle onto the named database.
func Open(name string) *Store {
	return &Store{db: lookupDB(name)}
}

// New returns a handle onto a private, unnamed database.
func New() *Store {
	return &Store{db: newDatabase()}
}

func (s *Store) Open(core.OpenMode) error { return nil }
func (s *Store) Close() error             { return nil }

func (s *Store) Begin() error {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	if s.inTxn {
		return core.ErrInTransaction
	}
	s.snapshot = make(map[kv.Bucket]map[string][]byte, len(s.db.buckets))
	for b, m := range s.db.buckets {
		c := make(map[string][]byte, len(m))
		for k, v := range m {
			c[k] = v
		}
		s.snapshot[b] = c
	}
	s.inTxn = true
	return nil
}

func (s *Store) Commit() error {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	if !s.inTxn {
		return core.ErrNotInTransaction
	}
	s.inTxn = false
	s.snapshot = nil
	return nil
}

func (s *Store) Rollback() error {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	if !s.inTxn {
		return core.ErrNotInTransaction
	}
	s.db.buckets = s.snapshot
	s.inTxn = false
	s.snapshot = nil
	return nil
}

func (s *Store) Put(k core.Key, d core.Data) error {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	s.db.buckets[kv.BucketFor(k.Type)][string(kv.EncodeKey(k))] = kv.EncodeData(d)
	return nil
}

func (s *Store) Get(k core.Key) (core.Data, bool, error) {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	if k.Type == core.KeyDomainPart {
		for raw := range s.db.buckets[kv.BucketDomains] {
			dk, err := kv.DecodeKey([]byte(raw))
			if err != nil {
				return core.Data{}, false, err
			}
			if kv.DomainMatches(dk.Str, k.Str) {
				return core.Data{PCount: core.PCountDomain}, true, nil
			}
		}
		return core.Data{}, false, nil
	}
	v, ok := s.db.buckets[kv.BucketFor(k.Type)][string(kv.EncodeKey(k))]
	if !ok {
		return core.Data{}, false, nil
	}
	d, err := kv.DecodeData(v)
	return d, err == nil, err
}

func (s *Store) Del(k core.Key) (bool, error) {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	b := s.db.buckets[kv.BucketFor(k.Type)]
	ek := string(kv.EncodeKey(k))
	if _, ok := b[ek]; !ok {
		return false, nil
	}
	delete(b, ek)
	return true, nil
}

func (s *Store) Iter(types core.IterTypes) (core.Iterator, error) {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	it := &iterator{s: s}
	for _, b := range []struct {
		t core.IterTypes
		b kv.Bucket
	}{{core.IterEntries, kv.BucketEntries}, {core.IterSpamtraps, kv.BucketSpamtraps}, {core.IterDomains, kv.BucketDomains}} {
		if types&b.t == 0 {
			continue
		}
		keys := make([]string, 0, len(s.db.buckets[b.b]))
		for k := range s.db.buckets[b.b] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		it.keys = append(it.keys, keys...)
	}
	it.pos = -1
	return it, nil
}

func (s *Store) Scan(now, whiteExp int64) (core.ScanResult, error) {
	return kv.Scan(s, now, whiteExp)
}

type iterator struct {
	s    *Store
	keys []string
	pos  int
	curr core.Key
	has  bool
}

func (it *iterator) Next() (core.Key, core.Data, bool, error) {
	it.s.db.mu.Lock()
	defer it.s.db.mu.Unlock()
	for {
		it.pos++
		if it.pos >= len(it.keys) {
			it.has = false
			return core.Key{}, core.Data{}, false, nil
		}
		k, err := kv.DecodeKey([]byte(it.keys[it.pos]))
		if err != nil {
			return core.Key{}, core.Data{}, false, err
		}
		v, ok := it.s.db.buckets[kv.BucketFor(k.Type)][it.keys[it.pos]]
		if !ok {
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
		return core.ErrNotInTransaction
	}
	return it.s.Put(it.curr, d)
}

func (it *iterator) DeleteCurrent() error {
	if !it.has {
		return core.ErrNotInTransaction
	}
	_, err := it.s.Del(it.curr)
	return err
}

func (it *iterator) Close() error { return nil }
