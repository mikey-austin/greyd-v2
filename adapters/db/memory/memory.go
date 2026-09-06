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
	"context"
	"maps"
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

type buckets map[kv.Bucket]map[string][]byte

// database is the shared state behind stores of the same name. One
// transaction runs at a time.
type database struct {
	mu   sync.Mutex
	data buckets
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
	return &database{data: buckets{
		kv.BucketEntries:   {},
		kv.BucketSpamtraps: {},
		kv.BucketDomains:   {},
	}}
}

func (b buckets) clone() buckets {
	c := make(buckets, len(b))
	for k, m := range b {
		c[k] = maps.Clone(m)
	}
	return c
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
	readOnly bool
}

// Open returns a handle onto the named database.
func Open(name string) *Store { return &Store{db: lookupDB(name)} }

// New returns a handle onto a private, unnamed database.
func New() *Store { return &Store{db: newDatabase()} }

func (s *Store) Open(_ context.Context, mode core.OpenMode) error {
	s.readOnly = mode == core.OpenRO
	return nil
}

func (s *Store) Close() error { return nil }

// View runs fn against a consistent view of the data.
func (s *Store) View(ctx context.Context, fn func(core.ReadTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	return fn(&tx{data: s.db.data, readOnly: true})
}

// Update runs fn against the data and keeps the changes only when fn
// returns nil.
func (s *Store) Update(ctx context.Context, fn func(core.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.readOnly {
		return core.ErrReadOnly
	}
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	work := s.db.data.clone()
	if err := fn(&tx{data: work}); err != nil {
		return err
	}
	s.db.data = work
	return nil
}

// tx implements core.Tx over a bucket set.
type tx struct {
	data     buckets
	readOnly bool
}

func (t *tx) Put(k core.Key, d core.Data) error {
	if t.readOnly {
		return core.ErrReadOnly
	}
	t.data[kv.BucketFor(k.Type)][string(kv.EncodeKey(k))] = kv.EncodeData(d)
	return nil
}

func (t *tx) Get(k core.Key) (core.Data, bool, error) {
	if k.Type == core.KeyDomainPart {
		for raw := range t.data[kv.BucketDomains] {
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
	v, ok := t.data[kv.BucketFor(k.Type)][string(kv.EncodeKey(k))]
	if !ok {
		return core.Data{}, false, nil
	}
	d, err := kv.DecodeData(v)
	return d, err == nil, err
}

func (t *tx) Del(k core.Key) (bool, error) {
	if t.readOnly {
		return false, core.ErrReadOnly
	}
	b := t.data[kv.BucketFor(k.Type)]
	ek := string(kv.EncodeKey(k))
	if _, ok := b[ek]; !ok {
		return false, nil
	}
	delete(b, ek)
	return true, nil
}

func (t *tx) Iter(types core.IterTypes) (core.Iterator, error) {
	it := &iterator{t: t, pos: -1}
	for _, b := range []struct {
		t core.IterTypes
		b kv.Bucket
	}{{core.IterEntries, kv.BucketEntries}, {core.IterSpamtraps, kv.BucketSpamtraps}, {core.IterDomains, kv.BucketDomains}} {
		if types&b.t == 0 {
			continue
		}
		keys := make([]string, 0, len(t.data[b.b]))
		for k := range t.data[b.b] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		it.keys = append(it.keys, keys...)
	}
	return it, nil
}

func (t *tx) Scan(now, whiteExp int64) (core.ScanResult, error) {
	if t.readOnly {
		return core.ScanResult{}, core.ErrReadOnly
	}
	return kv.Scan(t, now, whiteExp)
}

type iterator struct {
	t    *tx
	keys []string
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
		k, err := kv.DecodeKey([]byte(it.keys[it.pos]))
		if err != nil {
			return core.Key{}, core.Data{}, false, err
		}
		v, ok := it.t.data[kv.BucketFor(k.Type)][it.keys[it.pos]]
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

func (it *iterator) Close() error { return nil }
