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

package core

import (
	"errors"
	"os/user"

	"github.com/mikey-austin/greyd-golang/internal/config"
)

// KeyType identifies the kind of database key (greydb.h DB_KEY_*).
type KeyType int

const (
	// KeyIP keys a whitelisted or greytrapped address.
	KeyIP KeyType = 1
	// KeyMail keys a spamtrap email address.
	KeyMail KeyType = 2
	// KeyTuple keys a greylist tuple.
	KeyTuple KeyType = 3
	// KeyDomain keys a permitted domain.
	KeyDomain KeyType = 4
	// KeyDomainPart is a lookup-only key: does any permitted domain match
	// the suffix of this address.
	KeyDomainPart KeyType = 5
)

// Key is a database key.
type Key struct {
	Type KeyType
	// Str holds the IP, mail address or domain for the non-tuple types.
	Str string
	// Tuple holds the greylist tuple for KeyTuple.
	Tuple Tuple
}

// IPKey creates an address key.
func IPKey(ip string) Key { return Key{Type: KeyIP, Str: ip} }

// MailKey creates a spamtrap key.
func MailKey(addr string) Key { return Key{Type: KeyMail, Str: addr} }

// DomainKey creates a permitted domain key.
func DomainKey(d string) Key { return Key{Type: KeyDomain, Str: d} }

// DomainPartKey creates a permitted domain suffix lookup key.
func DomainPartKey(addr string) Key { return Key{Type: KeyDomainPart, Str: addr} }

// TupleKey creates a greylist tuple key.
func TupleKey(t Tuple) Key { return Key{Type: KeyTuple, Tuple: t} }

// Data holds the greylisting counters of an entry (struct Grey_data).
type Data struct {
	// First is when the entry was first seen.
	First int64
	// Pass is when the entry was (or may be) whitelisted.
	Pass int64
	// Expire is when the entry is removed.
	Expire int64
	// BCount is how many times the entry was blocked.
	BCount int
	// PCount is how many times the entry passed, or one of the sentinel
	// values below.
	PCount int
}

// Sentinel PCount values.
const (
	// PCountTrapped marks a greytrapped address.
	PCountTrapped = -1
	// PCountSpamtrap marks a spamtrap address (SQL drivers).
	PCountSpamtrap = -2
	// PCountDomain marks a permitted domain (SQL drivers).
	PCountDomain = -3
)

// OpenMode selects read-only or read-write access.
type OpenMode int

const (
	OpenRW OpenMode = 0
	OpenRO OpenMode = 1
)

// IterTypes selects which entry kinds an iterator returns.
type IterTypes int

const (
	IterEntries   IterTypes = 1
	IterSpamtraps IterTypes = 2
	IterDomains   IterTypes = 4
	IterAll                 = IterEntries | IterSpamtraps | IterDomains
)

// ScanResult is produced by Store.Scan.
type ScanResult struct {
	Whitelist   []string
	WhitelistV6 []string
	Traplist    []string
}

// ErrNotInTransaction is returned by Commit/Rollback without Begin.
var ErrNotInTransaction = errors.New("not in a transaction")

// ErrInTransaction is returned by Begin while a transaction is open.
var ErrInTransaction = errors.New("already in a transaction")

// Store is the database port. Implementations are not required to be safe
// for concurrent use; each process/goroutine opens its own Store.
type Store interface {
	// Open connects to the database. Calling it on an open store is a no-op.
	Open(mode OpenMode) error
	Close() error

	Begin() error
	Commit() error
	Rollback() error

	Put(k Key, d Data) error
	// Get returns the entry and whether it was found. For KeyDomainPart the
	// data is meaningless and only the found flag matters.
	Get(k Key) (Data, bool, error)
	// Del removes an entry and reports whether it existed.
	Del(k Key) (bool, error)

	Iter(types IterTypes) (Iterator, error)

	// Scan expires entries, whitelists grey tuples whose pass time has come
	// and returns the current whitelist (split by family) and traplist.
	Scan(now int64, whiteExp int64) (ScanResult, error)
}

// Iterator walks database entries.
type Iterator interface {
	// Next returns the next entry, or ok=false at the end.
	Next() (k Key, d Data, ok bool, err error)
	// ReplaceCurrent overwrites the data of the entry last returned.
	ReplaceCurrent(d Data) error
	// DeleteCurrent removes the entry last returned.
	DeleteCurrent() error
	Close() error
}

// StoreOptions carries process level information to store factories.
type StoreOptions struct {
	// User is the unprivileged database user (nil when privileges are not
	// dropped); file based stores chown newly created paths to it.
	User *user.User
	// Hostname identifies this greyd instance for shared SQL databases.
	Hostname string
}

// StoreFactory constructs a store from the "database" configuration
// section.
type StoreFactory func(cfg *config.Config, opts StoreOptions) (Store, error)

// Getter is the read side of a Store.
type Getter interface {
	Get(k Key) (Data, bool, error)
}

// AddrState reports the state of an address: 0 not found, 1 greytrapped,
// 2 whitelisted (DB_addr_state).
func AddrState(s Getter, ip string) (int, error) {
	d, found, err := s.Get(IPKey(ip))
	if err != nil {
		return -1, err
	}
	if !found {
		return 0, nil
	}
	if d.PCount == PCountTrapped {
		return 1, nil
	}
	return 2, nil
}
