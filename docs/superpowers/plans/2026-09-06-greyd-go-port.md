# greyd Go Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port greyd 0.11.6 (C) to Go with identical behaviour, a Makefile build, ports-and-adapters core, ANTLR4 configuration parser, privilege separation, and pluggable database/firewall adapters.

**Architecture:** `internal/core` defines domain types and the `Store`/`Firewall`/`SPFChecker` ports with registries; pure library packages (config, ipc, ip, blacklist, spamdlist, smtp, grey, sync, setup, privs, procs, logger) depend only on core; `adapters/*` implement the ports; `internal/app/*` wire everything for the four programs; `cmd/*` are thin mains. Privilege separation is achieved by re-executing the binary with a role marker and inherited pipes.

**Tech Stack:** Go 1.25, `github.com/antlr4-go/antlr/v4` v4.13.1 (+ tool jar 4.13.1), `modernc.org/sqlite`, `github.com/go-sql-driver/mysql`, `github.com/jackc/pgx/v5`, `go.etcd.io/bbolt`, `golang.org/x/sys`, `golang.org/x/net`, `github.com/vishvananda/netlink`, `github.com/ti-mo/conntrack`, `github.com/florianl/go-nflog/v2`, `kernel.org/pub/linux/libs/security/libcap/cap`, `blitiri.com.ar/go/spf`.

**Spec:** `docs/superpowers/specs/2026-09-06-greyd-go-port-design.md`

## Global Constraints

- Module path `github.com/mikey-austin/greyd-golang`; Go 1.25; no cgo anywhere (`CGO_ENABLED=0` must build all four binaries on linux).
- C reference tree: `/home/mikey/Workspace/greyd` (read-only). When behaviour is unclear, the C source wins.
- Every package has `_test.go` files; `make test` runs `go vet ./... && go test -race ./...` and must pass.
- Library packages return errors; only `internal/app` and `cmd` may call `logger.Fatal`/`os.Exit`.
- Config variable names, section names, defaults and units are exactly those in `src/constants.h`, `src/*.c`, and `doc/greyd.conf.5.md`.
- Wire formats (IPC frames, config socket, sync UDP) stay byte-compatible with the C implementation.
- Commit after every task with a message in imperative mood, ending with the session trailer.
- Licence headers: OpenBSD ISC licence text from `COPYING` at the top of every Go file, copyright `2014-2026 Mikey Austin`; the netfilter adapter carries the GPLv2 header as in `drivers/netfilter.c`.

---

## File map

```
Makefile
go.mod go.sum
.gitignore .github/workflows/go.yml
cmd/greyd/main.go cmd/greydb/main.go cmd/greyd-setup/main.go cmd/greylogd/main.go
internal/version/version.go                       Version, DefaultConfig, GreydPidfile, GreylogdPidfile (ldflags -X)
internal/logger/logger.go logger_test.go          Setup, Reinit, Debug/Info/Warning/Error/Fatal
internal/config/config.go section.go value.go     model + getters + merge + include queue
internal/config/loader.go                         LoadFile (uses parse), glob/tilde include expansion
internal/config/grammar/GreydConf.g4              ANTLR grammar
internal/config/grammar/*.go                      generated (committed)
internal/config/parse/parse.go listener.go        ParseString/ParseReader -> *config.Config, ParseError{Line,Col}
internal/ipc/frame.go writer.go                   Reader (frames), Message helpers, encoders
internal/ip/ip.go                                 CIDR/range math
internal/blacklist/blacklist.go trie.go ranges.go
internal/spamdlist/scanner.go parser.go
internal/core/store.go firewall.go spf.go registry.go tuple.go
adapters/db/kvscan/kvscan.go                      shared bdb-style scan over a KV iterator
adapters/db/memory/memory.go
adapters/db/bolt/bolt.go
adapters/db/sqlite/sqlite.go
adapters/db/sqlcommon/sqlcommon.go                shared SQL text builder + row mapping for the three SQL drivers
adapters/db/mysql/mysql.go
adapters/db/postgresql/postgresql.go
adapters/db/dbtest/conformance.go                 shared conformance suite (imported by each driver test)
adapters/db/all/all.go                            blank imports of every store adapter
adapters/fw/dummy/dummy.go
adapters/fw/netfilter/netfilter_linux.go caps_linux.go netfilter_other.go
adapters/fw/pf/pf_bsd.go natlook_openbsd.go natlook_freebsd.go natlook_other.go bpf_bsd.go pf_other.go
adapters/fw/all/all.go
adapters/spf/spf.go
internal/privs/privs.go pidfile.go daemon.go rlimit.go
internal/procs/procs.go                           Spawn(role, extraFiles) / Role() / InheritedFile(name)
internal/smtp/conn.go state.go reply.go proxy.go server.go
internal/sync/wire.go engine.go
internal/grey/greylister.go reader.go scanner.go domains.go
internal/setup/setup.go fetch.go
internal/app/greyd/{options.go,main_process.go,fw_child.go,grey_child.go,integration_test.go}
internal/app/greydb/greydb.go
internal/app/greylogd/greylogd.go
internal/app/setup/setup.go
doc/ etc/ packages/ utils/ website/ README.md INSTALL COPYING AUTHORS ChangeLog NEWS
```

---

### Task 1: Scaffold, Makefile, logger, version

**Files:**
- Create: `go.mod`, `.gitignore`, `Makefile`, `.github/workflows/go.yml`, `COPYING`, `AUTHORS`,
  `internal/version/version.go`, `internal/logger/logger.go`, `internal/logger/logger_test.go`,
  `cmd/greyd/main.go`, `cmd/greydb/main.go`, `cmd/greyd-setup/main.go`, `cmd/greylogd/main.go` (stubs printing usage)

**Interfaces:**
- Produces:
  ```go
  package version
  var ( Version = "dev"; DefaultConfig = "/etc/greyd/greyd.conf"
        GreydPidfile = "/var/empty/greyd/greyd.pid"; GreylogdPidfile = "/var/empty/greylogd/greylogd.pid" )

  package logger
  type Options struct { Ident string; Debug bool; Syslog bool; File string; Stderr io.Writer }
  func Setup(o Options) error      // opens syslog (facility daemon, LOG_PID) when Syslog, opens File in append mode
  func Reinit(file string) error   // re-open log file (children after re-exec)
  func Debug(format string, a ...any); func Info(...); func Warning(...); func Error(...)
  func Fatal(format string, a ...any)          // logs at LOG_CRIT then os.Exit(1)
  func SetExit(f func(int))                    // test hook
  ```
- Steps:
- [x] `go mod init github.com/mikey-austin/greyd-golang`; `.gitignore` with `bin/ .tools/ *.test coverage.out dist/ etc/greyd.conf etc/greyd.docker.conf etc/*-init`.
- [x] Makefile targets: `all build generate test test-race lint fmt man install uninstall dist docker clean`. Variables: `VERSION=1.0.0`, `prefix=/usr/local`, `sbindir=$(prefix)/sbin`, `sysconfdir=$(prefix)/etc`, `localstatedir=$(prefix)/var`, `mandir=$(prefix)/share/man`, `DEFAULT_CONFIG=$(sysconfdir)/greyd/greyd.conf`, `GREYD_PIDFILE=$(localstatedir)/empty/greyd/greyd.pid`, `GREYLOGD_PIDFILE=$(localstatedir)/empty/greylogd/greylogd.pid`, `CURL=/usr/bin/curl`, `ANTLR_VERSION=4.13.1`, `ANTLR_JAR=.tools/antlr-$(ANTLR_VERSION)-complete.jar`. `LDFLAGS=-X ...version.Version=$(VERSION) -X ...DefaultConfig=$(DEFAULT_CONFIG) ...`. `build` compiles the four programs into `bin/` with `CGO_ENABLED=0`. `generate` downloads the jar with curl if missing and runs `java -jar $(ANTLR_JAR) -Dlanguage=Go -package grammar -o internal/config/grammar -Xexact-output-dir internal/config/grammar/GreydConf.g4`. `install` uses `install -m 0750` for binaries, substitutes `etc/*.in` with sed exactly like `etc/Makefile.am`, installs man pages from `doc/*.8` and `doc/*.5`.
- [x] Logger test: with `Stderr` set to a `bytes.Buffer`, `Syslog:false`, `Debug:false`: `Debug("x")` writes nothing, `Info("hi %d", 1)` writes `ident[<pid>]: hi 1\n`; with `Debug:true` debug lines appear; `Fatal` calls the exit hook with 1. File output uses an exclusive `flock` per write like `log.c`.
- [x] Run `make build test`, commit `Scaffold Go module, Makefile, logger and version package`.

---

### Task 2: Configuration model

**Files:** `internal/config/value.go`, `section.go`, `config.go`, `config_test.go`

**Interfaces (produces):**
```go
type ValueType int; const ( TypeInt ValueType = 1; TypeStr = 2; TypeList = 3 )
type Value struct { Type ValueType; Int int; Str string; List []*Value }
func IntValue(int) *Value; func StrValue(string) *Value; func ListValue(...*Value) *Value
func (v *Value) Clone() *Value

type Section struct { Name string; vars map[string]*Value; order []string }
func NewSection(name string) *Section
func (s *Section) Get(name string) *Value; Set(name string, v *Value); Delete(name string)
func (s *Section) SetInt(name string, i int); SetStr(name, val string)
func (s *Section) Int(name string, def int) int; Str(name string, def string) string  // wrong type -> def
func (s *Section) List(name string) []*Value                                            // nil when absent or not list
func (s *Section) Keys() []string                                                       // insertion order

const DefaultSection = "default"
type Config struct { sections, blacklists, whitelists map[string]*Section; processed map[string]bool; includes []string }
func New() *Config
func (c *Config) AddSection(*Section); AddBlacklist(*Section); AddWhitelist(*Section)
func (c *Config) Section(name string) *Section; Blacklist(name) *Section; Whitelist(name) *Section
func (c *Config) SectionNames() []string
func (c *Config) Int(name, section string, def int) int   // section "" == default
func (c *Config) Str(name, section string, def string) string
func (c *Config) List(name, section string) []*Value
func (c *Config) StrList(name, section string) []string   // strings only
func (c *Config) SetInt(name, section string, v int); SetStr(name, section, v string)
func (c *Config) Delete(name, section string)
func (c *Config) AppendListStr(name, section, s string)
func (c *Config) Merge(from *Config)                       // sections only, clones values, creates sections
func (c *Config) AddInclude(pattern string)                // glob + "~" expansion, queue unprocessed matches
func (c *Config) MarkProcessed(path string); PendingIncludes() []string; popInclude() (string, bool)
```
- [x] Tests port `check/test_config.c`, `test_config_section.c`, `test_config_value.c`: getters with defaults, wrong-type returns default, list append creates the list, merge overrides and creates sections, `Str` returns "" default, `Delete` removes, `AddInclude` with a temp dir containing `a.conf b.conf c.txt` and pattern `<dir>/*.conf` queues two paths in sorted order and skips already processed ones; `~/x` expands `$HOME`.
- [x] Implement, run, commit `Add configuration model`.

---

### Task 3: ANTLR grammar, parser listener and loader

**Files:** `internal/config/grammar/GreydConf.g4`, generated `greydconf_lexer.go greydconf_parser.go greydconf_listener.go greydconf_base_listener.go`, `internal/config/parse/parse.go`, `listener.go`, `parse_test.go`, `internal/config/loader.go`, `loader_test.go`, `internal/config/testdata/{config_test1.conf,config_test2.conf,config_test3.conf,config_lexer_test1.conf}` (copied from `check/data/*.in` with `include "data/..."` paths rewritten to `include "testdata/config_test*.conf"`).

**Grammar (verbatim):**
```antlr
grammar GreydConf;

config      : EOL* (statement (EOL+ statement)*)? EOL* EOF ;
statement   : assignment | section | include ;
assignment  : NAME EQ value ;
value       : INT # intValue | STRING # strValue | list # listValue ;
list        : LSQ EOL* (value (EOL* COMMA EOL* value)* EOL* COMMA? EOL*)? RSQ ;
section     : sectionType NAME EOL* LBR EOL* (assignment (separator assignment)* separator?)? EOL* RBR ;
separator   : (COMMA | EOL)+ ;
sectionType : SECTION | BLACKLIST | WHITELIST ;
include     : INCLUDE STRING ;

SECTION   : S E C T I O N ;
INCLUDE   : I N C L U D E ;
BLACKLIST : B L A C K L I S T ;
WHITELIST : W H I T E L I S T ;
NAME      : [A-Za-z][A-Za-z0-9_]* ;
INT       : [0-9]+ ;
STRING    : '"' ( '\\' . | ~["\\] )* '"' ;
EQ : '=' ; COMMA : ',' ; LBR : '{' ; RBR : '}' ; LSQ : '[' ; RSQ : ']' ;
EOL       : '\n' | ';' ;
COMMENT   : '#' ~[\n]* -> skip ;
WS        : [ \t\r]+ -> skip ;
fragment A:[aA]; fragment B:[bB]; fragment C:[cC]; fragment D:[dD]; fragment E:[eE]; fragment H:[hH];
fragment I:[iI]; fragment K:[kK]; fragment L:[lL]; fragment N:[nN]; fragment O:[oO]; fragment S:[sS];
fragment T:[tT]; fragment U:[uU]; fragment W:[wW];
```
Note: `INT` is a keyword-free rule and `NAME` starts with a letter, so `12` and `test_var` never collide; keywords are listed before `NAME` so they win ties.

**Interfaces (produces):**
```go
package parse
type Error struct { Line, Col int; Msg string }  // Error() = "parse error at line L col C: msg"
func Into(cfg *config.Config, src string) error  // parses src, applies to cfg; keyword-lowercased names; strings unescaped (drop backslash, keep next char); INT overflow -> Error
func String(src string) (*config.Config, error)
func Reader(r io.Reader) (*config.Config, error)
package config
func (c *Config) LoadFile(path string) error     // parse file, mark processed, then loop PendingIncludes: LoadFile each unprocessed one
```
Listener semantics: assignments outside sections go to `DefaultSection` (created if missing on `Into`); a `section`/`blacklist`/`whitelist` creates a fresh `Section` replacing any existing one of the same name (as the C parser does); `include` calls `cfg.AddInclude(unescaped)`. Use a custom `antlr.ErrorListener` that records the first error and stop.

- [x] Tests (port `test_config_lexer.c`, `test_config_parser.c`, `test_config.c` include section): the string from `test_config_parser.c` parses; `test_var_1 == 12345`; section value `long "string"`; list sizes 2/2/3; blacklist/whitelist sections are retrievable through `Blacklist()`/`Whitelist()`; one pending include `testdata/config_test1.conf`; `LoadFile("testdata/config_test1.conf")` yields `limit == 25`, `another_global == "this is overwritten"`, `storage.storage_driver == "MySQL"`, `cache.port == 11211`, and each file processed exactly once (cycle `config_test3.conf -> config_test1.conf`). Error case: `foo = @` returns `*Error` with Line 1. Multi-line string with embedded newline parses. `Section GREY { a = 1 }` -> section name `grey`. Empty list `x = []` -> empty list. Trailing comma `x = [1, 2,]` -> 2 items. `a = 1; b = 2` -> both set.
- [x] Commit `Add ANTLR grammar, parser and config loader`.

---

### Task 4: IPC framing

**Files:** `internal/ipc/frame.go`, `writer.go`, `ipc_test.go`

**Interfaces:**
```go
const Terminator = "%%"
type Reader struct{ br *bufio.Reader }
func NewReader(r io.Reader) *Reader
func (r *Reader) Next() (*config.Config, error)         // reads lines until a line == "%%"; parses body; io.EOF at end; a frame that fails to parse returns *parse.Error (caller decides)
func (r *Reader) NextRaw() (string, error)              // body text without terminator

type Message struct{ b strings.Builder }
func (m *Message) Int(name string, v int) *Message; Str(name string, v string) *Message
func (m *Message) StrList(name string, vals []string) *Message     // name=["a","b"]
func (m *Message) Bytes() []byte                                   // appends "%%\n"
func WriteBlacklist(w io.Writer, name, message string, ips []string) error  // Greyd_send_config: skips when len(ips)==0; bare IPs get /32 or /128
func WriteGrey(w io.Writer, dstIP, ip, helo, from, to string) error         // type = 1 ... exactly as con.c (no sync field)
func WriteGreyFromSync(w, ip, helo, from, to string) error                  // type = 1, sync = 0
func WriteAddr(w io.Writer, msgType int, ip, source string, expires uint32, del bool) error // type 2/3 sync messages
func WriteReplace(w io.Writer, set string, af int, ips []string) error      // type="replace" name= af= ips=[...]
func WriteNAT(w io.Writer, src string, srcPort uint16, proxy string, proxyPort uint16) error
func WriteDst(w io.Writer, dst string) error                                // dst="..."
const ( MsgGrey = 1; MsgTrap = 2; MsgWhite = 3 )
```
Strings are written with `"` and `\` escaped by a preceding backslash (the C code writes raw; escaping is a strict improvement for addresses containing quotes and never changes output for normal values).
- [x] Tests: encode `WriteBlacklist("greyd-blacklist","Your IP %A", ["1.2.3.4","10.0.0.0/8","2001::1"])` equals `name="greyd-blacklist"\nmessage="Your IP %A"\nips=["1.2.3.4/32","10.0.0.0/8","2001::1/128"]\n%%\n`; reader round-trips two consecutive frames and then `io.EOF`; a frame containing `==` yields a parse error and the reader can continue to the next frame; a stream ending without terminator yields the final partial frame then EOF (matches the C behaviour where EOF completes the parse).
- [x] Commit `Add IPC frame reader and message encoders`.

---

### Task 5: IP math and blacklists

**Files:** `internal/ip/ip.go`, `ip_test.go`, `internal/blacklist/trie.go`, `ranges.go`, `blacklist.go`, `blacklist_test.go`

**Interfaces:**
```go
package ip
type CIDR struct { Addr uint32; Bits uint8 }
func CIDRToRange(c CIDR) (start, end uint32)
func RangeToCIDRs(start, end uint32) []string          // "a.b.c.d/n" strings, algorithm from ip.c (max_block/max_diff)
func (c CIDR) String() string
func CheckAddr(s string) int                            // 4, 6, or -1 (uses netip.ParseAddr; "1.2.3.4" ->4)
func ParsePrefix(s string) (netip.Prefix, error)       // accepts "a.b.c.d/n", "a.b.c.d" (=/32), "::1" (=/128); rejects /0 like C
func FamilyOf(a netip.Addr) int                         // 4 or 6

package blacklist
type Storage int; const ( StorageList Storage = 0; StorageTrie Storage = 1 )
type Type int;    const ( TypeWhite Type = 0; TypeBlack Type = 1 )
type Blacklist struct { Name, Message string; Count int; /* unexported */ }
func New(name, message string, s Storage) *Blacklist
func (b *Blacklist) Add(cidr string) error               // trie storage: insert prefix; list storage: append (addr,mask) for Match
func (b *Blacklist) Match(a netip.Addr) bool
func (b *Blacklist) AddRange(start, end uint32, t Type) // start>end ignored; appends two entries (start:+1, end:-1) like C
func (b *Blacklist) Collapse() []string                  // sort, sweep, RangeToCIDRs(bstart, addr-1) on 1->0 transitions; nil when empty
```
Trie: binary trie over prefix bits per family (`map[int]*node`); `Match` walks the address bits and returns true when any node on the path is terminal.
- [x] Tests port `test_ip.c` (CIDR string, range, `192.168.0.1-192.168.0.25` -> the six CIDRs, matching, `CheckAddr`) and `test_blacklist.c` (`AddRange` entries, three overlapping regions collapse to `10.0.0.0/27`, `10.0.0.32/29`; trie matches for `192.168.12.1/24`, `10.20.1.3/16`, `fe80::0202:b3ff:fe1e:2201/120`, `2010:2acd::beef:a322/64`) and `test_trie.c` semantics (duplicates do not increase matches; longer and shorter prefixes coexist).
- [x] Commit `Add IP math and blacklist storage`.

---

### Task 6: spamd list parser

**Files:** `internal/spamdlist/scanner.go`, `parser.go`, `spamdlist_test.go`

**Interfaces:**
```go
type TokenKind int // EOF, EOL, Int6 (<=63), Int8 (<=255), Dot, Dash, Slash
type Token struct { Kind TokenKind; Val int }
type Scanner struct{...}; func NewScanner(r io.Reader) *Scanner; func (s *Scanner) Next() Token; func (s *Scanner) Pos() (line, col int)
func Parse(r io.Reader, bl *blacklist.Blacklist, t blacklist.Type) error   // grammar from spamd_parser.h; returns *Error{Line,Col}
func OpenMaybeGzip(r io.Reader) (io.Reader, error)                           // sniff 0x1f 0x8b
```
Semantics from `spamd_lexer.c`: digit runs accumulate while `<= 255`, otherwise split; whitespace skipped; `#` to end of line skipped; unknown char -> EOF. Entry forms: `a.b.c.d`, `a.b.c.d/n` (n must be Int6), `a.b.c.d - e.f.g.h`; `AddRange(start, end+1, t)`.
- [x] Tests port `test_spamd_lexer.c` token sequence (including `123455` -> 123, 45, 5) and `test_spamd_parser.c`; gzip round trip via `compress/gzip`.
- [x] Commit `Add spamd list scanner and parser`.

---

### Task 7: Core ports, registry, memory store, conformance suite

**Files:** `internal/core/tuple.go`, `store.go`, `firewall.go`, `spf.go`, `registry.go`, `registry_test.go`, `adapters/db/kvscan/kvscan.go`, `adapters/db/memory/memory.go`, `adapters/db/dbtest/conformance.go`, `adapters/db/memory/memory_test.go`

**Interfaces:** as in spec §3.1 plus:
```go
package core
type Family int; const ( IPv4 Family = 4; IPv6 Family = 6 )
type OpenMode int; const ( OpenRW OpenMode = 0; OpenRO OpenMode = 1 )
type IterTypes int; const ( IterEntries IterTypes = 1; IterSpamtraps = 2; IterDomains = 4 )
type StoreOptions struct { User *user.User /* nil when not dropping privs */ ; Hostname string }
func NormalizeDriver(v string) string   // basename, strip greyd_ / .so / .la, bdb|bdb_sql -> bolt
func OpenStore(cfg *config.Config, o StoreOptions) (Store, error)  // reads section "database" driver, errors "no database configuration"/"unknown database driver X"
func OpenFirewall(cfg *config.Config) (Firewall, error)             // section "firewall"
func AddrState(s Store, ip string) (int, error) // 0 not found, 1 trapped (pcount==-1), 2 white

package kvscan
type KV interface { Iter(core.IterTypes) (core.Iterator, error); Put(core.Key, core.Data) error; Get(core.Key) (core.Data,bool,error) }
func Scan(kv KV, now, whiteExp int64) (core.ScanResult, error)   // exact port of bdb.c Mod_scan_db

package dbtest
func RunConformance(t *testing.T, open func(t *testing.T) core.Store)
```
Conformance scenarios (from `test_db.c` and the tally logic of `test_grey.c`): put/get/del of IP, MAIL, DOM, TUPLE keys; `Get` of missing -> found=false; `Del` missing -> found=false; iterate all types and count by key type; `DomainPart` lookup `x@sub.domain1.com` matches stored `domain1.com` and `greyd@domain3.com` matches exactly; `Scan` deletes expired white/trap/grey but not spamtraps or domains (expire 0, pcount -2/-3), whitelists a passed tuple (re-keyed by IP, `expire == now+whiteExp`), skips whitelisting when the IP is trapped, returns v4/v6 lists split by `:`; transaction rollback discards a put; `ReplaceCurrent`/`DeleteCurrent` on an iterator.
- [x] Commit `Add core ports, registry, memory store and conformance suite`.

---

### Task 8: bolt store

**Files:** `adapters/db/bolt/bolt.go`, `bolt_test.go`

Config: `path` (dir, default `/var/db/greyd`, created 0700 and chowned to `StoreOptions.User` when created), `db_name` (default `greyd.db`). Buckets `entries` (IP and TUPLE keys), `spamtraps`, `domains`. Key encoding: `byte(type) + fields joined by 0x00`. Value: 5 x int64 big-endian. Transactions: `Begin` opens a `bbolt` writable tx (RO mode opens read tx); operations without an explicit `Begin` run in an auto tx. `Scan` = `kvscan.Scan`. `DomainPart` lookup iterates domains bucket with `strings.HasSuffix(strings.ToLower(key), domain)`.
- [x] Test: `dbtest.RunConformance` with a temp dir; register name `bolt`.
- [x] Commit `Add bolt store adapter`.

---

### Task 9: sqlite store and shared SQL helpers

**Files:** `adapters/db/sqlcommon/sqlcommon.go`, `adapters/db/sqlite/sqlite.go`, `sqlite_test.go`

`sqlcommon` holds the row mapping (`populate_key`/`populate_val` logic: empty helo/from/to => IP key unless pcount -2 (MAIL) or -3 (DOM)), the iterator over `*sql.Rows`, and the three scan statements parameterised by dialect (placeholder style, identifier quoting, `UNIX_TIMESTAMP()`/`EXTRACT(EPOCH FROM now())`/bound `now`, optional `greyd_host` predicate). SQLite specifics from `sqlite.c`: schema creation on open, `BEGIN IMMEDIATE`/`COMMIT` with up to 20 retries of 5 s on busy (retry sleep injectable for tests), `INSERT OR REPLACE`, `INSERT OR IGNORE`, `? LIKE '%' || domain`, the `UPDATE OR REPLACE ... NOT IN (...)` whitelisting statement and the three-way `UNION` select. `Del` returns `RowsAffected() > 0`. Driver import `modernc.org/sqlite` (`sql.Open("sqlite", path)`).
- [x] Test: conformance with temp file; `Open` twice is a no-op; missing dir created 0700.
- [x] Commit `Add sqlite store adapter`.

---

### Task 10: mysql and postgresql stores

**Files:** `adapters/db/mysql/mysql.go`, `mysql_test.go`, `adapters/db/postgresql/postgresql.go`, `postgresql_test.go`, `adapters/db/all/all.go`, Makefile target `test-db-docker`, `packages/docker/docker-compose.test.yml`

Config keys (both): `host` (localhost), `port` (3306 / 5432), `name` (greyd), `user`, `pass`, `socket`. Schemas from `drivers/*_schema.sql` created with `CREATE TABLE IF NOT EXISTS` on open (the C drivers require pre-creation; auto-create is additive). `greyd_host` = `StoreOptions.Hostname` on every entries insert; scan delete/update restricted to own host (`mysql.c`/`postgresql.c` statements verbatim, with parameters instead of string formatting). MySQL upsert: `INSERT ... ON DUPLICATE KEY UPDATE`; PostgreSQL: `INSERT ... ON CONFLICT (...) DO UPDATE`. Tests skip unless `GREYD_TEST_MYSQL_DSN` / `GREYD_TEST_POSTGRESQL_DSN` set. `make test-db-docker` runs `docker compose -f packages/docker/docker-compose.test.yml up -d`, waits for readiness, exports the DSNs, runs the two test packages, then `down -v`.
- [x] Commit `Add mysql and postgresql store adapters`.

---

### Task 11: privileges, pidfile, daemonize, process spawning

**Files:** `internal/privs/privs.go`, `pidfile.go`, `rlimit.go`, `daemon.go`, `privs_test.go`, `internal/procs/procs.go`, `procs_test.go`

**Interfaces:**
```go
package privs
func LookupUser(name string) (*user.User, error)
func Drop(u *user.User) error                 // setgroups([gid]); setresgid; setresuid; then verify Setuid(0) fails when geteuid was 0
func Chroot(dir string) error                 // loads time zone data first (time.LoadLocation("Local") + os.Setenv TZ), then unix.Chroot + Chdir("/")
func SetMaxFiles(n uint64) error              // RLIMIT_NOFILE cur=max=n
func MaxFiles() (int, error)                  // hard limit - 200; error when < 10 ("max files is only %d, refusing to continue")
type Pidfile struct{ path string; f *os.File }
func WritePidfile(path string, owner *user.User) (*Pidfile, error) // ErrAlreadyRunning when F_SETLK fails with EAGAIN/EACCES
var ErrAlreadyRunning = errors.New("already running")
func (p *Pidfile) Close(chrootDir string)     // close, unlink path with chrootDir prefix stripped
func Daemonize() error                        // if env GREYD_DAEMONIZED != "1": re-exec self with Setsid, stdio -> /dev/null, cwd "/", env marker; parent os.Exit(0). Child returns nil.

package procs
const EnvRole = "GREYD_ROLE"
func Role() string                                        // "" in the parent
type Spawn struct { Role string; Files map[string]*os.File; Env []string }
func (s Spawn) Start() (*exec.Cmd, error)                 // exec.Command(os.Executable(), os.Args[1:]...) with ExtraFiles in sorted name order and env GREYD_FD_<NAME>=<index+3>
func InheritedFile(name string) (*os.File, error)         // os.NewFile from GREYD_FD_<NAME>
```
- [x] Tests: pidfile lock detects a second writer in the same process via a helper subprocess (`go test` re-exec pattern with `GO_TEST_HELPER=1`); `Close` strips chroot prefix; `procs.Spawn` with a pipe and role `echo` round-trips data through the test binary helper; `Drop` on non-root returns nil when target is current user.
- [x] Commit `Add privilege, pidfile and process spawning helpers`.

---

### Task 12: SMTP connection state machine and server

**Files:** `internal/smtp/reply.go`, `proxy.go`, `conn.go`, `state.go`, `server.go`, `smtp_test.go`

**Interfaces:**
```go
type Config struct {  // snapshot of config values used by con.c
    Hostname, Banner, ErrorCode string; Greylist bool; GreyStutter, Stutter int
    Verbose bool; Window int; ProxyProtocol bool; PermittedProxies *blacklist.Blacklist
}
type Deps struct {
    Blacklists func() []*blacklist.Blacklist      // current blacklist set (main process map snapshot)
    GreyOut io.Writer                             // grey pipe (nil when greylisting disabled)
    OrigDst func(src, local netip.AddrPort) (string, error)  // fw nat lookup; "" on failure
    Now func() time.Time; Sleep func(time.Duration)
}
type Counters struct { mu sync.Mutex; Clients, BlackClients, MaxCons, MaxBlack int; SlowUntil time.Time }

type Conn struct { /* exported for tests: */ State, LastState int; SrcAddr, DstAddr, Helo, Mail, Rcpt string; Lists []*blacklist.Blacklist; Stutter int; Out []byte; ... }
func NewConn(rw io.ReadWriter, src netip.AddrPort, local netip.AddrPort, cfg Config, deps Deps, c *Counters) *Conn   // Con_init: blacklist matching, counters++, initial state
func (c *Conn) Serve()                       // runs until close; goroutine per connection
func (c *Conn) NextState()                   // exported for tests (Con_next_state)
func (c *Conn) HandleRead() error; HandleWrite() error
func (c *Conn) BuildReply(code string)      // fills c.Out
func (c *Conn) SummarizeLists() string       // 80-char summary with " ..."
func ExpandMessage(dst []byte, format, code, srcAddr string) []byte  // Con_append_error_string semantics
func ParseProxyHeader(line string) (src, dst string, err error)     // PROXY TCP4|TCP6 src dst ...; ErrProxyUnknown for UNKNOWN

type Server struct{...}
func NewServer(cfg Config, deps Deps, counters *Counters) *Server
func (s *Server) ServeListener(ctx context.Context, l net.Listener)  // accept loop with EMFILE throttle, max cons check, logs "connected (x/y)"
```
State constants and transitions copied from `con.h`/`con.c` (ProxyIn -3 ... Close 99). Stuttering in `HandleWrite`: if `Stutter>0 && within_max` write one byte then `Sleep(Stutter seconds)`, else write all remaining; insert `\r` before `\n` when the previous byte written was not `\r`. Grey stutter cutoff and abandon rule as in spec §5. Read: up to 8191 bytes until a byte in `"\n"` appears or buffer full; trailing `\r`/`\n` trimmed; 400 s deadline via `SetReadDeadline` when rw is a `net.Conn`.
- [x] Tests port `test_con.c`: init state/last state, two matching lists, summary `blacklist_1 blacklist_2`, banner length 75 for hostname `greyd.org` at a fixed time, close resets counters, summary truncation `blacklist_2 ...` for the long name, `BuildReply("451")` for two lists equals the C expected text, write without stutter and with stutter (adds `\r`), greylisted reply is always `451 Temporary failure, please try again later.\r\n`, full dialogue over `net.Pipe`: `EHLO greyd.org` -> helo `greyd.org`; `MAIL FROM: <Mikey@greyd.ORG>` -> `mikey@greyd.org`; `RCPT TO: info@greyd.org` -> grey message written to `GreyOut` with `dst_ip` from `OrigDst`; `DATA` -> `354`, then for greylisted `451`; `QUIT` -> `221 greyd.org`; 21 unknown commands -> reply and close; proxy header parse table (`PROXY TCP4 1.2.3.4 5.6.7.8 1 2` ok, `PROXY UNKNOWN` unknown, `PROXY TCP4 x y 1 2` error) and rejection from a non-permitted proxy.
- [x] Commit `Add SMTP tarpit connection state machine`.

---

### Task 13: Sync engine

**Files:** `internal/sync/wire.go`, `engine.go`, `sync_test.go`

**Wire (verbatim layout):**
```go
const ( Version = 2; MaxSize = 1408; HMACLen = 20; MulticastAddr = "224.0.1.241"; DefaultTTL = 1; DefaultKey = "/etc/greyd/greyd.key"; DefaultPort = 8025 )
const ( TypeEnd = 0; TypeGrey = 1; TypeWhite = 2; TypeTrapped = 3; TypeDelWhite = 4; TypeDelTrapped = 5 )
// header 32 bytes: version u8, af u8 (=2 AF_INET), length u16be, counter u32be, hmac [20], pad [4]
// tlv grey: type u16, length u16, timestamp u32, ip [4] (network order), fromlen u16, tolen u16, helolen u16, then from\0 to\0 helo\0, padded to 16-byte multiple of (20+strings)
// tlv addr: type u16, length u16 (=16), timestamp u32, expire u32, ip [4]
// end: type u16 (0), length u16 (4)
type Key [41]byte   // hex sha1 of key file + NUL, or zeros
func LoadKey(path string) (Key, bool, error)   // ok=false when file missing (ENOENT)
func EncodeGrey(k *Key, counter uint32, ip netip.Addr, helo, from, to string, now uint32) []byte
func EncodeAddr(k *Key, counter uint32, typ uint16, ip netip.Addr, now, expire uint32) []byte
type Entry struct { Type uint16; IP netip.Addr; Helo, From, To string; Expire uint32; Delete bool }
func Decode(k *Key, pkt []byte) ([]Entry, error)   // verifies version, af, length, HMAC (hmac field zeroed), TLV bounds
```
Engine:
```go
type Engine struct{...}
func New(cfg *config.Config) (*Engine, error)   // nil,nil when sync.enable == 0; hosts from sync.hosts (interface names become the mcast iface); key per verify/key
func (e *Engine) Start() error                   // socket, bind (port 0 when neither bind_address nor iface), multicast join with iface addr, TTL from "iface:ttl" or sync.ttl
func (e *Engine) Stop()
func (e *Engine) Conn() net.PacketConn
func (e *Engine) Recv(greyOut io.Writer, greylistEnabled bool) // one packet -> ipc.WriteGreyFromSync / ipc.WriteAddr("sync=0")
func (e *Engine) Update(t core.Tuple, now time.Time); White(ip string, now, expire time.Time, del bool); Trapped(...)
```
- [x] Tests: encode a grey entry with zero key and assert the exact byte length (`32 + align16(20+len) + 4`) and that `Decode` round-trips; addr TLV is 16 bytes; HMAC mismatch -> error; truncated -> error; a fixed golden packet captured from the C code layout (construct by hand in the test from the struct definition) decodes to expected fields; two engines on loopback unicast exchange a white entry and the receiver writes `type = 3\nsync = 0\nip = "1.2.3.4"\nsource = "127.0.0.1"\nexpires = "N"\ndelete = 0\n%%\n`.
- [x] Commit `Add spamd-compatible sync engine`.

---

### Task 14: SPF adapter and dummy firewall

**Files:** `adapters/spf/spf.go`, `spf_test.go`, `adapters/fw/dummy/dummy.go`, `dummy_test.go`, `adapters/fw/all/all.go`

`spf.New()` returns a `core.SPFChecker` using `blitiri.com.ar/go/spf` `CheckHostWithSender(ip, helo, from)`: `spf.Pass`->SPFPass, `Fail`->SPFFail, `SoftFail`->SPFSoftFail, `Neutral|None`->SPFNone, others -> SPFError with the library error. Add `SPFSoftFail` to core. Dummy firewall: `Replace` returns `len(cidrs)`, `CaptureLog` blocks on ctx then returns nil, `LookupOrigDst` returns proxy.
- [x] Tests: spf mapping through an injected resolver (`spf.DefaultResolver` replaced by a `net.Resolver` pointing at a stub DNS? too heavy) -> test only the result mapping function with a table; dummy firewall trivial tests; registry finds `dummy`.
- [x] Commit `Add SPF checker and dummy firewall adapters`.

---

### Task 15: Greylisting engine

**Files:** `internal/grey/domains.go`, `greylister.go`, `reader.go`, `scanner.go`, `grey_test.go`, `internal/grey/testdata/permitted_domains.txt` (copy of `check/data/permitted_domains.txt.in`)

**Interfaces:**
```go
type Options struct { Config *config.Config; Store core.Store; Syncer Syncer /* nil ok */; SPF core.SPFChecker /* nil ok */
                      TrapOut io.Writer; FwOut io.Writer; Startup time.Time; Now func() time.Time }
type Syncer interface { Update(core.Tuple, time.Time); Trapped(ip string, now, expire time.Time, del bool); White(...) }
type Greylister struct { TraplistName, TraplistMsg, WhitelistName, WhitelistNameV6, LowPrioMX string
                         GreyExp, WhiteExp, TrapExp, PassTime int64; Domains []string; ... }
func New(o Options) (*Greylister, error)                 // reads grey section defaults: GREY_TRAP_NAME "greyd-greytrap", msg "Your address %A has mailed to spamtraps here", ...
func LoadDomains(path string) ([]string, error)          // Grey_load_domains rules (skip blank/comment/overlong lines >1023)
func (g *Greylister) ProcessMessage(m *config.Config) error   // process_message; ErrUnknownType for bad type
func (g *Greylister) RunReader(ctx context.Context, in io.Reader) error   // ipc.NewReader loop; stops on parse error/EOF
func (g *Greylister) ScanOnce() error                     // Grey_scan_db: txn, Store.Scan, ipc.WriteBlacklist(trap), ipc.WriteReplace v4 (+v6 when enable_ipv6)
func (g *Greylister) RunScanner(ctx context.Context, interval time.Duration) error
```
- [x] Tests port `test_grey.c` with the memory store: after the 20 messages the tallies are `entries 17, white 5, grey 3, trapped 6, spamtrap 1, white passed 3, white blocked 0, grey passed 0, grey blocked 6`; after adjusting one tuple's expire and another's pass and running `ScanOnce` the fw pipe contains a `replace` frame with `name="greyd-whitelist"`, `af=4` and the trap pipe contains `name="test traplist"` with 5 ips; tallies `14/5/1/5/1/3/2/0/2`; low priority MX trap when startup is 120 s ago; `LoadDomains` returns `[domain4.com domain2.com]`; parse error stops the reader.
- [x] Commit `Add greylisting engine`.

---

### Task 16: greyd application and integration test

**Files:** `internal/app/greyd/options.go`, `main_process.go`, `fw_child.go`, `grey_child.go`, `greyd.go`, `options_test.go`, `integration_test.go`, `cmd/greyd/main.go`

`options.go`: `ParseFlags(args []string) (configPath string, opts *config.Config, syncSend, syncRecv int, err error)` implementing every switch of `main_greyd.c` including validation (`-s` 0..10, `-S` 0..90, `-G` parsing, `-w > 0`, `-B/-c <= maxFiles`) and the usage text verbatim. `greyd.go`: `Run(args []string) int` dispatching on `procs.Role()`: `""` -> `runMain`, `"fw"` -> `runFwChild`, `"grey"` -> `runGreyChild`.

`runMain` order (spec §4): load config, merge opts, hostname default, limits (`max_cons`, `max_cons_black`, cap to max files, `max_black = max_cons` when greylisting disabled, error when `max_black > max_cons`), `setrlimit` when `setrlimit=1`, logger setup, proxy protocol setup, bind IPv4/config sockets (and IPv6 when enabled) with `SO_REUSEADDR`, daemonize, lookup main user, pidfile, when greylisting enabled: create pipes `fw` (main->fw), `nat` (fw->main), `greyfw` (grey->fw), `grey` (main->grey), `trap` (grey->main) and spawn `fw` role with files `fwin=fw[r] natout=nat[w] greyfwin=greyfw[r]`, spawn `grey` role with `greyin=grey[r] trapout=trap[w] fwout=greyfw[w]`; then `max_black` adjustment (`>= max_cons -> max_cons - 100`, floor 0); delete `sync.hosts`; sync engine; signal handling (SIGTERM/HUP/INT -> cancel ctx; SIGPIPE ignored); chroot; drop privs; listen; start goroutines: SMTP accept loops, config-socket loop (one connection at a time, reject source port >= 1024, `ipc.NewReader(conn).Next()` -> add blacklist to the shared map), trap pipe loop (same handler), sync recv loop; wait for ctx; on exit: close conns, stop sync, `SIGTERM` children, close pidfile.

`runFwChild`: open firewall, lookup main user, chroot unless driver is `pf`, drop privs, then two goroutines reading `greyfwin` and `fwin` frames and calling `processFwMessage(msg, fw, natout)` (port of `Greyd_process_fw_message`: `nat` -> `LookupOrigDst` -> `ipc.WriteDst`; `replace` -> filter valid addresses -> `Replace`).

`runGreyChild`: `grey.New` with a store for the scanner and a second store for the reader, lookup `grey.user`, delete `sync.bind_address`, start sync sender if hosts configured, drop privs, optional SPF, run reader and scanner goroutines; exit when either ends; SIGTERM the parent as C does when the scanner stops.

- [x] `options_test.go`: table of flag sets -> expected config values (`-G 25:4:864` -> 1500/14400/3110400; `-b` -> grey.enable 0; `-5` -> error_code 550; `-Y a -Y b` -> two hosts; invalid `-s 11` -> error).
- [x] `integration_test.go`: build a `*config.Config` in code (`drop_privs = 0`, `chroot = 0`, `daemonize = 0`, `setrlimit = 0`, `port = 0` semantics: use `bind_address = 127.0.0.1` and an OS-assigned port through an exported `runMainWithListeners` hook), memory store, dummy firewall, in-process children (`startChildrenInProcess` variant used only by tests that runs the fw and grey roles as goroutines over `os.Pipe`s), then: connect with `net.Dial`, read `220`, send `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, expect `451`; assert the memory store holds the grey tuple; open a second connection from a reserved port is not possible unprivileged, so test the config path by calling the shared `addBlacklistFromFrame` directly and then asserting a new connection from `10.0.0.1` (via proxy protocol with permitted proxies `127.0.0.0/8`) receives the blacklist message.
- [x] `cmd/greyd/main.go`: `os.Exit(greyd.Run(os.Args[1:]))` with blank imports of `adapters/db/all`, `adapters/fw/all`.
- [x] Commit `Add greyd daemon application`.

---

### Task 17: greydb

**Files:** `internal/app/greydb/greydb.go`, `greydb_test.go`, `cmd/greydb/main.go`

Port `main_greydb.c`: flags `a d t T D f: Y:`; list mode prints `GREY|...`, `WHITE|ip|||first|pass|expire|bcount|pcount`, `TRAPPED|ip|expire`, `SPAMTRAP|addr`, `DOMAIN|addr`; add/update/delete rules including `pcount` values (-1 trap, -2 spamtrap, -3 domain), email normalisation (`NormalizeEmail`: strip `<>`, drop `\\` and `"`, lowercase — put in `internal/core/tuple.go`), `IP.CheckAddr` validation, sync of WHITE/TRAPPED, `syslog_enable = 0`, `drop_privs = 0`, RO open for listing. `Run(args []string, stdout, stderr io.Writer) int`.
- [x] Tests with a temp bolt store config file: add white -> listing line format; add spamtrap `<Trap@Example.ORG>` -> `SPAMTRAP|trap@example.org`; delete missing -> exit 1 and `No entry for`; `-T` without `-a/-d` -> usage.
- [x] Commit `Add greydb tool`.

---

### Task 18: greyd-setup

**Files:** `internal/setup/setup.go`, `fetch.go`, `setup_test.go`, `internal/app/setup/setup.go`, `cmd/greyd-setup/main.go`

`fetch.go`: `Open(section *config.Section, cfg *config.Config) (io.ReadCloser, error)` for methods `file`, `http`/`ftp` (exec `curl -s [--proxy P] URL`, `curl_path` default `/bin/curl`), `exec` (split on space/tab, `exec.Command`), then `spamdlist.OpenMaybeGzip`. `setup.go`: `Run(cfg, opts Options{Dryrun, Debug, GreyOnly bool}, fw core.Firewall, dial func() (net.Conn, error)) error` implementing the list loop from `main_greyd_setup.c` (new blacklist flushes the previous; whitelist merges into the current blacklist; per-list debug line `blacklist name N entries`; collapse; `ipc.WriteBlacklist` over a fresh config connection per list; in `-b` mode accumulate all CIDRs and `fw.Replace("greyd-blacklist", all, IPv4)` after the final list). `DialReserved(port int) (net.Conn, error)`: try local ports 1023 down to 512 with `net.Dialer{LocalAddr}` until one binds (error `could not bind privileged source port`). App: flags `f: b d D n`, usage `usage: greyd-setup [-bDdn] [-f config]`, `-D` daemonizes via `privs.Daemonize`, `drop_privs = 0`, error `no lists configured in <file>` when `setup.lists` empty.
- [x] Tests: run against a fake greyd (`net.Listen` on loopback, collect frames) with two file-method lists (one gz, one plain) plus a whitelist: assert two frames with the collapsed CIDRs and the message; dryrun sends nothing; `-b` with dummy fw returns count.
- [x] Commit `Add greyd-setup`.

---

### Task 19: greylogd

**Files:** `internal/app/greylogd/greylogd.go`, `greylogd_test.go`, `cmd/greylogd/main.go`

Port `main_greylogd.c`: flags `d I W: Y: f: P: p:` (note the C getopt string omits `d`/`p` by mistake; the man page documents them, implement them), usage text, sync setup, user lookup, daemonize, pidfile (owned by grey user), `FW.StartLogCapture`, drop privs, loop: `CaptureLog` -> for each address `Begin; Get; new: first=pass=now; pcount++; expire=now+white_expiry; Put; Commit; Info("whitelisting %s"); Sync.White`. Shutdown on signals; `Info("exiting")`; `EndLogCapture`, close pidfile. Core loop factored as `processAddresses(store, addrs, now, whiteExp, syncer)` for tests.
- [x] Tests: `processAddresses` with the memory store creates and increments entries; a fake firewall returning two addresses then ctx cancel ends the loop.
- [x] Commit `Add greylogd`.

---

### Task 20: netfilter firewall adapter

**Files:** `adapters/fw/netfilter/netfilter_linux.go`, `caps_linux.go`, `nflog_linux.go`, `conntrack_linux.go`, `netfilter_other.go`, `netfilter_test.go`, GPL header

Config: `max_elements` (200000), `hash_size` (1048576), `track_outbound` (1), `inbound_group` (155), `outbound_group` (255). `Open`: `netlink` ipset handle; when `drop_privs` keep caps (`cap.GetProc`, set CAP_NET_ADMIN permitted, `unix.Prctl(PR_SET_KEEPCAPS,1)`). `Replace`: raise effective CAP_NET_ADMIN; `IpsetCreate(stage, "hash:net", Options{Family, HashSize, MaxElements, Replace:true})`, add each CIDR (`IpsetAdd` with `netlink.IPSetEntry{IP, CIDR}`), create real set if missing, `IpsetSwap(set, stage)`, `IpsetDestroy(stage)`; return count. `StartLogCapture`: `nflog.Open(&nflog.Config{Group: in, Copymode: NfUlnlCopyPacket, Bufsize: 1024, Timeout: 1500})` and a second for out when tracking outbound; callback extracts source (in) or destination (out) IP from the IPv4/IPv6 header into a channel. `CaptureLog(ctx)`: drain channel with 10 s timeout. `LookupOrigDst`: `conntrack.Dial`, `Get` with a filter flow built from reply tuple (`src`↔`proxy`) and return original destination; default proxy on miss. `Close`: clear caps. Non-linux file registers nothing.
- [x] Tests: pure functions only (packet header parsing for v4/v6 payloads, CIDR entry conversion, config defaults), plus a root-gated test (`GREYD_TEST_ROOT=1`) that creates/replaces/destroys a set named `greyd-test`.
- [x] Commit `Add netfilter firewall adapter`.

---

### Task 21: pf firewall adapter

**Files:** `adapters/fw/pf/pf_bsd.go` (`//go:build openbsd || freebsd || netbsd || dragonfly`), `bpf_bsd.go`, `natlook_openbsd.go`, `natlook_freebsd.go`, `natlook_other_bsd.go` (netbsd, dragonfly -> proxy fallback), `pf_other.go`, `pf_test.go`, `pflog.go` (portable pflog header parser, tested everywhere)

Config: `pfdev_path` (/dev/pf), `pfctl_path` (/sbin/pfctl), `pflog_if` (pflog0), `net_if`. `Replace`: `exec.Command(pfctl, "-p", pfdev, "-q", "-t", table, "-T", "replace", "-f", "-")` with CIDRs on stdin; 0 when list empty; error on non-zero exit. Log capture: open `/dev/bpf` (or `/dev/bpf0..9`), `unix.SetBpfInterface(fd, pflog_if)`, `SetBpfImmediate(fd, 1)`, read buffer, iterate `bpf_hdr` records, parse `pfloghdr` (length, af, action, dir, ifname) with `pflog.Parse`, accept `action == PF_PASS`, TCP, dst port 25, SYN without ACK, optional `net_if` match; collect src (in) or dst (out when `track_outbound`). NAT lookup: `DIOCNATLOOK` with the OpenBSD `pfioc_natlook` layout (saddr,daddr,rsaddr,rdaddr 16 bytes each; sport,dport,rsport,rdport u16; af,proto,proto_variant,direction u8) and the FreeBSD layout (same fields, no proto_variant); `unix.IoctlSetPointerInt` replaced by `unix.Syscall(SYS_IOCTL, fd, DIOCNATLOOK, ptr)`.
- [x] Tests: `pflog.Parse` on a hand-built header and IPv4 SYN packet returns the source address for `dir == PF_IN`, nothing for `action != PASS`, nothing for non-SYN; `GOOS=openbsd GOARCH=amd64 go vet ./adapters/fw/pf/` and `GOOS=freebsd ... go build ./...` succeed.
- [x] Commit `Add pf firewall adapter`.

---

### Task 22: Documentation, configuration samples, packaging

**Files:** `README.md` (edited copy of `README`), `INSTALL` (new, Go instructions), `ChangeLog`, `NEWS`, `AUTHORS`, `doc/*.md` (edited), `doc/*.8 doc/*.5 doc/*.html` (regenerated when `ronn` exists, else copied and edited with the same text changes), `etc/greyd.conf.in`, `etc/greyd.docker.conf.in`, `etc/*-init.in` (copied), `packages/docker/Dockerfile` (multi-stage: `golang:1.25-alpine` build, `alpine` runtime, users greyd/greydb, `ENTRYPOINT ["/usr/local/sbin/greyd","-F"]`), `packages/rpm/greyd.spec.in` and `packages/debian/*` (Go build steps, no shared objects), `packages/greyd_pkg_sign_pub.asc`, `utils/spf_whitelist.pl`, `website/` (copied), Makefile `man`, `dist`, `docker` targets.

Edits: driver documentation in `greyd.conf.5.md` (`driver = "netfilter"` / `"pf"` / `"dummy"`, `"sqlite"` / `"mysql"` / `"postgresql"` / `"bolt"` / `"memory"`; PostgreSQL section added with `host port name user pass socket`; note on legacy `.so` paths; bolt replaces Berkeley DB); `greyd.8.md` SPF section (built in, no configure flag); README development status, drivers list, docker, licensing (netfilter adapter GPL as before); sample config `driver` lines. `INSTALL`: requirements (Go 1.25, make, optional Java for `make generate`), `make`, `make test`, `make install`, users/dirs to create, chroot dir. `NEWS` entry dated 2026-09-06 describing the Go port and BDB replacement.
- [x] Verify with `make install DESTDIR=$(mktemp -d)` that files land where the C layout put them (`sbin/greyd`, `etc/greyd/greyd.conf`, `share/man/man8/greyd.8`).
- [x] Commit `Port documentation, sample configuration and packaging`.

---

### Task 23: Final verification

- [x] `make fmt lint test` clean; `make test-race`; `CGO_ENABLED=0 GOOS=linux go build ./...`; `GOOS=openbsd go vet ./...` and `GOOS=freebsd go vet ./...`; `docker build -f packages/docker/Dockerfile .` when docker is available; `make test-db-docker` when docker is available.
- [x] Smoke run as an unprivileged user: `bin/greyd -F -f etc/greyd.test.conf` with `drop_privs = 0`, `chroot = 0`, `setrlimit = 0`, memory store, dummy firewall, `bind_address = 127.0.0.1`, `port = 18025`, `config_port = 18026`; `nc` an SMTP dialogue and check `bin/greydb -f etc/greyd.test.conf` output shows the GREY entry (use sqlite for this run so greydb sees the data).
- [x] Update `README.md` status section with anything left unverified (pf, netfilter on real hosts). Commit `Finalize greyd Go port`.

## Follow-up: clean-up and hardening pass (2026-09-07)

Implemented after the port, in three commits on top of `Share one getopt implementation`:

- [x] Typed settings schema (`internal/settings`), shared getopt (`internal/cli`), injected slog
      logger, transactional `core.Store` and context-aware `core.Firewall`, typed IPC codec
      without ANTLR, lifecycle split of the greyd main process.
- [x] Security: unix configuration socket with peer credentials (`config_socket`), sync replay
      window and zero-key warning, per-source connection cap, SMTP line length cap, configuration
      frame / permitted domains / list entry caps, bounded PROXY header, per-process sandbox
      (Landlock + seccomp + no_new_privs on Linux, pledge on OpenBSD), hardened systemd units,
      patched toolchain pin.
- [x] Quality: `greyd -t`, `--drivers`, `--version`; generic driver registry with descriptions;
      fuzz targets (`make fuzz`), property tests (kv codec, Collapse, RangeToCIDRs, proxy header,
      sync wire) and benchmarks; golangci-lint + govulncheck in `make lint` and CI, tree clean.
- [x] Documentation: greyd.conf(5) and greyd(8) new options and switches, sample configuration,
      README, NEWS, INSTALL (systemd, toolchain).
