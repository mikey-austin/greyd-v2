# greyd Go port: design

Date: 2026-09-06
Status: approved by the session goal directive (autonomous run; decisions recorded here in place of interactive sign-off)

## 1. Goal

Port the C implementation of greyd (`/home/mikey/Workspace/greyd`, version 0.11.6) to Go, in
`/home/mikey/Workspace/greyd-v2`, preserving every user-visible behaviour: the four programs
(`greyd`, `greydb`, `greyd-setup`, `greylogd`), their command line switches, the `greyd.conf`
language, the SMTP tarpit dialogue, greylisting rules, greytrapping, SPF, blacklist configuration
connections, the spamd-compatible synchronisation protocol, pluggable firewalls and pluggable
databases. The existing documentation is reused with small edits.

Non-goals: new features, protocol changes, a different configuration syntax.

## 2. Constraints from the request

- Makefile build system.
- Decoupled, tested components with a solid core using the ports and adapters pattern.
- ANTLR4 for the configuration language.
- Security critical: privilege dropping, chroot, pidfile locking, privileged-port checks.
- Pluggable database implementations.

## 3. Architecture overview

```
cmd/greyd  cmd/greydb  cmd/greyd-setup  cmd/greylogd        (thin mains: flags -> app wiring)
        │
        ▼
internal/app/*            application services per program (greyd server, greylister, setup, logd)
        │
        ▼
internal/core             domain model + ports (interfaces). No I/O, no adapters imported.
        ▲
        │ implements
adapters/db/{sqlite,mysql,postgresql,bolt,memory}
adapters/fw/{netfilter,pf,dummy}
adapters/spf
```

Supporting libraries (pure, unit-tested, no adapter imports):

| package | responsibility | C origin |
|---|---|---|
| `internal/config` | Config model (sections, blacklists, whitelists, values), loader with include queue and glob, merge, typed getters | greyd_config, config_section, config_value |
| `internal/config/grammar` | ANTLR4 grammar `GreydConf.g4` and generated Go lexer/parser (committed) | config_lexer, config_parser |
| `internal/config/parse` | ANTLR listener that builds a `config.Config`; error listener with line/col | config_parser |
| `internal/ipc` | framing and encoding of the `%%`-terminated messages exchanged between processes and on the config socket | greyd.c Greyd_send_config / process_config, con.c, grey.c |
| `internal/ip` | CIDR/range math, address family checks | ip.c |
| `internal/blacklist` | Blacklist with radix-trie storage for lookups and range storage with collapse | blacklist.c, trie.c |
| `internal/spamdlist` | spamd-style address list scanner/parser (hand written, see 6.2) | spamd_lexer, spamd_parser |
| `internal/smtp` | per-connection SMTP tarpit state machine, stuttering, proxy protocol v1, reply expansion | con.c |
| `internal/grey` | greylisting engine: message processing, trap checks, permitted domains, SPF hook, scan/whitelist/traplist emission | grey.c |
| `internal/sync` | spamd-compatible UDP/multicast sync engine (HMAC-SHA1) | sync.c |
| `internal/setup` | list fetching, parsing, collapsing and shipping to greyd and the firewall | main_greyd_setup.c |
| `internal/logger` | syslog + optional file + stderr logging with debug gating | log.c, failures.c |
| `internal/privs` | drop privileges, chroot, pidfile lock, rlimit, daemonize by re-exec | utils.c |
| `internal/procs` | child process launcher: re-exec self with a role and inherited pipes | fork() sites in main_greyd.c, grey.c |

### 3.1 Ports (in `internal/core`)

```go
// Database
type KeyType int   // KeyIP, KeyMail, KeyTuple, KeyDomain, KeyDomainPart
type Key struct { Type KeyType; Str string; Tuple Tuple }
type Tuple struct { IP, Helo, From, To string }
type Data struct { First, Pass, Expire int64; BCount, PCount int }

type Store interface {
    Open(mode OpenMode) error          // OpenRO / OpenRW
    Close() error
    Begin() error; Commit() error; Rollback() error
    Put(Key, Data) error
    Get(Key) (Data, bool, error)       // found flag replaces GREYDB_FOUND/NOT_FOUND
    Del(Key) (bool, error)             // found flag
    Iter(types IterTypes) (Iterator, error)
    Scan(now int64, whiteExp int64) (ScanResult, error)
}
type Iterator interface { Next() (Key, Data, bool, error); ReplaceCurrent(Data) error; DeleteCurrent() error; Close() error }
type ScanResult struct { Whitelist, WhitelistV6, Traplist []string }
type StoreFactory func(cfg *config.Config, opts StoreOptions) (Store, error)
func RegisterStore(name string, f StoreFactory); func OpenStore(cfg, opts) (Store, error)

// Firewall
type Firewall interface {
    Open() error; Close() error
    Replace(set string, cidrs []string, af Family) (int, error)
    StartLogCapture() error; EndLogCapture() error
    CaptureLog(ctx context.Context) ([]string, error)   // blocks up to driver timeout
    LookupOrigDst(src, proxy netip.AddrPort) (netip.AddrPort, error)
}
type FirewallFactory func(cfg *config.Config) (Firewall, error)
func RegisterFirewall(name string, f FirewallFactory); func OpenFirewall(cfg) (Firewall, error)

// SPF
type SPFResult int // SPFPass, SPFNone, SPFFail, SPFError
type SPFChecker interface { Check(ip, helo, from string) (SPFResult, error) }
```

Driver selection: `section database { driver = "sqlite" }` and `section firewall { driver = "netfilter" }`.
For compatibility with existing configuration files, a driver value that looks like a path
(`/usr/lib/greyd/greyd_sqlite.so`, `greyd_netfilter.la`) is normalised by taking the basename,
stripping a `greyd_` prefix and a `.so`/`.la` suffix. `bdb` and `bdb_sql` map to `bolt` with a
one-time warning, because Berkeley DB is not available to pure Go.

Adapters register themselves in `init()`; each `cmd/*` main blank-imports the adapter set. The
`memory` store is used by unit tests and is also a legitimate driver for ephemeral deployments.

## 4. Process model and security

The C daemon relies on `fork()` to separate privileges. Go cannot fork safely, so `greyd` re-executes
its own binary with a role marker. Pipes are passed as inherited file descriptors (`ExtraFiles`);
the child learns fd numbers and its role from environment variables (`GREYD_ROLE`,
`GREYD_FD_*`) and receives the identical command line so configuration is parsed identically.

| process | role | user | chroot | holds |
|---|---|---|---|---|
| `greyd` main | accept SMTP + config connections, sync receive, trap pipe reader | `user` (default `greyd`) | yes (`chroot_dir`) after binding sockets | listening sockets, pipes only |
| `greyd` fw child | firewall handle; answers `nat` lookups and `replace` requests over pipes | `user` (default `greyd`) with CAP_NET_ADMIN retained on Linux | yes unless driver is `pf` | firewall handle |
| `greyd` grey child | greylister: reader goroutine (processes grey messages) + scanner goroutine (periodic DB scan, whitelist push, traplist push) | `grey.user` (default `greydb`) | no | database handle(s), sync sender |

The C code forks the grey process twice (reader and scanner). The Go grey child runs both as
goroutines with separate `Store` instances; both run as the same user in C, so no security boundary is
lost.

Pipes (all carry `%%`-framed messages, see 6.3):

- main -> grey: grey messages (`type = 1 ...`) and sync-received white/trap messages.
- grey -> main: traplist blacklist configuration (`name/message/ips`).
- grey -> fw: `replace` requests for the whitelist sets.
- main -> fw: `nat` lookup request; fw -> main: `dst` reply (1 s timeout on the main side).

Order of operations in main (as in C): parse config, compute limits, `setrlimit`, bind sockets
(privileged), daemonize (re-exec with `setsid`) unless `daemonize = 0` or `-F`, write and lock pidfile
(owned by the main user), start fw child, start grey child, delete `sync.hosts` from own config,
start sync receiver, install signal handlers, chroot, drop privileges, listen, serve.

`privs.Drop(user)` sets supplementary groups, gid, uid (`setgroups`, `setresgid`, `setresuid`) and
verifies that regaining root fails. Pidfile: `O_RDWR|O_CREAT` 0644, `fcntl(F_SETLK)` write lock,
truncate, write pid, `fchown` to the service user; the descriptor stays open; on exit unlink the
path with the chroot prefix removed. Config-socket connections must come from a source port below
1024 (as in C); `greyd-setup` binds a reserved source port before connecting.

Linux capability retention for the netfilter adapter uses `kernel.org/pub/linux/libs/security/libcap/cap`
(pure Go): `PR_SET_KEEPCAPS` before the uid change, then re-raise `CAP_NET_ADMIN` effective before
each netlink operation, and clear all capabilities on close.

## 5. Connection handling (`internal/smtp`)

Goroutine per connection instead of a poll loop, with identical externally observable behaviour:

- `Server` tracks `clients`, `blackClients`, `maxCons`, `maxBlack`, `slowUntil` under a mutex.
- Accept loop refuses beyond `maxCons` (close immediately), throttles for one second on
  `EMFILE`/`ENFILE`.
- `Conn` state machine is a pure function over an in-memory struct plus a `net.Conn`-like
  `io.ReadWriteCloser`, so it is unit tested with `net.Pipe`. States, transitions, replies, QUIT/RSET
  handling, NOOP, unknown command counting (max 20), 10-line body cutoff, verbose header/body logging
  match `con.c`.
- Stuttering: one byte per `stutter` seconds while `clients + 5 < maxCons`; a `\r` is inserted before
  a `\n` not preceded by `\r`; greylisted connections stop stuttering after `grey.stutter` seconds;
  stuttering is abandoned for blacklisted connections when `blackClients > maxBlack`.
- Read/write inactivity limit 400 s.
- Proxy protocol v1 (`PROXY TCP4|TCP6 src dst sport dport`) when `proxy_protocol_enable = 1`, only from
  `proxy_protocol_permitted_proxies` (a blacklist structure used as an allow list). `UNKNOWN` and
  malformed headers end the connection with the error reply.
- On a complete `RCPT` for a non-blacklisted connection with greylisting enabled: obtain original
  destination (proxy protocol value, or `nat` lookup through the fw pipe) and send the grey message.
- Reply construction: blacklisted connections get every matching list's message expanded with
  `%A` -> address, `\n` -> newline, `\\` -> `\`, `%%` -> `%`, each line prefixed by the error code with
  `-` continuation dashes; greylisted connections always get `451 Temporary failure, please try again later.`

## 6. Configuration language

### 6.1 ANTLR4 grammar (`GreydConf.g4`)

```
config      : EOL* (statement (EOL+ statement)*)? EOL* EOF ;
statement   : assignment | section | include ;
assignment  : NAME '=' value ;
value       : INT | STRING | list ;
list        : '[' EOL* (value (EOL* ',' EOL* value)* EOL* ','? EOL*)? ']' ;
section     : sectionType NAME EOL* '{' EOL* (assignment (separator assignment)* separator?)? EOL* '}' ;
separator   : (',' | EOL)+ ;
sectionType : SECTION | BLACKLIST | WHITELIST ;
include     : INCLUDE STRING ;

SECTION   : [Ss][Ee][Cc][Tt][Ii][Oo][Nn] ;      (keywords are case-insensitive, as C lowercases names)
INCLUDE, BLACKLIST, WHITELIST likewise
NAME      : [A-Za-z][A-Za-z0-9_]* ;              (lowercased by the listener)
INT       : [0-9]+ ;
STRING    : '"' ( '\\' . | ~["\\] )* '"' ;       (newlines allowed inside; escape = drop backslash, keep next char)
EOL       : '\n' | ';' ;
COMMENT   : '#' ~[\n]* -> skip ;
WS        : [ \t\r]+ -> skip ;
```

Differences from the C recursive-descent parser, all supersets: empty lists are accepted; assignments
inside a section may be separated by commas without a newline; an unknown character is a parse error
instead of silently ending the parse. Include files are queued and processed after the current file,
each path once, with glob and leading `~` expansion; later files override earlier sections and
variables.

Generated parser code is committed under `internal/config/grammar` so `go build` needs no Java. `make
generate` regenerates it with the pinned ANTLR tool jar (downloaded into `.tools/` on demand) and
the matching `github.com/antlr4-go/antlr/v4` runtime.

### 6.2 spamd list format

The list scanner splits digit runs greater than 255 into several tokens (`25566` -> `255`, `66`),
which a regular ANTLR lexer cannot express. The port keeps a small hand-written scanner and
recursive-descent parser in `internal/spamdlist` with the grammar from `spamd_parser.h` and tests
ported from `test_spamd_lexer.c` / `test_spamd_parser.c`. Input may be gzip-compressed or plain;
the reader sniffs the gzip magic.

### 6.3 IPC message framing (`internal/ipc`)

A message is a sequence of `greyd.conf` assignments terminated by a line containing exactly `%%`.
`ipc.Reader` yields one frame body at a time; the body is parsed with the ANTLR parser into a
`config.Config` and read from its default section. `ipc.Writer` helpers emit the same wire text as
the C code (`Greyd_send_config`, grey messages, `nat`, `replace`, `dst`), so a C `greyd-setup` can
still configure a Go `greyd` and vice versa. Parsing happens per frame, never on a partial stream,
which removes the reliance on `%` being an "unknown character".

## 7. Greylisting engine (`internal/grey`)

Ported one-to-one from `grey.c`:

- Configuration: `traplist_name`, `traplist_message`, `whitelist_name`, `whitelist_name_ipv6`,
  `grey_expiry`, `white_expiry`, `trap_expiry`, `pass_time`, `low_prio_mx`, `permitted_domains`,
  `db_permitted_domains`, `stutter`, `enable`, `user`.
- `trapCheck(to)`: file domains (suffix match, case-insensitive) then DB `KeyDomainPart`, then
  `KeyMail` spamtrap hit.
- `processGrey`: trap or tuple key; optional SPF (pass -> whitelist if `whitelist_on_pass`; fail or
  configured softfail -> trap); low priority MX trap when the tuple is new and the daemon has been up
  more than 60 s; new entry `pass = expire = now + expiry`, `bcount = 1`, `pcount = -1` for traps;
  existing entry `bcount++`, `pass = now` once `first + pass_time < now`; sync update/trapped
  messages sent when the message did not itself come from sync.
- `processNonGrey` (white/trap add, update, delete) with the expiry validation from C.
- Scanner: every 60 s run `Store.Scan` inside a transaction, send the traplist to main, send
  `replace` for IPv4 and (if `enable_ipv6`) IPv6 whitelists to the fw child.
- Shutdown on SIGTERM/SIGHUP/SIGINT; the scanner exit terminates the main process as in C.

Store scan semantics (identical across drivers, tested with a shared conformance suite):
delete entries with `expire <= now` and `pcount > -2`; collect trapped IPs (`pcount == -1`, IP key);
whitelist tuples whose `pass <= now` and `pcount >= 0` unless the IP already has a trapped entry,
re-keying them by IP with `expire = now + white_exp`; collect IP-keyed white entries by family.

SQL drivers keep the per-host scoping column `greyd_host` (set to the configured hostname) so several
greyd instances can share one MySQL/PostgreSQL database.

## 8. Synchronisation (`internal/sync`)

Byte-compatible with spamd and the C greyd (protocol version 2): header (version, af, length,
counter, 20-byte HMAC, 4 pad bytes), TLVs `GREY` (timestamp, ip, from/to/helo lengths, strings,
16-byte alignment padding), `WHITE`, `TRAPPED`, `DEL_WHITE`, `DEL_TRAPPED`, `END`. HMAC-SHA1 keyed with
a 41-byte buffer holding the lowercase hex SHA1 of the key file (or all zeros when no key), exactly as
C does. Unicast targets resolve to IPv4; multicast when a target or `bind_address` is an interface
name, with `iface[:ttl]` syntax, `mcast_address`, `ttl`, `port`. Received packets from our own
multicast address are ignored; grey/white/trapped entries are forwarded to the greylister as
`sync = 0` messages. Encoder and decoder are tested against fixed byte vectors and round trips.

## 9. Programs

- `greyd`: flags `-456bdvF -f -B -c -G -h -l -L -M -n -p -P -S -s -w -Y -y` merged over the config
  file exactly as `main_greyd.c` (units: `-G` minutes:hours:hours, `-S`/`-s` maxima 90 and 10).
- `greydb`: `-f -a -d -T -D -t -Y`; list output format identical; syslog disabled; privileges not
  dropped; sync of WHITE/TRAPPED add/delete.
- `greyd-setup`: `-f -b -D -d -n`; lists processed in order, whitelists subtracted from the preceding
  blacklist, `file`/`http`/`ftp` (via `curl_path` and `curl_proxy`)/`exec` methods, gzip or plain
  input, collapse to CIDRs, send each list over a config connection from a reserved port, and in
  `-b` mode replace the `greyd-blacklist` firewall set with all CIDRs.
- `greylogd`: `-d -I -f -p -P -W -Y`; capture firewall log, whitelist source (inbound) or destination
  (outbound) addresses, `pcount++`, `expire = now + white_expiry`, sync `WHITE`.

Version is injected with `-ldflags` and logged at start-up; no new flags are added.

## 10. Adapters

Database (`adapters/db/*`):

| name | library | notes |
|---|---|---|
| `sqlite` | `modernc.org/sqlite` (pure Go) | same schema and SQL as `sqlite.c`; busy retries (20 x 5 s) on `BEGIN IMMEDIATE`/`COMMIT` |
| `mysql` | `github.com/go-sql-driver/mysql` | schema from `mysql_schema.sql`; `greyd_host` scoping |
| `postgresql` | `github.com/jackc/pgx/v5/stdlib` | schema from `postgresql_schema.sql`; `greyd_host` scoping |
| `bolt` | `go.etcd.io/bbolt` | replaces Berkeley DB; key encoding `type|fields` with NUL separators; scan logic ported from `bdb.c` |
| `memory` | none | in-process map; scan logic shared with `bolt` through `adapters/db/kvscan` |

A conformance test suite in `adapters/db/dbtest` runs the same scenarios (ported from `test_db.c` and
`test_grey.c`) against every driver; MySQL and PostgreSQL run only when `GREYD_TEST_MYSQL_DSN` /
`GREYD_TEST_POSTGRESQL_DSN` are set. `make test-db-docker` starts containers and runs them.

Firewall (`adapters/fw/*`):

| name | mechanism | build |
|---|---|---|
| `dummy` | no-op; `Replace` returns the CIDR count; `LookupOrigDst` returns the proxy address | all |
| `netfilter` | ipset via netlink (`github.com/vishvananda/netlink`: create stage set `hash:net`, add, swap, destroy), conntrack original-destination lookup (`github.com/ti-mo/conntrack`), NFLOG capture (`github.com/florianl/go-nflog/v2`) with `inbound_group`/`outbound_group`/`track_outbound`/`max_elements`/`hash_size`; CAP_NET_ADMIN retention | linux |
| `pf` | table replace by executing `pfctl -p <pfdev> -q -t <table> -T replace -f -`; log capture by reading `/dev/bpf` bound to `pflog_if` (userland filter: pass, TCP, port 25, SYN only, optional `net_if`); NAT lookup by `DIOCNATLOOK` ioctl with per-OS struct layouts for OpenBSD and FreeBSD, falling back to the proxy address elsewhere | openbsd, freebsd, netbsd, dragonfly (unverified in this environment; documented) |

SPF (`adapters/spf`): `blitiri.com.ar/go/spf`, mail-from check with HELO fallback semantics of libspf2
mapped to pass/none/softfail/fail; softfail obeys `trap_on_softfail`.

## 11. Logging and errors

`internal/logger` writes to syslog (facility daemon, ident = program name, unless `syslog_enable = 0`),
to `log_to_file` when set, and always to stderr; debug lines only when `debug = 1`. Fatal conditions
log and exit(1) through a single `logger.Fatal` so children terminate like the C `i_critical`.
Library packages return errors; only `internal/app` and `cmd` decide to exit.

## 12. Build, layout, documentation

```
Makefile            all, build, generate, test, test-race, test-db-docker, lint, fmt, man, install, uninstall, dist, docker, clean
go.mod              module github.com/mikey-austin/greyd-v2
cmd/                greyd greydb greyd-setup greylogd
internal/ adapters/ as above
doc/                greyd.8.md greyd.conf.5.md greydb.8.md greyd-setup.8.md greylogd.8.md (+ generated .8/.5/.html)
etc/                greyd.conf.in greyd.docker.conf.in init scripts
packages/           docker (multi-stage Go build), rpm, debian, signing key
utils/              spf_whitelist.pl
website/            unchanged copy
README.md INSTALL COPYING AUTHORS ChangeLog NEWS
```

`make install` honours `DESTDIR`, `prefix`, `sbindir`, `sysconfdir`, `localstatedir`, `mandir`, and
substitutes `@PACKAGE@`, `@GREYD_PIDFILE@`, `@GREYLOGD_PIDFILE@`, `@DEFAULT_CONFIG@`, `@CURL@`,
`@sbindir@`, `@localstatedir@`, `@sysconfdir@` in `etc/*.in` like the automake rules. Default paths
are compiled in through `-ldflags -X` (`DEFAULT_CONFIG=/etc/greyd/greyd.conf`,
`GREYD_PIDFILE=/var/empty/greyd/greyd.pid`, `GREYLOGD_PIDFILE=/var/empty/greylogd/greylogd.pid`).

Documentation edits: driver configuration (names instead of shared objects, Berkeley DB -> bolt,
PostgreSQL section added), SPF and all drivers built in (no `--with-*` flags), build instructions in
INSTALL and README rewritten for Go, ChangeLog/NEWS entry for the port. Everything else is kept.

## 13. Testing

- Unit tests per package, porting every assertion group from `check/*.c` that still applies
  (config lexer/parser, config model and merge, ip, blacklist and collapse, trie, spamd list, smtp
  state machine and stuttering, reply expansion, grey engine, sync codec, setup collapse, privs
  helpers where testable without root).
- Driver conformance suite shared by all stores.
- Integration test (`internal/app/greyd`, no privilege changes): start the server in-process with
  the memory store and dummy firewall, drive a full SMTP dialogue over TCP, assert the grey message,
  then the trap pipe configuration flow through the config socket path.
- `go vet` and `-race` in `make test`.
- CI workflow (`.github/workflows/go.yml`): build, vet, test.

## 14. Risks and open items

- pf and Linux netfilter adapters cannot be exercised as root in this environment. Their logic is
  ported carefully, compiled for their targets, unit tested where mocking is possible, and flagged in
  the README as needing verification on real hosts.
- Berkeley DB is replaced, not ported; existing BDB databases must be re-created (they are caches
  with short expiries, so operational impact is small). Documented in NEWS.
- The npf (NetBSD) driver is out of scope for this pass; it is listed in the README as not yet ported.
