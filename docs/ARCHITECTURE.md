# greyd architecture

This document describes how the Go port of greyd is put together: the
processes that make up a running `greyd`, the pipes and sockets between
them, the wire formats, and the layout of the code. It is written for
people changing the code; the user-facing behaviour is documented in
`doc/greyd.8.md`, `doc/greyd.conf.5.md` and the other manual pages.

The port keeps the process model, configuration language, IPC formats and
sync protocol of the C implementation, so a `greyd` built from this tree
interoperates with existing `greyd` and OpenBSD `spamd` installations.

## Programs

| Program       | Entry point                          | Purpose                                                        |
|---------------|--------------------------------------|----------------------------------------------------------------|
| `greyd`       | `cmd/greyd`, `internal/app/greyd`    | the SMTP-speaking daemon: tarpits blacklisted hosts, greylists the rest |
| `greydb`      | `cmd/greydb`, `internal/app/greydb`  | lists, adds and deletes database entries; can announce changes over sync |
| `greyd-setup` | `cmd/greyd-setup`, `internal/app/setup`, `internal/setup` | fetches blacklists and whitelists and loads them into `greyd` and the firewall |
| `greylogd`    | `cmd/greylogd`, `internal/app/greylogd` | watches the firewall's connection log and refreshes whitelist entries |

Each `cmd/<name>/main.go` only blank-imports the driver bundles
(`adapters/db/all`, `adapters/fw/all`) and the configuration parser
(`internal/config/parse`), then calls the `Run` function of the matching
`internal/app` package. Everything below `cmd/` is testable without
executing a binary. The fifth program, `greyd-monitor`
(`internal/app/monitor`), is a Prometheus exporter built on
`internal/stats`; see "Statistics" below.

All five programs read the same `greyd.conf` (`internal/config`,
`internal/settings`) and accept the `spamd` command line switches
(`internal/cli` is a getopt(3) clone).

## The greyd processes

`greyd` runs as three processes when greylisting is enabled (`grey.enable`,
the default). The C daemon forks; Go cannot fork a multi-threaded runtime,
so the parent re-executes its own binary (`internal/procs`) with the same
command line, a role marker `GREYD_ROLE=fw|grey` in the environment, and
the pipe ends passed as inherited descriptors, announced as
`GREYD_FD_<NAME>=<fd>` (descriptors are numbered from 3 in sorted name
order, `procs.Spawn.Start`). Because the child gets the same arguments it
parses the configuration identically, then `greyd.Run`
(`internal/app/greyd/greyd.go`) dispatches on `procs.Role()`.

```
                        SMTP clients            greyd-setup / greydb / sync peers
                             |                             |
                    :8025 (tcp4, tcp6)      config socket (127.0.0.1:8026 or unix)
                             |                     sync UDP :8025 (receive)
                             v                             v
   +---------------------------------------------------------------------+
   | main process   (user greyd, chroot /var/empty/greyd, sandbox main)  |
   | internal/app/greyd: daemon.go serve.go listen.go config_socket.go   |
   | internal/smtp: the SMTP state machine, stutter, proxy protocol      |
   +-----+--------------------^--------------+-------------------^-------+
         | greyout            | trapin       | fwout             | natin
         | tuples, sync       | traplists    | NAT lookups       | answers
         | relays             |              |                   |
         v                    |              v                   |
   +-------------------------------+   +-------------------------------+
   | greylister  (user greydb,     |   | firewall child (user greyd,   |
   |  sandbox grey)                |   |  chroot unless pf, sandbox fw)|
   | grey_child.go, internal/grey  |   | fw_child.go                   |
   | two Store handles, SPF,       |   | one core.Firewall handle      |
   | sync send                     |   | (netfilter | pf | dummy)      |
   +---------------+---------------+   +-------------------------------+
                   | fwout: whitelist replace requests   ^
                   +-------------------------------------+
```

### Pipes

`spawnChildren` (`internal/app/greyd/spawn.go`) creates five pipes and
keeps only the parent's ends; each child receives the ends it needs and
closes them at exit. Every pipe carries frames in the `internal/ipc` format
(below) in one direction only:

| Pipe (name in `procs`)   | From → to     | Contents                                                                 |
|--------------------------|---------------|--------------------------------------------------------------------------|
| `greyin` / `greyOut`     | main → grey   | `GreyMessage` tuples from the SMTP handler (`ipc.WriteGrey`); greylist, white and trapped entries received from sync peers, relayed by the main process (`ipc.WriteGreyFromSync`, `ipc.WriteAddr`) |
| `trapout` / `trapIn`     | grey → main   | `BlacklistMessage` traplists produced by the database scan (`grey.ScanOnce` → `ipc.WriteBlacklist`) |
| `fwout` (grey) / `greyfwin` | grey → fw  | `ReplaceRequest` frames replacing the whitelist sets (`ipc.WriteReplace`) |
| `fwin` / `fwOut`         | main → fw     | `NATRequest`: the source and proxy address of a redirected connection (`ipc.WriteNAT`) |
| `natout` / `natIn`       | fw → main     | `DstReply` with the pre-DNAT destination (`ipc.WriteDst`)               |

NAT lookups are request/response and are serialised with a mutex and a
one second deadline (`internal/app/greyd/nat.go`); everything else is
fire-and-forget. A malformed frame on any pipe is logged and skipped; the
reader resynchronises at the next terminator (`ipc.Reader.Next`). The main
process shuts down when either child exits (`serve.go`), and the children
exit when their input pipe closes.

### Main process

`daemon.serve` (`serve.go`) runs the phases of the C `main()` in order:

1. privileged setup: resolve the `user` (default `greyd`), write and lock
   the pidfile (`privs.WritePidfile`), spawn the children, start the sync
   engine in receive-only mode (`settings.WithoutSyncHosts`);
2. confinement: `chroot` into `chroot_dir`, `privs.Drop` to the
   unprivileged user, then `sandbox.Apply` with `RoleMain`;
3. service loops: one `smtp.Server.ServeListener` per SMTP listener
   (`internal/smtp`), the configuration socket, the trap pipe reader and
   the sync receiver, all in goroutines collected by `loopGroup`;
4. shutdown in dependency order (listeners, SMTP connections, sync,
   children, pipes, pidfile).

The listening sockets are bound before privileges are dropped
(`listen.go`), and when `daemonize` is set the parent detaches before
binding so the sockets belong to the final process.

The main process holds the blacklists in memory (`internal/blacklist`, a
binary radix trie per address family) and hands a snapshot to the SMTP
handler for every connection. It never touches the database or the
firewall itself.

### Firewall child (`fw_child.go`)

Opens the configured `core.Firewall` while still root, then drops to the
main user, chroots (unless the driver is `pf`, which needs `pfctl` and
`/dev/pf`) and applies the firewall sandbox profile. It serves two pipes
with one handler: NAT lookups from the main process and set replacements
from the greylister, serialised through a mutex because most firewall
handles are not concurrency safe.

### Greylister (`grey_child.go`, `internal/grey`)

Resolves `grey.user` (default `greydb`), constructs two `core.Store`
handles, starts a send-only sync engine (`settings.WithoutSyncBind`),
drops privileges, opens both stores read-write and applies the grey
sandbox profile (`/etc` readable for the resolver, the store's directories
and the log file's directory writable). Two goroutines run:

- the reader (`grey.RunReader`) consumes `greyin`: greylist tuples are
  checked against spamtraps, permitted domains and SPF
  (`core.SPFChecker`, `adapters/spf`), then inserted or updated; white and
  trapped entries are applied; changes that did not come from sync are
  announced to sync peers;
- the scanner (`grey.RunScanner`, every `grey.ScanInterval`) expires
  entries, whitelists tuples that were retried after `pass_time`, and
  pushes the whitelist to the firewall child and the traplist to the main
  process.

## Configuration socket

`greyd-setup` delivers blacklists to a running `greyd` over the
configuration listener (`listen.go` `bindConfig`, `config_socket.go`).
There are two forms:

- the `spamd` compatible form, the default: a TCP socket on
  `127.0.0.1:<config_port>` (8026). A client is trusted only if its source
  port is below 1024 (`IPPortReserved`), which requires root;
  `setup.DialReserved` walks ports 1023 down to 512;
- `config_socket = "<path>"`: a unix domain socket created mode 0600. The
  peer's credentials are read (`internal/peercred`: `SO_PEERCRED` on
  Linux, `LOCAL_PEERCRED`/`getpeereid` on the BSDs) and the connection is
  accepted only from root or the daemon's own effective user. Where the
  platform cannot report credentials the socket mode is the only check.

Each connection carries one frame, bounded by `max_config_frame` and a
30 second deadline: a `BlacklistMessage` replaces any existing blacklist
with the same name (`daemon.installBlacklist`), and a `StatsRequest`
(`type = "stats"`) is answered with a `StatsReply` frame (see
"Statistics"). Connections are served one at a time.

The listener can also come from a service manager: `internal/activation`
implements the systemd `LISTEN_FDS` protocol and `daemon.adopt`
(`listen.go`) assigns the passed sockets by name (`smtp`, `smtp6`,
`config`). Started that way as an unprivileged user, `confine` skips the
chroot with a warning and `privs.SwitchUser` returns `ErrCannotSwitch`
rather than failing, so all three processes keep the service user.

## Statistics

The main process keeps cumulative totals in `smtp.Counters` (accepted and
refused connections, grey tuples sent, replies by kind, PROXY headers)
next to the live connection counts. The greylister counts the database
entries by kind after every scan (`stats.Summarize`, one read
transaction over `IterAll`) and sends a `ScanStats` frame up the trap
pipe; the main process keeps the last one (`stats.go`). A `StatsRequest`
on the configuration socket is answered with all of it plus the loaded
blacklists and their sizes as `name=entries`.

Three consumers share `internal/stats`: `greyd --stats` prints the reply,
`greydb -s` runs `Summarize` against the store directly, and
`greyd-monitor` polls the socket every `monitor.interval` seconds and
renders the last reply as Prometheus text (`monitor.WriteMetrics`) on
`monitor.bind_address:monitor.port`, with `greyd_up` and its own poll
counters describing the exporter's health. It runs as the `greyd` user,
which the unix configuration socket admits.

## Frame codec (`internal/ipc`)

All pipes and the configuration socket share one text format, identical to
the C implementation: a frame is a sequence of `greyd.conf` assignments
(`name = 1`, `name = "text"`, `name = [ "a", "b" ]`, `#` comments) ended by
a line containing only `%%`. `ipc.Reader` splits the stream into frames
(default limit 64 MiB, `SetMaxFrame` for the configuration socket) and
`ipc.Decode` classifies each into a typed `Message`:

| Message            | Distinguishing fields             | Used on                              |
|--------------------|-----------------------------------|--------------------------------------|
| `GreyMessage`      | `type = 1`, `ip`, `helo`, `from`, `to`, `dst_ip`, `sync` | `greyin`       |
| `AddrMessage`      | `type = 2` (trapped) or `3` (white), `ip`, `source`, `expires`, `delete`, `sync` | `greyin` |
| `BlacklistMessage` | `name`, `message`, `ips = [...]`  | configuration socket, `trapout`      |
| `ReplaceRequest`   | `type = "replace"`, `name` (the set), `af`, `ips = [...]` | `greyfwin`   |
| `NATRequest`       | `type = "nat"`, `src`, `src_port`, `proxy`, `proxy_port` | `fwin`        |
| `DstReply`         | `dst`                             | `natout`                             |

`ipc.Builder` and the `Write*` helpers produce frames. String values are
written verbatim, as the C code does, except where `SafeStr`/`Sanitize`
strip quotes and backslashes from client-controlled data.

## Sync protocol (`internal/sync`)

Sync is the `spamd` version 2 UDP protocol, byte for byte (`wire.go`):
a header with a counter, a sequence of TLV entries (`grey`, `white`,
`trapped`, `delwhite`, `deltrapped`) and an HMAC-SHA1 over the packet keyed
with the SHA1 digest of `sync.key` (all zeros when the key file is
absent). Packets go to the unicast `sync.hosts` and/or the multicast group
`224.0.1.241` on `sync.port`.

Sending and receiving are split between processes so that no process needs
both a bound socket and the database:

- the main process receives (`Engine.Serve`), validates the HMAC, applies
  the per-peer anti-replay window (`sync.replay_window`) and relays each
  entry to the greylister over `greyin` with `sync = 0` so it is not
  re-broadcast;
- the greylister, `greylogd` and `greydb -Y` send (`Engine.Update`,
  `White`, `Trapped`) for changes they make locally.

`Engine.New` returns nil when `sync.enable = 0`; the command line switches
`-y`/`-Y` add hosts as in `spamd`.

## Configuration and settings

`internal/config` is the generic model: named sections, `blacklist` and
`whitelist` sections, ordered keys, `include` globs. Text is parsed by an
ANTLR 4 grammar (`internal/config/grammar/GreydConf.g4`, generated sources
committed) through `internal/config/parse`, which installs itself as the
loader when imported.

`internal/settings` is the typed view. One struct per section (`Global`,
`Grey`, `Sync`, `SPF`, `Setup`, `Firewall`, `Database`) declares each
variable with `conf:"name"` and `def:"value"` struct tags; `settings.Load`
decodes the generic model into them, applies defaults, runs `Validate`
(ranges and cross-field rules) and records every unknown variable in
`Settings.Warnings`, which the daemons log and `greyd -t` prints. Driver
specific options stay in the section's `Raw` for the adapter factories.
`WithoutSyncBind` and `WithoutSyncHosts` derive the send-only and
receive-only sync configurations used by the different processes.

## Ports and adapters

`internal/core` defines the ports; adapters implement them and register
themselves; the applications only see the interfaces.

```
   internal/app/*  internal/grey  internal/setup  internal/smtp
          |               |             |
          v               v             v
   +--------------------------------------------------+
   | internal/core                                    |
   |   Store / ReadTx / Tx / Iterator   (store.go)    |
   |   Firewall                         (firewall.go) |
   |   SPFChecker                       (spf.go)      |
   |   RegisterStore / RegisterFirewall (registry.go) |
   +-----------+------------------+-------------------+
               |                  |
   adapters/db/{bolt,sqlite,      adapters/fw/{netfilter,pf,dummy}
     mysql,postgresql,memory}     adapters/spf
```

- `core.Store` is opened once per process; every operation runs inside a
  transaction created by `View` or `Update`, so rollback on error is
  automatic. Keys are typed (`KeyIP`, `KeyMail`, `KeyTuple`, `KeyDomain`,
  `KeyDomainPart`) and `Tx.Scan` performs the expiry/whitelisting pass
  used by the greylister. Stores that keep files implement
  `FilesystemUser` so the sandbox can keep their directories writable.
- `core.Firewall` covers set replacement, the connection log capture used
  by `greylogd` and the original-destination lookup; every method takes a
  context so shutdown can interrupt kernel or subprocess calls.
- Adapters register from `init()` (`core.RegisterStore`,
  `core.RegisterFirewall`) with a name and the description shown by
  `greyd --drivers`; the bundles `adapters/db/all` and `adapters/fw/all`
  import them all. `core.NormalizeDriver` maps the shared object paths of
  old configurations (`/usr/lib/greyd/greyd_sqlite.so`) and the former
  Berkeley DB drivers to the compiled-in names.
- `adapters/db/sqlcommon` holds the SQL shared by the mysql, postgresql
  and sqlite drivers; `adapters/db/kv` holds the key/value encoding of the
  bolt driver; `adapters/db/dbtest` is the conformance suite every store
  runs. `adapters/fw/netfilter` speaks netlink directly (ipset, NFLOG,
  conntrack); `adapters/fw/pf` drives `pfctl` and `/dev/pf`.

## Privilege dropping and the sandbox

`internal/privs` ports the security sensitive parts of `utils.c`: user
lookup (done before any chroot hides the passwd database), `Chroot`
(loading time zone data first), `Drop` (supplementary groups, then real,
effective and saved gid/uid, verifying that root cannot be regained),
`setrlimit`, pidfile creation and locking, and `Daemonize`. Every process
performs its own drop as described above; the systemd units therefore
start the daemons as root with a reduced capability bounding set.

`internal/sandbox` is applied by each process after the drop, once it has
opened everything it needs, and cannot be undone. A `Profile` names the
role (`RoleMain`, `RoleFirewall`, `RoleGrey`, `RoleTool`) and the
directories still required. On Linux `Apply` sets `PR_SET_NO_NEW_PRIVS`,
restricts the filesystem with Landlock to the profile's paths and installs
a seccomp deny list; on OpenBSD it pledges a per-role promise set;
elsewhere it returns `ErrUnsupported` and the daemons continue without it.
A kernel without Landlock or seccomp degrades to the remaining mechanisms
with a debug log line. The `sandbox` option in `greyd.conf` turns it off.

## The other programs

- `greyd-setup` (`internal/setup`) fetches each list in `setup.lists` by
  `http`/`ftp` (through curl), `exec` or `file`, parses the `spamd` list
  syntax (`internal/spamdlist`, gzip aware), subtracts whitelists from the
  blacklists before them and collapses the ranges into CIDR blocks
  (`blacklist.Collapse`). Each blacklist is sent as one frame over a fresh
  configuration connection; in blacklist-only mode (`-b`) it also loads
  every CIDR into the `greyd-blacklist` firewall set itself, which is why
  the unit runs it as root.
- `greylogd` opens the firewall handle for log capture (NFLOG groups on
  netfilter, `pflog` on pf), writes its pidfile, drops to `grey.user` and
  applies the grey sandbox profile, then loops over `Firewall.CaptureLog`,
  refreshing the whitelist entry of every address seen in its own store
  transaction and announcing it to sync peers.
- `greydb` opens the store directly with `drop_privs` forced off and
  lists, summarises (`-s`) or updates entries; `-Y host` sends
  white/trapped changes over sync so a cluster stays consistent.
- `greyd-monitor` (see "Statistics") is a small `net/http` server with no
  database access of its own.

All daemons reopen `log_to_file` on SIGHUP (`greyd` forwards the signal
to its children) so log rotation needs no restart.

Logging is common to all of them: `internal/logger` is a `log/slog`
handler writing syslog (facility daemon), an optional `log_to_file`
(appended under an fcntl lock so the three `greyd` processes can share it)
and standard error in the C line format.

## Directory map

```
cmd/<prog>/main.go        program entry points (driver imports + Run)
internal/app/<prog>/      command line, process wiring, Run()
internal/core/            ports and the driver registry
internal/settings/        typed greyd.conf
internal/config/          generic configuration model and ANTLR parser
internal/ipc/             frame codec shared by pipes and the config socket
internal/procs/           re-exec based process spawning
internal/privs/           chroot, setuid, rlimits, pidfiles, daemonize
internal/sandbox/         Landlock/seccomp/pledge profiles
internal/peercred/        unix socket peer credentials
internal/smtp/            the SMTP conversation, proxy protocol, counters
internal/grey/            greylisting engine
internal/blacklist/       radix trie and range collapsing
internal/spamdlist/       spamd list parser
internal/setup/           blacklist fetching and delivery
internal/sync/            spamd sync protocol
internal/logger/          slog handler for syslog/file/stderr
internal/version/         build-time paths and version (set by -ldflags)
adapters/db/, adapters/fw/, adapters/spf/   driver implementations
etc/, packages/systemd/   configuration and unit templates (.in)
```
