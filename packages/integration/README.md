# Integration harnesses

Two end-to-end tests that run the real daemons against a real firewall,
complementing the unit tests (which use the dummy firewall and in-process
databases):

| Harness | Where | Firewall | What it proves |
|---------|-------|----------|----------------|
| `run-linux.sh` | privileged Docker container (or a throw-away Linux root) | netfilter: ipset, NFLOG, conntrack | the full greyd / greylogd / greydb / greyd-setup flow with privilege separation, chroot and the Landlock/seccomp sandbox |
| `run-openbsd.sh` | OpenBSD VM (CI: `vmactions/openbsd-vm`) | pf: `pfctl`, `/dev/pf`, `DIOCNATLOOK` | the pf driver and the pledge sandbox keep greyd alive through a greylisting dialogue and a table replace |

Both are plain shell scripts, print one `PASS:`/`FAIL:` line per step and
exit non-zero on the first failed assertion after dumping logs, rules and
database contents. `.github/workflows/integration.yml` runs them on every
push and pull request.

## Linux harness

### Running

```sh
make test-integration                 # builds packages/integration/Dockerfile, runs it with --privileged
make test-integration INTEGRATION_RUN_FLAGS='-e GREYD_IT_WAIT=40'
```

`--privileged` is the simplest grant; the minimum is `--cap-add NET_ADMIN
--cap-add NET_RAW --cap-add SYS_CHROOT --cap-add SETUID --cap-add SETGID`.
The image is `golang:1.25-bookworm` plus `iptables ipset conntrack
netcat-openbsd python3`; the programs are built with `make build` during
the image build. Everything happens in the container's own network
namespace, so nothing on the host is touched.

The script can also run directly on a disposable Linux host as root
(`make test-integration-host`, or `sudo packages/integration/run-linux.sh`).
It writes `/etc/greyd/greyd.conf`, creates the `greyd` and `greydb` users,
adds iptables chains named `GREYD_IT_*` and the `greyd-whitelist` ipsets,
and removes the rules and sets again on exit. Do not run it on a machine
whose firewall matters.

Environment knobs: `GREYD_IT_WAIT` (poll budget per asynchronous
assertion, default 20 s), `GREYD_IT_KEEP=1` (leave daemons, rules and files
in place for inspection), `GREYD_IT_DROP_PRIVS=0` (write `drop_privs = 0`
so every process stays root; isolates privilege-drop failures from the rest
of the flow), `GREYD_BIN` (use pre-built programs), `GREYD_SRC`. Pass them
through docker with `INTEGRATION_RUN_FLAGS='-e GREYD_IT_DROP_PRIVS=0'`.

Until the top-level Makefile includes `integration.mk`, run
`make -f Makefile -f packages/integration/integration.mk test-integration`.

### Configuration under test

`drop_privs = 1` (or `$GREYD_IT_DROP_PRIVS`), `chroot = 1` (`/var/empty/greyd`), `sandbox = 1`,
`daemonize = 0`, syslog off, `log_to_file = /var/log/greyd/greyd.log`,
`bind_address = 127.0.0.1`, `config_socket = /run/greyd/config.sock`,
firewall driver `netfilter` (`track_outbound = 1`, groups 155/255),
database driver `sqlite` in `/var/lib/greyd`, `low_prio_mx = 127.0.0.2`,
SPF and sync disabled, `stutter = 0` in both sections so dialogues are not
tarpitted. A `blacklist integration { method = "file" ... }` section points
at a list file the harness writes later.

Firewall rules (all in dedicated chains):

```
nat OUTPUT -o lo  -p tcp --dport 2525 -j DNAT --to-destination 127.0.0.1:8025
filter OUTPUT -o lo -p tcp --dport 25 -m conntrack --ctstate NEW -j NFLOG --nflog-group 255
filter INPUT  -i lo -p tcp --dport 25 -m conntrack --ctstate NEW -j NFLOG --nflog-group 155
```

### Steps and assertions

1. **environment**: root, working `iptables -t nat`, `ipset`, `conntrack`,
   `python3` (falls back to `iptables-legacy` if the nf_tables backend is
   unusable).
2. **programs**: `greyd --drivers` lists `netfilter` and `sqlite`.
3. **configuration**: `greyd -t` prints `configuration OK`.
4. **rules** installed.
5. **greydb** (run as `greydb`) adds `WHITE|10.99.0.1`; the database file is
   owned by `greydb`.
6. **greyd -F** starts: log says `listening for incoming connections`, the
   unix configuration socket exists, and `ps` shows two processes as `greyd`
   (main + firewall) and one as `greydb` (greylister).
7. **greylogd** starts, writes its pidfile and runs as `greydb` (NFLOG
   sockets were bound before the privilege drop).
8. **greylisting through DNAT**: `smtpcheck.py` connects to
   `127.0.0.1:2525`, walks EHLO/MAIL/RCPT/DATA and gets
   `451 Temporary failure`; `greydb` then lists
   `GREY|127.0.0.1|it.example.test|sender@example.test|rcpt@example.test|...`;
   the log contains no `original destination lookup failed` /
   `nat lookup failed` / `conntrack lookup` message; `conntrack -L` shows the
   `dport=2525` flow.
9. **ipset**: `ipset test greyd-whitelist 10.99.0.1` succeeds (the
   greylister's start-up scan pushed the whitelist through the firewall
   process).
10. **NFLOG / greylogd**: a SYN from `127.0.0.6` to `127.0.0.5:25` (refused,
    only the SYN matters) makes greylogd add `WHITE|127.0.0.5` (outbound
    group, destination) and `WHITE|127.0.0.6` (inbound group, source).
11. **wait** until greyd has been up for 65 s (`grey.LowPrioGrace` is 60 s;
    the wait is bounded and shared with the next step).
12. **second scanner pass**: the ipset now also holds `127.0.0.5` and
    `127.0.0.6`.
13. **conntrack original destination**: a first-time client `127.0.0.9`
    connects to `127.0.0.2:2525`, which DNAT rewrites to `127.0.0.1:8025`.
    Only a successful conntrack lookup hands the greylister
    `dst_ip = 127.0.0.2 = low_prio_mx`, so `TRAPPED|127.0.0.9` in `greydb`
    proves the lookup returned the pre-DNAT address (the `greydb` listing
    itself does not show destinations).
14. **traplist**: the greylister ships its traplist to greyd on every scan,
    so within one scan interval (bounded at 75 s, polled every 3 s) a
    connection from `127.0.0.9` gets
    `450 Your address 127.0.0.9 has mailed to spamtraps here`.
15. **greyd-setup**: a list file containing `127.0.0.0/8` is pushed over
    `/run/greyd/config.sock`; the next connection from `127.0.0.1` gets
    `450 Your address 127.0.0.1 is in the integration test list` after the
    message body (blacklisted clients are answered after DATA).
16. **shutdown**: SIGTERM makes greylogd and greyd exit 0 and leaves no
    child processes.

A full run takes about 2.5 minutes plus the image build (the 60 s grace
period and one 60 s scan interval dominate).

`smtpcheck.py` accepts reply lines ending in a bare LF but prints
`WARNING: N reply line(s) ended in a bare LF instead of CRLF`; see
[Known failures](#known-failures) for why that currently fires.

### Known failures

The harness was run on 2026-09-07 against the tree as of that date:

- With the default `drop_privs = 1` it fails at step 6: the firewall
  process dies with
  `fatal error: AllThreadsSyscall6 results differ between threads; runtime corrupted`
  (`capset` returned `EPERM` on some threads). `PR_SET_KEEPCAPS` is a
  per-thread flag, so only the thread that called `prctl` in
  `adapters/fw/netfilter/netfilter_linux.go` (`Open`) keeps `CAP_NET_ADMIN`
  across the all-threads `setresuid`; the all-threads `capset` in
  `raiseCaps` then succeeds on that thread and fails on the rest, which the
  Go runtime treats as fatal. greylogd takes the same path (`Open`, drop,
  `CaptureLog` -> `raiseCaps`). The fix belongs in the driver (set
  `SECBIT_KEEP_CAPS` / `PR_SET_KEEPCAPS` on every thread, e.g. through
  libcap's `cap.SetUID` or `syscall.AllThreadsSyscall`); the harness prints
  a `HINT:` line when it sees this signature.
- With `GREYD_IT_DROP_PRIVS=0` all 16 steps pass; that run is what
  validates the rest of the flow (DNAT + conntrack, ipset, both NFLOG
  groups, traplist, greyd-setup over the unix socket, clean shutdown).
- Blacklist rejections (steps 14 and 15) arrive with a bare LF: `HandleWrite`
  in `internal/smtp/conn.go` only inserts a `\r` when the byte at the
  current write offset is `\n`, so when the whole reply is written in one
  chunk (no stuttering: `stutter = 0`, the grey stutter period over, or the
  blacklisted-connection cap reached) the newlines inside `FormatReply`'s
  output go out without CR. The 451 grey reply is unaffected (it carries
  its own CRLF). The client only warns about this.

### Debugging a failure

On any failed assertion the script prints the tail of
`/var/log/greyd/greyd.log` (all three greyd processes and greylogd log
there, tagged with their program name), the daemons' stderr, the full
`greydb` listing, `iptables -S`, `iptables -t nat -S`, `ipset list`,
`conntrack -L` and the greyd processes. Useful follow-ups:

- Keep the container alive and poke around:
  `docker run --rm -it --privileged --entrypoint bash greyd-integration:1.0.0`
  then `GREYD_IT_KEEP=1 packages/integration/run-linux.sh`; afterwards
  `greydb -f /etc/greyd/greyd.conf`, `ipset list`, `tail -f /var/log/greyd/greyd.log`.
- `sandbox not applied` warnings mean Landlock/seccomp could not be set up
  (old kernel or seccomp already filtered by Docker); they are warnings,
  not failures, but explain a process that can suddenly reach files it
  should not.
- A missing GREY tuple with a 451 reply points at the greylister (check
  for `grey message failed`, database permission errors: the sqlite
  directory must belong to `greydb`).
- No ipset entry while `greydb` shows WHITE entries points at the firewall
  process: look for `firewall replace failed` and `could not raise
  CAP_NET_ADMIN` (the container lacks NET_ADMIN, or the capability was not
  kept across the uid change).
- A 450 that never arrives in steps 14/15 while the log shows
  `black=1 lists=...`: check the transcript for framing; `smtpcheck.py`
  splits on LF and prints each server line as `S: ...`.
- No WHITE entry after the NFLOG step: verify the rules hit with
  `iptables -v -S GREYD_IT_OUT` / `GREYD_IT_IN` (packet counters) and that
  greylogd logged `packet received`; the inbound and outbound groups must
  differ and match `inbound_group` / `outbound_group`.
- No TRAPPED entry in step 13: the fw process's conntrack lookup returned
  the proxy address or failed; run `conntrack -L` while a connection is
  open and check `nat lookup failed` / `conntrack lookup` debug lines in
  the log.
- `iptables` errors about `nf_tables`: the host kernel lacks the nft
  modules; the script switches to `iptables-legacy` automatically when
  that binary exists.

## OpenBSD smoke test

### Running

In CI the `openbsd` job of `integration.yml` boots OpenBSD 7.7 with
`vmactions/openbsd-vm`, installs Go (`pkg_add go`, replaced by the official
`go1.25.x.openbsd-amd64` tarball when the package is older than 1.25), runs
`go vet -unreachable=false ./...` and `go test ./...` for the whole tree
(this compiles the pf adapter tests and the pledge sandbox, which Linux
skips), and then `sh packages/integration/run-openbsd.sh`.

By hand, on an OpenBSD machine or VM you do not mind reconfiguring, as
root with Go 1.25 on the PATH:

```sh
sh packages/integration/run-openbsd.sh
```

Knobs: `GREYD_IT_WAIT`, `GREYD_IT_KEEP=1`, `GREYD_BIN`, and
`GREYD_IT_DROP_PRIVS` (default `1`; set to `0` to keep the firewall process
root if `pfctl` cannot open `/dev/pf` as the unprivileged user, see below).

Locally, `make vet-openbsd` (`GOOS=openbsd go vet -unreachable=false ./...`)
checks that the code the script relies on still compiles for OpenBSD.

### What it does and asserts

The script writes `/etc/greyd/greyd.conf` (pf driver, sqlite in
`/var/greyd`, `chroot = 1` into `/var/empty`, `sandbox = 1` so every
process pledges, `config_socket`, no stutter) and `/etc/greyd/pf.conf`:

```
table <greyd-whitelist> persist
table <greyd-greytrap> persist
pass in quick on lo0 proto tcp to port 2525 rdr-to 127.0.0.1 port 8025
pass
```

then enables pf, loads that ruleset (remembering whether pf was enabled
before), whitelists `10.99.0.1` with `greydb` (as user `greydb`), starts
`greyd -F` and asserts:

1. `greyd -t` accepts the configuration; `--drivers` lists `pf` and `sqlite`.
2. pf reports both tables.
3. greyd logs `listening for incoming connections`, creates the
   configuration socket and shows three processes.
4. An `nc` dialogue to `127.0.0.1:2525` (redirected to 8025, which makes the
   firewall process issue `DIOCNATLOOK` under pledge `pf`) returns a `220`
   banner and `451`; `greydb` lists the GREY tuple.
5. All three processes are still alive afterwards, `dmesg` shows no
   `pledge` line for greyd and the log has no `child process exited`: a
   pledge violation kills the process with SIGABRT.
6. `pfctl -t greyd-whitelist -T show` lists `10.99.0.1` (the greylister's
   start-up scan replaced the table through `pfctl -T replace`).
7. SIGTERM makes greyd exit 0 with no surviving children.

On exit the tables are emptied, `/etc/pf.conf` is reloaded and pf is
disabled again if it was disabled before.

### Debugging a failure

The script dumps `greyd.log`, stderr, the `greydb` listing, `pfctl -sr`,
`pfctl -s Tables`, the whitelist table, the greyd processes and the tail of
`dmesg`. Things to look at:

- A process missing in step 5 with `greyd[pid]: pledge "xyz", syscall N` in
  `dmesg`: the pledge promise set in `internal/sandbox/sandbox_openbsd.go`
  is too narrow for that role.
- Step 6 failing with `firewall replace failed ... pfctl ... /dev/pf:
  Permission denied` in the log: the firewall process runs as `greyd`
  after `drop_privs` and `pfctl -p /dev/pf` re-opens the device, which
  only root may do (the C driver handed pfctl `/dev/fd/N` of the
  already-open descriptor). Re-run with `GREYD_IT_DROP_PRIVS=0` to confirm
  the rest works while the driver is fixed.
- `rdr-to` not taking effect (dialogue times out): check `pfctl -sr` shows
  the rule and that no `set skip on lo0` survived from the previous
  ruleset; the harness loads its own file with `pfctl -f`.
- In CI, the VM step has no interactive access; rerun locally with
  `GREYD_IT_KEEP=1` to leave greyd and pf configured.

## Files

- `Dockerfile`: harness image (golang:1.25-bookworm + netfilter tools).
- `run-linux.sh`: Linux harness (bash).
- `smtpcheck.py`: minimal SMTP client used by the Linux harness; prints the
  transcript, exits 0 when the final reply matches `--expect` /
  `--expect-text`.
- `run-openbsd.sh`: OpenBSD smoke test (POSIX sh, uses `nc`).
- `integration.mk`: `test-integration`, `test-integration-image`,
  `test-integration-host`, `vet-openbsd` (included from the top-level Makefile).

## spamd sync compatibility (OpenBSD)

`run-openbsd-sync.sh` runs the `spamd(8)` shipped with OpenBSD next to greyd
on loopback, each sending synchronisation messages to the other with a
shared `/etc/mail/spamd.key`, and asserts that:

- a greylisted dialogue against greyd appears in `spamdb` as a GREY entry;
- `greydb -Y` pushes WHITE and TRAPPED entries that `spamdb` lists;
- a greylisted dialogue against spamd appears in `greydb`;
- both daemons survive and greyd exits cleanly.

spamd binds the sync port on the wildcard address (`-y lo0`), greyd on the
loopback alias 127.0.0.2; both set SO_REUSEADDR, so the two sockets share
port 8025/udp. spamd's SMTP listener is moved to 18025 with `-p`.

    # sh packages/integration/run-openbsd-sync.sh

The CI job runs it after the pf smoke test. On failure the script dumps
both databases, both logs and the bound sockets.

## FreeBSD smoke test (ipfw)

`run-freebsd.sh` exercises the native ipfw driver in a FreeBSD VM: it loads
ipfw (default accept), creates the `ipfw0` log interface, installs `fwd`
rules from loopback port 2525 to greyd's 8025 and a `count log` rule for
SYNs to port 25, then checks that

- a greylisted dialogue through the `fwd` rule gets a 451 and a GREY tuple;
- the whitelist entry reaches the `greyd-whitelist` ipfw table (staging
  table swapped in by the privileged firewall process);
- greylogd whitelists the source of a SYN logged on `ipfw0`;
- a connection to the low priority MX alias through `fwd` is trapped, which
  proves the original destination survives the redirect;
- a blacklist pushed by greyd-setup over the unix socket takes effect;
- greyd exits cleanly.

    # sh packages/integration/run-freebsd.sh

The firewall process keeps root with this driver because the ipfw control
socket checks privileges on every call; the main and greylister processes
still drop to greyd and greydb.
