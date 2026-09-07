#!/bin/sh
#
# greyd <-> spamd synchronisation compatibility test (OpenBSD).
#
# Runs the spamd(8) that ships with OpenBSD next to greyd on loopback, each
# configured to send synchronisation messages to the other, and checks that
# entries created on one side appear in the other's database:
#
#   greyd -> spamd : a greylisted SMTP dialogue against greyd shows up in
#                    spamdb as a GREY entry; greydb -Y pushes WHITE and
#                    TRAPPED entries into spamdb.
#   spamd -> greyd : a greylisted dialogue against spamd shows up in greydb.
#
# Both sides authenticate with the same key file (/etc/mail/spamd.key), so
# the HMAC layout is exercised too. spamd serves SMTP on 127.0.0.1:18025
# and receives sync on the loopback alias 127.0.0.3 (-y with an address:
# in interface mode, -y lo0, spamd silently drops packets whose source is
# the interface's own address, which on one host is every packet); greyd
# serves SMTP on 127.0.0.2:8025 and receives sync on 127.0.0.2:8025.
#
# Run as root on OpenBSD with Go on the PATH:
#
#   sh packages/integration/run-openbsd-sync.sh
#
# Environment: GREYD_SRC, GREYD_BIN, GREYD_IT_WAIT (30), GREYD_IT_KEEP.
#
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${GREYD_SRC:-$(cd "$HERE/../.." && pwd)}
BIN=${GREYD_BIN:-$SRC/bin}
WAIT=${GREYD_IT_WAIT:-30}
KEEP=${GREYD_IT_KEEP:-0}

ETC=/etc/greyd
DB=/var/greyd-sync
RUNDIR=/var/run/greyd
LOGDIR=/var/log/greyd
CONF=$ETC/greyd-sync.conf
SOCK=$RUNDIR/sync-config.sock
LOG=$LOGDIR/greyd-sync.log
KEY=/etc/mail/spamd.key
# spamd is a daemon in libexec, not on the PATH.
SPAMD=${SPAMD:-/usr/libexec/spamd}
SPAMDB=${SPAMDB:-/usr/sbin/spamdb}

GREYD_ADDR=127.0.0.2
SPAMD_ADDR=127.0.0.1
SPAMD_SYNC_ADDR=127.0.0.3
GREYD_SMTP=8025
SPAMD_SMTP=18025
WHITE_IP=10.77.0.1
TRAP_IP=10.77.0.3

GREYD_PID=
SPAMD_PID=
ALIASES=
KEY_CREATED=0
STEP=0

say()  { printf '%s\n' "$*"; }
step() { STEP=$((STEP + 1)); say ""; say "=== sync step $STEP: $*"; }
pass() { say "PASS: $*"; }
is_alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }
run_greydb() { su greydb -c "\"$BIN/greydb\" -f \"$CONF\" $*"; }
greydb_has() { run_greydb 2>/dev/null | grep -q -- "$1"; }
spamdb_has() { "$SPAMDB" 2>/dev/null | grep -q -- "$1"; }

dump_state() {
    say ""
    say "--- diagnostics ---"
    say "greyd pid $GREYD_PID alive: $(is_alive "$GREYD_PID" && echo yes || echo no)"
    say "spamd pid $SPAMD_PID alive: $(is_alive "$SPAMD_PID" && echo yes || echo no)"
    say "--- $LOG (tail) ---";     tail -n 150 "$LOG" 2>/dev/null || true
    say "--- greyd stderr ---";    tail -n 40 "$LOGDIR/greyd-sync.stderr" 2>/dev/null || true
    say "--- spamd output ---";    tail -n 80 "$LOGDIR/spamd.out" 2>/dev/null || true
    say "--- spamdb ---";          "$SPAMDB" 2>&1 || true
    say "--- greydb ---";          run_greydb 2>&1 || true
    say "--- sockets ---";         netstat -an -f inet 2>/dev/null | grep -E '8025|18025' || true
    say "--- processes ---";       ps -axo pid,user,command | grep -E '[g]reyd|[s]pamd' || true
    say "--- dmesg (tail) ---";    dmesg | tail -n 10 2>/dev/null || true
}

die() { say "FAIL: $*" >&2; dump_state; exit 1; }

wait_for() {
    what=$1; shift
    i=0
    while ! "$@" >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge "$((WAIT * 2))" ]; then
            say "timed out after ${WAIT}s waiting for: $what" >&2
            return 1
        fi
        sleep 0.5
    done
    return 0
}

# smtp_dialogue ADDR PORT HELO FROM TO
smtp_dialogue() {
    {
        sleep 2; printf 'HELO %s\r\n' "$3"
        sleep 2; printf 'MAIL FROM:<%s>\r\n' "$4"
        sleep 2; printf 'RCPT TO:<%s>\r\n' "$5"
        sleep 2; printf 'DATA\r\n'
        sleep 3; printf 'Subject: sync\r\n\r\ntest\r\n.\r\n'
        sleep 2; printf 'QUIT\r\n'
        sleep 1
    } | nc -w 60 "$1" "$2" | tee "$LOGDIR/smtp-sync.out"
}

cleanup() {
    rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ]; then
        say "FAIL: aborted with status $rc at sync step $STEP" >&2
        dump_state
    fi
    if [ "$KEEP" = 1 ]; then
        say "GREYD_IT_KEEP=1: leaving greyd, spamd and files in place"
        exit "$rc"
    fi
    for pid in "$GREYD_PID" "$SPAMD_PID"; do
        if is_alive "$pid"; then
            kill -TERM "$pid" 2>/dev/null || true
            i=0
            while is_alive "$pid" && [ "$i" -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
            is_alive "$pid" && kill -KILL "$pid" 2>/dev/null
        fi
    done
    pkill -x spamd 2>/dev/null || true
    for a in $ALIASES; do ifconfig lo0 "$a" delete 2>/dev/null || true; done
    [ "$KEY_CREATED" -eq 1 ] && rm -f "$KEY"
    rm -f "$SOCK"
    exit "$rc"
}
trap cleanup EXIT

# --- 1. environment ----------------------------------------------------------

step "environment"
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ "$(uname -s)" = OpenBSD ] || die "this script is for OpenBSD (got $(uname -s))"
[ -x "$SPAMD" ] || die "$SPAMD not found (spamd is part of the OpenBSD base system)"
[ -x "$SPAMDB" ] || die "$SPAMDB not found"
command -v nc >/dev/null 2>&1 || die "nc not available"
pgrep -x spamd >/dev/null 2>&1 && die "a spamd is already running; stop it first"
pass "OpenBSD $(uname -r): $SPAMD and $SPAMDB present"

# --- 2. programs -------------------------------------------------------------

step "programs"
if [ ! -x "$BIN/greyd" ] || [ ! -x "$BIN/greydb" ]; then
    say "building into $BIN"
    mkdir -p "$BIN"
    for p in greyd greydb; do
        (cd "$SRC" && CGO_ENABLED=0 go build -trimpath -o "$BIN/$p" "./cmd/$p")
    done
fi
"$BIN/greyd" --version
pass "greyd and greydb present"

# --- 3. users, key, alias, configuration -------------------------------------

step "users, shared sync key, loopback alias and configuration"
for u in greyd greydb; do
    if ! getent group "$u" >/dev/null 2>&1; then groupadd "$u"; fi
    if ! id "$u" >/dev/null 2>&1; then
        shell=/sbin/nologin
        [ "$u" = greydb ] && shell=/bin/sh
        useradd -d /var/empty -s "$shell" -g "$u" -c "greyd $u" "$u"
    fi
done
mkdir -p "$ETC" "$RUNDIR" "$LOGDIR" "$DB"
chown greydb:greydb "$DB"
chmod 0700 "$DB"
rm -f "$LOG" "$LOGDIR/greyd-sync.stderr" "$LOGDIR/spamd.out" "$DB"/greyd.sqlite* "$SOCK"

if [ ! -s "$KEY" ]; then
    # Any bytes will do: both sides hash the file (spamd.key(5)).
    openssl rand -hex 32 >"$KEY"
    chmod 0600 "$KEY"
    KEY_CREATED=1
fi
# The key must be readable by greyd's greylister (runs as greydb) as well
# as by spamd (root).
chmod 0644 "$KEY"

for a in $GREYD_ADDR $SPAMD_SYNC_ADDR; do
    if ! ifconfig lo0 | grep -q "inet $a "; then
        ifconfig lo0 alias "$a" netmask 255.255.255.255
        ALIASES="$ALIASES $a"
    fi
done

# spamdb keeps state in /var/db/spamd across runs: start from a clean slate.
for ip in $WHITE_IP $TRAP_IP; do "$SPAMDB" -d "$ip" 2>/dev/null || true; done

cat >"$CONF" <<EOF
#
# greyd <-> spamd sync compatibility test (generated).
#
hostname       = "sync.example.test"
daemonize      = 0
debug          = 1
syslog_enable  = 0
log_to_file    = "$LOG"
user           = "greyd"
drop_privs     = 1
chroot         = 1
chroot_dir     = "/var/empty"
setrlimit      = 0
sandbox        = 1
bind_address   = "$GREYD_ADDR"
port           = $GREYD_SMTP
config_socket  = "$SOCK"
greyd_pidfile  = "/var/empty/greyd-sync.pid"
stutter        = 0

section firewall {
    driver = "dummy"
}

section database {
    driver  = "sqlite"
    path    = "$DB"
    db_name = "greyd.sqlite"
}

section grey {
    enable  = 1
    user    = "greydb"
    stutter = 0
    pass_time = 120
}

section spf {
    enable = 0
}

section sync {
    enable       = 1
    hosts        = [ "$SPAMD_SYNC_ADDR" ]
    bind_address = "$GREYD_ADDR"
    port         = 8025
    verify       = 1
    key          = "$KEY"
}
EOF
"$BIN/greyd" -t -f "$CONF" || die "greyd rejected the configuration"
pass "key $KEY shared, aliases $GREYD_ADDR and $SPAMD_SYNC_ADDR on lo0, configuration accepted"

# --- 4. spamd ----------------------------------------------------------------

step "start spamd (greylisting, -y $SPAMD_SYNC_ADDR -Y $GREYD_ADDR, SMTP on $SPAMD_ADDR:$SPAMD_SMTP)"
# -d keeps spamd in the foreground; -S 0 disables the stutter for greylisted
# connections so the dialogue completes quickly; -G shortens the times.
"$SPAMD" -d -G 2:4:864 -S 0 -l "$SPAMD_ADDR" -p "$SPAMD_SMTP" -y "$SPAMD_SYNC_ADDR" -Y "$GREYD_ADDR" -n "spamd sync test" \
    >"$LOGDIR/spamd.out" 2>&1 &
SPAMD_PID=$!
wait_for "spamd SMTP listener" sh -c "netstat -an -f inet | grep -q '$SPAMD_ADDR.$SPAMD_SMTP.*LISTEN'" \
    || die "spamd did not start listening"
netstat -an -f inet | grep -q "$SPAMD_SYNC_ADDR\.8025 " || die "spamd sync socket ($SPAMD_SYNC_ADDR:8025/udp) not bound"
is_alive "$SPAMD_PID" || die "spamd exited right after start"
pass "spamd running (pid $SPAMD_PID), sync socket bound"

# --- 5. greyd ----------------------------------------------------------------

step "start greyd (sync hosts = [$SPAMD_SYNC_ADDR], bind_address = $GREYD_ADDR)"
"$BIN/greyd" -F -f "$CONF" >"$LOGDIR/greyd-sync.stderr" 2>&1 &
GREYD_PID=$!
wait_for "greyd listening" grep -q "listening for incoming connections" "$LOG" \
    || die "greyd did not start listening (alive: $(is_alive "$GREYD_PID" && echo yes || echo no))"
is_alive "$GREYD_PID" || die "greyd exited right after start"
grep -q "added spam sync host" "$LOG" || die "greyd did not register $SPAMD_SYNC_ADDR as a sync target"
grep -q "no sync key loaded" "$LOG" && die "greyd did not load the sync key"
pass "greyd up, sending to $SPAMD_SYNC_ADDR and receiving on $GREYD_ADDR"

# --- 6. greyd -> spamd: grey entry ------------------------------------------

step "greyd -> spamd: greylisted dialogue against greyd appears in spamdb"
smtp_dialogue "$GREYD_ADDR" "$GREYD_SMTP" g2s.example.test g2s-sender@example.test g2s-rcpt@example.test
grep -q '^451' "$LOGDIR/smtp-sync.out" || die "greyd did not reply 451"
wait_for "GREY tuple in greydb" greydb_has "GREY|127.0.0.[0-9]*|g2s.example.test|g2s-sender@example.test|g2s-rcpt@example.test" \
    || die "greyd did not record the tuple itself"
wait_for "GREY tuple in spamdb" spamdb_has "GREY|127.0.0.[0-9]*|g2s.example.test|g2s-sender@example.test|g2s-rcpt@example.test" \
    || die "spamd did not receive the grey entry from greyd"
pass "spamdb lists GREY|...|g2s.example.test|... sent by greyd"

# --- 7. greyd -> spamd: white and trapped via greydb -Y ----------------------

step "greyd -> spamd: greydb -Y pushes WHITE and TRAPPED entries"
run_greydb -Y "$SPAMD_SYNC_ADDR" -a "$WHITE_IP" || die "greydb -a $WHITE_IP failed"
run_greydb -Y "$SPAMD_SYNC_ADDR" -t -a "$TRAP_IP" || die "greydb -t -a $TRAP_IP failed"
wait_for "WHITE in spamdb" spamdb_has "WHITE|$WHITE_IP|" || die "spamd did not receive WHITE|$WHITE_IP"
wait_for "TRAPPED in spamdb" spamdb_has "TRAPPED|$TRAP_IP|" || die "spamd did not receive TRAPPED|$TRAP_IP"
pass "spamdb lists WHITE|$WHITE_IP and TRAPPED|$TRAP_IP"

# --- 8. spamd -> greyd: grey entry ------------------------------------------

step "spamd -> greyd: greylisted dialogue against spamd appears in greydb"
smtp_dialogue "$SPAMD_ADDR" "$SPAMD_SMTP" s2g.example.test s2g-sender@example.test s2g-rcpt@example.test
grep -q '^451' "$LOGDIR/smtp-sync.out" || die "spamd did not reply 451"
wait_for "GREY tuple in spamdb" spamdb_has "GREY|127.0.0.[0-9]*|s2g.example.test|" \
    || die "spamd did not record its own tuple"
# spamd relays the envelope addresses with their angle brackets.
wait_for "GREY tuple in greydb" greydb_has "GREY|127.0.0.[0-9]*|s2g.example.test|<*s2g-sender@example.test>*|<*s2g-rcpt@example.test>*" \
    || die "greyd did not receive the grey entry from spamd"
pass "greydb lists GREY|...|s2g.example.test|... sent by spamd"

# --- 9. both alive, clean shutdown -------------------------------------------

step "both daemons survived and stop cleanly"
is_alive "$GREYD_PID" || die "greyd died during the test"
is_alive "$SPAMD_PID" || die "spamd died during the test"
grep -qi "pledge" "$LOGDIR/greyd-sync.stderr" && die "pledge violation reported"
kill -TERM "$GREYD_PID"
i=0; while is_alive "$GREYD_PID" && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
is_alive "$GREYD_PID" && die "greyd did not exit on SIGTERM"
wait "$GREYD_PID" 2>/dev/null && rc=0 || rc=$?
[ "$rc" -eq 0 ] || die "greyd exited with status $rc"
pass "greyd exited 0; spamd still running"

say ""
say "ALL PASS (sync compatibility, $STEP steps)"
