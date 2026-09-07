#!/bin/sh
#
# greyd FreeBSD smoke test: ipfw firewall driver, sqlite database.
#
# Run as root on a FreeBSD host or VM with Go on the PATH (the CI job runs
# it through vmactions/freebsd-vm, see .github/workflows/integration.yml):
#
#   sh packages/integration/run-freebsd.sh
#
# What it does:
#   1. builds the programs (unless $GREYD_BIN already holds them),
#   2. creates the greyd and greydb users and a greyd.conf using the ipfw
#      firewall driver and the sqlite database,
#   3. loads ipfw (default accept), creates the ipfw0 log interface, adds a
#      fwd rule redirecting loopback port 2525 to greyd's 8025 and a log
#      rule for SYNs to port 25,
#   4. starts greyd -F, runs a greylisted SMTP dialogue through the fwd
#      rule and checks the 451 reply and the GREY tuple,
#   5. checks that a whitelist entry reaches the greyd-whitelist ipfw
#      table, that a connection to the low priority MX alias through fwd is
#      trapped (the fwd original destination path), that greylogd whitelists
#      the source of a logged SYN, and that a blacklist pushed by
#      greyd-setup over the unix configuration socket takes effect,
#   6. stops everything cleanly and removes its ipfw rules and tables.
#
# Environment: GREYD_SRC, GREYD_BIN, GREYD_IT_WAIT (20), GREYD_IT_KEEP,
# GREYD_IT_DROP_PRIVS (1).
#
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${GREYD_SRC:-$(cd "$HERE/../.." && pwd)}
BIN=${GREYD_BIN:-$SRC/bin}
WAIT=${GREYD_IT_WAIT:-20}
DROP_PRIVS=${GREYD_IT_DROP_PRIVS:-1}
KEEP=${GREYD_IT_KEEP:-0}

ETC=/usr/local/etc/greyd
DB=/var/db/greyd
RUNDIR=/var/run/greyd
LOGDIR=/var/log/greyd
CHROOT=/var/empty
CONF=$ETC/greyd.conf
SOCK=$RUNDIR/config.sock
LOG=$LOGDIR/greyd.log
LISTDIR=$ETC/lists

SMTP_PORT=8025
RDR_PORT=2525
MX_ALIAS=127.0.0.2
LOGGED_SRC=127.0.0.6
LOGGED_DST=127.0.0.7
WHITELIST_TABLE=greyd-whitelist
PRELOAD_WHITE=10.99.0.1
RULE_BASE=1000

GREYD_PID=
GREYLOGD_PID=
ALIASES=
STEP=0

say()  { printf '%s\n' "$*"; }
step() { STEP=$((STEP + 1)); say ""; say "=== step $STEP: $*"; }
pass() { say "PASS: $*"; }
is_alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }
run_greydb() { su -m greydb -c "\"$BIN/greydb\" -f \"$CONF\" $*"; }
db_has() { run_greydb 2>/dev/null | grep -q -- "$1"; }
log_has() { grep -q -- "$1" "$LOG" 2>/dev/null; }

dump_state() {
    say ""
    say "--- diagnostics ---"
    say "greyd pid $GREYD_PID alive: $(is_alive "$GREYD_PID" && echo yes || echo no)"
    say "greylogd pid $GREYLOGD_PID alive: $(is_alive "$GREYLOGD_PID" && echo yes || echo no)"
    say "--- $LOG (tail) ---";     tail -n 200 "$LOG" 2>/dev/null || true
    say "--- greyd stderr ---";    tail -n 50 "$LOGDIR/greyd.stderr" 2>/dev/null || true
    say "--- greylogd stderr ---"; tail -n 50 "$LOGDIR/greylogd.stderr" 2>/dev/null || true
    say "--- greydb ---";          run_greydb 2>&1 || true
    say "--- ipfw list ---";       ipfw list 2>&1 || true
    say "--- ipfw table all list ---"; ipfw table all list 2>&1 || true
    say "--- sysctl ---";          sysctl net.inet.ip.fw.verbose net.inet.ip.fw.default_to_accept 2>&1 || true
    say "--- processes ---";       ps -axo pid,user,command | grep -E '[g]reyd|[g]reylogd' || true
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

# smtp_dialogue ADDR PORT HELO
smtp_dialogue() {
    {
        sleep 1; printf 'EHLO %s\r\n' "$3"
        sleep 1; printf 'MAIL FROM:<sender@example.test>\r\n'
        sleep 1; printf 'RCPT TO:<rcpt@example.test>\r\n'
        sleep 1; printf 'DATA\r\n'
        sleep 2; printf 'Subject: greyd\r\n\r\ntest\r\n.\r\n'
        sleep 2; printf 'QUIT\r\n'
        sleep 1
    } | nc -w 30 "$1" "$2" | tee "$LOGDIR/smtp.out"
}

stop_pid() {
    pid=$1
    if is_alive "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        i=0
        while is_alive "$pid" && [ "$i" -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
        is_alive "$pid" && kill -KILL "$pid" 2>/dev/null
    fi
}

cleanup() {
    rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ]; then
        say "FAIL: aborted with status $rc at step $STEP" >&2
        dump_state
    fi
    if [ "$KEEP" = 1 ]; then
        say "GREYD_IT_KEEP=1: leaving everything in place"
        exit "$rc"
    fi
    stop_pid "$GREYLOGD_PID"
    stop_pid "$GREYD_PID"
    for n in 0 1 2 3; do ipfw -q delete $((RULE_BASE + n)) 2>/dev/null || true; done
    for t in $WHITELIST_TABLE ${WHITELIST_TABLE}_new greyd-whitelist-ipv6 greyd-whitelist-ipv6_new; do
        ipfw -q table "$t" destroy 2>/dev/null || true
    done
    for a in $ALIASES; do ifconfig lo0 "$a" -alias 2>/dev/null || true; done
    rm -f "$SOCK" "$RUNDIR/greyd.pid" "$RUNDIR/greylogd.pid"
    exit "$rc"
}
trap cleanup EXIT

# --- 1. environment ----------------------------------------------------------

step "environment"
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ "$(uname -s)" = FreeBSD ] || die "this script is for FreeBSD (got $(uname -s))"
command -v go >/dev/null 2>&1 || die "go not on PATH"
command -v nc >/dev/null 2>&1 || die "nc not available"
command -v ipfw >/dev/null 2>&1 || die "ipfw not available"
if ! kldstat -q -m ipfw; then
    # Loaded with an accept-all default so the VM keeps its network.
    kenv net.inet.ip.fw.default_to_accept=1 >/dev/null
    kldload ipfw || die "could not load the ipfw module"
fi
sysctl net.inet.ip.fw.default_to_accept
ifconfig ipfw0 >/dev/null 2>&1 || ifconfig ipfw0 create
sysctl net.inet.ip.fw.verbose=0 >/dev/null
pass "FreeBSD $(uname -r) with $(go version | cut -d' ' -f3), ipfw loaded, ipfw0 present"

# --- 2. programs -------------------------------------------------------------

step "programs"
if [ ! -x "$BIN/greyd" ] || [ ! -x "$BIN/greydb" ] || [ ! -x "$BIN/greyd-setup" ] || [ ! -x "$BIN/greylogd" ]; then
    say "building into $BIN"
    mkdir -p "$BIN"
    for p in greyd greydb greyd-setup greylogd; do
        (cd "$SRC" && CGO_ENABLED=0 go build -trimpath -o "$BIN/$p" "./cmd/$p")
    done
fi
"$BIN/greyd" --version
"$BIN/greyd" --drivers | grep -q ipfw || die "ipfw firewall driver not compiled in"
"$BIN/greyd" --drivers | grep -q sqlite || die "sqlite database driver not compiled in"
pass "programs present with ipfw and sqlite drivers"

# --- 3. users, directories, configuration ------------------------------------

step "users, directories and configuration"
for u in greyd greydb; do
    pw groupshow "$u" >/dev/null 2>&1 || pw groupadd "$u"
    if ! pw usershow "$u" >/dev/null 2>&1; then
        shell=/usr/sbin/nologin
        [ "$u" = greydb ] && shell=/bin/sh
        pw useradd "$u" -d /var/empty -s "$shell" -g "$u" -c "greyd $u"
    fi
done
mkdir -p "$ETC" "$RUNDIR" "$LOGDIR" "$CHROOT" "$LISTDIR"
chmod 0755 "$ETC" "$RUNDIR" "$LOGDIR"
mkdir -p "$DB"
chown greydb:greydb "$DB"
chmod 0700 "$DB"
rm -f "$LOG" "$LOGDIR"/*.stderr "$LOGDIR"/smtp.out "$DB"/greyd.sqlite* "$SOCK"
for a in $MX_ALIAS $LOGGED_SRC $LOGGED_DST; do
    if ! ifconfig lo0 | grep -q "inet $a "; then
        ifconfig lo0 alias "$a" netmask 255.255.255.255
        ALIASES="$ALIASES $a"
    fi
done
printf '127.0.0.0/8\n' >"$LISTDIR/local.txt"

cat >"$CONF" <<EOF
#
# greyd FreeBSD integration test configuration (generated).
#
hostname       = "it.example.test"
daemonize      = 0
debug          = 1
syslog_enable  = 0
log_to_file    = "$LOG"
user           = "greyd"
drop_privs     = $DROP_PRIVS
chroot         = 1
chroot_dir     = "$CHROOT"
setrlimit      = 0
sandbox        = 1
bind_address   = "127.0.0.1"
port           = $SMTP_PORT
config_socket  = "$SOCK"
# /var/empty is immutable (schg) on FreeBSD, so the pidfiles live in the
# run directory; greyd cannot remove its own from inside the chroot, which
# is harmless.
greyd_pidfile  = "$RUNDIR/greyd.pid"
greylogd_pidfile = "$RUNDIR/greylogd.pid"
stutter        = 0

section firewall {
    driver         = "ipfw"
    ipfw_log_if    = "ipfw0"
    track_outbound = 1
}

section database {
    driver  = "sqlite"
    path    = "$DB"
    db_name = "greyd.sqlite"
}

section grey {
    enable       = 1
    user         = "greydb"
    stutter      = 0
    low_prio_mx  = "$MX_ALIAS"
    traplist_name    = "greyd-greytrap"
    traplist_message = "Your address %A has mailed to spamtraps here"
    whitelist_name   = "$WHITELIST_TABLE"
}

section spf {
    enable = 0
}

section setup {
    lists = [ "local" ]
}

blacklist local {
    method  = "file"
    file    = "$LISTDIR/local.txt"
    message = "Your address %A is in the integration test list"
}
EOF
"$BIN/greyd" -t -f "$CONF" || die "greyd rejected the configuration"
pass "configuration accepted by greyd -t"

# --- 4. ipfw rules -----------------------------------------------------------

step "ipfw fwd $RDR_PORT->$SMTP_PORT and log rules"
ipfw -q table "$WHITELIST_TABLE" create type addr 2>/dev/null || true
ipfw -q add $((RULE_BASE + 0)) fwd 127.0.0.1,$SMTP_PORT tcp from any to 127.0.0.1 $RDR_PORT in via lo0
ipfw -q add $((RULE_BASE + 1)) fwd 127.0.0.1,$SMTP_PORT tcp from any to $MX_ALIAS $RDR_PORT in via lo0
ipfw -q add $((RULE_BASE + 2)) count log tcp from any to any 25 setup in via lo0
ipfw -q add $((RULE_BASE + 3)) allow ip from any to any
ipfw list | grep -E "^0*$((RULE_BASE + 0)) |^0*$((RULE_BASE + 2)) "
pass "fwd and log rules installed, table $WHITELIST_TABLE exists"

# --- 5. pre-load whitelist entry ---------------------------------------------

step "pre-load whitelist entry with greydb"
run_greydb -a "$PRELOAD_WHITE" || die "greydb -a $PRELOAD_WHITE failed"
db_has "^WHITE|$PRELOAD_WHITE|" || die "greydb did not record WHITE entry for $PRELOAD_WHITE"
pass "WHITE|$PRELOAD_WHITE stored in the sqlite database"

# --- 6. greyd ----------------------------------------------------------------

step "start greyd -F (firewall process keeps root for ipfw)"
"$BIN/greyd" -F -f "$CONF" >"$LOGDIR/greyd.stderr" 2>&1 &
GREYD_PID=$!
wait_for "greyd listening" log_has "listening for incoming connections" \
    || die "greyd did not start listening (alive: $(is_alive "$GREYD_PID" && echo yes || echo no))"
is_alive "$GREYD_PID" || die "greyd exited right after start"
[ -S "$SOCK" ] || die "configuration socket $SOCK was not created"
log_has "firewall process keeps them" || die "the firewall process did not report keeping its privileges"
ps -axo pid,user,command | grep '[g]reyd'
pass "greyd is up with its firewall and greylister processes"

# --- 7. SMTP dialogue through fwd --------------------------------------------

step "greylisted SMTP dialogue via 127.0.0.1:$RDR_PORT (fwd to $SMTP_PORT)"
smtp_dialogue 127.0.0.1 "$RDR_PORT" it.example.test
grep -q '^220' "$LOGDIR/smtp.out" || die "no banner from greyd through the fwd rule"
grep -q '^451' "$LOGDIR/smtp.out" || die "greyd did not reply 451"
wait_for "GREY tuple in database" db_has "^GREY|127.0.0.1|it.example.test|sender@example.test|rcpt@example.test|" \
    || die "GREY tuple not recorded"
pass "451 reply and GREY|127.0.0.1|... recorded"

# --- 8. whitelist reaches the ipfw table -------------------------------------

step "whitelist entry reaches ipfw table $WHITELIST_TABLE"
wait_for "$PRELOAD_WHITE in ipfw table" sh -c "ipfw table $WHITELIST_TABLE list | grep -q '^$PRELOAD_WHITE/32'" \
    || die "ipfw table $WHITELIST_TABLE does not list $PRELOAD_WHITE"
pass "ipfw table $WHITELIST_TABLE lists $PRELOAD_WHITE (swapped in by the firewall process)"

# --- 9. greylogd -------------------------------------------------------------

step "greylogd whitelists the source of a logged SYN to port 25"
"$BIN/greylogd" -f "$CONF" >"$LOGDIR/greylogd.stderr" 2>&1
GREYLOGD_PID=$(cat "$RUNDIR/greylogd.pid" 2>/dev/null || true)
wait_for "greylogd pidfile" test -s "$RUNDIR/greylogd.pid" || die "greylogd did not write its pidfile"
GREYLOGD_PID=$(cat "$RUNDIR/greylogd.pid")
wait_for "greylogd listening" log_has "listening direction" || die "greylogd did not start"
# Nothing listens on 25: the SYN is logged by the count rule and answered
# with a reset, which is all greylogd needs.
nc -w 1 -s "$LOGGED_SRC" "$LOGGED_DST" 25 </dev/null >/dev/null 2>&1 || true
wait_for "WHITE|$LOGGED_SRC" db_has "^WHITE|$LOGGED_SRC|" || die "greylogd did not whitelist $LOGGED_SRC"
pass "greylogd whitelisted $LOGGED_SRC seen on ipfw0"

# --- 10. original destination through fwd (low priority MX trap) ----------------

step "connection to the low priority MX $MX_ALIAS through fwd is trapped"
started=$(stat -f %m "$LOG" 2>/dev/null || date +%s)
now=$(date +%s)
grace=$((60 - (now - started)))
[ "$grace" -gt 0 ] && { say "waiting ${grace}s for the low priority MX grace period"; sleep "$grace"; }
smtp_dialogue "$MX_ALIAS" "$RDR_PORT" mx.example.test >/dev/null
wait_for "TRAPPED|127.0.0.1" db_has "^TRAPPED|127.0.0.1|" \
    || die "connecting to $MX_ALIAS through fwd did not trap 127.0.0.1 (original destination lost?)"
pass "TRAPPED|127.0.0.1 recorded: greyd saw the original destination $MX_ALIAS"

# --- 11. blacklist via greyd-setup ------------------------------------------

step "greyd-setup pushes a blacklist over the unix configuration socket"
"$BIN/greyd-setup" -f "$CONF" -d || die "greyd-setup failed"
wait_for "blacklist loaded" log_has "loaded blacklist" || die "greyd did not report the blacklist"
smtp_dialogue 127.0.0.1 "$RDR_PORT" bl.example.test >/dev/null
grep -q "integration test list" "$LOGDIR/smtp.out" || die "blacklist message not returned: $(cat "$LOGDIR/smtp.out")"
pass "450 reply with the blacklist message"

# --- 12. shutdown --------------------------------------------------------------

step "clean shutdown"
stop_pid "$GREYLOGD_PID"
kill -TERM "$GREYD_PID"
i=0; while is_alive "$GREYD_PID" && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
is_alive "$GREYD_PID" && die "greyd did not exit on SIGTERM"
wait "$GREYD_PID" 2>/dev/null && rc=0 || rc=$?
[ "$rc" -eq 0 ] || die "greyd exited with status $rc"
[ -z "$(ps -axo command | grep '^[^ ]*greyd ' || true)" ] || die "greyd left processes behind"
pass "greyd exited 0 and left no child processes"

say ""
say "ALL PASS ($STEP steps)"
