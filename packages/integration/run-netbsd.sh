#!/bin/sh
#
# greyd NetBSD smoke test: npf firewall driver, sqlite database.
#
# Run as root on NetBSD with Go on the PATH (the CI job runs it through
# vmactions/netbsd-vm, see .github/workflows/integration.yml):
#
#   sh packages/integration/run-netbsd.sh
#
# What it does:
#   1. builds the programs (unless $GREYD_BIN already holds them),
#   2. creates the greyd and greydb users and a greyd.conf using the npf
#      firewall driver and the sqlite database,
#   3. loads an npf.conf declaring the greyd-whitelist and greyd-greytrap
#      tables and a rule logging SYNs to port 25 on npflog0,
#   4. starts greyd -F, runs a greylisted SMTP dialogue against port 8025
#      and checks the 451 reply and the GREY tuple,
#   5. checks that a whitelist entry reaches the greyd-whitelist npf table
#      (npfctl table ... replace by the firewall process), that greylogd
#      whitelists the source of a SYN logged on npflog0, and that a
#      blacklist pushed by greyd-setup over the unix configuration socket
#      takes effect,
#   6. stops everything cleanly and restores npf.
#
# NPF cannot report a redirected connection's original destination, so
# the low priority MX trap is not exercised here (see greyd.conf(5)).
#
# Environment: GREYD_SRC, GREYD_BIN, GREYD_IT_WAIT (20), GREYD_IT_KEEP.
#
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${GREYD_SRC:-$(cd "$HERE/../.." && pwd)}
BIN=${GREYD_BIN:-$SRC/bin}
WAIT=${GREYD_IT_WAIT:-20}
KEEP=${GREYD_IT_KEEP:-0}

ETC=/etc/greyd
DB=/var/db/greyd
RUNDIR=/var/run/greyd
LOGDIR=/var/log/greyd
CHROOT=/var/empty
CONF=$ETC/greyd.conf
NPFCONF=$ETC/npf.conf
SOCK=$RUNDIR/config.sock
LOG=$LOGDIR/greyd.log
LISTDIR=$ETC/lists

SMTP_PORT=8025
LOGGED_SRC=127.0.0.6
LOGGED_DST=127.0.0.7
WHITELIST_TABLE=greyd-whitelist
TRAP_TABLE=greyd-greytrap
PRELOAD_WHITE=10.99.0.1

GREYD_PID=
GREYLOGD_PID=
ALIASES=
NPF_WAS_ACTIVE=0
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
    say "--- npfctl show ---";     npfctl show 2>&1 || true
    say "--- npfctl table $WHITELIST_TABLE list ---"; npfctl table "$WHITELIST_TABLE" list 2>&1 || true
    say "--- npfctl stats ---";    npfctl stats 2>&1 | head -40 || true
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
    return 0
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
    npfctl flush >/dev/null 2>&1 || true
    if [ "$NPF_WAS_ACTIVE" -eq 0 ]; then
        npfctl stop >/dev/null 2>&1 || true
    elif [ -f /etc/npf.conf ]; then
        npfctl reload /etc/npf.conf >/dev/null 2>&1 || true
    fi
    for a in $ALIASES; do ifconfig lo0 inet "$a" delete 2>/dev/null || true; done
    rm -f "$SOCK" "$RUNDIR/greyd.pid" "$RUNDIR/greylogd.pid"
    exit "$rc"
}
trap cleanup EXIT

# --- 1. environment ----------------------------------------------------------

step "environment"
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ "$(uname -s)" = NetBSD ] || die "this script is for NetBSD (got $(uname -s))"
command -v go >/dev/null 2>&1 || die "go not on PATH"
command -v nc >/dev/null 2>&1 || die "nc not available"
command -v npfctl >/dev/null 2>&1 || die "npfctl not available"
if ! kldstat -q -m npf 2>/dev/null && ! modstat 2>/dev/null | grep -q '^npf '; then
    modload npf 2>/dev/null || true
fi
[ -c /dev/npf ] || die "/dev/npf missing (npf module not loaded?)"
ifconfig npflog0 >/dev/null 2>&1 || ifconfig npflog0 create
npfctl stats >/dev/null 2>&1 || die "npfctl cannot talk to the kernel"
if npfctl show 2>/dev/null | grep -q 'filtering:.*active'; then NPF_WAS_ACTIVE=1; fi
pass "NetBSD $(uname -r) with $(go version | cut -d' ' -f3), npf and npflog0 present"

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
"$BIN/greyd" --drivers | grep -q npf || die "npf firewall driver not compiled in"
"$BIN/greyd" --drivers | grep -q sqlite || die "sqlite database driver not compiled in"
pass "programs present with npf and sqlite drivers"

# --- 3. users, directories, configuration ------------------------------------

step "users, directories and configuration"
for u in greyd greydb; do
    getent group "$u" >/dev/null 2>&1 || groupadd "$u"
    if ! id "$u" >/dev/null 2>&1; then
        shell=/sbin/nologin
        [ "$u" = greydb ] && shell=/bin/sh
        useradd -d /var/empty -s "$shell" -g "$u" -c "greyd $u" "$u"
    fi
done
mkdir -p "$ETC" "$RUNDIR" "$LOGDIR" "$CHROOT" "$LISTDIR"
chmod 0755 "$ETC" "$RUNDIR" "$LOGDIR"
mkdir -p "$DB"
chown greydb:greydb "$DB"
chmod 0700 "$DB"
rm -f "$LOG" "$LOGDIR"/*.stderr "$LOGDIR"/smtp.out "$DB"/greyd.sqlite* "$SOCK"
for a in $LOGGED_SRC $LOGGED_DST; do
    if ! ifconfig lo0 | grep -q "inet $a[ /]"; then
        ifconfig lo0 inet "$a" netmask 255.255.255.255 alias
        ALIASES="$ALIASES $a"
    fi
done
printf '127.0.0.0/8\n' >"$LISTDIR/local.txt"

cat >"$CONF" <<EOF
#
# greyd NetBSD integration test configuration (generated).
#
hostname       = "it.example.test"
daemonize      = 0
debug          = 1
syslog_enable  = 0
log_to_file    = "$LOG"
user           = "greyd"
drop_privs     = 1
chroot         = 1
chroot_dir     = "$CHROOT"
setrlimit      = 0
sandbox        = 1
bind_address   = "127.0.0.1"
port           = $SMTP_PORT
config_socket  = "$SOCK"
greyd_pidfile  = "$RUNDIR/greyd.pid"
greylogd_pidfile = "$RUNDIR/greylogd.pid"
stutter        = 0

section firewall {
    driver         = "npf"
    npflog_if      = "npflog0"
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
    traplist_name    = "$TRAP_TABLE"
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

# --- 4. npf ------------------------------------------------------------------

step "npf tables and log rule"
cat >"$NPFCONF" <<EOF
# greyd smoke test ruleset (generated by run-netbsd.sh).
table <$WHITELIST_TABLE> type ipset
table <$TRAP_TABLE> type ipset

procedure "log" {
	log: npflog0
}

group default {
	# New connections to port 25 are logged for greylogd.
	pass in final proto tcp flags S/SA to any port 25 apply "log"
	pass final all
}
EOF
npfctl validate "$NPFCONF" || die "npf.conf does not validate"
npfctl reload "$NPFCONF" || die "npfctl reload failed"
npfctl start >/dev/null 2>&1 || true
npfctl show | grep -q "$WHITELIST_TABLE" || die "table $WHITELIST_TABLE not loaded"
pass "npf active with tables $WHITELIST_TABLE, $TRAP_TABLE and a log rule"

# --- 5. whitelist entry ------------------------------------------------------

step "pre-load whitelist entry with greydb"
run_greydb -a "$PRELOAD_WHITE" || die "greydb -a $PRELOAD_WHITE failed"
db_has "^WHITE|$PRELOAD_WHITE|" || die "greydb did not record WHITE entry for $PRELOAD_WHITE"
pass "WHITE|$PRELOAD_WHITE stored in the sqlite database"

# --- 6. greyd ----------------------------------------------------------------

step "start greyd -F (firewall process keeps root for npfctl)"
"$BIN/greyd" -F -f "$CONF" >"$LOGDIR/greyd.stderr" 2>&1 &
GREYD_PID=$!
wait_for "greyd listening" log_has "listening for incoming connections" \
    || die "greyd did not start listening (alive: $(is_alive "$GREYD_PID" && echo yes || echo no))"
is_alive "$GREYD_PID" || die "greyd exited right after start"
[ -S "$SOCK" ] || die "configuration socket $SOCK was not created"
log_has "firewall process keeps them" || die "the firewall process did not report keeping its privileges"
ps -axo pid,user,command | grep '[g]reyd'
pass "greyd is up with its firewall and greylister processes"

# --- 7. SMTP dialogue ---------------------------------------------------------

step "greylisted SMTP dialogue via 127.0.0.1:$SMTP_PORT"
smtp_dialogue 127.0.0.1 "$SMTP_PORT" it.example.test
grep -q '^220' "$LOGDIR/smtp.out" || die "no banner from greyd"
grep -q '^451' "$LOGDIR/smtp.out" || die "greyd did not reply 451"
wait_for "GREY tuple in database" db_has "^GREY|127.0.0.1|it.example.test|sender@example.test|rcpt@example.test|" \
    || die "GREY tuple not recorded"
pass "451 reply and GREY|127.0.0.1|... recorded"

# --- 8. whitelist reaches the npf table --------------------------------------

step "whitelist entry reaches npf table $WHITELIST_TABLE"
wait_for "$PRELOAD_WHITE in npf table" sh -c "npfctl table $WHITELIST_TABLE list | grep -q '$PRELOAD_WHITE'" \
    || die "npf table $WHITELIST_TABLE does not list $PRELOAD_WHITE"
pass "npfctl table $WHITELIST_TABLE list shows $PRELOAD_WHITE (replaced by the firewall process)"

# --- 9. greylogd -------------------------------------------------------------

step "greylogd whitelists the source of a SYN logged on npflog0"
"$BIN/greylogd" -f "$CONF" >"$LOGDIR/greylogd.stderr" 2>&1 &
GREYLOGD_PID=$!
wait_for "greylogd pidfile" test -s "$RUNDIR/greylogd.pid" || die "greylogd did not write its pidfile"
wait_for "greylogd listening" log_has "listening direction" || die "greylogd did not start"
nc -w 1 -s "$LOGGED_SRC" "$LOGGED_DST" 25 </dev/null >/dev/null 2>&1 || true
wait_for "WHITE|$LOGGED_SRC" db_has "^WHITE|$LOGGED_SRC|" || die "greylogd did not whitelist $LOGGED_SRC"
pass "greylogd whitelisted $LOGGED_SRC seen on npflog0"

# --- 10. blacklist via greyd-setup -------------------------------------------

step "greyd-setup pushes a blacklist over the unix configuration socket"
"$BIN/greyd-setup" -f "$CONF" -d || die "greyd-setup failed"
wait_for "blacklist loaded" log_has "loaded blacklist" || die "greyd did not report the blacklist"
smtp_dialogue 127.0.0.1 "$SMTP_PORT" bl.example.test >/dev/null
grep -q "integration test list" "$LOGDIR/smtp.out" || die "blacklist message not returned: $(cat "$LOGDIR/smtp.out")"
pass "450 reply with the blacklist message"

# --- 11. shutdown ---------------------------------------------------------------

step "clean shutdown"
stop_pid "$GREYLOGD_PID"
kill -TERM "$GREYD_PID"
i=0; while is_alive "$GREYD_PID" && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
is_alive "$GREYD_PID" && die "greyd did not exit on SIGTERM"
wait "$GREYD_PID" 2>/dev/null && rc=0 || rc=$?
[ "$rc" -eq 0 ] || die "greyd exited with status $rc"
pass "greyd exited 0"

say ""
say "ALL PASS ($STEP steps)"
