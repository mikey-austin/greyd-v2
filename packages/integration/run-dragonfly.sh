#!/bin/sh
#
# greyd DragonFly BSD smoke test: pf firewall driver, bolt database (the
# embedded SQLite has no DragonFly port).
#
# Run as root on an OpenBSD host or VM with Go on the PATH (the CI job
# runs it through vmactions/openbsd-vm, see .github/workflows/integration.yml):
#
#   sh packages/integration/run-dragonfly.sh
#
# What it does:
#   1. builds the programs (unless $GREYD_BIN already holds them),
#   2. creates the greyd and greydb users and a greyd.conf using the pf
#      driver, bolt under /var/greyd, chroot and drop_privs (there is no
#      sandbox on DragonFly, so sandbox = 1 is a no-op),
#   3. loads a minimal pf.conf defining the greyd-whitelist and
#      greyd-greytrap tables with an rdr-to of loopback port 2525 to
#      greyd's 8025 (exercises DIOCNATLOOK),
#   4. whitelists an address with greydb, starts greyd -F and checks:
#        - the SMTP dialogue through the redirected port ends in 451,
#        - greyd (all three processes) is still alive afterwards,
#        - the whitelist reached the pf table (pfctl -t greyd-whitelist -T show),
#        - greyd stops cleanly on SIGTERM,
#   5. restores the previous pf state and removes the test files.
#
# Environment:
#   GREYD_SRC          repository root (default: two levels above this script)
#   GREYD_BIN          directory holding the programs (default: $GREYD_SRC/bin)
#   GREYD_IT_WAIT      seconds to poll for asynchronous assertions (20)
#   GREYD_IT_DROP_PRIVS  drop_privs value written to greyd.conf (1)
#   GREYD_IT_KEEP      set to 1 to leave greyd, pf rules and files in place
#
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${GREYD_SRC:-$(cd "$HERE/../.." && pwd)}
BIN=${GREYD_BIN:-$SRC/bin}
WAIT=${GREYD_IT_WAIT:-20}
DROP_PRIVS=${GREYD_IT_DROP_PRIVS:-1}
KEEP=${GREYD_IT_KEEP:-0}

ETC=/etc/greyd
DB=/var/greyd
RUNDIR=/var/run/greyd
LOGDIR=/var/log/greyd
CHROOT=/var/empty
CONF=$ETC/greyd.conf
PFCONF=$ETC/pf.conf
SOCK=$RUNDIR/config.sock
LOG=$LOGDIR/greyd.log

SMTP_PORT=8025
RDR_PORT=2525
WHITELIST_TABLE=greyd-whitelist
TRAP_TABLE=greyd-greytrap
PRELOAD_WHITE=10.99.0.1

GREYD_PID=
PF_WAS_ENABLED=0
STEP=0
STATUS=1

say()  { printf '%s\n' "$*"; }
step() { STEP=$((STEP + 1)); say ""; say "=== step $STEP: $*"; }
pass() { say "PASS: $*"; }

is_alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

dump_state() {
    say ""
    say "--- diagnostics ---"
    say "greyd pid $GREYD_PID alive: $(is_alive "$GREYD_PID" && echo yes || echo no)"
    say "--- $LOG (tail) ---";      tail -n 200 "$LOG" 2>/dev/null || true
    say "--- greyd stderr ---";     tail -n 50 "$LOGDIR/greyd.stderr" 2>/dev/null || true
    say "--- greydb ---";           run_greydb 2>&1 || true
    say "--- pfctl -sr ---";        pfctl -sr 2>&1 || true
    say "--- pfctl -s Tables ---";  pfctl -s Tables 2>&1 || true
    say "--- pfctl -t $WHITELIST_TABLE -T show ---"; pfctl -t "$WHITELIST_TABLE" -T show 2>&1 || true
    say "--- processes ---";        ps -axo pid,user,command | grep '[g]reyd' || true
    say "--- dmesg (tail) ---";     dmesg | tail -n 20 2>/dev/null || true
}

die() {
    say "FAIL: $*" >&2
    dump_state
    exit 1
}

# wait_for DESCRIPTION COMMAND...: polls until COMMAND succeeds or $WAIT
# seconds pass.
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

# greydb runs as the greydb user so that the database files stay writable
# by the greylister (the test user is given /bin/sh as its shell for this).
run_greydb() { su greydb -c "\"$BIN/greydb\" -f \"$CONF\" $*"; }

db_has() { run_greydb 2>/dev/null | grep -q -- "$1"; }

log_has() { grep -q -- "$1" "$LOG" 2>/dev/null; }

# smtp_dialogue PORT: runs the SMTP dialogue with nc, prints the transcript
# and leaves it in $LOGDIR/smtp.out.
smtp_dialogue() {
    port=$1
    {
        sleep 1; printf 'EHLO it.example.test\r\n'
        sleep 1; printf 'MAIL FROM:<sender@example.test>\r\n'
        sleep 1; printf 'RCPT TO:<rcpt@example.test>\r\n'
        sleep 1; printf 'DATA\r\n'
        sleep 2; printf 'Subject: greyd\r\n\r\ntest\r\n.\r\n'
        sleep 2; printf 'QUIT\r\n'
        sleep 1
    } | nc -w 20 127.0.0.1 "$port" | tee "$LOGDIR/smtp.out"
}

cleanup() {
    rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ] && [ "$STATUS" -ne 0 ]; then
        say "FAIL: aborted with status $rc at step $STEP" >&2
        dump_state
    fi
    if [ "$KEEP" = 1 ]; then
        say "GREYD_IT_KEEP=1: leaving greyd, pf rules and files in place"
        exit "$rc"
    fi
    if is_alive "$GREYD_PID"; then
        kill -TERM "$GREYD_PID" 2>/dev/null || true
        i=0
        while is_alive "$GREYD_PID" && [ "$i" -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
        is_alive "$GREYD_PID" && kill -KILL "$GREYD_PID" 2>/dev/null
    fi
    pfctl -t "$WHITELIST_TABLE" -T kill >/dev/null 2>&1 || true
    pfctl -t "$TRAP_TABLE" -T kill >/dev/null 2>&1 || true
    if [ -f /etc/pf.conf ]; then
        pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
    fi
    if [ "$PF_WAS_ENABLED" -eq 0 ]; then
        pfctl -d >/dev/null 2>&1 || true
    fi
    rm -f "$SOCK" "$CHROOT/greyd.pid"
    exit "$rc"
}
trap cleanup EXIT

# --- 1. environment ----------------------------------------------------------

step "environment"
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ "$(uname -s)" = DragonFly ] || die "this script is for DragonFly BSD (got $(uname -s))"
command -v go >/dev/null 2>&1 || die "go not on PATH"
command -v nc >/dev/null 2>&1 || die "nc not available"
[ -c /dev/pf ] || die "/dev/pf missing"
go version
pass "DragonFly $(uname -r) with $(go version | cut -d' ' -f3), pf device present"

# --- 2. programs -------------------------------------------------------------

step "programs"
if [ ! -x "$BIN/greyd" ] || [ ! -x "$BIN/greydb" ] || [ ! -x "$BIN/greyd-setup" ] || [ ! -x "$BIN/greylogd" ]; then
    say "building into $BIN"
    mkdir -p "$BIN"
    for p in greyd greydb greyd-setup greylogd; do
        (cd "$SRC" && CGO_ENABLED=0 "${GREYD_GO:-go}" build -trimpath -o "$BIN/$p" "./cmd/$p")
    done
fi
"$BIN/greyd" --version
"$BIN/greyd" --drivers | grep -q pf || die "pf firewall driver not compiled in"
"$BIN/greyd" --drivers | grep -q bolt || die "bolt database driver not compiled in"
pass "programs present with pf and bolt drivers"

# --- 3. users, directories, configuration ------------------------------------

step "users, directories and configuration"
for u in greyd greydb; do
    pw groupshow "$u" >/dev/null 2>&1 || pw groupadd "$u"
    if ! pw usershow "$u" >/dev/null 2>&1; then
        shell=/sbin/nologin
        [ "$u" = greydb ] && shell=/bin/sh
        pw useradd "$u" -d /var/empty -s "$shell" -g "$u" -c "greyd $u"
    fi
done
mkdir -p "$ETC" "$RUNDIR" "$LOGDIR" "$CHROOT"
chmod 0755 "$ETC" "$RUNDIR" "$LOGDIR"
mkdir -p "$DB"
chown greydb:greydb "$DB"
chmod 0700 "$DB"
rm -f "$LOG" "$LOGDIR"/*.stderr "$LOGDIR"/smtp.out "$DB"/greyd.db* "$SOCK"

cat >"$CONF" <<EOF
#
# greyd OpenBSD smoke test configuration (generated by run-dragonfly.sh).
#
debug = 1
verbose = 1
daemonize = 0
syslog_enable = 0
log_to_file = "$LOG"

user = "greyd"
drop_privs = $DROP_PRIVS
chroot = 1
chroot_dir = "$CHROOT"
sandbox = 1

hostname = "greyd-openbsd"
bind_address = "127.0.0.1"
port = $SMTP_PORT
config_socket = "$SOCK"
greyd_pidfile = "$CHROOT/greyd.pid"
greylogd_pidfile = "$RUNDIR/greylogd.pid"

stutter = 0
banner = "greyd openbsd smoke test"
error_code = "450"

section firewall {
    driver     = "pf"
    pfdev_path = "/dev/pf"
    pfctl_path = "/sbin/pfctl"
    pflog_if   = "pflog0"
}

section database {
    driver  = "bolt"
    path    = "$DB"
    db_name = "greyd.db"
}

section grey {
    enable         = 1
    user           = "greydb"
    traplist_name  = "$TRAP_TABLE"
    whitelist_name = "$WHITELIST_TABLE"
    stutter        = 0
    pass_time      = 600
}

section spf {
    enable = 0
}

section sync {
    enable = 0
}

section setup {
    lists = [ "integration" ]
}

blacklist integration {
    message = "Your address %A is in the integration test list"
    method  = "file"
    file    = "$ETC/integration-blacklist.txt"
}
EOF
chmod 0644 "$CONF"
"$BIN/greyd" -t -f "$CONF" | tee "$LOGDIR/greyd-t.out"
grep -q "configuration OK" "$LOGDIR/greyd-t.out" || die "greyd -t did not accept the configuration"
pass "configuration accepted by greyd -t"

# --- 4. pf -------------------------------------------------------------------

step "pf tables and rdr-to rule"
if pfctl -si 2>/dev/null | grep -q '^Status: Enabled'; then PF_WAS_ENABLED=1; fi
cat >"$PFCONF" <<EOF
# greyd smoke test ruleset (generated by run-dragonfly.sh).
table <$WHITELIST_TABLE> persist
table <$TRAP_TABLE> persist
# Loopback connections to port $RDR_PORT are redirected to greyd; the fw
# process recovers the original destination with DIOCNATLOOK. DragonFly's
# pf keeps the pre-4.7 OpenBSD grammar with a separate rdr rule.
rdr pass on lo0 proto tcp from any to any port $RDR_PORT -> 127.0.0.1 port $SMTP_PORT
pass
EOF
pfctl -nf "$PFCONF" || die "pf.conf does not parse"
pfctl -e >/dev/null 2>&1 || true
pfctl -f "$PFCONF"
pfctl -s Tables | grep -q "^$WHITELIST_TABLE\$" || die "table $WHITELIST_TABLE not defined"
pfctl -s Tables | grep -q "^$TRAP_TABLE\$" || die "table $TRAP_TABLE not defined"
pfctl -sr
pass "pf enabled with tables $WHITELIST_TABLE, $TRAP_TABLE and rdr-to $RDR_PORT->$SMTP_PORT"

# --- 5. whitelist entry ------------------------------------------------------

step "pre-load whitelist entry with greydb"
run_greydb -a "$PRELOAD_WHITE"
db_has "^WHITE|$PRELOAD_WHITE|" || die "greydb did not record WHITE entry for $PRELOAD_WHITE"
pass "WHITE|$PRELOAD_WHITE stored in the bolt database"

# --- 6. greyd ----------------------------------------------------------------

step "start greyd -F"
"$BIN/greyd" -F -f "$CONF" >"$LOGDIR/greyd.stderr" 2>&1 &
GREYD_PID=$!
wait_for "greyd listening" log_has "listening for incoming connections" \
    || die "greyd did not start listening (alive: $(is_alive "$GREYD_PID" && echo yes || echo no))"
is_alive "$GREYD_PID" || die "greyd exited right after start"
[ -S "$SOCK" ] || die "configuration socket $SOCK was not created"
wait_for "three greyd processes" sh -c "[ \$(ps -axo command | grep -c '^$BIN/greyd ') -ge 3 ]" \
    || die "expected the main, firewall and greylister processes"
ps -axo pid,user,command | grep '[g]reyd'
pass "greyd is up with its firewall and greylister processes"

# --- 7. SMTP dialogue through the redirect ----------------------------------

step "greylisted SMTP dialogue via 127.0.0.1:$RDR_PORT (rdr-to $SMTP_PORT)"
smtp_dialogue "$RDR_PORT"
grep -q '^220 ' "$LOGDIR/smtp.out" || die "no 220 banner received"
grep -q '^451 ' "$LOGDIR/smtp.out" || die "no 451 greylist reply received"
wait_for "GREY tuple in database" db_has "^GREY|127.0.0.1|it.example.test|sender@example.test|rcpt@example.test|" \
    || die "GREY entry for the 127.0.0.1 tuple not found in greydb output"
pass "451 reply and GREY|127.0.0.1|... recorded"

step "greyd survived the dialogue"
sleep 1
is_alive "$GREYD_PID" || die "greyd main process died"
n=$(ps -axo command | grep -c "^$BIN/greyd ")
[ "$n" -ge 3 ] || die "expected 3 greyd processes, found $n"
if log_has "child process exited"; then
    die "greyd logged a child exit"
fi
pass "all three processes alive"

# --- 8. pf table -------------------------------------------------------------

step "whitelist entry reaches pf table $WHITELIST_TABLE"
wait_for "$PRELOAD_WHITE in table" sh -c "pfctl -t $WHITELIST_TABLE -T show | grep -q '$PRELOAD_WHITE'" \
    || die "$PRELOAD_WHITE not in pf table $WHITELIST_TABLE (pfctl replace by the firewall process failed?)"
pfctl -t "$WHITELIST_TABLE" -T show
pass "pfctl -t $WHITELIST_TABLE -T show lists $PRELOAD_WHITE"

# --- 9. shutdown -------------------------------------------------------------

step "clean shutdown on SIGTERM"
kill -TERM "$GREYD_PID"
set +e
wait "$GREYD_PID"; rc_greyd=$?
set -e
[ "$rc_greyd" -eq 0 ] || die "greyd exited with status $rc_greyd"
wait_for "child processes gone" sh -c "! ps -axo command | grep -q '^$BIN/greyd '" \
    || die "greyd child processes survived the parent"
GREYD_PID=
pass "greyd exited 0 and left no child processes"

say ""
say "ALL PASS ($STEP steps)"
STATUS=0
exit 0
