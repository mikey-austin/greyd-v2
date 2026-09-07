#!/usr/bin/env bash
#
# greyd Linux integration harness: netfilter firewall driver end to end.
#
# Runs as root inside a privileged container (or on a throw-away Linux
# host) and exercises the real daemons with privilege separation, chroot
# and the sandbox enabled:
#
#   1. builds (or reuses) the programs, creates the greyd/greydb users and
#      writes a greyd.conf using the netfilter and sqlite drivers,
#   2. installs iptables rules: a DNAT of loopback port 2525 to greyd's
#      8025 (exercises the conntrack original-destination lookup) and
#      NFLOG rules for new connections to port 25 in both directions
#      (exercises greylogd's inbound and outbound groups),
#   3. pre-loads a whitelist entry with greydb, starts greyd -F and
#      greylogd, and checks:
#        - an SMTP dialogue through the DNAT'd port is greylisted (451)
#          and recorded as a GREY tuple,
#        - the whitelist reached the greyd-whitelist ipset,
#        - an outbound SYN to port 25 whitelists both the destination
#          (outbound group) and the source (inbound group) through greylogd,
#        - after the low-priority MX grace period a connection whose
#          pre-DNAT destination is low_prio_mx is trapped: the conntrack
#          lookup returned the original destination,
#        - the trapped address is rejected with the traplist message,
#        - a blacklist pushed with greyd-setup over the unix configuration
#          socket is applied: the next connection gets the 450 message,
#        - both daemons stop cleanly on SIGTERM,
#   4. tears down the rules and ipsets; logs are dumped on failure.
#
# Environment:
#   GREYD_SRC       repository root (default: two levels above this script)
#   GREYD_BIN       directory holding the programs (default: $GREYD_SRC/bin,
#                   built with "go build" when missing)
#   GREYD_IT_WAIT   seconds to poll for each asynchronous assertion (20)
#   GREYD_IT_KEEP   set to 1 to leave rules, sets and files in place
#   GREYD_IT_DROP_PRIVS
#                   drop_privs value written to greyd.conf (1). 0 keeps every
#                   process root; only for isolating failures of the
#                   privilege drop itself from the rest of the flow.
#
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${GREYD_SRC:-$(cd "$HERE/../.." && pwd)}
BIN=${GREYD_BIN:-$SRC/bin}
WAIT=${GREYD_IT_WAIT:-20}
KEEP=${GREYD_IT_KEEP:-0}
DROP_PRIVS=${GREYD_IT_DROP_PRIVS:-1}

ETC=/etc/greyd
RUN=/run/greyd
LIB=/var/lib/greyd
LOGDIR=/var/log/greyd
CHROOT=/var/empty/greyd
CONF=$ETC/greyd.conf
SOCK=$RUN/config.sock
LOG=$LOGDIR/greyd.log
BLACKLIST_FILE=$ETC/integration-blacklist.txt

SMTP_PORT=8025
DNAT_PORT=2525
IN_GROUP=155
OUT_GROUP=255
WHITELIST_SET=greyd-whitelist

PRELOAD_WHITE=10.99.0.1   # whitelisted with greydb before greyd starts
LOW_PRIO_MX=127.0.0.2     # pre-DNAT destination that traps first-time senders
TRAP_SRC=127.0.0.9        # client that connects to the low priority MX
NFLOG_SRC=127.0.0.6       # client of the outbound port 25 SYN
NFLOG_DST=127.0.0.5       # destination of the outbound port 25 SYN
LOW_PRIO_GRACE=60         # grey.LowPrioGrace: the trap is armed this long after start

# Chains of our own so that teardown never touches foreign rules.
NAT_CHAIN=GREYD_IT_NAT
OUT_CHAIN=GREYD_IT_OUT
IN_CHAIN=GREYD_IT_IN

GREYD_PID=
GREYLOGD_PID=
GREYD_START=0
STATUS=1
STEP=0

# --- helpers -----------------------------------------------------------------

say()  { printf '%s\n' "$*"; }
step() { STEP=$((STEP + 1)); say ""; say "=== step $STEP: $*"; }
pass() { say "PASS: $*"; }

die() {
    say "FAIL: $*" >&2
    dump_state
    exit 1
}

dump_state() {
    say ""
    say "--- diagnostics ---"
    say "greyd pid $GREYD_PID alive: $(is_alive "$GREYD_PID" && echo yes || echo no)"
    say "greylogd pid $GREYLOGD_PID alive: $(is_alive "$GREYLOGD_PID" && echo yes || echo no)"
    say "--- $LOG (tail) ---";          tail -n 200 "$LOG" 2>/dev/null || true
    # Panics print their reason first, so show the head as well as the tail.
    say "--- greyd stderr (head) ---";  head -n 40 "$LOGDIR/greyd.stderr" 2>/dev/null || true
    say "--- greyd stderr (tail) ---";  tail -n 20 "$LOGDIR/greyd.stderr" 2>/dev/null || true
    say "--- greylogd stderr (head) ---"; head -n 40 "$LOGDIR/greylogd.stderr" 2>/dev/null || true
    if grep -qs "AllThreadsSyscall6 results differ between threads" "$LOGDIR/greyd.stderr" "$LOGDIR/greylogd.stderr"; then
        say "HINT: a capset() succeeded on one thread and failed (EPERM) on the others. PR_SET_KEEPCAPS is"
        say "      per-thread, so only the thread that called prctl in netfilter.Open keeps CAP_NET_ADMIN across"
        say "      the all-threads setuid; the all-threads capset in raiseCaps then disagrees between threads."
        say "      Re-run with GREYD_IT_DROP_PRIVS=0 to exercise the rest of the flow."
    fi
    say "--- greydb ---";               run_greydb 2>&1 || true
    say "--- iptables -S ---";          iptables -S 2>&1 || true
    say "--- iptables -t nat -S ---";   iptables -t nat -S 2>&1 || true
    say "--- ipset list ---";           ipset list 2>&1 || true
    say "--- conntrack -L ---";         conntrack -L 2>&1 | head -n 50 || true
    say "--- processes ---";            ps -eo pid,user,args 2>/dev/null | grep -E 'grey(d|logd)' | grep -v grep || true
}

is_alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

# wait_for DESCRIPTION COMMAND...: polls every $WAIT_STEP seconds until
# COMMAND succeeds or $WAIT seconds pass. Both may be overridden per call
# (WAIT=70 wait_for ...).
WAIT_STEP=0.5
wait_for() {
    local what=$1; shift
    local deadline=$((SECONDS + WAIT))
    while ! "$@" >/dev/null 2>&1; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            say "timed out after ${WAIT}s waiting for: $what" >&2
            return 1
        fi
        sleep "$WAIT_STEP"
    done
    return 0
}

# The database directory belongs to the grey user; greydb must run as that
# user or it would leave root-owned files the greylister cannot open.
run_greydb() {
    if command -v runuser >/dev/null 2>&1; then
        runuser -u greydb -- "$BIN/greydb" -f "$CONF" "$@"
    else
        su -s /bin/sh greydb -c "\"$BIN/greydb\" -f \"$CONF\" $*"
    fi
}

db_has() { run_greydb 2>/dev/null | grep -q -- "$1"; }

# smtp SRC DST PORT EXPECT [EXPECT_TEXT]
smtp() {
    local src=$1 dst=$2 port=$3 expect=$4 text=${5:-}
    set -- --dst "$dst" --port "$port" --expect "$expect" --timeout 30
    [ -n "$src" ] && set -- "$@" --src "$src"
    [ -n "$text" ] && set -- "$@" --expect-text "$text"
    python3 "$HERE/smtpcheck.py" "$@"
}

smtp_quiet() { smtp "$@" 2>/dev/null; }

log_has() { grep -q -- "$1" "$LOG" 2>/dev/null; }

# --- teardown ----------------------------------------------------------------

stop_daemon() {
    local pid=$1 name=$2
    if is_alive "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        local deadline=$((SECONDS + 10))
        while is_alive "$pid" && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.2; done
        if is_alive "$pid"; then
            say "$name did not stop on SIGTERM, killing" >&2
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
}

remove_rules() {
    iptables -t nat -D OUTPUT -o lo -j "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true
    iptables -D OUTPUT -o lo -j "$OUT_CHAIN" 2>/dev/null || true
    iptables -F "$OUT_CHAIN" 2>/dev/null || true
    iptables -X "$OUT_CHAIN" 2>/dev/null || true
    iptables -D INPUT -i lo -j "$IN_CHAIN" 2>/dev/null || true
    iptables -F "$IN_CHAIN" 2>/dev/null || true
    iptables -X "$IN_CHAIN" 2>/dev/null || true
    for s in "$WHITELIST_SET" "$WHITELIST_SET-ipv6" "$WHITELIST_SET-stage" "$WHITELIST_SET-ipv6-stage" greyd-blacklist greyd-blacklist-stage; do
        ipset destroy "$s" 2>/dev/null || true
    done
}

cleanup() {
    local rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ] && [ "$STATUS" -ne 0 ]; then
        # An unexpected error (set -e) rather than a die: show the state.
        say "FAIL: aborted with status $rc at step $STEP" >&2
        dump_state
    fi
    if [ "$KEEP" = 1 ]; then
        say "GREYD_IT_KEEP=1: leaving daemons, rules and files in place"
        exit "$rc"
    fi
    stop_daemon "$GREYLOGD_PID" greylogd
    stop_daemon "$GREYD_PID" greyd
    remove_rules
    rm -f "$SOCK" "$RUN/greylogd.pid" "$CHROOT/greyd.pid"
    exit "$rc"
}
trap cleanup EXIT

# --- 1. environment ----------------------------------------------------------

step "environment"
[ "$(id -u)" -eq 0 ] || die "must run as root (use docker run --privileged)"

missing=
for t in iptables ipset conntrack python3; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
if [ -n "$missing" ]; then
    if command -v apt-get >/dev/null 2>&1; then
        say "installing:$missing"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends iptables ipset conntrack python3 iproute2 procps >/dev/null
    else
        die "missing tools:$missing"
    fi
fi

# Debian's iptables defaults to the nf_tables backend; fall back to the
# legacy one when the kernel does not offer nf_tables inside this namespace.
if ! iptables -t nat -L -n >/dev/null 2>&1; then
    if command -v update-alternatives >/dev/null 2>&1 && [ -x /usr/sbin/iptables-legacy ]; then
        say "nf_tables backend unusable, switching to iptables-legacy"
        update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null
    fi
    iptables -t nat -L -n >/dev/null 2>&1 || die "iptables nat table not usable (missing CAP_NET_ADMIN?)"
fi
ipset list -n >/dev/null 2>&1 || die "ipset not usable (missing CAP_NET_ADMIN?)"
pass "root with iptables, ipset, conntrack and python3 available"

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
"$BIN/greyd" --drivers | grep -q netfilter || die "netfilter firewall driver not compiled in"
"$BIN/greyd" --drivers | grep -q sqlite || die "sqlite database driver not compiled in"
pass "programs present with netfilter and sqlite drivers"

# --- 3. users, directories, configuration ------------------------------------

step "users, directories and configuration"
for u in greyd greydb; do
    getent group "$u" >/dev/null || groupadd -r "$u"
    id "$u" >/dev/null 2>&1 || useradd -r -g "$u" -d /var/empty -s /usr/sbin/nologin "$u"
done
install -d -m 0755 "$ETC" "$RUN" "$LOGDIR" "$CHROOT" /var/empty
install -d -m 0700 -o greydb -g greydb "$LIB"
rm -f "$LOG" "$LOGDIR"/*.stderr "$LIB"/greyd.sqlite* "$SOCK"
remove_rules

cat >"$CONF" <<EOF
#
# greyd integration harness configuration (generated by run-linux.sh).
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

hostname = "greyd-integration"
bind_address = "127.0.0.1"
port = $SMTP_PORT
config_socket = "$SOCK"
greyd_pidfile = "$CHROOT/greyd.pid"
greylogd_pidfile = "$RUN/greylogd.pid"

# No tarpitting: the harness reads whole dialogues.
stutter = 0
banner = "greyd integration harness"
error_code = "450"

section firewall {
    driver         = "netfilter"
    track_outbound = 1
    inbound_group  = $IN_GROUP
    outbound_group = $OUT_GROUP
}

section database {
    driver  = "sqlite"
    path    = "$LIB"
    db_name = "greyd.sqlite"
}

section grey {
    enable              = 1
    user                = "greydb"
    traplist_name       = "greyd-greytrap"
    traplist_message    = "Your address %A has mailed to spamtraps here"
    whitelist_name      = "$WHITELIST_SET"
    whitelist_name_ipv6 = "$WHITELIST_SET-ipv6"
    low_prio_mx         = "$LOW_PRIO_MX"
    stutter             = 0
    pass_time           = 600
}

# SPF lookups would need DNS and could trap the test sender.
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
    file    = "$BLACKLIST_FILE"
}
EOF
chmod 0644 "$CONF"
"$BIN/greyd" -t -f "$CONF" | tee "$LOGDIR/greyd-t.out"
grep -q "configuration OK" "$LOGDIR/greyd-t.out" || die "greyd -t did not accept the configuration"
pass "configuration accepted by greyd -t"

# --- 4. firewall rules -------------------------------------------------------

step "iptables rules"
iptables -t nat -N "$NAT_CHAIN"
iptables -t nat -A OUTPUT -o lo -j "$NAT_CHAIN"
# Locally generated connections to loopback port 2525 land on greyd; the
# fw process must recover the original destination from conntrack.
iptables -t nat -A "$NAT_CHAIN" -p tcp --dport "$DNAT_PORT" -j DNAT --to-destination "127.0.0.1:$SMTP_PORT"

iptables -N "$OUT_CHAIN"
iptables -A OUTPUT -o lo -j "$OUT_CHAIN"
# Outbound SMTP: greylogd whitelists the destination (outbound group).
iptables -A "$OUT_CHAIN" -p tcp --dport 25 -m conntrack --ctstate NEW -j NFLOG --nflog-group "$OUT_GROUP"

iptables -N "$IN_CHAIN"
iptables -A INPUT -i lo -j "$IN_CHAIN"
# Inbound SMTP: greylogd whitelists the source (inbound group). Production
# rules sit in PREROUTING behind a greyd-whitelist match; loopback traffic
# only traverses INPUT.
iptables -A "$IN_CHAIN" -p tcp --dport 25 -m conntrack --ctstate NEW -j NFLOG --nflog-group "$IN_GROUP"
iptables -t nat -S "$NAT_CHAIN"
iptables -S "$OUT_CHAIN" "$IN_CHAIN" 2>/dev/null || { iptables -S "$OUT_CHAIN"; iptables -S "$IN_CHAIN"; }
pass "DNAT $DNAT_PORT->$SMTP_PORT and NFLOG groups $IN_GROUP/$OUT_GROUP installed"

# --- 5. pre-load a whitelist entry -------------------------------------------

step "pre-load whitelist entry with greydb"
run_greydb -a "$PRELOAD_WHITE"
db_has "^WHITE|$PRELOAD_WHITE|" || die "greydb did not record WHITE entry for $PRELOAD_WHITE"
[ "$(stat -c %U "$LIB/greyd.sqlite")" = greydb ] || die "database file is not owned by greydb"
pass "WHITE|$PRELOAD_WHITE stored in the sqlite database owned by greydb"

# --- 6. start greyd ----------------------------------------------------------

step "start greyd -F"
"$BIN/greyd" -F -f "$CONF" >"$LOGDIR/greyd.stderr" 2>&1 &
GREYD_PID=$!
GREYD_START=$SECONDS
wait_for "greyd listening" log_has "listening for incoming connections" \
    || die "greyd did not start listening (pid $GREYD_PID alive: $(is_alive "$GREYD_PID" && echo yes || echo no))"
is_alive "$GREYD_PID" || die "greyd exited right after start"
[ -S "$SOCK" ] || die "configuration socket $SOCK was not created"
# The three processes of the privilege separation.
if [ "$DROP_PRIVS" = 1 ]; then
    MAIN_USER=greyd; GREY_USER=greydb
else
    MAIN_USER=root; GREY_USER=root
fi
wait_for "fw and grey children" bash -c "[ \$(ps -eo user,args | grep -v grep | grep -c '^$GREY_USER .*$BIN/greyd ') -ge 1 ] && [ \$(ps -eo user,args | grep -v grep | grep -c '^$MAIN_USER .*$BIN/greyd ') -ge 2 ]" \
    || die "expected the main and firewall processes as $MAIN_USER and the greylister as $GREY_USER"
ps -eo pid,user,args | grep -E '[g]reyd' || true
pass "greyd is up: main + firewall processes as $MAIN_USER, greylister as $GREY_USER, config socket $SOCK"

# --- 7. start greylogd -------------------------------------------------------

step "start greylogd"
"$BIN/greylogd" -f "$CONF" >"$LOGDIR/greylogd.stderr" 2>&1 &
GREYLOGD_PID=$!
wait_for "greylogd pidfile" test -s "$RUN/greylogd.pid" || die "greylogd did not write its pidfile"
sleep 1
is_alive "$GREYLOGD_PID" || die "greylogd exited right after start"
[ "$(ps -o user= -p "$GREYLOGD_PID" | tr -d ' ')" = "$GREY_USER" ] || die "greylogd is not running as $GREY_USER"
pass "greylogd running as $GREY_USER, NFLOG groups bound"

# --- 8. greylisting through the DNAT'd port ----------------------------------

step "greylisted SMTP dialogue via 127.0.0.1:$DNAT_PORT (DNAT to $SMTP_PORT)"
smtp 127.0.0.1 127.0.0.1 "$DNAT_PORT" 451 "Temporary failure" || die "expected a 451 greylist reply"
wait_for "GREY tuple in database" db_has "^GREY|127.0.0.1|it.example.test|sender@example.test|rcpt@example.test|" \
    || die "GREY entry for 127.0.0.1 tuple not found in greydb output"
if log_has "original destination lookup failed" || log_has "nat lookup failed" || log_has "conntrack lookup"; then
    die "the firewall process reported an original destination lookup failure"
fi
conntrack -L 2>/dev/null | grep -q "dport=$DNAT_PORT" || die "no conntrack entry for the DNAT'd connection"
pass "451 reply, GREY|127.0.0.1|... recorded, conntrack shows the DNAT'd flow and no lookup failures were logged"

# --- 9. whitelist pushed to ipset by the greylister scanner ------------------

step "whitelist entry reaches ipset $WHITELIST_SET"
wait_for "$PRELOAD_WHITE in ipset" ipset test "$WHITELIST_SET" "$PRELOAD_WHITE" \
    || die "$PRELOAD_WHITE not in ipset $WHITELIST_SET"
ipset list "$WHITELIST_SET" | sed -n '1,12p'
pass "ipset $WHITELIST_SET contains $PRELOAD_WHITE (pushed by the greylister through the firewall process)"

# --- 10. greylogd via NFLOG --------------------------------------------------

step "greylogd whitelists addresses seen by NFLOG"
# A SYN from $NFLOG_SRC to $NFLOG_DST:25 (nothing listens; the SYN is what
# matters) traverses OUTPUT (group $OUT_GROUP) and INPUT (group $IN_GROUP).
python3 - "$NFLOG_SRC" "$NFLOG_DST" <<'EOF' || true
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.bind((sys.argv[1], 0))
try:
    s.connect((sys.argv[2], 25))
except OSError as e:
    print("connect to port 25 (expected to be refused): %s" % e)
s.close()
EOF
wait_for "WHITE|$NFLOG_DST (outbound group)" db_has "^WHITE|$NFLOG_DST|" \
    || die "greylogd did not whitelist the outbound destination $NFLOG_DST"
wait_for "WHITE|$NFLOG_SRC (inbound group)" db_has "^WHITE|$NFLOG_SRC|" \
    || die "greylogd did not whitelist the inbound source $NFLOG_SRC"
pass "greylogd whitelisted $NFLOG_DST (outbound group $OUT_GROUP) and $NFLOG_SRC (inbound group $IN_GROUP)"

# --- 11. after the low priority MX grace period -----------------------------

step "wait for the low priority MX grace period (${LOW_PRIO_GRACE}s after start)"
remaining=$((GREYD_START + LOW_PRIO_GRACE + 5 - SECONDS))
if [ "$remaining" -gt 0 ]; then
    say "sleeping ${remaining}s"
    sleep "$remaining"
fi
is_alive "$GREYD_PID" || die "greyd died while waiting"
is_alive "$GREYLOGD_PID" || die "greylogd died while waiting"

step "second scanner pass pushes greylogd's whitelist entries to ipset"
wait_for "$NFLOG_DST in ipset" ipset test "$WHITELIST_SET" "$NFLOG_DST" \
    || die "$NFLOG_DST not in ipset $WHITELIST_SET after the second scan"
ipset test "$WHITELIST_SET" "$NFLOG_SRC" >/dev/null 2>&1 || die "$NFLOG_SRC not in ipset $WHITELIST_SET after the second scan"
pass "ipset $WHITELIST_SET now also contains $NFLOG_DST and $NFLOG_SRC"

step "conntrack original destination: connection to low_prio_mx $LOW_PRIO_MX:$DNAT_PORT is trapped"
# The client connects to 127.0.0.2:2525; DNAT rewrites that to
# 127.0.0.1:8025. Only a successful conntrack lookup hands the greylister
# dst_ip = 127.0.0.2 = low_prio_mx, which traps a first-time sender.
smtp "$TRAP_SRC" "$LOW_PRIO_MX" "$DNAT_PORT" 451 || die "expected a 451 reply for the first connection from $TRAP_SRC"
wait_for "TRAPPED|$TRAP_SRC" db_has "^TRAPPED|$TRAP_SRC|" \
    || die "$TRAP_SRC was not trapped: the pre-DNAT destination did not reach the greylister"
pass "TRAPPED|$TRAP_SRC recorded: the firewall process resolved the pre-DNAT destination $LOW_PRIO_MX"

step "trapped address gets the traplist rejection (after the next scanner pass)"
# The greylister hands its traplist to greyd on every scan, so this can
# take up to one scan interval (grey.ScanInterval, 60s); poll slowly to
# keep the log readable.
WAIT=$((LOW_PRIO_GRACE + 15)) WAIT_STEP=3 wait_for "450 traplist reply" smtp_quiet "$TRAP_SRC" 127.0.0.1 "$DNAT_PORT" 450 "has mailed to spamtraps here" \
    || die "$TRAP_SRC did not receive the greyd-greytrap message within a scan interval"
smtp "$TRAP_SRC" 127.0.0.1 "$DNAT_PORT" 450 "Your address $TRAP_SRC has mailed to spamtraps here" \
    || die "traplist message did not expand %A to $TRAP_SRC"
pass "450 'Your address $TRAP_SRC has mailed to spamtraps here' (traplist sent by the greylister scan to greyd)"

# --- 12. blacklist via greyd-setup and the unix configuration socket ---------

step "push a blacklist with greyd-setup over $SOCK"
printf '# integration harness blacklist\n127.0.0.0/8\n' >"$BLACKLIST_FILE"
"$BIN/greyd-setup" -d -f "$CONF" 2>&1 | tee "$LOGDIR/greyd-setup.out"
WAIT_STEP=2 wait_for "450 blacklist reply" smtp_quiet 127.0.0.1 127.0.0.1 "$DNAT_PORT" 450 "integration test list" \
    || die "127.0.0.1 was not rejected with the pushed blacklist"
smtp 127.0.0.1 127.0.0.1 "$DNAT_PORT" 450 "Your address 127.0.0.1 is in the integration test list" \
    || die "blacklist message did not expand %A to 127.0.0.1"
pass "blacklist 127.0.0.0/8 applied: 450 'Your address 127.0.0.1 is in the integration test list'"

# --- 13. clean shutdown ------------------------------------------------------

step "clean shutdown on SIGTERM"
kill -TERM "$GREYLOGD_PID"
set +e
wait "$GREYLOGD_PID"; rc_logd=$?
set -e
[ "$rc_logd" -eq 0 ] || die "greylogd exited with status $rc_logd"
kill -TERM "$GREYD_PID"
set +e
wait "$GREYD_PID"; rc_greyd=$?
set -e
[ "$rc_greyd" -eq 0 ] || die "greyd exited with status $rc_greyd"
wait_for "child processes gone" bash -c "! ps -eo args | grep -v grep | grep -q '^$BIN/greyd '" \
    || die "greyd child processes survived the parent"
GREYD_PID=; GREYLOGD_PID=
pass "greyd and greylogd exited 0 and left no child processes"

say ""
say "ALL PASS ($STEP steps)"
STATUS=0
exit 0
