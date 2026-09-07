#!/usr/bin/env bash
#
# Shared setup and helpers of the Linux integration harnesses
# (run-linux.sh, soak.sh). Sourced, not executed: the caller sets
# HERE (its own directory), then calls it_setup_env, it_check_environment
# and so on in order. Everything here runs as root inside a privileged
# container or on a throw-away Linux host.
#
# Environment (all optional):
#   GREYD_SRC       repository root (default: two levels above HERE)
#   GREYD_BIN       directory holding the programs (default: $GREYD_SRC/bin,
#                   built with "go build" when missing)
#   GREYD_IT_WAIT   seconds to poll for each asynchronous assertion (20)
#   GREYD_IT_KEEP   set to 1 to leave daemons, rules, sets and files in place
#   GREYD_IT_DROP_PRIVS
#                   drop_privs value written to greyd.conf (1). 0 keeps every
#                   process root; only for isolating failures of the
#                   privilege drop itself from the rest of the flow.
#

# --- constants ---------------------------------------------------------------

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
PIDFILE=$CHROOT/greyd.pid
BLACKLIST_FILE=$ETC/integration-blacklist.txt

SMTP_PORT=8025
DNAT_PORT=2525
IN_GROUP=155
OUT_GROUP=255
WHITELIST_SET=greyd-whitelist
BLACKLIST_SET=greyd-blacklist

PRELOAD_WHITE=10.99.0.1   # whitelisted with greydb before greyd starts
LOW_PRIO_MX=127.0.0.2     # pre-DNAT destination that traps first-time senders
TRAP_SRC=127.0.0.9        # client that connects to the low priority MX
NFLOG_SRC=127.0.0.6       # client of the outbound port 25 SYN
NFLOG_DST=127.0.0.5       # destination of the outbound port 25 SYN
LOW_PRIO_GRACE=60         # grey.LowPrioGrace: the trap is armed this long after start
SCAN_INTERVAL=60          # grey.ScanInterval: the greylister scans the database this often
PASS_TIME=600             # grey.pass_time of the main configuration

# Chains of our own so that teardown never touches foreign rules.
NAT_CHAIN=GREYD_IT_NAT
OUT_CHAIN=GREYD_IT_OUT
IN_CHAIN=GREYD_IT_IN

GREYD_PID=
GREYLOGD_PID=
GREYD_START=0
GREYD_CONF=$CONF          # configuration the running greyd was started with
FW_PID=                   # firewall child of the running greyd
GREY_PID=                 # greylister child of the running greyd
STATUS=1
STEP=0
BACKGROUND_PIDS=          # helper processes killed at exit

if [ "$DROP_PRIVS" = 1 ]; then
    MAIN_USER=greyd; GREY_USER=greydb
else
    MAIN_USER=root; GREY_USER=root
fi

# --- output helpers ----------------------------------------------------------

say()  { printf '%s\n' "$*"; }
step() { STEP=$((STEP + 1)); say ""; say "=== step $STEP: $*"; }
pass() { say "PASS: $*"; }
warn() { say "WARN: $*"; }

die() {
    say "FAIL: $*" >&2
    dump_state
    exit 1
}

dump_state() {
    say ""
    say "--- diagnostics ---"
    say "greyd pid $GREYD_PID alive: $(is_alive "$GREYD_PID" && echo yes || echo no) (conf $GREYD_CONF)"
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
    if grep -qs 'greylister failed err="open .*: timeout"' "$LOG"; then
        say "HINT: the greylister could not open its second handle on the database within the driver's lock"
        say "      timeout. bbolt takes an exclusive flock() per open, and runGreyChild opens the store twice"
        say "      (reader and scanner) in the same process; with driver = \"bolt\" the second Open times out."
    fi
    say "--- database files ---";  ls -la "$LIB" 2>&1 || true
    for f in "$LIB"/*.sqlite; do
        [ -f "$f" ] && python3 - "$f" <<'PYEOF' 2>&1 || true
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
print("journal_mode", c.execute("pragma journal_mode").fetchone()[0],
      "entries", c.execute("select count(*) from entries").fetchone()[0],
      "integrity", c.execute("pragma integrity_check").fetchone()[0])
PYEOF
    done
    say "--- greydb ---";               run_greydb 2>&1 | head -n 60 || true
    say "--- iptables -S ---";          iptables -S 2>&1 || true
    say "--- iptables -t nat -S ---";   iptables -t nat -S 2>&1 || true
    say "--- ipset list -t ---";        ipset list -t 2>&1 || true
    say "--- conntrack -L ---";         conntrack -L 2>&1 | head -n 50 || true
    say "--- processes ---";            ps -eo pid,ppid,user,args 2>/dev/null | grep -E 'grey(d|logd)' | grep -v grep || true
}

# --- generic helpers ---------------------------------------------------------

is_alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

# Float arithmetic without bc: fmath "expression".
fmath() { awk "BEGIN { printf \"%.3f\", $1 }"; }
now_f() { printf '%s' "$EPOCHREALTIME"; }
elapsed_since() { fmath "$(now_f) - $1"; }
# float_lt A B: true when A < B.
float_lt() { awk "BEGIN { exit !($1 < $2) }"; }

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

# run_as USER COMMAND...
run_as() {
    local u=$1; shift
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$u" -- "$@"
    else
        local cmd
        printf -v cmd '%q ' "$@"
        su -s /bin/sh "$u" -c "$cmd"
    fi
}

# The database directory belongs to the grey user; greydb must run as that
# user or it would leave root-owned files the greylister cannot open.
# run_greydb [ARGS...] uses the configuration of the running greyd
# ($GREYD_CONF); run_greydb_conf CONF [ARGS...] names one explicitly.
run_greydb() { run_greydb_conf "$GREYD_CONF" "$@"; }
run_greydb_conf() {
    local conf=$1; shift
    run_as greydb "$BIN/greydb" -f "$conf" "$@"
}

db_has() { run_greydb 2>/dev/null | grep -q -- "$1"; }
# db_count PATTERN: number of matching greydb lines (0 when greydb fails).
db_count() { run_greydb 2>/dev/null | grep -c -- "$1" || true; }
db_count_at_least() { [ "$(db_count "$1")" -ge "$2" ]; }

# smtp SRC DST PORT EXPECT [EXPECT_TEXT] [HELO]
smtp() {
    local src=$1 dst=$2 port=$3 expect=$4 text=${5:-} helo=${6:-}
    set -- --dst "$dst" --port "$port" --expect "$expect" --timeout 30
    [ -n "$src" ] && set -- "$@" --src "$src"
    [ -n "$text" ] && set -- "$@" --expect-text "$text"
    [ -n "$helo" ] && set -- "$@" --helo "$helo" --mail-from "$helo@example.test"
    python3 "$HERE/smtpcheck.py" "$@"
}

smtp_quiet() { smtp "$@" 2>/dev/null; }

log_has() { grep -q -- "$1" "$LOG" 2>/dev/null; }
# log_has_since MARK PATTERN: PATTERN appears after the first MARK lines.
log_has_since() { tail -n +"$(($1 + 1))" "$LOG" 2>/dev/null | grep -q -- "$2"; }
LOG_MARK=0

stats() { "$BIN/greyd" --stats -f "$GREYD_CONF" 2>/dev/null; }
# stat_value NAME: one counter of greyd --stats (empty when unavailable).
stat_value() { stats | awk -v n="$1" '$1 == n { print $2 }'; }
stat_at_least() { local v; v=$(stat_value "$1"); [ -n "$v" ] && [ "$v" -ge "$2" ]; }

# ipset_entries SET: the "Number of entries" of a set (0 when missing).
ipset_entries() { ipset list "$1" -t 2>/dev/null | awk '/^Number of entries:/ { n = $4 } END { print n + 0 }'; }
ipset_entries_at_least() { [ "$(ipset_entries "$1")" -ge "$2" ]; }

# proc_field PID FIELD: a /proc/PID/status field, tabs collapsed to spaces.
proc_field() { awk -v f="$2:" '$1 == f { $1 = ""; sub(/^ +/, ""); print }' "/proc/$1/status" 2>/dev/null; }
proc_rss_kb() { awk '$1 == "VmRSS:" { print $2 }' "/proc/$1/status" 2>/dev/null; }
proc_fds() { ls "/proc/$1/fd" 2>/dev/null | wc -l; }
# proc_role PID: GREYD_ROLE of a re-exec'd child (fw, grey) or empty.
proc_role() { tr '\0' '\n' <"/proc/$1/environ" 2>/dev/null | sed -n 's/^GREYD_ROLE=//p'; }

# find_children: sets FW_PID and GREY_PID from the children of $GREYD_PID.
find_children() {
    FW_PID=; GREY_PID=
    local p
    for p in $(pgrep -P "$GREYD_PID" 2>/dev/null); do
        case "$(proc_role "$p")" in
            fw)   FW_PID=$p ;;
            grey) GREY_PID=$p ;;
        esac
    done
    [ -n "$FW_PID" ] && [ -n "$GREY_PID" ]
}

greyd_processes() { ps -eo pid,user,args 2>/dev/null | grep -v grep | grep -- "$BIN/greyd " || true; }
no_greyd_processes() { [ -z "$(greyd_processes)" ]; }

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
    for s in "$WHITELIST_SET" "$WHITELIST_SET-ipv6" "$WHITELIST_SET-stage" "$WHITELIST_SET-ipv6-stage" "$BLACKLIST_SET" "$BLACKLIST_SET-stage"; do
        ipset destroy "$s" 2>/dev/null || true
    done
}

kill_background() {
    local p
    for p in $BACKGROUND_PIDS; do
        kill "$p" 2>/dev/null || true
    done
    BACKGROUND_PIDS=
}

cleanup() {
    local rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ] && [ "$STATUS" -ne 0 ]; then
        # An unexpected error (set -e) rather than a die: show the state.
        say "FAIL: aborted with status $rc at step $STEP" >&2
        dump_state
    fi
    kill_background
    if [ "$KEEP" = 1 ]; then
        say "GREYD_IT_KEEP=1: leaving daemons, rules and files in place"
        exit "$rc"
    fi
    stop_daemon "$GREYLOGD_PID" greylogd
    stop_daemon "$GREYD_PID" greyd
    pkill -x greyd 2>/dev/null || true
    remove_rules
    rm -f "$SOCK" "$RUN/greylogd.pid" "$PIDFILE"
    exit "$rc"
}

it_setup_env() {
    set -euo pipefail
    trap cleanup EXIT
}

# --- environment, programs, users, configuration -----------------------------

it_check_environment() {
    [ "$(id -u)" -eq 0 ] || die "must run as root (use docker run --privileged)"

    local missing= t
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
}

it_check_programs() {
    local p
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
    "$BIN/greyd" --drivers | grep -q bolt || die "bolt database driver not compiled in"
}

# Users, directories and a clean slate. The pidfile directory (which is
# also the chroot) belongs to the greyd user like the package's
# postinstall makes it, so the chrooted main process can unlink its pidfile
# at exit; the database directory belongs to greydb.
it_setup_users_dirs() {
    local u
    for u in greyd greydb; do
        getent group "$u" >/dev/null || groupadd -r "$u"
        id "$u" >/dev/null 2>&1 || useradd -r -g "$u" -d /var/empty -s /usr/sbin/nologin "$u"
    done
    install -d -m 0755 "$ETC" "$RUN" "$LOGDIR" /var/empty
    install -d -m 0750 -o greyd -g greyd "$CHROOT"
    install -d -m 0700 -o greydb -g greydb "$LIB"
    rm -f "$LOG" "$LOGDIR"/*.stderr "$LIB"/greyd.sqlite* "$LIB"/greyd.db* "$SOCK" "$PIDFILE"
    remove_rules
}

# write_config FILE [name=value ...]: the harness configuration. Knobs:
#   driver=sqlite|bolt  db_name=FILE  pass_time=SECS  log_to_file=PATH|none
#   lists=NAME  list_file=PATH  list_message=TEXT
write_config() {
    local file=$1; shift
    local driver=sqlite db_name=greyd.sqlite pass_time=$PASS_TIME log_to_file=$LOG
    local lists=integration list_file=$BLACKLIST_FILE list_message="Your address %A is in the integration test list"
    local kv
    for kv in "$@"; do
        case "$kv" in
            driver=*)       driver=${kv#*=} ;;
            db_name=*)      db_name=${kv#*=} ;;
            pass_time=*)    pass_time=${kv#*=} ;;
            log_to_file=*)  log_to_file=${kv#*=} ;;
            lists=*)        lists=${kv#*=} ;;
            list_file=*)    list_file=${kv#*=} ;;
            list_message=*) list_message=${kv#*=} ;;
            *) die "write_config: unknown knob $kv" ;;
        esac
    done
    local logline="log_to_file = \"$log_to_file\""
    [ "$log_to_file" = none ] && logline="# logging to stderr only"

    cat >"$file" <<EOF
#
# greyd integration harness configuration (generated by lib.sh).
#
debug = 1
verbose = 1
daemonize = 0
syslog_enable = 0
$logline

user = "greyd"
drop_privs = $DROP_PRIVS
chroot = 1
chroot_dir = "$CHROOT"
sandbox = 1

hostname = "greyd-integration"
bind_address = "127.0.0.1"
port = $SMTP_PORT
config_socket = "$SOCK"
greyd_pidfile = "$PIDFILE"
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
    driver  = "$driver"
    path    = "$LIB"
    db_name = "$db_name"
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
    pass_time           = $pass_time
}

# SPF lookups would need DNS and could trap the test sender.
section spf {
    enable = 0
}

section sync {
    enable = 0
}

section setup {
    lists = [ "$lists" ]
}

blacklist $lists {
    message = "$list_message"
    method  = "file"
    file    = "$list_file"
}
EOF
    chmod 0644 "$file"
}

# --- firewall rules ----------------------------------------------------------

it_install_rules() {
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
}

# --- daemons -----------------------------------------------------------------

# start_greyd [CONF]: starts greyd -F in the background, waits until it
# listens and both children are up; sets GREYD_PID, FW_PID, GREY_PID.
start_greyd() {
    GREYD_CONF=${1:-$CONF}
    "$BIN/greyd" -F -f "$GREYD_CONF" >>"$LOGDIR/greyd.stderr" 2>&1 &
    GREYD_PID=$!
    GREYD_START=$SECONDS
    LOG_MARK=$(grep -c "" "$LOG" 2>/dev/null || echo 0)
    wait_for "greyd listening" log_has_since "$LOG_MARK" "listening for incoming connections" \
        || die "greyd did not start listening (pid $GREYD_PID alive: $(is_alive "$GREYD_PID" && echo yes || echo no))"
    is_alive "$GREYD_PID" || die "greyd exited right after start"
    [ -S "$SOCK" ] || die "configuration socket $SOCK was not created"
    wait_for "fw and grey children" find_children || die "greyd did not start both the firewall and the greylister child"
    [ "$(ps -o user= -p "$FW_PID" | tr -d ' ')" = "$MAIN_USER" ] || die "firewall child $FW_PID is not running as $MAIN_USER"
    [ "$(ps -o user= -p "$GREY_PID" | tr -d ' ')" = "$GREY_USER" ] || die "greylister child $GREY_PID is not running as $GREY_USER"
    [ "$(ps -o user= -p "$GREYD_PID" | tr -d ' ')" = "$MAIN_USER" ] || die "main process $GREYD_PID is not running as $MAIN_USER"
}

# stop_greyd: SIGTERM, waits and returns greyd's exit status in GREYD_RC.
GREYD_RC=
stop_greyd() {
    GREYD_RC=
    if [ -z "$GREYD_PID" ]; then
        return 0
    fi
    kill -TERM "$GREYD_PID" 2>/dev/null || true
    set +e
    wait "$GREYD_PID"; GREYD_RC=$?
    set -e
    GREYD_PID=; FW_PID=; GREY_PID=
    wait_for "greyd processes gone" no_greyd_processes || die "greyd child processes survived the parent"
}

start_greylogd() {
    local conf=${1:-$GREYD_CONF}
    "$BIN/greylogd" -f "$conf" >>"$LOGDIR/greylogd.stderr" 2>&1 &
    GREYLOGD_PID=$!
    wait_for "greylogd pidfile" test -s "$RUN/greylogd.pid" || die "greylogd did not write its pidfile"
    sleep 1
    is_alive "$GREYLOGD_PID" || die "greylogd exited right after start"
    [ "$(ps -o user= -p "$GREYLOGD_PID" | tr -d ' ')" = "$GREY_USER" ] || die "greylogd is not running as $GREY_USER"
}

GREYLOGD_RC=
stop_greylogd() {
    GREYLOGD_RC=
    [ -n "$GREYLOGD_PID" ] || return 0
    kill -TERM "$GREYLOGD_PID" 2>/dev/null || true
    set +e
    wait "$GREYLOGD_PID"; GREYLOGD_RC=$?
    set -e
    GREYLOGD_PID=
}

# --- shared steps ------------------------------------------------------------

# it_audit_process NAME PID USER CAPEFF ROOT: asserts the credentials,
# no_new_privs, seccomp filter mode, effective capabilities and root of a
# process. CAPEFF is the expected hex mask; ROOT may be empty (not checked).
it_audit_process() {
    local name=$1 pid=$2 user=$3 want_cap=$4 want_root=$5
    local uid gid want_uid want_gid nnp seccomp cap root
    is_alive "$pid" || die "$name (pid $pid) is not running"
    want_uid=$(id -u "$user"); want_gid=$(id -g "$user")
    uid=$(proc_field "$pid" Uid); gid=$(proc_field "$pid" Gid)
    nnp=$(proc_field "$pid" NoNewPrivs); seccomp=$(proc_field "$pid" Seccomp); cap=$(proc_field "$pid" CapEff)
    root=$(readlink "/proc/$pid/root" 2>/dev/null || true)
    say "$name pid=$pid uid=[$uid] gid=[$gid] NoNewPrivs=$nnp Seccomp=$seccomp CapEff=$cap root=$root"
    [ "$uid" = "$want_uid $want_uid $want_uid $want_uid" ] || die "$name: Uid is '$uid', expected all four = $want_uid ($user)"
    [ "$gid" = "$want_gid $want_gid $want_gid $want_gid" ] || die "$name: Gid is '$gid', expected all four = $want_gid ($user)"
    [ "$nnp" = 1 ] || die "$name: NoNewPrivs is '$nnp', expected 1"
    [ "$seccomp" = 2 ] || die "$name: Seccomp is '$seccomp', expected 2 (filter mode)"
    [ $((16#$cap)) -eq $((16#$want_cap)) ] || die "$name: CapEff is 0x$cap, expected 0x$want_cap"
    if [ -n "$want_root" ]; then
        [ "$root" = "$want_root" ] || die "$name: root is '$root', expected $want_root"
    fi
}
