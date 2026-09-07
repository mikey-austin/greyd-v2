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
#        - every process runs with the expected uid/gid, no_new_privs,
#          seccomp filter, capabilities and root (privilege audit),
#        - greyd --sandbox-probe confirms what each role's sandbox denies,
#        - an SMTP dialogue through the DNAT'd port is greylisted (451)
#          and recorded as a GREY tuple,
#        - the whitelist reached the greyd-whitelist ipset,
#        - an outbound SYN to port 25 whitelists both the destination
#          (outbound group) and the source (inbound group) through greylogd,
#        - 100 concurrent greylisted dialogues meet the latency SLO and
#          all reach the database,
#        - after the low-priority MX grace period a connection whose
#          pre-DNAT destination is low_prio_mx is trapped: the conntrack
#          lookup returned the original destination,
#        - the trapped address is rejected with the traplist message,
#        - a blacklist pushed with greyd-setup over the unix configuration
#          socket is applied: the next connection gets the 450 message,
#        - a 100,000 entry blacklist reaches the greyd-blacklist ipset in
#          time and 20,000 greydb whitelist entries reach greyd-whitelist,
#        - killing either child makes the parent exit cleanly,
#        - greylist state survives a restart (sqlite and bolt),
#        - both daemons stop cleanly on SIGTERM,
#   4. tears down the rules and ipsets; logs are dumped on failure.
#
# Environment: see lib.sh (GREYD_SRC, GREYD_BIN, GREYD_IT_WAIT,
# GREYD_IT_KEEP, GREYD_IT_DROP_PRIVS) plus
#   GREYD_IT_LOAD_COUNT   concurrent dialogues of the SLO step (100)
#   GREYD_IT_BLACK_COUNT  blacklist entries of the large set step (100000)
#   GREYD_IT_WHITE_COUNT  greydb whitelist entries of the large set step (20000)
#
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"
it_setup_env

LOAD_COUNT=${GREYD_IT_LOAD_COUNT:-100}
BLACK_COUNT=${GREYD_IT_BLACK_COUNT:-100000}
WHITE_COUNT=${GREYD_IT_WHITE_COUNT:-20000}
RESTART_PASS_TIME=10      # grey.pass_time of the restart steps
RESTART_SRC=127.0.0.11    # client of the restart steps (a fresh address)
SLO_P99=3                 # seconds
SLO_DB_WINDOW=10          # seconds for all tuples to reach the database
BIG_BLACKLIST_FILE=$ETC/big-blacklist.txt
BIG_CONF=$ETC/big.conf
PROBE_CONF=$ETC/probe.conf
RESTART_CONF=$ETC/restart-sqlite.conf
BOLT_CONF=$ETC/restart-bolt.conf

# --- step functions used more than once -------------------------------------

# probe_role ROLE USER: runs greyd --sandbox-probe as USER and asserts the
# expected verdicts (name=denied|ok) given as the remaining arguments.
# tcp-bind and udp-bind are informational: Landlock lets Go's net.Listen
# bind on some kernels, and UDP is unrestricted.
probe_role() {
    local role=$1 user=$2; shift 2
    local out=$LOGDIR/probe-$role.out rc=0 want name value got line
    run_as "$user" "$BIN/greyd" --sandbox-probe "$role" -f "$PROBE_CONF" >"$out" 2>"$out.err" || rc=$?
    if [ "$rc" -ne 0 ]; then
        cat "$out" "$out.err"
        die "greyd --sandbox-probe $role (as $user) exited $rc"
    fi
    line=$(grep -E '^(tcp-bind|udp-bind)=' "$out" | tr '\n' ' ')
    say "$role (as $user): $(grep -c '=' "$out") probes; informational: $line"
    for want in "$@"; do
        name=${want%%=*}; value=${want#*=}
        got=$(sed -n "s/^$name=//p" "$out")
        if [ "$got" != "$value" ]; then
            say "--- full probe output ($role) ---"; cat "$out" "$out.err"
            die "sandbox probe $role: $name=$got, expected $value"
        fi
    done
}

# hold_connection SECS: keeps an SMTP connection open in the background
# (banner + EHLO, then idle) so that chaos happens with a client attached.
hold_connection() {
    python3 - "$1" "$DNAT_PORT" <<'EOF' &
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=10)
s.recv(1024)
s.sendall(b"EHLO slow.example.test\r\n")
s.recv(1024)
time.sleep(float(sys.argv[1]))
s.close()
EOF
    BACKGROUND_PIDS="$BACKGROUND_PIDS $!"
}

# chaos_kill ROLE: SIGKILLs a child while a connection is open and asserts
# the parent logs it, exits 0 within 5 seconds, removes its pidfile and
# leaves no greyd process behind. The configuration socket lives outside
# the chroot, so the main process cannot unlink it; that is reported.
chaos_kill() {
    local role=$1 victim t0 elapsed
    case "$role" in
        firewall)   victim=$FW_PID ;;
        greylister) victim=$GREY_PID ;;
    esac
    hold_connection 30
    WAIT=10 wait_for "an open connection" stat_at_least connections_current 1 \
        || die "the slow client did not register as an open connection"
    say "connections_current=$(stat_value connections_current); SIGKILL $role child $victim"
    t0=$(now_f)
    kill -KILL "$victim"
    set +e
    wait "$GREYD_PID"; GREYD_RC=$?
    set -e
    elapsed=$(elapsed_since "$t0")
    say "parent $GREYD_PID exited with status $GREYD_RC after ${elapsed}s"
    log_has "child process exited role=$role" || die "the parent did not log the $role child's exit"
    [ "$GREYD_RC" -eq 0 ] || die "parent exited with status $GREYD_RC after the $role child was killed"
    # The parent gives the surviving child five seconds to finish (a scan
    # in progress runs to the end of its transaction) before killing it.
    float_lt "$elapsed" 10 || die "parent took ${elapsed}s to exit, expected under 10s"
    [ ! -e "$PIDFILE" ] || die "pidfile $PIDFILE was not removed"
    GREYD_PID=; FW_PID=; GREY_PID=
    wait_for "no greyd processes" no_greyd_processes || die "greyd processes survived: $(greyd_processes)"
    if [ -e "$SOCK" ]; then
        warn "configuration socket $SOCK still exists: the chrooted main process cannot unlink it (greyd removes stale sockets at start)"
    fi
    kill_background
}

# retry_ok_count_at_least LOG N / retry_ok_after LOG EPOCH: progress of the
# retry loop of restart_persistence (one "ok EPOCH" line per 451).
retry_ok_count_at_least() { local n; n=$(grep -c '^ok' "$1" 2>/dev/null || true); [ "${n:-0}" -ge "$2" ]; }
retry_ok_after() { awk -v t="$2" '$1 == "ok" && $2 > t { f = 1 } END { exit !f }' "$1" 2>/dev/null; }

# restart_persistence CONF LABEL: with a greylisted tuple being retried in a
# loop, SIGTERMs and restarts greyd (running with CONF, pass_time
# $RESTART_PASS_TIME) and asserts the tuple survives with its counters
# intact and is whitelisted once retried after pass_time. greydb is only
# consulted while greyd is stopped (bolt holds an exclusive file lock).
# Ends with greyd stopped.
restart_persistence() {
    local conf=$1 label=$2 helo="restart-$2.example.test"
    local key="^GREY|$RESTART_SRC|$helo|$helo@example.test|rcpt@example.test|"
    local log=$LOGDIR/restart-$label.log flag=$LOGDIR/restart-$label.stop
    local entry first pass expire bcount first2 pass2 expire2 bcount2 loop_pid
    rm -f "$flag" "$log"

    # The retry loop; connection failures during the restarts are expected.
    (
        while [ ! -e "$flag" ]; do
            if smtp_quiet "$RESTART_SRC" 127.0.0.1 "$DNAT_PORT" 451 "" "$helo" >/dev/null 2>&1; then
                echo "ok $EPOCHSECONDS" >>"$log"
            else
                echo "fail $EPOCHSECONDS" >>"$log"
            fi
            sleep 0.5
        done
    ) &
    loop_pid=$!
    BACKGROUND_PIDS="$BACKGROUND_PIDS $loop_pid"
    WAIT=10 wait_for "two greylisted attempts" retry_ok_count_at_least "$log" 2 \
        || die "the retry loop got no 451 replies ($(tail -n 3 "$log" 2>/dev/null | tr '\n' ' '))"

    say "SIGTERM greyd $GREYD_PID mid-traffic ($(grep -c '^ok' "$log") attempts so far)"
    stop_greyd
    [ "$GREYD_RC" -eq 0 ] || die "greyd exited with status $GREYD_RC on SIGTERM"
    entry=$(run_greydb_conf "$conf" 2>/dev/null | grep -- "$key" || true)
    [ -n "$entry" ] || die "GREY tuple $key not in the $label database after the first stop"
    IFS='|' read -r _ _ _ _ _ first pass expire bcount _ <<<"$entry"
    say "before restart: $entry"
    [ "$pass" = "$expire" ] || die "tuple already marked for whitelisting before pass_time (pass=$pass expire=$expire)"

    start_greyd "$conf"
    say "greyd restarted as $GREYD_PID; waiting for a retry after pass_time (first=$first + ${RESTART_PASS_TIME}s)"
    WAIT=$((RESTART_PASS_TIME + 20)) wait_for "a 451 after pass_time" retry_ok_after "$log" $((first + RESTART_PASS_TIME + 1)) \
        || die "no greylisted retry happened after pass_time (loop log: $(tail -n 5 "$log" | tr '\n' ' '))"
    touch "$flag"
    wait "$loop_pid" 2>/dev/null || true
    say "retry loop: $(grep -c '^ok' "$log") x 451, $(grep -c '^fail' "$log") failed attempts (during the restart)"

    stop_greyd
    [ "$GREYD_RC" -eq 0 ] || die "greyd exited with status $GREYD_RC on the second SIGTERM"
    entry=$(run_greydb_conf "$conf" 2>/dev/null | grep -- "$key" || true)
    [ -n "$entry" ] || die "GREY tuple $key vanished across the restart"
    IFS='|' read -r _ _ _ _ _ first2 pass2 expire2 bcount2 _ <<<"$entry"
    say "after restart: $entry"
    [ "$first2" = "$first" ] || die "tuple was recreated: first changed $first -> $first2"
    [ "$bcount2" -gt "$bcount" ] || die "bcount did not grow across the restart ($bcount -> $bcount2)"
    [ "$pass2" -lt "$expire2" ] || die "retry after pass_time did not mark the tuple for whitelisting (pass=$pass2 expire=$expire2)"

    # The greylister's periodic scan re-keys the passed tuple as a WHITE
    # address entry. Poll while greyd runs (greydb reads retry on a busy
    # database) rather than assume the first scan finished within a fixed
    # sleep.
    start_greyd "$conf"
    white_present() { run_greydb_conf "$conf" 2>/dev/null | grep -q "^WHITE|$RESTART_SRC|"; }
    WAIT=$((RESTART_PASS_TIME + 20)) wait_for "WHITE|$RESTART_SRC from the scan" white_present         || die "WHITE|$RESTART_SRC not created by the scan after the restart"
    if run_greydb_conf "$conf" 2>/dev/null | grep -q -- "$key"; then
        stop_greyd
        die "GREY tuple still present after being whitelisted"
    fi
    stop_greyd
    [ "$GREYD_RC" -eq 0 ] || die "greyd exited with status $GREYD_RC on the third SIGTERM"
}

# --- 1. environment ----------------------------------------------------------

step "environment"
it_check_environment
pass "root with iptables, ipset, conntrack and python3 available"

# --- 2. programs -------------------------------------------------------------

step "programs"
it_check_programs
pass "programs present with netfilter, sqlite and bolt drivers"

# --- 3. users, directories, configuration ------------------------------------

step "users, directories and configuration"
it_setup_users_dirs
write_config "$CONF"
"$BIN/greyd" -t -f "$CONF" | tee "$LOGDIR/greyd-t.out"
grep -q "configuration OK" "$LOGDIR/greyd-t.out" || die "greyd -t did not accept the configuration"
pass "configuration accepted by greyd -t"

# --- 4. firewall rules -------------------------------------------------------

step "iptables rules"
it_install_rules
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
start_greyd "$CONF"
ps -eo pid,ppid,user,args | grep -E '[g]reyd' || true
pass "greyd is up: main $GREYD_PID + firewall $FW_PID as $MAIN_USER, greylister $GREY_PID as $GREY_USER, config socket $SOCK"

# --- 7. start greylogd -------------------------------------------------------

step "start greylogd"
start_greylogd
pass "greylogd running as $GREY_USER, NFLOG groups bound"

# --- 8. privilege audit ------------------------------------------------------

step "privilege audit (/proc/PID/status of all four processes)"
if [ "$DROP_PRIVS" = 1 ]; then
    # CAP_NET_ADMIN is bit 12 = 0x1000.
    it_audit_process "main"       "$GREYD_PID"    greyd  0    "$CHROOT"
    it_audit_process "firewall"   "$FW_PID"       greyd  1000 "$CHROOT"
    it_audit_process "greylister" "$GREY_PID"     greydb 0    ""
    it_audit_process "greylogd"   "$GREYLOGD_PID" greydb 1000 ""
    pass "uid/gid, NoNewPrivs=1, Seccomp=2, CapEff (0 / CAP_NET_ADMIN only) and chroot as expected"
else
    say "SKIP: GREYD_IT_DROP_PRIVS=0, every process is root"
fi

# --- 9. sandbox enforcement --------------------------------------------------

step "sandbox enforcement (greyd --sandbox-probe per role)"
# The probe logs to stderr: the harness log belongs to root and an
# unwritable log_to_file makes the probe fail.
write_config "$PROBE_CONF" log_to_file=none
CONFINED="read-etc-passwd=denied list-root=denied write-tmp=denied exec=denied tcp-connect=denied mount=denied chroot=denied setuid-root=denied init-module=denied"
# shellcheck disable=SC2086
probe_role main greyd $CONFINED
# shellcheck disable=SC2086
probe_role firewall greyd $CONFINED
probe_role grey greydb read-allowed=ok write-allowed=ok read-etc-passwd=ok \
    write-tmp=denied exec=denied tcp-connect=denied mount=denied chroot=denied setuid-root=denied init-module=denied
pass "main/firewall deny filesystem, exec, network, mount, chroot, setuid, init-module; grey reads /etc and writes $LIB only"

# --- 10. greylisting through the DNAT'd port ---------------------------------

step "greylisted SMTP dialogue via 127.0.0.1:$DNAT_PORT (DNAT to $SMTP_PORT)"
smtp 127.0.0.1 127.0.0.1 "$DNAT_PORT" 451 "Temporary failure" || die "expected a 451 greylist reply"
wait_for "GREY tuple in database" db_has "^GREY|127.0.0.1|it.example.test|sender@example.test|rcpt@example.test|" \
    || die "GREY entry for 127.0.0.1 tuple not found in greydb output"
if log_has "original destination lookup failed" || log_has "nat lookup failed" || log_has "conntrack lookup"; then
    die "the firewall process reported an original destination lookup failure"
fi
conntrack -L 2>/dev/null | grep -q "dport=$DNAT_PORT" || die "no conntrack entry for the DNAT'd connection"
pass "451 reply, GREY|127.0.0.1|... recorded, conntrack shows the DNAT'd flow and no lookup failures were logged"

# --- 11. whitelist pushed to ipset by the greylister scanner -----------------

step "whitelist entry reaches ipset $WHITELIST_SET"
wait_for "$PRELOAD_WHITE in ipset" ipset test "$WHITELIST_SET" "$PRELOAD_WHITE" \
    || die "$PRELOAD_WHITE not in ipset $WHITELIST_SET"
ipset list "$WHITELIST_SET" | sed -n '1,12p'
pass "ipset $WHITELIST_SET contains $PRELOAD_WHITE (pushed by the greylister through the firewall process)"

# --- 12. greylogd via NFLOG --------------------------------------------------

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

# --- 13. throughput and latency SLO ------------------------------------------

step "throughput and latency SLO: $LOAD_COUNT concurrent greylisted dialogues"
SLO_JSON=$LOGDIR/slo.json
python3 "$HERE/loadgen.py" --port "$DNAT_PORT" --count "$LOAD_COUNT" --concurrency "$LOAD_COUNT" \
    --prefix slo --timeout 30 --json "$SLO_JSON" 2>&1 | tee "$LOGDIR/loadgen-slo.out"
[ "${PIPESTATUS[0]}" -eq 0 ] || die "not every dialogue got a 451 (see above)"
read -r P50 P99 TPUT LAST_OK <<<"$(python3 -c '
import json, sys
s = json.load(open(sys.argv[1]))
print("%.3f %.3f %.1f %.3f" % (s["p50_seconds"], s["p99_seconds"], s["throughput_per_second"], s["last_ok_epoch"]))' "$SLO_JSON")"
float_lt "$P99" "$SLO_P99" || die "p99 time-to-451 is ${P99}s, SLO is under ${SLO_P99}s"
WAIT=$SLO_DB_WINDOW WAIT_STEP=0.2 wait_for "$LOAD_COUNT slo tuples in greydb" db_count_at_least "^GREY|127.0.0.1|slo-" "$LOAD_COUNT" \
    || die "only $(db_count '^GREY|127.0.0.1|slo-') of $LOAD_COUNT GREY tuples reached the database within ${SLO_DB_WINDOW}s"
INSERT_LAG=$(fmath "$(now_f) - $LAST_OK")
say "greylister insert lag (last 451 -> last tuple visible in greydb, includes 0.2s polling): ${INSERT_LAG}s"
pass "p50=${P50}s p99=${P99}s (SLO < ${SLO_P99}s) throughput=${TPUT}/s, all $LOAD_COUNT tuples stored, insert lag ${INSERT_LAG}s"

# --- 14. after the low priority MX grace period ------------------------------

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
WAIT=$((SCAN_INTERVAL + 15)) WAIT_STEP=3 wait_for "450 traplist reply" smtp_quiet "$TRAP_SRC" 127.0.0.1 "$DNAT_PORT" 450 "has mailed to spamtraps here" \
    || die "$TRAP_SRC did not receive the greyd-greytrap message within a scan interval"
smtp "$TRAP_SRC" 127.0.0.1 "$DNAT_PORT" 450 "Your address $TRAP_SRC has mailed to spamtraps here" \
    || die "traplist message did not expand %A to $TRAP_SRC"
pass "450 'Your address $TRAP_SRC has mailed to spamtraps here' (traplist sent by the greylister scan to greyd)"

# --- 18. blacklist via greyd-setup and the unix configuration socket ---------

step "push a blacklist with greyd-setup over $SOCK"
printf '# integration harness blacklist\n127.0.0.0/8\n' >"$BLACKLIST_FILE"
"$BIN/greyd-setup" -d -f "$CONF" 2>&1 | tee "$LOGDIR/greyd-setup.out"
WAIT_STEP=2 wait_for "450 blacklist reply" smtp_quiet 127.0.0.1 127.0.0.1 "$DNAT_PORT" 450 "integration test list" \
    || die "127.0.0.1 was not rejected with the pushed blacklist"
smtp 127.0.0.1 127.0.0.1 "$DNAT_PORT" 450 "Your address 127.0.0.1 is in the integration test list" \
    || die "blacklist message did not expand %A to 127.0.0.1"
pass "blacklist 127.0.0.0/8 applied: 450 'Your address 127.0.0.1 is in the integration test list'"

# --- 19. large firewall sets -------------------------------------------------

step "large firewall sets: $BLACK_COUNT blacklist entries via greyd-setup -b, $WHITE_COUNT whitelist entries via greydb"
# Half /24s, half /32s, none adjacent or nested (odd third/fourth octets),
# so the count after CIDR collapsing equals the number of lines; the
# expected count is nevertheless computed from the file.
python3 - "$BIG_BLACKLIST_FILE" "$BLACK_COUNT" <<'EOF'
import sys
path, n = sys.argv[1], int(sys.argv[2])
half = n // 2
with open(path, "w") as f:
    f.write("# integration harness large blacklist\n")
    for i in range(half):
        r = i % 32768
        f.write("%d.%d.%d.0/24\n" % (10 + i // 32768, r // 128, (r % 128) * 2 + 1))
    for i in range(n - half):
        r = i % 32768
        f.write("172.%d.%d.%d\n" % (16 + i // 32768, r // 128, (r % 128) * 2 + 1))
EOF
EXPECTED_BLACK=$(python3 -c '
import ipaddress, sys
nets = [ipaddress.ip_network(l.strip()) for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
print(len(list(ipaddress.collapse_addresses(nets))))' "$BIG_BLACKLIST_FILE")
write_config "$BIG_CONF" lists=big list_file="$BIG_BLACKLIST_FILE" list_message="Your address %A is in the big list"
T0=$(now_f)
"$BIN/greyd-setup" -b -d -f "$BIG_CONF" 2>&1 | tail -n 5 | tee "$LOGDIR/greyd-setup-big.out"
[ "${PIPESTATUS[0]}" -eq 0 ] || die "greyd-setup -b failed"
BLACK_SECS=$(elapsed_since "$T0")
BLACK_IN_SET=$(ipset_entries "$BLACKLIST_SET")
say "greyd-setup -b took ${BLACK_SECS}s; ipset $BLACKLIST_SET: $BLACK_IN_SET entries ($(ipset list "$BLACKLIST_SET" | wc -l) lines), expected $EXPECTED_BLACK after collapsing"
float_lt "$BLACK_SECS" 60 || die "greyd-setup -b took ${BLACK_SECS}s, expected under 60s"
[ "$BLACK_IN_SET" = "$EXPECTED_BLACK" ] || die "ipset $BLACKLIST_SET holds $BLACK_IN_SET entries, expected $EXPECTED_BLACK"
ipset test "$BLACKLIST_SET" 10.0.1.7 >/dev/null 2>&1 || die "10.0.1.7 (inside 10.0.1.0/24) not matched by $BLACKLIST_SET"

# Whitelist path: greydb -> database -> greylister scan -> firewall
# process -> ipset. Odd host octets again so nothing collapses.
WHITE_KEYS=$(python3 -c 'import sys; n = int(sys.argv[1]); print(" ".join("192.168.%d.%d" % ((i // 128) % 256, (i % 128) * 2 + 1) for i in range(n)))' "$WHITE_COUNT")
WHITE_BASE=$(ipset_entries "$WHITELIST_SET")
T0=$(now_f)
# shellcheck disable=SC2086
run_greydb -a $WHITE_KEYS
GREYDB_SECS=$(elapsed_since "$T0")
say "greydb -a with $WHITE_COUNT keys took ${GREYDB_SECS}s (one transaction per key)"
[ "$(db_count '^WHITE|192.168.')" -ge "$WHITE_COUNT" ] || die "greydb lists $(db_count '^WHITE|192.168.') WHITE 192.168.* entries, expected $WHITE_COUNT"
T1=$(now_f)
WAIT=90 WAIT_STEP=1 wait_for "$WHITE_COUNT more entries in $WHITELIST_SET" ipset_entries_at_least "$WHITELIST_SET" $((WHITE_BASE + WHITE_COUNT)) \
    || die "ipset $WHITELIST_SET has $(ipset_entries "$WHITELIST_SET") entries, expected at least $((WHITE_BASE + WHITE_COUNT)) within 90s of greydb finishing"
WHITE_SECS=$(elapsed_since "$T1")
ipset test "$WHITELIST_SET" 192.168.0.1 >/dev/null 2>&1 || die "192.168.0.1 not in $WHITELIST_SET"
say "whitelist entries visible in ipset ${WHITE_SECS}s after greydb finished (scan interval ${SCAN_INTERVAL}s)"
pass "blacklist: $BLACK_IN_SET entries in ${BLACK_SECS}s (< 60s); whitelist: $WHITE_COUNT entries in ipset ${WHITE_SECS}s after greydb (< 90s; greydb itself ${GREYDB_SECS}s)"

# --- 20/21. chaos on the pipes -----------------------------------------------

step "chaos: SIGKILL the firewall child with a connection open"
chaos_kill firewall
pass "parent logged the firewall child's exit, exited 0 within 5s, removed the pidfile, no greyd processes left"
start_greyd "$CONF"
say "greyd restarted: main $GREYD_PID, firewall $FW_PID, greylister $GREY_PID"

step "chaos: SIGKILL the greylister child with a connection open"
chaos_kill greylister
pass "parent logged the greylister child's exit, exited 0 within 5s, removed the pidfile, no greyd processes left"

# --- 22. restart mid-traffic with persistence (sqlite) -----------------------

step "restart mid-traffic with persistence (sqlite, pass_time ${RESTART_PASS_TIME}s)"
write_config "$RESTART_CONF" pass_time=$RESTART_PASS_TIME
start_greyd "$RESTART_CONF"
restart_persistence "$RESTART_CONF" sqlite
pass "sqlite: GREY tuple kept first/bcount across SIGTERM+restart, marked at pass_time and whitelisted by the next start-up scan"
start_greyd "$RESTART_CONF"

# --- 23. clean shutdown ------------------------------------------------------

step "clean shutdown on SIGTERM"
stop_greylogd
[ "$GREYLOGD_RC" -eq 0 ] || die "greylogd exited with status $GREYLOGD_RC"
stop_greyd
[ "$GREYD_RC" -eq 0 ] || die "greyd exited with status $GREYD_RC"
pass "greyd and greylogd exited 0 and left no child processes"

# --- 24. restart mid-traffic with persistence (bolt) -------------------------

step "restart mid-traffic with persistence (bolt driver, pass_time ${RESTART_PASS_TIME}s)"
write_config "$BOLT_CONF" driver=bolt db_name=greyd.db pass_time=$RESTART_PASS_TIME
"$BIN/greyd" -t -f "$BOLT_CONF" | grep -q "configuration OK" || die "greyd -t did not accept the bolt configuration"
start_greyd "$BOLT_CONF"
restart_persistence "$BOLT_CONF" bolt
[ "$(stat -c %U "$LIB/greyd.db")" = greydb ] || die "bolt database file is not owned by greydb"
pass "bolt: GREY tuple kept first/bcount across SIGTERM+restart, marked at pass_time and whitelisted by the next start-up scan"

say ""
say "ALL PASS ($STEP steps)"
STATUS=0
exit 0
