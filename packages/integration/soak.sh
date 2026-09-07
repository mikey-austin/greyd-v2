#!/usr/bin/env bash
#
# greyd soak test: run the daemons under a steady load for SOAK_MINUTES
# (default 30) and check that memory, descriptors and the scanner stay
# healthy. Runs inside the privileged integration container like
# run-linux.sh (same lib.sh, same netfilter/sqlite setup):
#
#   make test-soak SOAK_MINUTES=30
#
# Every SOAK_SAMPLE seconds (30) it records, to $LOGDIR/soak.csv:
#   epoch, greyd --stats counters of interest, VmRSS and descriptor counts
#   of the main, firewall and greylister processes and greylogd.
# Load: loadgen.py in steady mode at SOAK_RATE dialogues per second (20),
# a greyd-setup push every 60s and a greydb addition every 60s.
#
# Assertions at the end:
#   - RSS of every process grew less than SOAK_MAX_RSS_GROWTH percent (20)
#     between the 5 minute mark and the end (or the first sample when the
#     run is shorter),
#   - descriptor counts at the end are within +10 of that reference sample,
#   - counters never decreased,
#   - db_scan_age_seconds never exceeded twice the scan interval (60s),
#   - no line with level ERROR (or "fatal") in the greyd log,
#   - the daemons are still alive and stop cleanly.
#
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib.sh"
it_setup_env

SOAK_MINUTES=${SOAK_MINUTES:-30}
SOAK_SAMPLE=${SOAK_SAMPLE:-30}
SOAK_RATE=${SOAK_RATE:-20}
SOAK_MAX_RSS_GROWTH=${SOAK_MAX_RSS_GROWTH:-20}
SOAK_REF_MINUTE=5
CSV=$LOGDIR/soak.csv
SOAK_CONF=$ETC/soak.conf

step "environment, programs, users and configuration"
it_check_environment
it_check_programs
it_setup_users_dirs
write_config "$SOAK_CONF" pass_time=60
"$BIN/greyd" -t -f "$SOAK_CONF" >/dev/null || die "configuration rejected"
pass "ready: ${SOAK_MINUTES} minutes at ${SOAK_RATE} dialogues/s, samples every ${SOAK_SAMPLE}s"

step "iptables rules"
it_install_rules
pass "rules installed"

step "start greyd and greylogd"
start_greyd "$SOAK_CONF"
find_children || die "could not find the firewall and greylister children"
start_greylogd "$SOAK_CONF"
pass "greyd $GREYD_PID (fw $FW_PID, grey $GREY_PID), greylogd $GREYLOGD_PID"

# --- load ---------------------------------------------------------------------

step "start the steady load"
duration=$((SOAK_MINUTES * 60))
python3 "$HERE/loadgen.py" --port "$DNAT_PORT" --rate "$SOAK_RATE" --duration "$duration" --report 60 >"$LOGDIR/soak-load.out" 2>&1 &
LOAD_PID=$!
BACKGROUND_PIDS="$BACKGROUND_PIDS $LOAD_PID"
(
    i=0
    while kill -0 "$LOAD_PID" 2>/dev/null; do
        sleep 60
        i=$((i + 1))
        "$BIN/greyd-setup" -f "$SOAK_CONF" >/dev/null 2>&1 || echo "greyd-setup failed at minute $i" >>"$LOGDIR/soak-side.out"
        run_greydb_conf "$SOAK_CONF" -a "10.200.$(( (i / 256) % 256 )).$(( i % 256 ))" >/dev/null 2>&1 || echo "greydb -a failed at minute $i" >>"$LOGDIR/soak-side.out"
    done
) &
SIDE_PID=$!
BACKGROUND_PIDS="$BACKGROUND_PIDS $SIDE_PID"
pass "loadgen pid $LOAD_PID, side jobs pid $SIDE_PID"

# --- sampling -----------------------------------------------------------------

step "sample for ${SOAK_MINUTES} minutes"
counters="connections_total greylist_tuples_total replies_grey_total replies_black_total db_entries_grey db_entries_white db_scan_age_seconds"
{
    printf 'epoch'
    for c in $counters; do printf ',%s' "$c"; done
    printf ',main_rss_kb,fw_rss_kb,grey_rss_kb,greylogd_rss_kb,main_fds,fw_fds,grey_fds,greylogd_fds\n'
} >"$CSV"
sample() {
    local s line c v
    s=$(stats) || return 1
    line=$EPOCHSECONDS
    for c in $counters; do
        v=$(printf '%s\n' "$s" | awk -v n="$c" '$1 == n { print $2 }')
        line="$line,${v:-}"
    done
    line="$line,$(proc_rss_kb "$GREYD_PID"),$(proc_rss_kb "$FW_PID"),$(proc_rss_kb "$GREY_PID"),$(proc_rss_kb "$GREYLOGD_PID")"
    line="$line,$(proc_fds "$GREYD_PID"),$(proc_fds "$FW_PID"),$(proc_fds "$GREY_PID"),$(proc_fds "$GREYLOGD_PID")"
    echo "$line" >>"$CSV"
}
end=$((EPOCHSECONDS + duration))
n=0
while [ "$EPOCHSECONDS" -lt "$end" ]; do
    sample || die "greyd --stats failed during the soak (greyd alive: $(is_alive "$GREYD_PID" && echo yes || echo no))"
    is_alive "$GREYD_PID" || die "greyd died during the soak"
    is_alive "$GREYLOGD_PID" || die "greylogd died during the soak"
    n=$((n + 1))
    if [ $((n % 10)) -eq 0 ]; then say "$(tail -n 1 "$CSV")"; fi
    sleep "$SOAK_SAMPLE"
done
sample || true
wait "$LOAD_PID" 2>/dev/null; load_rc=$?
kill "$SIDE_PID" 2>/dev/null || true
pass "$(wc -l <"$CSV") samples; loadgen exit status $load_rc"
[ -s "$LOGDIR/soak-side.out" ] && { say "side job failures:"; cat "$LOGDIR/soak-side.out"; }

# --- assertions ---------------------------------------------------------------

step "assertions"
python3 - "$CSV" "$SOAK_MAX_RSS_GROWTH" "$SOAK_REF_MINUTE" "$SOAK_SAMPLE" <<'EOF' || die "soak assertions failed"
import csv, sys
path, max_growth, ref_minute, sample_s = sys.argv[1], float(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
rows = list(csv.DictReader(open(path)))
if len(rows) < 3:
    sys.exit("too few samples: %d" % len(rows))
ref_index = min(len(rows) - 2, (ref_minute * 60) // max(sample_s, 1))
ref, last = rows[ref_index], rows[-1]
failed = False
def num(r, k):
    try:
        return float(r[k])
    except (TypeError, ValueError):
        return None
for proc in ("main", "fw", "grey", "greylogd"):
    a, b = num(ref, proc + "_rss_kb"), num(last, proc + "_rss_kb")
    if a and b:
        growth = (b - a) / a * 100
        print("%-9s RSS %8.0f kB -> %8.0f kB (%+.1f%%)" % (proc, a, b, growth))
        if growth > max_growth:
            print("  FAIL: RSS grew more than %.0f%%" % max_growth); failed = True
    fa, fb = num(ref, proc + "_fds"), num(last, proc + "_fds")
    if fa is not None and fb is not None:
        print("%-9s fds %4.0f -> %4.0f" % (proc, fa, fb))
        if fb > fa + 10:
            print("  FAIL: descriptor count grew"); failed = True
for c in ("connections_total", "greylist_tuples_total", "replies_grey_total"):
    vals = [num(r, c) for r in rows if num(r, c) is not None]
    if any(b < a for a, b in zip(vals, vals[1:])):
        print("FAIL: %s decreased" % c); failed = True
    print("%-24s %s -> %s" % (c, vals[0] if vals else "?", vals[-1] if vals else "?"))
ages = [num(r, "db_scan_age_seconds") for r in rows if num(r, "db_scan_age_seconds") is not None]
if ages:
    print("max db_scan_age_seconds %.0f" % max(ages))
    if max(ages) > 120:
        print("FAIL: scanner fell behind (age > 120s)"); failed = True
sys.exit(1 if failed else 0)
EOF
if grep -Ei "level=ERROR|fatal error|panic:" "$LOG" >/dev/null 2>&1; then
    grep -Ei "level=ERROR|fatal error|panic:" "$LOG" | head -20
    die "errors in the greyd log"
fi
pass "memory, descriptors, counters, scanner and log are healthy"

step "clean shutdown"
stop_greylogd
stop_greyd
[ "${GREYD_RC:-1}" -eq 0 ] || die "greyd exited with status $GREYD_RC"
pass "stopped cleanly"

STATUS=0
say ""
say "SOAK PASS (${SOAK_MINUTES} minutes, samples in $CSV)"
