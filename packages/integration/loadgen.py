#!/usr/bin/env python3
"""Concurrent SMTP load generator for the greyd integration harnesses.

Every dialogue is a greylisting attempt (banner, EHLO, MAIL FROM, RCPT TO,
DATA) from one source address with a distinct HELO / sender / recipient,
so each is a distinct greylist tuple. The time from connect() to the final
reply (the 451) is recorded per dialogue.

Two modes:

  burst (default)   --count N dialogues run concurrently (bounded by
                    --concurrency), used for the latency SLO step;
  steady            --rate R --duration S starts R dialogues per second
                    for S seconds (a --pool P cycles through P tuples so
                    retries and whitelisting are exercised), used by the
                    soak; a summary line is printed every --report seconds.

The summary (p50/p99/max latency, throughput, failures, epoch of the last
451) is printed to stderr and, with --json FILE, written as JSON so the
harness can compute the greylister's insert lag. Exit status: 0 when every
dialogue got the expected reply, 1 when some failed, 2 on a usage error.
"""

import argparse
import asyncio
import json
import sys
import time


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


class Failure(Exception):
    pass


async def read_reply(reader, timeout):
    """Read one (possibly multi-line) reply; return (code, text)."""
    lines = []
    while True:
        raw = await asyncio.wait_for(reader.readuntil(b"\n"), timeout)
        line = raw.rstrip(b"\r\n").decode("utf-8", "replace")
        lines.append(line)
        if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
            return line[:3], "\n".join(lines)
        if len(line) < 4 or not line[:3].isdigit() or line[3] != "-":
            raise Failure("malformed reply line %r" % line)


async def dialogue(args, n, results):
    """One greylisting attempt for tuple number n; appends to results."""
    helo = "%s-%d.example.test" % (args.prefix, n)
    mail_from = "%s-%d@example.test" % (args.prefix, n)
    rcpt_to = "rcpt-%d@example.test" % n
    t0 = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(args.dst, args.port, local_addr=(args.src, 0) if args.src else None),
            args.timeout)

        async def cmd(line, want):
            writer.write((line + "\r\n").encode())
            await writer.drain()
            code, text = await read_reply(reader, args.timeout)
            if code != want:
                raise Failure("%s: expected %s, got %s (%s)" % (line.split(":")[0], want, code, text.replace("\n", " | ")))
            return code, text

        code, text = await read_reply(reader, args.timeout)
        if code != "220":
            raise Failure("banner: expected 220, got %s" % code)
        await cmd("EHLO " + helo, "250")
        await cmd("MAIL FROM:<%s>" % mail_from, "250")
        await cmd("RCPT TO:<%s>" % rcpt_to, "250")
        writer.write(b"DATA\r\n")
        await writer.drain()
        code, text = await read_reply(reader, args.timeout)
        if code == "354":
            writer.write(b"Subject: greyd loadgen\r\n\r\ntest\r\n.\r\n")
            await writer.drain()
            code, text = await read_reply(reader, args.timeout)
        elapsed = time.monotonic() - t0
        if code != args.expect:
            raise Failure("final reply %s, expected %s (%s)" % (code, args.expect, text.replace("\n", " | ")))
        results.append((elapsed, time.time(), None))
        try:
            writer.write(b"QUIT\r\n")
            await writer.drain()
        except OSError:
            pass
    except (OSError, Failure, asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
        results.append((time.monotonic() - t0, time.time(), "%s: %s" % (type(e).__name__, e) if str(e) else type(e).__name__))
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


def percentile(sorted_values, p):
    if not sorted_values:
        return float("nan")
    k = max(0, min(len(sorted_values) - 1, int(round(p / 100.0 * len(sorted_values) + 0.5)) - 1))
    return sorted_values[k]


def summarize(results, wall, label=""):
    ok = [r for r in results if r[2] is None]
    failed = [r for r in results if r[2] is not None]
    lat = sorted(r[0] for r in ok)
    s = {
        "label": label,
        "count": len(results),
        "ok": len(ok),
        "failed": len(failed),
        "wall_seconds": wall,
        "throughput_per_second": (len(ok) / wall) if wall > 0 else 0.0,
        "p50_seconds": percentile(lat, 50),
        "p99_seconds": percentile(lat, 99),
        "max_seconds": lat[-1] if lat else float("nan"),
        "last_ok_epoch": max((r[1] for r in ok), default=0.0),
        "first_ok_epoch": min((r[1] for r in ok), default=0.0),
    }
    return s, failed


def fmt(s):
    return ("%sdialogues=%d ok=%d failed=%d wall=%.2fs throughput=%.1f/s p50=%.3fs p99=%.3fs max=%.3fs"
            % (("[%s] " % s["label"]) if s["label"] else "", s["count"], s["ok"], s["failed"], s["wall_seconds"],
               s["throughput_per_second"], s["p50_seconds"], s["p99_seconds"], s["max_seconds"]))


async def burst(args):
    results = []
    sem = asyncio.Semaphore(args.concurrency)

    async def one(n):
        async with sem:
            await dialogue(args, n, results)

    t0 = time.monotonic()
    await asyncio.gather(*(one(args.start + i) for i in range(args.count)))
    return results, time.monotonic() - t0


async def steady(args):
    results = []
    tasks = set()
    interval = 1.0 / args.rate
    t0 = time.monotonic()
    next_report = t0 + args.report
    reported = 0
    n = 0
    deadline = t0 + args.duration
    due = t0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now < due:
            await asyncio.sleep(min(due - now, deadline - now))
            continue
        due += interval
        idx = args.start + (n % args.pool if args.pool > 0 else n)
        n += 1
        if len(tasks) < args.concurrency:
            t = asyncio.ensure_future(dialogue(args, idx, results))
            tasks.add(t)
            t.add_done_callback(tasks.discard)
        else:
            results.append((0.0, time.time(), "concurrency limit reached, dialogue skipped"))
        if now >= next_report:
            window = results[reported:]
            reported = len(results)
            s, _ = summarize(window, args.report, "t+%ds" % int(now - t0))
            log(fmt(s))
            next_report += args.report
    if tasks:
        await asyncio.wait(tasks, timeout=args.timeout + 1)
    return results, time.monotonic() - t0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dst", default="127.0.0.1")
    p.add_argument("--port", type=int, default=2525)
    p.add_argument("--src", default=None, help="local address to bind (default: unbound, i.e. 127.0.0.1 on loopback)")
    p.add_argument("--expect", default="451", help="expected final reply code")
    p.add_argument("--prefix", default="load", help="HELO / sender prefix; tuples are PREFIX-N")
    p.add_argument("--start", type=int, default=0, help="first tuple number")
    p.add_argument("--count", type=int, default=100, help="burst mode: number of dialogues")
    p.add_argument("--concurrency", type=int, default=100, help="maximum simultaneous dialogues")
    p.add_argument("--rate", type=float, default=0.0, help="steady mode: dialogues per second")
    p.add_argument("--duration", type=float, default=0.0, help="steady mode: seconds to run")
    p.add_argument("--pool", type=int, default=0, help="steady mode: cycle through this many tuples (0 = all distinct)")
    p.add_argument("--report", type=float, default=30.0, help="steady mode: seconds between summary lines")
    p.add_argument("--timeout", type=float, default=30.0, help="per-operation timeout")
    p.add_argument("--json", default=None, help="write the summary to this file")
    p.add_argument("--max-failures", type=int, default=0, help="tolerate this many failed dialogues")
    args = p.parse_args()
    if args.rate > 0 and args.duration <= 0:
        p.error("--rate needs --duration")

    if args.rate > 0:
        results, wall = asyncio.run(steady(args))
        label = "steady %.1f/s for %.0fs" % (args.rate, args.duration)
    else:
        results, wall = asyncio.run(burst(args))
        label = "burst %d x %d" % (args.count, args.concurrency)
    s, failed = summarize(results, wall, label)
    log(fmt(s))
    if failed:
        reasons = {}
        for _, _, why in failed:
            reasons[why] = reasons.get(why, 0) + 1
        for why, n in sorted(reasons.items(), key=lambda kv: -kv[1])[:10]:
            log("  %5d x %s" % (n, why))
    if args.json:
        with open(args.json, "w") as f:
            json.dump(s, f, indent=1)
            f.write("\n")
    return 0 if s["failed"] <= args.max_failures else 1


if __name__ == "__main__":
    sys.exit(main())
