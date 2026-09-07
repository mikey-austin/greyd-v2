#!/usr/bin/env python3
"""Fail when benchstat's CSV shows a significant slowdown.

Reads the CSV that `benchstat -format csv OLD NEW` prints on stdin. For the
sec/op table it looks at the "vs base" column of each benchmark: a value like
"+62.31% (p=0.002 n=6)" is a regression when the percentage exceeds the
threshold and p < 0.05. Rows marked "~" (no significant change) or with too
few samples are ignored.
"""
import argparse
import csv
import re
import sys

VS = re.compile(r"([+-]?\d+(?:\.\d+)?)%\s*\(p=(\d+(?:\.\d+)?)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-slowdown", type=float, default=50.0, help="percent")
    ap.add_argument("--max-p", type=float, default=0.05)
    args = ap.parse_args()

    rows = list(csv.reader(sys.stdin))
    unit = None
    regressions, checked = [], 0
    for row in rows:
        if not row:
            continue
        if row[0].startswith("goos:") or row[0].startswith("goarch:") or row[0].startswith("pkg:") or row[0].startswith("cpu:"):
            continue
        # A header row names the unit in the second column ("sec/op", "B/op", ...).
        if len(row) >= 2 and row[1] in ("sec/op", "B/op", "allocs/op"):
            unit = row[1]
            continue
        if unit != "sec/op" or len(row) < 4:
            continue
        name, vs = row[0], row[-1]
        if name in ("geomean",):
            continue
        m = VS.search(vs)
        if not m:
            continue
        checked += 1
        pct, p = float(m.group(1)), float(m.group(2))
        if pct > args.max_slowdown and p < args.max_p:
            regressions.append((name, pct, p))
    if regressions:
        print("benchmark regressions (sec/op):")
        for name, pct, p in regressions:
            print(f"  {name}: +{pct:.1f}% (p={p})")
        sys.exit(1)
    print(f"no significant slowdown above {args.max_slowdown:.0f}% in {checked} compared benchmarks")


if __name__ == "__main__":
    main()
