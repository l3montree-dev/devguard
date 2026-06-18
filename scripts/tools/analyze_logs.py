#!/usr/bin/env python3
"""
analyze_logs.py — Find recurring patterns and strange/rare occurrences in a log file.

Built for triaging DevGuard incidents (degraded performance, error storms), but the
parsing is generic enough for most structured logs. It auto-detects two formats:

  1. zerolog console output (the devguard-api logs), e.g.
       1:32PM ERR middlewares/server.go:70 code=404, message=asset not found ...
     (ANSI color codes are stripped automatically)

  2. PostgreSQL stderr logs, e.g.
       2026-06-14 20:34:15.222 UTC [1375131] ERROR:  canceling statement due to user request

What it reports:
  - Summary (line count, time range, severity distribution)
  - Top RECURRING normalized messages (the noise — what dominates the log)
  - Top callers / source locations
  - Per-minute (or per-hour) histogram to spot bursts
  - RARE / strange events (normalized messages seen only once or twice — the signal)
  - Targeted health signals (timeouts, goroutine/OOM/panic/deadlock, FK violations, ...)

Usage:
  python3 scripts/analyze_logs.py <logfile> [--top N] [--rare-max K] [--bucket minute|hour]
                                            [--level ERR,WRN] [--grep REGEX] [--full]

Examples:
  python3 scripts/analyze_logs.py devguard-api.log
  python3 scripts/analyze_logs.py postgresql.log --bucket hour --top 15
  python3 scripts/analyze_logs.py devguard-api.log --level ERR --rare-max 1
"""
import argparse
import re
import sys
from collections import Counter, defaultdict

ANSI = re.compile(r"\x1b\[[0-9;]*m")

# zerolog console: "1:32PM ERR caller/file.go:70 message..."
ZEROLOG = re.compile(
    r"^(?P<ts>\d{1,2}:\d{2}(?::\d{2})?(?:AM|PM)?)\s+"
    r"(?P<level>TRC|DBG|INF|WRN|ERR|FTL|PNC)\s+"
    r"(?P<caller>[\w./-]+\.go:\d+)?\s*"
    r"(?P<msg>.*)$"
)

# postgres: "2026-06-14 20:34:15.222 UTC [1375131] ERROR:  message..."
POSTGRES = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[.\d]*\s+\S+\s+"
    r"\[(?P<pid>\d+)\]\s+"
    r"(?P<level>LOG|ERROR|WARNING|FATAL|PANIC|DETAIL|HINT|STATEMENT|CONTEXT):\s+"
    r"(?P<msg>.*)$"
)

# Order matters: most specific first, generic number last.
NORMALIZERS = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"pkg:[^\s\"']+"), "<purl>"),
    (re.compile(r"https?://[^\s\"']+"), "<url>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.I), "<hex>"),
    (re.compile(r"\$\d+(?:\s*,\s*\$\d+)+"), "$N,..."),          # SQL bind-param lists
    (re.compile(r"\([^)]*\$\d+[^)]*\)(?:\s*,\s*\([^)]*\))*"), "(...)"),  # VALUES tuples
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|µs|us|ns|s)\b"), "<dur>"),
    (re.compile(r"\bid=\d+\b"), "id=N"),
    (re.compile(r"=\"[^\"]*\""), "=\"...\""),                    # quoted key=val payloads
    (re.compile(r"\b\d+\b"), "N"),
]

SIGNALS = {
    "timeout (context deadline)": re.compile(r"context deadline exceeded|deadline exceeded", re.I),
    "statement canceled": re.compile(r"canceling statement", re.I),
    "goroutine leak hint": re.compile(r"goroutine", re.I),
    "panic": re.compile(r"\bpanic\b|panicked", re.I),
    "OOM / out of memory": re.compile(r"out of memory|oom|cannot allocate", re.I),
    "deadlock": re.compile(r"deadlock", re.I),
    "connection refused / reset": re.compile(r"connection refused|reset by peer|broken pipe|EOF", re.I),
    "too many connections/clients/files": re.compile(r"too many (clients|connections|open files)", re.I),
    "dial/network failure": re.compile(r"dial tcp|no such host|i/o timeout|network is unreachable", re.I),
    "FK constraint violation": re.compile(r"violates foreign key constraint", re.I),
    "ON CONFLICT double-affect": re.compile(r"cannot affect row a second time", re.I),
    "5xx server error": re.compile(r"\bcode=5\d\d\b|status=5\d\d\b"),
    "auth/identity failure": re.compile(
        r"failed to get identity|\bunauthorized\b|\bforbidden\b|"
        r"(?:code|status)[=: ]\s*40[13]\b", re.I),
}

ERROR_LEVELS = {"ERR", "ERROR", "FTL", "FATAL", "PNC", "PANIC"}
WARN_LEVELS = {"WRN", "WARNING"}


def normalize(msg: str) -> str:
    s = msg
    for rx, repl in NORMALIZERS:
        s = rx.sub(repl, s)
    return s.strip()[:200]


def bucket_key(ts: str, mode: str) -> str:
    if mode == "hour":
        # postgres "2026-06-14 20:34:15" -> "2026-06-14 20"; zerolog "1:32PM" -> "1PM"
        m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2})", ts)
        if m:
            return m.group(1)
        m = re.match(r"(\d{1,2}):\d{2}(?::\d{2})?(AM|PM)?", ts)
        return f"{m.group(1)}{m.group(2) or ''}" if m else ts
    # minute
    m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2})", ts)
    if m:
        return m.group(1)
    m = re.match(r"(\d{1,2}:\d{2})(?::\d{2})?(AM|PM)?", ts)
    return f"{m.group(1)}{m.group(2) or ''}" if m else ts


def parse(line: str):
    line = ANSI.sub("", line.rstrip("\n"))
    if not line.strip():
        return None
    m = ZEROLOG.match(line)
    if m:
        d = m.groupdict()
        return {"ts": d["ts"], "level": d["level"], "caller": d["caller"] or "", "msg": d["msg"], "raw": line}
    m = POSTGRES.match(line)
    if m:
        d = m.groupdict()
        return {"ts": d["ts"], "level": d["level"], "caller": f"pid {d['pid']}", "msg": d["msg"], "raw": line}
    return {"ts": "", "level": "?", "caller": "", "msg": line, "raw": line}  # unparsed


def hbar(n: int, mx: int, width: int = 40) -> str:
    return "█" * max(1, round(n / mx * width)) if mx and n else ""


def section(title: str):
    print(f"\n\033[1m{'═' * 70}\n {title}\n{'═' * 70}\033[0m")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile")
    ap.add_argument("--top", type=int, default=20, help="how many recurring patterns/callers to show")
    ap.add_argument("--rare-max", type=int, default=2, help="max count for a pattern to count as 'rare'")
    ap.add_argument("--bucket", choices=["minute", "hour"], default="minute", help="time histogram granularity")
    ap.add_argument("--level", help="comma-separated levels to keep (e.g. ERR,WRN)")
    ap.add_argument("--grep", help="only analyze lines matching this regex (on the raw, ANSI-stripped line)")
    ap.add_argument("--full", action="store_true", help="show full (untruncated) example for each pattern")
    args = ap.parse_args()

    keep_levels = {l.strip().upper() for l in args.level.split(",")} if args.level else None
    grep_rx = re.compile(args.grep) if args.grep else None

    levels = Counter()
    callers = Counter()
    norm_msgs = Counter()
    norm_example = {}
    norm_levels = defaultdict(Counter)
    time_hist = Counter()
    err_time_hist = Counter()
    signal_hits = defaultdict(list)
    total = unparsed = 0
    first_ts = last_ts = None

    try:
        f = open(args.logfile, encoding="utf-8", errors="replace")
    except OSError as e:
        sys.exit(f"cannot open {args.logfile}: {e}")

    with f:
        for line in f:
            rec = parse(line)
            if rec is None:
                continue
            if grep_rx and not grep_rx.search(rec["raw"]):
                continue
            if keep_levels and rec["level"] not in keep_levels:
                continue
            total += 1
            if rec["level"] == "?":
                unparsed += 1
            levels[rec["level"]] += 1
            if rec["caller"]:
                callers[rec["caller"]] += 1
            if rec["ts"]:
                first_ts = first_ts or rec["ts"]
                last_ts = rec["ts"]
                bk = bucket_key(rec["ts"], args.bucket)
                time_hist[bk] += 1
                if rec["level"] in ERROR_LEVELS:
                    err_time_hist[bk] += 1
            nm = normalize(rec["msg"])
            if nm:
                norm_msgs[nm] += 1
                norm_levels[nm][rec["level"]] += 1
                norm_example.setdefault(nm, rec["msg"])
            for name, rx in SIGNALS.items():
                if rx.search(rec["raw"]):
                    signal_hits[name].append(rec)

    if not total:
        sys.exit("no lines matched the given filters.")

    # ---- Summary ----
    section(f"SUMMARY  —  {args.logfile}")
    print(f"  lines analyzed : {total:,}" + (f"   (unparsed: {unparsed:,})" if unparsed else ""))
    print(f"  time range     : {first_ts}  →  {last_ts}")
    print("  severity       :")
    mx = max(levels.values())
    for lvl, c in sorted(levels.items(), key=lambda x: -x[1]):
        color = "\033[91m" if lvl in ERROR_LEVELS else "\033[93m" if lvl in WARN_LEVELS else "\033[0m"
        print(f"    {color}{lvl:8}\033[0m {c:6,}  {hbar(c, mx, 30)}")

    # ---- Health signals (the targeted stuff that matters in an incident) ----
    section("HEALTH SIGNALS (targeted patterns)")
    if not signal_hits:
        print("  none of the tracked failure signals fired. 👍")
    else:
        for name, rx in SIGNALS.items():
            hits = signal_hits.get(name)
            if not hits:
                continue
            print(f"\n  \033[91m●\033[0m {name}: \033[1m{len(hits):,}\033[0m hit(s)")
            ex = hits[0]
            print(f"      first: {ex['ts']} {ex['caller']}".rstrip())
            print(f"      e.g. : {ex['msg'][:160]}")

    # ---- Recurring patterns ----
    section(f"TOP {args.top} RECURRING PATTERNS (normalized message)")
    mx = norm_msgs.most_common(1)[0][1]
    for nm, c in norm_msgs.most_common(args.top):
        lv = ",".join(f"{k}:{v}" for k, v in norm_levels[nm].most_common())
        print(f"\n  \033[1m{c:5,}×\033[0m [{lv}]  {hbar(c, mx, 20)}")
        print(f"        {(norm_example[nm] if args.full else nm)[:180]}")

    # ---- Top callers ----
    if callers:
        section(f"TOP {args.top} SOURCE LOCATIONS")
        mx = callers.most_common(1)[0][1]
        for caller, c in callers.most_common(args.top):
            print(f"  {c:6,}  {caller:45}  {hbar(c, mx, 20)}")

    # ---- Time histogram ----
    section(f"ACTIVITY OVER TIME (per {args.bucket}) — total / errors")
    mx = max(time_hist.values())
    for bk in sorted(time_hist):
        tot, err = time_hist[bk], err_time_hist.get(bk, 0)
        marker = "  \033[91m← error burst\033[0m" if err and err >= 0.5 * mx else ""
        print(f"  {bk:18} {tot:5,} {hbar(tot, mx, 35)}  err={err}{marker}")

    # ---- Rare / strange events ----
    section(f"RARE / STRANGE EVENTS (patterns seen ≤ {args.rare_max}×) — the anomalies")
    rare = [(nm, c) for nm, c in norm_msgs.items() if c <= args.rare_max]
    # Surface error/warn-level rarities first — those are the interesting needles.
    rare.sort(key=lambda x: (
        0 if any(l in ERROR_LEVELS for l in norm_levels[x[0]]) else
        1 if any(l in WARN_LEVELS for l in norm_levels[x[0]]) else 2,
        x[1],
    ))
    print(f"  {len(rare):,} distinct rare patterns. Showing up to 30 (errors/warnings first):\n")
    for nm, c in rare[:30]:
        lv = ",".join(norm_levels[nm].keys())
        tag = "\033[91m" if any(l in ERROR_LEVELS for l in norm_levels[nm]) else \
              "\033[93m" if any(l in WARN_LEVELS for l in norm_levels[nm]) else "\033[2m"
        print(f"  {tag}{c}× [{lv}]\033[0m {(norm_example[nm])[:150]}")
    print()


if __name__ == "__main__":
    main()
