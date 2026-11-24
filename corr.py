#!/usr/bin/env python3
"""corr.py - do logged events cluster around incidents more than chance? (Python 3.9+ standard library only)

Inputs
  incidents   CSV with header: time,label[,precision_s]
              time is device local ISO ("2026-01-15T10:51:04"); precision_s (default 60) widens the window
              when you only know the time roughly.
  sources     any mix of
                --il  <ilpass output folder>   (uses events.jsonl)
                --bra <bra.py output folder>   (uses data/bhist_events.jsonl, data/bhist_app_events.jsonl,
                                                data/bt_sessions.csv, data/bt_media.csv)

Method (fixed before any results were looked at)
  * Every event gets a "kind": e.g. dns:com.example.music, connect:com.example.rides, sec:app_process_start:com.x,
    sec:keyguard_dismissed, battery:+audio, battery:phone_signal_strength->poor, app:+top:com.example.music,
    bt:LE:initiated-remote, media:AVRCP PASS_THROUGH FORWARD.
  * For each kind, the statistic is the number of incidents with at least one event of that kind within
    [t - before - precision, t + after + precision]. Only incidents whose window lies inside that source's
    coverage count.
  * Null: shift ALL incidents together by every offset on a --step grid (default 10 s), circularly within the
    source's coverage (keeps the incidents' spacing; destroys only their alignment with the logs). Exhaustive and
    deterministic. Shifts within one window-width of zero (either direction) are excluded, since they only
    slide each incident onto the same events. p = (1 + #shifts >= observed) / (1 + N); with a day of logs N is about 8,600, so the
    smallest p is about 0.0001, small enough to survive the multiple-comparison correction.
  * Benjamini-Hochberg q-values across all tested kinds.
  * A kind is tested only if it has >= --min-events events and >= --min-incidents covered incidents.

Reading (pre-registered)
  * FLAG: q < 0.05 and >= 3 covered incidents with an event of that kind nearby. Look closer at what the kind
    is; many will be mundane (screen on, an app you opened because of the incident).
  * Not flagged with few incidents is NOT evidence of absence; the report prints the smallest p-value the test
    could reach with the incidents it had.

Usage
  python3 -I corr.py incidents.csv --il out/il-1124 --bra out/bra-1556 --out out/corr-1124
                     [--before 120] [--after 60] [--step 10] [--tz America/New_York]
"""
import argparse
import bisect
import collections
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    sys.exit("Python 3.9+ required")

VERSION = "0.1.0 (2026-11-24)"


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def to_s(s, tz):
    d = datetime.fromisoformat(s.strip())
    if d.tzinfo is None:
        d = d.replace(tzinfo=tz)
    return d.timestamp()


# ------------------------------------------------------------------------------------------ adapters

def from_ilpass(folder):
    """Yield (t_seconds, kind) from ilpass events.jsonl."""
    out = []
    for l in open(os.path.join(folder, "events.jsonl")):
        e = json.loads(l)
        p, t, typ = e["payload"], e["t_ns"] / 1e9, e["type"]
        if typ in ("dns", "connect"):
            out.append((t, f"{typ}:{(p.get('package_name') or '(system)').split(':')[0]}"))
        elif typ == "sec:app_process_start":
            out.append((t, f"{typ}:{(p.get('process') or '').split(':')[0]}"))
        elif typ in ("sec:bluetooth_connection", "sec:bluetooth_disconnection"):
            out.append((t, f"{typ}" + (f":{p.get('reason')}" if p.get("reason") else "")))
        elif typ == "sec:keyguard_dismiss_auth_attempt":
            out.append((t, f"{typ}:{'ok' if p.get('success') else 'FAIL'}:m{p.get('method_strength')}"))
        elif typ.startswith("sec:package_"):
            out.append((t, f"{typ}:{p.get('package_name')}"))
        else:
            out.append((t, typ))
    return out


def from_bra(folder, tz):
    out = []
    d = os.path.join(folder, "data")
    p = os.path.join(d, "bhist_events.jsonl")
    if os.path.exists(p):
        for l in open(p):
            e = json.loads(l)
            if e["old"] is None:
                continue
            k = e["key"]
            if k.startswith("+"):
                kind = f"battery:{'+' if e['new'] else '-'}{k[1:]}"
            else:
                kind = f"battery:{k}->{e['new']}"
            out.append((to_s(e["t"], tz), kind))
    p = os.path.join(d, "bhist_app_events.jsonl")
    if os.path.exists(p):
        for l in open(p):
            e = json.loads(l)
            if e["key"] in ("top", "fg", "pkginst", "pkgunin", "job", "longwake", "screenwake", "alarm") and e["sign"]:
                v = e["value"]
                if e["key"] == "job":
                    v = v.split("/")[0].split("@")[-1]
                out.append((to_s(e["t"], tz), f"app:{e['sign']}{e['key']}:{v}"))
    year = None
    for name, tcol, kindf in (("bt_sessions.csv", "start", lambda r: f"bt:{r['transport']}:initiated-{r['initiated by']}"),
                              ("bt_media.csv", "time", lambda r: f"media:{r['dir']} {r['protocol']} " +
                               " ".join(w for w in r["event"].split() if w.isupper() and len(w) > 2)[:60])):
        p = os.path.join(d, name)
        if not os.path.exists(p):
            continue
        if year is None:
            m = json.load(open(os.path.join(folder, "manifest.json")))
            year = int(m.get("run_utc", "2026")[:4])
        for r in csv.DictReader(open(p)):
            t = r.get(tcol, "")
            if not t or t == "-":
                continue
            out.append((to_s(f"{year}-{t[:5]}T{t[6:]}", tz), kindf(r)))
    return out


# ------------------------------------------------------------------------------------------ test

def bh(ps):
    n = len(ps)
    order = sorted(range(n), key=lambda i: ps[i])
    q = [0.0] * n
    prev = 1.0
    for rank, i in reversed(list(enumerate(order, 1))):
        prev = min(prev, ps[i] * n / rank)
        q[i] = prev
    return q


def run(events, incidents, before, after, step, min_events, min_inc, label):
    if not events:
        return [], None
    events.sort()
    lo, hi = events[0][0], events[-1][0]
    span = hi - lo
    covered = [(t, lab, pr) for t, lab, pr in incidents if lo + before + pr <= t <= hi - after - pr]
    bykind = collections.defaultdict(list)
    for t, k in events:
        bykind[k].append(t)
    # shifts smaller than the window just slide each incident onto the same events: exclude them both ways
    guard = before + after + 2 * max((pr for _, _, pr in covered), default=0)
    offs = [k * step for k in range(1, int(span // step)) if guard < k * step < span - guard]
    shifts = len(offs)

    def count(ts, incs):
        c = 0
        for t, _, pr in incs:
            i = bisect.bisect_left(ts, t - before - pr)
            if i < len(ts) and ts[i] <= t + after + pr:
                c += 1
        return c

    def shifted(off):
        out = []
        for t, lab, pr in covered:
            u = lo + ((t + off - lo) % span)
            if lo + before + pr <= u <= hi - after - pr:
                out.append((u, lab, pr))
        return out
    shifted_sets = [shifted(o) for o in offs]
    rows = []
    for k, ts in bykind.items():
        if len(ts) < min_events or len(covered) < min_inc:
            continue
        obs = count(ts, covered)
        null = [count(ts, s) for s in shifted_sets]
        ge = sum(1 for x in null if x >= obs)
        p = (1 + ge) / (1 + shifts)
        exp = sum(null) / len(null)
        near = [lab for t, lab, pr in covered if count(ts, [(t, lab, pr)])]
        rows.append({"source": label, "kind": k, "events": len(ts), "covered": len(covered), "observed": obs,
                     "expected": round(exp, 2), "p": p, "near": near})
    return rows, {"source": label, "first": lo, "last": hi, "covered": [l for _, l, _ in covered],
                  "not_covered": [l for t, l, pr in incidents if (t, l, pr) not in covered],
                  "shifts": shifts, "min_p": 1 / (1 + shifts) if covered else None}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("incidents")
    ap.add_argument("--il", action="append", default=[])
    ap.add_argument("--bra", action="append", default=[])
    ap.add_argument("--out", required=True)
    ap.add_argument("--before", type=float, default=120)
    ap.add_argument("--after", type=float, default=60)
    ap.add_argument("--step", type=float, default=10, help="grid step for the circular shifts, seconds")
    ap.add_argument("--min-events", type=int, default=5)
    ap.add_argument("--min-incidents", type=int, default=3)
    ap.add_argument("--tz", default="America/New_York")
    a = ap.parse_args()
    if os.path.exists(a.out):
        sys.exit(f"--out {a.out} already exists")
    if not a.il and not a.bra:
        sys.exit("give at least one --il or --bra folder")
    tz = ZoneInfo(a.tz)
    incidents = []
    for r in csv.DictReader(open(a.incidents)):
        incidents.append((to_s(r["time"], tz), r.get("label", r["time"]), float(r.get("precision_s") or 60)))
    srcs = [(f"il:{os.path.basename(os.path.normpath(f))}", from_ilpass(f)) for f in a.il] + \
           [(f"bra:{os.path.basename(os.path.normpath(f))}", from_bra(f, tz)) for f in a.bra]
    rows, cov = [], []
    for label, evs in srcs:
        r, c = run(evs, incidents, a.before, a.after, a.step, a.min_events, a.min_incidents, label)
        rows += r
        if c:
            cov.append(c)
    for r, q in zip(rows, bh([r["p"] for r in rows])):
        r["q"] = q
        r["flag"] = q < 0.05 and r["observed"] >= 3
    rows.sort(key=lambda r: (r["q"], r["p"], -r["observed"]))
    os.makedirs(a.out)
    fmt = lambda s: datetime.fromtimestamp(s, tz=timezone.utc).astimezone(tz).strftime("%m-%d %H:%M:%S")
    P = ["# Incident correlation\n\n",
         f"corr.py {VERSION} (SHA-256 `{sha256_file(os.path.abspath(__file__))[:16]}…`). Incidents: {len(incidents)} "
         f"from `{os.path.basename(a.incidents)}` (SHA-256 `{sha256_file(a.incidents)[:16]}…`). Window −{a.before:g} s / "
         f"+{a.after:g} s plus each incident's precision. All circular shifts on a {a.step:g} s grid. "
         f"Tested kinds: {len(rows)}.\n\n",
         "> **Flag:** q < 0.05 with ≥ 3 incidents having that kind of event nearby. Unflagged with few incidents is "
         "not evidence of absence.\n\n## Coverage\n\n| source | first | last | incidents covered | not covered | smallest reachable p |\n|---|---|---|---|---|---|\n"]
    for c in cov:
        P.append(f"| {c['source']} | {fmt(c['first'])} | {fmt(c['last'])} | {len(c['covered'])} | "
                 f"{', '.join(c['not_covered']) or '-'} | {c['min_p']:.4f} |\n" if c["min_p"] else
                 f"| {c['source']} | {fmt(c['first'])} | {fmt(c['last'])} | 0 | all | - |\n")
    flagged = [r for r in rows if r["flag"]]
    P.append(f"\n## Flagged kinds: {len(flagged)}\n\n")
    hdr = "| source | kind | events | incidents with one nearby / covered | expected by chance | p | q | which incidents |\n|---|---|---|---|---|---|---|---|\n"
    line = lambda r: (f"| {r['source']} | {r['kind'].replace('|', '/')} | {r['events']} | {r['observed']}/{r['covered']} | "
                      f"{r['expected']} | {r['p']:.4f} | {r['q']:.3f} | {', '.join(r['near'])[:120]} |\n")
    P.append(hdr + "".join(line(r) for r in flagged) if flagged else "_(none)_\n")
    P.append("\n## Top 30 kinds by p (for context; unflagged rows are not findings)\n\n" + hdr +
             "".join(line(r) for r in rows[:30]))
    with open(os.path.join(a.out, "report.md"), "w") as fh:
        fh.write("".join(P))
    with open(os.path.join(a.out, "results.json"), "w") as fh:
        json.dump({"coverage": cov, "rows": rows, "args": vars(a), "version": VERSION}, fh, indent=1)
    print(f"report: {os.path.join(a.out, 'report.md')}  tested kinds: {len(rows)}  flagged: {len(flagged)}")


if __name__ == "__main__":
    main()
