#!/usr/bin/env python3
"""batpass.py - battery pass over an Android bug report (Python 3.9+ standard library only).

Monitoring software has to run while you aren't using the phone, and running costs battery. This pass reads
what the bug report records about that cost and who incurred it:

  1. coverage         - battery-history span, time since the last full charge, capacity, current level
  2. discharge        - screen-off spans (brief glances merged): % per hour against the other spans, time the
                        CPU was awake, mobile radio, GPS, and the apps that held the phone awake, ran jobs or fired alarms
  3. hourly           - the same per hour, as a CSV for plotting
  4. per app          - since-charge background power, wakelocks, wakeup alarms, jobs, GPS, CPU, data, by app
  5. long wakelocks   - wakelocks held over a minute (battery history "longwake")
  6. alarms           - AlarmManager's top alarms (wakeups per app)
  7. location         - location requests per app and provider since boot
  8. kernel wakeups   - why the CPU woke (wakeup reasons), history window and since charge
  9. event windows    - battery state around times you give (--event)

It never modifies its input; a zip is hashed and extracted read-only. Each section prints its "look closer"
reading, fixed before results were viewed (PREREGISTERED.md). Nothing here proves how anything was done.

Usage
  python3 -I stalkeraware.py battery <bugreport.zip | folder | bugreport-*.txt> --out <new folder>
                                     [--event "2026-01-15T03:10:00|phone warm in pocket"] [--before 900] [--after 300]
"""
import argparse
import collections
import json
import os
import re
import statistics
import sys
from datetime import datetime, timedelta, timezone

from .common import (BR, Ctx, Out, appid_of, bh_state_at, fmt_dur, fmt_t, is_google, open_input, p_battery_history,
                     p_identity, p_uidstats_full, parse_dur, parse_events, part, pkg_is_google, r_identity, sha256_file,
                     toolkit_sha256)

VERSION = "0.1.0 (2026-11-24)"

# Pre-registered thresholds (PREREGISTERED.md). Change them only by adding a new dated version there.
MIN_STRETCH_MIN = 30          # spans shorter than this aren't rated (1 % level steps are too coarse)
GLANCE_MAX_S = 120            # screen-on glances up to this long don't split a screen-off span (amended 2026-11-24)
HIGH_DRAIN_X = 2.0            # screen-off stretch draining >= 2x the median screen-off rate
MIN_DROP_PCT = 2              # ... and losing at least this many percentage points
TOP_N = 5                     # "top N" in the per-app ranks
ALARMS_PER_H = 4.0            # non-Google app averaging >= 4 wakeup alarms per hour since charge
LONGWAKE_MIN_S = 60
MIN_CHARGE_H = 2.0          # per-app ranks need at least this long on battery since the last charge


def hist_extras(ctx):
    """Second pass over battery history for what the shared parser doesn't keep: awake (+running) intervals,
    the first wakelock holder at each acquire, and kernel wakeup reasons."""
    L = ctx.br.L
    a, b = ctx.bh["range"]
    line_t = {r["line"]: r["t"] for r in ctx.bh["rows"]}
    running, wl, wr = [], [], []
    open_run = None
    for ln in range(a, b + 1):
        t = line_t.get(ln)
        if t is None:
            continue
        rest = L[ln - 1]
        if "+running" in rest and open_run is None:
            open_run = t
        if "-running" in rest and open_run is not None:
            running.append((open_run, t))
            open_run = None
        for m in re.finditer(r'\+wake_lock=(-?[0-9a-z]+):"([^"]*)"', rest):
            wl.append((t, ln, m.group(1), m.group(2)))
        for m in re.finditer(r'wake_reason=\d+:"([^"]*)"', rest):
            wr.append((t, ln, m.group(1)))
    if open_run is not None and ctx.bh["rows"]:
        running.append((open_run, ctx.bh["rows"][-1]["t"]))
    ctx.running, ctx.wl_hist, ctx.wr_hist = running, wl, wr


def overlap(ivs, a, b):
    tot = 0.0
    for x, y in ivs:
        lo, hi = max(x, a), min(y, b)
        if hi > lo:
            tot += (hi - lo).total_seconds()
    return tot


def flag_seconds(rows, a, b, key):
    tot = 0.0
    for x, y in zip(rows, rows[1:]):
        lo, hi = max(x["t"], a), min(y["t"], b)
        if hi > lo and x.get(key):
            tot += (hi - lo).total_seconds()
    return tot


def unplugged(r):
    return not r.get("+plugged")


def stretches(ctx):
    """Maximal runs of rows with the same (screen, plugged) state."""
    rows = ctx.bh["rows"]
    out, cur = [], None
    for r in rows:
        key = (bool(r.get("+screen")), bool(r.get("+plugged")))
        if cur is None or key != cur["key"]:
            if cur:
                cur["end"], cur["l1"] = r["t"], r["level"]
                out.append(cur)
            cur = {"key": key, "start": r["t"], "l0": r["level"], "line": r["line"]}
    if cur and rows:
        cur["end"], cur["l1"] = rows[-1]["t"], rows[-1]["level"]
        out.append(cur)
    return out


def app_activity(ctx, a, b):
    """Per uid inside [a, b): jobs, syncs, alarms, longwake, wakelock first-holder counts from battery history."""
    c = collections.defaultdict(collections.Counter)
    for t, ln, sign, key, uid, val in ctx.bh["app"]:
        if a <= t < b and sign == "+" and key in ("job", "sync", "alarm", "longwake", "fg", "top"):
            c[uid][key] += 1
    for t, ln, uid, tag in ctx.wl_hist:
        if a <= t < b:
            c[uid]["wakelock"] += 1
    return c


def fmt_activity(ctx, c, n=4):
    rank = sorted(c.items(), key=lambda kv: -(kv[1]["job"] + kv[1]["alarm"] + kv[1]["wakelock"] + 5 * kv[1]["longwake"]
                                             + kv[1]["sync"]))
    out = []
    for uid, k in rank[:n]:
        bits = ", ".join(f"{v} {x}" for x, v in k.items() if v and x not in ("top",))
        if bits:
            out.append(f"{ctx.uidname(uid)}: {bits}")
    return "; ".join(out)


# ---------------------------------------------------------------------------------------------- sections

def r_coverage(ctx):
    rep = ctx.rep
    rep.h(2, "2. Coverage")
    rows = ctx.bh["rows"]
    items = []
    if rows:
        items.append(("battery history", f"{fmt_t(rows[0]['t'])} → {fmt_t(rows[-1]['t'])} "
                      f"({fmt_dur((rows[-1]['t'] - rows[0]['t']).total_seconds())}), {len(rows)} lines",
                      f"L{ctx.bh['range'][0]}-L{ctx.bh['range'][1]}"))
        items.append(("level now (last history line)", f"{rows[-1]['level']} %", f"L{rows[-1]['line']}"))
    for k, (v, ln) in getattr(ctx, "charge_meta", {}).items():
        items.append((f"since charge: {k}", v, f"L{ln}"))
    svc = ctx.br.service("battery")
    if svc:
        for i in range(svc[0], svc[1] + 1):
            m = re.match(r"^\s+(AC powered|USB powered|Wireless powered|status|health|level|temperature|"
                         r"Charge counter|charge counter|present): (.*)$", ctx.br.L[i])
            if m:
                items.append((f"dumpsys battery: {m.group(1)}", m.group(2).strip(), f"L{i + 1}"))
    rep.table(["item", "value", "ref"], items)
    rep.p("Battery history covers roughly the last day; per-app totals cover the time since the last full charge "
          "(or since boot, where the report says so). A stretch outside the history's span can't be judged here.")


def off_spans(ctx, st):
    """Screen-off spans for rating: consecutive unplugged screen-off stretches, merging screen-on glances shorter than
    GLANCE_MAX_S between them (a glance at the clock shouldn't split a night into unrateable pieces)."""
    spans, cur = [], None
    for s in st:
        on, plugged = s["key"]
        dur = (s["end"] - s["start"]).total_seconds()
        if plugged:
            cur = None
            continue
        if not on:
            if cur is None:
                cur = {"start": s["start"], "end": s["end"], "l0": s["l0"], "l1": s["l1"], "glances": 0,
                       "glance_s": 0.0, "line": s["line"], "pending": None}
                spans.append(cur)
            else:
                if cur["pending"]:
                    cur["glances"] += 1
                    cur["glance_s"] += cur["pending"]
                cur["end"], cur["l1"], cur["pending"] = s["end"], s["l1"], None
        elif cur is not None and dur <= GLANCE_MAX_S and cur["pending"] is None:
            cur["pending"] = dur
        else:
            cur = None
    return spans


def r_discharge(ctx):
    rep, out = ctx.rep, ctx.out
    rep.h(2, "3. Discharge with the screen off (unplugged)")
    allst = stretches(ctx)
    st = [s for s in allst if not s["key"][1]]
    rows_bh = ctx.bh["rows"]
    spans = off_spans(ctx, allst)
    for s in spans:
        s["dur"] = (s["end"] - s["start"]).total_seconds()
        s["drop"] = (s["l0"] or 0) - (s["l1"] or 0)
        s["rate"] = s["drop"] / (s["dur"] / 3600) if s["dur"] >= MIN_STRETCH_MIN * 60 else None
        s["awake"] = overlap(ctx.running, s["start"], s["end"])
        s["mrad"] = flag_seconds(rows_bh, s["start"], s["end"], "+mobile_radio")
        s["gps"] = flag_seconds(rows_bh, s["start"], s["end"], "+gps")
        s["act"] = app_activity(ctx, s["start"], s["end"])
    off = [s for s in spans if s["rate"] is not None]
    for s in off:
        others = [o["rate"] for o in off if o is not s]
        s["base"] = statistics.median(others) if others else None
    flagged = [s for s in off if s["base"] is not None and s["drop"] >= MIN_DROP_PCT
               and (s["rate"] >= HIGH_DRAIN_X * s["base"] if s["base"] > 0 else s["rate"] >= 1.0)]
    med = statistics.median(o["rate"] for o in off) if off else None
    ctx.flagged_stretches = flagged
    rep.p(f"Screen-off spans of ≥ {MIN_STRETCH_MIN} min (glances at the screen under {GLANCE_MAX_S:g} s are merged in "
          f"and counted): {len(off)}; median drain {'-' if med is None else f'{med:.2f}'} %/h. Look closer: a span "
          f"draining ≥ {HIGH_DRAIN_X:g}× the median of the *other* spans and losing ≥ {MIN_DROP_PCT} points, where the "
          "apps active in it don't explain the use. Ordinary causes: weak signal (mobile radio time here; signal bars "
          "in the wireless pass), music or navigation, a backup or photo upload, a system update, heat. The level is "
          "whole percent, so short spans aren't rated.")
    rep.table(["start", "end", "length", "glances", "level", "%/h", "baseline %/h", "CPU awake", "mobile radio", "GPS",
               "", "most active apps (history counts)", "ref"],
              [(fmt_t(s["start"]), fmt_t(s["end"], False), fmt_dur(s["dur"]), f"{s['glances']} ({fmt_dur(s['glance_s'])})",
                f"{s['l0']}→{s['l1']}", f"{s['rate']:.2f}", "-" if s["base"] is None else f"{s['base']:.2f}",
                f"{100 * s['awake'] / s['dur']:.0f}%", fmt_dur(s["mrad"]), fmt_dur(s["gps"]),
                "LOOK" if s in flagged else "", fmt_activity(ctx, s["act"]), f"L{s['line']}") for s in off])
    rep.p("\"CPU awake\" is the share of the span the phone wasn't asleep. History counts: job = job starts, alarm = "
          "alarm deliveries, wakelock = times the app was the first to hold the phone awake, longwake = wakelocks held "
          "over a minute, fg = foreground-service starts.")
    rep.p("**Spans meeting the look-closer threshold:** " + ("; ".join(
        f"{fmt_t(s['start'])}–{fmt_t(s['end'], False)} {s['rate']:.2f} %/h (others {s['base']:.2f})" for s in flagged)
        if flagged else "none."))
    for s in st:
        s["dur"] = (s["end"] - s["start"]).total_seconds()
    out.csv("stretches.csv", ["start", "end", "screen", "seconds", "level_start", "level_end", "awake_s",
                              "mobile_radio_s", "gps_s", "apps"],
            [(s["start"].isoformat(), s["end"].isoformat(), "on" if s["key"][0] else "off", round(s["dur"]), s["l0"],
              s["l1"], round(overlap(ctx.running, s["start"], s["end"])),
              round(flag_seconds(rows_bh, s["start"], s["end"], "+mobile_radio")),
              round(flag_seconds(rows_bh, s["start"], s["end"], "+gps")),
              fmt_activity(ctx, app_activity(ctx, s["start"], s["end"]), 10)) for s in st])
    out.csv("screen_off_spans.csv", ["start", "end", "seconds", "glances", "glance_s", "level_start", "level_end",
                                     "pct_per_h", "baseline", "awake_s", "mobile_radio_s", "gps_s", "flag", "apps"],
            [(s["start"].isoformat(), s["end"].isoformat(), round(s["dur"]), s["glances"], round(s["glance_s"]),
              s["l0"], s["l1"], None if s["rate"] is None else round(s["rate"], 3),
              None if s.get("base") is None else round(s["base"], 3), round(s["awake"]), round(s["mrad"]),
              round(s["gps"]), "look" if s in flagged else "", fmt_activity(ctx, s["act"], 10)) for s in spans])
    rep.p(f"Every unplugged screen-on and screen-off stretch ({len(st)}) is in `data/stretches.csv`; all screen-off "
          "spans, rated or not, in `data/screen_off_spans.csv`.")


def r_hourly(ctx):
    rows = ctx.bh["rows"]
    if not rows:
        return
    t = rows[0]["t"].replace(minute=0, second=0, microsecond=0)
    end = rows[-1]["t"]
    out = []
    while t < end:
        b = t + timedelta(hours=1)
        r0, r1 = bh_state_at(ctx, max(t, rows[0]["t"])), bh_state_at(ctx, min(b, end))
        scr = flag_seconds(rows, t, b, "+screen")
        plug = flag_seconds(rows, t, b, "+plugged")
        act = app_activity(ctx, t, b)
        out.append((t.isoformat(), r0["level"] if r0 else None, r1["level"] if r1 else None, round(scr), round(plug),
                    round(overlap(ctx.running, t, b)), round(flag_seconds(rows, t, b, "+mobile_radio")),
                    round(flag_seconds(rows, t, b, "+gps")), round(flag_seconds(rows, t, b, "+camera")),
                    fmt_activity(ctx, act, 6)))
        t = b
    ctx.out.csv("hourly.csv", ["hour", "level_start", "level_end", "screen_on_s", "plugged_s", "awake_s",
                               "mobile_radio_s", "gps_s", "camera_s", "apps"], out)
    ctx.rep.p("Per-hour figures (level, screen, plugged, awake, mobile radio, GPS, camera, most active apps) are in "
              "`data/hourly.csv`.")


def r_apps(ctx):
    rep = ctx.rep
    rep.h(2, "4. Per app, since the last full charge")
    U, P = ctx.uidfull, ctx.power
    hours = None
    m = getattr(ctx, "charge_meta", {}).get("Time on battery")
    if m:
        hours = (parse_dur(m[0].split("(")[0]) or 0) / 3600 or None
    tab = []
    for uid, st in U.items():
        a = appid_of(uid)
        if a is None or a < 10000:
            continue
        pw = P.get(uid, {})
        bgp = sum(x for x in (pw.get("bg"), pw.get("fgs"), pw.get("cached")) if x) if pw.get("bg") is not None else None
        gps = (st.get("sensors") or {}).get("GPS")
        row = {"uid": uid, "name": ctx.uidname(uid), "google": pkg_is_google(ctx, uid=uid),
               "mah": pw.get("total"), "bg_mah": bgp, "wl_bg": st.get("wl_bg"), "wl_actual": st.get("wl_actual"),
               "alarms": st.get("wakeup_alarms", 0), "jobs": st.get("job_count", 0), "job_sec": st.get("job_sec", 0),
               "gps": gps[0] if gps else None, "gps_bg": gps[2] if gps else None, "cpu": st.get("cpu"),
               "bgtime": st.get("state_background"), "fgs": st.get("state_fg_service"),
               "mob_tx": st.get("mobile_tx"), "wifi_tx": st.get("wifi_tx"), "line": st["line"]}
        tab.append(row)
    if not tab:
        rep.p("**problem:** no per-app blocks parsed; check 'Statistics since last charge' by hand.")
        return
    short = hours is None or hours < MIN_CHARGE_H
    if short:
        rep.p(f"**Only {fmt_dur(hours * 3600) if hours else 'an unknown time'} on battery since the last charge.** "
              f"The per-app rules need at least {MIN_CHARGE_H:g} h, so nothing below is flagged; take the bug report "
              "after the phone has been off the charger for a while (e.g. the morning after a night unplugged). "
              "Sections 3 and 5 (battery history, about a day) still apply.")

    def top(key):
        r = [x for x in tab if x.get(key)]
        return {x["uid"] for x in sorted(r, key=lambda x: -x[key])[:TOP_N]}
    t_bg, t_wl = top("bg_mah") if any(x.get("bg_mah") for x in tab) else top("mah"), top("wl_bg") or top("wl_actual")
    flags = []
    for x in tab:
        why = []
        if not x["google"]:
            if x["uid"] in t_bg:
                why.append(f"top {TOP_N} background power")
            if x["uid"] in t_wl:
                why.append(f"top {TOP_N} background wakelock")
            if x["gps"]:
                why.append("GPS")
            if hours and x["alarms"] / hours >= ALARMS_PER_H:
                why.append(f"{x['alarms'] / hours:.1f} wakeup alarms/h")
        x["why"] = "" if short else ", ".join(why)
        if x["why"]:
            flags.append(x)
    ctx.app_flags = flags
    rep.p(f"Look closer: a non-Google app that is in the top {TOP_N} for background power or background wakelock "
          f"time, uses GPS, or averages ≥ {ALARMS_PER_H:g} wakeup alarms an hour, **and** whose function doesn't "
          "explain it. Ordinary: messaging, calling, music/podcasts, navigation and ride-hailing during a trip, "
          "fitness tracking, cloud photo/backup, security apps, your launcher and keyboard.")
    tab.sort(key=lambda x: -((x["bg_mah"] if x["bg_mah"] is not None else x["mah"]) or 0))

    def f(x, d=1):
        return "-" if x is None else f"{x:.{d}f}"
    rep.table(["app (uid)", "mAh", "bg+fgs+cached mAh", "bg wakelock", "wakeup alarms", "jobs", "GPS (bg)",
               "CPU", "fg service", "mobile tx MB", "look closer", "ref"],
              [(x["name"], f(x["mah"]), f(x["bg_mah"]), fmt_dur(x["wl_bg"] if x["wl_bg"] is not None else x["wl_actual"]),
                x["alarms"], x["jobs"], (f"{fmt_dur(x['gps'])} ({fmt_dur(x['gps_bg'])})" if x["gps"] else "-"),
                fmt_dur(x["cpu"]), fmt_dur(x["fgs"]), f((x["mob_tx"] or 0) / 1e6), x["why"], f"L{x['line']}")
               for x in tab], limit=40, more="data/apps.csv")
    ctx.out.csv("apps.csv", list(tab[0].keys()), [list(x.values()) for x in tab])
    rep.p("**Non-Google apps meeting a look-closer rule:** " +
          ("; ".join(f"{x['name']} ({x['why']})" for x in flags) if flags else "none."))
    if ctx.wl_global:
        rep.h(3, "Top partial wakelocks (all apps and system)")
        g = sorted(ctx.wl_global, key=lambda w: -(w["sec"] or 0))[:20]
        rep.table(["holder", "tag", "time", "times", "ref"],
                  [(ctx.uidname(w["uid"]), w["tag"][:90], fmt_dur(w["sec"]), w["count"], f"L{w['line']}") for w in g])


def r_longwake(ctx):
    rep = ctx.rep
    rep.h(2, "5. Wakelocks held over a minute (battery history)")
    open_, rows = {}, []
    for t, ln, sign, key, uid, val in ctx.bh["app"]:
        if key != "longwake" or not sign:      # unsigned entries restate what's already held
            continue
        k = (uid, val)
        if sign == "+":
            open_.setdefault(k, (t, ln))
        elif k in open_:
            t0, l0 = open_.pop(k)
            rows.append((t0, t, uid, val, l0, True))
    end = ctx.bh["rows"][-1]["t"] if ctx.bh["rows"] else None
    for (uid, val), (t0, l0) in open_.items():
        rows.append((t0, end, uid, val, l0, False))
    rows.sort()
    minute = timedelta(seconds=LONGWAKE_MIN_S)
    rep.p("Android marks a wakelock \"long\" once it has been held for a minute, so each one was taken about a minute "
          "before the time shown and held for the length shown (which includes that minute). Look closer: a non-Google "
          "app holding the phone awake for long periods with the screen off and nothing of its own on screen. Ordinary: "
          "music (AudioMix), calls, navigation, downloads, app jobs and sync, the system and Play services.")
    tab, per = [], collections.defaultdict(lambda: [0, 0.0, 0])
    for a, b, u, v, l0, closed in rows:
        held = (b - a).total_seconds() + LONGWAKE_MIN_S if b else None
        scr = "on" if (bh_state_at(ctx, a - minute) or {}).get("+screen") else "off"
        tab.append((fmt_t(a - minute), fmt_t(b, False) if b else "-",
                    (fmt_dur(held) if closed else f">= {fmt_dur(held)} (held at end of history)") if held else "-",
                    ctx.uidname(u), v[:80], scr, f"L{l0}"))
        if not pkg_is_google(ctx, uid=u):
            p = per[u]
            p[0] += 1
            p[1] += held or 0
            p[2] += scr == "off"
    rep.table(["taken (approx.)", "released", "held", "holder", "tag", "screen when taken", "ref"], tab, limit=60,
              more="data/longwake.csv")
    ctx.out.csv("longwake.csv", ["taken_approx", "released", "held_s", "uid", "holder", "tag", "line"],
                [((a - minute).isoformat(), b.isoformat() if b else "", round((b - a).total_seconds() + LONGWAKE_MIN_S)
                  if b else "", u, ctx.uidname(u), v, l0) for a, b, u, v, l0, c in rows])
    ctx.longwake_ng = per
    rep.p("**Non-Google holders:** " + ("; ".join(f"{ctx.uidname(u)}: {n}x, {fmt_dur(t)} in all, {off} taken with "
                                                  f"the screen off" for u, (n, t, off) in
                                                  sorted(per.items(), key=lambda kv: -kv[1][1])) or "none."))


def r_alarms(ctx):
    rep = ctx.rep
    rep.h(2, "6. Alarms (AlarmManager top alarms)")
    svc = ctx.br.service("alarm")
    rows, on = [], False
    if svc:
        for i in range(svc[0], svc[1] + 1):
            l = ctx.br.L[i]
            if l.strip().startswith("Top Alarms:"):
                on = True
                continue
            if on:
                m = re.match(r"^\s+\+?(\S+) running, (\d+) wakeups?, (\d+) alarms?: (\S+?):(\S+)", l)
                if m:
                    rows.append((m.group(5), ctx.uidname(m.group(4)), int(m.group(2)), int(m.group(3)),
                                 fmt_dur(parse_dur(m.group(1))), f"L{i + 1}"))
                elif l.strip() and not l.startswith("      ") and not l.strip().startswith("*"):
                    if rows:
                        break
    if not rows:
        rep.p("_(Top Alarms list not found in `dumpsys alarm`)_")
        return
    rep.p("Wakeups wake the phone from sleep. Look closer: a non-Google app with many wakeups that its function "
          "doesn't explain.")
    rep.table(["package", "uid", "wakeups", "alarms", "time running", "ref"], rows)
    ctx.alarms_ng = [r for r in rows if not is_google(r[0]) and r[2] > 0]


def r_location(ctx):
    rep = ctx.rep
    rep.h(2, "7. Location requests by app (since boot)")
    svc = ctx.br.service("location")
    rows, prov, on = [], None, False
    if svc:
        for i in range(svc[0], svc[1] + 1):
            l = ctx.br.L[i]
            if "Historical Aggregate Location Provider Data" in l:
                on = True
                continue
            if not on:
                continue
            if "Historical Aggregate" in l:
                break
            m = re.match(r"^\s+(\w+)(?: provider)?:\s*$", l)
            if m:
                prov = m.group(1)
                continue
            m = re.match(r"^\s+(?:(\d+)/)?([\w.]+)(?:\[([^\]]*)\])?: min/max interval = (\S+)/(\S+), total/active/"
                         r"foreground duration = (\S+)/(\S+)/(\S+), locations = (\d+)", l)
            if m:
                uid, pkg, tag = m.group(1), m.group(2), m.group(3)
                g = is_google(pkg) or (uid is not None and int(uid) % 100000 < 10000)
                rows.append((prov, pkg + (f" [{tag}]" if tag else ""), m.group(4), fmt_dur(parse_dur(m.group(6))),
                             fmt_dur(parse_dur(m.group(7))), fmt_dur(parse_dur(m.group(8))), int(m.group(9)),
                             "" if g else "non-Google", f"L{i + 1}"))
    if not rows:
        rep.p("_(Historical location data not found in `dumpsys location`)_")
        return
    rep.p("Total = time the request existed, active = time it was being served, foreground = time the app was in "
          "the foreground. Look closer: a non-Google app with long active, non-foreground requests and no location "
          "function. Ordinary: maps, weather, ride-hailing, delivery, fitness, Find My Device, Play services.")
    rows.sort(key=lambda r: (r[7] == "", r[1]))
    rep.table(["provider", "package", "min interval", "total", "active", "foreground", "fixes", "", "ref"], rows)


def r_wakeups(ctx):
    rep = ctx.rep
    rep.h(2, "8. Why the CPU woke (kernel wakeup reasons)")
    c = collections.Counter(r for t, ln, r in ctx.wr_hist)
    rep.p(f"In the history window ({len(ctx.wr_hist)} wakeups):")
    rep.table(["wakeup reason", "count"], c.most_common(15))
    if ctx.wakeup_reasons:
        rep.p("Since the last charge:")
        rep.table(["wakeup reason", "time", "count", "ref"],
                  [(w["reason"][:90], fmt_dur(w["sec"]), w["count"], f"L{w['line']}")
                   for w in sorted(ctx.wakeup_reasons, key=lambda w: -w["count"])[:15]])
    rep.p("These are hardware interrupt names (modem, Wi-Fi, alarm timer, sensors). They say which chip woke the "
          "phone, not which app asked; read them together with sections 3 and 6.")


def r_events(ctx):
    if not ctx.events:
        return
    rep = ctx.rep
    rep.h(2, "9. Event windows")
    bef, aft = timedelta(seconds=ctx.args.before), timedelta(seconds=ctx.args.after)
    rows_bh = ctx.bh["rows"]
    for t0, label in ctx.events:
        a, b = t0 - bef, t0 + aft
        rep.h(3, f"{label} - {t0} (window {fmt_t(a)} -> {fmt_t(b, False)})")
        if not rows_bh or rows_bh[0]["t"] > a or rows_bh[-1]["t"] < b:
            rep.p("Battery history does not cover the whole window.")
        r0, r1 = bh_state_at(ctx, a), bh_state_at(ctx, b)
        rep.p(f"Level {r0['level'] if r0 else '?'} → {r1['level'] if r1 else '?'} %; CPU awake "
              f"{fmt_dur(overlap(ctx.running, a, b))}; screen on {fmt_dur(flag_seconds(rows_bh, a, b, '+screen'))}; "
              f"mobile radio {fmt_dur(flag_seconds(rows_bh, a, b, '+mobile_radio'))}; GPS "
              f"{fmt_dur(flag_seconds(rows_bh, a, b, '+gps'))}.")
        ev = []
        for e in ctx.bh["events"]:
            if a <= e[0] <= b and e[2] in ("+screen", "+plugged", "+gps", "+mobile_radio", "+camera", "+audio",
                                           "+wifi_scan", "+ble_scan", "+flashlight", "+video"):
                ev.append((e[0], "battery", f"{e[2]} {e[3]} -> {e[4]}", f"L{e[1]}"))
        for t, ln, sign, key, uid, val in ctx.bh["app"]:
            if a <= t <= b:
                ev.append((t, "app", f"{sign}{key} {ctx.uidname(uid)} {val}"[:140], f"L{ln}"))
        for t, ln, uid, tag in ctx.wl_hist:
            if a <= t <= b:
                ev.append((t, "wakelock", f"{ctx.uidname(uid)} {tag}"[:140], f"L{ln}"))
        for t, ln, r in ctx.wr_hist:
            if a <= t <= b:
                ev.append((t, "wakeup", r[:140], f"L{ln}"))
        ev.sort(key=lambda x: x[0])
        rep.table(["time", "source", "event", "ref"], [(fmt_t(t), s, e, r) for t, s, e, r in ev], limit=250)


def r_glance(ctx):
    rows = []
    fs = getattr(ctx, "flagged_stretches", [])
    rows.append(("Screen-off spans with unusually high drain", str(len(fs)) + (
        " (" + "; ".join(f"{fmt_t(s['start'])} {s['rate']:.1f} %/h" for s in fs[:4]) + ")" if fs else ""), "section 3"))
    af = getattr(ctx, "app_flags", [])
    rows.append(("Non-Google apps meeting a per-app rule", ", ".join(x["name"] for x in af) or "none", "section 4"))
    lw = getattr(ctx, "longwake_ng", {})
    rows.append(("Non-Google wakelocks over a minute (screen off when taken)",
                 "; ".join(f"{ctx.uidname(u)} {n}x ({off})" for u, (n, t, off) in
                           sorted(lw.items(), key=lambda kv: -kv[1][1])) or "none", "section 5"))
    al = getattr(ctx, "alarms_ng", [])
    rows.append(("Non-Google apps with wakeup alarms (top list)", ", ".join(f"{r[0]} {r[2]}" for r in al[:6]) or "none",
                 "section 6"))
    from .common import Report
    mini = Report()
    mini.h(2, "At a glance (neutral checks; details in the sections named)")
    mini.table(["check", "result", "where"], rows)
    ctx.rep.parts[2:2] = mini.parts


# ---------------------------------------------------------------------------------------------- main

def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(prog=prog, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="bug report .zip, extracted folder, or bugreport-*.txt")
    ap.add_argument("--out", required=True, help="new output folder (must not exist)")
    ap.add_argument("--event", action="append", default=[], help='"YYYY-MM-DDTHH:MM:SS|label" in device local time')
    ap.add_argument("--before", type=float, default=900.0)
    ap.add_argument("--after", type=float, default=300.0)
    args = ap.parse_args(argv)
    if os.path.exists(args.out):
        sys.exit(f"--out {args.out} already exists; choose a new folder so earlier results are never overwritten")
    os.makedirs(args.out)
    ctx = Ctx(args)
    ctx.out = Out(args.out)
    rep = ctx.rep
    man = {"tool": "batpass.py", "version": VERSION, "tool_sha256": sha256_file(os.path.abspath(__file__)),
           "toolkit_sha256": toolkit_sha256(), "python": sys.version.split()[0],
           "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "input": os.path.abspath(args.input),
           "events": args.event}
    main_txt = open_input(ctx, args.input, man)
    if not main_txt:
        sys.exit("could not find the main bugreport-*.txt")
    man["main_txt"], man["main_txt_sha256"] = main_txt, sha256_file(main_txt)
    ctx.br = BR(main_txt, rep.problems)
    part(ctx, "identity", p_identity)
    parse_events(ctx, args.event)
    ctx.running, ctx.wl_hist, ctx.wr_hist, ctx.uidfull, ctx.wl_global, ctx.wakeup_reasons, ctx.power = [], [], [], {}, [], [], {}
    part(ctx, "battery history", p_battery_history)
    if ctx.bh is None:
        ctx.bh = {"rows": [], "events": [], "app": [], "range": (0, 0), "mismatch": 0, "markers": []}
    part(ctx, "battery history extras", hist_extras)
    part(ctx, "batterystats per-uid", p_uidstats_full)
    rep.p("# Battery pass\n")
    rep.p(f"Input `{os.path.basename(args.input)}`" + (f" (SHA-256 `{man['input_sha256']}`)" if man.get("input_sha256") else "")
          + f"; main text `{os.path.basename(main_txt)}` (SHA-256 `{man['main_txt_sha256']}`). batpass.py {VERSION} "
          f"(toolkit SHA-256 `{man['toolkit_sha256'][:16]}…`), run {man['run_utc']} UTC. Line numbers (L…) refer to "
          "the main text file. Times are device local time.")
    for name, fn in (("identity report", r_identity), ("coverage", r_coverage), ("discharge", r_discharge),
                     ("hourly", r_hourly), ("apps", r_apps), ("longwake", r_longwake), ("alarms", r_alarms),
                     ("location", r_location), ("wakeups", r_wakeups), ("event windows", r_events),
                     ("at a glance", r_glance)):
        part(ctx, name, fn)
    rep.h(2, "10. Run notes")
    rep.bullets([f"batpass.py {VERSION}; Python {man['python']}"] + [f"problem: {p}" for p in rep.problems]
                or ["no problems"])
    with open(os.path.join(args.out, "report.md"), "w") as fh:
        fh.write(rep.text())
    man["outputs"] = sorted(os.path.relpath(p, args.out) for p in ctx.out.files) + ["report.md"]
    man["problems"] = rep.problems
    with open(os.path.join(args.out, "manifest.json"), "w") as fh:
        json.dump(man, fh, indent=1, default=str)
    print(f"report: {os.path.join(args.out, 'report.md')}  problems: {len(rep.problems)}")
    for p in rep.problems:
        print("  -", p)


if __name__ == "__main__":
    main()
