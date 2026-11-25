#!/usr/bin/env python3
"""rfpass.py - Android bug-report radio pass: wireless analyzer (repeatable; Python 3.9+ standard library only).

Reads an Android bug report (the .zip from the phone, an extracted folder, or the main
bugreport-*.txt) and writes a Markdown report plus CSV/JSONL tables covering:

  identity & log coverage | cellular (signal, RAT/band, ciphers, 2G, PLMN/TAC, NITZ, radio power,
  data stalls) | Wi-Fi (saved networks, connections, BSSIDs, station events, scans by app,
  airplane toggles) | mobile data vs Wi-Fi (hourly bytes, cellular bring-ups, validation probes) |
  airplane-mode intervals | Bluetooth (HCI snoop sessions, initiator, app holding the link, pairing,
  advertisers by UUID, the phone's own advertising sets, scanners by app, media control timeline) |
  app attribution (process state of apps doing Bluetooth work) | remote-control surfaces
  (accessibility, device admins, notification listeners, ADB, verified boot) | event windows.

Every table cites bug-report line numbers or btsnoop record numbers where practical. Inputs are
never modified: a zip is hashed, then extracted into <out>/extracted (read-only copies).

Usage
  python3 -I stalkeraware.py wireless <bugreport.zip | folder | bugreport-*.txt> --out <new folder>
                    [--event "2026-01-15T10:51:04|signal drop"] ...   (device local time)
                    [--before 120] [--after 120]                          (event window, seconds)
                    [--keep-big]                                          (also dump every battery-history line)

Capturing a useful bug report
  * Keep Developer options > "Enable Bluetooth HCI snoop log" set to Enabled (full), so the zip carries
    FS/data/misc/bluetooth/logs/btsnoop_hci.log*.
  * Take the report (Developer options > Take bug report > Full report) as soon as possible after an
    event: the radio logcat holds well under a minute, SystemUI's signal log a few minutes, the
    telephony registry log 15-20 minutes; battery history (signal, Wi-Fi, app state) covers about a day.
  * Note the event time to the second and pass it with --event.

Notes
  * Times are device local time (persist.sys.timezone); btsnoop times are converted to it.
  * Masked addresses (XX:XX:XX:XX:ab:cd) in Android dumps are matched to HCI addresses by the
    last two bytes only; such matches are labelled "suffix match".
  * Nothing here proves how anything was done; the report states what the logs record.
"""
import argparse
import bisect
import collections
import hashlib
import json
import os
import re
import struct
import sys
import zipfile
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

from .common import (BR, Ctx, Out, Report, app_state, bh_state_at, fmt_dur, fmt_t, integrate, iso,
                     locate_main_txt, locate_snoops, mac, p_battery_history, p_identity, p_logcat_coverage,
                     part, pct, pt_seconds, r_coverage, r_identity, safe_extract, sha256_file, suffix2,
                     toolkit_sha256, uid_of_pkg)

VERSION = "1.1.0 (2026-11-24)"
EPOCH_DELTA = 0x00DCDDB30F2F8000          # btsnoop: microseconds from year 0 to 1970-01-01


# ----------------------------------------------------------------------------------------------
# cellular
# ----------------------------------------------------------------------------------------------


def r_cellular(ctx):
    rep, out = ctx.rep, ctx.out
    rows, events = ctx.bh["rows"], ctx.bh["events"]
    rep.h(2, "2. Cellular")
    if not rows:
        rep.p("No battery history.")
        return
    a, b = rows[0]["t"], rows[-1]["t"]
    rep.p(f"Battery history {fmt_t(a)} -> {fmt_t(b)} (lines L{ctx.bh['range'][0]}-L{ctx.bh['range'][1]}); "
          f"text-vs-state-word signal mismatches: {ctx.bh['mismatch']}.")

    def summary(name, keep):
        dur = collections.Counter()
        tot = ins = 0.0
        for x, y in zip(rows, rows[1:]):
            if not keep(x):
                continue
            d = (y["t"] - x["t"]).total_seconds()
            if d <= 0:
                continue
            tot += d
            dur[x["phone_signal_strength"]] += d
            if x["phone_state"] in (None, "in"):
                ins += d
        ev = [e for e in events if keep(bh_state_at(ctx, e[0]) or {})]
        lvl = [e for e in ev if e[2] == "phone_signal_strength" and e[3] is not None]
        poor = [e for e in lvl if e[4] == "poor"]
        rat = [e for e in ev if e[2] == "data_conn" and e[3] is not None and {e[3], e[4]} == {"lte", "nr"}]
        nr = [e for e in ev if e[2] == "nr_state" and e[3] is not None]
        return (name, fmt_dur(tot), pct(ins, tot), ", ".join(f"{k}={pct(v, tot)}" for k, v in dur.most_common()),
                len(lvl), len(poor), len(rat), len(nr))

    rep.h(3, "Signal summary")
    rep.table(["period", "time", "in service", "time at level", "level changes", "drops to poor", "LTE<->NR",
               "nr_state changes"],
              [summary("whole history", lambda r: True),
               summary("Wi-Fi associated", lambda r: r.get("wifi_suppl") == "completed"),
               summary("Wi-Fi not associated", lambda r: r.get("wifi_suppl") != "completed")])
    rep.p("'Level' is the bar level Android computed (none/poor/moderate/good/great). 'In service' counts "
          "phone_state 'in'.")

    # half-hour table
    def bucket(t):
        return t.replace(minute=(t.minute // 30) * 30, second=0, microsecond=0)
    B = collections.defaultdict(lambda: collections.Counter())
    for e in events:
        if e[3] is None:
            continue
        k = bucket(e[0])
        if e[2] == "phone_signal_strength":
            B[k]["lvl"] += 1
            if e[4] == "poor":
                B[k]["to_poor"] += 1
        elif e[2] == "data_conn" and {e[3], e[4]} == {"lte", "nr"}:
            B[k]["rat"] += 1
        elif e[2] == "nr_state":
            B[k]["nr"] += 1
    for x, y in zip(rows, rows[1:]):
        t = x["t"]
        while t < y["t"]:
            nb = bucket(t) + timedelta(minutes=30)
            se = min(y["t"], nb)
            d = (se - t).total_seconds()
            c = B[bucket(t)]
            c["dur"] += d
            if x["phone_signal_strength"] == "poor":
                c["poor"] += d
            if x["phone_signal_strength"] == "great":
                c["great"] += d
            if x["phone_signal_strength"] == "none":
                c["none"] += d
            if x["phone_state"] not in (None, "in"):
                c["oos"] += d
            if x["wifi_suppl"] == "completed":
                c["wifi"] += d
            if x["screen"]:
                c["screen"] += d
            if x["+cellular_high_tx_power"]:
                c["hitx"] += d
            if x["+mobile_radio"]:
                c["mrad"] += d
            t = se
    hh = []
    for k in sorted(B):
        c = B[k]
        if c["dur"] <= 0:
            continue
        hh.append((k.strftime("%m-%d %H:%M"), c["lvl"], c["to_poor"], c["rat"], c["nr"], pct(c["poor"], c["dur"]),
                   pct(c["great"], c["dur"]), f"{c['none']:.0f}", f"{c['oos']:.0f}", pct(c["wifi"], c["dur"]),
                   pct(c["screen"], c["dur"]), pct(c["mrad"], c["dur"]), pct(c["hitx"], c["dur"])))
    hdr = ["half hour", "level chg", "to poor", "LTE<->NR", "nr chg", "poor", "great", "none s", "not in service s",
           "Wi-Fi assoc", "screen on", "mobile radio active", "high TX power"]
    f = out.csv("cell_halfhour.csv", hdr, hh)
    rep.h(3, "Half-hour view")
    rep.table(hdr, hh, limit=80, more=f)

    # poor intervals
    net = [(e[0], e) for e in events if e[2] in ("data_conn", "nr_state") and e[3] is not None]
    nt = [x[0] for x in net]
    poor_iv, cur = [], None
    for r in rows:
        if r["phone_signal_strength"] == "poor" and cur is None:
            cur = r
        elif r["phone_signal_strength"] != "poor" and cur is not None:
            st = cur["t"]
            i = bisect.bisect_right(nt, st) - 1
            j = bisect.bisect_left(nt, r["t"])
            prev = f"{net[i][1][2]} {net[i][1][3]}->{net[i][1][4]} {(st - net[i][0]).total_seconds() * 1000:+.0f} ms before" if i >= 0 else "-"
            nxt = f"{net[j][1][2]} {net[j][1][3]}->{net[j][1][4]} {(net[j][0] - r['t']).total_seconds() * 1000:.0f} ms after" if j < len(net) else "-"
            poor_iv.append((fmt_t(st), fmt_t(r["t"], False), f"{(r['t'] - st).total_seconds():.1f}", cur["data_conn"],
                            cur["wifi_suppl"], prev, nxt, r["phone_signal_strength"], f"L{cur['line']}-L{r['line']}"))
            cur = None
    hdr = ["poor from", "to", "s", "data_conn", "wifi_suppl", "previous network change", "next network change",
           "back to", "lines"]
    f = out.csv("cell_poor_intervals.csv", hdr, poor_iv)
    rep.h(3, f"Intervals at level 'poor' ({len(poor_iv)})")
    rep.table(hdr, poor_iv, limit=40, more=f)

    # coupling
    lvl_ev = [e[0] for e in events if e[2] == "phone_signal_strength" and e[3] is not None]
    to_poor = [e[0] for e in events if e[2] == "phone_signal_strength" and e[3] is not None and e[4] == "poor"]
    span = (b - a).total_seconds()

    def near(t, w):
        i = bisect.bisect_left(nt, t - w)
        return i < len(nt) and nt[i] <= t + w
    crow = []
    for wms in (100, 250, 1000, 3000):
        w = timedelta(milliseconds=wms)
        if not lvl_ev or not nt:
            break
        obs = sum(near(t, w) for t in lvl_ev) / len(lvl_ev)
        cov, cs, ce = 0.0, None, None
        for t in nt:
            s, e = t - w, t + w
            if ce is None or s > ce:
                if ce is not None:
                    cov += (ce - cs).total_seconds()
                cs, ce = s, e
            else:
                ce = max(ce, e)
        cov += (ce - cs).total_seconds()
        crow.append((f"+-{wms} ms", f"{100 * obs:.1f}%", f"{100 * cov / span:.1f}%",
                     f"{sum(near(t, w) for t in to_poor)}/{len(to_poor)}"))
    rep.h(3, "Do bar changes coincide with network-type changes?")
    rep.table(["window", "level changes within window of a data_conn/nr_state change", "expected by chance",
               "drops to poor within window"], crow)

    # phone_state / scanning / none / oos
    ps = [(fmt_t(e[0]), f"L{e[1]}", e[2], e[3], e[4]) for e in events
          if e[2] in ("phone_state", "+phone_scanning") or (e[2] == "phone_signal_strength" and e[4] == "none")
          or (e[2] == "data_conn" and e[4] in ("oos", "none"))]
    rep.h(3, "Service-state changes (phone_state, scanning, level none, data out of service)")
    rep.table(["time", "line", "key", "from", "to"], ps, limit=60)


REG_SS = re.compile(r"^\s+(\d{4}-\d\d-\d\dT[\d:.]+) - notifyServiceStateForSubscriber: subId=(-?\d+) phoneId=(\d+) state=(.*)$")


def p_registry(ctx):
    br = ctx.br
    svc = br.service("telephony.registry")
    if not svc:
        raise RuntimeError("telephony.registry dump not found")
    L = br.L
    loc = br.find("local logs:", svc[0], svc[1], exact=True)
    kinds = collections.Counter()
    first = last = None
    if loc is not None:
        for i in range(loc + 1, svc[1] + 1):
            m = re.match(r"^\s+(\d{4}-\d\d-\d\dT[\d:.]+) - (\w+)", L[i])
            if not m:
                continue
            t = iso(m.group(1))
            kinds[m.group(2)] += 1
            first = first or t
            last = t
            m2 = REG_SS.match(L[i])
            if m2:
                st = m2.group(4)

                def g(p, s=st):
                    x = re.search(p, s)
                    return x.group(1) if x else None
                bw = g(r"mCellBandwidths=\[([^\]]*)\]") or ""
                bands = re.findall(r"domain=PS transportType=WWAN.*?mBands ?= ?\[([^\]]*)\]", st)
                ctx.reg.append({"t": t, "line": i + 1, "sub": m2.group(2), "phone": m2.group(3),
                                "rat": g(r"getRilDataRadioTechnology=\d+\((\w+)\)") or "?",
                                "ch": g(r"mChannelNumber=(-?\d+)"), "bw": bw,
                                "ncc": len([x for x in bw.split(",") if x.strip()]),
                                "band": bands[0] if bands else "?", "vreg": g(r"mVoiceRegState=(\d\(\w+\))"),
                                "dreg": g(r"mDataRegState=(\d\(\w+\))"), "op": g(r"mOperatorAlphaLong=([^,]*)"),
                                "nrfr": g(r"mNrFrequencyRange=(-?\d+)")})
    ctx.reg.sort(key=lambda r: r["t"])
    if first:
        ctx.coverage.append(("telephony.registry local log", first, last, sum(kinds.values()), f"L{loc + 1}"))
    ctx.reg_kinds = kinds
    # current state lines
    cur = {}
    for i in range(svc[0], (loc or svc[1])):
        for key in ("mAllowedNetworkTypeReason", "mAllowedNetworkTypeValue", "mNetworkSecurityEvents",
                    "mIsDataEnabled", "mCarrierPrivilegeState", "mDataEnabledReason"):
            if L[i].strip().startswith(key + "="):
                cur.setdefault(key, (L[i].strip().split("=", 1)[1], i + 1))
    ctx.reg_cur = cur


# Android TelephonyManager.NETWORK_TYPE_BITMASK_* bits (1 << (NETWORK_TYPE - 1))
NT_BITS = {1: "GPRS", 2: "EDGE", 3: "UMTS", 4: "CDMA", 5: "EVDO_0", 6: "EVDO_A", 7: "1xRTT", 8: "HSDPA",
           9: "HSUPA", 10: "HSPA", 11: "IDEN", 12: "EVDO_B", 13: "LTE", 14: "EHRPD", 15: "HSPAP", 16: "GSM",
           17: "TD_SCDMA", 18: "IWLAN", 19: "LTE_CA", 20: "NR"}
TWO_G = {"GPRS", "EDGE", "CDMA", "1xRTT", "IDEN", "GSM"}
NT_REASONS = {0: "USER", 1: "POWER", 2: "CARRIER", 3: "ENABLE_2G (2G toggle)", 4: "USER_RESTRICTIONS"}


def r_registry(ctx):
    rep, out = ctx.rep, ctx.out
    rep.h(3, "Serving network log (telephony.registry)")
    reg = ctx.reg
    if not reg:
        rep.p("No service-state entries.")
        return
    rep.p(f"{len(reg)} service-state entries {fmt_t(reg[0]['t'])} -> {fmt_t(reg[-1]['t'])}; "
          f"entry kinds: {dict(ctx.reg_kinds)}.")
    hdr = ["time", "line", "sub", "phone", "data RAT", "channel", "carriers", "bandwidths kHz", "PS band", "voice reg",
           "data reg", "operator"]
    rows = [(fmt_t(r["t"]), r["line"], r["sub"], r["phone"], r["rat"], r["ch"], r["ncc"], r["bw"], r["band"], r["vreg"],
             r["dreg"], r["op"]) for r in reg]
    f = out.csv("cell_registry.csv", hdr, rows)
    # time-weighted summary per (phone, rat, band, ncc)
    agg = collections.defaultdict(lambda: [0, 0.0])
    for x, y in zip(reg, reg[1:] + [None]):
        k = (x["phone"], x["rat"], x["band"], x["ncc"], x["ch"])
        agg[k][0] += 1
        if y is not None and y["phone"] == x["phone"]:
            agg[k][1] += (y["t"] - x["t"]).total_seconds()
    rep.table(["phone", "data RAT", "PS band", "carriers", "channel", "entries", "time until next entry"],
              [(k[0], k[1], k[2], k[3], k[4], v[0], fmt_dur(v[1])) for k, v in sorted(agg.items(), key=lambda kv: -kv[1][1])],
              limit=25, more=f)
    rep.p(f"Full timeline: {f}.")
    cur = ctx.reg_cur
    rep.h(3, "Network-type restrictions and security state")
    rows = []
    if "mAllowedNetworkTypeValue" in cur:
        v = int(cur["mAllowedNetworkTypeValue"][0])
        types = [n for bit, n in NT_BITS.items() if v & (1 << (bit - 1))]
        two = sorted(TWO_G & set(types))
        reason = cur.get("mAllowedNetworkTypeReason", ("?", None))[0]
        try:
            reason_s = NT_REASONS.get(int(reason), reason)
        except ValueError:
            reason_s = reason
        rows.append(("allowed network types (last notification)", f"{v} = {'|'.join(types)}",
                     f"L{cur['mAllowedNetworkTypeValue'][1]}"))
        rows.append(("  reason of that notification", reason_s, f"L{cur.get('mAllowedNetworkTypeReason', ('', '?'))[1]}"))
        rows.append(("  2G types allowed", ", ".join(two) if two else "none (2G excluded)", ""))
    for k in ("mNetworkSecurityEvents", "mIsDataEnabled", "mCarrierPrivilegeState"):
        if k in cur:
            rows.append((k, cur[k][0][:120], f"L{cur[k][1]}"))
    rep.table(["item", "value", "ref"], rows)


def p_radio_log(ctx):
    br, L = ctx.br, ctx.br.L
    sec = br.section("RADIO LOG")
    ctx.radio = {"ss": [], "alg": collections.Counter(), "alg_rows": [], "notifier": collections.Counter(),
                 "cells_reg": collections.OrderedDict(), "cells_ci": collections.OrderedDict(), "sec": sec}
    if not sec:
        return
    R = ctx.radio
    for i in range(sec[0], sec[1] + 1):
        l = L[i]
        if len(l) < 19 or not l[0].isdigit():
            continue
        if "notifySignalStrength:" in l:
            t = ctx.ytime(l[0:2], l[3:5], l[6:8], l[9:11], l[12:14], l[15:18])

            def g(p):
                m = re.search(p, l)
                return m.group(1) if m else None
            lte = re.search(r"mLte=CellSignalStrengthLte: rssi=(-?\d+) rsrp=(-?\d+) rsrq=(-?\d+) rssnr=(-?\d+).*?level=(\d+)", l)
            nr = re.search(r"ssRsrp = (-?\d+) ssRsrq = (-?\d+) ssSinr = (-?\d+) level = (\d+)", l)
            inv = "2147483647"
            R["ss"].append({"t": t, "line": i + 1, "level": g(r"notifySignalStrength: level=(\d+)"),
                            "voice": g(r"voiceRat=(\w+)"), "data": g(r"dataRat=(\w+)"),
                            "lte_rsrp": lte.group(2) if lte and lte.group(2) != inv else None,
                            "lte_rsrq": lte.group(3) if lte and lte.group(2) != inv else None,
                            "lte_lvl": lte.group(5) if lte else None,
                            "nr_rsrp": nr.group(1) if nr and nr.group(1) != inv else None,
                            "nr_sinr": nr.group(3) if nr and nr.group(1) != inv else None,
                            "nr_lvl": nr.group(4) if nr else None, "primary": g(r"primary=(\w+)")})
        elif "SecurityAlgorithmUpdate{" in l:
            m = re.search(r"connectionEvent: (\w+), encryption: (\w+), integrity: (\w+), isUnprotectedEmergency: (\w+)", l)
            if m:
                R["alg"][m.groups()] += 1
                R["alg_rows"].append((l[:18], i + 1) + m.groups())
        elif "NullCipherNotifier" in l and ("Notifier is disabled" in l or "enabled" in l.lower()):
            R["notifier"][l.split(": ", 1)[-1].strip()[:80]] += 1
        elif "RmmNwHdlr" in l:
            t = l[6:18]
            m = re.search(r"\[(handleCsInd|handlePsInd)\]\[\w+\] stat=(\d+), lac=([^,]+), cid=([^,]+), eAct=(\d+)", l)
            if m:
                k = m.groups()
                v = R["cells_reg"].setdefault(k, [t, t, 0, i + 1])
                v[1] = t
                v[2] += 1
            m = re.search(r"\] (NR|LTE):state = (\d+), registred=(\d+), plmn = (\d*),\s*pscPci = ([^,]+), (nr_arfcn|earfcn) = (\d+), cid = ([^,]+), tac = ([^,]+),.*?band = (\d+)", l)
            if m:
                k = (m.group(1), m.group(4), m.group(5), m.group(7), m.group(8), m.group(9), m.group(10))
                v = R["cells_ci"].setdefault(k, [t, t, 0, i + 1])
                v[1] = t
                v[2] += 1


def r_radio(ctx):
    rep, out = ctx.rep, ctx.out
    R = ctx.radio
    rep.h(3, "Ciphering reported by the modem (radio log)")
    if not R["sec"]:
        rep.p("No radio log section.")
        return
    rows = [(k[0], k[1], k[2], k[3], v, "NULL/UNPROTECTED" if (k[1] in NULL_ALGS or k[2] in NULL_ALGS or k[3] == "true") else "")
            for k, v in sorted(R["alg"].items(), key=lambda kv: -kv[1])]
    rep.table(["connection event", "encryption", "integrity", "unprotected emergency", "count", "flag"], rows)
    if R["alg_rows"]:
        out.csv("cell_cipher_updates.csv", ["time", "line", "event", "encryption", "integrity", "unprotected_emergency"],
                R["alg_rows"])
    rep.p("NEA0/EEA0 (no encryption) or NIA0/EIA0 (no integrity) would be flagged here. 'UNKNOWN' means the modem did "
          "not report that algorithm; it is not the same as NULL. Null-cipher notifier messages: "
          + (", ".join(f"'{k}' x{v}" for k, v in R["notifier"].items()) or "none") + ".")
    ss = R["ss"]
    if ss:
        hdr = ["time", "line", "level", "voice", "data", "LTE rsrp", "LTE rsrq", "LTE lvl", "NR ssRsrp", "NR sinr",
               "NR lvl", "primary"]
        f = out.csv("cell_radio_signal.csv", hdr, [(fmt_t(s["t"]), s["line"], s["level"], s["voice"], s["data"],
                                                    s["lte_rsrp"], s["lte_rsrq"], s["lte_lvl"], s["nr_rsrp"],
                                                    s["nr_sinr"], s["nr_lvl"], s["primary"]) for s in ss])
        rep.p(f"Radio-log signal reports: {len(ss)} ({fmt_t(ss[0]['t'])} -> {fmt_t(ss[-1]['t'])}); levels "
              f"{dict(collections.Counter(s['level'] for s in ss))}. Table: {f}.")
    if R["cells_reg"] or R["cells_ci"]:
        rep.h(3, "Serving-cell identifiers in the radio log (modem RIL; partially masked by Android)")
        rep.table(["domain", "stat", "lac/tac", "cell id", "eAct", "first", "last", "count", "first line"],
                  [k + tuple(v) for k, v in R["cells_reg"].items()], limit=20)
        rep.table(["RAT", "PLMN", "PCI", "ARFCN", "cell id", "TAC", "band", "first", "last", "count", "first line"],
                  [k + tuple(v) for k, v in R["cells_ci"].items()], limit=20)


WIFI_CTRL_CMDS = {"CMD_AIRPLANE_TOGGLED", "CMD_WIFI_TOGGLED", "CMD_SCAN_ALWAYS_MODE_CHANGED", "CMD_EMERGENCY_MODE_CHANGED",
                  "CMD_EMERGENCY_CALL_STATE_CHANGED", "CMD_EMERGENCY_SCAN_STATE_CHANGED", "CMD_SET_AP", "CMD_AP_STOPPED",
                  "CMD_STA_STOPPED", "CMD_STA_START_FAILURE", "CMD_RECOVERY_RESTART_WIFI", "CMD_RECOVERY_DISABLE_WIFI",
                  "CMD_DEFERRED_RECOVERY_RESTART_WIFI", "CMD_SATELLITE_MODE_CHANGED", "CMD_AP_START_FAILURE",
                  "CMD_UPDATE_AP_CONFIG", "CMD_UPDATE_AP_CAPABILITY"}
NULL_ALGS = {"NEA0", "EEA0", "NIA0", "EIA0", "GEA0", "A5_0", "A50", "SIP_NULL", "SRTP_NULL", "IMS_NULL",
             "SIP_NO_INTEGRITY", "ENCR_NULL", "AUTH_HMAC_NULL"}


def p_mobileinput(ctx):
    br, L = ctx.br, ctx.br.L
    s = br.find("BUFFER MobileInputLog:", exact=True)
    ctx.mil = []
    if s is None:
        return
    for i in range(s + 1, min(s + 20000, len(L))):
        l = L[i]
        if l.strip().startswith("-----"):
            continue
        m = re.match(r"^\s+(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3}) \w (\w+): (.*)$", l)
        if not m:
            if l.strip().startswith("BUFFER ") or (l.strip() and not l.startswith("    ")):
                break
            continue
        t = ctx.ytime(*m.groups()[:6])
        msg = m.group(8)
        row = {"t": t, "line": i + 1, "msg": msg[:60]}
        if "onSignalStrengthsChanged" in msg:
            lte = re.search(r"rsrp=(-?\d+)", msg)
            nr = re.search(r"ssRsrp = (-?\d+)", msg)
            prim = re.search(r"primary=(\w+)", msg)
            row.update(kind="signal", lte=int(lte.group(1)) if lte else None, nr=int(nr.group(1)) if nr else None,
                       primary=prim.group(1) if prim else "?")
        else:
            row["kind"] = msg.split(":", 1)[0]
        ctx.mil.append(row)
    if ctx.mil:
        ctx.coverage.append(("SystemUI MobileInputLog", ctx.mil[0]["t"], ctx.mil[-1]["t"], len(ctx.mil), f"L{s + 1}"))


def r_signal_by_band(ctx):
    rep = ctx.rep
    sig = [m for m in ctx.mil if m.get("kind") == "signal"]
    reg = [r for r in ctx.reg if r["phone"] == "0"]
    if not sig or not reg:
        return
    rt = [r["t"] for r in reg]
    agg = collections.defaultdict(list)
    for m in sig:
        j = bisect.bisect_right(rt, m["t"]) - 1
        if j < 0:
            continue
        settled = (m["t"] - reg[j]["t"]).total_seconds() >= 0.3
        if m["primary"].endswith("Nr"):
            v, kind = m["nr"], "NR ssRsrp"
        else:
            v, kind = m["lte"], "LTE rsrp"
        if v is None or v == 2147483647:
            continue
        agg[(f"{reg[j]['rat']} band {reg[j]['band']}", kind, "settled" if settled else "<0.3 s after change")].append(v)
    rep.h(3, "Signal readings by serving band (SystemUI log joined to the registry state)")
    rep.table(["serving state", "primary measurement", "timing", "n", "min dBm", "median", "max"],
              [(k[0], k[1], k[2], len(v), min(v), sorted(v)[len(v) // 2], max(v)) for k, v in sorted(agg.items())])


def p_carrier_config(ctx):
    br, L = ctx.br, ctx.br.L
    svc = br.service("carrier_config")
    ctx.cc = []
    if not svc:
        return
    phone = sub = None
    keys = ("lte_rsrp_thresholds_int_array", "5g_nr_ssrsrp_thresholds_int_array", "lte_rsrq_thresholds_int_array",
            "lte_rssnr_thresholds_int_array", "5g_nr_sssinr_thresholds_int_array",
            "parameters_used_for_lte_signal_bar_int", "parameters_use_for_5g_nr_signal_bar_int")
    for i in range(svc[0], svc[1] + 1):
        l = L[i]
        m = re.match(r"^Phone Id = (\d+)", l)
        if m:
            phone = m.group(1)
            continue
        if l.strip().startswith("Default Values from CarrierConfigManager"):
            phone, sub = "-", "platform defaults"
            continue
        m = re.match(r"^    (m\w+) : ?(.*)$", l)
        if m:
            sub = m.group(1)
            if m.group(2).strip() not in ("", "null"):
                ctx.cc.append((phone, sub, "(block)", m.group(2).strip()[:60], i + 1))
            continue
        s = l.strip()
        for k in keys:
            if s.startswith(k + " = "):
                ctx.cc.append((phone, sub, k, s.split(" = ", 1)[1], i + 1))


def r_carrier_config(ctx):
    rep = ctx.rep
    if not ctx.cc:
        return
    rep.h(3, "Signal-bar thresholds (carrier_config)")
    rep.table(["phone", "config layer", "key", "value", "line"], ctx.cc)
    rep.p("Layers other than mConfigFromDefaultApp being non-null (carrier app, overrides) would mean the defaults "
          "were changed on this phone.")


def p_tds(ctx):
    """TelephonyDebugService: radio power log, data networks, data-stall log, NITZ."""
    br, L = ctx.br, ctx.br.L
    i0 = br.find("SERVICE com.android.phone/.TelephonyDebugService")
    ctx.tds = {"power": [], "stall": [], "nitz": [], "tz": collections.Counter(), "nitz_sig": None}
    if i0 is None:
        return
    # end: next "SERVICE " line at the same level
    i1 = None
    for i in range(i0 + 1, len(L)):
        if L[i].startswith("SERVICE ") or L[i].startswith("------ "):
            i1 = i - 1
            break
    i1 = i1 or len(L) - 1
    T = ctx.tds
    T["range"] = (i0 + 1, i1 + 1)
    p = br.find("Radio power Log:", i0, i1)
    if p is not None:
        for i in range(p + 1, min(p + 400, i1)):
            m = re.match(r"^\s+(\d{4}-\d\d-\d\dT[\d:.]+) - (.*)$", L[i])
            if not m:
                if L[i].strip():
                    break
                continue
            msg = m.group(2)
            des = re.search(r"mDesiredPowerState=(\w+)", msg)
            rs = re.search(r"getRadioState=(\d)", msg)
            why = re.search(r"mRadioPowerOffReasons=\[([^\]]*)\]", msg)
            T["power"].append((iso(m.group(1)), i + 1, des.group(1) if des else msg[:60],
                               rs.group(1) if rs else "", why.group(1) if why else ""))
    for s in range(i0, i1 + 1):
        if re.match(r"^\s+DataStallRecoveryManager-\d+:\s*$", L[s]):
            ind = len(L[s]) - len(L[s].lstrip())
            for i in range(s + 1, min(s + 800, i1)):
                l = L[i]
                if l.strip() and len(l) - len(l.lstrip()) <= ind:
                    break
                m = re.match(r"^\s+(\d{4}-\d\d-\d\dT[\d:.]+) - (.*)$", l)
                if m:
                    T["stall"].append((iso(m.group(1)), i + 1, m.group(2)[:140]))
            break
    # data networks
    dn = None
    for i in range(i0, i1 + 1):
        l = L[i]
        m = re.match(r"^\s+Tag: (DN-(\d+)-\w+)", l)
        if m:
            dn = {"tag": m.group(1), "id": int(m.group(2)), "apn": None, "setup": None, "teardown": None,
                  "reason": None, "disc": None, "line": i + 1, "access": None}
            ctx.dn.append(dn)
            continue
        if dn is None:
            continue
        if "mDataProfile=[DataProfile=[ApnSetting]" in l and dn["apn"] is None:
            m = re.search(r"\[ApnSetting\] ([^,]+),", l)
            dn["apn"] = m.group(1) if m else "?"
        m = re.match(r"^\s+(\d{4}-\d\d-\d\dT[\d:.]+) - (\w+): (.*)$", l)
        if m:
            t, stt, msg = iso(m.group(1)), m.group(2), m.group(3)
            if msg.startswith("setupData:") and dn["setup"] is None:
                dn["setup"] = t
                a = re.search(r"accessNetwork=(\w+)", msg)
                dn["access"] = a.group(1) if a else None
                if dn["apn"] is None:
                    a = re.search(r"\[ApnSetting\] ([^,]+),", msg)
                    dn["apn"] = a.group(1) if a else None
            elif "onTearDown" in msg:
                dn["teardown"] = t
                r = re.search(r"reason=(\w+)", msg)
                dn["reason"] = r.group(1) if r else msg[:40]
            elif stt == "DisconnectedState" and "disconnected" in msg:
                dn["disc"] = t
        if l.strip().startswith("DataNetwork:") or "curState=" in l:
            pass
    # NITZ time suggestions and zone suggestions
    for i in range(i0, i1 + 1):
        l = L[i]
        if "Sending time suggestion" in l:
            m = re.search(r"(PT[\dHMS.]+) / (\d{4}-\d\d-\d\dT[\d:.]+)Z - Sending time suggestion: .*?mElapsedRealtimeMillis=(\d+), mUnixEpochTimeMillis=(\d+)", l)
            if m:
                log_el = pt_seconds(m.group(1))
                log_wall = datetime.fromisoformat(m.group(2)).replace(tzinfo=timezone.utc)
                rec_el = int(m.group(3)) / 1000.0
                nitz = int(m.group(4)) / 1000.0
                dev_at_receipt = log_wall.timestamp() - (log_el - rec_el)
                T["nitz"].append((log_wall.astimezone(ctx.tz).replace(tzinfo=None), i + 1, nitz - dev_at_receipt))
        elif "Suggesting time zone update" in l:
            m = re.search(r"mZoneId='([^']*)', mCountryIsoCode='([^']*)'", l)
            if m:
                T["tz"][m.groups()] += 1
        elif "mLatestNitzSignal=" in l and T["nitz_sig"] is None:
            m = re.search(r"mOriginalString=([^,]+,[^,]+)", l)
            T["nitz_sig"] = (m.group(1) if m else l.strip()[:80], i + 1)


def r_tds(ctx):
    rep, out = ctx.rep, ctx.out
    T = ctx.tds
    if not T.get("range"):
        return
    rep.h(3, "Radio power requests (TelephonyDebugService)")
    rep.table(["time", "line", "desired power on", "radio state (0 off, 1 on, 2 unavailable)", "power-off reasons"],
              [(fmt_t(t), ln, d, rs, why) for t, ln, d, rs, why in T["power"]])
    rep.p("Reason 0 is a user request (airplane mode); other reasons (thermal, carrier, nearby device) would show "
          "other numbers.")
    if T["stall"]:
        rep.h(3, "Data-stall recovery log")
        rep.table(["time", "line", "entry"], [(fmt_t(t), ln, m) for t, ln, m in T["stall"]], limit=40)
    if T["nitz"]:
        offs = [o for _, _, o in T["nitz"]]
        big = [(fmt_t(t), ln, f"{o:+.2f}") for t, ln, o in T["nitz"] if abs(o) > 2.0]
        rep.h(3, "Network time (NITZ) vs the phone clock")
        rep.p(f"{len(offs)} NITZ time suggestions; network-minus-phone offset at receipt: min {min(offs):+.2f} s, "
              f"max {max(offs):+.2f} s (NITZ carries whole seconds, so about +-1 s is normal). Time-zone suggestions: "
              + ", ".join(f"{z} / {c} x{n}" for (z, c), n in T["tz"].items())
              + (f". Latest NITZ string: {T['nitz_sig'][0]} (L{T['nitz_sig'][1]})." if T["nitz_sig"] else "."))
        if big:
            rep.p("Offsets larger than 2 s:")
            rep.table(["time", "line", "offset s"], big, limit=20)


def p_ims_aos(ctx):
    br, L = ctx.br, ctx.br.L
    ctx.aos = {"plmn": [], "air": [], "wifi": []}
    # IMS service log lines (Pixel 'Aos' local log) - search the APP SERVICES section region
    sec = br.section("APP SERVICES PLATFORM")
    rng = range(sec[0], sec[1] + 1) if sec else range(len(L))
    seen = set()
    for i in rng:
        l = L[i]
        if "J2N_NOTIFY_" not in l:
            continue
        m = re.match(r"^\s+(\d{4}-\d\d-\d\dT[\d:.]+) - J2N_NOTIFY_(PLMN_CHANGED|AIRPLANE_SETTING|WIFI_SETTING): (.*)$", l)
        if not m:
            continue
        t, kind, msg = iso(m.group(1)), m.group(2), m.group(3)
        key = (t.replace(microsecond=(t.microsecond // 100000) * 100000) if t else None, kind, msg)
        if key in seen:
            continue
        seen.add(key)
        if kind == "PLMN_CHANGED":
            ctx.aos["plmn"].append((t, i + 1, msg))
        elif kind == "AIRPLANE_SETTING":
            ctx.aos["air"].append((t, i + 1, "true" in msg))
        else:
            ctx.aos["wifi"].append((t, i + 1, msg))


def p_lbe_tac(ctx):
    L = ctx.br.L
    ctx.tacs = collections.Counter()
    for i, l in enumerate(L):
        if "Plmn" in l and "Rat" in l and "Tac" in l:
            m = re.match(r"^\s+Plmn(\d+)Rat(\w+?)Tac(\d+)Link\d+Level\d+(?:Count|Data) : (\d+)", l)
            if m and m.group(3) != "2147483647":
                ctx.tacs[(m.group(1), m.group(2), int(m.group(3)))] += 1


def r_plmn(ctx):
    rep = ctx.rep
    rep.h(3, "Operator (PLMN) and tracking areas")
    rows = [(fmt_t(t), ln, msg) for t, ln, msg in sorted(ctx.aos["plmn"])]
    rep.p("PLMN changes reported to the IMS service:")
    rep.table(["time", "line", "entry"], rows, limit=30)
    if ctx.tacs:
        rep.p("Tracking-area codes recorded by Android's bandwidth estimator (persistent statistics):")
        rep.table(["PLMN", "RAT", "TAC", "TAC hex", "keys"],
                  [(p, r, t, f"0x{t:X}", n) for (p, r, t), n in sorted(ctx.tacs.items())])


# ----------------------------------------------------------------------------------------------
# Wi-Fi
# ----------------------------------------------------------------------------------------------


def p_wifi(ctx):
    br, L = ctx.br, ctx.br.L
    svc = br.service("wifi")
    ctx.wifi = {"nets": [], "metrics": [], "unusable": [], "ctrl": [], "svc": svc}
    if not svc:
        raise RuntimeError("wifi dump not found")
    W = ctx.wifi
    s, e = svc
    # configured networks
    a = br.find("WifiConfigManager - Configured networks Begin", s, e)
    if a is not None:
        cur = None
        for i in range(a + 1, e + 1):
            l = L[i]
            if l.startswith("WifiConfigManager - Configured networks End"):
                break
            m = re.match(r'^ID: (\d+) SSID: (".*?"|\S+) PROVIDER-NAME: (.*?) BSSID: (\S+) FQDN: (.*?) HOME-PROVIDER-NETWORK: (\w+) PRIO: \d+ HIDDEN: (\w+) PMF: (\w+)', l)
            if m:
                cur = {"id": m.group(1), "ssid": m.group(2), "provider": m.group(3), "fqdn": m.group(5),
                       "hidden": m.group(7), "pmf": m.group(8), "line": i + 1, "keymgmt": None, "ever": None,
                       "macrand": None, "assoc": None, "last": None, "creator": None, "autojoin": None,
                       "connected": "Currently Connected: true" in l}
                W["nets"].append(cur)
                continue
            if not cur:
                continue
            st = l.strip()
            if st.startswith("KeyMgmt:") and cur["keymgmt"] is None:
                cur["keymgmt"] = st.split()[1] if len(st.split()) > 1 else ""
            elif st.startswith("hasEverConnected:"):
                cur["ever"] = st.split(":", 1)[1].strip()
            elif st.startswith("macRandomizationSetting:"):
                cur["macrand"] = st.split(":", 1)[1].strip()
            elif st.startswith("numAssociation"):
                cur["assoc"] = st.split()[-1]
            elif st.startswith("lastConnected:"):
                cur["last"] = st.split(":", 1)[1].strip()
            elif st.startswith("cuid="):
                m2 = re.search(r"cname=(\S+)", st)
                cur["creator"] = m2.group(1) if m2 else None
                m2 = re.search(r"allowAutojoin=(\w+)", st)
                cur["autojoin"] = m2.group(1) if m2 else None
    # connection events
    a = br.find("mConnectionEvents:", s, e, exact=True)
    if a is not None:
        for i in range(a + 1, e + 1):
            l = L[i]
            if not l.startswith("startTime="):
                if l.strip() and not l.startswith(" "):
                    break
                continue
            m = re.match(r"startTime=(\d+)-(\d+) (\d+):(\d+):(\d+)\.(\d+), SSID=(\".*?\"|[^,]*), BSSID=([^,]*), durationMillis=(\d+), roamType=(\w+), connectionResult=(\d+), level2FailureCode=(\w+), connectivityLevelFailureCode=(\w+), signalStrength=(-?\d+)", l)
            if not m:
                continue
            g = m.groups()
            t = ctx.ytime(g[0], g[1], g[2], g[3], g[4], int(g[5]))
            ch = re.search(r"mChannelInfo=(\d+)", l)
            ctx.wconn.append({"t": t, "line": i + 1, "ssid": g[6], "bssid": g[7], "ms": int(g[8]), "roam": g[9],
                              "ok": g[10] == "1", "l2fail": g[11], "connfail": g[12], "rssi": int(g[13]),
                              "freq": ch.group(1) if ch else None, "screen": "screenOn=true" in l})
    # metrics key=value lines
    for i in range(s, e + 1):
        l = L[i]
        if l.startswith("mWifiLogProto."):
            k, _, v = l[len("mWifiLogProto."):].partition("=")
            if re.search(r"Passpoint|SoftAp|P2p|Suggestion|Hidden|Open|Enterprise|SavedNetworks|MacRandom|Toggl|Airplane|Wps|Dpp", k):
                W["metrics"].append((k, v.strip()[:60], i + 1))
    # station events
    a = br.find("StaEventList:", s, e, exact=True)
    if a is not None:
        for i in range(a + 1, e + 1):
            l = L[i].strip()
            m = re.match(r"^(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3}) (\w+)(.*)$", l)
            if not m:
                if l and not L[i].startswith(" ") and ctx.sta:
                    break
                continue
            t = ctx.ytime(*m.groups()[:6])
            rest = m.group(8)

            def gi(k):
                x = re.search(k + r"=(-?\d+)", rest)
                return int(x.group(1)) if x else None
            cd = re.search(r"cellularData=(\w+)", rest)
            ctx.sta.append({"t": t, "line": i + 1, "type": m.group(7), "mtx": gi("mobileTxBytes"),
                            "mrx": gi("mobileRxBytes"), "ttx": gi("totalTxBytes"), "trx": gi("totalRxBytes"),
                            "rssi": gi("lastRssi"), "freq": gi("lastFreq"), "reason": gi("reason"),
                            "cell": cd.group(1) if cd else None, "screen": "screenOn=true" in rest})
        if ctx.sta:
            ctx.coverage.append(("Wi-Fi StaEventList", ctx.sta[0]["t"], ctx.sta[-1]["t"], len(ctx.sta), f"L{a + 1}"))
    a = br.find("WifiIsUnusableEventList:", s, e)
    if a is not None:
        for i in range(a + 1, min(a + 200, e)):
            l = L[i]
            m = re.match(r"^(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3}) (\S+(?: \(\d+\))?) (.*)$", l)
            if not m:
                break
            W["unusable"].append((ctx.ytime(*m.groups()[:6]), i + 1, m.group(7)))
    # Wi-Fi controller records (who toggled Wi-Fi / airplane)
    for i in range(s, e + 1):
        l = L[i]
        if "rec[" in l and "what=CMD_" in l and "time=" in l:
            m = re.search(r"time=(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3}) processed=(\w+) org=(\w+) dest=(\S+) what=(\w+)(.*)$", l)
            if m and m.group(10) in WIFI_CTRL_CMDS:
                ws = re.search(r"WorkSource\{([^}]*)\}", m.group(11))
                ar = re.match(r"\s+(-?\d+) (-?\d+)", m.group(11))
                W["ctrl"].append((ctx.ytime(*m.groups()[:6]), i + 1, m.group(10) + (f" {ar.group(1)}" if ar else ""),
                                  m.group(8), m.group(9), ws.group(1) if ws else ""))


def r_wifi(ctx):
    rep, out = ctx.rep, ctx.out
    W = ctx.wifi
    rep.h(2, "3. Wi-Fi")
    rep.h(3, "Saved networks")
    rep.table(["id", "SSID", "key mgmt", "hidden", "PMF", "MAC randomization", "ever connected", "associations",
               "last connected", "created by", "autojoin", "FQDN (Passpoint)", "line"],
              [(n["id"], n["ssid"], n["keymgmt"], n["hidden"], n["pmf"],
                {"3": "auto (3)", "2": "non-persistent (2)", "1": "persistent (1)", "0": "OFF (0)"}.get(n["macrand"], n["macrand"]),
                n["ever"], n["assoc"], n["last"], n["creator"], n["autojoin"], n["fqdn"], n["line"]) for n in W["nets"]])
    rep.h(3, "Connection attempts and access points (BSSIDs)")
    hdr = ["time", "SSID", "BSSID", "result", "L2 failure", "connectivity failure", "RSSI", "MHz", "screen on", "line"]
    rows = [(fmt_t(c["t"]), c["ssid"], c["bssid"], "ok" if c["ok"] else "FAIL", c["l2fail"], c["connfail"], c["rssi"],
             c["freq"], c["screen"], c["line"]) for c in ctx.wconn]
    f = out.csv("wifi_connections.csv", hdr, rows)
    rep.table(hdr, rows, limit=40, more=f)
    per = collections.defaultdict(lambda: collections.Counter())
    for c in ctx.wconn:
        per[c["ssid"]][(c["bssid"], c["freq"])] += 1
    rep.table(["SSID", "BSSID", "MHz", "attempts"],
              [(s, b, fq, n) for s, c in per.items() for (b, fq), n in c.most_common()])
    rep.p("A second BSSID per SSID on another band from the same access point is normal (e.g. cc:... and ce:... "
          "differing only in the first byte). An unfamiliar BSSID for a saved SSID is what to look for.")
    if ctx.sta:
        rep.h(3, "Station events")
        cnt = collections.Counter(s["type"] for s in ctx.sta)
        rep.p("Counts: " + ", ".join(f"{k} {v}" for k, v in cnt.most_common()))
        keep = ("CMD_ASSOCIATED_BSSID", "NETWORK_CONNECTION_EVENT", "NETWORK_DISCONNECTION_EVENT",
                "CMD_IP_CONFIGURATION_SUCCESSFUL", "CMD_IP_CONFIGURATION_LOST", "NETWORK_AGENT_VALID_NETWORK",
                "CMD_START_CONNECT", "CMD_START_ROAM", "WIFI_ENABLED", "WIFI_DISABLED", "MAC_CHANGE",
                "AUTHENTICATION_FAILURE_EVENT", "ASSOCIATION_REJECTION_EVENT", "CMD_TARGET_BSSID",
                "FRAMEWORK_DISCONNECT", "SUPPLICANT_STATE_CHANGE_EVENT")
        hdr = ["time", "type", "reason", "RSSI", "MHz", "cellularData", "screen on", "line"]
        rows = [(fmt_t(s["t"]), s["type"], s["reason"], s["rssi"], s["freq"], s["cell"], s["screen"], s["line"])
                for s in ctx.sta if s["type"] in keep]
        f = out.csv("wifi_sta_events.csv", hdr, [(fmt_t(s["t"]), s["type"], s["reason"], s["rssi"], s["freq"], s["cell"],
                                                   s["screen"], s["line"]) for s in ctx.sta])
        rep.table(hdr, rows, limit=50, more=f)
    if W["unusable"]:
        rep.h(3, "Wi-Fi 'unusable' events")
        rep.table(["time", "line", "type"], [(fmt_t(t), ln, k) for t, ln, k in W["unusable"]], limit=30)
    if W["ctrl"]:
        rep.h(3, "Wi-Fi controller commands (with requesting app where recorded)")
        grp = collections.OrderedDict()
        for t, ln, w, o, d, ws in W["ctrl"]:
            g = grp.setdefault((w, ws), [0, t, t])
            g[0] += 1
            g[2] = t
        rep.table(["command", "requested by (WorkSource)", "count", "first", "last"],
                  [(k[0], k[1], v[0], fmt_t(v[1]), fmt_t(v[2])) for k, v in grp.items()])
        rare = [(fmt_t(t), w, o, d, ws, ln) for t, ln, w, o, d, ws in W["ctrl"] if grp[(w, ws)][0] <= 6]
        if rare:
            rep.p("Individual commands (types seen 6 times or fewer):")
            rep.table(["time", "command", "from state", "to state", "requested by (WorkSource)", "line"], rare, limit=40)
        f = out.csv("wifi_controller.csv", ["time", "command", "from", "to", "worksource", "line"],
                    [(fmt_t(t), w, o, d, ws, ln) for t, ln, w, o, d, ws in W["ctrl"]])
        rep.p(f"All commands: {f}. The number after a command is its first argument (for CMD_SET_AP and "
              "CMD_EMERGENCY_SCAN_STATE_CHANGED: 1 = start, 0 = stop).")
    if W["metrics"]:
        rep.h(3, "Wi-Fi metrics: saved, hidden, Passpoint, hotspot, P2P, suggestions")
        rep.table(["metric", "value", "line"], W["metrics"], limit=60)
    # scans by app
    rows = []
    for uid, st in ctx.uidstats.items():
        if "wifi_scan" in st:
            rows.append((ctx.uidname(uid), st["wifi_scan"][0], st["wifi_scan"][1]))
    if rows:
        rep.h(3, "Wi-Fi scans attributed to apps (batterystats, since the last charge)")
        rep.table(["app / uid", "scan time", "scans"], sorted(rows, key=lambda r: -int(r[2] or 0)))


# ----------------------------------------------------------------------------------------------
# batterystats per-UID, process exits, integrity
# ----------------------------------------------------------------------------------------------


def p_uidstats(ctx):
    L = ctx.br.L
    s = ctx.br.find("Statistics since last charge:")
    if s is None:
        return
    uid = None
    ctx.since_charge = None
    for i in range(s, min(s + 400000, len(L))):
        l = L[i]
        if l.startswith("  Start clock time:") and ctx.since_charge is None:
            ctx.since_charge = l.split(":", 1)[1].strip()
        if l.startswith("  Total run time:") and not hasattr(ctx, "total_run"):
            ctx.total_run = l.split(":", 1)[1].strip()
        m = re.match(r"^  (u\d+a\d+|\d+):\s*$", l)
        if m:
            uid = m.group(1)
            ctx.uidstats.setdefault(uid, {"line": i + 1})
            continue
        if l and not l.startswith(" ") and uid:
            break
        if uid is None or not l.startswith("    "):
            continue
        st = ctx.uidstats[uid]
        t = l.strip()
        m = re.match(r"Wifi Scan \(blamed\): (.+?) \([\d.]+%\) (\d+)x", t)
        if m:
            st["wifi_scan"] = (m.group(1), m.group(2))
        m = re.match(r"Bluetooth Scan \(total actual realtime\): (.+?)\s+\((\d+) times\)", t)
        if m:
            st["bt_scan"] = (m.group(1), m.group(2))
        m = re.match(r"Bluetooth Scan \(background realtime\): (.+?)\s+\((\d+) times\)", t)
        if m:
            st["bt_scan_bg"] = (m.group(1), m.group(2))
        m = re.match(r"Bluetooth Scan Results: (\d+) \((\d+) in background\)", t)
        if m:
            st["bt_results"] = (m.group(1), m.group(2))
        for key in ("Top for", "Fg Service for", "Background for", "Cached for", "Total running",
                    "Foreground services"):
            if t.startswith(key + ":"):
                st[key] = t.split(":", 1)[1].strip()
        m = re.match(r"Mobile network: (.+?) received, (.+?) sent", t)
        if m:
            st["mobile"] = (m.group(1), m.group(2))
        m = re.match(r"Wi-Fi network: (.+?) received, (.+?) sent", t)
        if m:
            st["wifi"] = (m.group(1), m.group(2))
        m = re.match(r"Proc (\S+):", t)
        if m:
            st.setdefault("procs", []).append(m.group(1))
        m = re.match(r"(\d+) starts", t)
        if m and st.get("procs"):
            st.setdefault("starts", []).append((st["procs"][-1], int(m.group(1))))


def p_exits(ctx):
    br, L = ctx.br, ctx.br.L
    sec = br.section("ACTIVITY MANAGER PROCESS EXIT INFO")
    s = sec[0] if sec else br.find("ACTIVITY MANAGER PROCESS EXIT INFO")
    if s is None:
        return
    e = sec[1] if sec else min(s + 60000, len(L) - 1)
    pkg = None
    cur = None
    for i in range(s, e + 1):
        l = L[i]
        m = re.match(r"^  package: (\S+)", l)
        if m:
            pkg = m.group(1)
            continue
        m = re.search(r"timestamp=(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) pid=(\d+) realUid=(\d+) packageUid=(\d+)", l)
        if m:
            cur = {"t": datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f"), "pid": m.group(2), "pkg": pkg,
                   "line": i + 1, "process": None, "reason": None, "desc": None, "importance": None}
            ctx.exits.append(cur)
            continue
        if cur is None:
            continue
        m = re.search(r"process=(\S+) reason=(\d+ \([^)]*\))(?: subreason=(\d+ \([^)]*\)))?", l)
        if m:
            cur["process"] = m.group(1)
            cur["reason"] = m.group(2) + (" / " + m.group(3) if m.group(3) else "")
        m = re.search(r"importance=(\d+)", l)
        if m and cur["importance"] is None:
            cur["importance"] = m.group(1)
        m = re.search(r"description=(.*)$", l)
        if m:
            cur["desc"] = m.group(1).strip()
    # pid -> process name for current processes (who requested task removals)
    ctx.pidname = {}
    for i, l in enumerate(L):
        if "ProcessRecord{" in l:
            for m in re.finditer(r"ProcessRecord\{\w+ (\d+):([\w.:]+)/", l):
                ctx.pidname.setdefault(m.group(1), m.group(2))


def r_integrity(ctx):
    rep, br, L, S = ctx.rep, ctx.br, ctx.br.L, ctx.settings
    rep.h(2, "9. Remote-control surfaces and device integrity")
    rows = []
    for k in ("ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.boot.vbmeta.device_state", "ro.debuggable"):
        if k in ctx.props:
            rows.append((k, ctx.props[k][0], f"L{ctx.props[k][1]}"))
    for k in ("adb_enabled", "adb_wifi_enabled", "development_settings_enabled", "install_non_market_apps",
              "enabled_accessibility_services", "accessibility_enabled", "enabled_notification_listeners",
              "private_dns_mode", "private_dns_specifier", "ble_scan_always_enabled", "wifi_scan_always_enabled",
              "airplane_mode_on", "bluetooth_on", "wifi_on", "mobile_data", "location_mode", "nearby_sharing_enabled"):
        if k in S:
            v = S[k][0]
            rows.append((f"setting {k}", v[:150] + ("..." if len(v) > 150 else ""), f"L{S[k][2]}"))
    svc = br.service("accessibility")
    if svc:
        for i in range(svc[0], svc[1] + 1):
            st = L[i].strip()
            if st.startswith("Enabled services:") or st.startswith("Bound services:"):
                rows.append(("accessibility " + st.split(":", 1)[0], st.split(":", 1)[1][:150], f"L{i + 1}"))
    svc = br.service("device_policy")
    if svc:
        a = br.find("Enabled Device Admins", svc[0], svc[1])
        if a is not None:
            admins = []
            for i in range(a + 1, min(a + 60, svc[1])):
                if "mPasswordOwner" in L[i]:
                    break
                m = re.match(r"^\s+([\w.]+/[\w.$]+):?\s*$", L[i])
                if m:
                    admins.append(m.group(1))
            rows.append(("device admins", ", ".join(admins) if admins else "none", f"L{a + 1}"))
    a = br.find("All notification listeners (", 0)
    if a is not None:
        lst = []
        for i in range(a + 1, a + 40):
            m = re.search(r"ComponentInfo\{([^/}]+)/", L[i])
            if not m or "Live notification listeners" in L[i]:
                break
            lst.append(m.group(1))
        rows.append(("enabled notification listeners", ", ".join(lst), f"L{a + 1}"))
    rep.table(["item", "value", "ref"], rows)
    rep.p("Accessibility services are the usual way an app drives the screen for someone else; device admins and "
          "notification listeners are the other common surveillance surfaces.")
    # installs in battery history
    inst = [(fmt_t(t), ln, sign + key, uid, val) for t, ln, sign, key, uid, val in ctx.bh["app"]
            if key in ("pkginst", "pkgunin")] if ctx.bh else []
    if inst:
        rep.h(3, "Package installs/removals during the battery history")
        rep.table(["time", "line", "event", "version code (as printed in the uid slot)", "package"], inst)
    # task removals by requesting pid
    rem = [x for x in ctx.exits if x["desc"] and x["desc"].startswith("remove-by-pid#")]
    if rem:
        by = collections.Counter(x["desc"].split("#")[1] for x in rem)
        rep.h(3, "Apps removed from Recents (process exit records)")
        rep.p("Requesting process: " + ", ".join(f"pid {p} = {ctx.pidname.get(p, 'not running now')} x{n}"
                                                for p, n in by.items())
              + ". The Pixel Launcher hosts the Recents screen; removals need an unlocked phone.")
        hdr = ["time", "package", "process", "requested by pid", "line"]
        rows = [(fmt_t(x["t"]), x["pkg"], x["process"], x["desc"].split("#")[1], x["line"])
                for x in sorted(rem, key=lambda x: x["t"])]
        f = ctx.out.csv("recents_removals.csv", hdr, rows)
        night = [r for r, x in zip(rows, sorted(rem, key=lambda x: x["t"])) if x["t"].hour < 4 or x["t"].hour >= 22]
        if night:
            rep.p("Between 22:00 and 04:00:")
            rep.table(hdr, night, limit=40, more=f)
        else:
            rep.p(f"None between 22:00 and 04:00. Full list: {f}.")


# ----------------------------------------------------------------------------------------------
# mobile data vs Wi-Fi, airplane mode
# ----------------------------------------------------------------------------------------------


def p_netstats(ctx):
    br, L = ctx.br, ctx.br.L
    svc = br.service("netstats")
    ctx.ns = collections.defaultdict(collections.Counter)
    if not svc:
        return
    x = br.find("Xt stats:", svc[0], svc[1])
    if x is None:
        return
    cur = None
    for i in range(x + 1, svc[1] + 1):
        l = L[i]
        if l and not l.startswith(" "):
            break
        m = re.search(r"ident=\[\{type=(\d+), ratType=([^,]+),.*?metered=(\w+), defaultNetwork=(\w+)", l)
        if m:
            typ, rat, met, dflt = m.groups()
            if typ == "1":
                cur = "wifi_default" if dflt == "true" else "wifi_notdefault"
            elif typ == "0":
                cur = ("mob_inet_" if met == "true" else "mob_ims_") + ("default" if dflt == "true" else "notdefault")
            else:
                cur = f"type{typ}"
            continue
        m = re.match(r"\s+st=(\d+) rb=(\d+) rp=\d+ tb=(\d+)", l)
        if m and cur:
            ctx.ns[int(m.group(1))][cur] += int(m.group(2)) + int(m.group(3))
    ctx.ns_line = x + 1


def p_validation(ctx):
    br, L = ctx.br, ctx.br.L
    ctx.val = collections.defaultdict(list)
    a = br.find("Validation logs (most recent first):")
    if a is None:
        return
    net = None
    for i in range(a + 1, min(a + 5000, len(L))):
        l = L[i]
        m = re.match(r"^(\d+) - (\S+)\s*$", l)
        if m:
            net = (int(m.group(1)), m.group(2))
            continue
        m = re.match(r"^\s+(\d{4}-\d\d-\d\dT[\d:.]+) - (.*)$", l)
        if m and net:
            ctx.val[net].append((iso(m.group(1)), i + 1, m.group(2)[:110]))
            continue
        if l.strip() and not l.startswith(" ") and not re.match(r"^\d+ - ", l):
            break


def r_mobile_vs_wifi(ctx):
    rep, out = ctx.rep, ctx.out
    rep.h(2, "4. Mobile data while on Wi-Fi")
    rows_bh = ctx.bh["rows"] if ctx.bh else []
    tz = ctx.tz
    share, mrad, tot = collections.Counter(), collections.Counter(), collections.Counter()
    for x, y in zip(rows_bh, rows_bh[1:]):
        t = x["t"]
        while t < y["t"]:
            h = t.replace(minute=0, second=0, microsecond=0)
            se = min(y["t"], h + timedelta(hours=1))
            d = (se - t).total_seconds()
            k = int(h.replace(tzinfo=tz).timestamp())
            tot[k] += d
            if x["wifi_suppl"] == "completed":
                share[k] += d
            if x["+mobile_radio"]:
                mrad[k] += d
            t = se
    hdr = ["hour", "Wi-Fi (default) bytes", "mobile internet as default", "mobile internet NOT default",
           "mobile IMS (VoLTE) bytes", "Wi-Fi associated", "mobile radio active", "flag"]
    rows = []
    for st in sorted(ctx.ns):
        c = ctx.ns[st]
        h = datetime.fromtimestamp(st, tz=timezone.utc).astimezone(tz).replace(tzinfo=None)
        ws = share[st] / tot[st] if tot.get(st) else None
        flag = ""
        if ws is not None and ws >= 0.995 and c["mob_inet_default"] > 0:
            flag = "mobile was the default route while Wi-Fi was associated all hour"
        if c["mob_inet_notdefault"] >= 1000:
            flag = (flag + "; " if flag else "") + "mobile internet carried traffic while not the default"
        rows.append((h.strftime("%m-%d %H:00"), f"{c['wifi_default']:,}", f"{c['mob_inet_default']:,}",
                     f"{c['mob_inet_notdefault']:,}", f"{c['mob_ims_default'] + c['mob_ims_notdefault']:,}",
                     pct(share[st], tot[st]) if tot.get(st) else "n/a", pct(mrad[st], tot[st]) if tot.get(st) else "n/a",
                     flag))
    f = out.csv("netstats_hourly.csv", hdr, rows)
    rep.p(f"Hourly bytes from netstats 'Xt stats' (L{getattr(ctx, 'ns_line', '?')}), with the share of each hour the "
          "phone was associated to Wi-Fi (battery history). 'Default' means the network carried the phone's "
          "default internet route. IMS (VoLTE/SMS) stays on cellular by design.")
    rep.table(hdr, rows, limit=60, more=f)
    # data networks
    if ctx.dn:
        rep.h(3, "Cellular data connections (TelephonyDebugService)")
        hdr = ["network", "APN", "access", "setup", "teardown", "teardown reason", "disconnected", "lasted",
               "validation probes (by number)", "line"]
        rows = []
        for d in sorted(ctx.dn, key=lambda d: d["setup"] or datetime.min):
            end = d["disc"] or d["teardown"]
            dur = (end - d["setup"]).total_seconds() if end and d["setup"] else None
            probes = [v for k, v in ctx.val.items() if k[0] == d["id"]]
            ptxt = ""
            if probes:
                p = probes[0]
                ts_ = [x[0] for x in p if x[0]]
                ptxt = f"{len(p)} entries {fmt_t(min(ts_), False)}-{fmt_t(max(ts_), False)}" if ts_ else f"{len(p)} entries"
            rows.append((d["tag"], d["apn"], d["access"], fmt_t(d["setup"]), fmt_t(d["teardown"]), d["reason"],
                         fmt_t(d["disc"]), fmt_dur(dur) if dur is not None else "still up" if not end else "-", ptxt,
                         d["line"]))
        out.csv("cell_data_networks.csv", hdr, rows)
        rep.table(hdr, rows)
        short = [r for r, d in zip(rows, sorted(ctx.dn, key=lambda d: d["setup"] or datetime.min))
                 if d["setup"] and (d["disc"] or d["teardown"]) and ((d["disc"] or d["teardown"]) - d["setup"]).total_seconds() < 10]
        if short:
            rep.p(f"{len(short)} cellular connection(s) lasted under 10 s. CONNECTIVITY_SERVICE_UNWANTED means Android "
                  "dropped it because another network (Wi-Fi) was preferred.")
    rep.p("Non-default mobile bytes in hours when Wi-Fi came or went are the hand-over overlap. Station-event mobile "
          "byte counters are not used here: they are not monotonic in this data.")


def r_airplane(ctx):
    rep = ctx.rep
    rep.h(2, "5. Airplane mode")
    iv = []
    air = sorted(ctx.aos.get("air", [])) if hasattr(ctx, "aos") else []
    on = None
    for t, ln, v in air:
        if v and on is None:
            on = (t, ln)
        elif not v and on is not None:
            iv.append((on[0], t, f"IMS log L{on[1]}/L{ln}"))
            on = None
    if not iv:   # fall back to the Wi-Fi controller
        tog = [(t, ln) for t, ln, w, o, d, ws in ctx.wifi.get("ctrl", []) if w.startswith("CMD_AIRPLANE_TOGGLED")]
        for (a, la), (b, lb) in zip(tog[::2], tog[1::2]):
            iv.append((a, b, f"Wi-Fi controller L{la}/L{lb}"))
    if not iv:
        rep.p("No airplane-mode interval found in the IMS or Wi-Fi logs.")
        return
    rows_bh = ctx.bh["rows"]
    for a, b, src in iv:
        rep.h(3, f"{fmt_t(a)} -> {fmt_t(b, False)} ({fmt_dur((b - a).total_seconds())}; source {src})")
        lo, hi = a - timedelta(seconds=5), b + timedelta(seconds=20)
        ev = [e for e in ctx.bh["events"] if lo <= e[0] <= hi and e[2] in
              ("phone_state", "+mobile_radio", "+wifi_radio", "+wifi", "wifi_suppl", "conn", "data_conn",
               "+phone_scanning")]
        rep.table(["time", "line", "battery-history change", "from", "to"],
                  [(fmt_t(e[0]), e[1], e[2], e[3], e[4]) for e in ev], limit=40)
        mr = integrate(rows_bh, a, b, lambda r: r["+mobile_radio"])
        wr = integrate(rows_bh, a, b, lambda r: r["+wifi_radio"])
        wa = integrate(rows_bh, a, b, lambda r: r["wifi_suppl"] == "completed")
        bullets = [f"mobile radio active flag set for {mr:.1f} s inside the interval; Wi-Fi radio active {wr:.1f} s; "
                   f"Wi-Fi associated {wa:.1f} s."]
        pw = [(t, d, why) for t, ln, d, rs, why in ctx.tds.get("power", []) if lo <= t <= hi]
        if pw:
            bullets.append("radio power log: " + "; ".join(f"{fmt_t(t, False)} desired={d} reasons=[{w}]" for t, d, w in pw))
        dn = [d for d in ctx.dn if (d["teardown"] and lo <= d["teardown"] <= hi) or (d["setup"] and lo <= d["setup"] <= hi + timedelta(seconds=60))]
        for d in dn:
            bullets.append(f"{d['tag']} ({d['apn']}): setup {fmt_t(d['setup'], False)}, teardown {fmt_t(d['teardown'], False)} {d['reason'] or ''}")
        if ctx.bt and ctx.bt.get("first"):
            if ctx.bt["first"] <= a and ctx.bt["last"] >= b:
                pk = [x for x in ctx.bt["pkt_times"] if a <= x[0] <= b]
                cnt = collections.Counter((x[1], x[2]) for x in pk)
                bullets.append("Bluetooth HCI traffic inside the interval: " + (", ".join(f"{k[0]} {k[1]} x{v}" for k, v in cnt.most_common()) or "none")
                               + " (Bluetooth may stay on in airplane mode by design).")
            else:
                bullets.append("Bluetooth snoop log does not cover this interval.")
        rep.bullets(bullets)


# ----------------------------------------------------------------------------------------------
# Bluetooth: btsnoop parser
# ----------------------------------------------------------------------------------------------

UUID16 = {"FE2C": "Google Fast Pair", "FEF3": "Google (Nearby)", "FEAA": "Google Eddystone (Find Hub beacons)",
          "FD6F": "Exposure Notification", "180F": "Battery", "180A": "Device Information", "1812": "HID",
          "110B": "Audio Sink", "110A": "Audio Source", "111E": "Handsfree", "1108": "Headset",
          "184E": "LE Audio ASCS", "184F": "LE Audio BASS", "1850": "LE Audio PACS"}
COMPANY = {"004C": "Apple", "0006": "Microsoft", "0075": "Samsung", "00E0": "Google", "0171": "Amazon",
           "0057": "Harman", "0059": "Nordic Semiconductor"}
KNOWN128 = {"df21fe2c-2515-4fdb-8886-f12c4d67927c": "Google Fast Pair message stream (RFCOMM)"}
HCI_REASON = {0x05: "auth failure", 0x08: "timeout", 0x13: "remote user terminated", 0x14: "remote low resources",
              0x15: "remote power off", 0x16: "local host terminated", 0x1F: "unspecified", 0x22: "LL response timeout",
              0x28: "instant passed", 0x3B: "unacceptable conn params", 0x3D: "MIC failure", 0x3E: "failed to establish",
              0x02: "unknown connection id", 0x04: "page timeout"}
ATT_NAMES = {0x01: "Error", 0x02: "MTU req", 0x03: "MTU rsp", 0x04: "FindInfo req", 0x05: "FindInfo rsp",
             0x06: "FindByType req", 0x07: "FindByType rsp", 0x08: "ReadByType req", 0x09: "ReadByType rsp",
             0x0A: "Read req", 0x0B: "Read rsp", 0x0C: "ReadBlob req", 0x0D: "ReadBlob rsp", 0x0E: "ReadMulti req",
             0x0F: "ReadMulti rsp", 0x10: "ReadByGroup req", 0x11: "ReadByGroup rsp", 0x12: "Write req",
             0x13: "Write rsp", 0x16: "PrepWrite req", 0x17: "PrepWrite rsp", 0x18: "ExecWrite req", 0x19: "ExecWrite rsp",
             0x1B: "Notify", 0x1D: "Indicate", 0x1E: "Confirm", 0x52: "Write cmd", 0xD2: "Signed write"}
ATT_REQ = {0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x16, 0x18, 0x20, 0x52, 0xD2}
ATT_WRITE = {0x12, 0x16, 0x18, 0x52, 0xD2}
ATT_READ = {0x0A, 0x0C, 0x0E, 0x08}
PT_OPS = {0x44: "PLAY", 0x45: "STOP", 0x46: "PAUSE", 0x4B: "FORWARD", 0x4C: "BACKWARD", 0x41: "VOLUME_UP",
          0x42: "VOLUME_DOWN", 0x48: "REWIND", 0x49: "FAST_FORWARD"}
AVDTP = {0x06: "OPEN", 0x07: "START", 0x08: "CLOSE", 0x09: "SUSPEND", 0x0A: "ABORT"}
CTYPE = {0x0: "CONTROL", 0x1: "STATUS", 0x3: "NOTIFY", 0x8: "NOT_IMPL", 0x9: "ACCEPTED", 0xA: "REJECTED",
         0xC: "STABLE", 0xD: "CHANGED", 0xF: "INTERIM"}
PDU = {0x31: "REGISTER_NOTIFICATION", 0x30: "GET_PLAY_STATUS", 0x20: "GET_ELEMENT_ATTRIBUTES",
       0x50: "SET_ABSOLUTE_VOLUME", 0x10: "GET_CAPABILITIES"}
AVRCP_EVT = {0x01: "PLAYBACK_STATUS_CHANGED", 0x02: "TRACK_CHANGED", 0x05: "PLAYBACK_POS_CHANGED",
             0x0D: "VOLUME_CHANGED", 0x0A: "AVAILABLE_PLAYERS_CHANGED", 0x0B: "ADDRESSED_PLAYER_CHANGED",
             0x09: "NOW_PLAYING_CONTENT_CHANGED"}
PLAYSTAT = {0: "STOPPED", 1: "PLAYING", 2: "PAUSED", 3: "FWD_SEEK", 4: "REV_SEEK", 0xFF: "ERROR"}


def uuid128(b):
    u = b[::-1].hex()
    return f"{u[0:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:32]}"


def ad_summary(data):
    out = {}
    i = 0
    while i < len(data):
        ln = data[i]
        if ln == 0 or i + 1 + ln > len(data):
            break
        t = data[i + 1]
        v = data[i + 2:i + 1 + ln]
        if t in (0x08, 0x09):
            out["name"] = v.decode("utf-8", "replace")
        elif t in (0x02, 0x03, 0x14):
            out.setdefault("uuid16", []).extend(f"{v[j] | v[j + 1] << 8:04X}" for j in range(0, len(v) - 1, 2))
        elif t in (0x06, 0x07, 0x15):
            out.setdefault("uuid128", []).extend(uuid128(v[j:j + 16]) for j in range(0, len(v) - 15, 16))
        elif t == 0x16 and len(v) >= 2:
            out.setdefault("svc16", []).append(f"{v[0] | v[1] << 8:04X}")
        elif t == 0x21 and len(v) >= 16:
            out.setdefault("svc128", []).append(uuid128(v[0:16]))
        elif t == 0xFF and len(v) >= 2:
            out.setdefault("mfr", []).append(f"{v[0] | v[1] << 8:04X}")
        elif t == 0x01 and len(v) >= 1:
            out["flags"] = v[0]
        elif t == 0x0A and len(v) >= 1:
            out["txp"] = struct.unpack("b", v[:1])[0]
        elif t == 0x19 and len(v) >= 2:
            out["appearance"] = f"0x{v[0] | v[1] << 8:04X}"
        i += 1 + ln
    return out


def ad_text(ad, labels=None):
    labels = labels or {}
    parts = []
    if ad.get("name"):
        parts.append(f"name='{ad['name']}'")
    for k in ("uuid16", "svc16"):
        for u in ad.get(k, []):
            parts.append(f"{'svc' if k == 'uuid16' else 'data'}:{u}" + (f"({UUID16[u]})" if u in UUID16 else ""))
    for k in ("uuid128", "svc128"):
        for u in ad.get(k, []):
            lab = labels.get(u) or KNOWN128.get(u)
            parts.append(f"{'svc' if k == 'uuid128' else 'data'}:{u}" + (f"({lab})" if lab else ""))
    for m in ad.get("mfr", []):
        parts.append(f"mfr:{m}" + (f"({COMPANY[m]})" if m in COMPANY else ""))
    return " ".join(parts) or "-"


class Snoop:
    """Streaming btsnoop parser that keeps aggregates, not every packet."""

    def __init__(self, tz):
        self.tz = tz
        self.files = []
        self.sessions = []
        self.open = {}                 # handle -> session
        self.pend_out = {}             # addr -> t (Create_Connection)
        self.pend_in = {}              # addr -> t (Connection_Request)
        self.local_disc = {}           # handle -> t
        self.adv = collections.defaultdict(lambda: {"data": [], "rsp": [], "params": [], "addr": [], "on": [],
                                                    "frag": {}, "cur": {}})
        self.adv_on = {}               # handle -> t enabled
        self.scan_on = None
        self.scan_iv = []
        self.reports = {}              # addr -> aggregate
        self.pairing = []
        self.notable = []              # (t, idx, file, dir, text)
        self.media = []                # (t, dir, proto, text, addr)
        self.chan = {}                 # (handle, dir, cid) -> psm
        self.pend_l2 = {}              # (handle, ident, initiator) -> (psm, scid)
        self.avdtp_sig = {}            # handle -> (dir, cid) of signalling channel(s)
        self.addr_of = {}              # handle -> addr
        self.sco = {}
        self.inquiry = []
        self.scan_enable = []
        self.pkt_times = []            # (t, dir, kind) for coarse activity counts
        self.first = self.last = None
        self.names = {}                # classic addr -> remote name

    def t(self, ts):
        us = ts - EPOCH_DELTA
        return datetime.fromtimestamp(us / 1e6, tz=timezone.utc).astimezone(self.tz).replace(tzinfo=None)

    def parse_file(self, path):
        raw = open(path, "rb").read()
        name = os.path.basename(path)
        if raw[:8] != b"btsnoop\x00":
            self.files.append({"file": name, "error": "not a btsnoop file"})
            return
        ver, dlt = struct.unpack(">II", raw[8:16])
        info = {"file": name, "version": ver, "datalink": dlt, "records": 0, "first": None, "last": None, "drops": 0,
                "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        self.files.append(info)
        if dlt != 1002:
            info["error"] = f"datalink {dlt} not supported (expected 1002 H4)"
            return
        off, idx = 16, 0
        while off + 24 <= len(raw):
            olen, ilen, flags, drops, ts = struct.unpack_from(">IIIIq", raw, off)
            pkt = raw[off + 24: off + 24 + ilen]
            off += 24 + ilen
            t = self.t(ts)
            info["first"] = info["first"] or t
            info["last"] = t
            info["drops"] = drops
            d = "rx" if flags & 1 else "tx"
            if pkt:
                try:
                    self.packet(t, d, pkt, name, idx)
                except Exception as ex:
                    info.setdefault("decode_errors", 0)
                    info["decode_errors"] += 1
            idx += 1
        info["records"] = idx
        info["trailing"] = len(raw) - off
        self.first = min([x for x in (self.first, info["first"]) if x]) if info["first"] else self.first
        self.last = max([x for x in (self.last, info["last"]) if x]) if info["last"] else self.last

    # -- packet dispatch
    def packet(self, t, d, pkt, fn, idx):
        h4, p = pkt[0], pkt[1:]
        if h4 == 0x01:
            self.cmd(t, d, p, fn, idx)
            self.pkt_times.append((t, d, "cmd"))
        elif h4 == 0x04:
            self.evt(t, d, p, fn, idx)
            if len(p) and not (p[0] == 0x3E and len(p) > 2 and p[2] in (0x02, 0x0D)) and p[0] not in (0x0E, 0x0F, 0x13):
                self.pkt_times.append((t, d, "event"))
        elif h4 == 0x02:
            self.acl(t, d, p)
            self.pkt_times.append((t, d, "acl"))
        elif h4 == 0x03:
            self.pkt_times.append((t, d, "sco"))

    def note(self, t, d, fn, idx, text):
        self.notable.append((t, idx, fn, d, text))

    def cmd(self, t, d, p, fn, idx):
        if len(p) < 3:
            return
        op = p[0] | p[1] << 8
        par = p[3:]
        if op == 0x0405 and len(par) >= 6:
            a = mac(par[0:6])
            self.pend_out[a] = t
            self.note(t, d, fn, idx, f"phone -> Create_Connection {a}")
        elif op == 0x0406 and len(par) >= 3:
            h = (par[0] | par[1] << 8) & 0x0FFF
            self.local_disc[h] = t
        elif op == 0x0401:
            self.inquiry.append((t, "Inquiry (classic discovery) started"))
            self.note(t, d, fn, idx, "phone -> Inquiry (classic device discovery)")
        elif op == 0x0402:
            self.inquiry.append((t, "Inquiry cancelled"))
        elif op == 0x0C1A and len(par) >= 1:
            v = par[0]
            txt = {0: "not discoverable, not connectable", 1: "DISCOVERABLE only", 2: "connectable (page scan)",
                   3: "DISCOVERABLE + connectable"}.get(v, str(v))
            self.scan_enable.append((t, txt))
            self.note(t, d, fn, idx, f"phone -> Write_Scan_Enable: {txt}")
        elif op == 0x0419 and len(par) >= 6:
            self.note(t, d, fn, idx, f"phone -> Remote_Name_Request {mac(par[0:6])}")
        elif op in (0x040B, 0x040C, 0x042B, 0x042C, 0x042D) and len(par) >= 6:
            nm = {0x040B: "Link_Key_Request_Reply", 0x040C: "Link_Key_Request_Negative_Reply (no stored key)",
                  0x042B: "IO_Capability_Request_Reply", 0x042C: "User_Confirmation_Request_Reply (accept)",
                  0x042D: "User_Confirmation_Request_Negative_Reply (reject)"}[op]
            self.pairing.append((t, mac(par[0:6]), nm))
        elif op in (0x2043, 0x200D):
            if op == 0x2043 and len(par) >= 9:
                fp, peer = par[0], mac(par[3:9])
            elif len(par) >= 12:
                fp, peer = par[4], mac(par[6:12])
            else:
                return
            self.note(t, d, fn, idx, f"phone -> LE create connection ({'accept-list' if fp else peer})")
        elif op == 0x2035 and len(par) >= 7:
            self.adv[par[0]]["addr"].append((t, mac(par[1:7])))
        elif op == 0x2036 and len(par) >= 10:
            props = par[1] | par[2] << 8
            self.adv[par[0]]["params"].append((t, {"connectable": bool(props & 1), "scannable": bool(props & 2),
                                                   "legacy": bool(props & 0x10), "own_type": par[9]}))
        elif op in (0x2037, 0x2038) and len(par) >= 4:
            h, oper, ln = par[0], par[1], par[3]
            frag = par[4:4 + ln]
            key = "data" if op == 0x2037 else "rsp"
            A = self.adv[h]
            buf = A["frag"].get(key, b"")
            if oper in (0x01,):            # first fragment
                A["frag"][key] = frag
                return
            if oper == 0x00:               # intermediate
                A["frag"][key] = buf + frag
                return
            if oper == 0x02:               # last
                frag = buf + frag
            if oper == 0x04:               # unchanged data, new DID
                return
            A["frag"][key] = b""
            ad = ad_summary(frag)
            A[key].append((t, ad))
            A["cur"][key] = ad
        elif op == 0x2008 and len(par) >= 1:   # legacy advertising data
            ad = ad_summary(par[1:1 + par[0]])
            self.adv["L"]["data"].append((t, ad))
            self.adv["L"]["cur"]["data"] = ad
        elif op == 0x200A and len(par) >= 1:
            self.adv_toggle("L", t, par[0])
        elif op == 0x2039 and len(par) >= 2:
            en, n = par[0], par[1]
            if n == 0 and en == 0:
                for h in list(self.adv_on):
                    self.adv_toggle(h, t, 0)
            off = 2
            for _ in range(n):
                if off + 4 > len(par):
                    break
                self.adv_toggle(par[off], t, en)
                off += 4
        elif op in (0x2042, 0x200C) and len(par) >= 1:
            if par[0] and self.scan_on is None:
                self.scan_on = t
            elif not par[0] and self.scan_on is not None:
                self.scan_iv.append((self.scan_on, t))
                self.scan_on = None

    def adv_toggle(self, h, t, en):
        if en:
            self.adv_on.setdefault(h, t)
        elif h in self.adv_on:
            a = self.adv_on.pop(h)
            cur = self.adv[h]["cur"]
            self.adv[h]["on"].append((a, t, dict(cur)))

    def evt(self, t, d, p, fn, idx):
        if len(p) < 2:
            return
        code, par = p[0], p[2:]
        if code == 0x3E and par:
            self.le_meta(t, d, par, fn, idx)
            return
        if code == 0x03 and len(par) >= 11:
            st, h, a = par[0], (par[1] | par[2] << 8) & 0xFFF, mac(par[3:9])
            init = "?"
            if a in self.pend_in and (a not in self.pend_out or self.pend_in[a] >= self.pend_out[a]):
                init = "remote"
            elif a in self.pend_out:
                init = "phone"
            self.pend_in.pop(a, None)
            self.pend_out.pop(a, None)
            if st != 0:
                self.sessions.append({"start": t, "end": t, "addr": a, "transport": "classic", "init": init,
                                      "failed": f"0x{st:02X}", "file": fn, "idx": idx})
                return
            self.new_session(h, {"start": t, "addr": a, "transport": "classic", "init": init, "file": fn, "idx": idx,
                                 "link_type": par[9]})
            self.addr_of[h] = a
            self.note(t, d, fn, idx, f"classic connection up {a} handle {h} initiated by {init}")
        elif code == 0x04 and len(par) >= 10:
            a = mac(par[0:6])
            self.pend_in[a] = t
            self.note(t, d, fn, idx, f"remote -> Connection_Request {a} CoD 0x{par[6] | par[7] << 8 | par[8] << 16:06X}")
        elif code == 0x05 and len(par) >= 4:
            h, reason = (par[1] | par[2] << 8) & 0xFFF, par[3]
            if h in self.sco:
                a = self.sco.pop(h)
                self.media.append((t, d, "SCO", f"call-audio link down reason 0x{reason:02X}", a))
                self.local_disc.pop(h, None)
                return
            s = self.open.pop(h, None)
            for k in [k for k in self.chan if k[0] == h]:
                del self.chan[k]
            self.avdtp_sig.pop(h, None)
            if s is None:
                self.sessions.append({"start": None, "end": t, "addr": self.addr_of.get(h, "?"), "transport": "?",
                                      "init": "?", "reason": reason, "note": "connected before the log started",
                                      "file": fn, "idx": idx, "ended_by": self.ended_by(h, None, t, reason)})
                return
            s["end"] = t
            s["reason"] = reason
            s["ended_by"] = self.ended_by(h, s["start"], t, reason)
            self.sessions.append(s)
            self.note(t, d, fn, idx, f"disconnect {s['addr']} handle {h} ({HCI_REASON.get(reason, hex(reason))}, ended by {s['ended_by']})")
        elif code == 0x07 and len(par) >= 7:
            nm = par[7:7 + 248].split(b"\x00")[0].decode("utf-8", "replace")
            if par[0] == 0:
                self.names[mac(par[1:7])] = nm
        elif code in (0x08, 0x59) and len(par) >= 4:
            h = (par[1] | par[2] << 8) & 0xFFF
            if h in self.open:
                self.open[h]["enc"].append((t, par[0], par[3]))
        elif code == 0x06 and len(par) >= 3:
            h = (par[1] | par[2] << 8) & 0xFFF
            a = self.open.get(h, {}).get("addr", "?")
            self.pairing.append((t, a, f"Authentication_Complete status 0x{par[0]:02X}"))
        elif code == 0x17 and len(par) >= 6:
            self.pairing.append((t, mac(par[0:6]), "Link_Key_Request (controller asks for stored key)"))
        elif code == 0x18 and len(par) >= 23:
            kt = {0: "combination", 4: "unauthenticated P-192", 5: "authenticated P-192", 6: "changed combination",
                  7: "unauthenticated P-256", 8: "authenticated P-256"}.get(par[22], str(par[22]))
            self.pairing.append((t, mac(par[0:6]), f"Link_Key_Notification: NEW KEY ({kt})"))
        elif code == 0x31 and len(par) >= 6:
            self.pairing.append((t, mac(par[0:6]), "IO_Capability_Request"))
        elif code == 0x32 and len(par) >= 9:
            self.pairing.append((t, mac(par[0:6]), f"IO_Capability_Response io={par[6]} auth_req={par[8]}"))
        elif code == 0x33 and len(par) >= 10:
            self.pairing.append((t, mac(par[0:6]), "User_Confirmation_Request (numeric comparison / pop-up)"))
        elif code == 0x36 and len(par) >= 7:
            self.pairing.append((t, mac(par[1:7]), f"Simple_Pairing_Complete status 0x{par[0]:02X}"))
        elif code == 0x2C and len(par) >= 10:
            h = (par[1] | par[2] << 8) & 0xFFF
            a = mac(par[3:9])
            if par[0] == 0:
                self.sco[h] = a
            self.media.append((t, d, "SCO", f"{'eSCO' if par[9] == 2 else 'SCO'} call-audio link up status 0x{par[0]:02X}", a))
        elif code in (0x02, 0x22, 0x2F) and par:
            n = par[0]
            if code == 0x2F:
                a = mac(par[1:7])
                self.inquiry.append((t, f"inquiry result {a}"))
            else:
                for k in range(n):
                    self.inquiry.append((t, "inquiry result"))

    def ended_by(self, h, start, t, reason):
        ld = self.local_disc.pop(h, None)
        if ld and (start is None or ld >= start) and ld <= t:
            return "phone"
        if reason in (0x13, 0x14, 0x15):
            return "remote"
        return HCI_REASON.get(reason, f"0x{reason:02X}")

    def new_session(self, h, s):
        s.update({"enc": [], "acl": collections.Counter(), "att_tx": collections.Counter(),
                  "att_rx": collections.Counter(), "psm": set(), "smp": collections.Counter(), "via_adv": None})
        self.open[h] = s

    def le_meta(self, t, d, q, fn, idx):
        sub, q = q[0], q[1:]
        if sub in (0x01, 0x0A, 0x29) and len(q) >= 18:
            st, h, role, ptype, a = q[0], (q[1] | q[2] << 8) & 0xFFF, q[3], q[4], mac(q[5:11])
            peer_rpa = mac(q[17:23]) if sub != 0x01 and len(q) >= 23 else None
            if peer_rpa == "00:00:00:00:00:00":
                peer_rpa = None
            init = "phone" if role == 0 else "remote"
            if st != 0:
                if st != 0x02:
                    self.sessions.append({"start": t, "end": t, "addr": a, "transport": "LE", "init": init,
                                          "failed": f"0x{st:02X}", "file": fn, "idx": idx})
                return
            s = {"start": t, "addr": a, "transport": "LE", "init": init, "peer_type": ptype, "peer_rpa": peer_rpa,
                 "file": fn, "idx": idx}
            self.new_session(h, s)
            if sub == 0x29 and len(q) >= 31 and q[30] != 0xFF and role == 1:
                s["via_adv"] = q[30]
            self.addr_of[h] = a
            self.note(t, d, fn, idx, f"LE connection up {a} handle {h} initiated by {init}")
        elif sub == 0x12 and len(q) >= 4:
            st, ah, h = q[0], q[1], (q[2] | q[3] << 8) & 0xFFF
            if st == 0 and h in self.open:
                self.open[h]["via_adv"] = ah
        elif sub == 0x02 and q:
            n = q[0]
            off = 1
            try:
                et = q[off:off + n]
                off += n
                at = q[off:off + n]
                off += n
                ads = [mac(q[off + 6 * k: off + 6 * k + 6]) for k in range(n)]
                off += 6 * n
                lens = q[off:off + n]
                off += n
                datas = []
                for k in range(n):
                    datas.append(q[off:off + lens[k]])
                    off += lens[k]
                for k in range(n):
                    rssi = struct.unpack("b", q[off + k:off + k + 1])[0] if off + k < len(q) else None
                    self.report(t, ads[k], at[k], et[k], rssi, datas[k])
            except (IndexError, struct.error):
                pass
        elif sub == 0x0D and q:
            n = q[0]
            off = 1
            for _ in range(n):
                if off + 24 > len(q):
                    break
                et = q[off] | q[off + 1] << 8
                at = q[off + 2]
                a = mac(q[off + 3:off + 9])
                rssi = struct.unpack("b", q[off + 13:off + 14])[0]
                dl = q[off + 23]
                self.report(t, a, at, et, rssi if rssi != 127 else None, q[off + 24:off + 24 + dl])
                off += 24 + dl

    def report(self, t, a, at, et, rssi, data):
        r = self.reports.get(a)
        if r is None:
            r = self.reports[a] = {"n": 0, "first": t, "last": t, "rmin": None, "rmax": None, "types": set(),
                                   "names": set(), "u16": set(), "u128": set(), "s16": set(), "s128": set(),
                                   "mfr": set(), "conn": False}
        r["n"] += 1
        r["last"] = t
        if rssi is not None:
            r["rmin"] = rssi if r["rmin"] is None else min(r["rmin"], rssi)
            r["rmax"] = rssi if r["rmax"] is None else max(r["rmax"], rssi)
        r["types"].add(at)
        if et & 1:
            r["conn"] = True
        if data:
            ad = ad_summary(data)
            if ad.get("name"):
                r["names"].add(ad["name"])
            r["u16"].update(ad.get("uuid16", []))
            r["u128"].update(ad.get("uuid128", []))
            r["s16"].update(ad.get("svc16", []))
            r["s128"].update(ad.get("svc128", []))
            r["mfr"].update(ad.get("mfr", []))

    def acl(self, t, d, p):
        if len(p) < 4:
            return
        hdl = p[0] | p[1] << 8
        h, pb = hdl & 0xFFF, (hdl >> 12) & 3
        s = self.open.get(h)
        if s is not None:
            s["acl"][d] += 1
            s["acl"][d + "_bytes"] += len(p) - 4
        if pb not in (0, 2):
            return
        pl = p[4:]
        if len(pl) < 4:
            return
        cid = pl[2] | pl[3] << 8
        body = pl[4:]
        if cid == 0x0004 and body and s is not None:
            (s["att_tx"] if d == "tx" else s["att_rx"])[body[0]] += 1
            return
        if cid == 0x0006 and body and s is not None:
            s["smp"][body[0]] += 1
            return
        if cid == 0x0001 and len(body) >= 4:
            code, ident = body[0], body[1]
            if code == 0x02 and len(body) >= 8:
                psm, scid = body[4] | body[5] << 8, body[6] | body[7] << 8
                initiator = "phone" if d == "tx" else "remote"
                self.pend_l2[(h, ident, initiator)] = (psm, scid)
                if s is not None:
                    s["psm"].add(psm)
            elif code == 0x03 and len(body) >= 12:
                dcid, scid, res = body[4] | body[5] << 8, body[6] | body[7] << 8, body[8] | body[9] << 8
                initiator = "remote" if d == "tx" else "phone"
                pr = self.pend_l2.get((h, ident, initiator))
                if pr and res == 0:
                    psm = pr[0]
                    phone_cid, remote_cid = (scid, dcid) if initiator == "phone" else (dcid, scid)
                    self.chan[(h, "rx", phone_cid)] = psm
                    self.chan[(h, "tx", remote_cid)] = psm
                    if psm == 0x19 and h not in self.avdtp_sig:
                        self.avdtp_sig[h] = {("rx", phone_cid), ("tx", remote_cid)}
            return
        psm = self.chan.get((h, d, cid))
        if psm == 0x17 and len(body) >= 6:
            self.avrcp(t, d, h, body)
        elif psm == 0x19 and len(body) >= 2 and (d, cid) in self.avdtp_sig.get(h, set()):
            mtype, ptype = body[0] & 0x03, (body[0] >> 2) & 0x03
            sig = body[1] & 0x3F
            if ptype == 0 and sig in AVDTP:
                mt = {0: "cmd", 1: "general_reject", 2: "accept", 3: "reject"}[mtype]
                self.media.append((t, d, "AVDTP", f"{AVDTP[sig]} {mt}", self.addr_of.get(h, "?")))

    def avrcp(self, t, d, h, body):
        pid = body[1] << 8 | body[2]
        if pid != 0x110E:
            return
        cr = "rsp" if body[0] & 0x02 else "cmd"
        ctype = body[3] & 0x0F
        opcode = body[5]
        a = self.addr_of.get(h, "?")
        if opcode == 0x7C and len(body) >= 7:
            op = body[6]
            rel = bool(op & 0x80)
            op &= 0x7F
            self.media.append((t, d, "AVRCP", f"PASS_THROUGH {cr} {CTYPE.get(ctype, ctype)} {PT_OPS.get(op, hex(op))} "
                                              f"{'released' if rel else 'pressed'}", a))
        elif opcode == 0x00 and len(body) >= 13:
            pdu = body[9]
            desc = f"VENDOR {cr} {CTYPE.get(ctype, ctype)} {PDU.get(pdu, hex(pdu))}"
            if pdu == 0x31 and len(body) >= 14:
                ev = body[13]
                desc += f" {AVRCP_EVT.get(ev, hex(ev))}"
                if ev == 0x01 and len(body) >= 15 and cr == "rsp":
                    desc += f" -> {PLAYSTAT.get(body[14], body[14])}"
            if pdu == 0x50 and len(body) >= 14:
                desc += f" vol={body[13] & 0x7F}"
            self.media.append((t, d, "AVRCP", desc, a))

    def finish(self):
        end = self.last
        for h, s in list(self.open.items()):
            s["end"] = None
            s["note"] = "still connected at end of log"
            self.sessions.append(s)
        self.open = {}
        for h, a in list(self.adv_on.items()):
            self.adv[h]["on"].append((a, None, dict(self.adv[h]["cur"])))
        if self.scan_on is not None:
            self.scan_iv.append((self.scan_on, None))
        self.sessions.sort(key=lambda s: s["start"] or s["end"])


def p_btsnoop(ctx):
    files = ctx.snoops
    if not files:
        return
    sn = Snoop(ctx.tz)
    # order by first record time (the .last file is older)
    def first_ts(p):
        try:
            with open(p, "rb") as fh:
                h = fh.read(16 + 24)
            return struct.unpack(">q", h[16 + 16:16 + 24])[0]
        except Exception:
            return 0
    for p in sorted(files, key=first_ts):
        sn.parse_file(p)
    sn.finish()
    ctx.bt = {"sn": sn, "first": sn.first, "last": sn.last, "pkt_times": sn.pkt_times}
    for f in sn.files:
        if f.get("first"):
            ctx.coverage.append((f"btsnoop {f['file']}", f["first"], f["last"], f["records"], f["sha256"][:12]))


# ----------------------------------------------------------------------------------------------
# Bluetooth: bluetooth_manager dump
# ----------------------------------------------------------------------------------------------


def p_btmanager(ctx):
    br, L = ctx.br, ctx.br.L
    svc = br.service("bluetooth_manager")
    if not svc:
        raise RuntimeError("bluetooth_manager dump not found")
    s, e = svc
    B = ctx.btm = {"bonded": [], "cache": [], "scanners": [], "gatt_client": [], "gatt_server": [], "tcb": [],
                   "bond_events": [], "linkkeys": [], "sockets": [], "adv_map": [], "mediakeys": [], "range": svc}
    # remote devices
    a = br.find("Bonded devices:", s, e)
    section = "bonded"
    if a is not None:
        cur = None
        for i in range(a, min(a + 3000, e)):
            l = L[i]
            st = l.strip()
            if st.startswith("Bonded devices:"):
                section = "bonded"
                continue
            if st.startswith("Other devices:"):
                section = "cache"
                continue
            m = re.match(r"^\s+XX:XX:XX:XX:([0-9A-F]{2}:[0-9A-F]{2})\((\w+)\) => (\S+) \[\s*([A-Z/?]+)\s*\] \[(0x[0-9A-F]+)\] .*?\[ACL BR/EDR:(\w) LE:(\w)\].*?LE:[^\]]*\] ?(.*)$", l)
            if m:
                cur = {"suffix": m.group(1), "type": m.group(4), "cod": m.group(5), "acl": f"BR/EDR {m.group(6)} LE {m.group(7)}",
                       "name": m.group(8).strip(), "pkgs": "", "line": i + 1}
                B[section].append(cur)
                continue
            m = re.match(r"^\s+\[Packages\s*\]: \[(.*)\]", l)
            if m and cur:
                cur["pkgs"] = m.group(1)
                continue
            if st and not st.startswith("[") and not st.startswith("XX:") and cur and not l.startswith("    "):
                break
    # LE scanner map
    a = br.find("LE Scanner Map:", s, e)
    if a is not None:
        cur = None
        last = None
        for i in range(a + 1, min(a + 4000, e)):
            l = L[i]
            m = re.match(r"^  \[(\d+)/(\d+)\] (\S+):\s*$", l)
            if m:
                cur = {"app": m.group(3), "line": i + 1, "started": None, "active_ms": None, "results": None,
                       "scans": [], "modes": ""}
                B["scanners"].append(cur)
                continue
            if cur is None:
                continue
            if l and not l.startswith(" "):
                break
            st = l.strip()
            m = re.match(r"^(\d+)\s+(\d+)\s+.*?\((\d+)ms\)\s+.*?\((\d+)ms\)\s+.*?\((\d+)ms\)\s+(\d+)\s*$", st)
            if m and cur["started"] is None:
                cur["started"], cur["stopped"], cur["active_ms"] = int(m.group(1)), int(m.group(2)), int(m.group(3))
                continue
            if st.startswith("COUNTER"):
                cur["modes_c"] = st.split()[1:]
            m = re.match(r"^(ALL_MATCHES|FIRST_MATCH|MATCH_LOST|\w+_MATCH\w*)\s+(\d+)\s+(\d+)\s+(\d+)", st)
            if m:
                cur["results"] = (int(m.group(2)), int(m.group(3)), int(m.group(4)))
            m = re.match(r"^\[(\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) --> (\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\] Duration: (.*)$", st)
            if m:
                last = {"start": m.group(1), "end": m.group(2), "dur": m.group(3), "info": "", "imp": "", "filters": []}
                cur["scans"].append(last)
                continue
            if last is not None and st.startswith("\u2514 Info:"):
                last["info"] = st[len("\u2514 Info:"):].strip()
            elif last is not None and st.startswith("\u2514 App Importance:"):
                last["imp"] = st.split(":", 1)[1].strip()
            elif last is not None and st.startswith("\u2514 Filter:"):
                last["filters"].append(st.split(":", 1)[1].strip())
    # GATT client / server last apps
    for key, anchor in (("gatt_client", "GATT Client Map:"), ("gatt_server", "GATT Server Map:")):
        a = br.find(anchor, s, e)
        if a is None:
            continue
        for i in range(a + 1, min(a + 60, e)):
            m = re.search(r"AppRecord\((\d\d-\d\d \d\d:\d\d:\d\d) ~ (\d\d-\d\d \d\d:\d\d:\d\d), id=(\d+), appName=(\S+), (\w+), reason=(\w+)\)", L[i])
            if m:
                B[key].append(m.groups() + (i + 1,))
            elif L[i].strip().startswith("GATT ") and i > a + 1:
                break
    # advertiser map (Last Advertising)
    a = br.find("GATT Advertiser Map:", s, e)
    if a is not None:
        cur = None
        for i in range(a + 1, min(a + 3000, e)):
            l = L[i]
            st = l.strip()
            if re.match(r"^\s{6}\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\s*$", l):
                cur = {"time": st, "app": None, "tag": "", "start": "", "stop": "", "imp": "", "connectable": "",
                       "uuids": [], "line": i + 1}
                B["adv_map"].append(cur)
                continue
            if cur is None:
                if st.startswith("GATT ") and i > a + 2:
                    break
                continue
            if cur["app"] is None and st and ":" not in st:
                cur["app"] = st
            elif st.startswith("Tag"):
                cur["tag"] = st.split(":", 1)[1].strip()
            elif "Start time" in st:
                cur["start"] = st.split(":", 1)[1].strip()
            elif "Stop time" in st:
                cur["stop"] = st.split(":", 1)[1].strip()
            elif "App Importance" in st:
                cur["imp"] = st.split(":", 1)[1].strip()
            elif st.startswith("\u2514Connectable"):
                cur["connectable"] = st.split(":", 1)[1].strip()
            elif st.startswith("[") and "-" in st:
                cur["uuids"].append(st.strip("[]"))
            elif st.startswith("GATT ") or (l and not l.startswith(" ")):
                break
    # gatt tcb transitions
    for i in range(s, e + 1):
        l = L[i]
        if not l.startswith("stack::gatt"):
            continue
        m = re.match(r"^stack::gatt\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) (\S+), (BT_TRANSPORT_\w+), state: (GATT_CH_\w+), (.*)$", l)
        if m:
            t = datetime.strptime(m.group(1)[:23], "%Y-%m-%d %H:%M:%S.%f")
            holders = re.findall(r"([\w.\[\]]+) \((\d+)\)", m.group(5))
            B["tcb"].append((t, m.group(2).upper(), m.group(3), m.group(4), holders, i + 1))
    if B["tcb"]:
        ctx.coverage.append(("Bluetooth GATT link log (last 100 transitions)", B["tcb"][0][0], B["tcb"][-1][0],
                             len(B["tcb"]), f"L{B['tcb'][0][5]}"))
    # bonding events, link key types, socket events
    a = br.find("Bonding Events:", s, e, exact=True)
    if a is not None:
        for i in range(a + 1, min(a + 300, e)):
            m = re.match(r"^\s+(\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \[([^\]]+)\] (.*)$", L[i])
            if not m:
                break
            B["bond_events"].append((m.group(1), m.group(2), m.group(3)[:150], i + 1))
    a = br.find("Link Key Types:", s, e, exact=True)
    if a is not None:
        addr = None
        for i in range(a + 1, min(a + 200, e)):
            st = L[i].strip()
            if re.match(r"^xx:xx:xx:xx:[0-9a-f]{2}:[0-9a-f]{2}$", st):
                addr = st.upper()[-5:]
            elif st.startswith(("BR:", "LE:")) and addr:
                v = st.split(":", 1)[1].strip()
                if v:
                    B["linkkeys"].append((addr, st[:2], v))
            elif st and not st.startswith(("BR", "LE", "xx")):
                break
    a = br.find("Socket Events:", s, e, exact=True)
    if a is not None:
        for i in range(a + 2, min(a + 400, e)):
            parts = [x.strip() for x in L[i].split("\t") if x.strip()]
            if len(parts) < 6 or not re.match(r"\d\d:\d\d:\d\d", parts[0]):
                if parts:
                    break
                continue
            B["sockets"].append(tuple(parts[:7]) + (i + 1,))
    # media key events from the AVRCP target
    for i in range(s, e + 1):
        if "sendMediaKeyEvent:" in L[i]:
            m = re.search(r"(\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) sendMediaKeyEvent: device=(\S+) key=(\w+) pushed=(\w+).*?active player is (\S+)", L[i])
            if m:
                B["mediakeys"].append(m.groups() + (i + 1,))


def mdtime(ctx, s):
    """'01-15 12:41:05[.123]' -> datetime"""
    m = re.match(r"(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)(?:\.(\d{3}))?", s)
    if not m:
        return None
    g = m.groups()
    return ctx.ytime(g[0], g[1], g[2], g[3], g[4], g[5] or 0)


def r_bluetooth(ctx):
    rep, out = ctx.rep, ctx.out
    B = ctx.btm
    bt = ctx.bt
    rep.h(2, "6. Bluetooth")
    # labels for 128-bit UUIDs from app scan filters
    labels = {}
    for sc in B.get("scanners", []):
        for s in sc["scans"]:
            for f in s["filters"]:
                for u in re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", f):
                    labels.setdefault(u, f"scan filter of {sc['app']}")
    ctx.uuid_labels = labels
    # cache names by suffix
    names = collections.defaultdict(set)
    for d in B.get("bonded", []) + B.get("cache", []):
        if d["name"] and d["name"] != "null":
            names[d["suffix"]].add(d["name"])
    ctx.bt_names = names

    def nm(addr):
        n = names.get(suffix2(addr))
        return "/".join(sorted(n)) + " (suffix match)" if n else ""

    rep.h(3, "Bonded (paired) devices")
    rep.table(["address (masked)", "name", "type", "class", "connected", "line"],
              [("..:" + d["suffix"], d["name"], d["type"], d["cod"], d["acl"], d["line"]) for d in B.get("bonded", [])])
    if B.get("linkkeys"):
        rep.table(["device", "transport", "link key type"], B["linkkeys"])
    if B.get("bond_events"):
        rep.p("Pairing (bonding) events recorded by the Bluetooth service:")
        rep.table(["time", "device", "event", "line"], B["bond_events"], limit=30)
    if bt:
        sn = bt["sn"]
        rep.h(3, "HCI snoop logs")
        rep.table(["file", "records", "first", "last", "dropped", "decode errors", "SHA-256"],
                  [(f["file"], f.get("records"), fmt_t(f.get("first")), fmt_t(f.get("last")), f.get("drops"),
                    f.get("decode_errors", 0), f.get("sha256", "")[:16] + "...") for f in sn.files])
        if sn.pairing:
            rep.h(3, "Pairing activity on the radio (HCI)")
            rep.table(["time", "device", "event"], [(fmt_t(t), a, e) for t, a, e in sn.pairing], limit=40)
        if sn.scan_enable or sn.inquiry:
            rep.h(3, "Classic discoverability and device discovery by the phone")
            rep.table(["time", "event"], [(fmt_t(t), e) for t, e in sn.scan_enable + sn.inquiry[:40]], limit=40)
        # sessions
        tcb = B.get("tcb", [])
        rep.h(3, "Connections (who started them, who ended them, which app held the link)")
        hdr = ["start", "end", "lasted", "transport", "address", "cached name", "initiated by", "ended by", "reason",
               "phone as GATT client (req/read/write)", "remote as GATT client (req/read/write)", "L2CAP PSMs",
               "via phone's adv set", "app holding the link (GATT log)", "record"]
        rows = []
        for s in sn.sessions:
            if s.get("addr") in ("?", None) and s.get("end"):
                for t, sx, tr, stt, hs, ln in tcb:
                    if stt == "GATT_CH_CLOSE" and abs((t - s["end"]).total_seconds()) < 0.2:
                        s["addr"] = "..:" + sx[-5:]
                        s["transport"] = "LE"
                        s["note"] = f"address from GATT log L{ln}"
                        break
            dur = (s["end"] - s["start"]).total_seconds() if s.get("end") and s.get("start") else None
            atx, arx = s.get("att_tx", collections.Counter()), s.get("att_rx", collections.Counter())
            pc = f"{sum(v for k, v in atx.items() if k in ATT_REQ)}/{sum(v for k, v in atx.items() if k in ATT_READ)}/{sum(v for k, v in atx.items() if k in ATT_WRITE)}"
            rc = f"{sum(v for k, v in arx.items() if k in ATT_REQ)}/{sum(v for k, v in arx.items() if k in ATT_READ)}/{sum(v for k, v in arx.items() if k in ATT_WRITE)}"
            holders = set()
            lo = s["start"] - timedelta(seconds=2) if s.get("start") else (s["end"] - timedelta(seconds=60) if s.get("end") else None)
            if lo is not None:
                for t, sx, tr, stt, hs, ln in tcb:
                    if sx[-5:] == suffix2(s["addr"]) and lo <= t <= (s.get("end") or t) + timedelta(seconds=1):
                        holders.update(h for h, _ in hs)
            rows.append((fmt_t(s.get("start")), fmt_t(s.get("end"), False) if s.get("end") else "open", fmt_dur(dur),
                         s["transport"], s["addr"], nm(s["addr"]), s.get("init"), s.get("ended_by", s.get("failed", "")),
                         HCI_REASON.get(s.get("reason"), s.get("reason")) if s.get("reason") is not None else (("failed " + s["failed"]) if s.get("failed") else ""),
                         pc, rc, ",".join(f"0x{p:02X}" for p in sorted(s.get("psm", []))),
                         s.get("via_adv") if s.get("via_adv") is not None else "", ", ".join(sorted(holders)),
                         f"{s['file']}#{s['idx']}"))
        f = out.csv("bt_sessions.csv", hdr, rows)
        rep.table(hdr, rows, limit=80, more=f)
        rep.p("'Initiated by remote' on LE means the other device connected to one of the phone's advertising sets "
              "(column 'via phone's adv set'). GATT counts: requests/reads/writes sent by that side.")
    # GATT link log grouped
    tcb = B.get("tcb", [])
    if tcb:
        rep.h(3, "Apps that held Bluetooth LE links (GATT link log)")
        g = collections.defaultdict(lambda: {"opens": 0, "holds": collections.Counter(), "first": None, "last": None})
        for t, sx, tr, stt, hs, ln in tcb:
            x = g[sx]
            x["first"] = x["first"] or t
            x["last"] = t
            if stt == "GATT_CH_OPEN" and not hs:
                pass
            for h, idn in hs:
                x["holds"][h] += 1
        opens = collections.Counter()
        prev = {}
        for t, sx, tr, stt, hs, ln in tcb:
            if stt == "GATT_CH_OPEN" and prev.get(sx) != "GATT_CH_OPEN":
                opens[sx] += 1
            prev[sx] = stt
        rep.table(["peer (masked)", "cached name", "links opened", "app(s) holding (distinct GATT clients)", "first", "last"],
                  [("..:" + sx[-5:], "/".join(sorted(names.get(sx[-5:], []))), opens[sx],
                    ", ".join(f"{h} x{len({i for tt, s2, tr, st2, hs, ln in tcb if s2 == sx for hh, i in hs if hh == h})}" for h in x["holds"]),
                    fmt_t(x["first"]), fmt_t(x["last"])) for sx, x in g.items()])
    # scanners
    if B.get("scanners"):
        rep.h(3, "Apps scanning for Bluetooth LE devices")
        rows = []
        for sc in B["scanners"]:
            uid = uid_of_pkg(ctx, sc["app"])
            us = ctx.uidstats.get(uid, {}) if uid else {}
            filt = sorted({f for s in sc["scans"] for f in s["filters"]})
            rows.append((sc["app"], sc.get("started"), fmt_dur((sc.get("active_ms") or 0) / 1000),
                         "/".join(map(str, sc["results"])) if sc.get("results") else "",
                         us.get("bt_scan", ("", ""))[0], us.get("bt_scan_bg", ("", ""))[0],
                         "/".join(us.get("bt_results", ("", ""))), "; ".join(filt)[:200], sc["line"]))
        rep.table(["app", "scans (BT service)", "active time (BT service)", "results screen-off/on/total",
                   "scan time (batterystats)", "of which app in background", "results (bg)", "filters (last scans)", "line"],
                  rows)
        rep.p("The Bluetooth service counts since Bluetooth started; batterystats counts since the last charge.")
        for sc in B["scanners"]:
            if sc["scans"]:
                rep.p(f"Last scans of {sc['app']}:")
                rep.table(["start", "end", "duration", "info", "app importance", "filters"],
                          [(x["start"], x["end"], x["dur"], x["info"], x["imp"], "; ".join(x["filters"])[:120])
                           for x in sc["scans"]])
    if B.get("gatt_client") or B.get("gatt_server"):
        rep.h(3, "Recent GATT client/server registrations by app")
        rep.table(["role", "from", "to", "id", "app", "transport", "ended", "line"],
                  [("client",) + x for x in B.get("gatt_client", [])] + [("server",) + x for x in B.get("gatt_server", [])])
    if B.get("sockets"):
        rep.h(3, "Bluetooth sockets (RFCOMM/L2CAP)")
        rep.table(["time", "address", "state", "role", "channel", "type", "service", "line"], B["sockets"], limit=40)
    if bt:
        sn = bt["sn"]
        # the phone's own advertising
        rep.h(3, "What the phone itself advertised (HCI advertising sets)")
        rows = []
        for h, A in sorted(sn.adv.items(), key=lambda kv: str(kv[0])):
            for a, b, cur in A["on"]:
                txt = ad_text(cur.get("data", {}), labels)
                rsp = ad_text(cur.get("rsp", {}), labels) if cur.get("rsp") else ""
                rows.append((fmt_t(a), fmt_t(b, False) if b else "open", h, txt + (f" | scan rsp: {rsp}" if rsp else "")))
        rows.sort()
        agg = collections.Counter((r[2], r[3]) for r in rows)
        f = out.csv("bt_own_advertising.csv", ["enabled", "disabled", "set", "content"], rows)
        rep.table(["set", "content", "times enabled"], [(k[0], k[1], v) for k, v in agg.most_common()], limit=40, more=f)
        # advertisers seen
        rep.h(3, "Devices seen advertising nearby (HCI)")
        reps = sn.reports
        rows = []
        for a, r in reps.items():
            content = []
            for u in sorted(r["u16"] | r["s16"]):
                content.append(u + (f"({UUID16[u]})" if u in UUID16 else ""))
            for u in sorted(r["u128"] | r["s128"]):
                lab = labels.get(u) or KNOWN128.get(u)
                content.append(u + (f"({lab})" if lab else ""))
            for m in sorted(r["mfr"]):
                content.append("mfr " + m + (f"({COMPANY[m]})" if m in COMPANY else ""))
            rows.append((a, "/".join(sorted(r["names"])) or nm(a), r["n"], fmt_t(r["first"]), fmt_t(r["last"], False),
                         f"{r['rmin']}..{r['rmax']}", ",".join(map(str, sorted(r["types"]))), r["conn"], " ".join(content)[:180]))
        rows.sort(key=lambda x: -x[2])
        f = out.csv("bt_advertisers.csv", ["address", "name", "reports", "first", "last", "RSSI dBm", "addr type",
                                           "connectable", "content"], rows)
        grp = collections.OrderedDict()
        for r in rows:
            key = (r[1] or "(no name)", r[8] or "-")
            g = grp.setdefault(key, {"addr": 0, "n": 0, "first": None, "last": None, "rmax": None})
            g["addr"] += 1
            g["n"] += r[2]
            rr = reps[r[0]]
            g["first"] = min([x for x in (g["first"], rr["first"]) if x])
            g["last"] = max([x for x in (g["last"], rr["last"]) if x])
            if rr["rmax"] is not None:
                g["rmax"] = rr["rmax"] if g["rmax"] is None else max(g["rmax"], rr["rmax"])
        rep.p(f"{len(rows)} addresses advertised (per-address table: {f}). Grouped by advertised name and content; "
              "random addresses (type 1) rotate, so one device appears under many addresses:")
        rep.table(["name (or cached name)", "content", "addresses", "reports", "first", "last", "strongest RSSI"],
                  [(k[0], k[1][:150], g["addr"], g["n"], fmt_t(g["first"]), fmt_t(g["last"]), g["rmax"])
                   for k, g in sorted(grp.items(), key=lambda kv: -kv[1]["n"])], limit=40, more=f)
        # by 128-bit uuid
        by = collections.defaultdict(list)
        for a, r in reps.items():
            for u in r["u128"] | r["s128"]:
                by[u].append((a, r))
        if by:
            rep.p("Custom 128-bit service UUIDs seen in adverts:")
            rep.table(["UUID", "label", "addresses", "first", "last", "strongest RSSI"],
                      [(u, labels.get(u) or KNOWN128.get(u, ""), len(v), fmt_t(min(r["first"] for a, r in v)),
                        fmt_t(max(r["last"] for a, r in v)), max((r["rmax"] for a, r in v if r["rmax"] is not None), default=""))
                       for u, v in sorted(by.items(), key=lambda kv: -len(kv[1]))])
        # media
        if sn.media:
            rep.h(3, "Headset/speaker control traffic (AVRCP, AVDTP, call audio)")
            med = sorted(sn.media, key=lambda x: x[0])
            f = out.csv("bt_media.csv", ["time", "dir", "protocol", "event", "device"],
                        [(fmt_t(t), d, p, e, a) for t, d, p, e, a in med])
            remote_cmds = [(fmt_t(t), a, e) for t, d, p, e, a in med if d == "rx" and "PASS_THROUGH cmd" in e and "pressed" in e]
            playstat = [(fmt_t(t), e.split("-> ")[-1]) for t, d, p, e, a in med if "CHANGED REGISTER_NOTIFICATION PLAYBACK_STATUS_CHANGED" in e]
            stream = [(fmt_t(t), e) for t, d, p, e, a in med if p in ("AVDTP", "SCO") and ("cmd" in e or "link" in e)]
            rep.p(f"{len(med)} events (all in {f}). Button presses sent BY the headset/speaker to the phone:")
            rep.table(["time", "device", "command"], remote_cmds, limit=60)
            rep.p("Playback state changes the phone reported to the headset:")
            rep.table(["time", "state"], playstat, limit=60)
            rep.p("Audio stream starts/stops and call-audio links:")
            rep.table(["time", "event"], stream, limit=60)
    if B.get("mediakeys"):
        rep.p("Media keys routed by the Bluetooth service to the active player:")
        rep.table(["time", "device", "key", "pushed", "active player", "line"], B["mediakeys"], limit=40)
    # cache summary
    if B.get("cache"):
        rep.h(3, "Bluetooth device cache (names the phone learned)")
        c = collections.Counter((d["name"], d["pkgs"]) for d in B["cache"])
        rep.table(["name", "apps tagged on the entry", "cache entries"], [(k[0], k[1], v) for k, v in c.most_common()],
                  limit=40)
        rep.p("Many entries with one name are one device rotating its random address. The app tag shows which app's "
              "scan or connection the device was seen through.")


def r_app_attribution(ctx):
    """Process state of apps that did Bluetooth work, at the times they did it."""
    rep, out = ctx.rep, ctx.out
    B = ctx.btm
    apps = set()
    for sc in B.get("scanners", []):
        apps.add(sc["app"])
    for x in B.get("gatt_client", []) + B.get("gatt_server", []):
        apps.add(x[3])
    for t, sx, tr, stt, hs, ln in B.get("tcb", []):
        for h, _ in hs:
            apps.add(re.sub(r"\[.*\]$", "", h))
    apps.discard("")
    if not apps:
        return
    rep.h(2, "7. Apps behind Bluetooth activity: were they running?")
    rep.p("Process state comes from battery history (+top = on screen, +fg = foreground service such as a media "
          "notification). 'Not on screen, no foreground service' means the process may still have been alive "
          "(cached) or not running at all; exit records below show when Android or the user ended it.")
    for app in sorted(apps):
        uid = uid_of_pkg(ctx, app)
        if uid is None:
            continue
        us = ctx.uidstats.get(uid, {})
        rep.h(3, app)
        bul = []
        if us:
            bul.append("since last charge: " + ", ".join(f"{k} {us[k]}" for k in ("Total running", "Fg Service for", "Top for",
                                                                                 "Background for", "Cached for") if k in us))
            if "bt_scan" in us:
                bul.append(f"Bluetooth scanning {us['bt_scan'][0]} ({us['bt_scan'][1]} scans), of which with the app in "
                           f"the background {us.get('bt_scan_bg', ('0', '0'))[0]}; results {'/'.join(us.get('bt_results', ('', '')))} (total/background)")
            if us.get("starts"):
                bul.append("process starts: " + ", ".join(f"{p} x{n}" for p, n in us["starts"]))
        rep.bullets(bul)
        rows = []
        seen_ids = set()
        for t, sx, tr, stt, hs, ln in B.get("tcb", []):
            for h, idn in hs:
                if re.sub(r"\[.*\]$", "", h) == app and (sx, idn) not in seen_ids:
                    seen_ids.add((sx, idn))
                    rows.append((fmt_t(t), "held LE link to ..:" + sx[-5:] + " " + "/".join(sorted(ctx.bt_names.get(sx[-5:], []))),
                                 app_state(ctx, uid, t), f"L{ln}"))
        for sc in B.get("scanners", []):
            if sc["app"] == app:
                for x in sc["scans"]:
                    t = mdtime(ctx, x["start"])
                    if t:
                        rows.append((fmt_t(t), f"scan {x['dur']} (BT service says importance: {x['imp']})",
                                     app_state(ctx, uid, t), f"L{sc['line']}"))
        for x in B.get("gatt_client", []) + B.get("gatt_server", []):
            if x[3] == app:
                t = mdtime(ctx, x[0])
                rows.append((fmt_t(t), f"GATT {'client' if x in B.get('gatt_client', []) else 'server'} registered until {x[1]}",
                             app_state(ctx, uid, t), f"L{x[6]}"))
        # the phone's own adverts carrying this app's scan-filter UUIDs
        if ctx.bt:
            mine = {u for u, lab in getattr(ctx, "uuid_labels", {}).items() if lab.endswith(app)}
            if mine:
                for h, A in ctx.bt["sn"].adv.items():
                    for t, ad in A["data"] + A["rsp"]:
                        if mine & (set(ad.get("uuid128", [])) | set(ad.get("svc128", []))):
                            rows.append((fmt_t(t), f"phone set advert data with this app's UUID (set {h})",
                                         app_state(ctx, uid, t), "btsnoop"))
        rows.sort()
        f = out.csv(f"app_{app.replace('.', '_')}_bt.csv", ["time", "activity", "app state", "ref"], rows)
        cnt = collections.Counter(r[2] for r in rows)
        dedup = []
        for r in rows:
            if dedup and r[1] == dedup[-1][4] and r[2] == dedup[-1][2]:
                d = dedup[-1]
                dedup[-1] = (d[0].split(" .. ")[0] + " .. " + r[0][6:], f"{d[4]} (x{d[5] + 1})", r[2], d[3], d[4], d[5] + 1)
                continue
            dedup.append((r[0], r[1], r[2], r[3], r[1], 1))
        dedup = [x[:4] for x in dedup]
        rep.p("Activity by app state: " + ", ".join(f"{k}: {v}" for k, v in cnt.most_common()) + f" (all rows in {f}).")
        rep.table(["time", "activity", "app state", "ref"], dedup, limit=25, more=f)
        ex = [x for x in ctx.exits if x["pkg"] == app]
        if ex:
            rep.p("Process exits:")
            rep.table(["time", "process", "reason", "description", "line"],
                      [(fmt_t(x["t"]), x["process"], x["reason"], x["desc"], x["line"]) for x in ex], limit=15)


# ----------------------------------------------------------------------------------------------
# event windows
# ----------------------------------------------------------------------------------------------


def r_events(ctx):
    rep = ctx.rep
    if not ctx.events:
        return
    rep.h(2, "8. Event windows")
    bef, aft = timedelta(seconds=ctx.args.before), timedelta(seconds=ctx.args.after)
    for t0, label in ctx.events:
        a, b = t0 - bef, t0 + aft
        rep.h(3, f"{label} - {t0} (window {fmt_t(a)} -> {fmt_t(b, False)})")
        cov = []
        for s, f, l, n, ref in ctx.coverage:
            if f and l:
                c = "covers" if f <= a and l >= b else ("partly" if l >= a and f <= b else "NO")
                cov.append(f"{s}: {c}")
        rep.p("Coverage: " + "; ".join(cov))
        ev = []
        if ctx.bh:
            keys = ("phone_signal_strength", "data_conn", "nr_state", "phone_state", "+phone_scanning", "wifi_suppl",
                    "+wifi", "+wifi_radio", "+mobile_radio", "conn", "+screen", "+audio", "+phone_in_call", "+ble_scan")
            for e in ctx.bh["events"]:
                if a <= e[0] <= b and e[2] in keys:
                    ev.append((e[0], "battery", f"{e[2]} {e[3]} -> {e[4]}", f"L{e[1]}"))
            for t, ln, sign, key, uid, val in ctx.bh["app"]:
                if a <= t <= b and key in ("top", "fg", "pkginst", "pkgunin"):
                    ev.append((t, "app", f"{sign}{key} {ctx.uidname(uid)} {val}", f"L{ln}"))
        for r in ctx.reg:
            if a <= r["t"] <= b:
                ev.append((r["t"], "registry", f"ph{r['phone']} {r['rat']} band {r['band']} ch {r['ch']} {r['ncc']} carrier(s)", f"L{r['line']}"))
        for s in getattr(ctx, "radio", {}).get("ss", []):
            if a <= s["t"] <= b:
                ev.append((s["t"], "radio", f"signal level {s['level']} data {s['data']} LTE {s['lte_rsrp']} NR {s['nr_rsrp']} primary {s['primary']}", f"L{s['line']}"))
        for m in ctx.mil:
            if a <= m["t"] <= b:
                ev.append((m["t"], "SystemUI", (f"signal LTE {m.get('lte')} NR {m.get('nr')} primary {m.get('primary')}" if m.get("kind") == "signal" else m["msg"]), f"L{m['line']}"))
        for s in ctx.sta:
            if a <= s["t"] <= b:
                ev.append((s["t"], "wifi", f"{s['type']} rssi {s['rssi']} cellularData {s['cell']}", f"L{s['line']}"))
        for c in ctx.wconn:
            if a <= c["t"] <= b:
                ev.append((c["t"], "wifi", f"connect {c['ssid']} {c['bssid']} {'ok' if c['ok'] else 'FAIL'}", f"L{c['line']}"))
        for d in ctx.dn:
            for k in ("setup", "teardown", "disc"):
                if d[k] and a <= d[k] <= b:
                    ev.append((d[k], "data", f"{d['tag']} {d['apn']} {k} {d['reason'] if k == 'teardown' else ''}", f"L{d['line']}"))
        for t, ln, w, o, d2, ws in getattr(ctx, "wifi", {}).get("ctrl", []):
            if a <= t <= b:
                ev.append((t, "wifi ctrl", f"{w} {o}->{d2} {ws}", f"L{ln}"))
        for t, ln, v in getattr(ctx, "aos", {}).get("air", []):
            if a <= t <= b:
                ev.append((t, "IMS", f"airplane mode {'ON' if v else 'OFF'}", f"L{ln}"))
        for t, ln, dsr, rs, why in getattr(ctx, "tds", {}).get("power", []):
            if a <= t <= b:
                ev.append((t, "radio power", f"desired={dsr} reasons=[{why}]", f"L{ln}"))
        if ctx.bt:
            sn = ctx.bt["sn"]
            for t, idx, fn, d, txt in sn.notable:
                if a <= t <= b:
                    addrs = re.findall(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", txt)
                    nmx = "/".join(sorted(getattr(ctx, "bt_names", {}).get(suffix2(addrs[0]), []))) if addrs else ""
                    ev.append((t, "bt-hci", txt + (f" [{nmx}, suffix match]" if nmx else ""), f"{fn}#{idx}"))
            for t, d, p, e, ad in sn.media:
                if a <= t <= b:
                    ev.append((t, "bt-media", f"{d} {p} {e}", ad))
            for t, ad, e in sn.pairing:
                if a <= t <= b:
                    ev.append((t, "bt-pair", e, ad))
        for t, sx, tr, stt, hs, ln in ctx.btm.get("tcb", []):
            if a <= t <= b:
                ev.append((t, "bt-gatt", f"..:{sx[-5:]} {stt} {', '.join(h for h, _ in hs) or 'no app'}", f"L{ln}"))
        for x in ctx.exits:
            if a <= x["t"] <= b:
                ev.append((x["t"], "process", f"{x['process']} ended: {x['reason']} {x['desc'] or ''}", f"L{x['line']}"))
        ev.sort(key=lambda x: x[0])
        rep.table(["time", "source", "event", "ref"], [(fmt_t(t), s, e, r) for t, s, e, r in ev], limit=250)



def r_glance(ctx):
    """Neutral one-line checks, inserted near the top of the report."""
    rows = []
    P, br, L = ctx.props, ctx.br, ctx.br.L

    def prop(k):
        return P.get(k, ("?", None))[0]
    rows.append(("Verified boot / bootloader", f"{prop('ro.boot.verifiedbootstate')}, flash.locked={prop('ro.boot.flash.locked')}, "
                 f"vbmeta={prop('ro.boot.vbmeta.device_state')}", "section 9"))
    ap = br.find("isAdvancedProtectionEnabled:")
    rows.append(("Advanced Protection", L[ap].split(":", 1)[1].strip() if ap is not None else "not found", "section 1"))
    adb = ctx.settings.get("adb_enabled", ("?",))[0]
    rows.append(("USB/wireless debugging", f"adbd {prop('init.svc.adbd')}, adb_enabled={adb}, "
                 f"adb_wifi_enabled={ctx.settings.get('adb_wifi_enabled', ('?',))[0]}", "section 9"))
    dev = ctx.settings.get("development_settings_enabled", ("?",))[0]
    rows.append(("Developer options", {"1": "on (the Bluetooth HCI snoop log setting lives there)", "0": "off"}.get(dev, dev),
                 "section 9"))
    svc = br.service("accessibility")
    acc = "?"
    if svc:
        for i in range(svc[0], svc[1] + 1):
            if L[i].strip().startswith("Enabled services:"):
                acc = L[i].strip().split(":", 1)[1].strip() or "{}"
                break
    rows.append(("Accessibility services enabled", "none" if acc == "{}" else acc[:120], "section 9"))
    two = "?"
    cur = getattr(ctx, "reg_cur", {})
    if "mAllowedNetworkTypeValue" in cur:
        v = int(cur["mAllowedNetworkTypeValue"][0])
        t2 = [n for bit, n in NT_BITS.items() if v & (1 << (bit - 1)) and n in TWO_G]
        two = "no (2G excluded)" if not t2 else "yes: " + ",".join(t2)
    rows.append(("2G allowed", two, "section 2"))
    R = getattr(ctx, "radio", {}) or {}
    nul = sum(v for k, v in R.get("alg", {}).items() if k[1] in NULL_ALGS or k[2] in NULL_ALGS or k[3] == "true")
    tot = sum(R.get("alg", {}).values())
    rows.append(("Null/unprotected ciphering reported", f"{nul} of {tot} reports (radio log window only)", "section 2"))
    T = getattr(ctx, "tds", {}) or {}
    if T.get("nitz"):
        big = [o for _, _, o in T["nitz"] if abs(o) > 2]
        rows.append(("NITZ network time off by >2 s", f"{len(big)} of {len(T['nitz'])}", "section 2"))
    per = collections.defaultdict(set)
    for c in ctx.wconn:
        per[c["ssid"]].add(c["bssid"])
    rows.append(("Wi-Fi networks joined (BSSIDs)", "; ".join(f"{k}: {len(v)}" for k, v in per.items()) or "none in log",
                 "section 3"))
    tz = ctx.tz
    share, tot_h = collections.Counter(), collections.Counter()
    rb = ctx.bh["rows"] if ctx.bh else []
    for x, y in zip(rb, rb[1:]):
        t = x["t"]
        while t < y["t"]:
            h = t.replace(minute=0, second=0, microsecond=0)
            se = min(y["t"], h + timedelta(hours=1))
            k = int(h.replace(tzinfo=tz).timestamp())
            tot_h[k] += (se - t).total_seconds()
            if x["wifi_suppl"] == "completed":
                share[k] += (se - t).total_seconds()
            t = se
    full = [k for k in tot_h if tot_h[k] >= 3500 and share[k] / tot_h[k] >= 0.995]
    md = [k for k in full if ctx.ns.get(k, {}).get("mob_inet_default", 0) > 0]
    mn = [k for k in full if ctx.ns.get(k, {}).get("mob_inet_notdefault", 0) >= 1000]
    rows.append(("Mobile data used while on Wi-Fi all hour", f"default route: {len(md)} of {len(full)} hours; "
                 f"non-default >=1 kB: {len(mn)} hours", "section 4"))
    short = [d for d in ctx.dn if d["setup"] and (d["disc"] or d["teardown"]) and ((d["disc"] or d["teardown"]) - d["setup"]).total_seconds() < 10]
    rows.append(("Cellular data connections under 10 s", ", ".join(f"{d['tag']} {fmt_t(d['setup'])}" for d in short) or "none",
                 "section 4"))
    air = sorted(getattr(ctx, "aos", {}).get("air", []))
    ons = sorted({fmt_t(t)[:-4] for t, ln, v in air if v})
    rows.append(("Airplane mode switched on", ", ".join(ons) or "not in logs", "section 5"))
    if ctx.bt:
        sn = ctx.bt["sn"]
        newkeys = [(t, a) for t, a, e in sn.pairing if "NEW KEY" in e]
        rows.append(("New Bluetooth pairing keys", ", ".join(f"{a} {fmt_t(t)}" for t, a in newkeys) or "none", "section 6"))
        names = getattr(ctx, "bt_names", {})
        rin = [s for s in sn.sessions if s.get("init") == "remote" and not s.get("failed")]
        gi = collections.OrderedDict()
        for s_ in rin:
            k = (s_["transport"], "/".join(sorted(names.get(suffix2(s_["addr"]), []))) or s_["addr"])
            gi.setdefault(k, []).append(s_["start"])
        rows.append(("Connections started by other devices",
                     "; ".join(f"{k[1]} ({k[0]}) x{len(v)}, first {fmt_t(min(v))}" for k, v in gi.items()) or "none",
                     "section 6"))
        disc = [(t, e) for t, e in sn.scan_enable if "DISCOVERABLE" in e]
        rows.append(("Phone made itself discoverable (classic)", ", ".join(fmt_t(t) for t, e in disc) or "none in snoop log",
                     "section 6"))
        presses = [x for x in sn.media if x[1] == "rx" and "PASS_THROUGH cmd" in x[3] and "pressed" in x[3]]
        rows.append(("Button presses sent by headsets/speakers", f"{len(presses)} "
                     f"({', '.join(f'{k} {v}' for k, v in collections.Counter(x[3].split()[3] for x in presses).most_common())})",
                     "section 6"))
    holders = collections.defaultdict(set)
    for t, sx, tr, stt, hs, ln in ctx.btm.get("tcb", []):
        for h, idn in hs:
            holders[re.sub(r"\[.*\]$", "", h)].add((sx, idn))
    rows.append(("Apps that held Bluetooth LE links (GATT sessions, peers)",
                 ", ".join(f"{k} ({len(v)}, {len({x[0] for x in v})} peers)" for k, v in sorted(holders.items(), key=lambda kv: -len(kv[1])))
                 or "none", "sections 6-7"))
    bg = []
    for sc in ctx.btm.get("scanners", []):
        uid = uid_of_pkg(ctx, sc["app"])
        us = ctx.uidstats.get(uid, {}) if uid else {}
        if us.get("bt_scan_bg"):
            bg.append(f"{sc['app']} {us['bt_scan_bg'][0]}")
    rows.append(("Bluetooth scanning while the app was in the background (since charge)", "; ".join(bg) or "none",
                 "section 6"))
    rem = [x for x in ctx.exits if x["desc"] and x["desc"].startswith("remove-by-pid#") and (x["t"].hour < 4 or x["t"].hour >= 22)]
    rows.append(("Apps removed from Recents 22:00-04:00", f"{len(rem)}" + (f" ({', '.join(sorted({fmt_t(x['t'])[:11] for x in rem}))})" if rem else ""),
                 "section 9"))
    inst = [x for x in (ctx.bh["app"] if ctx.bh else []) if x[3] in ("pkginst", "pkgunin")]
    rows.append(("Package installs/removals in battery history", f"{len(inst)}", "section 9"))
    mini = Report()
    mini.h(2, "At a glance (neutral checks; details in the sections named)")
    mini.table(["check", "result", "where"], rows)
    ctx.rep.parts[2:2] = mini.parts

# ----------------------------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------------------------


def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(prog=prog, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="bug report .zip, extracted folder, or bugreport-*.txt")
    ap.add_argument("--out", required=True, help="new output folder (must not exist)")
    ap.add_argument("--event", action="append", default=[], help='"YYYY-MM-DDTHH:MM:SS|label" in device local time')
    ap.add_argument("--before", type=float, default=120.0)
    ap.add_argument("--after", type=float, default=120.0)
    ap.add_argument("--keep-big", action="store_true", help="also write every battery-history line as JSONL")
    args = ap.parse_args(argv)
    if os.path.exists(args.out):
        sys.exit(f"--out {args.out} already exists; choose a new folder so earlier results are never overwritten")
    os.makedirs(args.out)
    ctx = Ctx(args)
    ctx.out = Out(args.out)
    rep = ctx.rep
    manifest = {"tool": "rfpass.py", "version": VERSION, "tool_sha256": sha256_file(os.path.abspath(__file__)),
                "toolkit_sha256": toolkit_sha256(),
                "python": sys.version.split()[0], "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "input": os.path.abspath(args.input), "events": args.event}
    inp = args.input
    if os.path.isfile(inp) and zipfile.is_zipfile(inp):
        manifest["input_sha256"] = sha256_file(inp)
        manifest["input_bytes"] = os.path.getsize(inp)
        folder = os.path.join(args.out, "extracted")
        manifest["members"] = safe_extract(inp, folder, rep.problems)
        main_txt = locate_main_txt(folder)
    elif os.path.isdir(inp):
        folder = inp
        main_txt = locate_main_txt(folder)
    else:
        folder = os.path.dirname(os.path.abspath(inp))
        main_txt = inp
    if not main_txt:
        sys.exit("could not find the main bugreport-*.txt")
    manifest["main_txt"] = main_txt
    manifest["main_txt_sha256"] = sha256_file(main_txt)
    ctx.snoops = locate_snoops(folder)
    ctx.br = BR(main_txt, rep.problems)
    part(ctx, "identity", p_identity)
    for ev in args.event:
        ts, _, label = ev.partition("|")
        t = iso(ts.strip())
        if t is None:
            rep.problems.append(f"bad --event time {ts!r}")
        else:
            ctx.events.append((t.replace(tzinfo=None), label.strip() or ts))
    for name, fn in (("logcat coverage", p_logcat_coverage), ("battery history", p_battery_history),
                     ("telephony registry", p_registry), ("radio log", p_radio_log), ("SystemUI log", p_mobileinput),
                     ("carrier config", p_carrier_config), ("telephony debug", p_tds), ("IMS log", p_ims_aos),
                     ("bandwidth estimator TACs", p_lbe_tac), ("wifi", p_wifi), ("batterystats per-uid", p_uidstats),
                     ("process exits", p_exits), ("netstats", p_netstats), ("validation logs", p_validation),
                     ("btsnoop", p_btsnoop), ("bluetooth_manager", p_btmanager)):
        part(ctx, name, fn)
    if ctx.bh is None:
        ctx.bh = {"rows": [], "events": [], "app": [], "range": (0, 0), "mismatch": 0, "markers": []}
    for d in ("wifi", "tds", "aos", "radio"):
        if not hasattr(ctx, d):
            setattr(ctx, d, {})
    if not hasattr(ctx, "mil"):
        ctx.mil = []
    rep.p(f"# Bug-report wireless analysis\n")
    rep.p(f"Input `{os.path.basename(args.input)}`" + (f" (SHA-256 `{manifest.get('input_sha256')}`)" if manifest.get("input_sha256") else "")
          + f"; main text `{os.path.basename(main_txt)}` (SHA-256 `{manifest['main_txt_sha256']}`). "
          f"Generated by rfpass.py {VERSION} (SHA-256 `{manifest['tool_sha256'][:16]}...`) on {manifest['run_utc']} UTC. "
          "Line numbers (L...) refer to the main text file; btsnoop references are file#record (0-based).")
    for name, fn in (("identity report", r_identity), ("coverage report", r_coverage), ("cellular report", r_cellular),
                     ("registry report", r_registry), ("signal by band", r_signal_by_band),
                     ("carrier config report", r_carrier_config), ("radio report", r_radio), ("tds report", r_tds),
                     ("plmn report", r_plmn), ("wifi report", r_wifi), ("mobile vs wifi", r_mobile_vs_wifi),
                     ("airplane", r_airplane), ("bluetooth report", r_bluetooth), ("app attribution", r_app_attribution),
                     ("event windows", r_events), ("integrity", r_integrity), ("at a glance", r_glance)):
        part(ctx, name, fn)
    rep.h(2, "10. Run notes")
    rep.bullets([f"tool version {VERSION}; Python {manifest['python']}",
                 f"btsnoop files: {', '.join(os.path.basename(x) for x in ctx.snoops) or 'none found'}",
                 f"battery-history text-vs-state-word signal mismatches: {ctx.bh.get('mismatch')}"]
                + [f"problem: {p}" for p in rep.problems] or ["no problems"])
    with open(os.path.join(args.out, "report.md"), "w") as fh:
        fh.write(rep.text())
    manifest["outputs"] = sorted(os.path.relpath(p, args.out) for p in ctx.out.files) + ["report.md"]
    manifest["problems"] = rep.problems
    with open(os.path.join(args.out, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, default=str)
    print(f"report: {os.path.join(args.out, 'report.md')}  problems: {len(rep.problems)}")
    for p in rep.problems:
        print("  -", p)


if __name__ == "__main__":
    main()
