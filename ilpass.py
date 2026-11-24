#!/usr/bin/env python3
"""ilpass.py - Android Advanced Protection intrusion-log analyzer (Python 3.9+ standard library only).

Consolidates a set of one-off analysis scripts into one repeatable pass. Input: the exported intrusion-log
files (a folder of *.txt, or the .zip the phone produces). Output: report.md, tables.json, manifest.json and
a normalized events.jsonl in a new folder. Inputs are never modified.

Sections
  1. provenance      - file hashes, coverage per file, parse errors, duplicates, counts by type
  2. completeness    - boots (from ID resets and os_startup/os_shutdown), missing network IDs per boot,
                       security-ID slotting test (are ID gaps filled by events exported with ID 0?), silences
  3. unlocks         - attempts by method and result, failures, first unlock after each boot, unlocks in a
                       night window, dismissals with no auth attempt
  4. packages        - installs/updates/uninstalls, APK-hash continuity per package (Play update, across a boot,
                       or unexplained), signer-tag consistency, secondary users/profiles
  5. network         - ports, destination classes, odd DNS answers, connects with no prior lookup, PaaS/tunnel
                       hostnames, first-seen domains per day, public connects while locked at night
  6. indicators      - domains (+ parents), IPs, packages and APK hashes against every STIX2 file given
                       (default: MVT's downloaded indicator folder)
  7. bluetooth       - bonded devices (pairing successes), sessions, short connections to unbonded addresses,
                       bursts, and which app had network activity just before each burst began
  8. event windows   - every event within a window around times you pass with --event

Each section prints its "look closer" reading next to the table. Nothing here proves how anything was done.

Usage
  python3 -I ilpass.py <folder | export.zip> --out <new folder>
         [--iocs DIR ...] [--event "2026-01-15T10:08:11|label"] [--before 120] [--after 120]
         [--night 21-04] [--tz America/New_York]
"""
import argparse
import bisect
import collections
import glob
import hashlib
import ipaddress
import json
import os
import re
import statistics
import sys
import zipfile
from datetime import datetime, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    sys.exit("Python 3.9+ required (zoneinfo)")

VERSION = "0.1.2 (2026-11-24)"
SOMETIMES_NUMBERED = ("sec:bluetooth_connection", "sec:bluetooth_disconnection", "sec:keyguard_dismiss_auth_attempt",
                      "sec:keyguard_dismissed", "sec:keyguard_secured")
PAAS = ("onrender.com", "ngrok", "trycloudflare", "herokuapp", "vercel.app", "netlify.app", "workers.dev", "pages.dev",
        "glitch.me", "repl.co", "duckdns", "no-ip", "ddns", "serveo", "localtunnel", "pastebin", "github.io",
        "firebaseio.com", "appspot.com", "web.app")
SHARED_PROCS = {"android.process.acore", "android.process.media", "com.android.phone", "system"}
RENDERER = ("sandboxed_process", "webview", "isolated", "privileged_process", "WebViewLoader")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Rep:
    def __init__(self):
        self.parts = []

    def h(self, n, t):
        self.parts.append("\n" + "#" * n + " " + t + "\n\n")

    def p(self, t):
        self.parts.append(t + "\n\n")

    def look(self, t):
        self.parts.append("> **Look closer if:** " + t + "\n\n")

    def table(self, hdr, rows, limit=None):
        rows = list(rows)
        if not rows:
            self.p("_(none)_")
            return
        esc = lambda x: str("" if x is None else x).replace("|", "\\|").replace("\n", " ")
        self.parts.append("| " + " | ".join(hdr) + " |\n|" + "|".join("---" for _ in hdr) + "|\n")
        for r in rows[:limit]:
            self.parts.append("| " + " | ".join(esc(c) for c in r) + " |\n")
        if limit and len(rows) > limit:
            self.parts.append(f"\n_({len(rows) - limit} more rows in tables.json)_\n")
        self.parts.append("\n")


# ---------------------------------------------------------------------------------------------- loading

def load(src_dir, tz):
    files = sorted(f for f in os.listdir(src_dir) if f.endswith(".txt"))
    rows, bad, per_file = [], 0, []
    for f in files:
        p = os.path.join(src_dir, f)
        ts = []
        with open(p, "rb") as fh:
            for ln, raw in enumerate(fh, 1):
                s = raw.decode("utf-8", "replace").strip()
                if not s:
                    continue
                try:
                    d = json.loads(s)
                    (top, body), = d.items()
                except Exception:
                    bad += 1
                    continue
                traw = int(body.get("event_time", 0))
                t_ns = traw if traw > 10 ** 15 else traw * 1_000_000
                if top == "security_event":
                    sub = [k for k in body if k not in ("event_id", "event_time")]
                    typ = "sec:" + (sub[0] if sub else "?")
                    payload = body[sub[0]] if sub else {}
                elif top == "dns_event":
                    typ, payload = "dns", {k: v for k, v in body.items() if k not in ("event_id", "event_time")}
                elif top == "connect_event":
                    typ, payload = "connect", {k: v for k, v in body.items() if k not in ("event_id", "event_time")}
                else:
                    typ, payload = "other:" + top, body
                rows.append({"top": top, "type": typ, "id": body.get("event_id"), "t_raw": traw, "t_ns": t_ns,
                             "payload": payload, "file": f, "line": ln})
                ts.append(t_ns)
        per_file.append((f, sha256_file(p), len(ts), min(ts) if ts else None, max(ts) if ts else None))
    seen, uniq = set(), []
    for r in rows:
        k = (r["top"], r["id"], r["t_raw"], json.dumps(r["payload"], sort_keys=True))
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    uniq.sort(key=lambda r: (r["t_ns"], r["file"], r["line"]))
    return uniq, per_file, bad, len(rows) - len(uniq)


# ---------------------------------------------------------------------------------------------- helpers

def mk_fmt(tz):
    def et(ns, f="%a %m-%d %H:%M:%S"):
        return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).astimezone(tz).strftime(f)

    def dt(ns):
        return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).astimezone(tz)
    return et, dt


def pkg(e):
    p = e["payload"]
    if e["type"] in ("dns", "connect"):
        return (p.get("package_name") or "").split(":")[0]
    if e["type"] == "sec:app_process_start":
        return (p.get("process") or "").split(":")[0]
    return p.get("package_name", "")


def ipn(s):
    return (s or "").lstrip("/")


def ipclass(a):
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return "invalid"
    if str(ip) in ("0.0.0.0", "::"):
        return "blocked(0.0.0.0/::)"
    if ip.is_loopback:
        return "loopback"
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    return "public"


def regdom(h):
    parts = h.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def epochs_by_reset(evs):
    """Split time-ordered events into epochs where the ID resets to near zero (a reboot restarts the counter).
    Small backward steps are not resets: events sharing a timestamp can be exported out of ID order."""
    out, cur = [], []
    hi = -1
    for e in evs:
        if cur and e["id"] <= 100 and hi - e["id"] > 100:
            out.append(cur)
            cur = []
            hi = -1
        cur.append(e)
        hi = max(hi, e["id"])
    if cur:
        out.append(cur)
    return out


# ---------------------------------------------------------------------------------------------- sections

def s_provenance(R, T, ev, per_file, bad, dups, et):
    R.h(2, "1. Provenance")
    R.table(["file", "SHA-256", "events", "first", "last"],
            [(f, h, n, et(a) if a else "-", et(b) if b else "-") for f, h, n, a, b in per_file])
    c = collections.Counter(e["type"] for e in ev)
    R.p(f"{len(ev)} unique events; {dups} duplicate lines removed; {bad} lines failed to parse. "
        f"Range {et(ev[0]['t_ns'])} → {et(ev[-1]['t_ns'])}.")
    R.table(["type", "count"], c.most_common())
    R.look("parse errors > 0, or files whose time ranges leave a gap between exports.")
    T["counts"] = dict(c)


def s_completeness(R, T, ev, et):
    R.h(2, "2. Boots and completeness")
    net = [e for e in ev if e["top"] != "security_event"]
    sec = [e for e in ev if e["top"] == "security_event"]
    rows = []
    for ep in epochs_by_reset(net):
        ids = [e["id"] for e in ep]
        s = set(ids)
        miss = [i for i in range(min(ids), max(ids) + 1) if i not in s]
        rows.append((et(ep[0]["t_ns"]), et(ep[-1]["t_ns"]), len(ep), f"{min(ids)}–{max(ids)}", len(miss),
                     ", ".join(map(str, miss[:10]))))
    R.p("Network-event ID epochs (IDs restart at 0 after each boot):")
    R.table(["first", "last", "events", "IDs", "missing", "first missing"], rows)
    T["net_epochs"] = rows
    nz = sorted((e for e in sec if e["id"] != 0), key=lambda e: e["t_ns"])
    sep = epochs_by_reset(nz)
    R.p("Security-event ID epochs (nonzero IDs):")
    R.table(["first", "first ID", "last", "last ID", "events"],
            [(et(p[0]["t_ns"]), p[0]["id"], et(p[-1]["t_ns"]), p[-1]["id"], len(p)) for p in sep])
    # slotting test
    z = [e for e in sec if e["id"] == 0 and e["type"] in SOMETIMES_NUMBERED]
    zt = [e["t_ns"] for e in z]
    missing = filled = 0
    mism = []
    for ep in sep:
        for a, b in zip(ep, ep[1:]):
            step = b["id"] - a["id"]
            if step <= 1:
                continue
            n0 = bisect.bisect_left(zt, b["t_ns"]) - bisect.bisect_right(zt, a["t_ns"])
            missing += step - 1
            filled += min(n0, step - 1)
            if n0 != step - 1:
                mism.append((et(a["t_ns"]), a["id"], et(b["t_ns"]), b["id"], step - 1, n0))
    R.p(f"Slotting test: {missing} gaps in nonzero security IDs; {len(z)} events exported with ID 0 of types that "
        f"are sometimes numbered; {filled} gaps filled exactly. Gaps where the counts differ: {len(mism)}.")
    R.table(["after", "ID", "before", "ID", "IDs missing", "ID-0 events available"], mism, limit=40)
    starts = [(et(e["t_ns"]), e["type"][4:]) for e in sec if e["type"] in ("sec:os_startup", "sec:os_shutdown")]
    R.p("Logged startups/shutdowns: " + (", ".join(f"{t} {k}" for t, k in starts) or "none") +
        ". Events between a shutdown and the first unlock after boot are not exported.")
    allt = sorted(e["t_ns"] for e in ev)
    gaps = sorted(((b - a) / 6e10, a, b) for a, b in zip(allt, allt[1:]))[-8:]
    R.p("Longest silences (all streams):")
    R.table(["minutes", "from", "to"], [(f"{g:.1f}", et(a), et(b)) for g, a, b in reversed(gaps)])
    R.look("missing network IDs inside an epoch; security-ID gaps not filled by ID-0 events; a silence that "
           "isn't explained by the phone being idle, off, or not yet unlocked after a boot.")
    T["slotting"] = {"missing": missing, "filled": filled, "mismatches": mism}


def s_unlocks(R, T, ev, et, dt, night):
    R.h(2, "3. Unlocks")
    kg = [e for e in ev if e["type"] in ("sec:keyguard_dismiss_auth_attempt", "sec:keyguard_dismissed",
                                         "sec:keyguard_secured")]
    att = [e for e in kg if e["type"] == "sec:keyguard_dismiss_auth_attempt"]
    c = collections.Counter((e["payload"].get("success"), e["payload"].get("method_strength")) for e in att)
    R.table(["success", "method (1 = PIN/password, 0 = biometric/trust agent)", "attempts"],
            [(k[0], k[1], v) for k, v in sorted(c.items(), key=str)])
    ok = [e["t_ns"] for e in att if e["payload"].get("success")]
    fails = []
    for e in att:
        if not e["payload"].get("success"):
            i = bisect.bisect_right(ok, e["t_ns"])
            nxt = (ok[i] - e["t_ns"]) / 1e9 if i < len(ok) else None
            fails.append((et(e["t_ns"]), e["payload"].get("method_strength"),
                          f"{nxt:.1f}" if nxt is not None else "none", f"{e['file']}:{e['line']}"))
    R.p(f"Failed attempts: {len(fails)}")
    R.table(["time", "method", "s to next success", "source"], fails)
    # first unlock after each boot
    sec_nz = sorted((e for e in ev if e["top"] == "security_event" and e["id"] != 0), key=lambda e: e["t_ns"])
    bstarts = [p[0]["t_ns"] for p in epochs_by_reset(sec_nz)]
    first = []
    for b in bstarts:
        nxt = [e for e in att if e["t_ns"] >= b - 5e9 and e["payload"].get("success")][:1]
        if nxt:
            first.append((et(b), et(nxt[0]["t_ns"]), "PIN/password" if nxt[0]["payload"].get("method_strength") == 1
                          else "NOT PIN"))
    R.p("First successful unlock after each boot (Android requires the PIN after a restart):")
    R.table(["boot (first numbered event)", "first unlock", "method"], first)
    a, b = night
    nn = [(et(e["t_ns"]), e["payload"].get("method_strength"), e["payload"].get("success")) for e in att
          if (dt(e["t_ns"]).hour >= a or dt(e["t_ns"]).hour < b)]
    R.p(f"Auth attempts between {a:02d}:00 and {b:02d}:00: {len(nn)}")
    R.table(["time", "method", "success"], nn, limit=60)
    # dismissals with no attempt in the preceding 2 s
    at = sorted(e["t_ns"] for e in att)
    lonely = []
    for e in kg:
        if e["type"] != "sec:keyguard_dismissed":
            continue
        i = bisect.bisect_right(at, e["t_ns"] + 2e9)
        if i == 0 or e["t_ns"] - at[i - 1] > 2e9:
            lonely.append(et(e["t_ns"]))
    R.p(f"Dismissals with no auth attempt within 2 s: {len(lonely)}" + (f" — {', '.join(lonely[:20])}" if lonely else ""))
    R.look("a non-PIN first unlock after a boot; unlocks during hours you were asleep (confirm each); dismissals "
           "with no attempt while the phone had been secured; repeated failures not followed by your own success.")
    T["unlocks"] = {"fails": fails, "first_after_boot": first, "night": nn, "no_attempt": lonely}


def s_packages(R, T, ev, et):
    R.h(2, "4. Packages and processes")
    for typ, title in (("sec:package_installed", "Installs"), ("sec:package_uninstalled", "Uninstalls")):
        xs = [(et(e["t_ns"]), e["payload"].get("package_name"), e["payload"].get("version_code"),
               e["payload"].get("user_id")) for e in ev if e["type"] == typ]
        R.p(f"{title}: {len(xs)}")
        R.table(["time", "package", "version", "user"], xs, limit=60)
    upd = collections.defaultdict(list)
    for e in ev:
        if e["type"] == "sec:package_updated":
            upd[e["payload"].get("package_name")].append(e["t_ns"])
    R.p(f"Updates: {sum(len(v) for v in upd.values())} across {len(upd)} packages.")
    ps = [e for e in ev if e["type"] == "sec:app_process_start"]
    sec_nz = sorted((e for e in ev if e["top"] == "security_event" and e["id"] != 0), key=lambda e: e["t_ns"])
    # a reboot happened after the last event of one epoch; use that as the boundary
    boots = [p[-1]["t_ns"] + 1 for p in epochs_by_reset(sec_nz)][:-1]
    seq = collections.defaultdict(list)
    tags = collections.defaultdict(collections.Counter)
    for e in ps:
        n = e["payload"].get("process", "")
        if any(k in n for k in RENDERER):
            continue
        b = n.split(":")[0]
        part = (re.search(r"partition=([a-z_]+)", e["payload"].get("seinfo", "")) or [None, "data"])[1]
        seq[b].append((e["t_ns"], e["payload"].get("sha256"), part))
        tags[b][e["payload"].get("seinfo", "").split(":")[0]] += 1
    cls, unexplained = collections.Counter(), []
    for b, xs in seq.items():
        xs.sort()
        for (t0, h0, p0), (t1, h1, p1) in zip(xs, xs[1:]):
            if h0 == h1:
                continue
            ups = [u for p, us in upd.items() if b == p or b.startswith(p + ".") for u in us]
            if any(t0 - 5e9 <= u <= t1 + 5e9 for u in ups):
                cls["Play update in between"] += 1
            elif any(t0 < bt <= t1 for bt in boots) and p0 != "data":
                cls["across a reboot, system partition (OTA)"] += 1
            elif b in SHARED_PROCS:
                cls["shared process name (hosts several packages)"] += 1
            else:
                cls["UNEXPLAINED"] += 1
                unexplained.append((b, et(t0), et(t1), (h0 or "")[:12], (h1 or "")[:12], p0, p1))
    R.p("APK-hash changes per package (own processes; WebView renderers excluded because they carry WebView's hash):")
    R.table(["classification", "changes"], cls.most_common())
    R.table(["package", "last old", "first new", "old hash", "new hash", "old partition", "new partition"],
            unexplained)
    multi = [(b, dict(t)) for b, t in tags.items() if len(t) > 1]
    nosha = collections.Counter(e["payload"].get("process", "").split(":")[0] for e in ps if not e["payload"].get("sha256"))
    users = sorted({e["payload"].get("uid") // 100000 for e in ps if isinstance(e["payload"].get("uid"), int)})
    R.p(f"Packages with more than one signer tag: {multi or 'none'}. Process starts without an APK hash: "
        f"{dict(nosha) or 'none'}. Android users seen in process UIDs: {users}.")
    R.look("an UNEXPLAINED hash change; a package with two signer tags; a process start with no hash; a user other "
           "than 0 (work profile, Private Space, second user) you didn't create; installs or uninstalls you didn't do.")
    T["apk"] = {"classes": dict(cls), "unexplained": unexplained, "multi_signer": multi}


def s_network(R, T, ev, et, dt, night):
    R.h(2, "5. Network")
    dns = [e for e in ev if e["type"] == "dns"]
    con = [e for e in ev if e["type"] == "connect"]
    R.p(f"{len(dns)} DNS lookups, {len(con)} TCP connects. The log has no byte counts and no UDP/QUIC.")
    ports = collections.Counter(e["payload"].get("port") for e in con)
    R.table(["port", "connects", "top apps"],
            [(p, n, ", ".join(f"{a} ({c})" for a, c in collections.Counter(pkg(e) for e in con if e["payload"].get("port") == p).most_common(3)))
             for p, n in ports.most_common()])
    cc = collections.Counter(ipclass(ipn(e["payload"].get("ip_address"))) for e in con)
    R.p("Destination classes: " + ", ".join(f"{k} {v}" for k, v in cc.most_common()))
    odd = collections.Counter()
    for e in con:
        c = ipclass(ipn(e["payload"].get("ip_address")))
        if c in ("private", "link-local", "cgnat", "multicast", "invalid"):
            odd[(pkg(e) or "(system)", ipn(e["payload"].get("ip_address")), e["payload"].get("port"), c)] += 1
    R.table(["app", "destination", "port", "class", "connects"], [k + (v,) for k, v in odd.most_common()], limit=30)
    oddans = collections.Counter()
    for e in dns:
        h = e["payload"].get("hostname", "")
        if h == "localhost":
            continue
        for a in e["payload"].get("ip_addresses", []) or []:
            c = ipclass(ipn(a))
            if c not in ("public", "blocked(0.0.0.0/::)"):
                oddans[(h, ipn(a), c, pkg(e))] += 1
    blocked = collections.Counter(e["payload"].get("hostname") for e in dns
                                  if any(ipclass(ipn(a)) == "blocked(0.0.0.0/::)" for a in e["payload"].get("ip_addresses", []) or []))
    R.p(f"DNS answers in private/loopback/odd ranges for public names: {sum(oddans.values())}. "
        f"Lookups answered 0.0.0.0/:: (blocked by your resolver): {sum(blocked.values())} across {len(blocked)} names.")
    R.table(["hostname", "answer", "class", "app", "n"], [k + (v,) for k, v in oddans.most_common()], limit=30)
    first_ip = {}
    for e in dns:
        for a in e["payload"].get("ip_addresses", []) or []:
            first_ip.setdefault(ipn(a), e["t_ns"])
    nodns = collections.defaultdict(set)
    for e in con:
        a = ipn(e["payload"].get("ip_address"))
        if ipclass(a) == "public" and (a not in first_ip or first_ip[a] > e["t_ns"]):
            nodns[(pkg(e) or "(system)", e["payload"].get("port"))].add(a)
    R.p("Connects to public IPs never seen in a DNS answer before the connect (apps with their own DNS-over-HTTPS, "
        "carrier IMS, and hard-coded endpoints appear here):")
    R.table(["app", "port", "distinct IPs", "examples"],
            sorted(((k[0], k[1], len(v), ", ".join(sorted(v)[:4])) for k, v in nodns.items()), key=lambda r: -r[2]), limit=30)
    paas = collections.defaultdict(list)
    for e in dns:
        h = (e["payload"].get("hostname") or "").lower()
        if any(k in h for k in PAAS):
            paas[(h, pkg(e))].append(e["t_ns"])
    R.p("PaaS / tunnel / dynamic-DNS hostnames:")
    R.table(["hostname", "app", "lookups", "first", "last"],
            [(h, p, len(ts), et(min(ts)), et(max(ts))) for (h, p), ts in sorted(paas.items(), key=lambda kv: kv[1][0])])
    first = {}
    for e in dns:
        r = regdom((e["payload"].get("hostname") or "").lower())
        if r and r not in first:
            first[r] = (e["t_ns"], pkg(e), e["payload"].get("hostname"))
    byday = collections.Counter(dt(t).strftime("%a %m-%d") for t, _, _ in first.values())
    R.p("First-seen registrable domains per day (the first day is everything seen so far): " +
        ", ".join(f"{d} {n}" for d, n in byday.items()) + ". Full list in tables.json.")
    kg = sorted((e for e in ev if e["type"] in ("sec:keyguard_secured", "sec:keyguard_dismissed")), key=lambda e: e["t_ns"])
    kt = [e["t_ns"] for e in kg]

    def locked(t):
        i = bisect.bisect_right(kt, t) - 1
        return i >= 0 and kg[i]["type"] == "sec:keyguard_secured"
    a, b = night
    nights = collections.defaultdict(collections.Counter)
    for e in con:
        h = dt(e["t_ns"]).hour
        if (h >= a or h < b) and ipclass(ipn(e["payload"].get("ip_address"))) == "public":
            nights[dt(e["t_ns"] - (b * 3600e9)).strftime("night of %a %m-%d") + (" locked" if locked(e["t_ns"]) else " unlocked")][pkg(e) or "(system)"] += 1
    R.p(f"Public connects between {a:02d}:00 and {b:02d}:00, by night and lock state:")
    R.table(["night", "connects", "top apps"],
            [(k, sum(v.values()), ", ".join(f"{p} ({n})" for p, n in v.most_common(6))) for k, v in sorted(nights.items())])
    R.look("private or odd answers for public names (DNS tampering); connects to private/CGNAT addresses by an app "
           "with no local-network function; a non-system app with many connects that never resolved by DNS; a PaaS "
           "or dynamic-DNS host contacted by an app you can't tie to a page you loaded; locked-night traffic from an "
           "app with no reason to sync then.")
    T["network"] = {"ports": dict(ports), "classes": dict(cc), "odd_answers": [list(k) + [v] for k, v in oddans.items()],
                    "no_dns": {f"{k[0]}:{k[1]}": sorted(v) for k, v in nodns.items()},
                    "paas": {f"{h} {p}": len(ts) for (h, p), ts in paas.items()},
                    "first_seen": sorted(((et(t), r, h, p) for r, (t, p, h) in first.items()))}


def load_iocs(dirs):
    DOM, IP, PKG, SHA = (collections.defaultdict(set) for _ in range(4))
    pat = re.compile(r"\[(domain-name:value|ipv4-addr:value|ipv6-addr:value|app:id|file:hashes\.sha256|"
                     r"file:hashes\.'SHA-256'|url:value)\s*=\s*'([^']+)'\]")
    dom_re = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
    files = []
    for d in dirs:
        files += sorted(glob.glob(os.path.join(os.path.expanduser(d), "**", "*.stix2"), recursive=True))
    for f in files:
        src = os.path.basename(f)
        try:
            objs = json.load(open(f)).get("objects", [])
        except Exception:
            continue
        for o in objs:
            for k, v in pat.findall(o.get("pattern") or ""):
                if k in ("domain-name:value", "url:value"):
                    v = re.sub(r"^https?://", "", v.lower()).split("/")[0].split(":")[0].lstrip("*.").rstrip(".")
                    if "@" not in v and dom_re.match(v):
                        DOM[v].add(src)
                elif k.startswith("ipv"):
                    try:
                        IP[str(ipaddress.ip_address(v.split("/")[0]))].add(src)
                    except ValueError:
                        pass
                elif k == "app:id":
                    PKG[v].add(src)
                else:
                    if re.match(r"^[0-9a-fA-F]{64}$", v):
                        SHA[v.lower()].add(src)
    return files, DOM, IP, PKG, SHA


def s_indicators(R, T, ev, dirs):
    R.h(2, "6. Indicator matching")
    files, DOM, IP, PKG, SHA = load_iocs(dirs)
    hosts, ips, pkgs, shas = set(), set(), set(), set()
    for e in ev:
        p = e["payload"]
        if e["type"] == "dns":
            h = (p.get("hostname") or "").lower().rstrip(".")
            parts = h.split(".")
            hosts.update(".".join(parts[i:]) for i in range(len(parts) - 1))
            ips.update(ipn(a) for a in p.get("ip_addresses", []) or [])
        elif e["type"] == "connect":
            ips.add(ipn(p.get("ip_address")))
        elif e["type"] == "sec:app_process_start" and p.get("sha256"):
            shas.add(p["sha256"].lower())
        if pkg(e):
            pkgs.add(pkg(e))
    hits = []
    hits += [("domain", d, sorted(DOM[d])[:3]) for d in sorted(hosts) if d in DOM]
    for i in sorted(ips):
        try:
            k = str(ipaddress.ip_address(i))
        except ValueError:
            continue
        if k in IP:
            hits.append(("ip", k, sorted(IP[k])[:3]))
    hits += [("package", k, sorted(PKG[k])[:3]) for k in sorted(pkgs) if k in PKG]
    hits += [("apk sha256", k, sorted(SHA[k])[:3]) for k in sorted(shas) if k in SHA]
    R.p(f"{len(files)} STIX2 files from {', '.join(dirs)}: {len(DOM)} domains, {len(IP)} IPs, {len(PKG)} packages, "
        f"{len(SHA)} hashes. Observables: {len(hosts)} hostnames incl. parents, {len(ips)} IPs, {len(pkgs)} packages, "
        f"{len(shas)} APK hashes. **Hits: {len(hits)}**")
    R.table(["kind", "value", "indicator file(s)"], [(k, v, ", ".join(s)) for k, v, s in hits])
    R.look("any hit. A hit is a strong lead for an examiner; zero hits only rules out the campaigns in these files.")
    T["ioc"] = {"files": [os.path.basename(f) for f in files], "hits": hits}


def s_bluetooth(R, T, ev, et, gapmin, minn):
    R.h(2, "7. Bluetooth")
    bt = [e for e in ev if e["type"] in ("sec:bluetooth_connection", "sec:bluetooth_disconnection")]
    for e in bt:
        e["addr"] = (e["payload"].get("addr") or "").upper()[-5:]
    bonded = sorted({e["addr"] for e in bt if e["type"] == "sec:bluetooth_connection"
                     and "SUCCESS" in str(e["payload"].get("reason", "")).upper()})
    sess, open_ = [], {}
    for e in bt:
        a = e["addr"]
        if e["type"] == "sec:bluetooth_connection":
            if e["payload"].get("reason"):
                continue
            open_[a] = {"addr": a, "start": e["t_ns"], "end": None, "reason": None, "src": f"{e['file']}:{e['line']}"}
        elif a in open_:
            s = open_.pop(a)
            s["end"], s["reason"] = e["t_ns"], e["payload"].get("reason")
            sess.append(s)
    sess += list(open_.values())
    sess.sort(key=lambda s: s["start"])
    by = collections.defaultdict(list)
    for s in sess:
        by[s["addr"]].append(s)
    known = set(bonded) | {a for a, ss in by.items()
                           if sum(((s["end"] or s["start"]) - s["start"]) for s in ss) / 6e10 > 30}
    R.p(f"Addresses with a pairing success (bonded): {', '.join(bonded) or 'none in this export'}. Treated as your "
        f"devices: those plus any address connected for more than 30 minutes in total: {', '.join(sorted(known))}.")
    R.table(["address", "sessions", "total minutes", "first", "last", "end reasons"],
            [(a, len(by[a]), f"{sum(((s['end'] or s['start']) - s['start']) for s in by[a]) / 6e10:.0f}",
              et(by[a][0]["start"]), et(by[a][-1]["start"]),
              dict(collections.Counter(s["reason"] for s in by[a]))) for a in sorted(known) if a in by])
    unk = [s for s in sess if s["addr"] not in known]
    R.p(f"Short connections to other addresses: {len(unk)} to {len({s['addr'] for s in unk})} addresses; "
        f"end reasons {dict(collections.Counter(s['reason'] for s in unk))}.")
    bursts, cur = [], []
    for s in unk:
        if cur and s["start"] - cur[-1]["start"] > gapmin * 6e10:
            bursts.append(cur)
            cur = []
        cur.append(s)
    if cur:
        bursts.append(cur)
    big = [b for b in bursts if len(b) >= minn]
    net = [e for e in ev if e["type"] in ("dns", "connect") and pkg(e)]
    nt = [e["t_ns"] for e in net]
    rows = []
    for b in big:
        t0 = b[0]["start"]
        lo, hi = bisect.bisect_left(nt, t0 - 60e9), bisect.bisect_right(nt, t0 + 5e9)
        apps = collections.Counter(pkg(e) for e in net[lo:hi])
        d = [((s["end"] or s["start"]) - s["start"]) / 1e9 for s in b]
        rows.append((et(t0), et(b[-1]["start"], "%H:%M:%S"), len(b), len({s["addr"] for s in b}),
                     f"{statistics.median(d):.1f}", ", ".join(f"{a} ({n})" for a, n in apps.most_common(3)) or "-"))
    R.p(f"Bursts (≥{minn} short connections, gaps ≤{gapmin:g} min):")
    R.table(["start", "end", "connections", "addresses", "median s", "apps with network activity 60 s before onset"], rows)
    small = [(et(s["start"]), s["addr"], f"{((s['end'] or s['start']) - s['start']) / 1e9:.0f}", s["reason"], s["src"])
             for b in bursts if len(b) < minn for s in b]
    R.p("Isolated short connections (outside bursts):")
    R.table(["time", "address", "s", "ended", "source"], small, limit=60)
    R.look("bursts with no app activity before them that a test (e.g. revoking an app's Nearby devices permission) "
           "doesn't remove; an unbonded address that recurs across days and places; a pairing success you didn't do.")
    T["bt"] = {"bonded": bonded, "known": sorted(known), "bursts": rows, "isolated": small}


def s_events(R, ev, et, events, before, after):
    if not events:
        return
    R.h(2, "8. Event windows")
    ts = [e["t_ns"] for e in ev]
    for t0, label in events:
        lo, hi = bisect.bisect_left(ts, t0 - before * 1e9), bisect.bisect_right(ts, t0 + after * 1e9)
        R.h(3, f"{label} — {et(t0)} (−{before:g} s / +{after:g} s)")
        rows = []
        for e in ev[lo:hi]:
            p = e["payload"]
            if e["type"] == "dns":
                d = f"{pkg(e)} {p.get('hostname')}"
            elif e["type"] == "connect":
                d = f"{pkg(e)} {ipn(p.get('ip_address'))}:{p.get('port')}"
            else:
                d = json.dumps(p)[:140]
            rows.append((et(e["t_ns"], "%m-%d %H:%M:%S.%f")[:-3], e["id"], e["type"], d, f"{e['file']}:{e['line']}"))
        R.table(["time", "id", "type", "detail", "source"], rows, limit=300)


# ---------------------------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("--out", required=True)
    ap.add_argument("--iocs", action="append", default=[], help="folder of STIX2 files (repeatable)")
    ap.add_argument("--event", action="append", default=[])
    ap.add_argument("--before", type=float, default=120)
    ap.add_argument("--after", type=float, default=120)
    ap.add_argument("--night", default="21-04", help="hours treated as night, e.g. 21-04")
    ap.add_argument("--tz", default="America/New_York")
    ap.add_argument("--burst-gap", type=float, default=10, help="minutes between short connections in one burst")
    ap.add_argument("--burst-min", type=int, default=20)
    a = ap.parse_args()
    if os.path.exists(a.out):
        sys.exit(f"--out {a.out} already exists")
    os.makedirs(a.out)
    tz = ZoneInfo(a.tz)
    et, dt = mk_fmt(tz)
    man = {"tool": "ilpass.py", "version": VERSION, "tool_sha256": sha256_file(os.path.abspath(__file__)),
           "python": sys.version.split()[0], "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "input": os.path.abspath(a.input), "args": vars(a)}
    src = a.input
    if os.path.isfile(src) and zipfile.is_zipfile(src):
        man["input_sha256"] = sha256_file(src)
        src = os.path.join(a.out, "extracted")
        os.makedirs(src)
        with zipfile.ZipFile(a.input) as z:
            for zi in z.infolist():
                name = os.path.basename(zi.filename)
                if zi.is_dir() or not name.endswith(".txt") or name.startswith("."):
                    continue
                dest = os.path.join(src, name)
                with z.open(zi) as s, open(dest, "xb") as d:
                    for b in iter(lambda: s.read(1 << 20), b""):
                        d.write(b)
                os.chmod(dest, 0o444)
    ev, per_file, bad, dups = load(src, tz)
    if not ev:
        sys.exit("no events parsed")
    night = tuple(int(x) for x in a.night.split("-"))
    events = []
    for x in a.event:
        ts, _, label = x.partition("|")
        events.append((int(datetime.fromisoformat(ts).replace(tzinfo=tz).timestamp() * 1e9), label or ts))
    iocdirs = a.iocs or ["~/.local/share/mvt/indicators"]
    R, T = Rep(), {}
    R.p("# Intrusion-log pass")
    R.p(f"ilpass.py {VERSION} (SHA-256 `{man['tool_sha256'][:16]}…`), run {man['run_utc']} UTC"
        + (f"; input zip SHA-256 `{man['input_sha256']}`" if "input_sha256" in man else "") + f". Times in {a.tz}.")
    s_provenance(R, T, ev, per_file, bad, dups, et)
    s_completeness(R, T, ev, et)
    s_unlocks(R, T, ev, et, dt, night)
    s_packages(R, T, ev, et)
    s_network(R, T, ev, et, dt, night)
    s_indicators(R, T, ev, iocdirs)
    s_bluetooth(R, T, ev, et, a.burst_gap, a.burst_min)
    s_events(R, ev, et, events, a.before, a.after)
    with open(os.path.join(a.out, "report.md"), "w") as fh:
        fh.write("".join(R.parts))
    with open(os.path.join(a.out, "tables.json"), "w") as fh:
        json.dump(T, fh, indent=1, default=str)
    with open(os.path.join(a.out, "events.jsonl"), "w") as fh:
        for e in ev:
            e = {k: v for k, v in e.items() if k != "addr"}
            fh.write(json.dumps(e, sort_keys=True) + "\n")
    man["files"] = [{"file": f, "sha256": h, "events": n} for f, h, n, _, _ in per_file]
    with open(os.path.join(a.out, "manifest.json"), "w") as fh:
        json.dump(man, fh, indent=1, default=str)
    print(f"report: {os.path.join(a.out, 'report.md')}  events: {len(ev)}  ioc hits: {len(T['ioc']['hits'])}")


if __name__ == "__main__":
    main()
