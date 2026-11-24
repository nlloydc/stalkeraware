#!/usr/bin/env python3
"""swpass.py - stalkerware-footprint pass over an Android bug report (Python 3.9+ standard library only).

Companion to bra.py. Reads the main bugreport-*.txt (or an extracted folder / the .zip) and reports the
places commercial stalkerware has to leave a footprint:

  1. installers        - every user app's installer and initiating installer (non-Play = flag)
  2. hidden apps       - user apps with no MAIN activity (proxy for "no launcher icon")
  3. permissions       - sensitive runtime grants per non-Google user app (SMS, call log, mic, location...)
  4. roles             - default SMS / dialer / assistant / browser / home / device-policy holders
  5. admin surfaces    - device admins, accessibility, notification listeners, VPN, trust agents (Smart Lock),
                         ADB / wireless debugging, users, account types, companion devices, and which non-system
                         packages have written global/secure settings
  6. doze exemptions   - app ids exempt from Doze, mapped to packages
  7. app ops           - mic / camera / location / data-op ACCESS entries, with process state
  8. upload volume     - per-app tx/rx bytes since boot (netstats mAppUidStatsMap)
  9. scheduled jobs    - non-Google packages with registered and periodic jobs

It writes report.md plus JSON tables. It never modifies its input. Thresholds and "look closer"
criteria are printed in the report next to each table; they were fixed before results were viewed
(see PREREGISTERED.md in the repo). Nothing here proves how anything was done.

Usage
  python3 -I swpass.py <bugreport.zip | folder | bugreport-*.txt> --out <new folder>
"""
import argparse
import collections
import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone

VERSION = "0.2.0 (2026-11-24)"
GOOGLE_PREFIXES = ("com.google.", "com.android.", "android")
SENSITIVE = {
    "android.permission.READ_SMS": "SMS", "android.permission.RECEIVE_SMS": "SMS",
    "android.permission.SEND_SMS": "SMS", "android.permission.READ_CALL_LOG": "CALLLOG",
    "android.permission.PROCESS_OUTGOING_CALLS": "CALLLOG", "android.permission.RECORD_AUDIO": "MIC",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "BGLOC", "android.permission.ACCESS_FINE_LOCATION": "LOC",
    "android.permission.READ_CONTACTS": "CONTACTS", "android.permission.CAMERA": "CAMERA",
    "android.permission.READ_PHONE_STATE": "PHONE", "android.permission.READ_MEDIA_IMAGES": "PHOTOS",
}
INSTALL_FLAGS = ("SYSTEM_ALERT_WINDOW", "PACKAGE_USAGE_STATS", "RECEIVE_BOOT_COMPLETED",
                 "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "QUERY_ALL_PACKAGES")
MICCAM_OPS = {"RECORD_AUDIO", "CAMERA", "PHONE_CALL_MICROPHONE", "PHONE_CALL_CAMERA", "RECORD_AUDIO_HOTWORD",
              "RECORD_AUDIO_OUTPUT", "RECORD_INCOMING_PHONE_AUDIO", "PROJECT_MEDIA", "RECEIVE_AMBIENT_TRIGGER_AUDIO"}
LOC_OPS = {"COARSE_LOCATION", "FINE_LOCATION", "MONITOR_HIGH_POWER_LOCATION", "MONITOR_LOCATION"}
DATA_OPS = {"READ_SMS", "READ_CALL_LOG", "READ_CONTACTS", "READ_CLIPBOARD", "GET_USAGE_STATS",
            "SYSTEM_ALERT_WINDOW", "READ_MEDIA_IMAGES", "ACCESS_NOTIFICATIONS"}
ROLES = ("SMS", "DIALER", "ASSISTANT", "BROWSER", "HOME", "CALL_REDIRECTION", "CALL_SCREENING",
         "DEVICE_POLICY_MANAGEMENT", "SYSTEM_SUPERVISION", "NOTES")
SVC_RE = re.compile(r"^DUMP OF SERVICE (?:(?:CRITICAL|HIGH) )?(\S+):\s*$")


def is_google(name):
    return name.startswith(GOOGLE_PREFIXES)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load(path):
    with open(path, "rb") as fh:
        L = fh.read().decode("utf-8", "replace").split("\n")
    svc = {}
    cur = None
    for i, l in enumerate(L):
        if l.startswith("DUMP OF SERVICE"):
            m = SVC_RE.match(l)
            if m:
                if cur and cur[0] not in svc:
                    svc[cur[0]] = (cur[1], i - 1)
                cur = (m.group(1), i)
        elif cur and l.startswith("--------- ") and "was the duration of dumpsys" in l:
            # keep the first, CRITICAL-less dump where both exist: normal dumps come later and are longer
            prev = svc.get(cur[0])
            if prev is None or (i - cur[1]) > (prev[1] - prev[0]):
                svc[cur[0]] = (cur[1], i)
            cur = None
    return L, svc


def block(L, svc, name):
    r = svc.get(name)
    return L[r[0]:r[1] + 1] if r else []


# ------------------------------------------------------------------------------------------ packages

def parse_packages(lines):
    pkgs, cur, sect = {}, None, None
    for line in lines:
        m = re.match(r"^  Package \[([^\]]+)\]", line)
        if m:
            cur = pkgs.setdefault(m.group(1), {"name": m.group(1), "runtime": [], "install": [], "u0": {}})
            sect = None
            continue
        if cur is None:
            continue
        if line.strip() and not line.startswith("    "):
            cur = None
            continue
        s = line.strip()
        for key in ("appId", "codePath", "installerPackageName", "initiatingPackageName", "originatingPackageName",
                    "lastUpdateTime"):
            if s.startswith(key + "="):
                cur.setdefault(key, s.split("=", 1)[1])
        if s.startswith("pkgFlags=["):
            cur["system"] = " SYSTEM " in s + " "
        if s.startswith("firstInstallTime="):
            cur.setdefault("firstInstallTime", s.split("=", 1)[1])
        m = re.match(r"User 0: .*installed=(\w+) hidden=(\w+)", s)
        if m:
            cur["u0"] = {"installed": m.group(1), "hidden": m.group(2)}
        if s == "runtime permissions:":
            sect = "runtime"
            continue
        if s == "install permissions:":
            sect = "install"
            continue
        if s.endswith(":") and " " not in s and not s.startswith("android.") and sect:
            sect = None
        m = re.match(r"([\w.]+): granted=true", s)
        if m and sect:
            cur[sect].append(m.group(1))
    return pkgs


def main_activities(lines):
    """Packages with an activity for android.intent.action.MAIN in the activity resolver table."""
    out, on = set(), False
    for l in lines:
        s = l.strip()
        if s == "android.intent.action.MAIN:":
            on = True
            continue
        if on:
            m = re.match(r"^[0-9a-f]+ ([\w.]+)/", s)
            if m:
                out.add(m.group(1))
            elif s.endswith(":") or not s:
                on = False
    return out


# ------------------------------------------------------------------------------------------ app ops

def parse_appops(lines):
    """Yield (package, op, mode, uid_state, timestamp, duration, access/reject)."""
    pkg = op = mode = None
    for l in lines:
        m = re.match(r"^    Package (\S+):", l)
        if m:
            pkg = m.group(1)
            continue
        m = re.match(r"^      ([A-Z_]+) \((\w+)(?: / [^)]*)?\):", l)
        if m:
            op, mode = m.group(1), m.group(2)
            continue
        m = re.match(r"^\s+(Access|Reject): \[([\w-]+)\] (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+).*?(?:\(duration=\+?([^)]+)\))?\s*$", l)
        if m and pkg and op:
            yield (pkg, op, mode, m.group(2), m.group(3)[:19], m.group(4), m.group(1))


# ------------------------------------------------------------------------------------------ report

class Rep:
    def __init__(self):
        self.parts = []

    def h(self, n, t):
        self.parts.append("\n" + "#" * n + " " + t + "\n\n")

    def p(self, t):
        self.parts.append(t + "\n\n")

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
            self.parts.append(f"\n_({len(rows) - limit} more rows in the JSON output)_\n")
        self.parts.append("\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if os.path.exists(a.out):
        sys.exit(f"--out {a.out} already exists")
    os.makedirs(a.out)
    man = {"tool": "swpass.py", "version": VERSION, "tool_sha256": sha256_file(os.path.abspath(__file__)),
           "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "input": os.path.abspath(a.input)}
    txt = a.input
    if os.path.isfile(txt) and zipfile.is_zipfile(txt):
        man["input_sha256"] = sha256_file(txt)
        with zipfile.ZipFile(txt) as z:
            names = [n for n in z.namelist() if re.match(r"^bugreport-.*\.txt$", n)]
            if not names:
                sys.exit("no bugreport-*.txt in the zip")
            dest = os.path.join(a.out, "main.txt")
            with z.open(names[0]) as s, open(dest, "xb") as d:
                for b in iter(lambda: s.read(1 << 20), b""):
                    d.write(b)
            os.chmod(dest, 0o444)
            man["main_txt_name"] = names[0]
            txt = dest
    elif os.path.isdir(txt):
        c = [os.path.join(txt, f) for f in os.listdir(txt) if f.startswith("bugreport-") and f.endswith(".txt")]
        txt = max(c, key=os.path.getsize)
    man["main_txt_sha256"] = sha256_file(txt)
    L, svc = load(txt)
    R = Rep()
    out = {}
    R.p("# Stalkerware-footprint pass\n")
    R.p(f"Main text `{man.get('main_txt_name', os.path.basename(txt))}` (SHA-256 `{man['main_txt_sha256']}`). "
        f"swpass.py {VERSION} (SHA-256 `{man['tool_sha256'][:16]}...`), run {man['run_utc']} UTC.")

    pk_lines = block(L, svc, "package")
    pkgs = parse_packages(pk_lines)
    mains = main_activities(pk_lines)
    inst = [p for p in pkgs.values() if p["u0"].get("installed") == "true"]
    user = [p for p in inst if p.get("codePath", "").startswith("/data/app")]
    byid = collections.defaultdict(list)
    for p in pkgs.values():
        byid[p.get("appId")].append(p["name"])

    # 1 installers
    R.h(2, "1. Installers of user apps")
    R.p("Look closer: a third-party app whose installer or initiating installer is not the Play Store "
        "(`com.android.vending`). Shared libraries installed by the system (installer `null`) are expected.")
    ic = collections.Counter((p.get("installerPackageName"), p.get("initiatingPackageName")) for p in user)
    R.table(["installer", "initiating installer", "apps"], [(k[0], k[1], v) for k, v in ic.most_common()])
    nonplay = [p for p in user if p.get("installerPackageName") != "com.android.vending"]
    R.table(["package", "installer", "initiating", "originating", "first install"],
            [(p["name"], p.get("installerPackageName"), p.get("initiatingPackageName"), p.get("originatingPackageName"),
              p.get("firstInstallTime")) for p in nonplay])
    out["nonplay"] = [p["name"] for p in nonplay]

    # 2 hidden
    R.h(2, "2. User apps with no MAIN activity (proxy for no launcher icon)")
    R.p("The bug report's resolver table has no categories, so any MAIN activity counts as an icon; this errs "
        "toward listing more apps. Look closer: a non-Google app here that also holds sensitive permissions.")
    nomain = [p for p in user if p["name"] not in mains]
    R.table(["package", "Google/AOSP", "sensitive grants"],
            [(p["name"], is_google(p["name"]), ",".join(sorted({SENSITIVE[x] for x in p["runtime"] if x in SENSITIVE})))
             for p in sorted(nomain, key=lambda p: (is_google(p["name"]), p["name"]))])
    R.p(f"Hidden flag set for user 0: {[p['name'] for p in inst if p['u0'].get('hidden') == 'true'] or 'none'}.")
    out["no_main"] = [p["name"] for p in nomain]

    # 3 permissions
    R.h(2, "3. Sensitive grants held by non-Google user apps")
    R.p("Look closer: 3 or more of SMS, call log, mic, background location, contacts, camera, usage stats, "
        "overlay that the app's function doesn't explain.")
    rows = []
    for p in sorted(user, key=lambda p: p["name"]):
        if is_google(p["name"]):
            continue
        cats = sorted({SENSITIVE[x] for x in p["runtime"] if x in SENSITIVE})
        ins = [f for f in INSTALL_FLAGS if f"android.permission.{f}" in p["install"]]
        if cats or ins:
            rows.append((p["name"], ",".join(cats), " ".join(ins), (p.get("firstInstallTime") or "")[:10], len(cats)))
    rows.sort(key=lambda r: -r[4])
    R.table(["package", "runtime grants", "install-time flags", "first install"], [r[:4] for r in rows])
    out["grants"] = rows

    # 4 roles
    R.h(2, "4. Default-app roles")
    R.p("Look closer: SMS, dialer, assistant or home held by an app that isn't Google's or the user's choice.")
    rl, name = [], None
    for l in block(L, svc, "role"):
        m = re.search(r"name=android\.app\.role\.(\w+)", l)
        if m:
            name = m.group(1)
        m = re.search(r"holders=(\S*)", l)
        if m and name in ROLES:
            rl.append((name, m.group(1) or "(none)"))
            name = None
    R.table(["role", "holder"], sorted(set(rl)))
    out["roles"] = sorted(set(rl))

    # 5 admin surfaces
    R.h(2, "5. Device admins, accessibility, notification listeners, VPN")
    dp = block(L, svc, "device_policy")
    admins, on = [], False
    for l in dp:
        if "Enabled Device Admins" in l:
            on = True
            continue
        if on:
            if "mPasswordOwner" in l:
                break
            m = re.match(r"^\s+([\w.]+/[\w.$]+):?\s*$", l)
            if m:
                admins.append(m.group(1))
    enforcers = sorted(set(re.findall(r"EnforcingAdmin \{ mPackageName= ([\w.]*),", "\n".join(dp))) - {""})
    acc = [l.strip() for l in block(L, svc, "accessibility") if l.strip().startswith(("Enabled services:", "Bound services:"))]
    nls = []
    for i, l in enumerate(L):
        if l.strip().startswith("All notification listeners ("):
            for k in L[i + 1:i + 40]:
                m = re.search(r"ComponentInfo\{([^/}]+)/", k)
                if not m:
                    break
                nls.append(m.group(1))
            break
    vpn = [l.strip() for l in block(L, svc, "vpn_management") if "Active package name" in l or "alwaysOn" in l]
    trust, on = [], False
    for l in block(L, svc, "trust"):
        if "Enabled agents:" in l:
            on = True
            continue
        if on:
            m = re.match(r"^\s{4}(\S+/\S+)\s*$", l)
            if m:
                trust.append(m.group(1))
            elif l.strip().startswith("Events:"):
                break
    tstate = [l.strip() for l in block(L, svc, "trust") if "trustState=" in l]
    adb = [l.strip() for l in block(L, svc, "adb") if re.match(r"^\s+(connected_to_adb|enabled|network_ssid|is_trusted_network)=", l)]
    users = [l.strip() for l in block(L, svc, "user") if "UserInfo{" in l]
    accts = sorted(set(t for n, t in re.findall(r"Account \{name=([^,]+), type=([^}]+)\}", "\n".join(block(L, svc, "account")))))
    cdm = [l.strip() for l in block(L, svc, "companiondevice") if l.strip().startswith("Companion Device Associations")]
    writers = collections.Counter()
    scope = None
    for l in block(L, svc, "settings"):
        m = re.match(r"^(GLOBAL|SECURE|SYSTEM|CONFIG) SETTINGS \(user 0\)", l)
        if m:
            scope = m.group(1)
            continue
        m = re.match(r"^_id:\d+ name:(\S+) pkg:(\S+) value:", l)
        if m and scope in ("GLOBAL", "SECURE") and not is_google(m.group(2)):
            writers[m.group(2)] += 1
    R.table(["item", "value"], [("device admins", ", ".join(admins) or "none"),
                                ("policy enforcers (any)", ", ".join(enforcers) or "none"),
                                ("accessibility", "; ".join(acc)),
                                ("notification listeners", ", ".join(nls)),
                                ("VPN", "; ".join(vpn) or "none"),
                                ("Smart Lock / trust agents enabled", ", ".join(trust) or "none"),
                                ("trust state", "; ".join(tstate)),
                                ("ADB / wireless debugging", "; ".join(adb)),
                                ("Android users", "; ".join(users)),
                                ("account types", ", ".join(accts)),
                                ("companion-device associations", "; ".join(cdm)),
                                ("non-system writers of global/secure settings", ", ".join(f"{k} ({v})" for k, v in writers.items()) or "none")])
    R.p("`com.google.android.devicelockcontroller` appears as an enforcer on stock Pixels; check that its only "
        "policy is protecting itself (userControlDisabledPackages) unless the phone is financed.")
    R.p("Trust agents listed as enabled are Google's defaults on Pixels; whether a trusted device or place is actually "
        "configured isn't in the bug report (check Settings → Security → Extend Unlock / Smart Lock).")
    out["admins"], out["enforcers"], out["listeners"] = admins, enforcers, nls
    out["trust_agents"], out["adb"], out["users"], out["account_types"], out["settings_writers"] = trust, adb, users, accts, dict(writers)

    # 6 doze
    R.h(2, "6. Doze exemptions")
    R.p("Look closer: a third-party app exempt from Doze (stalkerware asks for this to stay alive).")
    ids, on = set(), False
    for l in block(L, svc, "deviceidle"):
        if "Whitelist (except idle) all app ids:" in l:
            on = True
            continue
        if on and not l.startswith("    "):
            on = False
        if on and l.strip().isdigit():
            ids.add(l.strip())
    dz = [(i, ", ".join(byid.get(i, ["?"]))) for i in sorted(ids, key=int) if int(i) >= 10000]
    R.table(["app id", "package(s)"], dz)
    out["doze_third_party"] = [r for r in dz if not all(is_google(n) for n in r[1].split(", "))]
    R.p(f"Third-party exemptions: {out['doze_third_party'] or 'none'}.")

    # 7 app ops
    R.h(2, "7. App-op access: mic, camera, location, data")
    R.p("States: top = on screen, fg/fgsvc = foreground, bg = background, cch = cached. Look closer: a "
        "non-Google app using mic or camera while not on screen, or background location by an app with no "
        "location function.")
    ops = list(parse_appops(block(L, svc, "appops")))
    mc = [(p, o, st, t, d) for p, o, m_, st, t, d, acc_ in ops if o in MICCAM_OPS and acc_ == "Access"]
    R.table(["package", "op", "state", "last", "duration"], sorted(mc, key=lambda r: (is_google(r[0]), r[0], r[3])))
    ng = [(p, o, st, t) for p, o, m_, st, t, d, acc_ in ops
          if not is_google(p) and o in LOC_OPS | DATA_OPS and acc_ == "Access"]
    R.p("Non-Google apps, location and data ops:")
    R.table(["package", "op", "state", "last"], ng)
    flag = [r for r in mc if not is_google(r[0]) and not r[2].startswith("top")]
    R.p(f"Non-Google mic/camera access while not on screen: {flag or 'none'}.")
    out["appops_miccam"], out["appops_nongoogle"], out["appops_flag"] = mc, ng, flag
    if not ops:
        R.p("**problem:** no app-op entries parsed; check this section by hand.")

    # 8 upload
    R.h(2, "8. Upload volume per app since boot")
    R.p("From netstats mAppUidStatsMap (no foreground/background split). Look closer: a non-Google app "
        "uploading far more than its function explains. Moving bug reports off the phone shows up here "
        "(hundreds of MB through whichever app carried them).")
    rows, on = [], False
    for l in block(L, svc, "netstats"):
        if l.strip() == "mAppUidStatsMap:":
            on = True
            continue
        if on:
            f = l.split()
            if len(f) == 5 and f[0].isdigit():
                rows.append((f[0], int(f[1]), int(f[3])))
            elif l.strip().startswith("m"):
                break
    rows.sort(key=lambda r: -r[2])
    R.table(["uid", "tx MB", "rx MB", "tx/rx", "package(s)"],
            [(u, f"{tx / 1e6:.1f}", f"{rx / 1e6:.1f}", f"{tx / max(rx, 1):.2f}",
              ", ".join(byid.get(u, ["(system uid)" if int(u) < 10000 else "?"]))[:80]) for u, rx, tx in rows], limit=25)
    out["upload"] = rows

    # 9 jobs
    R.h(2, "9. Scheduled jobs of non-Google apps")
    js = "\n".join(block(L, svc, "jobscheduler"))
    jobs = re.findall(r"JOB #u0a?\d*/(-?\d+): \w+ (\S+?)/(\S+)\n(.*?)(?=\n  JOB #|\n\n)", js, re.S)
    c = collections.defaultdict(lambda: [0, 0])
    for jid, pkg, svc_, body in jobs:
        if is_google(pkg):
            continue
        c[pkg][0] += 1
        if "PERIODIC" in body or "period=" in body:
            c[pkg][1] += 1
    R.table(["package", "jobs", "periodic"], sorted(((k, v[0], v[1]) for k, v in c.items()), key=lambda r: -r[2]))
    out["jobs"] = dict(c)

    with open(os.path.join(a.out, "report.md"), "w") as fh:
        fh.write("".join(R.parts))
    with open(os.path.join(a.out, "tables.json"), "w") as fh:
        json.dump(out, fh, indent=1, default=str)
    with open(os.path.join(a.out, "manifest.json"), "w") as fh:
        json.dump(man, fh, indent=1)
    print(f"report: {os.path.join(a.out, 'report.md')}  apps: {len(user)} user / {len(inst)} installed; "
          f"non-Play: {len(nonplay)}; app-op rows: {len(ops)}")


if __name__ == "__main__":
    main()
