#!/usr/bin/env python3
"""snapdiff.py - snapshot an Android bug report's security-relevant state, and diff two snapshots.
Python 3.9+ standard library only.

A single bug report shows a state; two show a change. A change with a time window ("between report A and
report B") that nobody explains is better evidence than any setting looked at once.

  snap  <bugreport.zip | bugreport-*.txt>  -o state.json
  diff  <old: state.json | bugreport>  <new: state.json | bugreport>  -o <new folder>

What a snapshot holds
  packages     version, installer, first install / last update, signing cert, sensitive runtime grants,
               install-time flags (overlay, usage stats, boot, battery-exemption request, query-all), hidden
  app ops      non-default modes for mic, camera, location, SMS, call log, contacts, clipboard, usage stats,
               overlay, notification access, media projection
  roles        SMS, dialer, assistant, browser, home, device policy, supervision, call screening/redirection
  admin        device admins, policy enforcers, enabled/bound accessibility services, notification listeners,
               Smart Lock trust agents, ADB (connected, wireless debugging, trusted network), VPN, users,
               accounts (type + name), companion-device associations, Doze-exempt app ids
  settings     every GLOBAL and SECURE setting with its value and the package that last wrote it
  radios       saved Wi-Fi networks (SSID, security, MAC randomization), bonded Bluetooth devices

The diff report lists each change with its "look closer" reading. Settings that change on their own all the
time (counters, timestamps, server flags) are listed in tables.json; the report shows security-relevant
keys and any setting written by a package that isn't Android, a com.android.* component, or Google.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone

VERSION = "0.1.0 (2026-11-24)"
SVC_RE = re.compile(r"^DUMP OF SERVICE (?:(?:CRITICAL|HIGH) )?(\S+):\s*$")
SENSITIVE = {"READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS", "RECORD_AUDIO",
             "ACCESS_BACKGROUND_LOCATION", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_CONTACTS",
             "CAMERA", "READ_PHONE_STATE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "BODY_SENSORS",
             "ACTIVITY_RECOGNITION", "NEARBY_WIFI_DEVICES", "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "POST_NOTIFICATIONS"}
INSTALL_FLAGS = {"SYSTEM_ALERT_WINDOW", "PACKAGE_USAGE_STATS", "RECEIVE_BOOT_COMPLETED",
                 "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "QUERY_ALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE",
                 "BIND_DEVICE_ADMIN", "BIND_NOTIFICATION_LISTENER_SERVICE", "REQUEST_INSTALL_PACKAGES"}
OPS = {"RECORD_AUDIO", "CAMERA", "COARSE_LOCATION", "FINE_LOCATION", "READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG",
       "READ_CONTACTS", "READ_CLIPBOARD", "GET_USAGE_STATS", "SYSTEM_ALERT_WINDOW", "ACCESS_NOTIFICATIONS",
       "PROJECT_MEDIA", "RECORD_AUDIO_OUTPUT", "RECEIVE_AMBIENT_TRIGGER_AUDIO", "MANAGE_EXTERNAL_STORAGE",
       "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE"}
WATCH_SETTINGS = {"adb_enabled", "adb_wifi_enabled", "development_settings_enabled", "install_non_market_apps",
                  "enabled_accessibility_services", "accessibility_enabled", "enabled_notification_listeners",
                  "enabled_notification_assistant", "private_dns_mode", "private_dns_specifier", "location_mode",
                  "location_providers_allowed", "always_on_vpn_app", "always_on_vpn_lockdown", "lockscreen.disabled",
                  "lock_screen_owner_info_enabled", "trust_agents_initialized", "enabled_input_methods",
                  "default_input_method", "voice_interaction_service", "assistant", "autofill_service",
                  "credential_service", "credential_service_primary", "ble_scan_always_enabled",
                  "wifi_scan_always_enabled", "verifier_verify_adb_installs", "package_verifier_enable",
                  "package_verifier_user_consent", "usb_mass_storage_enabled", "bluetooth_on", "nfc_on",
                  "airplane_mode_on", "mobile_data", "preferred_network_mode", "lock_screen_show_notifications",
                  "lock_screen_allow_private_notifications", "screensaver_components", "sms_default_application",
                  "dialer_default_application", "managed_provisioning_complete", "device_provisioned",
                  "user_setup_complete", "secure_frp_mode", "show_password", "sysui_qs_tiles"}
SYSTEM_WRITERS = ("android", "com.android.", "com.google.")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def read_main(path):
    """Return (lines, meta) for a bug report zip or text file."""
    meta = {"input": os.path.abspath(path), "input_sha256": sha256_file(path)}
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist() if re.match(r"^bugreport-.*\.txt$", os.path.basename(n))]
            if not names:
                sys.exit("no bugreport-*.txt in the zip")
            data = z.read(names[0])
            meta["main_txt"] = names[0]
    else:
        data = open(path, "rb").read()
        meta["main_txt"] = os.path.basename(path)
    meta["main_txt_sha256"] = hashlib.sha256(data).hexdigest()
    return data.decode("utf-8", "replace").split("\n"), meta


def index(L):
    svc, cur = {}, None
    for i, l in enumerate(L):
        if l.startswith("DUMP OF SERVICE"):
            m = SVC_RE.match(l)
            if m:
                cur = (m.group(1), i)
        elif cur and l.startswith("--------- ") and "was the duration of dumpsys" in l:
            prev = svc.get(cur[0])
            if prev is None or (i - cur[1]) > (prev[1] - prev[0]):
                svc[cur[0]] = (cur[1], i)
            cur = None
    return svc


def blk(L, svc, name):
    r = svc.get(name)
    return L[r[0]:r[1] + 1] if r else []


# ------------------------------------------------------------------------------------------ extraction

def x_packages(lines):
    pkgs, cur, sect = {}, None, None
    for line in lines:
        m = re.match(r"^  Package \[([^\]]+)\]", line)
        if m:
            cur = pkgs.setdefault(m.group(1), {"grants": [], "flags": []})
            sect = None
            continue
        if cur is None:
            continue
        if line.strip() and not line.startswith("    "):
            cur = None
            continue
        s = line.strip()
        for key in ("versionCode", "versionName", "installerPackageName", "initiatingPackageName", "lastUpdateTime",
                    "codePath"):
            m = re.match(rf"{key}=(\S+(?: \d\d:\d\d:\d\d)?)", s)
            if m and key not in cur:
                cur[key] = m.group(1)
        if s.startswith("firstInstallTime=") and "firstInstallTime" not in cur:
            cur["firstInstallTime"] = s.split("=", 1)[1]
        if s.startswith("signatures="):
            m = re.search(r"signatures:\[([^\]]*)\]", s)
            cur.setdefault("cert", m.group(1) if m else s[:80])
        if s.startswith("pkgFlags=["):
            cur["system"] = " SYSTEM " in s + " "
        m = re.match(r"User 0: .*installed=(\w+) hidden=(\w+).*?enabled=(\d+)", s)
        if m:
            cur["installed"], cur["hidden"], cur["enabled"] = m.group(1) == "true", m.group(2) == "true", m.group(3)
        if s == "runtime permissions:":
            sect = "grants"
            continue
        if s == "install permissions:":
            sect = "flags"
            continue
        if s.endswith(":") and " " not in s and not s.startswith("android.") and sect:
            sect = None
        m = re.match(r"(?:android\.permission\.)?([\w.]+): granted=true", s)
        if m and sect:
            short = m.group(1).split(".")[-1]
            if (sect == "grants" and short in SENSITIVE) or (sect == "flags" and short in INSTALL_FLAGS):
                cur[sect].append(short)
    out = {}
    for k, v in pkgs.items():
        if v.get("installed") is False:
            continue
        v["grants"], v["flags"] = sorted(set(v["grants"])), sorted(set(v["flags"]))
        out[k] = v
    return out


def x_appops(lines):
    out, pkg = {}, None
    for l in lines:
        m = re.match(r"^    Package (\S+):", l)
        if m:
            pkg = m.group(1)
            continue
        m = re.match(r"^      ([A-Z_]+) \((\w+)", l)
        if m and pkg and m.group(1) in OPS and m.group(2) not in ("default",):
            out.setdefault(pkg, {})[m.group(1)] = m.group(2)
    return out


def x_roles(lines):
    out, name = {}, None
    for l in lines:
        m = re.search(r"name=android\.app\.role\.(\w+)", l)
        if m:
            name = m.group(1)
        m = re.search(r"holders=(\S*)", l)
        if m and name:
            out[name] = m.group(1)
            name = None
    return out


def x_settings(lines):
    out, scope = {}, None
    for l in lines:
        m = re.match(r"^(GLOBAL|SECURE|SYSTEM|CONFIG) SETTINGS \(user 0\)", l)
        if m:
            scope = m.group(1)
            continue
        if scope not in ("GLOBAL", "SECURE"):
            continue
        m = re.match(r"^_id:(\d+) name:(\S+) pkg:(\S+) value:(.*?)(?: default:| defaultSystemSet:|$)", l)
        if m:
            out[f"{scope.lower()}:{m.group(2)}"] = {"value": m.group(4).strip(), "pkg": m.group(3), "id": int(m.group(1))}
    return out


def snapshot(path):
    L, meta = read_main(path)
    S = index(L)
    st = {"tool": "snapdiff.py", "version": VERSION, "meta": meta}
    for i in range(min(400, len(L))):
        m = re.match(r"^== dumpstate: (.*)$", L[i])
        if m:
            st["meta"]["captured"] = m.group(1).strip()
        for k in ("Build fingerprint:", "Uptime:"):
            if L[i].startswith(k):
                st["meta"][k.rstrip(":")] = L[i][len(k):].strip()[:160]
    st["packages"] = x_packages(blk(L, S, "package"))
    st["appops"] = x_appops(blk(L, S, "appops"))
    st["roles"] = x_roles(blk(L, S, "role"))
    dp = blk(L, S, "device_policy")
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
    enforcers = {}
    cur_key = None
    for l in dp:
        if "admin policy size limit" in l or l.strip().startswith("Admin Policies size"):
            break
        m = re.match(r"^\s+(?:UserRestrictionPolicyKey|DefaultPolicyKey|\w+PolicyKey) (\S+)", l)
        if m:
            cur_key = m.group(1)
        m = re.search(r"EnforcingAdmin \{ mPackageName= ([\w.]+),", l)
        if m and cur_key:
            enforcers.setdefault(m.group(1), set()).add(cur_key)
    acc = {}
    for l in blk(L, S, "accessibility"):
        s = l.strip()
        for k in ("Enabled services:", "Bound services:"):
            if s.startswith(k):
                acc[k.rstrip(":")] = s.split(":", 1)[1].strip()
    nls = []
    for i, l in enumerate(L):
        if l.strip().startswith("All notification listeners ("):
            for k in L[i + 1:i + 40]:
                m = re.search(r"ComponentInfo\{([^}]+)\}", k)
                if not m:
                    break
                nls.append(m.group(1))
            break
    trust, on = [], False
    for l in blk(L, S, "trust"):
        if "Enabled agents:" in l:
            on = True
            continue
        if on:
            m = re.match(r"^\s{4}(\S+/\S+)\s*$", l)
            if m:
                trust.append(m.group(1))
            elif l.strip().startswith("Events:"):
                break
    adb = {}
    for l in blk(L, S, "adb"):
        m = re.match(r"^\s+(connected_to_adb|enabled|network_ssid|is_trusted_network)=(.*)$", l)
        if m:
            adb[m.group(1)] = m.group(2).strip()
    vpn = [l.strip() for l in blk(L, S, "vpn_management") if "Active package name" in l or "alwaysOn" in l]
    users = [l.strip() for l in blk(L, S, "user") if "UserInfo{" in l]
    accounts = sorted(set(re.findall(r"Account \{name=([^,]+), type=([^}]+)\}", "\n".join(blk(L, S, "account")))))
    cdm = [l.strip() for l in blk(L, S, "companiondevice") if l.strip().startswith("Companion Device Associations")]
    doze, on = [], False
    for l in blk(L, S, "deviceidle"):
        if "Whitelist (except idle) all app ids:" in l:
            on = True
            continue
        if on and not l.startswith("    "):
            on = False
        if on and l.strip().isdigit():
            doze.append(l.strip())
    st["admin"] = {"device_admins": sorted(admins), "enforcers": {k: sorted(v) for k, v in enforcers.items()},
                   "accessibility": acc, "notification_listeners": sorted(nls), "trust_agents": sorted(trust),
                   "adb": adb, "vpn": vpn, "users": users, "accounts": [f"{t}: {n}" for n, t in accounts],
                   "companion_associations": cdm, "doze_exempt_appids": sorted(doze, key=int)}
    st["settings"] = x_settings(blk(L, S, "settings"))
    wifi = {}
    for l in blk(L, S, "wifi"):
        m = re.match(r'^ID: (\d+) SSID: (".*?"|\S+) .*?HIDDEN: (\w+) PMF: (\w+)', l)
        if m:
            cur = wifi.setdefault(m.group(2), {"hidden": m.group(3), "pmf": m.group(4)})
            continue
        s = l.strip()
        if wifi and s.startswith("KeyMgmt:") and "keymgmt" not in cur:
            cur["keymgmt"] = s.split()[1] if len(s.split()) > 1 else ""
        if wifi and s.startswith("macRandomizationSetting:"):
            cur["macrand"] = s.split(":", 1)[1].strip()
    bonded, sect = {}, None
    for l in blk(L, S, "bluetooth_manager"):
        s = l.strip()
        if s.startswith("Bonded devices:"):
            sect = "b"
            continue
        if s.startswith("Other devices:"):
            break
        if sect:
            m = re.match(r"^\s+XX:XX:XX:XX:([0-9A-F]{2}:[0-9A-F]{2})\(\w+\) => (\S+) \[\s*([A-Z/?]+)\s*\].*?\] ?([^\]]*)$", l)
            if m:
                bonded[m.group(1)] = {"type": m.group(3), "name": m.group(4).strip()}
    st["radios"] = {"wifi_saved": wifi, "bt_bonded": bonded}
    return st


# ------------------------------------------------------------------------------------------ diff

def load_state(p):
    if p.endswith(".json"):
        return json.load(open(p))
    return snapshot(p)


def dd(a, b):
    """added, removed, changed keys between two dicts."""
    add = sorted(set(b) - set(a))
    rem = sorted(set(a) - set(b))
    chg = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    return add, rem, chg


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
            self.p("_(no change)_")
            return
        esc = lambda x: str("" if x is None else x).replace("|", "\\|").replace("\n", " ")
        self.parts.append("| " + " | ".join(hdr) + " |\n|" + "|".join("---" for _ in hdr) + "|\n")
        for r in rows[:limit]:
            self.parts.append("| " + " | ".join(esc(c) for c in r) + " |\n")
        if limit and len(rows) > limit:
            self.parts.append(f"\n_({len(rows) - limit} more rows in tables.json)_\n")
        self.parts.append("\n")


def system_writer(pkg):
    return pkg.startswith(SYSTEM_WRITERS)


def diff(A, B, out):
    R, T = Rep(), {}
    R.p("# Snapshot diff")
    R.p(f"snapdiff.py {VERSION}. **Old:** {A['meta'].get('main_txt')} (captured {A['meta'].get('captured')}, text "
        f"SHA-256 `{A['meta'].get('main_txt_sha256', '')[:16]}…`). **New:** {B['meta'].get('main_txt')} (captured "
        f"{B['meta'].get('captured')}, text SHA-256 `{B['meta'].get('main_txt_sha256', '')[:16]}…`).")
    if A["meta"].get("Build fingerprint") != B["meta"].get("Build fingerprint"):
        R.p(f"**Build changed:** {A['meta'].get('Build fingerprint')} → {B['meta'].get('Build fingerprint')} "
            "(an OTA explains many system-package changes below).")

    # packages
    R.h(2, "1. Packages")
    pa, pb = A["packages"], B["packages"]
    add, rem, chg = dd(pa, pb)
    R.p(f"Installed: {len(add)}; removed: {len(rem)}; changed: {len(chg)}.")
    R.table(["installed", "version", "installer", "initiating", "first install", "sensitive grants", "flags"],
            [(k, pb[k].get("versionName"), pb[k].get("installerPackageName"), pb[k].get("initiatingPackageName"),
              pb[k].get("firstInstallTime"), ",".join(pb[k]["grants"]), ",".join(pb[k]["flags"])) for k in add])
    R.table(["removed", "version", "installer"], [(k, pa[k].get("versionName"), pa[k].get("installerPackageName")) for k in rem])
    rows = []
    for k in chg:
        x, y = pa[k], pb[k]
        what = []
        for f in ("versionName", "installerPackageName", "cert", "hidden", "enabled", "system"):
            if x.get(f) != y.get(f):
                what.append(f"{f}: {x.get(f)} → {y.get(f)}")
        ga, gb = set(x["grants"]), set(y["grants"])
        fa, fb = set(x["flags"]), set(y["flags"])
        if gb - ga:
            what.append("+grants " + ",".join(sorted(gb - ga)))
        if ga - gb:
            what.append("-grants " + ",".join(sorted(ga - gb)))
        if fb - fa:
            what.append("+flags " + ",".join(sorted(fb - fa)))
        if fa - fb:
            what.append("-flags " + ",".join(sorted(fa - fb)))
        if what and not (len(what) == 1 and what[0].startswith("versionName")):
            rows.append((k, "; ".join(what)))
    vers = [k for k in chg if any(r[0] == k for r in rows) is False]
    R.p(f"Packages whose only change is a version update: {len(vers)} (listed in tables.json).")
    R.table(["package", "change"], rows, limit=80)
    R.look("a new package not installed by the Play Store; a signing-certificate change (an update can't legitimately "
           "change it); a new sensitive grant or install-time flag you don't remember allowing; a package that became "
           "hidden or disabled.")
    T["packages"] = {"added": add, "removed": rem, "changed": rows, "version_only": vers}

    # app ops
    R.h(2, "2. App-op modes (non-default)")
    oa, ob = A["appops"], B["appops"]
    rows = []
    for k in sorted(set(oa) | set(ob)):
        x, y = oa.get(k, {}), ob.get(k, {})
        for op in sorted(set(x) | set(y)):
            if x.get(op) != y.get(op):
                rows.append((k, op, x.get(op, "default"), y.get(op, "default")))
    R.table(["package", "op", "old", "new"], rows, limit=80)
    R.look("an op moved to allow for an app you didn't change (especially mic, camera, location, SMS, notifications, "
           "overlay, usage stats).")
    T["appops"] = rows

    # roles + admin
    R.h(2, "3. Roles and remote-control surfaces")
    ra, rb = A["roles"], B["roles"]
    R.table(["role", "old", "new"], [(k, ra.get(k), rb.get(k)) for k in sorted(set(ra) | set(rb)) if ra.get(k) != rb.get(k)])
    xa, xb = A["admin"], B["admin"]
    def change(o, n):
        if isinstance(o, list) and isinstance(n, list):
            return "; ".join(["+ " + str(x) for x in n if x not in o] + ["- " + str(x) for x in o if x not in n])
        if isinstance(o, dict) and isinstance(n, dict):
            return "; ".join(f"{k}: {o.get(k)} → {n.get(k)}" for k in sorted(set(o) | set(n)) if o.get(k) != n.get(k))
        return f"{o} → {n}"
    rows = [(k, change(xa.get(k), xb.get(k))) for k in sorted(set(xa) | set(xb)) if xa.get(k) != xb.get(k)]
    R.table(["item", "change"], rows)
    R.p("Current state (new snapshot): admins " + (", ".join(xb.get("device_admins", [])) or "none") +
        "; trust agents " + (", ".join(xb.get("trust_agents", [])) or "none") +
        "; ADB " + json.dumps(xb.get("adb", {})) + "; users " + str(len(xb.get("users", []))) +
        "; accounts " + str(len(xb.get("accounts", []))) + ".")
    R.look("any change here. Each item is a way to read or drive the phone without an app looking like spyware: "
           "admins, accessibility, notification access, trust agents (keep the phone unlocked), wireless debugging, "
           "VPN, a new user/profile, a new account, a new companion device, a new Doze exemption.")
    T["roles_admin"] = rows

    # settings
    R.h(2, "4. Settings (global and secure)")
    sa, sb = A["settings"], B["settings"]
    add, rem, chg = dd(sa, sb)
    allrows = [(k, sa.get(k, {}).get("value"), sb.get(k, {}).get("value"), sb.get(k, sa.get(k, {})).get("pkg"))
               for k in add + rem + chg]
    key = lambda k: k.split(":", 1)[1]
    flagged = [r for r in allrows if key(r[0]) in WATCH_SETTINGS or (r[3] and not system_writer(r[3]))]
    R.p(f"Settings added {len(add)}, removed {len(rem)}, changed {len(chg)}. Shown: security-relevant keys and anything "
        "written by a non-system package; the rest are in tables.json.")
    R.table(["setting", "old", "new", "last written by"], [(k, (o or "")[:80], (n or "")[:80], p) for k, o, n, p in flagged])
    writers = sorted({v["pkg"] for v in sb.values() if not system_writer(v["pkg"])})
    R.p("Non-system packages that have written any global/secure setting (new snapshot): " + (", ".join(writers) or "none") + ".")
    R.look("a security-relevant setting changed when you didn't change it; any setting written by a package that "
           "isn't Android or Google.")
    T["settings"] = {"all": allrows, "flagged": flagged, "non_system_writers": writers}

    # radios
    R.h(2, "5. Saved Wi-Fi and bonded Bluetooth")
    wa, wb = A["radios"]["wifi_saved"], B["radios"]["wifi_saved"]
    add, rem, chg = dd(wa, wb)
    R.table(["Wi-Fi", "change", "detail"], [(k, "added", json.dumps(wb[k])) for k in add] +
            [(k, "removed", json.dumps(wa[k])) for k in rem] + [(k, "changed", f"{wa[k]} → {wb[k]}") for k in chg])
    ba, bb = A["radios"]["bt_bonded"], B["radios"]["bt_bonded"]
    add, rem, chg = dd(ba, bb)
    R.table(["Bluetooth (masked)", "change", "detail"], [(k, "bonded", json.dumps(bb[k])) for k in add] +
            [(k, "unbonded", json.dumps(ba[k])) for k in rem] + [(k, "changed", f"{ba[k]} → {bb[k]}") for k in chg])
    R.look("a saved network or bonded device you didn't add; MAC randomization switched off for a network.")

    os.makedirs(out)
    with open(os.path.join(out, "report.md"), "w") as fh:
        fh.write("".join(R.parts))
    with open(os.path.join(out, "tables.json"), "w") as fh:
        json.dump(T, fh, indent=1, default=str)
    return T


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snap")
    s.add_argument("input")
    s.add_argument("-o", "--out", required=True)
    d = sub.add_parser("diff")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("-o", "--out", required=True)
    a = ap.parse_args()
    if os.path.exists(a.out):
        sys.exit(f"{a.out} already exists")
    tool = {"tool_sha256": sha256_file(os.path.abspath(__file__)),
            "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if a.cmd == "snap":
        st = snapshot(a.input)
        st["meta"].update(tool)
        with open(a.out, "w") as fh:
            json.dump(st, fh, indent=1, sort_keys=True, default=lambda x: sorted(x))
        print(f"{a.out}: {len(st['packages'])} packages, {len(st['settings'])} settings, "
              f"{sum(len(v) for v in st['appops'].values())} non-default ops, {len(st['admin']['trust_agents'])} trust agents")
    else:
        A, B = load_state(a.old), load_state(a.new)
        T = diff(A, B, a.out)
        with open(os.path.join(a.out, "manifest.json"), "w") as fh:
            json.dump({**tool, "tool": "snapdiff.py", "version": VERSION, "old": A["meta"], "new": B["meta"]}, fh, indent=1)
        print(f"report: {os.path.join(a.out, 'report.md')}  packages +{len(T['packages']['added'])} "
              f"-{len(T['packages']['removed'])} ~{len(T['packages']['changed'])}; ops {len(T['appops'])}; "
              f"admin/roles {len(T['roles_admin'])}; flagged settings {len(T['settings']['flagged'])}")


if __name__ == "__main__":
    main()
