#!/usr/bin/env python3
"""mitm.py - look for man-in-the-middle signs in an Android bug report, intrusion logs and a Chrome NetLog.
Python 3.9+ standard library only. Nothing here proves how anything was done; it reports what the logs record.

Inputs (any combination; the bug report is the main one)
  --br  <bugreport.zip | bugreport-*.txt>
  --il  <ilpass output folder>            (uses events.jsonl)
  --netlog <chrome net-export .json>      (Chrome on the phone: chrome://net-export, Start logging; reproduce; Stop)

Checks
  1. Wi-Fi / LAN     from IpClient's connectivity packet log and state machine: every ARP reply (IP -> MAC) per
                     network session, the gateway, DHCP server, DNS servers handed out, and the BSSIDs joined.
  2. Validation      NetworkMonitor probes per network: DNS, HTTP, HTTPS, fallback, Private DNS. Failures with
                     time and (for Wi-Fi) the signal from the blocklist monitor; DNS answers for Google's probe
                     hosts outside Google's published ranges; Private DNS (strict mode) resolution sets.
  3. Cellular        modem cipher reports (null encryption/integrity), null-cipher notifier, network security
                     events, identifier-disclosure lines, 2G restriction.
  4. Intrusion log   connects on port 853 (DNS-over-TLS) to addresses outside the Private DNS set; certificate /
                     key security events; TLS-port connects to private addresses.
  5. Chrome NetLog   certificates not issued by a known (publicly trusted) root, certificate errors, TLS errors,
                     proxy configuration.

Usage
  python3 -I stalkeraware.py mitm --bugreport <zip> [--intrusion-logs out/il-x] [--netlog chrome-net-export-log.json] --out <new folder>
"""
import argparse
import collections
import hashlib
import ipaddress
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone

from .common import toolkit_sha256

VERSION = "0.1.1 (2026-11-24)"
# Google's IP space for its probe hosts (connectivitycheck.gstatic.com, www.google.com, *.metric.gstatic.com).
# A subset of goog.json; an answer outside it is listed, not concluded.
GOOGLE_NETS = [ipaddress.ip_network(n) for n in (
    "8.8.4.0/24", "8.8.8.0/24", "34.64.0.0/10", "35.184.0.0/13", "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19",
    "72.14.192.0/18", "74.125.0.0/16", "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16",
    "173.194.0.0/16", "192.178.0.0/15", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19",
    "2001:4860::/32", "2404:6800::/32", "2607:f8b0::/32", "2800:3f0::/32", "2a00:1450::/32", "2c0f:fb50::/32")]
PROBE_HOSTS = ("connectivitycheck.gstatic.com", "www.google.com", "play.googleapis.com", "metric.gstatic.com")
NULL_ALGS = {"NEA0", "EEA0", "NIA0", "EIA0", "GEA0", "A5_0", "SIP_NULL", "SRTP_NULL", "IMS_NULL", "ENCR_NULL",
             "AUTH_HMAC_NULL"}
CERT_EVENTS = ("cert_authority_installed", "cert_authority_removed", "cert_validation_failure",
               "key_integrity_violation", "crypto_self_test_completed", "key_generated", "key_imported",
               "key_destroyed", "keystore")


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def in_google(a):
    try:
        ip = ipaddress.ip_address(a.strip().lstrip("/"))
    except ValueError:
        return None
    return any(ip in n for n in GOOGLE_NETS)


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


def read_br(path):
    raw = open(path, "rb").read()
    meta = {"input": os.path.abspath(path), "input_sha256": sha256_bytes(raw)}
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            n = [x for x in z.namelist() if re.match(r"^bugreport-.*\.txt$", os.path.basename(x))][0]
            raw = z.read(n)
            meta["main_txt"] = n
    meta["main_txt_sha256"] = sha256_bytes(raw)
    return raw.decode("utf-8", "replace").split("\n"), meta


# ------------------------------------------------------------------------------------------ 1. LAN

def lan(L):
    sessions, cur, dhcp, lp = [], None, [], []
    seen = set()
    for i, l in enumerate(L):
        m = re.match(r"^\s+(\S+) - --- START \((.*)\) ---", l)
        if m:
            key = (m.group(1), m.group(2))
            if key in seen:          # the dump repeats; keep the first copy
                cur = None
                continue
            seen.add(key)
            cur = {"start": m.group(1), "ssid": m.group(2), "arp": collections.defaultdict(set), "dhcp_ack_from": set(),
                   "line": i + 1, "end": None}
            sessions.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+(\S+) - --- STOP", l)
        if m:
            cur["end"] = m.group(1)
            cur = None
            continue
        m = re.match(r"^\s+\S+ - RX (\S+) > \S+ arp reply (\S+) (\S+)", l)
        if m:
            cur["arp"][m.group(2)].add(m.group(3))
            if m.group(1) != m.group(3):
                cur.setdefault("arp_src_mismatch", set()).add((m.group(2), m.group(1), m.group(3)))
        m = re.match(r"^\s+\S+ - RX (\S+) > \S+ ipv4 (\S+) > \S+ udp 67 > 68 dhcp4 .*?(ACK|OFFER)", l)
        if m:
            cur["dhcp_ack_from"].add((m.group(2), m.group(1)))
    for l in L:
        m = re.search(r"^\s+(\S+) - INVOKE onNewDhcpResults\(\{.*?DHCP server (\S+) .*?lease (\d+)", l)
        if m:
            dhcp.append((m.group(1), m.group(2).lstrip("/"), m.group(3)))
        m = re.search(r"^\s+(\S+) - INVOKE onProvisioningSuccess\(\{\{InterfaceName: (\S+) LinkAddresses: \[([^\]]*)\] "
                      r"DnsAddresses: \[([^\]]*)\].*?(?:ServerAddress: (\S+))?.*?Routes: \[([^\]]*)\]", l)
        if m:
            gw = re.findall(r"0\.0\.0\.0/0 -> (\S+)", m.group(6))
            lp.append((m.group(1), m.group(2), m.group(3).strip(), m.group(4).strip(), (m.group(5) or "").lstrip("/"),
                       ",".join(sorted(set(gw)))))
    return sessions, sorted(set(dhcp)), sorted(set(lp))


# ------------------------------------------------------------------------------------------ 2. validation

def validation(L):
    nets, cur, seen_nets = {}, None, set()
    start = None
    for i, l in enumerate(L):
        if l.startswith("Validation logs (most recent first):"):
            start = i
            break
    if start is None:
        return nets
    for l in L[start + 1:start + 20000]:
        m = re.match(r"^(\d+) - (.+?)\s*$", l)
        if m:
            k = (m.group(1), m.group(2))
            if k in seen_nets:
                break                 # second copy of the dump
            seen_nets.add(k)
            cur = nets.setdefault(k, [])
            continue
        m = re.match(r"^\s+(\d{4}-\d\d-\d\dT[\d:.]+) - (.*)$", l)
        if m and cur is not None:
            cur.append((m.group(1), m.group(2)))
            continue
        if l.strip() and not l.startswith(" ") and not re.match(r"^\d+ - ", l):
            break
    return nets


def parse_probe(msg):
    m = re.match(r"(PROBE_\w+) (\S+)(.*)$", msg)
    if not m:
        return None
    kind, target, rest = m.groups()
    r = {"kind": kind, "target": target, "ok": None, "ret": None, "answers": [], "detail": rest.strip()[:160]}
    if kind == "PROBE_DNS":
        a = re.search(r"\d+ms (OK|FAIL)\s*(\S*)", rest)
        if a:
            r["ok"] = a.group(1) == "OK"
            r["answers"] = [x for x in a.group(2).split(",") if x]
    elif kind == "PROBE_PRIVDNS":
        r["ok"] = "FAIL" not in rest and "exception" not in rest.lower()
        r["answers"] = [x.strip().lstrip("/") for x in re.findall(r"/([0-9a-fA-F:.]+)", rest)]
    else:
        a = re.search(r"ret=(\d+)", rest)
        r["ret"] = int(a.group(1)) if a else None
        r["ok"] = r["ret"] in (204, 200) if a else False
    return r


# ------------------------------------------------------------------------------------------ main

def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(prog=prog, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bugreport", dest="br", metavar="BUGREPORT", help="bug report .zip or bugreport-*.txt")
    ap.add_argument("--intrusion-logs", dest="il", metavar="FOLDER", help="output folder of the intrusion-logs pass")
    ap.add_argument("--netlog", help="Chrome NetLog JSON (chrome://net-export)")
    ap.add_argument("--br", dest="br", help=argparse.SUPPRESS)          # earlier names, still accepted
    ap.add_argument("--il", dest="il", help=argparse.SUPPRESS)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if not (a.br or a.il or a.netlog):
        sys.exit("give --bugreport, --intrusion-logs and/or --netlog")
    if os.path.exists(a.out):
        sys.exit(f"--out {a.out} already exists")
    R, T = Rep(), {}
    man = {"tool": "mitm.py", "version": VERSION, "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "tool_sha256": sha256_bytes(open(os.path.abspath(__file__), "rb").read()),
           "toolkit_sha256": toolkit_sha256()}
    R.p("# Man-in-the-middle checks")
    privdns_set = set()

    if a.br:
        L, meta = read_br(a.br)
        man["br"] = meta
        R.p(f"Bug report `{meta.get('main_txt', os.path.basename(a.br))}` (text SHA-256 `{meta['main_txt_sha256'][:16]}…`). "
            f"mitm.py {VERSION}.")
        # 1. LAN
        R.h(2, "1. Wi-Fi / LAN (IpClient packet log)")
        sessions, dhcp, lp = lan(L)
        rows, flags = [], []
        for s in sessions:
            arp = "; ".join(f"{ip} → {', '.join(sorted(m))}" for ip, m in sorted(s["arp"].items()))
            rows.append((s["start"][:19], (s["end"] or "")[:19], s["ssid"], arp,
                         ", ".join(f"{ip} via {mac}" for ip, mac in sorted(s["dhcp_ack_from"]))))
            for ip, macs in s["arp"].items():
                if len(macs) > 1:
                    flags.append(f"{s['ssid']} {s['start'][:19]}: {ip} answered by {len(macs)} MACs {sorted(macs)}")
            for x in s.get("arp_src_mismatch", ()):
                flags.append(f"{s['ssid']} {s['start'][:19]}: ARP reply for {x[0]} claims {x[2]} but came from {x[1]}")
        R.table(["session start", "end", "SSID", "ARP replies seen (IP → MAC)", "DHCP replies (server via MAC)"], rows)
        R.table(["time", "DHCP server", "lease s"], dhcp)
        R.table(["time", "interface", "addresses", "DNS servers handed out", "server", "default gateway"], lp)
        bss = collections.defaultdict(set)
        for l in L:
            m = re.match(r"^startTime=\S+ \S+, SSID=(\".*?\"|[^,]*), BSSID=([^,]*),", l)
            if m:
                bss[m.group(1)].add(m.group(2))
        R.p("BSSIDs joined per SSID (Wi-Fi connection events): " +
            "; ".join(f"{k}: {', '.join(sorted(v))}" for k, v in bss.items()) + ".")
        gw_macs = {m for s in sessions for ip, ms in s["arp"].items() for m in ms}
        allb = {b.lower() for v in bss.values() for b in v}
        R.p("Gateway MACs that are also a joined BSSID (router and access point in one box): " +
            (", ".join(sorted(g for g in gw_macs if g.lower() in allb)) or "none") + ".")
        R.p("**Flags:** " + ("; ".join(flags) if flags else "none — every IP was answered by a single MAC, and every "
                                                             "ARP reply came from the MAC it claimed."))
        R.look("one IP answered by two MACs (ARP spoofing); an ARP reply whose sender differs from the MAC it claims; a "
               "DHCP reply from a second server; DNS servers handed out that aren't your router; a BSSID you don't "
               "recognize for a saved SSID.")
        T["lan"] = {"sessions": rows, "flags": flags, "dhcp": dhcp, "link": lp, "bssids": {k: sorted(v) for k, v in bss.items()}}

        # 2. validation
        R.h(2, "2. Network validation probes")
        nets = validation(L)
        bl = [l.strip()[:200] for l in L if "WifiBlocklistMonitor addToBlocklist" in l]
        summary, fails, offg, priv = [], [], [], collections.Counter()
        for (nid, name), entries in nets.items():
            c = collections.Counter()
            for t, msg in entries:
                if msg.startswith("Strict mode hostname resolution"):
                    ips = re.findall(r"/([0-9a-fA-F:.]+)", msg)
                    host = re.search(r" for (\S+)", msg)
                    priv[(name, host.group(1) if host else "?", tuple(sorted(ips)))] += 1
                    privdns_set.update(ips)
                    if " OK " not in msg:
                        fails.append((t[:19], nid, name, "Private DNS resolution", msg[:140]))
                    continue
                pr = parse_probe(msg)
                if not pr:
                    continue
                c[(pr["kind"], "ok" if pr["ok"] else "FAIL")] += 1
                if not pr["ok"]:
                    fails.append((t[:19], nid, name, pr["kind"], f"{pr['target']} {pr['detail']}"[:160]))
                if pr["kind"] in ("PROBE_DNS", "PROBE_PRIVDNS") and any(h in pr["target"] for h in PROBE_HOSTS):
                    bad = [x for x in pr["answers"] if in_google(x) is False]
                    if bad:
                        offg.append((t[:19], nid, name, pr["target"], ", ".join(bad)))
            summary.append((nid, name, ", ".join(f"{k[0][6:]} {k[1]} {v}" for k, v in sorted(c.items()))))
        R.table(["net id", "network", "probe results"], summary)
        R.p("Failed probes:")
        R.table(["time", "net id", "network", "probe", "detail"], fails)
        if bl:
            R.p("Wi-Fi blocklist entries (context for Wi-Fi validation failures, with signal): ")
            R.table(["entry"], [(x,) for x in bl])
        R.p("Answers for Google's probe hostnames outside Google's ranges:")
        R.table(["time", "net id", "network", "host", "answers outside Google"], offg)
        R.p("Private DNS (strict mode) hostname resolutions:")
        R.table(["network", "hostname", "addresses", "times seen"],
                [(nw, h, ", ".join(ips), n) for (nw, h, ips), n in sorted(priv.items())])
        sets = collections.defaultdict(set)
        for (nw, h, ips), n in priv.items():
            sets[(nw.strip('"') if nw != "nrphone" else "cellular", h)].add(ips)
        R.p("Address sets per network type: " + "; ".join(f"{k[0]}: {len(v)} set(s)" for k, v in sorted(sets.items())) +
            ". A DNS provider steering to nearby servers gives different sets on different networks; different sets on "
            "the SAME network at nearby times, or addresses outside the provider, are what to check.")
        R.look("an HTTPS probe failing while the HTTP probe on the same network succeeds (TLS interception without a "
               "trusted certificate); probe hostnames resolving outside Google's ranges (DNS spoofing); the Private DNS "
               "hostname resolving to a different set of addresses on one network; Private DNS probes failing on a "
               "network where plain DNS works. Failures at weak signal or while leaving a network are ordinary.")
        T["validation"] = {"summary": summary, "fails": fails, "off_google": offg,
                           "privdns": [[nw, h, list(ips), n] for (nw, h, ips), n in priv.items()]}

        # 3. cellular
        R.h(2, "3. Cellular")
        alg = collections.Counter()
        for l in L:
            m = re.search(r"connectionEvent: (\w+), encryption: (\w+), integrity: (\w+), isUnprotectedEmergency: (\w+)", l)
            if m:
                alg[m.groups()] += 1
        R.table(["connection event", "encryption", "integrity", "unprotected emergency", "reports", "flag"],
                [k + (v, "NULL" if (k[1] in NULL_ALGS or k[2] in NULL_ALGS or k[3] == "true") else "")
                 for k, v in alg.most_common()])
        notes = []
        for l in L:
            s = l.strip()
            if "NullCipherNotifier" in s or "mNetworkSecurityEvents" in s or "IdentifierDisclosure" in s:
                notes.append(s[:180])
            if s.startswith("mAllowedNetworkTypeValue="):
                notes.append(s)
        R.table(["line"], [(x,) for x in dict.fromkeys(notes)], limit=30)
        R.p("The modem's cipher reports cover only the short radio-log window; the notifier lines show whether "
            "Android's cellular security notifications are on (if off, null-cipher and identifier-disclosure events "
            "aren't surfaced).")
        R.look("any NULL row (NEA0/EEA0 encryption or NIA0/EIA0 integrity); network security events that aren't empty; "
               "2G allowed while Advanced Protection is on.")
        T["cellular"] = {"ciphers": [list(k) + [v] for k, v in alg.items()], "notes": list(dict.fromkeys(notes))}

    if a.il:
        R.h(2, "4. Intrusion log")
        ev = [json.loads(l) for l in open(os.path.join(a.il, "events.jsonl"))]
        fmt = lambda ns: datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).astimezone().strftime("%m-%d %H:%M:%S")
        dot = collections.Counter()
        for e in ev:
            if e["type"] == "connect" and e["payload"].get("port") == 853:
                dot[e["payload"].get("ip_address", "").lstrip("/")] += 1
        outside = {ip: n for ip, n in dot.items() if privdns_set and ip not in privdns_set}
        R.p(f"DNS-over-TLS (port 853) connects: {sum(dot.values())} to {len(dot)} addresses. Private DNS set from the "
            f"bug report: {', '.join(sorted(privdns_set)) or 'not available (no --br)'}.")
        R.table(["port-853 destination", "connects", "in Private DNS set"],
                [(ip, n, (ip in privdns_set) if privdns_set else "?") for ip, n in dot.most_common()])
        KEY_ROUTINE = ("sec:key_generated", "sec:key_destruction", "sec:key_destroyed", "sec:key_imported")
        certs = [(fmt(e["t_ns"]), e["type"][4:], json.dumps(e["payload"])[:160], f"{e['file']}:{e['line']}")
                 for e in ev if e["type"].startswith("sec:") and any(c in e["type"] for c in CERT_EVENTS)
                 and e["type"] not in KEY_ROUTINE
                 and not (e["type"] == "sec:crypto_self_test_completed" and e["payload"].get("success") is not False)]
        routine = collections.Counter((e["type"][4:], e["payload"].get("success")) for e in ev
                                      if e["type"] in KEY_ROUTINE or e["type"] == "sec:crypto_self_test_completed")
        R.p("Routine keystore events (counted; listed below only if they failed): " +
            (", ".join(f"{k[0]} success={k[1]}: {v}" for k, v in sorted(routine.items(), key=str)) or "none") + ".")
        fails = collections.Counter((e["type"][4:], e["payload"].get("uid")) for e in ev
                                    if e["type"] in KEY_ROUTINE and e["payload"].get("success") is False)
        if fails:
            R.p("Failed routine keystore operations by app UID (usually an app deleting a key alias that doesn't "
                "exist; listed for completeness):")
            R.table(["event", "uid", "count"], [k + (v,) for k, v in fails.most_common()], limit=20)
        R.p("Certificate-authority installs/removals, certificate-validation failures, key-integrity violations, "
            "and any failed keystore or self-test event:")
        R.table(["time", "event", "detail", "source"], certs, limit=60)
        bysec = collections.defaultdict(list)
        for e in ev:
            if e["type"] == "connect" and e["payload"].get("port") == 853:
                ip = e["payload"].get("ip_address", "").lstrip("/")
                if privdns_set and ip not in privdns_set:
                    bysec[(fmt(e["t_ns"]), e["payload"].get("package_name"))].append(ip)
        if bysec:
            R.p("Port-853 connects outside the Private DNS set, grouped by second (a bug report's connectivity "
                "diagnostics probe the carrier's and Google's resolvers together in one burst):")
            R.table(["time", "app", "destinations"], [(k[0], k[1], ", ".join(sorted(set(v)))) for k, v in sorted(bysec.items())])
        priv443 = collections.Counter()
        for e in ev:
            if e["type"] == "connect" and e["payload"].get("port") in (443, 853):
                try:
                    ip = ipaddress.ip_address(e["payload"].get("ip_address", "").lstrip("/"))
                except ValueError:
                    continue
                if ip.is_private and not ip.is_loopback and not ip.is_unspecified:
                    priv443[(e["payload"].get("package_name") or "(system)", str(ip), e["payload"].get("port"))] += 1
        R.p("TLS-port connects to private (LAN/carrier-internal) addresses:")
        R.table(["app", "address", "port", "connects"], [k + (v,) for k, v in priv443.most_common()])
        R.look("a port-853 connect to an address outside the Private DNS set (DNS-over-TLS redirected); a CA installed "
               "or a certificate-validation failure you can't explain; TLS to a LAN address by an app with no reason to.")
        T["il"] = {"dot": dict(dot), "dot_outside": outside, "cert_events": certs,
                   "private_tls": [list(k) + [v] for k, v in priv443.items()]}

    if a.netlog:
        R.h(2, "5. Chrome NetLog")
        man["netlog_sha256"] = sha256_bytes(open(a.netlog, "rb").read())
        try:
            NL = json.load(open(a.netlog))
        except json.JSONDecodeError:
            txt = open(a.netlog, errors="replace").read().rstrip().rstrip(",")
            NL = json.loads(txt + ("]}" if not txt.endswith("}") else ""))
        names = {v: k for k, v in NL.get("constants", {}).get("logEventTypes", {}).items()}
        neterr = {v: k for k, v in NL.get("constants", {}).get("netError", {}).items()}
        host_of, certs, errs, proxy = {}, [], collections.Counter(), []
        for e in NL.get("events", []):
            name = names.get(e.get("type"), str(e.get("type")))
            src = (e.get("source") or {}).get("id")
            p = e.get("params") or {}
            if "host" in p and src is not None:
                host_of[src] = p["host"]
            if name in ("CERT_VERIFIER_JOB", "CERT_VERIFIER_TASK", "CERT_VERIFY_PROC") and "is_issued_by_known_root" in p:
                certs.append((host_of.get(src, "?"), p.get("is_issued_by_known_root"), p.get("cert_status"),
                              (e.get("time") or "")))
            ne = p.get("net_error")
            if isinstance(ne, int) and ne < 0 and (-219 <= ne <= -200 or -199 <= ne <= -100):
                errs[(name, neterr.get(ne, ne), host_of.get(src, "?"))] += 1
            if "PROXY" in name and p:
                proxy.append((name, json.dumps(p)[:160]))
        unknown = [c for c in certs if c[1] is False]
        R.p(f"NetLog SHA-256 `{man['netlog_sha256'][:16]}…`: {len(NL.get('events', []))} events, {len(certs)} certificate "
            f"verifications, {len(unknown)} not issued by a known root.")
        R.table(["host", "issued by known root", "cert status", "time"], unknown, limit=60)
        R.p("TLS / certificate errors:")
        R.table(["event", "error", "host", "count"], [k + (v,) for k, v in errs.most_common()], limit=60)
        R.p("Proxy-related events:")
        R.table(["event", "params"], proxy, limit=20)
        R.look("any certificate for a public site not issued by a known root (a locally installed CA is signing for "
               "it); certificate-authority or pinning errors; a proxy you didn't configure.")
        T["netlog"] = {"unknown_root": unknown, "errors": [list(k) + [v] for k, v in errs.items()], "proxy": proxy}

    os.makedirs(a.out)
    with open(os.path.join(a.out, "report.md"), "w") as fh:
        fh.write("".join(R.parts))
    with open(os.path.join(a.out, "tables.json"), "w") as fh:
        json.dump(T, fh, indent=1, default=str)
    with open(os.path.join(a.out, "manifest.json"), "w") as fh:
        json.dump(man, fh, indent=1)
    print(f"report: {os.path.join(a.out, 'report.md')}")


if __name__ == "__main__":
    main()
