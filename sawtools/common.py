"""common.py - bug-report plumbing shared by the stalkeraware passes (Python 3.9+ standard library only).

Moved verbatim from rfpass.py 1.0.2 so every bug-report pass reads the report the same way:
input handling (safe zip extraction, locating the main text), the section/service index, report and
table writers, device identity and settings, logcat coverage, battery history (state changes and
per-app on-screen/foreground intervals) and per-UID batterystats.
"""
import bisect
import collections
import csv
import glob
import hashlib
import json
import os
import re
import stat
import traceback
import zipfile
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

MAX_EXTRACT = 6 * 1024 ** 3               # refuse to extract more than 6 GiB in total
PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def toolkit_sha256():
    """One hash over every module in the package (name + content), so a manifest pins the exact code that ran."""
    h = hashlib.sha256()
    for p in sorted(glob.glob(os.path.join(PKG_DIR, "*.py"))):
        h.update(os.path.basename(p).encode() + b"\0")
        with open(p, "rb") as fh:
            h.update(fh.read())
        h.update(b"\0")
    return h.hexdigest()

# ----------------------------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------------------------


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def fmt_t(t, date=True):
    if t is None:
        return "-"
    s = t.strftime("%m-%d %H:%M:%S.%f")[:-3]
    return s if date else s[6:]


def fmt_dur(sec):
    if sec is None:
        return "-"
    sec = float(sec)
    if sec < 60:
        return f"{sec:.1f}s"
    m, s = divmod(int(round(sec)), 60)
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"


def pct(a, b):
    return f"{100.0 * a / b:.1f}%" if b else "n/a"


def mdcell(x):
    s = "" if x is None else str(x)
    return s.replace("|", "\\|").replace("\n", " ")


def mac(b):
    return ":".join(f"{x:02X}" for x in reversed(b))


def suffix2(addr):
    """Last two bytes of an address, upper case, e.g. 'AB:CD'."""
    if not addr:
        return ""
    return addr.upper()[-5:]


def iso(s):
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


PT_RE = re.compile(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?")


def pt_seconds(s):
    m = PT_RE.match(s)
    if not m:
        return None
    h, mi, se = m.groups()
    return int(h or 0) * 3600 + int(mi or 0) * 60 + float(se or 0)


class Report:
    def __init__(self):
        self.parts = []
        self.problems = []
        self.toc = []

    def h(self, level, text):
        if level == 2:
            self.toc.append(text)
        self.parts.append("\n" + "#" * level + " " + text + "\n")

    def p(self, text=""):
        self.parts.append(text + "\n\n")

    def bullets(self, items):
        self.parts.append("\n")
        for it in items:
            self.parts.append(f"- {it}\n")
        self.parts.append("\n")

    def table(self, headers, rows, limit=None, more=None):
        rows = list(rows)
        if not rows:
            self.p("_(none)_")
            return
        shown = rows if limit is None else rows[:limit]
        self.parts.append("\n| " + " | ".join(mdcell(h) for h in headers) + " |\n")
        self.parts.append("|" + "|".join("---" for _ in headers) + "|\n")
        for r in shown:
            self.parts.append("| " + " | ".join(mdcell(c) for c in r) + " |\n")
        self.parts.append("\n")
        if limit is not None and len(rows) > limit:
            self.p(f"_({len(rows) - limit} more rows{(' in ' + more) if more else ''})_")

    def text(self):
        head = "".join(self.parts[:1])
        return head + "".join(self.parts[1:])


class Out:
    def __init__(self, root):
        self.root = root
        self.data = os.path.join(root, "data")
        os.makedirs(self.data, exist_ok=True)
        self.files = []

    def csv(self, name, headers, rows):
        p = os.path.join(self.data, name)
        with open(p, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(headers)
            for r in rows:
                w.writerow(["" if c is None else c for c in r])
        self.files.append(p)
        return "data/" + name

    def jsonl(self, name, rows):
        p = os.path.join(self.data, name)
        with open(p, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, default=str) + "\n")
        self.files.append(p)
        return "data/" + name


# ----------------------------------------------------------------------------------------------
# input handling
# ----------------------------------------------------------------------------------------------


def safe_extract(zpath, dest, problems):
    os.makedirs(dest, exist_ok=False)
    real_dest = os.path.realpath(dest)
    members = []
    total = 0
    with zipfile.ZipFile(zpath) as z:
        for zi in z.infolist():
            name = zi.filename
            if zi.is_dir():
                continue
            mode = (zi.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                problems.append(f"zip: skipped symlink member {name!r}")
                continue
            norm = os.path.normpath(name.replace("\\", "/"))
            if name.startswith(("/", "\\")) or norm.startswith("..") or os.path.isabs(norm) or ":" in norm.split(os.sep)[0]:
                problems.append(f"zip: skipped unsafe path {name!r}")
                continue
            target = os.path.join(dest, norm)
            if not os.path.realpath(target).startswith(real_dest + os.sep):
                problems.append(f"zip: skipped path escaping the folder {name!r}")
                continue
            total += zi.file_size
            if total > MAX_EXTRACT:
                problems.append("zip: stopped extracting, total size limit reached")
                break
            os.makedirs(os.path.dirname(target), exist_ok=True)
            h = hashlib.sha256()
            try:
                with z.open(zi) as src, open(target, "xb") as dst:
                    for blk in iter(lambda: src.read(1 << 20), b""):
                        h.update(blk)
                        dst.write(blk)
            except FileExistsError:
                problems.append(f"zip: duplicate member name {name!r} (kept the first)")
                continue
            os.chmod(target, 0o444)
            members.append({"name": name, "size": zi.file_size, "sha256": h.hexdigest()})
    return members


def locate_main_txt(folder):
    me = os.path.join(folder, "main_entry.txt")
    if os.path.isfile(me):
        name = open(me, "rb").read().decode("utf-8", "replace").strip()
        p = os.path.join(folder, name)
        if os.path.isfile(p):
            return p
    cands = [os.path.join(folder, f) for f in os.listdir(folder)
             if f.startswith("bugreport-") and f.endswith(".txt")]
    if cands:
        return max(cands, key=os.path.getsize)
    return None


def locate_snoops(folder):
    out = []
    for root, _, files in os.walk(folder):
        for f in files:
            if f.startswith("btsnoop_hci.log") and not f.endswith((".txt", ".gz")):
                out.append(os.path.join(root, f))
    return sorted(out)


# ----------------------------------------------------------------------------------------------
# bug-report text and section index
# ----------------------------------------------------------------------------------------------

SVC_RE = re.compile(r"^DUMP OF SERVICE (?:(CRITICAL|HIGH) )?(\S+):\s*$")
SEC_RE = re.compile(r"^------ (.*) ------\s*$")


class BR:
    def __init__(self, path, problems):
        with open(path, "rb") as fh:
            data = fh.read()
        self.L = data.decode("utf-8", "replace").split("\n")
        del data
        self.problems = problems
        self.services = collections.defaultdict(list)   # name -> [(start, end, prio)]
        self.sections = []                               # (idx, title)
        cur = None
        for i, l in enumerate(self.L):
            if not l or (l[0] != "-" and l[0] != "D"):
                continue
            if l[0] == "D":
                m = SVC_RE.match(l)
                if m:
                    if cur:
                        self.services[cur[0]].append((cur[1], i - 1, cur[2]))
                    cur = (m.group(2), i, m.group(1))
                continue
            if l.startswith("--------- ") and "was the duration of dumpsys" in l:
                if cur:
                    self.services[cur[0]].append((cur[1], i, cur[2]))
                    cur = None
                continue
            m = SEC_RE.match(l)
            if m:
                title = m.group(1)
                if "was the duration of" not in title:
                    self.sections.append((i, title))
                if cur:
                    self.services[cur[0]].append((cur[1], i - 1, cur[2]))
                    cur = None
        if cur:
            self.services[cur[0]].append((cur[1], len(self.L) - 1, cur[2]))

    def service(self, name):
        """(start, end) of the normal-priority dump of a service, else the first one; None if absent."""
        v = self.services.get(name)
        if not v:
            return None
        for s, e, pr in v:
            if pr is None:
                return (s, e)
        return (v[0][0], v[0][1])

    def section(self, prefix):
        for k, (i, title) in enumerate(self.sections):
            if title.startswith(prefix):
                end = self.sections[k + 1][0] - 1 if k + 1 < len(self.sections) else len(self.L) - 1
                # a section ends at its "was the duration" line, which is not in self.sections
                for j in range(i + 1, min(end + 1, len(self.L))):
                    lj = self.L[j]
                    if lj.startswith("------ ") and "was the duration of" in lj:
                        end = j - 1
                        break
                return (i + 1, end)
        return None

    def find(self, needle, start=0, end=None, exact=False):
        end = len(self.L) if end is None else min(end + 1, len(self.L))
        for i in range(start, end):
            l = self.L[i]
            if (l.strip() == needle) if exact else (needle in l):
                return i
        return None


# ----------------------------------------------------------------------------------------------
# context
# ----------------------------------------------------------------------------------------------


class Ctx:
    def __init__(self, args):
        self.args = args
        self.rep = Report()
        self.out = None
        self.br = None
        self.tzname = "America/New_York"
        self.tz = None
        self.report_dt = None
        self.year = None
        self.props = {}
        self.settings = {}
        self.uidpkg = {}           # appId (int) -> [packages]
        self.pkguid = {}           # package -> appId
        self.events = []           # (t, label)
        self.bh = None             # battery history result
        self.reg = []              # registry service-state entries
        self.sta = []              # wifi station events
        self.wconn = []            # wifi connection events
        self.dn = []               # data networks
        self.bt = None             # btsnoop result
        self.btm = {}              # bluetooth_manager parse
        self.uidstats = {}         # batterystats per-UID
        self.exits = []            # process exits
        self.coverage = []         # (source, first, last)
        self.ev_sources = collections.defaultdict(list)   # source -> [(t, text)]
        self.ns = collections.defaultdict(collections.Counter)
        self.reg_cur, self.reg_kinds, self.val, self.cc, self.tacs, self.exits = {}, {}, {}, [], collections.Counter(), []
        self.pidname = {}

    def ytime(self, mo, d, H, M, S, ms):
        y = self.year
        if self.report_dt and int(mo) > self.report_dt.month:
            y -= 1
        return datetime(y, int(mo), int(d), int(H), int(M), int(S), int(ms) * 1000)

    def uidname(self, uid):
        """'u0a411' / '10411' / '1000' -> readable name."""
        s = str(uid)
        m = re.match(r"u(\d+)a(\d+)$", s)
        if m:
            app = 10000 + int(m.group(2))
        else:
            try:
                app = int(s) % 100000
            except ValueError:
                return s
        if app in SYSTEM_UIDS:
            return f"{SYSTEM_UIDS[app]} ({app})"
        p = self.uidpkg.get(app)
        if p:
            return f"{p[0]}{' +%d' % (len(p) - 1) if len(p) > 1 else ''} ({app})"
        return str(app)


SYSTEM_UIDS = {0: "root", 1000: "system", 1001: "radio/phone", 1002: "bluetooth", 1010: "wifi",
               1013: "media", 1027: "nfc", 1041: "audioserver", 1047: "cameraserver",
               1066: "statsd", 1068: "secure_element", 1073: "network_stack", 2000: "shell"}


def part(ctx, name, fn):
    try:
        fn(ctx)
    except Exception as ex:  # keep going; record the failure in the report
        tb = traceback.format_exc(limit=3).strip().splitlines()
        ctx.rep.problems.append(f"{name}: {type(ex).__name__}: {ex} | {' / '.join(x.strip() for x in tb[-3:])}")


# ----------------------------------------------------------------------------------------------
# identity, properties, settings, package uids
# ----------------------------------------------------------------------------------------------


def p_identity(ctx):
    L = ctx.br.L
    hdr = {}
    for i in range(0, min(400, len(L))):
        l = L[i]
        m = re.match(r"^== dumpstate: (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", l)
        if m:
            ctx.report_dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            hdr["dumpstate"] = (m.group(1), i + 1)
        for key in ("Build:", "Build fingerprint:", "Bootloader:", "Radio:", "Network:", "Kernel:", "Uptime:"):
            if l.startswith(key) and key not in hdr:
                hdr[key] = (l[len(key):].strip()[:160], i + 1)
    if ctx.report_dt is None:
        raise RuntimeError("no '== dumpstate:' header; is this an Android bug report?")
    ctx.year = ctx.report_dt.year
    sec = ctx.br.section("SYSTEM PROPERTIES")
    if sec:
        for i in range(sec[0], sec[1] + 1):
            m = re.match(r"^\[([^\]]+)\]: \[(.*)\]\s*$", L[i])
            if m:
                ctx.props[m.group(1)] = (m.group(2), i + 1)
    ctx.tzname = ctx.props.get("persist.sys.timezone", ("America/New_York", None))[0] or "America/New_York"
    ctx.tz = ZoneInfo(ctx.tzname) if ZoneInfo else timezone.utc
    ctx.hdr = hdr
    # settings provider dump: name:<key> pkg:<pkg> value:<value>
    svc = ctx.br.service("settings")
    if svc:
        scope = "?"
        for i in range(svc[0], svc[1] + 1):
            l = L[i]
            if l.endswith("SETTINGS (user 0)") or re.match(r"^\s*(GLOBAL|SECURE|SYSTEM|CONFIG) SETTINGS", l.strip()):
                scope = l.strip()
            m = re.search(r"\bname:(\S+) pkg:(\S+) value:(.*?)(?: default:| defaultSystemSet:|$)", l)
            if m and m.group(1) not in ctx.settings:
                ctx.settings[m.group(1)] = (m.group(3).strip(), scope, i + 1)
    # package -> appId
    svc = ctx.br.service("package")
    rng = range(svc[0], svc[1] + 1) if svc else range(len(L))
    cur = None
    for i in rng:
        l = L[i]
        if l.startswith("  Package ["):
            m = re.match(r"^  Package \[([^\]]+)\]", l)
            cur = (m.group(1), i) if m else None
            continue
        if cur and i - cur[1] < 6:
            m = re.match(r"^    (?:appId|userId)=(\d+)", l)
            if m:
                a = int(m.group(1))
                ctx.uidpkg.setdefault(a, [])
                if cur[0] not in ctx.uidpkg[a]:
                    ctx.uidpkg[a].append(cur[0])
                ctx.pkguid[cur[0]] = a
                cur = None


def r_identity(ctx):
    rep, P = ctx.rep, ctx.props
    rep.h(2, "1. Device, build and log coverage")
    rows = []
    for k in ("dumpstate", "Build fingerprint:", "Bootloader:", "Radio:", "Network:", "Uptime:"):
        if k in ctx.hdr:
            rows.append((k.rstrip(":"), ctx.hdr[k][0], f"L{ctx.hdr[k][1]}"))
    for k in ("ro.product.model", "ro.product.device", "ro.build.version.security_patch", "ro.boot.verifiedbootstate",
              "ro.boot.flash.locked", "ro.boot.vbmeta.device_state", "ro.debuggable", "persist.sys.timezone",
              "persist.logd.size", "init.svc.adbd", "persist.sys.usb.config", "sys.usb.config"):
        if k in P:
            rows.append((k, P[k][0], f"L{P[k][1]}"))
    ap = ctx.br.find("isAdvancedProtectionEnabled:")
    if ap is not None:
        rows.append(("Advanced Protection", ctx.br.L[ap].split(":", 1)[1].strip(), f"L{ap + 1}"))
    rep.table(["item", "value", "ref"], rows)
    rep.p(f"Times in this report are device local time ({ctx.tzname}); the report was captured {ctx.report_dt}.")


def p_logcat_coverage(ctx):
    L = ctx.br.L
    ts = re.compile(r"^(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3})")
    for prefix in ("SYSTEM LOG", "EVENT LOG", "RADIO LOG", "LAST LOGCAT"):
        sec = ctx.br.section(prefix)
        if not sec:
            continue
        buf = prefix
        per = {}
        n = 0
        for i in range(sec[0], sec[1] + 1):
            l = L[i]
            if l.startswith("--------- beginning of ") or l.startswith("--------- switch to "):
                buf = l.split()[-1]
                continue
            m = ts.match(l)
            if not m:
                continue
            n += 1
            t = ctx.ytime(*m.groups())
            f = per.setdefault(buf, [t, t, 0, i + 1])
            if t < f[0]:
                f[0] = t
            if t > f[1]:
                f[1] = t
            f[2] += 1
        for b, (a, z, c, ln) in per.items():
            ctx.coverage.append((f"logcat {prefix} / {b}", a, z, c, f"L{sec[0]}-L{sec[1] + 1}"))


def r_coverage(ctx):
    rep = ctx.rep
    rep.h(3, "Log coverage (what each source can and cannot speak to)")
    rows = [(s, fmt_t(a), fmt_t(z), fmt_dur((z - a).total_seconds()) if a and z else "-", n, ref)
            for s, a, z, n, ref in sorted(ctx.coverage, key=lambda x: (x[1] or datetime.min))]
    rep.table(["source", "first", "last", "span", "entries", "ref"], rows)
    rep.p("A window outside a source's span cannot be judged from that source. The radio logcat buffer is "
          "small; capture a bug report within about a minute of an event if cellular detail matters.")


# ----------------------------------------------------------------------------------------------
# battery history
# ----------------------------------------------------------------------------------------------

SIG_NAMES = {"none": 0, "poor": 1, "moderate": 2, "good": 3, "great": 4}
TRACK_EQ = ("phone_signal_strength", "data_conn", "nr_state", "phone_state", "wifi_suppl",
            "wifi_signal_strength")
TRACK_FLAG = ("phone_scanning", "mobile_radio", "wifi_radio", "wifi", "screen", "audio", "phone_in_call",
              "wifi_running", "cellular_high_tx_power", "wifi_scan", "gps", "camera", "video", "ble_scan",
              "plugged", "flashlight")
BH_LINE = re.compile(r"^  (\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3}) (\d{3}) ([0-9a-f]{8})(?: (.*))?$")
BH_TIME = re.compile(r"^  (\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3}) (?:RESET:)?TIME: (\d{4})-")
BH_APP = re.compile(r'(?:^|\s)([+-]?)([a-z_]+)=(-?[0-9a-z]+):"([^"]*)"')
APP_KEYS = {"top", "fg", "longwake", "pkgactive", "pkginactive", "pkginst", "pkgunin", "tmpwhitelist",
            "screenwake", "job", "sync", "wake_lock_in", "alarm"}


def p_battery_history(ctx):
    L = ctx.br.L
    start = end = None
    for i, l in enumerate(L):
        if start is None:
            if l.startswith("Battery History [Format"):
                start = i
        elif l.startswith("Per-PID Stats") or l.startswith("Discharge step durations"):
            end = i - 1
            break
    if start is None:
        raise RuntimeError("battery history section not found")
    end = end or len(L) - 1
    year = None
    state = {k: None for k in TRACK_EQ}
    flags = {k: None for k in TRACK_FLAG}
    rows, events, app_ev, mism, markers = [], [], [], 0, []
    conn_last = {}
    for i in range(start, end + 1):
        l = L[i]
        if not l.startswith("  "):
            continue
        m = BH_TIME.match(l)
        if m:
            year = int(m.group(7))
            markers.append((i + 1, l.strip()[:80]))
            continue
        m = BH_LINE.match(l)
        if not m:
            continue
        mo, d, H, M, S, ms, lvl, hx, rest = m.groups()
        y = year or ctx.year
        t = datetime(y, int(mo), int(d), int(H), int(M), int(S), int(ms) * 1000)
        st = int(hx, 16)
        rest = rest or ""
        for am in BH_APP.finditer(rest):
            sign, key, uid, val = am.groups()
            if key in APP_KEYS:
                app_ev.append((t, i + 1, sign, key, uid, val))
        for cm in re.finditer(r'conn=(\d+):"([A-Z_]*)"', rest):
            v = f"{cm.group(1)}:{cm.group(2)}"
            if conn_last.get(cm.group(1)) != v:
                events.append((t, i + 1, "conn", conn_last.get(cm.group(1)), v))
                conn_last[cm.group(1)] = v
        bare = re.sub(r'"[^"]*"', '""', rest)
        for tok in bare.split(" "):
            if not tok:
                continue
            if tok[0] in "+-":
                k = tok[1:].split("=", 1)[0]
                if k in flags:
                    v = tok[0] == "+"
                    if flags[k] != v:
                        events.append((t, i + 1, "+" + k, flags[k], v))
                        flags[k] = v
            elif "=" in tok:
                k, v = tok.split("=", 1)
                if k in state:
                    v = v.rstrip(":")
                    if state[k] != v:
                        events.append((t, i + 1, k, state[k], v))
                        state[k] = v
        sig_hex = (st >> 3) & 7
        if state["phone_signal_strength"] is not None and SIG_NAMES.get(state["phone_signal_strength"]) != sig_hex:
            mism += 1
        rows.append({"t": t, "line": i + 1, "level": int(lvl), "sig_hex": sig_hex, "screen": (st >> 20) & 1,
                     "audio_hex": (st >> 22) & 1, "mrad_hex": (st >> 25) & 1, "wrad_hex": (st >> 26) & 1,
                     **{k: state[k] for k in TRACK_EQ}, **{"+" + k: flags[k] for k in TRACK_FLAG}})
    ctx.bh = {"rows": rows, "events": events, "app": app_ev, "range": (start + 1, end + 1), "mismatch": mism,
              "markers": markers}
    if rows:
        ctx.coverage.append(("battery history", rows[0]["t"], rows[-1]["t"], len(rows), f"L{start + 1}-L{end + 1}"))
    ctx.out.jsonl("bhist_events.jsonl", ({"t": e[0].isoformat(timespec="milliseconds"), "line": e[1], "key": e[2],
                                         "old": e[3], "new": e[4]} for e in events))
    ctx.out.jsonl("bhist_app_events.jsonl", ({"t": e[0].isoformat(timespec="milliseconds"), "line": e[1], "sign": e[2],
                                             "key": e[3], "uid": e[4], "value": e[5]} for e in app_ev))
    if getattr(ctx.args, "keep_big", False):
        ctx.out.jsonl("bhist_lines.jsonl", ({**r, "t": r["t"].isoformat(timespec="milliseconds")} for r in rows))


def bh_state_at(ctx, t):
    rows = ctx.bh["rows"]
    if not hasattr(ctx, "_bh_t"):
        ctx._bh_t = [r["t"] for r in rows]
    i = bisect.bisect_right(ctx._bh_t, t) - 1
    return rows[i] if i >= 0 else None


def integrate(rows, a, b, fn):
    """Seconds within [a, b) for which fn(row) is true, integrating the state held by each history line."""
    tot = 0.0
    for x, y in zip(rows, rows[1:]):
        lo, hi = max(x["t"], a), min(y["t"], b)
        if hi > lo and fn(x):
            tot += (hi - lo).total_seconds()
    return tot


def app_intervals(ctx):
    """Per uid: list of (start, end, kind) for 'top' and 'fg' from battery history."""
    if hasattr(ctx, "_appiv"):
        return ctx._appiv
    open_ = {}
    iv = collections.defaultdict(list)
    for t, ln, sign, key, uid, val in ctx.bh["app"]:
        if key not in ("top", "fg") or sign not in "+-" or not sign:
            continue
        k = (uid, key)
        if sign == "+":
            open_.setdefault(k, t)
        elif k in open_:
            iv[uid].append((open_.pop(k), t, key))
        else:   # closed without an open inside the history: started before coverage
            iv[uid].append((ctx.bh["rows"][0]["t"], t, key))
    end = ctx.bh["rows"][-1]["t"] if ctx.bh["rows"] else None
    for (uid, key), t in open_.items():
        iv[uid].append((t, end, key))
    ctx._appiv = iv
    return iv


def app_state(ctx, uid, t):
    iv = app_intervals(ctx).get(uid)
    if not iv:
        return "unknown (no on-screen/foreground events for this app in battery history)"
    kinds = {k for a, b, k in iv if a <= t <= (b or t)}
    if "top" in kinds:
        return "on screen"
    if "fg" in kinds:
        return "foreground service"
    if any(k == "top" and t < a <= t + timedelta(seconds=1) for a, b, k in iv):
        return "being opened (on screen within 1 s)"
    return "not on screen, no foreground service"


def uid_of_pkg(ctx, pkg):
    a = ctx.pkguid.get(pkg)
    if a is None:
        return None
    return f"u0a{a - 10000}" if a >= 10000 else str(a)



# ----------------------------------------------------------------------------------------------
# helpers shared by batpass.py and micpass.py (new in 2026-11-24)
# ----------------------------------------------------------------------------------------------

GOOGLE_PREFIXES = ("com.google.", "com.android.", "android")
DUR_RE = re.compile(r"(\d+(?:\.\d+)?)(ms|d|h|m|s)")
DUR_UNIT = {"d": 86400.0, "h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}


def is_google(name):
    """Google / AOSP package name (or 'android'). Not proof of origin; the package's signer isn't checked here."""
    return bool(name) and (name == "android" or name.startswith(GOOGLE_PREFIXES))


def parse_dur(s):
    """'1h 2m 3s 45ms', '+1m2s345ms', '12s 3ms' -> seconds (float); None if nothing parses."""
    if not s:
        return None
    hits = DUR_RE.findall(s)
    if not hits:
        return None
    return sum(float(v) * DUR_UNIT[u] for v, u in hits)


def parse_size(s):
    """'1.23MB' / '456KB' / '12B' / '3.4GB' -> bytes."""
    m = re.match(r"\s*([\d.]+)\s*([KMG]?B)", s or "")
    if not m:
        return None
    return float(m.group(1)) * {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9}[m.group(2)]


def uid_tag(uid):
    """10234 / '10234' / 'u0a234' / '1000' -> battery-history style 'u0a234' or '1000'."""
    s = str(uid)
    if re.match(r"^u\d+a\d+$", s):
        return s
    try:
        n = int(s)
    except ValueError:
        return s
    user, app = divmod(n, 100000)
    return f"u{user}a{app - 10000}" if app >= 10000 else str(app)


def appid_of(uid):
    s = uid_tag(uid)
    m = re.match(r"^u\d+a(\d+)$", s)
    return 10000 + int(m.group(1)) if m else (int(s) if s.isdigit() else None)


def pkg_is_google(ctx, uid=None, pkg=None):
    """True if the package (or every package sharing the uid) is Google/AOSP, or the uid is a system uid."""
    if pkg:
        return is_google(pkg)
    a = appid_of(uid)
    if a is None:
        return False
    if a < 10000:
        return True
    pk = ctx.uidpkg.get(a) or []
    return bool(pk) and all(is_google(p) for p in pk)


def screen_at(ctx, t):
    r = bh_state_at(ctx, t) if ctx.bh and ctx.bh.get("rows") else None
    if r is None or r.get("+screen") is None:
        return "unknown"
    return "on" if r["+screen"] else "off"


def open_input(ctx, path, manifest):
    """Zip -> hash + safe extraction into <out>/extracted; folder or text used as is. Returns the main text path."""
    if os.path.isfile(path) and zipfile.is_zipfile(path):
        manifest["input_sha256"] = sha256_file(path)
        manifest["input_bytes"] = os.path.getsize(path)
        folder = os.path.join(ctx.out.root, "extracted")
        manifest["members"] = safe_extract(path, folder, ctx.rep.problems)
        return locate_main_txt(folder)
    if os.path.isdir(path):
        return locate_main_txt(path)
    return path


def parse_events(ctx, specs):
    for ev in specs:
        ts, _, label = ev.partition("|")
        t = iso(ts.strip())
        if t is None:
            ctx.rep.problems.append(f"bad --event time {ts!r}")
        else:
            ctx.events.append((t.replace(tzinfo=None), label.strip() or ts))


def p_uidstats_full(ctx):
    """Per-UID 'Statistics since last charge' blocks -> ctx.uidfull[uid] (numbers in seconds / counts / bytes).

    Also the global partial-wakelock and kernel wakeup-reason tables, and the 'Estimated power use (mAh)' rows.
    Every value keeps the line number it came from.
    """
    L = ctx.br.L
    s = ctx.br.find("Statistics since last charge:")
    ctx.uidfull, ctx.wl_global, ctx.wakeup_reasons, ctx.power = {}, [], [], {}
    ctx.charge_meta = {}
    if s is None:
        raise RuntimeError("no 'Statistics since last charge:' section")
    uid = None
    section = None
    for i in range(s, min(s + 600000, len(L))):
        l = L[i]
        if i > s and l and not l.startswith(" "):
            break
        t = l.strip()
        for key in ("Start clock time", "Total run time", "Time on battery", "Time on battery screen off",
                    "Total run time realtime", "Screen on", "Discharge", "Screen off discharge"):
            if t.startswith(key + ":") and key not in ctx.charge_meta:
                ctx.charge_meta[key] = (t.split(":", 1)[1].strip(), i + 1)
        m = re.match(r"^Capacity: (\d+), Computed drain: ([\d.]+), actual drain: (\S+)", t)
        if m and "capacity" not in ctx.charge_meta:
            ctx.charge_meta["capacity"] = (f"{m.group(1)} mAh; computed drain {m.group(2)}; actual {m.group(3)}", i + 1)
        if t.startswith("All partial wake locks:"):
            section = "wl"
            continue
        if t.startswith("All wakeup reasons:") or t.startswith("All kernel wake locks:"):
            section = "wr" if "wakeup" in t else "kwl"
            continue
        if re.match(r"^  (u\d+a\d+|\d+):\s*$", l):
            uid = l.strip().rstrip(":")
            section = None
            ctx.uidfull.setdefault(uid, {"line": i + 1})
            continue
        m = re.match(r"^UID (\S+): ([\d.]+)(.*)$", t)
        if m and m.group(1) not in ctx.power:
            st_ = dict((k, float(v)) for k, v in re.findall(r"\b(fg|bg|fgs|cached): ([\d.]+)", m.group(3)))
            comp = dict((k, float(v)) for k, v in re.findall(r"(\w[\w:-]*)=([\d.]+)", m.group(3)))
            ctx.power[m.group(1)] = {"total": float(m.group(2)), "fg": st_.get("fg"), "bg": st_.get("bg"),
                                     "fgs": st_.get("fgs"), "cached": st_.get("cached"), "components": comp,
                                     "line": i + 1}
            continue
        if section == "wl" and uid is None:
            m = re.match(r"^Wake lock (\S+) (.+?): (.+?) realtime \((\d+) times\)", t)
            if m:
                ctx.wl_global.append({"uid": m.group(1), "tag": m.group(2), "sec": parse_dur(m.group(3)),
                                      "count": int(m.group(4)), "line": i + 1})
                continue
        if section == "wr" and uid is None:
            m = re.match(r"^Wakeup reason (.+?): (.+?) realtime \((\d+) times\)", t)
            if m:
                ctx.wakeup_reasons.append({"reason": m.group(1), "sec": parse_dur(m.group(2)),
                                           "count": int(m.group(3)), "line": i + 1})
                continue
        if uid is None or not l.startswith("    "):
            continue
        st = ctx.uidfull[uid]
        m = re.match(r"^TOTAL wake: (.*)$", t)
        if m:
            for kind, rx in (("wl_blamed", r"(.+?) blamed partial"), ("wl_actual", r"(?:,\s*)?([^,]+?) actual partial"),
                             ("wl_bg", r"(?:,\s*)?([^,]+?) actual background partial")):
                mm = re.search(rx, m.group(1))
                if mm:
                    st[kind] = parse_dur(mm.group(1))
            continue
        m = re.match(r"^Wake lock (.+?): (.*)$", t)
        if m and "partial" in m.group(2):
            mm = re.search(r"(\S.*?) partial \((\d+) times\)", m.group(2))
            if mm:
                st.setdefault("wakelocks", []).append((m.group(1), parse_dur(mm.group(1)), int(mm.group(2))))
            continue
        m = re.match(r"^Wakeup alarm (.+?): (\d+) times", t)
        if m:
            st["wakeup_alarms"] = st.get("wakeup_alarms", 0) + int(m.group(2))
            st.setdefault("alarm_tags", []).append((m.group(1), int(m.group(2))))
            continue
        m = re.match(r"^Job (\S+): (.+?) realtime \((\d+) times\)", t)
        if m:
            st["job_sec"] = st.get("job_sec", 0) + (parse_dur(m.group(2)) or 0)
            st["job_count"] = st.get("job_count", 0) + int(m.group(3))
            continue
        m = re.match(r"^Sensor (\S+): (.+?) realtime \((\d+) times\)(?:, (.+?) background \((\d+) times\))?", t)
        if m:
            st.setdefault("sensors", {})[m.group(1)] = (parse_dur(m.group(2)), int(m.group(3)),
                                                         parse_dur(m.group(4)) if m.group(4) else None)
            continue
        m = re.match(r"^(Camera|Audio|Video|Flashlight|Foreground activities|Foreground services): (.+?) realtime \((\d+) times\)", t)
        if m:
            st[m.group(1).lower()] = (parse_dur(m.group(2)), int(m.group(3)), i + 1)
            continue
        m = re.match(r"^(Top|Fg Service|Foreground|Background|Cached|Top Sleeping|Heavy Weight) for: (.+)$", t)
        if m:
            st["state_" + m.group(1).lower().replace(" ", "_")] = parse_dur(m.group(2))
            continue
        m = re.match(r"^Total running: (.+)$", t)
        if m:
            st["running"] = parse_dur(m.group(1))
            continue
        m = re.match(r"^Total cpu time: u=(.+?) s=(.+?)(?:\s+p=.*)?$", t)
        if m:
            st["cpu"] = (parse_dur(m.group(1)) or 0) + (parse_dur(m.group(2)) or 0)
            continue
        m = re.match(r"^(Mobile|Wi-Fi) network: (\S+) received, (\S+) sent", t)
        if m:
            k = "mobile" if m.group(1) == "Mobile" else "wifi"
            st[k + "_rx"], st[k + "_tx"] = parse_size(m.group(2)), parse_size(m.group(3))
            continue
        m = re.match(r"^Mobile radio active: (.+?) \(", t)
        if m:
            st["mobile_radio"] = parse_dur(m.group(1))
