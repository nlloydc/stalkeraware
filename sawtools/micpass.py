#!/usr/bin/env python3
"""micpass.py - camera and microphone pass over an Android bug report (Python 3.9+ standard library only).

Reads every place a bug report records camera or microphone use, puts it on one timeline, and labels each use
with what was on screen at the time:

  1. sources          - which records were found and the span each covers
  2. camera sessions  - camera service's own open/close log (who opened which camera, from which process, when)
  3. mic sessions     - AudioService's recording log (who recorded, from which source: mic, voice call,
                        voice recognition, hotword, playback capture)
  4. battery history  - camera-on intervals (about a day), with the app on screen and the screen state
  5. app ops          - last mic/camera/screen-capture access and every *rejected* attempt, per app and state
  6. since charge     - camera / audio / video / flashlight time per app
  7. at capture       - foreground services typed camera or microphone, open camera clients, media projection
                        (screen capture), the mic/camera privacy toggles
  8. logcat           - CameraService connect/disconnect lines (short span)
  9. timeline         - everything above in time order; event windows around times you give (--event)

Android shows a green dot whenever an app uses the mic or camera, and from Android 11 an app in the background
can only do so from a foreground service with a visible notification. So the questions here are: who used them,
was it on screen, was the screen on, and is it the app you'd expect. A record outside a source's span can't be
judged from that source.

It never modifies its input. "Look closer" readings were fixed before results were viewed (PREREGISTERED.md).
Nothing here proves how anything was done.

Usage
  python3 -I stalkeraware.py camera-microphone <bugreport.zip | folder | bugreport-*.txt> --out <new folder>
                                               [--event "2026-01-15T22:10:00|heard a click"] [--before 300] [--after 120]
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

from .common import (BR, Ctx, Out, Report, app_state, appid_of, fmt_dur, fmt_t, is_google, open_input,
                     p_battery_history, p_identity, p_logcat_coverage, p_uidstats_full, parse_dur, parse_events, part,
                     pkg_is_google, r_identity, screen_at, sha256_file, toolkit_sha256, uid_of_pkg, uid_tag)

VERSION = "0.1.0 (2026-11-24)"

MIC_OPS = {"RECORD_AUDIO", "PHONE_CALL_MICROPHONE", "RECORD_AUDIO_HOTWORD", "RECEIVE_AMBIENT_TRIGGER_AUDIO",
           "RECORD_INCOMING_PHONE_AUDIO", "RECEIVE_SANDBOX_TRIGGER_AUDIO", "RECORD_AUDIO_SANDBOXED"}
CAM_OPS = {"CAMERA", "PHONE_CALL_CAMERA"}
CAPTURE_OPS = {"PROJECT_MEDIA", "RECORD_AUDIO_OUTPUT"}
ALL_OPS = MIC_OPS | CAM_OPS | CAPTURE_OPS
NOT_MIC_SOURCES = {"REMOTE_SUBMIX", "ECHO_REFERENCE", "RADIO_TUNER", "AUDIO_SOURCE_INVALID"}
FGS_BITS = {0x20: "mediaProjection", 0x40: "camera", 0x80: "microphone"}
ON_SCREEN = ("on screen", "being opened")

CAM_EV = re.compile(r"^\s*(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)(?:\.(\d{3}))? : (\w+) (.*)$")
REC_EV = re.compile(r"^\s*(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)[:.](\d{3}) .*?\brec (\w+) "
                    r"riid:(\d+) uid:(\d+) session:(-?\d+) src:(\S+)((?: (?:not )?silenced)?)(?: pack:(\S+))?")
LOGCAT = re.compile(r"^(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3})\s+(\d+)\s+(\d+)\s+\w\s+(\S+)\s*:\s?(.*)$")


def label_state(ctx, pkg=None, uid=None, t=None):
    """What the battery history says about the app at time t."""
    u = uid_tag(uid) if uid is not None else (uid_of_pkg(ctx, pkg) if pkg else None)
    if u is None or not ctx.bh or not ctx.bh.get("rows"):
        return "unknown"
    rows = ctx.bh["rows"]
    if t < rows[0]["t"] or t > rows[-1]["t"]:
        return "outside battery history"
    return app_state(ctx, u, t)


def classify(ctx, who_google, state, scr):
    """Pre-registered: look closer at a non-Google user that was neither on screen nor being opened,
    or any use (Google included) while the screen was off, except the ordinary exceptions noted per source."""
    if state.startswith(ON_SCREEN):
        bg = False
    else:
        bg = state not in ("unknown", "outside battery history")
    if not who_google and bg:
        return f"LOOK: not on screen ({state})"
    if scr == "off" and not who_google:
        return "LOOK: screen off"
    if scr == "off":
        return "note: screen off (Google/system)"
    return ""


# ---------------------------------------------------------------------------------------------- parsers

def p_camera_log(ctx):
    svc = ctx.br.service("media.camera")
    ctx.cam_ev, ctx.cam_clients = [], []
    if not svc:
        raise RuntimeError("dumpsys media.camera not found")
    L = ctx.br.L
    on = False
    for i in range(svc[0], svc[1] + 1):
        l = L[i]
        if "Camera service events log" in l or "== Camera service events log" in l:
            on = True
            continue
        if on and l.startswith("==") and "events log" not in l:
            on = False
        m = re.search(r"Client Package Name: ([\w.:]+)", l)
        if m:
            ctx.cam_clients.append((m.group(1), l.strip()[:200], i + 1))
        if not on:
            continue
        m = CAM_EV.match(l)
        if not m:
            continue
        mo, d, H, M, S, ms, kind, rest = m.groups()
        t = ctx.ytime(mo, d, H, M, S, ms or 0)
        dev = re.search(r"device (\S+)", rest)
        pkg = re.search(r"package (\S+?)(?:\s|$|,)", rest)
        pid = re.search(r"PID (\d+)", rest)
        ctx.cam_ev.append({"t": t, "kind": kind, "dev": dev.group(1) if dev else None,
                           "pkg": pkg.group(1) if pkg else None, "pid": pid.group(1) if pid else None,
                           "text": rest.strip(), "line": i + 1})
    ctx.cam_ev.sort(key=lambda e: (e["t"], -e["line"]))   # log is newest-first
    if ctx.cam_ev:
        ctx.coverage.append(("camera service events log", ctx.cam_ev[0]["t"], ctx.cam_ev[-1]["t"], len(ctx.cam_ev),
                             f"L{svc[0] + 1}-L{svc[1] + 1}"))
    # sessions: CONNECT ... DISCONNECT for the same device + pid
    open_, ses = {}, []
    for e in ctx.cam_ev:
        k = (e["dev"], e["pid"])
        if e["kind"] == "CONNECT":
            open_[k] = e
        elif e["kind"] in ("DISCONNECT", "EVICT") and k in open_:
            s = open_.pop(k)
            ses.append({"start": s["t"], "end": e["t"], "dev": s["dev"], "pkg": s["pkg"], "pid": s["pid"],
                        "how": e["kind"], "line": s["line"]})
        elif e["kind"] == "DISCONNECT":
            ses.append({"start": None, "end": e["t"], "dev": e["dev"], "pkg": e["pkg"], "pid": e["pid"],
                        "how": "DISCONNECT (open before the log starts)", "line": e["line"]})
    for k, s in open_.items():
        ses.append({"start": s["t"], "end": None, "dev": s["dev"], "pkg": s["pkg"], "pid": s["pid"],
                    "how": "still open at the end of the log", "line": s["line"]})
    ctx.cam_ses = sorted(ses, key=lambda s: s["start"] or s["end"])


def p_audio_rec(ctx):
    """AudioService's recording monitor. Older builds log start/stop/release; Android 17 logs only 'update' for
    each active recorder (riid), so a session is the span between the first and last record of a riid. The same
    lines also appear in logcat (tag AudioSvc.RecMon), which can reach further back or forward than the dump."""
    ctx.rec_ev = []
    svc = ctx.br.service("audio")
    if not svc:
        raise RuntimeError("dumpsys audio not found")
    L = ctx.br.L
    ranges = [("dumpsys audio", range(svc[0], svc[1] + 1))]
    for title in ("SYSTEM LOG", "LAST LOGCAT"):
        sec = ctx.br.section(title)
        if sec:
            ranges.append((title, range(sec[0], sec[1] + 1)))
    seen = set()
    per_src = {}
    for src_name, rng in ranges:
        for i in rng:
            l = L[i]
            if "rec " not in l or "riid:" not in l:
                continue
            m = REC_EV.match(l)
            if not m:
                continue
            mo, d, H, M, S, ms, ev, riid, uid, sess, src, sil, pack = m.groups()
            key = (mo, d, H, M, S, ms[:2], ev, riid)      # same record in dump and logcat: drop the copy
            if key in seen:
                continue
            seen.add(key)
            t = ctx.ytime(mo, d, H, M, S, ms)
            ctx.rec_ev.append({"t": t, "ev": ev, "riid": riid, "uid": int(uid), "session": sess, "src": src,
                               "silenced": sil.strip() == "silenced", "pkg": pack, "line": i + 1, "from": src_name})
            f = per_src.setdefault(src_name, [t, t, 0, i])
            f[0], f[1], f[2] = min(f[0], t), max(f[1], t), f[2] + 1
    ctx.rec_ev.sort(key=lambda e: e["t"])
    for name, (a, z, n, i) in per_src.items():
        ctx.coverage.append((f"audio recording records ({name})", a, z, n, f"from L{i + 1}"))
    by = {}
    for e in ctx.rec_ev:
        by.setdefault(e["riid"], []).append(e)
    ses = []
    for riid, evs in by.items():
        first, last = evs[0], evs[-1]
        kinds = {e["ev"] for e in evs}
        ended = last["ev"] in ("stop", "release")
        ses.append({"start": first["t"], "end": last["t"] if (ended or len(evs) > 1) else None,
                    "how": ("start/stop logged" if "start" in kinds and ended else
                            f"{len(evs)} record(s): {', '.join(sorted(kinds))}"),
                    "silenced": any(e["silenced"] for e in evs), "uid": first["uid"], "src": first["src"],
                    "pkg": first["pkg"], "line": first["line"], "riid": riid})
    ctx.rec_ses = sorted(ses, key=lambda s: s["start"])


def p_appops(ctx):
    svc = ctx.br.service("appops")
    ctx.ops, ctx.ops_running = [], []
    if not svc:
        raise RuntimeError("dumpsys appops not found")
    L = ctx.br.L
    pkg = op = mode = None
    for i in range(svc[0], svc[1] + 1):
        l = L[i]
        m = re.match(r"^    Package (\S+):", l)
        if m:
            pkg, op = m.group(1), None
            continue
        m = re.match(r"^      ([A-Z_0-9]+) \((\w+)(?: / [^)]*)?\):", l)
        if m:
            op, mode = m.group(1), m.group(2)
            continue
        if not pkg or op not in ALL_OPS:
            continue
        m = re.match(r"^\s+(Access|Reject): \[([\w-]+)\] (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+).*?"
                     r"(?:\(?duration=\+?([^)\s]+)\)?)?\s*$", l)
        if m:
            t = datetime.strptime(m.group(3)[:23], "%Y-%m-%d %H:%M:%S.%f")
            ctx.ops.append({"pkg": pkg, "op": op, "mode": mode, "kind": m.group(1), "state": m.group(2), "t": t,
                            "dur": parse_dur(m.group(4)) if m.group(4) else None, "line": i + 1})
            continue
        if "Running" in l or "running" in l.split("=")[0]:
            ctx.ops_running.append((pkg, op, l.strip()[:160], i + 1))


def p_at_capture(ctx):
    L = ctx.br.L
    ctx.fgs = []
    # foreground services with camera / microphone / mediaProjection types
    sec = ctx.br.section("DUMPSYS ACTIVITY SERVICES") or ctx.br.section("ACTIVITY MANAGER SERVICES")
    rng = range(sec[0], sec[1] + 1) if sec else range(len(L))
    cur = None
    for i in rng:
        l = L[i]
        m = re.match(r"^\s+\* ServiceRecord\{\w+ u\d+ ([\w.]+)/([\w.$]+)", l)
        if m:
            cur = {"pkg": m.group(1), "cls": m.group(2), "line": i + 1, "fg": False, "types": 0}
            continue
        if cur is None:
            continue
        if "isForeground=true" in l:
            cur["fg"] = True
        m = re.search(r"(?:foregroundServiceType|types)=0x([0-9a-fA-F]+)", l)
        if m:
            cur["types"] |= int(m.group(1), 16)
        if cur["fg"] and cur["types"] & 0xE0 and cur not in ctx.fgs:
            ctx.fgs.append(cur)
    ctx.projection = []
    svc = ctx.br.service("media_projection")
    if svc:
        ctx.projection = [(L[i].strip()[:200], i + 1) for i in range(svc[0] + 1, svc[1]) if L[i].strip()
                          and not L[i].startswith("---")][:25]
    ctx.privacy = []
    svc = ctx.br.service("sensor_privacy")
    if svc:
        ctx.privacy = [(L[i].strip()[:200], i + 1) for i in range(svc[0] + 1, svc[1])
                       if re.search(r"(?i)microphone|camera|enabled|state|toggle", L[i])][:30]


def p_logcat_camera(ctx):
    ctx.lc = []
    for title in ("SYSTEM LOG", "LAST LOGCAT"):
        sec = ctx.br.section(title)
        if not sec:
            continue
        L = ctx.br.L
        for i in range(sec[0], sec[1] + 1):
            l = L[i]
            if "CameraService" not in l and "PrivacyLog" not in l and "CameraManagerGlobal" not in l:
                continue
            m = LOGCAT.match(l)
            if not m:
                continue
            msg = m.group(10)
            if ("connect call" in msg or "disconnect" in msg.lower() or "Opened" in msg or "PrivacyLog" in m.group(9)
                    or "PrivacyLog" in msg or "CameraManagerGlobal" in m.group(9)):
                ctx.lc.append({"t": ctx.ytime(*m.groups()[:6]), "pid": m.group(7), "tag": m.group(9),
                               "msg": msg.strip()[:200], "line": i + 1, "src": title})


# ---------------------------------------------------------------------------------------------- report

def r_sources(ctx):
    rep = ctx.rep
    rep.h(2, "2. Sources and what each covers")
    rows = [(s, fmt_t(a), fmt_t(z), fmt_dur((z - a).total_seconds()) if a and z else "-", n, ref)
            for s, a, z, n, ref in sorted(ctx.coverage, key=lambda x: (x[1] or datetime.min))]
    rep.table(["source", "first", "last", "span", "entries", "ref"], rows)
    rep.p("The camera service keeps its last 100 or so events and the audio recording log its last 50, so on a busy "
          "phone they may reach back only hours. Battery history (about a day) only says *that* the camera was on; "
          "app ops keep only the last use per app and state, with no history before it.")


def r_camera(ctx):
    rep = ctx.rep
    rep.h(2, "3. Camera sessions (camera service log)")
    rep.p("Look closer: a session by a non-Google app that was neither on screen nor being opened, or any non-Google "
          "session with the screen off. Ordinary: the camera app, video calls, QR/payment scanners while open, "
          "Face Unlock (a system client, screen just woken), Android System Intelligence (`com.google.android.as`) "
          "taking a ~1 s front-camera look for auto-rotate or screen attention while the screen is on, the flashlight "
          "(shows as a torch, not a session).")
    rows = []
    for s in ctx.cam_ses:
        t = s["start"] or s["end"]
        g = is_google(s["pkg"] or "")
        stt, scr = label_state(ctx, pkg=s["pkg"], t=t), screen_at(ctx, t)
        fl = classify(ctx, g, stt, scr)
        s.update(state=stt, screen=scr, flag=fl)
        rows.append((fmt_t(s["start"]), fmt_t(s["end"], False) if s["end"] else "-",
                     fmt_dur((s["end"] - s["start"]).total_seconds()) if s["start"] and s["end"] else "-",
                     s["dev"], s["pkg"], s["pid"], stt, scr, s["how"], fl, f"L{s['line']}"))
    rep.table(["open", "close", "length", "camera", "package", "PID", "app state", "screen", "closed by", "", "ref"],
              rows, limit=120, more="data/camera_sessions.csv")
    ctx.out.csv("camera_sessions.csv", ["start", "end", "camera", "package", "pid", "app_state", "screen", "closed_by",
                                        "flag", "line"],
                [(s["start"].isoformat() if s["start"] else "", s["end"].isoformat() if s["end"] else "", s["dev"],
                  s["pkg"], s["pid"], s["state"], s["screen"], s["how"], s["flag"], s["line"]) for s in ctx.cam_ses])
    other = [e for e in ctx.cam_ev if e["kind"] not in ("CONNECT", "DISCONNECT")]
    if other:
        rep.p("Other camera service events (evictions, rejections, user switches, torch):")
        rep.table(["time", "event", "detail", "ref"], [(fmt_t(e["t"]), e["kind"], e["text"][:140], f"L{e['line']}")
                                                       for e in other], limit=60)
    if ctx.cam_clients:
        rep.p("Camera clients listed as open at capture: " + "; ".join(f"{p} (L{ln})" for p, _, ln in ctx.cam_clients))
    else:
        rep.p("Camera clients listed as open at capture: none.")


def r_mic(ctx):
    rep = ctx.rep
    rep.h(2, "4. Recording sessions (AudioService recording log)")
    rep.p("Source MIC / CAMCORDER / VOICE_RECOGNITION / VOICE_COMMUNICATION / UNPROCESSED / VOICE_PERFORMANCE use "
          "the microphone; HOTWORD is the always-on wake-word path; REMOTE_SUBMIX captures what the phone is playing, "
          "not the mic. Look closer: a non-Google app recording from a mic source while neither on screen nor being "
          "opened, or with the screen off. Ordinary: calls and voice notes, voice typing, the assistant and \"Now "
          "Playing\" (Google, hotword path), apps you were using.")
    rows = []
    for s in ctx.rec_ses:
        pkg = s["pkg"] or ", ".join(ctx.uidpkg.get(appid_of(s["uid"]), []) or [str(s["uid"])])
        g = pkg_is_google(ctx, uid=s["uid"], pkg=s["pkg"])
        stt = label_state(ctx, pkg=s["pkg"], t=s["start"]) if s["pkg"] else label_state(ctx, uid=s["uid"], t=s["start"])
        scr = screen_at(ctx, s["start"])
        mic = s["src"] not in NOT_MIC_SOURCES
        fl = classify(ctx, g, stt, scr) if mic else ""
        s.update(name=pkg, state=stt, screen=scr, flag=fl, mic=mic)
        rows.append((fmt_t(s["start"]), fmt_t(s["end"], False) if s["end"] else "-",
                     fmt_dur((s["end"] - s["start"]).total_seconds()) if s["end"] else "-", pkg[:60], s["src"],
                     "mic" if mic else "not mic", "silenced" if s["silenced"] else "", s["how"], stt, scr, fl,
                     f"L{s['line']}"))
    rep.p("Where the build logs only updates, first/last are the first and last time the recorder was seen active; "
          "it may have started earlier and run later. \"silenced\" means Android was feeding it silence (e.g. a "
          "background app or the mic toggle on).")
    rep.table(["first seen", "last seen", "span", "app", "source", "", "", "records", "app state", "screen", "",
               "ref"], rows, limit=150,
              more="data/mic_sessions.csv")
    ctx.out.csv("mic_sessions.csv", ["start", "end", "uid", "app", "source", "mic", "app_state", "screen", "flag",
                                     "line"],
                [(s["start"].isoformat(), s["end"].isoformat() if s["end"] else "", s["uid"], s["name"], s["src"],
                  s["mic"], s["state"], s["screen"], s["flag"], s["line"]) for s in ctx.rec_ses])
    if not ctx.rec_ev:
        rep.p("**No recording events parsed.** Either nothing recorded in the log's span or this build prints the "
              "log differently; search the `dumpsys audio` section for \"recording activity\" by hand.")


def r_history(ctx):
    rep = ctx.rep
    rep.h(2, "5. Camera on, from battery history")
    iv, cur = [], None
    for e in ctx.bh["events"]:
        if e[2] == "+camera":
            if e[4] and cur is None:
                cur = (e[0], e[1])
            elif not e[4] and cur is not None:
                iv.append((cur[0], e[0], cur[1]))
                cur = None
    if cur and ctx.bh["rows"]:
        iv.append((cur[0], ctx.bh["rows"][-1]["t"], cur[1]))
    tops = [(t, uid) for t, ln, sign, key, uid, val in ctx.bh["app"] if key == "top" and sign == "+"]
    rows = []
    ctx.cam_hist = []
    for a, b, ln in iv:
        prior = [u for t, u in tops if t <= a]
        on = []
        for uid in {u for t, u in tops}:
            if app_state(ctx, uid, a).startswith(ON_SCREEN):
                on.append(ctx.uidname(uid))
        scr = screen_at(ctx, a)
        any_ses = any(s["start"] and s["start"] - timedelta(seconds=2) <= a <= (s["end"] or a) + timedelta(seconds=2)
                      for s in ctx.cam_ses)
        fl = "LOOK: screen off" if scr == "off" else ("note: nothing on screen" if not on else "")
        ctx.cam_hist.append({"start": a, "end": b, "on_screen": on, "screen": scr, "flag": fl, "line": ln})
        rows.append((fmt_t(a), fmt_t(b, False), fmt_dur((b - a).total_seconds()), ", ".join(on) or "-",
                     ctx.uidname(prior[-1]) if prior else "-", scr,
                     "yes" if any_ses else ("outside log" if not ctx.cam_ev or a < ctx.cam_ev[0]["t"] else "no"),
                     fl, f"L{ln}"))
    rep.p("The history doesn't name the camera's user; this lists what was on screen when it turned on. Look closer: "
          "camera on with the screen off. Face Unlock runs while the screen is waking and can log as off for an "
          "instant; check those against an unlock right after.")
    rep.table(["on", "off", "length", "on screen then", "last app brought on screen before", "screen", "in camera log", "", "ref"],
              rows, limit=120)


def r_appops(ctx):
    rep = ctx.rep
    rep.h(2, "6. App ops: last use and rejected attempts")
    rep.p("States: top = on screen, fgsvc = foreground service, fg = foreground, bg = background, cch = cached. "
          "Look closer: a non-Google app with an Access in bg/cch (or fgsvc you didn't start), or any Reject of mic/"
          "camera by a non-Google app (it tried and was refused, e.g. from the background or with a toggle off).")
    ops = sorted(ctx.ops, key=lambda o: (is_google(o["pkg"]), o["pkg"], o["op"], o["t"]))
    rows, flags = [], []
    for o in ops:
        g = is_google(o["pkg"])
        fl = ""
        if not g and o["op"] in MIC_OPS | CAM_OPS:
            if o["kind"] == "Reject":
                fl = "LOOK: rejected attempt"
            elif o["state"].startswith(("bg", "cch")):
                fl = "LOOK: background"
            elif o["state"].startswith("fgsvc"):
                fl = "check: foreground service; did you start it?"
        if fl.startswith("LOOK"):
            flags.append(o)
        rows.append((o["pkg"], o["op"], o["mode"], o["kind"], o["state"], fmt_t(o["t"]), fmt_dur(o["dur"]),
                     screen_at(ctx, o["t"]), fl, f"L{o['line']}"))
    ctx.ops_flags = flags
    rep.table(["package", "op", "mode", "", "state", "time", "duration", "screen", "", "ref"], rows, limit=150,
              more="data/appops.csv")
    ctx.out.csv("appops.csv", ["package", "op", "mode", "kind", "state", "time", "duration_s", "line"],
                [(o["pkg"], o["op"], o["mode"], o["kind"], o["state"], o["t"].isoformat(), o["dur"], o["line"])
                 for o in ops])
    if ctx.ops_running:
        rep.p("Ops marked running at capture:")
        rep.table(["package", "op", "line text", "ref"], [(p, o, s, f"L{ln}") for p, o, s, ln in ctx.ops_running])
    if not ctx.ops:
        rep.p("**problem:** no mic/camera app-op entries parsed; check `dumpsys appops` by hand.")


def r_since_charge(ctx):
    rep = ctx.rep
    rep.h(2, "7. Camera, audio, video and flashlight time per app (since charge)")
    rows = []
    for uid, st in getattr(ctx, "uidfull", {}).items():
        vals = {k: st.get(k) for k in ("camera", "audio", "video", "flashlight")}
        if any(vals.values()):
            rows.append((ctx.uidname(uid), *[f"{fmt_dur(v[0])} ({v[1]}x)" if v else "-" for v in vals.values()],
                         "" if pkg_is_google(ctx, uid=uid) else "non-Google", f"L{st['line']}"))
    rows.sort(key=lambda r: (r[5] == "", r[0]))
    rep.p("Audio here is mostly playback; recording is in sections 4 and 6. Look closer: camera time for a non-Google "
          "app you don't use the camera in.")
    rep.table(["app", "camera", "audio", "video", "flashlight", "", "ref"], rows)


def r_capture(ctx):
    rep = ctx.rep
    rep.h(2, "8. State at capture")
    rows = [(f["pkg"], f["cls"], ", ".join(n for b, n in FGS_BITS.items() if f["types"] & b), f"0x{f['types']:x}",
             "" if is_google(f["pkg"]) else "non-Google", f"L{f['line']}") for f in ctx.fgs]
    rep.p("Foreground services running with a camera, microphone or screen-capture type (each shows a notification):")
    rep.table(["package", "service", "types", "raw", "", "ref"], rows)
    rep.p("Screen capture / casting (`dumpsys media_projection`):")
    rep.table(["line", "ref"], [(s, f"L{ln}") for s, ln in ctx.projection])
    rep.p("Mic and camera privacy toggles (`dumpsys sensor_privacy`; enabled = access blocked):")
    rep.table(["line", "ref"], [(s, f"L{ln}") for s, ln in ctx.privacy])


def r_logcat(ctx):
    rep = ctx.rep
    rep.h(2, "9. Logcat lines (CameraService, privacy indicator)")
    rep.table(["time", "PID", "tag", "message", "ref"],
              [(fmt_t(x["t"]), x["pid"], x["tag"], x["msg"][:150], f"L{x['line']}") for x in ctx.lc], limit=80)


def timeline(ctx):
    ev = []
    for s in ctx.cam_ses:
        if s["start"]:
            ev.append((s["start"], "camera", f"open cam {s['dev']} {s['pkg']} pid {s['pid']} [{s.get('state')}; screen {s.get('screen')}]", s.get("flag", ""), f"L{s['line']}"))
        if s["end"]:
            ev.append((s["end"], "camera", f"close cam {s['dev']} {s['pkg']}", "", f"L{s['line']}"))
    for s in ctx.rec_ses:
        ev.append((s["start"], "mic" if s.get("mic") else "capture", f"rec start {s.get('name')} src {s['src']} [{s.get('state')}; screen {s.get('screen')}]",
                   s.get("flag", ""), f"L{s['line']}"))
        if s["end"]:
            ev.append((s["end"], "mic" if s.get("mic") else "capture", f"rec stop {s.get('name')}", "", f"L{s['line']}"))
    for h in getattr(ctx, "cam_hist", []):
        ev.append((h["start"], "battery", f"camera on; on screen: {', '.join(h['on_screen']) or '-'}", h["flag"], f"L{h['line']}"))
    for o in ctx.ops:
        ev.append((o["t"], "appops", f"{o['kind']} {o['op']} {o['pkg']} [{o['state']}] {fmt_dur(o['dur'])}", "", f"L{o['line']}"))
    for x in ctx.lc:
        ev.append((x["t"], "logcat", f"{x['tag']}: {x['msg'][:120]}", "", f"L{x['line']}"))
    ev.sort(key=lambda e: e[0])
    return ev


def r_timeline(ctx):
    rep = ctx.rep
    ev = timeline(ctx)
    ctx.out.csv("timeline.csv", ["time", "source", "event", "flag", "ref"], [(t.isoformat(), *r) for t, *r in ev])
    ctx.out.jsonl("micam_events.jsonl", ({"t": t.isoformat(timespec="milliseconds"), "source": s, "event": e,
                                          "flag": f} for t, s, e, f, r in ev))
    rep.h(2, "10. Timeline and event windows")
    rep.p(f"All {len(ev)} records in time order are in `data/timeline.csv`.")
    bef, aft = timedelta(seconds=ctx.args.before), timedelta(seconds=ctx.args.after)
    for t0, label in ctx.events:
        a, b = t0 - bef, t0 + aft
        rep.h(3, f"{label} - {t0} (window {fmt_t(a)} -> {fmt_t(b, False)})")
        cov = [f"{s}: {'covers' if f <= a and l >= b else ('partly' if l >= a and f <= b else 'NO')}"
               for s, f, l, n, ref in ctx.coverage if f and l]
        rep.p("Coverage: " + "; ".join(cov))
        w = [(fmt_t(t), s, e, f, r) for t, s, e, f, r in ev if a <= t <= b]
        for e in ctx.bh["events"]:
            if a <= e[0] <= b and e[2] in ("+screen", "+camera", "+audio", "+video", "+flashlight"):
                w.append((fmt_t(e[0]), "battery", f"{e[2]} {e[3]} -> {e[4]}", "", f"L{e[1]}"))
        for t, ln, sign, key, uid, val in ctx.bh["app"]:
            if a <= t <= b and key in ("top", "fg"):
                w.append((fmt_t(t), "app", f"{sign}{key} {ctx.uidname(uid)}", "", f"L{ln}"))
        w.sort(key=lambda x: x[0])
        rep.table(["time", "source", "event", "", "ref"], w, limit=250)


def r_glance(ctx):
    rows = []
    cl = [s for s in ctx.cam_ses if s.get("flag", "").startswith("LOOK")]
    rows.append(("Camera sessions meeting a look-closer rule", f"{len(cl)} of {len(ctx.cam_ses)}" + (
        " (" + "; ".join(f"{s['pkg']} {fmt_t(s['start'])}" for s in cl[:4]) + ")" if cl else ""), "section 3"))
    ml = [s for s in ctx.rec_ses if s.get("flag", "").startswith("LOOK")]
    rows.append(("Mic sessions meeting a look-closer rule", f"{len(ml)} of {len(ctx.rec_ses)}" + (
        " (" + "; ".join(f"{s['name']} {fmt_t(s['start'])}" for s in ml[:4]) + ")" if ml else ""), "section 4"))
    hl = [h for h in getattr(ctx, "cam_hist", []) if h["flag"].startswith("LOOK")]
    rows.append(("Camera on with screen off (battery history)", f"{len(hl)} of {len(getattr(ctx, 'cam_hist', []))}",
                 "section 5"))
    of = getattr(ctx, "ops_flags", [])
    rows.append(("Non-Google background or rejected mic/camera app ops",
                 ", ".join(sorted({f"{o['pkg']} {o['op']} {o['kind']} [{o['state']}]" for o in of}))[:300] or "none",
                 "section 6"))
    rows.append(("Mic/camera foreground services running at capture",
                 ", ".join(f["pkg"] for f in ctx.fgs) or "none", "section 8"))
    rows.append(("Camera clients open at capture", ", ".join(p for p, _, _ in ctx.cam_clients) or "none", "section 3"))
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
    ap.add_argument("--before", type=float, default=300.0)
    ap.add_argument("--after", type=float, default=120.0)
    args = ap.parse_args(argv)
    if os.path.exists(args.out):
        sys.exit(f"--out {args.out} already exists; choose a new folder so earlier results are never overwritten")
    os.makedirs(args.out)
    ctx = Ctx(args)
    ctx.out = Out(args.out)
    rep = ctx.rep
    man = {"tool": "micpass.py", "version": VERSION, "tool_sha256": sha256_file(os.path.abspath(__file__)),
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
    ctx.cam_ev, ctx.cam_ses, ctx.cam_clients, ctx.rec_ev, ctx.rec_ses = [], [], [], [], []
    ctx.ops, ctx.ops_running, ctx.fgs, ctx.projection, ctx.privacy, ctx.lc = [], [], [], [], [], []
    for name, fn in (("logcat coverage", p_logcat_coverage), ("battery history", p_battery_history),
                     ("camera service log", p_camera_log), ("audio recording log", p_audio_rec),
                     ("app ops", p_appops), ("state at capture", p_at_capture), ("logcat camera", p_logcat_camera),
                     ("batterystats per-uid", p_uidstats_full)):
        part(ctx, name, fn)
    if ctx.bh is None:
        ctx.bh = {"rows": [], "events": [], "app": [], "range": (0, 0), "mismatch": 0, "markers": []}
    rep.p("# Camera and microphone pass\n")
    rep.p(f"Input `{os.path.basename(args.input)}`" + (f" (SHA-256 `{man['input_sha256']}`)" if man.get("input_sha256") else "")
          + f"; main text `{os.path.basename(main_txt)}` (SHA-256 `{man['main_txt_sha256']}`). micpass.py {VERSION} "
          f"(toolkit SHA-256 `{man['toolkit_sha256'][:16]}…`), run {man['run_utc']} UTC. Line numbers (L…) refer to "
          "the main text file. Times are device local time.")
    for name, fn in (("identity report", r_identity), ("sources", r_sources), ("camera", r_camera), ("mic", r_mic),
                     ("battery history camera", r_history), ("app ops", r_appops),
                     ("since charge", r_since_charge), ("at capture", r_capture), ("logcat", r_logcat),
                     ("timeline", r_timeline), ("at a glance", r_glance)):
        part(ctx, name, fn)
    rep.h(2, "11. Run notes")
    rep.bullets([f"micpass.py {VERSION}; Python {man['python']}"] + [f"problem: {p}" for p in rep.problems]
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
