"""cli.py - the single entry point: `stalkeraware.py <command> ...` runs each pass as a module.

Commands
  stalkerware        stalkerware footprint (bug report)
  wireless           cellular, Wi-Fi, Bluetooth (bug report)
  battery            discharge, wakelocks, alarms, jobs, location (bug report)
  camera-microphone  camera and microphone use (bug report)
  snapshot           record a state snapshot of a bug report
  compare            compare two snapshots
  intrusion-logs     intrusion-log pass
  mitm               man-in-the-middle signs (bug report, intrusion logs, Chrome NetLog)
  correlate          do logged events cluster around times you noticed something?
  all                extract a bug report once and run every bug-report pass on it (plus intrusion-logs,
                     compare and mitm when given)
  versions           print each module's version and hash

`stalkeraware.py <command> -h` shows that command's options.
"""
import argparse
import importlib
import json
import os
import sys
import traceback
from datetime import datetime, timezone

from .common import Report, locate_main_txt, safe_extract, sha256_file, toolkit_sha256

COMMANDS = {
    "stalkerware": ("swpass", None, "stalkerware footprint (bug report)"),
    "wireless": ("rfpass", None, "cellular, Wi-Fi, Bluetooth (bug report)"),
    "battery": ("batpass", None, "discharge, wakelocks, alarms, jobs, location (bug report)"),
    "camera-microphone": ("micpass", None, "camera and microphone use (bug report)"),
    "snapshot": ("snapdiff", "snapshot", "record a state snapshot of a bug report"),
    "compare": ("snapdiff", "compare", "compare two snapshots"),
    "intrusion-logs": ("ilpass", None, "intrusion logs"),
    "mitm": ("mitm", None, "man-in-the-middle signs"),
    "correlate": ("corr", None, "incident correlation"),
}
# earlier short names, still accepted (not listed)
ALIASES = {"sw": "stalkerware", "rf": "wireless", "bat": "battery", "micam": "camera-microphone", "snap": "snapshot",
           "diff": "compare", "il": "intrusion-logs", "corr": "correlate"}


def run(cmd, argv):
    """Run one command in-process. Returns (status, message)."""
    mod, sub, _ = COMMANDS[cmd]
    m = importlib.import_module(f"{__package__}.{mod}")
    prog = f"stalkeraware.py {cmd}"
    if sub:   # snapdiff has its own snap/diff subcommands; show the new names in its usage line
        m.main([sub] + list(argv), prog="stalkeraware.py")
    else:
        m.main(list(argv), prog=prog)


def safe_run(cmd, argv, log):
    try:
        run(cmd, argv)
        log.append((cmd, "ok", ""))
    except SystemExit as ex:
        code = ex.code
        log.append((cmd, "ok" if code in (None, 0) else "stopped", "" if code in (None, 0) else str(code)))
    except Exception as ex:  # one pass failing must not stop the others
        tb = traceback.format_exc(limit=4).strip().splitlines()
        log.append((cmd, "error", f"{type(ex).__name__}: {ex} | {' / '.join(x.strip() for x in tb[-3:])}"))


def cmd_all(argv):
    ap = argparse.ArgumentParser(prog="stalkeraware.py all", description="Extract a bug report once and run every "
                                 "bug-report pass on it: stalkerware, wireless, battery, camera-microphone, snapshot, "
                                 "mitm (+ compare and intrusion-logs when given).")
    ap.add_argument("bugreport", help="bug report .zip (or an extracted folder / bugreport-*.txt)")
    ap.add_argument("--out", required=True, help="new output folder (must not exist); each pass gets a subfolder")
    ap.add_argument("--event", action="append", default=[], help='"YYYY-MM-DDTHH:MM:SS|label" (repeatable)')
    ap.add_argument("--intrusion-logs", dest="il", metavar="EXPORT", help="intrusion-log export (.zip or folder); also fed to mitm")
    ap.add_argument("--il", dest="il", help=argparse.SUPPRESS)
    ap.add_argument("--netlog", help="Chrome NetLog JSON for mitm")
    ap.add_argument("--prev-state", help="earlier snapshot JSON to diff this report against")
    ap.add_argument("--iocs", action="append", default=[], help="indicator folder for intrusion-logs (repeatable)")
    a = ap.parse_args(argv)
    if os.path.exists(a.out):
        sys.exit(f"--out {a.out} already exists; choose a new folder so earlier results are never overwritten")
    os.makedirs(a.out)
    man = {"tool": "stalkeraware.py all", "toolkit_sha256": toolkit_sha256(), "python": sys.version.split()[0],
           "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "input": os.path.abspath(a.bugreport),
           "args": vars(a), "steps": []}
    problems = []
    src = a.bugreport
    if os.path.isfile(src) and src.lower().endswith(".zip"):
        print(f"hashing and extracting {src} ...")
        man["input_sha256"] = sha256_file(src)
        folder = os.path.join(a.out, "extracted")
        man["members"] = safe_extract(src, folder, problems)
        main_txt = locate_main_txt(folder)
    elif os.path.isdir(src):
        main_txt = locate_main_txt(src)
    else:
        main_txt = src
    if not main_txt:
        sys.exit("could not find the main bugreport-*.txt")
    man["main_txt"] = main_txt
    ev = sum((["--event", e] for e in a.event), [])
    o = lambda n: os.path.join(a.out, n)
    log = []
    steps = [("stalkerware", [main_txt, "--out", o("stalkerware")]),
             ("wireless", [main_txt, "--out", o("wireless")] + ev),
             ("battery", [main_txt, "--out", o("battery")] + ev),
             ("camera-microphone", [main_txt, "--out", o("camera-microphone")] + ev),
             ("snapshot", [main_txt, "-o", o("state.json")])]
    if a.prev_state:
        steps.append(("compare", [a.prev_state, o("state.json"), "-o", o("compare")]))
    if a.il:
        steps.append(("intrusion-logs", [a.il, "--out", o("intrusion-logs")] + ev
                      + sum((["--iocs", x] for x in a.iocs), [])))
    mitm_args = ["--bugreport", main_txt, "--out", o("mitm")]
    if a.il:
        mitm_args += ["--intrusion-logs", o("intrusion-logs")]
    if a.netlog:
        mitm_args += ["--netlog", a.netlog]
    steps.append(("mitm", mitm_args))
    for cmd, args in steps:
        print(f"\n== {cmd} ==", flush=True)
        if cmd == "mitm" and a.il and not os.path.isdir(o("intrusion-logs")):
            mitm_args.remove("--intrusion-logs")
            mitm_args.remove(o("intrusion-logs"))
        safe_run(cmd, args, log)
    man["steps"] = [{"command": c, "status": s, "detail": d} for c, s, d in log]
    man["problems"] = problems
    R = Report()
    R.p("# stalkeraware run")
    R.p(f"Input `{os.path.basename(a.bugreport)}`" + (f" (SHA-256 `{man['input_sha256']}`)" if "input_sha256" in man else "")
        + f"; main text `{os.path.basename(main_txt)}`. Toolkit SHA-256 `{man['toolkit_sha256']}`, run {man['run_utc']} UTC.")
    rows = []
    for c, s, d in log:
        rep = {"snapshot": "state.json"}.get(c, f"{c}/report.md")
        rows.append((c, COMMANDS[c][2], s, rep if os.path.exists(o(rep)) else "-", d[:200]))
    R.table(["command", "what", "status", "report", "detail"], rows)
    R.p("Each report starts with an \"At a glance\" table. Problems: " + ("; ".join(problems) if problems else "none") + ".")
    with open(o("run.md"), "w") as fh:
        fh.write(R.text())
    with open(o("manifest.json"), "w") as fh:
        json.dump(man, fh, indent=1, default=str)
    print(f"\nsummary: {o('run.md')}")
    for c, s, d in log:
        print(f"  {c:18} {s}{(': ' + d) if d else ''}")


def cmd_versions():
    import glob
    print(f"toolkit {toolkit_sha256()}")
    for c, (mod, sub, what) in COMMANDS.items():
        if sub == "compare":
            continue
        m = importlib.import_module(f"{__package__}.{mod}")
        print(f"  {c:18} {mod + '.py':12} {getattr(m, 'VERSION', '?'):20} {sha256_file(m.__file__)[:16]}…")
    for p in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "*.py"))):
        n = os.path.basename(p)
        if n in ("common.py", "cli.py", "__init__.py"):
            print(f"  {'':18} {n:12} {'':20} {sha256_file(p)[:16]}…")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd, rest = argv[0], argv[1:]
    if cmd == "all":
        return cmd_all(rest)
    if cmd in ("versions", "--version"):
        return cmd_versions()
    cmd = ALIASES.get(cmd, cmd)
    if cmd not in COMMANDS:
        sys.exit(f"unknown command {cmd!r}; run without arguments for the list")
    run(cmd, rest)
