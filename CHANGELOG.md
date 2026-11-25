# Changelog

## 2026-11-24 — one program, battery and camera/microphone passes
- `stalkeraware.py <command>` is now the single entry point; the tools are modules in `sawtools/`. Commands: `stalkerware`, `wireless`, `battery`, `camera-microphone`, `snapshot`, `compare`, `intrusion-logs`, `mitm`, `correlate`, `all`, `versions`; options spelled out (`--bugreport`, `--intrusion-logs`, `--wireless`). The short names (`sw`, `rf`, `il`, `--br`, …) are still accepted. `all` extracts a bug report once and runs every bug-report pass on it (plus `intrusion-logs`, `compare` and `mitm` when given), writing `run.md` and a manifest.
- `sawtools/common.py`: bug-report plumbing moved verbatim from `rfpass.py` (input handling, section index, report writers, identity, battery history), plus helpers for the new passes. Manifests now also carry a toolkit hash over the whole package.
- New `batpass.py` 0.1.0 (`battery`) and `micpass.py` 0.1.0 (`camera-microphone`); look-closer rules added to `PREREGISTERED.md` before any real run, with a dated amendment after the first. Fixes from that run (Pixel, Android 17): recording log has only `update` records (sessions = first to last record per recorder, read from both `dumpsys audio` and logcat); camera log is newest-first (same-second events were paired backwards); `longwake` is stamped one minute after the wakelock was taken; location history is `uid/package[tag]` under bare provider names; per-UID power lines carry a duration after each state.
- `rfpass.py` 1.1.0: imports the shared plumbing; output unchanged. `swpass.py`, `snapdiff.py`, `mitm.py`, `ilpass.py`, `corr.py`: callable as modules; output unchanged (checked against the previous versions on the synthetic report). Run commands change from `python3 -I rfpass.py …` to `python3 -I stalkeraware.py wireless …`.
- `tests/selftest.py` + `tests/fixture.py`: synthetic bug report with planted positive and negative cases.

## 2026-11-24 — rename
- `bra.py` renamed `rfpass.py` (1.0.2; name only). `corr.py` 0.1.1 takes `--rf` for its output folders (`--bra` still accepted).

## 2026-11-24 — first public release

- `bra.py` 1.0.1 (now `rfpass.py`) — bug-report wireless analyzer (cellular, Wi-Fi, mobile data on Wi-Fi, airplane mode, Bluetooth, app attribution, remote-control surfaces, event windows). 1.0.1 only generalizes examples in comments.
- `swpass.py` 0.2.0 — stalkerware-footprint pass over a bug report. Reproduces a manual pass on a real report.
- `snapdiff.py` 0.1.0 — state snapshot of a bug report and a diff of two. Self-diff gives zero changes; planted changes (sideloaded app, certificate swap, new app op, ADB on, rogue trust agent, accessibility setting written by a non-system app, unknown Bluetooth bond) are all caught; routine Google-written settings stay out of the main list.
- `ilpass.py` 0.1.2 — intrusion-log analyzer. Reproduces an independent manual analysis of a real four-day export on every count checked. Fixes found during that validation: a reboot is counted only when event IDs reset to near zero (events sharing a timestamp can be exported out of ID order); the reboot boundary is the last event before it; Play-services sub-processes are matched to Play-services updates; shared process names are labelled.
- `mitm.py` 0.1.1 — man-in-the-middle checks from a bug report, intrusion logs and a Chrome NetLog. The NetLog part is untested.
- `corr.py` 0.1.0 — incident correlation with a circular-shift null (all shifts on a 10 s grid, shifts smaller than the window excluded) and Benjamini-Hochberg correction. Positive control (incidents planted at one app's foreground events) flags that app first; negative control (random times) flags nothing.
