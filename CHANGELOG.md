# Changelog

## 2026-11-24 — rename
- `bra.py` renamed `rfpass.py` (1.0.2; name only). `corr.py` 0.1.1 takes `--rf` for its output folders (`--bra` still accepted).

## 2026-11-24 — first public release

- `bra.py` 1.0.1 (now `rfpass.py`) — bug-report wireless analyzer (cellular, Wi-Fi, mobile data on Wi-Fi, airplane mode, Bluetooth, app attribution, remote-control surfaces, event windows). 1.0.1 only generalizes examples in comments.
- `swpass.py` 0.2.0 — stalkerware-footprint pass over a bug report. Reproduces a manual pass on a real report.
- `snapdiff.py` 0.1.0 — state snapshot of a bug report and a diff of two. Self-diff gives zero changes; planted changes (sideloaded app, certificate swap, new app op, ADB on, rogue trust agent, accessibility setting written by a non-system app, unknown Bluetooth bond) are all caught; routine Google-written settings stay out of the main list.
- `ilpass.py` 0.1.2 — intrusion-log analyzer. Reproduces an independent manual analysis of a real four-day export on every count checked. Fixes found during that validation: a reboot is counted only when event IDs reset to near zero (events sharing a timestamp can be exported out of ID order); the reboot boundary is the last event before it; Play-services sub-processes are matched to Play-services updates; shared process names are labelled.
- `mitm.py` 0.1.1 — man-in-the-middle checks from a bug report, intrusion logs and a Chrome NetLog. The NetLog part is untested.
- `corr.py` 0.1.0 — incident correlation with a circular-shift null (all shifts on a 10 s grid, shifts smaller than the window excluded) and Benjamini-Hochberg correction. Positive control (incidents planted at one app's foreground events) flags that app first; negative control (random times) flags nothing.
