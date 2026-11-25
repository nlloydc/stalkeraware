# stalkeraware

Tools for reading an Android phone's own logs for signs of stalkerware, abuse of built-in features ("living off the land"), and man-in-the-middle interception. Built for people who suspect their phone is being monitored and want something concrete, timestamped and checkable to hand to an examiner or the police, rather than a yes/no from an app.

Everything runs on a computer, offline, with nothing but Python 3.9+ (standard library only). The phone doesn't need to be rooted and nothing is installed on it. Every tool hashes its input, never modifies it, and writes a Markdown report plus machine-readable tables to a new folder.

## Safety first

If someone else has access to your phone or accounts, they may notice changes: Developer options turned on, a bug report being taken, Advanced Protection or intrusion logging switched on. Think about whether that's safe for you before you start. The Coalition Against Stalkerware (https://stopstalkerware.org) lists support organizations that can help you plan. These tools don't remove anything; removing stalkerware can tip off whoever installed it.

## What they read

| Source | How to get it |
|---|---|
| **Bug report** (`bugreport-*.zip`) | Settings → About phone → tap Build number 7× → Developer options → Take bug report → Full report. Turn on "Bluetooth HCI snoop log" there first if Bluetooth matters. |
| **Intrusion logs** (Android 16+ with Advanced Protection and intrusion logging on) | Download from the Advanced Protection settings (under Security & privacy; the exact menu varies by version). Logs upload about once a day, so an export covers up to roughly the previous day. |
| **Chrome NetLog** (optional) | In Chrome on the phone: `chrome://net-export` → Start logging → browse → Stop → share the file. |

## Commands

One program, `stalkeraware.py`, runs every pass. Each pass is a module in `sawtools/`.

| Command | Module | Reads | What it covers |
|---|---|---|---|
| `stalkerware` | `swpass.py` | bug report | Stalkerware footprint: who installed each app, apps without a launcher icon, sensitive permission clusters, default SMS/dialer/assistant roles, device admins, accessibility, notification access, VPN, Smart Lock trust agents, ADB/wireless debugging, users, accounts, companion devices, apps exempt from battery limits, background mic/camera/location use, upload volume per app, scheduled jobs, and which non-system apps changed security settings |
| `snapshot` / `compare` | `snapdiff.py` | bug reports | Records a snapshot of the security-relevant state of each report and lists what changed between two: new apps, certificate swaps, new permissions or app ops, role changes, new admins or trust agents, ADB, users, accounts, settings and the package that wrote them, Wi-Fi networks, Bluetooth bonds |
| `intrusion-logs` | `ilpass.py` | intrusion logs | Completeness (boots, missing event IDs), unlocks (failures, first unlock after boot, night-time), APK-hash continuity (Play update vs system update vs unexplained), network (odd DNS answers, connects without DNS, tunnel/PaaS hosts, locked-night traffic), indicator matching, Bluetooth bursts and the app active just before each |
| `mitm` | `mitm.py` | bug report, intrusion logs, Chrome NetLog | Man-in-the-middle signs: ARP spoofing and rogue DHCP on Wi-Fi, Android's own connectivity probes (HTTPS failing while HTTP works, DNS answers outside Google's ranges), Private DNS consistency, cellular null ciphers and 2G, DNS-over-TLS redirected elsewhere, certificate-authority installs and validation failures, certificates not issued by a publicly trusted root in Chrome |
| `wireless` | `rfpass.py` | bug report | Wireless detail: cellular signal, bands and ciphers; Wi-Fi networks and access points; mobile data while on Wi-Fi; airplane mode; Bluetooth connections, pairing, who initiated, which app held the link; event windows around times you give |
| `battery` | `batpass.py` | bug report | Battery: screen-off spans (% per hour against the other spans, time awake, mobile radio, GPS, which apps held the phone awake, ran jobs or fired alarms), spans draining far faster than the others, per-app background power, wakelocks, wakeup alarms, jobs, GPS and data since charge, wakelocks held over a minute, AlarmManager's top alarms, location requests per app, kernel wakeup reasons |
| `camera-microphone` | `micpass.py` | bug report | Camera and microphone: camera sessions from the camera service's own log, recording sessions with their audio source (mic, call, voice recognition, hotword, playback capture), camera-on intervals from battery history, last use and rejected attempts in app ops, camera/audio time per app, mic/camera foreground services, screen capture and the privacy toggles at capture. Each use is labelled with whether the app was on screen and whether the screen was on |
| `correlate` | `corr.py` | outputs of `intrusion-logs` / `wireless` | Do any logged events cluster around the times you noticed something, more than chance would predict? |

## Running

```sh
mkdir -p evidence out states
cp bugreport-*.zip intrusion-logs.zip evidence/ && chmod 444 evidence/* && sha256sum evidence/*

# everything at once: extracts the bug report once and runs stalkerware, wireless, battery, camera-microphone,
# snapshot and mitm (+ intrusion-logs and compare when given)
python3 -I stalkeraware.py all evidence/<bugreport>.zip --out out/run-1 \
        --event "2026-01-15T10:51:04|what you noticed" \
        [--intrusion-logs evidence/<intrusion-logs>.zip] [--prev-state out/run-0/state.json]

# or one pass at a time
python3 -I stalkeraware.py stalkerware       evidence/<bugreport>.zip --out out/sw-1
python3 -I stalkeraware.py wireless          evidence/<bugreport>.zip --out out/rf-1 --event "2026-01-15T10:51:04|what you noticed"
python3 -I stalkeraware.py battery           evidence/<bugreport>.zip --out out/bat-1
python3 -I stalkeraware.py camera-microphone evidence/<bugreport>.zip --out out/cam-1
python3 -I stalkeraware.py snapshot          evidence/<bugreport>.zip -o states/1.json     # keep every state file
python3 -I stalkeraware.py compare           states/1.json states/2.json -o out/compare-1-2
python3 -I stalkeraware.py intrusion-logs    evidence/<intrusion-logs>.zip --out out/il-1
python3 -I stalkeraware.py mitm              --bugreport evidence/<bugreport>.zip --intrusion-logs out/il-1 \
                                             [--netlog chrome-net-export.json] --out out/mitm-1
python3 -I stalkeraware.py correlate         incidents.csv --intrusion-logs out/il-1 --wireless out/rf-1 --out out/corr-1
python3 -I stalkeraware.py versions          # module versions and hashes
```

`stalkeraware.py <command> -h` lists a command's options. The earlier short names (`sw`, `rf`, `bat`, `micam`, `snap`, `diff`, `il`, `corr`, and `--br`/`--il`/`--rf`) still work. `all` writes `run.md` (what ran, status, where each report is) and a `manifest.json` with the input's hash and the toolkit hash.

`incidents.csv` has a header `time,label,precision_s`: the local time you noticed something, a short label, and how many seconds you might be off by.

`--out` folders must not exist yet, so earlier results are never overwritten. Times are the phone's local time. `-I` keeps Python from importing anything from the folder you run it in (which may hold untrusted files); `stalkeraware.py` adds only its own `sawtools` package to the import path.

Also run [MVT](https://github.com/mvt-project/mvt) on the same files (`mvt-android check-bugreport`, `mvt-android check-intrusion-logs`). It matches against published spyware and stalkerware indicators. `intrusion-logs` reuses the indicator files MVT downloads (`mvt-android download-iocs`); point `--iocs` elsewhere to use others.

## Reading the results

- Each report section prints its **"Look closer if"** reading next to the table. `PREREGISTERED.md` explains why those readings are written down before results are seen, and gives a template for your own.
- Most odd-looking things in phone logs have ordinary causes: an app's own feature, a weak signal, a system update, the bug report itself. The reports try to show the ordinary explanation next to each item.
- A clean result rules out the known indicators and the common footprint on that phone at that time. It doesn't rule out compromise below the operating system. That needs a professional examiner.
- A hit is a lead, not proof. Take the report, the original files and their hashes to an examiner or the police; don't confront anyone with it.
- Nothing here proves how anything was done. The reports state what the logs record.

## Validation

`ilpass.py` reproduces an independent manual analysis of a real four-day intrusion-log export: event counts, boot and ID accounting, failed unlocks, APK-hash classification, indicator matching and Bluetooth burst detection. `swpass.py` reproduces a manual stalkerware pass on a real bug report. `snapdiff.py` was tested with a self-diff (no changes) and with planted changes (all caught). `corr.py` was tested with positive and negative controls. The Chrome NetLog part of `mitm.py` hasn't been tested on a real NetLog yet. `batpass.py` and `micpass.py` pass `tests/selftest.py` (a synthetic bug report with planted positive and negative cases) and were checked by hand against one real Pixel/Android 17 report, which is where Android 17's recording log ("update" records only, no start/stop), the newest-first camera log and the one-minute delay in long-wakelock records were found. On other builds, treat a parser problem or an empty section as "check by hand", not as "nothing there". The parsers were written against a Pixel on Android 17; other phones and versions may format sections differently. A section that fails to parse says so in the report.

## Integrity

`SHA256SUMS` lists every file's hash: `sha256sum -c SHA256SUMS`. Each report's `manifest.json` records the module's hash, a toolkit hash over the whole `sawtools` package, the input hash and the run time. `python3 -I tests/selftest.py` checks the bug-report passes against a synthetic report.

## Not in this repo

Evidence and outputs. `.gitignore` blocks the usual names; don't add personal data to a fork.

## License

Apache-2.0. See `LICENSE`.
