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

## Tools

| Tool | Reads | What it covers |
|---|---|---|
| `swpass.py` | bug report | Stalkerware footprint: who installed each app, apps without a launcher icon, sensitive permission clusters, default SMS/dialer/assistant roles, device admins, accessibility, notification access, VPN, Smart Lock trust agents, ADB/wireless debugging, users, accounts, companion devices, apps exempt from battery limits, background mic/camera/location use, upload volume per app, scheduled jobs, and which non-system apps changed security settings |
| `snapdiff.py` | bug reports | Records a snapshot of the security-relevant state of each report and lists what changed between two: new apps, certificate swaps, new permissions or app ops, role changes, new admins or trust agents, ADB, users, accounts, settings and the package that wrote them, Wi-Fi networks, Bluetooth bonds |
| `ilpass.py` | intrusion logs | Completeness (boots, missing event IDs), unlocks (failures, first unlock after boot, night-time), APK-hash continuity (Play update vs system update vs unexplained), network (odd DNS answers, connects without DNS, tunnel/PaaS hosts, locked-night traffic), indicator matching, Bluetooth bursts and the app active just before each |
| `mitm.py` | bug report, intrusion logs, Chrome NetLog | Man-in-the-middle signs: ARP spoofing and rogue DHCP on Wi-Fi, Android's own connectivity probes (HTTPS failing while HTTP works, DNS answers outside Google's ranges), Private DNS consistency, cellular null ciphers and 2G, DNS-over-TLS redirected elsewhere, certificate-authority installs and validation failures, certificates not issued by a publicly trusted root in Chrome |
| `rfpass.py` | bug report | Wireless detail: cellular signal, bands and ciphers; Wi-Fi networks and access points; mobile data while on Wi-Fi; airplane mode; Bluetooth connections, pairing, who initiated, which app held the link; event windows around times you give |
| `corr.py` | outputs of `ilpass.py` / `rfpass.py` | Do any logged events cluster around the times you noticed something, more than chance would predict? |

## Running

```sh
mkdir -p evidence out states
cp bugreport-*.zip intrusion-logs.zip evidence/ && chmod 444 evidence/* && sha256sum evidence/*

python3 -I swpass.py   evidence/<bugreport>.zip --out out/sw-1
python3 -I rfpass.py   evidence/<bugreport>.zip --out out/rf-1 --event "2026-01-15T10:51:04|what you noticed"
python3 -I snapdiff.py snap evidence/<bugreport>.zip -o states/1.json        # keep every state file
python3 -I snapdiff.py diff states/1.json states/2.json -o out/diff-1-2       # once you have two
python3 -I ilpass.py   evidence/<intrusion-logs>.zip --out out/il-1
python3 -I mitm.py     --br evidence/<bugreport>.zip --il out/il-1 [--netlog chrome-net-export.json] --out out/mitm-1
python3 -I corr.py     incidents.csv --il out/il-1 --rf out/rf-1 --out out/corr-1
```

`incidents.csv` has a header `time,label,precision_s`: the local time you noticed something, a short label, and how many seconds you might be off by.

`--out` folders must not exist yet, so earlier results are never overwritten. Times are the phone's local time.

Also run [MVT](https://github.com/mvt-project/mvt) on the same files (`mvt-android check-bugreport`, `mvt-android check-intrusion-logs`). It matches against published spyware and stalkerware indicators. `ilpass.py` reuses the indicator files MVT downloads (`mvt-android download-iocs`); point `--iocs` elsewhere to use others.

## Reading the results

- Each report section prints its **"Look closer if"** reading next to the table. `PREREGISTERED.md` explains why those readings are written down before results are seen, and gives a template for your own.
- Most odd-looking things in phone logs have ordinary causes: an app's own feature, a weak signal, a system update, the bug report itself. The reports try to show the ordinary explanation next to each item.
- A clean result rules out the known indicators and the common footprint on that phone at that time. It doesn't rule out compromise below the operating system. That needs a professional examiner.
- A hit is a lead, not proof. Take the report, the original files and their hashes to an examiner or the police; don't confront anyone with it.
- Nothing here proves how anything was done. The reports state what the logs record.

## Validation

`ilpass.py` reproduces an independent manual analysis of a real four-day intrusion-log export: event counts, boot and ID accounting, failed unlocks, APK-hash classification, indicator matching and Bluetooth burst detection. `swpass.py` reproduces a manual stalkerware pass on a real bug report. `snapdiff.py` was tested with a self-diff (no changes) and with planted changes (all caught). `corr.py` was tested with positive and negative controls. The Chrome NetLog part of `mitm.py` hasn't been tested on a real NetLog yet. The parsers were written against a Pixel on Android 17; other phones and versions may format sections differently. A section that fails to parse says so in the report.

## Integrity

`SHA256SUMS` lists every tool's hash: `sha256sum -c SHA256SUMS`. Each report's `manifest.json` records the tool hash, input hash and run time.

## Not in this repo

Evidence and outputs. `.gitignore` blocks the usual names; don't add personal data to a fork.

## License

Apache-2.0. See `LICENSE`.
