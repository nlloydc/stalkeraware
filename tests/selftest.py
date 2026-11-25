#!/usr/bin/env python3
"""selftest.py - build the synthetic bug report, run `stalkeraware.py all` on it, and check the planted results.

    python3 -I tests/selftest.py

Positive controls: com.example.planted opens the camera and records from the mic with the screen off from a
foreground service, holds a long wakelock, uses GPS, fires frequent wakeup alarms and drains a screen-off stretch.
Negative controls: the camera app on screen, a WhatsApp call on screen, the Google hotword path, Spotify playback
capture (not the mic), Play-services jobs. Synthetic data only; it shows the parsers and rules work on the formats
they were written for, not that they parse every build.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import fixture  # noqa: E402

EXPECT = {
    "battery/report.md": ["| Screen-off spans with unusually high drain | 1 (11-24 02:05:00.000",
                      "com.example.planted (10300) (top 5 background power, top 5 background wakelock, GPS, 22.5 wakeup alarms/h)",
                      "| Non-Google wakelocks over a minute (screen off when taken) | com.example.planted (10300) 1x (1) |"],
    "camera-microphone/report.md": ["| Camera sessions meeting a look-closer rule | 1 of 2 (com.example.planted 11-24 03:10:00.000) |",
                        "| Mic sessions meeting a look-closer rule | 1 of 4 (com.example.planted 11-24 03:12:00.000) |",
                        "| Camera on with screen off (battery history) | 1 of 2 |",
                        "com.example.planted CAMERA Access [bg-s], com.example.planted RECORD_AUDIO Reject [cch-s]",
                        "| Mic/camera foreground services running at capture | com.example.planted |"],
    "run.md": ["| stalkerware |", "| wireless |", "| battery |", "| camera-microphone |", "| snapshot |", "| mitm |"],
}
NOT_EXPECT = {
    "camera-microphone/report.md": ["com.google.android.GoogleCamera | 5555 | on screen | on | DISCONNECT | LOOK",
                        "com.whatsapp | VOICE_COMMUNICATION | mic | on screen | on | LOOK"],
    "run.md": ["| error |", "| stopped |"],
}


def main():
    root = os.path.dirname(HERE)
    with tempfile.TemporaryDirectory() as tmp:
        z = os.path.join(tmp, "fixture.zip")
        fixture.write(z)
        out = os.path.join(tmp, "run")
        r = subprocess.run([sys.executable, "-I", os.path.join(root, "stalkeraware.py"), "all", z, "--out", out,
                            "--event", "2026-11-24T03:12:00|planted"], capture_output=True, text=True)
        fails = []
        if r.returncode:
            fails.append(f"all exited {r.returncode}: {r.stderr[-500:]}")
        for f, needles in EXPECT.items():
            txt = open(os.path.join(out, f)).read()
            fails += [f"{f}: missing {n!r}" for n in needles if n not in txt]
        for f, needles in NOT_EXPECT.items():
            txt = open(os.path.join(out, f)).read()
            fails += [f"{f}: unexpected {n!r}" for n in needles if n in txt]
        for f in ("battery/report.md", "camera-microphone/report.md"):
            if "problem:" in open(os.path.join(out, f)).read():
                fails.append(f"{f}: reports a parser problem")
    print("selftest: " + ("PASS" if not fails else "FAIL\n  " + "\n  ".join(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
