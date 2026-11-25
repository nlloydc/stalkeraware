"""Synthetic bug report: ordinary use plus planted look-closer cases. Not real data; no personal information."""
import zipfile, sys
L = []
A = L.append
A("========================================================")
A("== dumpstate: 2026-11-24 05:25:31")
A("========================================================")
A("Build: TEST.000000.000")
A("Build fingerprint: 'generic/test/test:17/TEST.000000.000/1:user/release-keys'")
A("Uptime: up 0 weeks, 1 days")
A("------ SYSTEM PROPERTIES (getprop) ------")
A("[persist.sys.timezone]: [America/New_York]")
A("[ro.product.model]: [Pixel Test]")
A("------ 0.01s was the duration of 'SYSTEM PROPERTIES' ------")
A("------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------")
A("--------- beginning of main")
A("11-24 03:09:59.900  1047  1100 I CameraService: CameraService::connect call (PID 4321 \"com.example.planted\", camera ID 1) and Camera API version 2")
A("11-24 03:10:40.100  1047  1100 I CameraService: disconnect: Disconnected client for camera 1 for PID 4321")
A("11-24 05:20:00.000  1000  1000 I ActivityManager: something")
A("------ 0.2s was the duration of 'SYSTEM LOG' ------")
A("------ DUMPSYS ACTIVITY SERVICES (dumpsys activity services) ------")
A("  * ServiceRecord{aa11 u0 com.example.planted/.RecSvc c:com.example.planted}")
A("    isForeground=true foregroundId=7 types=0x00000080 foregroundNoti=Notification(...)")
A("  * ServiceRecord{bb22 u0 com.spotify.music/.Play c:com.spotify.music}")
A("    isForeground=true foregroundId=2 types=0x00000002")
A("------ 0.1s was the duration of 'DUMPSYS ACTIVITY SERVICES' ------")
def svc(name, lines):
    A("-------------------------------------------------------------------------------")
    A(f"DUMP OF SERVICE {name}:")
    L.extend(lines)
    A(f"--------- 0.01s was the duration of dumpsys {name}, ending at: 2026-11-24 05:25:40")
pk = []
for name, aid in (("com.google.android.GoogleCamera", 10200), ("com.example.planted", 10300), ("com.whatsapp", 10250),
                  ("com.google.android.as", 10150), ("com.spotify.music", 10260), ("com.google.android.gms", 10140)):
    pk += [f"  Package [{name}] (1234):", f"    appId={aid}", f"    codePath=/data/app/~~x/{name}-1",
           "    installerPackageName=com.android.vending", "    pkgFlags=[ HAS_CODE ]",
           "    User 0: ceDataInode=1 installed=true hidden=false", "    runtime permissions:",
           "      android.permission.RECORD_AUDIO: granted=true", ""]
svc("package", ["Packages:"] + pk)
svc("battery", ["Current Battery Service state:", "  AC powered: false", "  level: 61", "  temperature: 302",
                "  health: 2", "  status: 3"])
svc("media.camera", [
 "== Service global info: ==", "Number of camera devices: 3",
 "== Camera service events log (most recent at top): ==",
 "  11-24 05:24:30 : DISCONNECT device 0 client for package com.google.android.GoogleCamera (PID 5555)",
 "  11-24 05:24:00 : CONNECT device 0 client for package com.google.android.GoogleCamera (PID 5555)",
 "  11-24 03:10:40 : DISCONNECT device 1 client for package com.example.planted (PID 4321)",
 "  11-24 03:10:00 : CONNECT device 1 client for package com.example.planted (PID 4321)",
 "  11-24 01:00:00 : REJECT device 1 client for package com.example.planted (PID 4321), access denied",
 "== Camera Provider HAL ==",
 "Active Camera Clients:", "[", "]"])
svc("audio", ["AudioService state", "",
 "recording activity received by AudioService (last 50):",
 "11-24 03:12:00:000 rec start riid:41 uid:10300 session:801 src:MIC pack:com.example.planted",
 "11-24 03:14:30:000 rec stop riid:41 uid:10300 session:801 src:MIC pack:com.example.planted",
 "11-24 04:00:00:000 rec start riid:42 uid:10150 session:802 src:HOTWORD pack:com.google.android.as",
 "11-24 04:00:00:040 rec stop riid:42 uid:10150 session:802 src:HOTWORD pack:com.google.android.as",
 "11-24 05:22:00:000 rec start riid:43 uid:10250 session:803 src:VOICE_COMMUNICATION pack:com.whatsapp",
 "11-24 05:23:00:000 rec release riid:43 uid:10250 session:803 src:VOICE_COMMUNICATION pack:com.whatsapp",
 "11-24 05:23:10:000 rec start riid:44 uid:10260 session:804 src:REMOTE_SUBMIX pack:com.spotify.music",
])
svc("appops", ["Current AppOps Service state:", "  Uid u0a300:", "    state=cch",
 "    Package com.example.planted:",
 "      CAMERA (allow):",
 "          Access: [bg-s] 2026-11-24 03:10:00.123 (-2h15m) duration=+40s0ms",
 "      RECORD_AUDIO (allow):",
 "          Access: [fgsvc-s] 2026-11-24 03:12:00.000 (-2h13m) duration=+2m30s0ms",
 "          Reject: [cch-s] 2026-11-24 01:00:00.500 (-4h25m)",
 "  Uid u0a250:", "    Package com.whatsapp:",
 "      RECORD_AUDIO (allow):",
 "          Access: [top-s] 2026-11-24 05:22:00.000 (-3m) duration=+1m0ms",
 "  Uid u0a200:", "    Package com.google.android.GoogleCamera:",
 "      CAMERA (allow):",
 "          Access: [top-s] 2026-11-24 05:24:00.000 (-1m) duration=+30s0ms"])
svc("alarm", ["Current Alarm Manager state:", "  Top Alarms:",
 "    +2m10s0ms running, 180 wakeups, 180 alarms: u0a300:com.example.planted",
 "      *walarm*:com.example.planted.BEAT",
 "    +1s0ms running, 12 wakeups, 40 alarms: u0a140:com.google.android.gms",
 "      *walarm*:com.google.android.gms.X",
 " ", "  Alarm Stats:"])
svc("location", ["Location Manager State:", "  Historical Aggregate Location Provider Data:", "    gps provider:",
 "        com.example.planted: min/max interval = +1m0s0ms/+1m0s0ms, total/active/foreground duration = +3h0m0s0ms/+2h0m0s0ms/+0ms, locations = 120",
 "        com.google.android.apps.maps: min/max interval = +1s0ms/+1s0ms, total/active/foreground duration = +10m0s0ms/+10m0s0ms/+10m0s0ms, locations = 600",
 "    fused provider:",
 "        com.google.android.gms[fused]: min/max interval = +1m0s0ms/+5m0s0ms, total/active/foreground duration = +20h0m0s0ms/+20h0m0s0ms/+0ms, locations = 900",
 "  Event Log:"])
svc("sensor_privacy", ["SENSOR PRIVACY MANAGER STATE (dumpsys sensor_privacy)", "  User 0:",
                       "    Sensor microphone: enabled=false", "    Sensor camera: enabled=false"])
svc("media_projection", ["MEDIA PROJECTION MANAGER (dumpsys media_projection)", "Media Projection: null"])
# batterystats: history + since charge
B = ["Battery History [Format: 2] (2% used, 5KB used of 256KB, 120 strings using 8KB):",
     "  11-23 21:00:00.000 RESET:TIME: 2026-11-23-21-00-00"]
def h(t, lvl, rest=""):
    B.append(f"  {t} {lvl:03d} c0000000 {rest}".rstrip())
h("11-23 21:00:00.000", 100, "status=charging +plugged +screen +running")
h("11-23 21:30:00.000", 100, "-plugged status=discharging")
h("11-23 21:40:00.000", 99, "-screen")
# quiet night 21:40 -> 02:00: lose 2 % over 4h20
h("11-23 23:00:00.000", 99, "-running wake_reason=0:\"Abort:modem\"")
h("11-24 00:00:00.000", 98, "+running wake_reason=0:\"alarmtimer\" +job=u0a140:\"com.google.android.gms/.Sync\"")
h("11-24 00:00:05.000", 98, "-running -job=u0a140:\"com.google.android.gms/.Sync\"")
h("11-24 01:00:00.000", 98, "+running wake_reason=0:\"alarmtimer\"")
h("11-24 01:00:02.000", 98, "-running")
h("11-24 02:00:00.000", 97, "+screen +top=u0a250:\"com.whatsapp\"")
h("11-24 02:05:00.000", 97, "-screen -top=u0a250:\"com.whatsapp\"")
# heavy stretch 02:05 -> 04:10: lose 12 %
h("11-24 02:06:00.000", 97, "+running +wake_lock=u0a300:\"planted:beat\" wake_reason=0:\"alarmtimer\" +fg=u0a300:\"com.example.planted\"")
h("11-24 02:07:00.000", 97, "+longwake=u0a300:\"planted:beat\" +gps +mobile_radio")
h("11-24 02:30:00.000", 95, "+job=u0a300:\"com.example.planted/.Up\"")
h("11-24 02:31:00.000", 95, "-job=u0a300:\"com.example.planted/.Up\"")
h("11-24 03:10:00.000", 92, "+camera")
h("11-24 03:10:40.000", 92, "-camera")
h("11-24 03:30:00.000", 90, "+job=u0a300:\"com.example.planted/.Up\"")
h("11-24 03:31:00.000", 90, "-job=u0a300:\"com.example.planted/.Up\"")
h("11-24 04:05:00.000", 86, "-longwake=u0a300:\"planted:beat\" -gps -mobile_radio -fg=u0a300:\"com.example.planted\"")
h("11-24 04:10:00.000", 85, "-running")
h("11-24 05:20:00.000", 84, "+screen +running")
h("11-24 05:21:00.000", 84, "+top=u0a250:\"com.whatsapp\"")
h("11-24 05:23:30.000", 84, "-top=u0a250:\"com.whatsapp\"")
h("11-24 05:23:59.000", 84, "+top=u0a200:\"com.google.android.GoogleCamera\"")
h("11-24 05:24:00.500", 84, "+camera")
h("11-24 05:24:30.000", 84, "-camera -top=u0a200:\"com.google.android.GoogleCamera\"")
h("11-24 05:25:30.000", 84, "")
B += ["", "Per-PID Stats:", "  PID 1 wake time: +1s", "",
      "Statistics since last charge:",
      "  System starts: 0, currently on battery: true",
      "  Time on battery: 8h 0m 0s 0ms (99.0%) realtime, 3h 0m 0s 0ms (40.0%) uptime",
      "  Time on battery screen off: 7h 30m 0s 0ms (90.0%) realtime",
      "  Start clock time: 2026-11-23-21-30-00",
      "  Estimated power use (mAh):",
      "    Capacity: 4700, Computed drain: 760, actual drain: 705-752",
      "    Global",
      "      screen: 120 apps: 120 duration: 30m",
      "    UID u0a300: 310 fg: 0 bg: 250 fgs: 60 cached: 0 ( cpu=200 (1h 0m) gnss=80 mobile_radio=30 )",
      "    UID u0a250: 40.5 fg: 30 bg: 10 fgs: 0.5 cached: 0 ( cpu=20 (5m) )",
      "    UID u0a140: 90 fg: 0 bg: 85 fgs: 5 cached: 0 ( cpu=60 (10m) )",
      "  All partial wake locks:",
      "  Wake lock u0a300 planted:beat: 1h 58m 0s 0ms realtime (40 times)",
      "  Wake lock u0a140 *job*/com.google.android.gms/.Sync: 5s 0ms realtime (1 times)",
      "",
      "  All wakeup reasons:",
      "  Wakeup reason Abort:modem: 1m 0s realtime (12 times)",
      "  Wakeup reason alarmtimer: 3m 0s realtime (190 times)",
      "",
      "  u0a300:",
      "    Wake lock planted:beat: 1h 58m 0s 0ms partial (40 times) max=3600000 actual=7080000 realtime",
      "    TOTAL wake: 1h 58m 0s 0ms blamed partial, 1h 58m 0s 0ms actual partial, 1h 58m 0s 0ms actual background partial realtime",
      "    Wakeup alarm *walarm*:com.example.planted.BEAT: 180 times",
      "    Job com.example.planted/.Up: 2m 0s 0ms realtime (2 times)",
      "    Sensor GPS: 1h 58m 0s 0ms realtime (1 times), 1h 58m 0s 0ms background (1 times)",
      "    Camera: 40s 0ms realtime (1 times)",
      "    Mobile network: 45.00MB received, 120.00MB sent (packets 1 received, 1 sent)",
      "    Fg Service for: 1h 59m 0s 0ms",
      "    Background for: 2h 0m 0s 0ms",
      "    Total cpu time: u=50m 0s 0ms s=10m 0s 0ms",
      "  u0a200:",
      "    Camera: 30s 0ms realtime (1 times)",
      "    Top for: 31s 0ms",
      "  u0a250:",
      "    Audio: 1m 0s 0ms realtime (1 times)",
      "    TOTAL wake: 10s 0ms blamed partial, 10s 0ms actual partial, 0ms actual background partial realtime",
      "    Top for: 7m 30s 0ms",
      "  u0a140:",
      "    TOTAL wake: 5s 0ms blamed partial, 5s 0ms actual partial, 5s 0ms actual background partial realtime",
      "    Wakeup alarm *walarm*:com.google.android.gms.X: 12 times",
      "    Job com.google.android.gms/.Sync: 5s 0ms realtime (1 times)",
      "", "Discharge step durations:"]
svc("batterystats", B)
txt = "\n".join(L) + "\n"


def write(path):
    name = "bugreport-test-FIXTURE-2026-11-24-05-25-31"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name + ".txt", txt)
        z.writestr("main_entry.txt", name + ".txt")
        z.writestr("version.txt", "2.0")


if __name__ == "__main__":
    write(sys.argv[1])
