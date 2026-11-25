# Readings decided before looking

Phone logs are full of things that look odd. If you decide what counts as a hit *after* seeing the results, almost anything can be made to look meaningful, or explained away. So write down, before running a check, what result would make you look closer and what result is ordinary. Date it. Don't change it afterwards; add a new dated version instead.

Below is the set used for `swpass.py`. Copy it, adjust it to your situation (which apps you installed, which features you use), and date your copy before your first run.

| Check | Look closer | Ordinary |
|---|---|---|
| Indicator match (package, certificate, domain, hash) | Any match against a stalkerware/spyware set | 0 matches; parser artifacts after inspection |
| MVT heuristic warnings | A warning naming an app that isn't Google, the phone maker, or one you installed | Warnings explained by system components or apps you installed |
| Installer source | A third-party app installed by anything other than the Play Store (`com.android.vending`), preinstalled, or your own known sideloads | All Play or system |
| No launcher icon | A non-system app with no launcher activity that holds sensitive permissions or runs services/receivers | Only libraries, overlays, license keys, system/Google components |
| Sensitive permission clusters | A non-Google app holding ≥3 of: SMS, call log, mic, background location, contacts, camera, usage stats, overlay, notification access | Explained by the app's obvious function (a calling app with contacts + mic) |
| Default roles (SMS, dialer, assistant, browser, home) | Held by an app that isn't Google/the phone maker's or your own choice | The stock apps, or ones you chose |
| Background mic/camera (app ops) | A non-Google app using mic or camera while not on screen, with no action of yours | None, or on-screen use only |
| Background location (app ops) | An app you don't recognize, or frequent background fixes by an app with no location function | Maps, weather, ride-hailing, delivery during an order |
| Boot receivers + battery exemption + recurring jobs | The same non-Google app has all three plus network use | Common in messaging and system apps; not a hit alone |
| Background upload volume per app | A non-Google app uploading far more than its function explains | Sync/backup/media apps; whatever app you used to move large files off the phone |
| User CA certificates / VPN | Any user-installed CA or VPN profile you didn't set up | None (a Private DNS setting isn't a VPN) |
| Device admin / accessibility / notification listeners / trust agents | Any entry that isn't a system/Google component or something you enabled | System and Google defaults |

Limits: a clean result rules out known indicators and the common stalkerware footprint on that device at that time. It doesn't exclude implants below the operating system; that's examiner work.

## Added 2026-11-24: battery (`bat`) and camera/microphone (`micam`)

Written before either pass was run on a real report. Thresholds are constants at the top of `sawtools/batpass.py`.

| Check | Look closer | Ordinary |
|---|---|---|
| Screen-off drain | An unplugged screen-off span of ≥ 30 min draining ≥ 2× the median of the *other* screen-off stretches and losing ≥ 2 points, where the apps active in it don't explain it | Weak signal (long mobile-radio time), music or navigation, a backup or photo upload, a system update, heat |
| Per-app background cost (since charge) | A non-Google app in the top 5 for background power or background wakelock time, using GPS, or averaging ≥ 4 wakeup alarms/h, whose function doesn't explain it | Messaging, calling, music, navigation/ride-hailing during a trip, fitness, cloud backup, security apps, launcher, keyboard |
| Wakelocks over a minute | A non-Google app holding the phone awake for long periods with the screen off and nothing of its own on screen | Music, calls, navigation, downloads, system, Play services |
| Location requests | A non-Google app with long active, non-foreground requests and no location function | Maps, weather, ride-hailing, delivery, fitness, Find My Device, Play services |
| Camera sessions | A non-Google app opening a camera while neither on screen nor being opened, or with the screen off | Camera app, video calls, scanners while open, Face Unlock while the screen wakes |
| Recording sessions | A non-Google app recording from a mic source while neither on screen nor being opened, or with the screen off | Calls and voice notes, voice typing, the assistant and Now Playing (hotword path), playback capture (REMOTE_SUBMIX isn't the mic) |
| Camera on (battery history) | Camera on with the screen off | Camera on with the camera or a scanner app on screen |
| App ops, mic/camera | A non-Google app with an Access in background/cached state, or any Reject (an attempt that was refused); an Access from a foreground service you didn't start | Accesses while on screen |
| At capture | A mic/camera/screen-capture foreground service, open camera client or media projection you didn't start | None, or ones you started |

A use flagged by more than one source (camera service log, battery history, app ops) at the same time is a stronger lead than one source alone. Absence in a source whose span doesn't cover the time means nothing; each report lists the spans.

### Amendment 2026-11-24 (after the first real run)

Two changes to how `battery` applies the rules above; the thresholds themselves are unchanged.

- **Screen-off spans merge glances.** As first written, any screen-on moment split a stretch, so a day of normal use left only 3 rateable stretches. Screen-on glances of ≤ 2 min between screen-off stretches are now merged into one span (the report shows how many and how long). Changed after seeing the first real report's output; the first rule is kept here for the record.
- **Per-app ranks need ≥ 2 h on battery since the last charge.** That report had 8 minutes since charging, which made a "top 5" meaningless; below 2 h nothing is ranked or flagged, and the report says so.
