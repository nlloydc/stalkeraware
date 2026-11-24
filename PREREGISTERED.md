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
