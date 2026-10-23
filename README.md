# CyberGuard Android (v0.4)

CyberGuard is an on-device Android security helper built with Kotlin and Jetpack Compose.

## Build APK

Push this repository to GitHub, then open **Actions → Build APK**. Download the
`CyberGuard-debug-apk` artifact after the workflow succeeds. This is a debug-signed
APK for testing, not a Play Store release build.

## Features

- Scan installed applications using package identity, installer source, selected risky
  permissions, enabled accessibility services, active device-admin packages and
  notification-listener packages.
- Optional heavy scan of shared storage (requires Android's special all-files access).
- APK and file checks using SHA-256, known hash entries, EICAR test detection,
  file-signature checks and suspicious double extensions.
- Quarantine files into app-private storage with copy verification, restore without
  overwriting an existing file, and permanent deletion with result checks.
- Scan history, URL checks, Wi-Fi checks and privacy/usage audit tools.
- Periodic lightweight package scan through WorkManager and package-install scan
  notifications. Android controls background timing; periodic work is not exact.
- Dark, neon-green Jetpack Compose interface.

## Important limitations

- The built-in signature lists are empty by default. A genuine up-to-date malware
  signature feed or reputable reputation service must be configured separately.
- Heuristic findings can be false positives or miss malware. A clean result does not
  prove a file or app is safe.
- Android restricts access to some folders, particularly `Android/data` and `Android/obb`.
- Android requires system confirmation to uninstall another app. CyberGuard does not
  silently uninstall apps.
- Notifications require user permission on Android 13+.
- Battery percentage per app is not available through the normal public API; usage
  time is only an indirect signal.
- This project is not a replacement for Google Play Protect or a professional endpoint
  security product.
