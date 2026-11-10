# Changelog

This file records each release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- The General tab icon in the desktop app's Settings window is now a gear. It used to look like a ship's wheel.

## 0.3.0 - 2026-11-10

### Added

- Downloadable proxy binary for macOS and Linux on each GitHub release, so you can install the proxy without Rust.
- A General tab in the desktop app's Settings window, where you change the watched audit log without a relaunch and turn blocked-call notifications off and on. The app keeps your settings across relaunches.
- A Choose… button on the General tab of the desktop app's Settings window. It opens the system folder panel in the folder of the current audit log, and the app then watches `audit.jsonl` in the folder you pick.
- `mcp-guardrail-proxy probe`, which lists an MCP server's tools directly and through the proxy, fails when the lists differ, and gives the policy outcome of each tool in a clean and a tainted session.
- The desktop app checks for updates when you click "Check for Updates…" in the tray or Check now in its Settings window.
- An update mode on the Updates tab of the desktop app's Settings window: Off, Notify, or Install. The default is Notify. In Notify and Install, the app checks github.com about one minute after launch and once a day after that. Off makes no check until you start one.
- In Notify mode, the desktop app sends one notification for each new version.
- A desktop app installed from a release `.dmg` or `.AppImage` installs a new version when you press Install, or by itself in Install mode. Restart the app to use it.
- Each GitHub release also holds a signed `.app.tar.gz` for each Mac architecture and `mcp-guardrail-desktop-update.json`, which the desktop app's updater reads.
- A Settings window in the desktop app, with General and Updates tabs in a toolbar. Open it from "Settings…" in the tray, the Settings… button on the dashboard, or Cmd+,. "Check for Updates…" in the tray also opens the Updates tab. The main window shows only the dashboard.

## 0.2.0 - 2026-11-06

### Added

- Read-only desktop tray app that shows sessions and recent calls and notifies you when a call is blocked.
- Downloadable desktop app for macOS and Linux on each GitHub release.

### Changed

- The default policy now covers tools named `powershell`, `pwsh`, and `cmd` in `deny-destructive-shell`, `deny-env-dump`, and `tainted-deny-shell-exec`. Those calls used to get the default allow, even in a tainted session. If you rely on one of these tools after a tainted read, use a custom policy with `--policy`.

### Fixed

- The proxy now exits when writing to the host fails while the upstream server has stopped reading its input. It used to hang until the server exited.

## 0.1.0 - 2026-11-05

### Added

- Stdio MCP proxy that enforces a TOML policy and a monotonic session taint on `tools/call` and `resources/read`.
- Redacted JSONL audit log.
- TLA+ model of the taint state machine, mirrored in Rust tests.
- Replay corpus of prompt-injection scenarios.
