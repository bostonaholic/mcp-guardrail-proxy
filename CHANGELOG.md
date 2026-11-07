# Changelog

This file records each release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Downloadable proxy binary for macOS and Linux on each GitHub release, so you can install the proxy without Rust.
- A Settings section in the desktop app window, where you change the watched audit log without a relaunch and turn blocked-call notifications off and on. The app keeps your settings across relaunches.

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
