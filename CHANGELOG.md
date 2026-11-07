# Changelog

This file records each release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Read-only desktop tray app that shows sessions and recent calls and notifies you when a call is blocked.
- Downloadable desktop app for macOS and Linux on each GitHub release.
- Windows shells in the default shell rules.

### Fixed

- The proxy now exits when writing to the host fails while the upstream server has stopped reading its input. It used to hang until the server exited.

## 0.1.0 - 2026-11-05

### Added

- Stdio MCP proxy that enforces a TOML policy and a monotonic session taint on `tools/call` and `resources/read`.
- Redacted JSONL audit log.
- TLA+ model of the taint state machine, mirrored in Rust tests.
- Replay corpus of prompt-injection scenarios.
