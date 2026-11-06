# MCP Guardrail desktop

A read-only tray app that watches the proxy's audit log. It shows sessions and recent calls, and sends a notification when a call is blocked.

The app only reads the log. It never talks to a proxy, so it cannot approve a call or weaken a decision, and proxies run the same when it is closed. It is a separate crate, outside the proxy's build, so its dependencies do not reach the proxy.

## Run it

You need Rust and `tauri-cli` (`cargo install tauri-cli --version "^2" --locked`).

```sh
cd desktop
cargo tauri build --bundles app
open "target/release/bundle/macos/MCP Guardrail.app"
```

The app reads `~/.local/state/mcp-guardrail/audit.jsonl`, the path in the root README's quick start. To watch another file, launch with `MCP_GUARDRAIL_AUDIT_LOG` set:

```sh
open --env MCP_GUARDRAIL_AUDIT_LOG=/abs/path/audit.jsonl "target/release/bundle/macos/MCP Guardrail.app"
```

Point each proxy at that file with `--audit-log`. Several proxies can share one file. macOS asks for notification permission at first launch.

## Notifications on macOS

Each blocked call reaches Notification Center within about 3 seconds. Open it to see the alerts. macOS decides whether a banner also pops up, using the app's setting in System Settings > Notifications and any Focus mode. The app needs a bundle signature whose identifier matches its bundle id, so `tauri.conf.json` signs ad hoc. A public release needs a Developer ID signature.

## What the audit log cannot show

- Taint lags by one call. An audit line records the level from before its call, so a call that taints a session shows up on that session's next call.
- Ended sessions stay listed, because the log has no end-of-session record.
- An audit sink failure is invisible here. The failed line goes to stderr as `audit-fallback:`, not to the log.
- Lines already in the log at launch load as history and raise no notification.

The app leaves out `arguments`, because redaction matches known patterns and a secret could survive it.

## Icons

`icons/app-icon.svg` and `icons/tray-icon.svg` are the sources. The mark is a call stopped at a gate inside a shield. To regenerate the files the build uses, run this in `desktop/`:

```sh
rsvg-convert -w 72 -h 72 icons/tray-icon.svg -o icons/tray.png
rsvg-convert -w 1024 -h 1024 icons/app-icon.svg -o /tmp/app-icon.png
cargo tauri icon /tmp/app-icon.png -o icons
```

`cargo tauri icon` also writes Android, iOS, and Windows Store sizes, which this app does not use, so delete them.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`src/audit.rs` turns log lines into dashboard state and does no I/O. `src/tail.rs` follows the file. `src/main.rs` holds the tray, the window, and the notifications. Every audit value reaches the page through `textContent`, because tool names and URIs can hold attacker-influenced text.
