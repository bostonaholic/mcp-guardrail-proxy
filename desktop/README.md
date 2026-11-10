# MCP Guardrail desktop

A tray app that watches the proxy's audit log. It shows sessions and recent calls, and sends a notification when a call is blocked. It also checks for its own updates.

The app reads the log and writes only its own settings files, plus the new version of itself when it installs an update. It never talks to a proxy, so it cannot approve a call or weaken a decision, and proxies run the same when it is closed. It contacts github.com only to check for updates and to download them. It is a separate crate, outside the proxy's build, so its dependencies do not reach the proxy.

## Run it

You need Rust and `tauri-cli` (`cargo install tauri-cli --version "^2" --locked`).

```sh
cd desktop
cargo tauri build --bundles app
open "target/release/bundle/macos/MCP Guardrail.app"
```

A build from a clone stays in `target/release/bundle/macos/`. [INSTALL.md](../INSTALL.md) copies it to `~/Applications/MCP Guardrail.app` and opens that copy.

The app reads `~/.local/state/mcp-guardrail/audit.jsonl`, the path in the root README's quick start. To watch another file, open Settings, and on the General tab either type the path of that file and save it, or press Choose… and pick the folder that holds `audit.jsonl`. You can also launch with `MCP_GUARDRAIL_AUDIT_LOG` set:

```sh
open --env MCP_GUARDRAIL_AUDIT_LOG=/abs/path/audit.jsonl "target/release/bundle/macos/MCP Guardrail.app"
```

Point each proxy at that file with `--audit-log`. Several proxies can share one file. macOS asks for notification permission at first launch.

## Settings

The app has two windows. The main window is the dashboard: stats, sessions, recent calls, and banners about the log and the settings file. The Settings window holds the settings. It has two tabs in a toolbar at the top:

- General: the audit log path and the blocked-call notifications checkbox.
- Updates: the version, the update mode, the update status, and the update buttons.

Open the Settings window in one of these ways:

- Click "Settings…" in the tray. The General tab opens.
- Click "Check for Updates…" in the tray. The check starts, and the Updates tab opens.
- Click Settings… in the dashboard header. The General tab opens.
- Press Cmd+, (Ctrl+, on Linux) in either window.

The Settings window has a fixed size. Close it when you are done. The app keeps running in the tray, and the window opens again on the tab you ask for. To move between tabs with the keyboard, focus a tab, then press the Left and Right arrow keys.

The General tab holds the audit log path. A saved path takes effect within one poll, with no relaunch. The dashboard then shows only the new file. Lines already in that file load as history and raise no notification.

The path must be a full path that starts with `/`. The app does not expand `~`. A file that does not exist yet saves, because a proxy creates the log when it starts. Choose… picks a folder, not a file, and saves `audit.jsonl` in that folder as the path, so it works before any proxy has made the log. A log with another file name needs a typed path. A folder, a device, or a file the app cannot read shows an error, and the previous path stays. When `MCP_GUARDRAIL_AUDIT_LOG` is set, the General tab disables the path field, Choose…, and Save.

The app saves its settings to `settings.json` and reads that file at launch:

- macOS: `~/Library/Application Support/com.bostonaholic.mcp-guardrail/settings.json`
- Linux: `$XDG_CONFIG_HOME/com.bostonaholic.mcp-guardrail/settings.json`, else `~/.config/com.bostonaholic.mcp-guardrail/settings.json`

At launch, `MCP_GUARDRAIL_AUDIT_LOG` wins when it is set. Then comes the saved path, then the default path.

Clear the "Notify me when a call is blocked" checkbox to stop notifications. The table and the tray still update. Alerts that the app drops while the box is clear never replay when you check it again. The checkbox works while `MCP_GUARDRAIL_AUDIT_LOG` is set.

If the app cannot read `settings.json` at launch, it uses the defaults and shows a banner on the dashboard that names the file. The next save replaces the file. To reset the settings, delete `settings.json`.

## Notifications on macOS

Each blocked call reaches Notification Center within about 3 seconds. Open it to see the alerts. macOS decides whether a banner also pops up, using the app's setting in System Settings > Notifications and any Focus mode. The app needs a bundle signature whose identifier matches its bundle id, so `tauri.conf.json` signs ad hoc. Downloaded releases carry that ad hoc signature too, so macOS blocks them until you clear the quarantine flag, as the release notes explain. A Developer ID signature would remove that step.

## Updates

Click "Check for Updates…" in the tray, or Check now on the Updates tab of the Settings window, to start a check. A tray check also opens the Updates tab, which shows the result. When a check has found a new version, the tray item reads "Update Available…" and opens the Updates tab. The app reads one file, `https://github.com/bostonaholic/mcp-guardrail-proxy/releases/latest/download/mcp-guardrail-desktop-update.json`, and compares its version with the running version.

The Updates tab has three update modes:

- Off: the app makes no check until you start one.
- Notify: the app checks on a schedule and sends one notification for each new version. This is the default.
- Install: the app checks on a schedule and installs each new version, then asks you to restart. A copy that cannot install acts as Notify.

In Notify and Install, the first check happens about one minute after launch. The next check is due 24 hours after a check that worked, or 1 hour after a check that failed. A check that you start also sets the next due time.

The app saves the mode in `updates/settings.json` in its config folder. This file is separate from the `settings.json` that the General tab writes, and neither save changes the other file. On macOS the update file is `~/Library/Application Support/com.bostonaholic.mcp-guardrail/updates/settings.json`. On Linux it is `$XDG_CONFIG_HOME/com.bostonaholic.mcp-guardrail/updates/settings.json`, by default under `~/.config`. The file has three keys, and each is optional:

- `update_mode`: `off`, `notify`, or `install`. The app writes it only after you choose a mode.
- `notified_version`: the highest version the app told you about. A version at or below it gets no second notification.
- `failed_version`: the highest version whose install failed. A version at or below it never installs automatically. The Install button still tries it.

Delete the file to reset all three. A file that the app cannot read gives Notify, and the Updates tab names the problem. Two app processes whose saves overlap can lose one change.

Only a copy from a release `.dmg` or `.AppImage` can install itself. A `.deb`, an `.rpm`, or a build from a clone tells you about a new version and shows Open release page in place of Install. A copy that runs from the mounted `.dmg` volume cannot replace itself, so its install fails, and the app does not try that version again automatically. Copy the app to a folder you can write first.

On the Updates tab, Install downloads and installs the version the last check found. After an install, Restart starts the new version. The app never restarts by itself. Open release page opens `https://github.com/bostonaholic/mcp-guardrail-proxy/releases/latest` in your browser.

## What the audit log cannot show

- Taint lags by one call. An audit line records the level from before its call, so a call that taints a session shows up on that session's next call.
- Ended sessions stay listed, because the log has no end-of-session record.
- An audit sink failure is invisible here. The failed line goes to stderr as `audit-fallback:`, not to the log.
- Lines already in the log at launch load as history and raise no notification. If the first read fails, the first read that works counts as that launch read.
- A replacement log that grows past the old read position between two polls goes unnoticed, because the app polls by size. Its earlier lines are lost to the dashboard. The proxy only appends, so only an outside rotation can cause this.

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

`src/audit.rs` turns log lines into dashboard state and does no I/O. `src/tail.rs` follows the file. `src/watch.rs` decides what each poll publishes and whether it may notify. `src/monitor.rs` joins the tail, the dashboard, and the poll decision for one watched log. `src/update.rs` is the pure update machine, which decides each update check, install, and notice. `src/tail.rs`, `src/watch.rs`, and `src/update.rs` hold state machines that `cargo test` walks against `../specs/graphs`. `src/settings.rs` holds the app's own settings. `src/update_settings.rs` reads and writes the update settings file. `src/updater.rs` is the only module that reaches the network. `src/notify.rs` sends the notifications. `src/main.rs` holds the tray, the two windows, the commands, the poll thread, and the update thread. `ui/index.html` and `ui/app.js` are the dashboard. `ui/settings.html` and `ui/settings.js` are the Settings window. Every audit value reaches the page through `textContent`, because tool names and URIs can hold attacker-influenced text.
