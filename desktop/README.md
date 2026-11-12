# MCP Guardrail desktop

A tray app that watches the proxy's audit log. It shows sessions and recent calls, and sends a notification when a call is blocked. It also checks for its own updates.

The app reads the log. For its Servers tab, it also reads the MCP client config files that [INSTALL.md](../INSTALL.md#client-reference) lists. It writes its own settings files, plus the new version of itself when it installs an update. When you press Wrap on the Servers tab, it also writes the client config files of the rows you selected, a backup and a kept copy of each, and the audit log's folder and file. The tab starts your login shell to read its `PATH`, and a wrap first runs `mcp-guardrail-proxy check-policy`. It never talks to a proxy, so it cannot approve a call or weaken a decision, and proxies run the same when it is closed. It contacts github.com only to check for updates and to download them. It is a separate crate, outside the proxy's build, so its dependencies do not reach the proxy.

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

The app has two windows. The main window is the dashboard: stats, sessions, recent calls, and banners about the log and the settings file. The Settings window holds the settings. It has three tabs in a toolbar at the top:

- General: the audit log path and the blocked-call notifications checkbox.
- Updates: the version, the update mode, the update status, and the update buttons.
- Servers: the MCP servers that the proxy does not wrap. See [Servers](#servers).

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

## Servers

The Servers tab lists each MCP server in your client config files that the proxy does not wrap. The app scans when you open the tab and when you press Scan again. It reads the files of the [client reference](../INSTALL.md#client-reference) in `INSTALL.md`, except the Claude Code plugin row. It reads each file whole, with no size cap.

Each row shows the client, the scope, the server name, the status, and the reason. The scope is `user`, or `local:` and the project folder for a Claude Code local-scope server. The tab gives each server the status of `INSTALL.md` step 5.2:

- `remote`: the server runs over HTTP or SSE, which the proxy does not wrap.
- `disabled`: the client has the server turned off, or the server's Claude Code project folder is gone.
- `malformed`: the entry breaks a step 5.2 rule, and the reason names the rule. A file that does not parse gives one `malformed` row for the whole file, with the line and the column of the error.
- `wrappable`: the proxy can wrap the server.
- `unreadable`: the app cannot read the file. The path is a folder, a named pipe, or another non-file, the app has no permission to read it, or its bytes are not UTF-8 text. This status is the app's own, not part of step 5.2.

The tab counts the `already wrapped` servers and does not list them. When it finds no client config file, it says so. When every server it finds is wrapped, it says that too.

The tab never shows a `command`, `args`, or `env` value, because those values can hold tokens. A parse error shows only its line and column, because a parser's message can quote the bad value.

Claude Code plugin servers are not listed. When `~/.claude.json` exists, the tab says so. The install steps in [INSTALL.md](../INSTALL.md) wrap plugin servers.

### Wrap

The tab shows the binary and the audit log that a wrap writes into each entry. The binary is the first `mcp-guardrail-proxy` on your login shell's `PATH`, else `${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}/bin/mcp-guardrail-proxy`, as in install step 3.

A macOS app that Finder starts gets a short `PATH`, which misses folders that a version manager adds. So each scan and each wrap runs your login shell once, as `"$SHELL" -i -l -c`, and reads the `PATH` that it prints. It runs `/bin/sh` when `SHELL` is not set or not a full path. That `PATH` finds the binary and each bare upstream command. When the shell fails, prints more than 64 KiB, or does not end within 10 s, the app uses its own `PATH`, and the tab says so in a note. The shell runs your startup files, so keep them quiet and fast. The audit log is the path that the dashboard watches. A row has a checkbox when the app can wrap it, and each checkbox starts checked. Press Wrap to wrap the checked rows. The tab shows one result line per row, then scans again. The result lines stay until the next Wrap or Scan again press.

Wrap is off for every row, with the reason in the banner, when:

- the app cannot find the binary, or the binary's path is not UTF-8;
- the audit log path is not a full UTF-8 path;
- the audit log path is a client config file of the table, also one that does not exist yet, or a link to one;
- the audit log path names a backup or a kept copy, directly or through a link, or it is a link to a file that does not exist;
- the platform is not macOS or Linux.

Before the first write, a press runs `mcp-guardrail-proxy check-policy`, as install step 3 does. It must exit 0 within 10 s and print `policy OK:` first, in at most 64 KiB. Else the wrap refuses, changes no file, and shows the exit status and the last line that the binary printed to stderr. This stops a wrap that would point every server at a binary that cannot start, such as one that macOS quarantines.

A press also refuses the whole wrap, and changes no file, when the audit log is a folder or another non-file, or when its folder cannot be created or the file does not open for append. A missing log becomes an empty file with mode 0600, as the first proxy start would make it.

For each row, the app reads the file again and checks the entry again. A server that is gone, or that is no longer `wrappable`, is skipped with the reason. The app then writes the entry of `INSTALL.md` step 6. It changes only the values of `command` and `args`, and every other byte of a JSON file stays as it was. `command` becomes the binary. `args` becomes `proxy`, `--audit-log`, the log path, `--`, the old command, and the old `args`. A bare command that the app finds on the login shell's `PATH` becomes its full path, as in step 5.3. A bare command that it does not find stays bare, with the note `not found on PATH`.

The app writes each file once per row, with a rename, in this order:

1. It writes `<file>.bak-guardrail`, a copy of the file before the row. The next wrap of a row in that file replaces it.
2. It writes the kept copy `<file>.bak-guardrail-<T>`, where `<T>` is the time in Unix seconds. No later backup write reaches the kept copy.
3. It writes the new text to a temp file beside the real file, with the file's group and mode. A symlinked dotfile stays a link, and its target gets the new text.
4. It reads the file again. When the bytes, the mode, the owner, or the group changed since its first read, the row fails with "changed while the app wrapped it. Scan again.", and the file stays as it is.
5. It renames the temp file over the file and reads the file back. New text means the row is wrapped, and the app removes the kept copy.

When the read after the rename shows other bytes, another program wrote the file after the app. The app leaves that file as it is, and the kept copy stays. The result names the kept copy.

The app cannot wrap a file whose group you are not in, because the new file must keep the old group. Change the file's group, then wrap again. A rename drops extended attributes and ACLs, as most editors do.

After a wrap, restart the client, as the client reference in `INSTALL.md` says: quit and reopen Claude Desktop, Cursor, VS Code, or Windsurf, or start a new Gemini CLI session. The app does not probe the wrapped server. To undo a wrap, use [Undo](../INSTALL.md#undo) in `INSTALL.md`.

The kept copy holds your `env` values, with mode 0600. The app removes it when a read confirms the end of the row. A result that names a kept copy means the copy stays until you remove it.

### Restore a server

Restore from the kept copy, not from `<file>.bak-guardrail`, because the next wrap of a row in that file replaces the backup. After a result names a kept copy, or after the app quits or stops during a wrap, look for `<file>.bak-guardrail-*` beside each client file.

Restore one entry, never the whole file. A copy of the kept copy over the file erases each later change to that file, by another program or by a later wrap.

For a JSON file:

1. Quit the client.
2. Find the server's entry in the kept copy.
3. In the file, set the `command` and `args` of that entry to the values in the kept copy. Remove `args` from the file's entry when the kept copy's entry has none. Change nothing else. When the entry is gone from the file, copy the whole entry from the kept copy into the file's server table.
4. Make sure that the file's entry shows the `command` and `args` of the kept copy. Then remove the kept copy, because it holds your `env` values.

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

`src/audit.rs` turns log lines into dashboard state and does no I/O. `src/tail.rs` follows the file. `src/watch.rs` decides what each poll publishes and whether it may notify. `src/monitor.rs` joins the tail, the dashboard, and the poll decision for one watched log. `src/update.rs` is the pure update machine, which decides each update check, install, and notice. `src/tail.rs`, `src/watch.rs`, and `src/update.rs` hold state machines that `cargo test` walks against `../specs/graphs`. `src/clients.rs` holds the client table and the scan rules of `INSTALL.md` step 5.2, and does no I/O. `src/servers.rs` reads the client config files for the Servers tab and writes the rows that Wrap wraps. `src/settings.rs` holds the app's own settings. `src/update_settings.rs` reads and writes the update settings file. `src/updater.rs` is the only module that reaches the network. `src/notify.rs` sends the notifications. `src/main.rs` holds the tray, the two windows, the commands, the poll thread, and the update thread. `ui/index.html` and `ui/app.js` are the dashboard. `ui/settings.html` and `ui/settings.js` are the Settings window. Every audit value reaches the page through `textContent`, because tool names and URIs can hold attacker-influenced text.
