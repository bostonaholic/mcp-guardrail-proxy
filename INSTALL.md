# Install

An agent that follows these steps builds the binary, tests it, builds the desktop app on macOS, finds your MCP servers, and asks you once before it edits any MCP client config. You can also do the steps yourself.

## Steps

Agents: do the steps in order. If a step fails, stop. Show the user the command and its full output. Do not guess a fix.

Two kinds of failure end only one row of the approved table, not the run:

- In step 6, and in the writes of Undo and Upgrade, a failed row is rolled back and shown. Then the next row runs.
- In step 7, and in the probes of Upgrade, a failed row is never rolled back. It gets the step 7 actions for a failed probe. Then the next row runs.

Every other failure stops the run.

You need macOS or Linux, a POSIX shell, and Rust 1.85 or later.

1. Run `cargo --version`. If `cargo` is absent, stop and tell the user to install Rust from <https://rustup.rs>. If the version is below 1.85, stop and tell the user to run `rustup update`.

2. Install the binary. The crate is not on crates.io, so cargo builds it from GitHub. The build takes several minutes, so give the command a timeout of at least 10 minutes.

   ```sh
   cargo install --git https://github.com/bostonaholic/mcp-guardrail-proxy mcp-guardrail-proxy --locked
   ```

3. Test the binary. The binary holds the default policy, so you need no policy file. Run this block in one shell.

   ```sh
   BIN="$(command -v mcp-guardrail-proxy || echo "${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}/bin/mcp-guardrail-proxy")"
   printf '%s\n' "$BIN"
   "$BIN" check-policy
   echo '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}' \
     | "$BIN" proxy -- cat
   ```

   Expect the full path, then a line that starts with `policy OK:`. The last command sends a call that reads `/etc/shadow` through the proxy to `cat`. Expect exactly one line on stdout, the reply, which holds `"code":-32001`. `cat` echoes what it receives, so a second stdout line means the call leaked. The audit line on stderr holds `"decision":"deny"`.

   `<BIN>` in the steps that follow is the full path that this block printed.

4. Install the desktop app. The tray app shows sessions and recent calls and notifies you when a call is blocked. It builds from a clone, and this step is for macOS. On Linux, or if the user asks for the proxy only, skip to step 5. See [desktop/README.md](desktop/README.md).

   Run each of the five commands that follow as its own tool call. Each one fits in a 10-minute tool timeout.

   1. Pick the source folder. Give this command a timeout of 5 minutes, because a new clone downloads the repository.

      ```sh
      (
        set -e
        TOP="$(git rev-parse --show-toplevel 2>/dev/null || true)"
        if [ -n "$TOP" ] && grep -q '"com.bostonaholic.mcp-guardrail"' "$TOP/desktop/tauri.conf.json" 2>/dev/null; then
          SRC="$TOP"
        elif [ -d "$HOME/.local/share/mcp-guardrail/src/.git" ]; then
          SRC="$HOME/.local/share/mcp-guardrail/src"
          git -C "$SRC" pull --ff-only
        else
          SRC="$HOME/.local/share/mcp-guardrail/src"
          mkdir -p "$HOME/.local/share/mcp-guardrail"
          git clone https://github.com/bostonaholic/mcp-guardrail-proxy "$SRC"
        fi
        printf '%s\n' "$SRC"
      )
      ```

      The last line of the output is the source folder. `<SRC>` in the commands that follow is that path. When the current folder is in a clone of this project, the command uses that clone and never pulls it. Otherwise it uses `~/.local/share/mcp-guardrail/src`, and pulls or clones it. That folder stays after the session ends.
   2. Install `tauri-cli` when no 2.x version is installed. Give this command a timeout of 10 minutes. The install took about 7.5 minutes on one Mac.

      ```sh
      cargo tauri --version 2>/dev/null | grep -q '^tauri-cli 2\.' || cargo install tauri-cli --version "^2" --locked
      ```

      A version check that prints `tauri-cli 2.` and a version number skips the install.
   3. Build the app. Give this command a timeout of 10 minutes.

      ```sh
      cd "<SRC>/desktop" && cargo tauri build --bundles app -- --locked
      ```

      `--locked` keeps `desktop/Cargo.lock` unchanged, so a later `pull --ff-only` does not stop on a local change. The build is not notarized, so expect a warning that notarization was skipped. Nobody has observed that warning with these steps.
   4. Stop a running copy, replace the app in `~/Applications`, and open it. Give this command a timeout of 1 minute.

      ```sh
      pkill -f '/MCP Guardrail[.]app/Contents/MacOS/' || true
      rm -rf "$HOME/Applications/MCP Guardrail.app"
      mkdir -p "$HOME/Applications"
      ditto "<SRC>/desktop/target/release/bundle/macos/MCP Guardrail.app" "$HOME/Applications/MCP Guardrail.app"
      open "$HOME/Applications/MCP Guardrail.app"
      ```

      `ditto` keeps the bundle signature. The `rm -rf` comes first, because `ditto` onto an old bundle keeps files that the new version deleted.
   5. Check that the app runs. Give this command a timeout of 1 minute.

      ```sh
      pgrep -f '/MCP Guardrail[.]app/Contents/MacOS/'
      ```

      Expect one process id. If none prints, wait 5 s and run it once more. If none prints again, stop. At first launch, macOS asks the user for notification permission. Do not wait for the answer.

5. Find the servers. Read the configs yourself, and do not ask for a client or a path.

   1. Read each config file in the [client reference](#client-reference) for this platform. Skip a file that does not exist.
   2. Give each server entry one status. Check the statuses in this order, and use the first that applies:
      - `already wrapped`: `command` equals `mcp-guardrail-proxy` or ends in `/mcp-guardrail-proxy`. Also, `args` starts with `proxy` and holds at least one token after its first `--`.
      - `remote`: the entry has a `type` that is not `stdio`. Or it has a `url`, `httpUrl`, or `serverUrl` key, even an empty one, and no `command`.
      - `disabled`: the client does not start the entry. That means `enabled = false`, `"disabled": true`, a local-scope entry whose project folder does not exist, or a plugin that `claude plugin list --json` shows with `"enabled": false`.
      - `malformed`: the file does not parse, so every entry in it is `malformed`. Or the entry has neither `command` nor a remote key. Or `command` is not a string. Or `args` is present and is not a list of strings. Or an `env` key is empty or holds `=`. Or `command` passes the `already wrapped` test for `command` and `args` does not, with the note `runs the proxy binary in another form`.
      - `wrappable`: every other entry. An entry with no `args` key is `wrappable`.

      A Claude Code plugin moves as one unit, so two statuses apply to all rows of an enabled plugin. Check them after the statuses above, in this order:
      - `malformed`, with the note `plugin has a malformed server: <name>`, when one row of the plugin is `malformed`.
      - `name taken`, when one of the plugin's server names is already in use. In use means a server in `~/.claude.json`, at user scope or in a project, or a server of another enabled user-scope plugin. This status replaces only `wrappable` and `remote`. The note names the other server and its scope.
   3. Work out the new upstream command of each `wrappable` entry, in this order:
      - A bare command, one with no `/`, becomes the output of `sh -c 'command -v -- "$1"' sh '<command>'` when that output starts with `/`. Else keep it, with the note `not found on PATH`. When `env` sets `PATH`, keep the bare command, with the note `uses the entry's PATH`. GUI clients often lack `npx`, `bun`, `uvx`, and `docker` on their `PATH`, so the absolute path matters.
      - A relative command, one with a `/` that does not start with `/`, becomes `<cwd>/<command>` when `cwd` starts with `/`. Keep `cwd` in the entry. Else keep the command, with the note `relative command`.
      - In a plugin row, replace every `${CLAUDE_PLUGIN_ROOT}` in `command`, `args`, `env` values, and `cwd` with the plugin's `installPath`. Do this first. Add the note `${CLAUDE_PLUGIN_ROOT} resolved, re-wrap after a plugin update`.
      - Keep every other client variable, such as `${HOME}`, as written. The client expands it before it starts the proxy.
      - Docker with `-e NAME` and an `env` block works unchanged, because the proxy passes its environment to the upstream. Add the note `Docker with -e, the env passes through`.
   4. Add these notes where they apply:
      - `moves the plugin's servers to user scope and disables the plugin`, on each row of an enabled plugin.
      - `moved to user scope by the guardrail`, on a `disabled` plugin that has a key in the plugin move record of step 6.
      - `an arg names mcp-guardrail-proxy`, when an arg equals `mcp-guardrail-proxy` or ends in `/mcp-guardrail-proxy`. Such an entry can run the proxy through an outer command, such as `env`. Wrapping it again still works.
      - `probe not run: <reason>`, when step 7 cannot start the entry as its client does. The reasons are `client variable` (a `$` in `command`, `args`, an `env` value, or `cwd`), `cwd is not absolute`, `relative command` (the command is still relative), and `relative argument` (an arg starts with `./` or `../`, and no `cwd` starts with `/`). Step 6 still wires the row.
   5. Show the user one table with the columns `#`, `Client`, `Config file`, `Scope`, `Server`, `Status`, and `Note`. List every entry you found, with one status each.
   6. Below the table, list each `wrappable` row. These rows are the default selection. A plugin with a `wrappable` row is selected with all of its rows, and its `remote` rows move as they are. For each row, give the exact new entry or command from step 6, every file it changes, and each backup path.
   7. End the message with one request: reply yes to apply the listed rows, or name the rows to leave out. The user approves or leaves out a plugin as one unit.
   8. Wait for the reply. This is the only time the install waits for the user.

   If no entry is `wrappable`, tell the user so and stop. A second full run of these steps stops here, because every wired entry is `already wrapped`.

6. Wire the approved rows. Run this command first:

   ```sh
   mkdir -p ~/.local/state/mcp-guardrail
   ```

   `<AUDIT>` is the full path of `~/.local/state/mcp-guardrail/audit.jsonl`, the file the desktop app reads. JSON does not expand `~` or `$HOME`, so write the full path.

   Each wired entry gets this `command` and `args`. Keep the entry name and every other key, such as `env`, `cwd`, and `type`.

   ```json
   "<name>": {
     "command": "<BIN>",
     "args": ["proxy", "--audit-log", "<AUDIT>", "--", "<command>", "<arg>", "..."]
   }
   ```

   `<command>` is the upstream command from step 5. Put all of the old `args` after it. If the old entry has no `args`, end the list at `<command>`. To keep a custom policy for this row, put `"--policy"` and its absolute path before `"--"`.

   For each row, do these steps:

   1. Back up the file before the row's write to it, with `command cp -pf '<file>' '<file>.bak-guardrail'`. `command` skips a `cp -i` alias, and `-p` keeps the file mode. The backup holds the file from right before the latest write.
   2. Write the row with the writer in its client reference row.
   3. If the write or its re-parse fails, roll back the row, show the command and its output, and go to the next row.

   Quote every value from a config file as one single-quoted shell word, and write each `'` in it as `'\''`. Pass an `env` pair as one word, `'NAME=value'`, after `env --`. Never let the shell parse a key or a value.

   Warning: during `claude mcp add-json` and an `env --` probe, the `env` values of the entry, such as tokens, are in a process argument list. Another user on the same machine can read it with `ps` while the command runs.

   The writers:

   - Claude Code, user scope. Run `claude mcp remove '<name>' --scope user`. Then pass the new entry, on one line, through a quoted heredoc:

     ```sh
     claude mcp add-json '<name>' "$(cat <<'JSON'
     {"command":"<BIN>","args":["proxy","--audit-log","<AUDIT>","--","<command>","<arg>"],"env":{"NAME":"<value>"}}
     JSON
     )" --scope user
     ```

     `<<'JSON'` turns off shell expansion, so the entry needs only JSON escapes. If `add-json` fails, add the old entry back the same way, as step 5 read it, and report the row.
   - Claude Code, local scope. Run the same two commands with `--scope local`, in the project folder of the entry.
   - Codex. Edit `~/.codex/config.toml` in place. In `[mcp_servers.<name>]`, change only the values of `command` and `args`. If the table has no `args`, add it on the line after `command`. Do not touch any other key or subtable, such as `cwd`, `enabled`, or `[mcp_servers.<name>.env]`. Write each value as a TOML basic string, with `"` and `\` escaped. Then re-parse with `codex mcp get '<name>' --json > /dev/null`. If `codex` is not on `PATH`, re-parse with `python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' ~/.codex/config.toml`, which needs Python 3.11 or later. If the re-parse fails, or neither command can run, restore the file with `command cp -f ~/.codex/config.toml.bak-guardrail ~/.codex/config.toml` and report the row.
   - Claude Code plugin. Never edit a plugin's own files, because a plugin update undoes the edit. Move the plugin's servers to user scope in its place, and record the move in `~/.local/state/mcp-guardrail/plugin-moves.json`. The record is one JSON object. Each key is `<plugin>@<marketplace>`, and its value lists the server names that the move added. This writer changes `~/.claude.json`, `~/.claude/settings.json`, and the record, so back up all three first. Skip the record backup when the record does not exist.
     1. If the record does not exist, write it as `{}`. Add the plugin's key with the value `[]`. Re-parse the record with `python3 -m json.tool`. If that fails, restore the record with `command cp -f`, report the row, and run no `claude` command for it.
     2. Run `claude plugin disable '<plugin>@<marketplace>' --scope user`.
     3. For each server of the plugin, run `claude mcp add-json` at user scope, as for a user-scope row. Wrap a stdio server. Add a remote server as it is.
     4. After each `add-json` passes, append the server name to the plugin's key, and re-parse the record.

     Roll back a failed plugin row in this way:
     - If `claude plugin disable` fails, run `claude plugin list --json`. If it still shows the plugin with `"enabled": true`, remove the plugin's key from the record. Else keep the key.
     - If an `add-json` fails, run the Undo of this plugin: `claude plugin enable`, then `claude mcp remove` for each server in its key, then remove the key. If `claude plugin enable` fails, stop there, and keep the added servers and the key.
     - If an append fails, run `claude mcp remove '<name>' --scope user` for the server just added. Then restore the record with `command cp -f '<record>.bak-guardrail' '<record>'`. If the remove passed, do the rollback of a failed `add-json`. If the remove failed, stop, and report that server as moved and not recorded, with its remove command.
   - JSON clients. Edit the entry in place and keep every other key. Then re-parse with `python3 -m json.tool '<file>' > /dev/null`. If it fails, restore the file with `command cp -f '<file>.bak-guardrail' '<file>'` and report the row.

   Never write `~/.claude.json` or `~/.claude/settings.json` yourself. Claude Code rewrites them while it runs, and only the `claude` CLI writes them safely. For the same reason, never copy their backups over them.

7. Check each wired row, then tell the user what to restart. This step writes nothing, so it never rolls back a row.

   1. Probe each row that has no `probe not run` note. Build the probe from the row's new `args`:
      - The upstream is every token after the first `--`.
      - A `--policy <file>` or `--policy=<file>` before that `--` becomes `--policy '<file>'` in the probe. Leave out `--audit-log` and `--session-id`, because `probe` takes neither.
      - Add `cd -- '<cwd>' &&` only when the entry has `cwd`. Add `env -- 'NAME=<value>'...` only when it has `env`.

      ```sh
      (cd -- '<cwd>' && env -- 'NAME=<value>' "<BIN>" probe --policy '<file>' -- '<command>' '<arg>')
      ```

      Give each probe call a timeout of 10 minutes. A probe exits 0 when the server lists the same tools directly and through the proxy.
   2. If a probe call reaches the 10-minute timeout, report `probe did not end` for the row. One cause is a process that the server started and that keeps stderr open. Then go to the next row.
   3. If a probe exits 1, find the cause in the stderr line that contains `mcp-guardrail-proxy: probe`. Search for the text, because server output can come first on the same line. Then do these actions in order:
      1. If the cause is a timeout, and the upstream command is `npx`, `bun`, `uvx`, or `docker`, bare or as a full path, run the probe once more with `--timeout 240`. Such a server can download a package on its first start. If the second probe exits 0, the row passes.
      2. Run the entry's own `command` and `args`, quoted as in step 6, with `< /dev/null`. The proxy ends this run within about 6 s.
      3. Show the user every probe output and the output of that run.
      4. In the final report, offer the undo of the row: an Undo request that names the row. For a plugin row, offer the Undo of the whole plugin, and name its other servers, because that Undo removes them too. Do not wait for a reply.
      5. Go to the next row.

      A server that holds a lock file or a port can fail its probe while a client runs its own copy of it. Name this as one possible cause when the user has the client open.
   4. For each Claude Code row, run `claude mcp get '<name>'`. It reports if the server connects.
   5. Give the final report. List each wired row with its probe result, or the reason no probe ran. List the tools that the probe shows as `deny` or `require-approval` in a tainted session. Name the rows that have only probe evidence, and the clients to restart, with the restart from the client reference. For Claude Code, say that a new session is necessary, because the current session keeps the old server.

The binary embeds `policies/default-policy.toml`. To change the rules, copy that file, edit the copy, and pass it with `--policy`. Run `check-policy --policy <file>` on the edited copy before you wire it in.

From a clone, run `cargo install --path . --locked` in place of step 2.

Releases after 0.2.0 attach a prebuilt binary for macOS and Linux, so you can skip Rust and steps 1 and 2. Download `mcp-guardrail-proxy-<version>-<platform>.tar.gz` from the [releases page](https://github.com/bostonaholic/mcp-guardrail-proxy/releases), then run this block in the download folder. It puts the binary in `~/.local/bin`, which must be on your `PATH` for step 3. The `xattr` line is for macOS, which blocks a binary that a browser downloaded.

```sh
mkdir -p ~/.local/bin
tar -xzf mcp-guardrail-proxy-*.tar.gz -C ~/.local/bin
xattr -dr com.apple.quarantine ~/.local/bin/mcp-guardrail-proxy
```

## Client reference

Step 5 reads these files. "Tested" says where the facts in a row come from. A row marked "no" comes from the client's documentation, read on 2026-11-07, and nobody has wired that client with these steps. Check its documentation before you rely on the row.

| Client | Config file | Where servers live | Writer | Re-parse | Restart | Tested |
|---|---|---|---|---|---|---|
| Claude Code, user scope | `~/.claude.json`, macOS and Linux | top-level `mcpServers` | `claude mcp remove`, then `claude mcp add-json`, with `--scope user` | the `claude` CLI checks the entry; `claude mcp get '<name>'` reports the connection | start a new session | yes, install transcript |
| Claude Code, local scope | `~/.claude.json`, macOS and Linux | `projects.<project path>.mcpServers` | the same two commands with `--scope local`, run in the project folder | the same | start a new session in that folder | yes, install transcript |
| Claude Code, plugin | the plugin's `installPath` from `claude plugin list --json`, for entries with `"scope": "user"`. The servers are in `<installPath>/.mcp.json`, at its top level or under `mcpServers`, or under `mcpServers` in `<installPath>/.claude-plugin/plugin.json`. | as in the file | the plugin writer in step 6 | `python3 -m json.tool` for the record | start a new session | yes, install transcript. These paths are Claude Code internals that can change. A server list in another shape makes its rows `malformed`. |
| Codex | `~/.codex/config.toml`, macOS and Linux | `[mcp_servers.<name>]`, with `enabled = false` for a disabled server | the TOML recipe in step 6 | `codex mcp get '<name>' --json > /dev/null` | start a new session | yes, install transcript |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`, macOS only | `mcpServers` | the JSON writer in step 6 | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no, from the client's documentation |
| Cursor | `~/.cursor/mcp.json`, macOS and Linux | `mcpServers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no, from the client's documentation |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` on macOS, `~/.config/Code/User/mcp.json` on Linux | `servers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no. The documentation puts `mcp.json` in the user profile but does not give the path. A file with comments does not parse, so its entries are `malformed`. |
| Windsurf | `~/.codeium/windsurf/mcp_config.json`, macOS and Linux | `mcpServers`, with `"disabled": true` for a disabled server | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no. The path comes from the VS Code documentation, not checked against Windsurf's own documentation. |
| Gemini CLI | `~/.gemini/settings.json`, macOS and Linux | `mcpServers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | start a new session | no, from the client's documentation. `gemini mcp disable` records a disabled server in `~/.gemini/mcp-server-enablement.json`, which step 5 does not read. |

To undo a row, use [Undo](#undo).

## Undo

Undo needs no backup. It rebuilds each original entry from its wrapped entry, so it works for a row wired in any pass, and it keeps edits made after the wiring. When the request names a client or a server, undo only those rows. A request that names the change needs no approval table.

1. Run the step 5 scan. The rows to undo are the `already wrapped` rows. Read the plugin move record, `~/.local/state/mcp-guardrail/plugin-moves.json`. A user-scope server whose name is in a record key belongs to that plugin's move, not to a user-scope row.
2. Rebuild each row. The new `command` is the first token after the first `--` in `args`. The new `args` is every token after that one, or `[]` when there is none. Keep every other key as it is now.
3. Write each row:
   - Claude Code, user or local scope: read the entry from `~/.claude.json`, but never write that file. Run `claude mcp remove '<name>' --scope <scope>`. Then run `claude mcp add-json` with the rebuilt entry through the heredoc of step 6, with the same `--scope`. For local scope, run both commands in the project folder of the entry. If that folder no longer exists, report `project folder gone` with its path, and change nothing in the row. If `add-json` fails, add the wrapped entry back as you read it, and report the row.
   - Codex and the JSON clients: back up the file with `command cp -pf '<file>' '<file>.bak-guardrail'`. Set `command` and `args` of the row to the rebuilt values. Re-parse the file with the command in its client reference row. If the re-parse fails, run `command cp -f '<file>.bak-guardrail' '<file>'` and report the row.
4. Undo each plugin move that the request covers, one record key at a time:
   1. Run `claude plugin enable '<plugin>@<marketplace>' --scope user`. If it fails, stop for this plugin, keep its key, and report it.
   2. Run `claude mcp remove '<name>' --scope user` for each name in the key. Report a name that is no longer there.
   3. Back up the record, remove the key, and re-parse the record with `python3 -m json.tool`.

   If the request covers Claude Code and the record does not exist, say so. Then rebuild each wrapped user-scope server as a user-scope row, and enable no plugin. Tell the user to run `claude plugin enable` for each plugin they want back.
5. Report each row that now has a full path where the original had a bare or relative command. That path runs the same program. Then name the clients to restart, with the restart from the client reference.

## Upgrade

Do these steps in order when the user asks for an upgrade.

1. Upgrade the binary: run step 2 again. When the installed binary came from another commit, cargo prints `Replaced package` and replaces it. When it came from the same commit, cargo prints `is already installed, use --force to override`, exits 0, and keeps the binary. Both were observed in a sandbox on 2026-11-07.
2. Run the step 5 scan. Probe each `already wrapped` row by the rules of step 7. A failed probe gets the step 7 actions.
3. If `<BIN>` changed, re-wire each `already wrapped` row whose `command` is not the new `<BIN>`. A switch between `cargo install` and the prebuilt binary changes `<BIN>`.
   - Set only `command` to the new `<BIN>`. Keep `args`, `env`, `cwd`, and every other key.
   - Write the row with its writer from the client reference, and back up the file first. A Claude Code row gets `claude mcp remove`, then `claude mcp add-json` with the entry as read and the new `command`.
   - For a local-scope row whose project folder is gone, report `project folder gone`, and do not re-wire it.
   - The server names do not change, so the plugin move record stays valid.
4. On macOS, upgrade the app: run step 4 again from step 4.1. If step 4.1 picks the current clone, it does not pull it. Then say in the report that you did not pull that clone. Tell the user to pull it and ask for the upgrade again to get a newer app.
5. After a plugin update, the moved servers still point at the old `installPath`. Run the Undo of that plugin, then run the steps again from step 5.
6. After a runtime upgrade, such as a new Node version from a version manager, probe the rows again as in item 2. A full path that step 6 wrote can point at a removed version.

Policy files from an earlier version still load, because the policy format does not change.

## Uninstall

`INSTALL.md` owns these paths, and Uninstall removes only them:

- `~/Applications/MCP Guardrail.app`
- `~/.local/state/mcp-guardrail/`, which holds the audit log and `plugin-moves.json`
- each `<file>.bak-guardrail`
- the binary, at the cargo path of step 3 or at `~/.local/bin/mcp-guardrail-proxy`

The user owns the removal of `~/.local/share/mcp-guardrail/src`, because a clone can hold their own work.

Do these steps in order. Ask no question.

1. Run the step 5 scan. Before any undo write, note each distinct `command` of the `already wrapped` rows. Resolve a bare `mcp-guardrail-proxy` with the `BIN` line of step 3. If no row is wrapped, note the output of that line.
2. Run [Undo](#undo) for every wired row. If Undo reports a row that it did not undo, other than a `project folder gone` row, stop here. List those rows and remove nothing, so they keep working in their clients.
3. Stop the app and remove it:

   ```sh
   pkill -f '/MCP Guardrail[.]app/Contents/MacOS/' || true
   rm -rf "$HOME/Applications/MCP Guardrail.app"
   ```

4. Run the step 5 scan again. List each row with the note `an arg names mcp-guardrail-proxy`. Warn the user that such a row stops working if it runs the binary through an outer command, such as `env`. Do not stop for these rows.
5. Remove each binary that step 1 noted, by the first rule that its path matches:
   - `${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}/bin/mcp-guardrail-proxy`: run `cargo uninstall mcp-guardrail-proxy`.
   - `$HOME/.local/bin/mcp-guardrail-proxy`: run `command rm -f -- "$HOME/.local/bin/mcp-guardrail-proxy"`.
   - Any other path, or a path that does not exist: leave it, and name it in the report.
6. Leave `~/.local/share/mcp-guardrail/src` and its parent folder in place. If the clone exists, name it in the report, and say that it can hold the user's own work. Give the user these two commands to run after they check it. Do not run them yourself.

   ```sh
   rm -rf "$HOME/.local/share/mcp-guardrail/src"
   rmdir "$HOME/.local/share/mcp-guardrail"
   ```

7. Name the audit log, `~/.local/state/mcp-guardrail/audit.jsonl`, in the report. It is the only record of the proxy's decisions. Then remove its folder:

   ```sh
   rm -rf "$HOME/.local/state/mcp-guardrail"
   ```

8. For each config file in the client reference for this platform, and for `~/.claude/settings.json`, remove `<file>.bak-guardrail` if it exists. Use `command rm -f -- '<file>.bak-guardrail'`.
9. Run `cargo uninstall tauri-cli` only when the user's request names `tauri-cli`.
