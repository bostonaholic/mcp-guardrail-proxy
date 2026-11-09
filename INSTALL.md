# Install

An agent that follows these steps builds the binary, tests it, builds the desktop app on macOS, finds your MCP servers, and asks you once before it edits any MCP client config. You can also do the steps yourself.

## Steps

Agents: do the steps in order. If a step fails, stop. Show the user the command and its full output. Do not guess a fix.

Two kinds of failure end only one row of the approved table, not the run:

- In step 6, and in the writes of Undo and Upgrade, a failed row is rolled back and shown. Then the next row runs.
- In step 7, and in the probes of Upgrade, a failed row is never rolled back. It gets the step 7 actions for a failed probe. Then the next row runs.

Every other failure stops the run.

A path placeholder in a command, such as `<file>`, `<record>`, or a `--policy` path, is a full path. Replace a leading `~` with the value of `$HOME`. A shell does not expand `~` inside quotes, so `'~/.cursor/mcp.json'` names no file.

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

4. Install the desktop app. The tray app shows sessions and recent calls and notifies you when a call is blocked. It builds from a clone, and this step is for macOS. A clone build tells you about updates but cannot install them. On Linux, or if the user asks for the proxy only, skip to step 5. See [desktop/README.md](desktop/README.md).

   Run each of the five commands that follow as its own tool call, with the timeout that the command names.

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

      `--locked` keeps `desktop/Cargo.lock` unchanged. The build is not notarized, so expect a warning that notarization was skipped. Nobody has observed that warning with these steps.
   4. Stop a running copy, replace the app in `~/Applications`, and open it. Give this command a timeout of 1 minute.

      ```sh
      (
        set -e
        pkill -f '/MCP Guardrail[.]app/Contents/MacOS/' || true
        rm -rf "$HOME/Applications/MCP Guardrail.app"
        mkdir -p "$HOME/Applications"
        ditto "<SRC>/desktop/target/release/bundle/macos/MCP Guardrail.app" "$HOME/Applications/MCP Guardrail.app"
        open "$HOME/Applications/MCP Guardrail.app"
      )
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
      - `disabled`: the entry has `enabled = false` or `"disabled": true`. Or it is a local-scope entry whose project folder does not exist. Or it belongs to a plugin that `claude plugin list --json` shows with `"enabled": false`.
      - `malformed`: the file does not parse, so every entry in it is `malformed`. Or the entry has neither `command` nor a remote key. Or `command` is not a string. Or `args` is present and is not a list of strings. Or an `env` key is empty or holds `=`. Or `command` passes the `already wrapped` test for `command` and `args` does not, with the note `runs the proxy binary in another form`.
      - `wrappable`: every other entry. An entry with no `args` key is `wrappable`.

      A Claude Code plugin moves as one unit, so two statuses apply to all rows of an enabled plugin. Check them after the statuses above, in this order:
      - `malformed`, with the note `plugin has a malformed server: <name>`, when one row of the plugin is `malformed`.
      - `name taken`, when one of the plugin's server names is already in use. In use means a server in `~/.claude.json`, at user scope or in a project, or a server of another enabled user-scope plugin. This status replaces only `wrappable` and `remote`. The note names the other server and its scope.
   3. Work out the entry that step 6 writes. Each rule names the rows it applies to. Apply the rules in this order:
      1. Each `wrappable`, `remote`, or `already wrapped` row of an enabled plugin: replace every `${CLAUDE_PLUGIN_ROOT}` in `command`, `args`, `env` values, and `cwd` with the plugin's `installPath`. On each row where you replace one, add the note `${CLAUDE_PLUGIN_ROOT} resolved, re-wrap after a plugin update`. Step 6 moves these rows to user scope.
      2. Each `wrappable` row: work out the new upstream command.
         - A bare command, one with no `/`, becomes the output of `sh -c 'command -v -- "$1"' sh '<command>'` when that output starts with `/`. Else keep it, with the note `not found on PATH`. When `env` sets `PATH`, keep the bare command, with the note `uses the entry's PATH`. GUI clients often lack `npx`, `bun`, `uvx`, and `docker` on their `PATH`, so the absolute path matters.
         - A relative command, one with a `/` that does not start with `/`, becomes `<cwd>/<command>` when `cwd` starts with `/`. Keep `cwd` in the entry. Else keep the command, with the note `relative command`.
         - Keep every other client variable, such as `${HOME}`, as written. Step 5.4 gives the row the note `probe not run: client variable`. Nobody has tested whether a client expands such a variable.
         - Docker with `-e NAME` and an `env` block works unchanged, because the proxy passes its environment to the upstream. Add the note `Docker with -e, the env passes through`.
      3. Each `remote` or `already wrapped` row: change nothing more, so that no server is wrapped twice.
   4. Add these notes. Each note names the rows it applies to:
      - `moves the plugin's servers to user scope and disables the plugin`, on each row of a plugin that has a `wrappable` row.
      - `moved to user scope by the guardrail`, on each row of a `disabled` plugin that has a key in the plugin move record of step 6.
      - `an arg names mcp-guardrail-proxy`, on any row where an arg equals `mcp-guardrail-proxy` or ends in `/mcp-guardrail-proxy`. Such an entry can run the proxy through an outer command, such as `env`. Step 6 still wires the row.
      - `probe not run: <reason>`, on a `wrappable` row, an `already wrapped` row, or a `remote` row of a plugin that has a `wrappable` row, when step 7 cannot start the entry as its client does. Check the entry after item 3. The upstream command is the new upstream command of a `wrappable` row, and the first token after the first `--` in `args` of an `already wrapped` row. The reasons are `client variable` (a `$` in `command`, `args`, an `env` value, or `cwd`), `cwd is not absolute`, `relative command` (the upstream command is still relative), `relative argument` (an arg starts with `./` or `../`, and no `cwd` starts with `/`), and `remote` (a `remote` row, because `probe` starts only a stdio server). Step 6 still wires the row.

        The `relative argument` reason does not catch a bare relative arg, such as `server.py` in `python3 server.py`. When such a row has no `cwd`, the probe looks for that file in the agent's folder, not the client's. So the probe can fail although the client starts the server. In the step 7 report, name this as one possible cause of a failed probe.
   5. Show the user one table with the columns `#`, `Client`, `Config file`, `Scope`, `Server`, `Status`, and `Note`. List every entry you found, with one status each.
   6. Below the table, list the default selection: each `wrappable` row, and each row of a plugin that has a `wrappable` row. For each row, give the exact entry or command that step 6 writes, every file it changes, and each backup path.
   7. End the message with one request: reply yes to apply the listed rows, or name the rows to leave out. The user approves or leaves out a plugin as one unit.
   8. Wait for the reply. This is the only time the install waits for the user.

   If no entry is `wrappable`, tell the user so and stop. A second full run of these steps stops here, because every wired entry is `already wrapped`.

6. Wire the approved rows. Run this command first:

   ```sh
   mkdir -p ~/.local/state/mcp-guardrail
   ```

   `<AUDIT>` is the full path of `~/.local/state/mcp-guardrail/audit.jsonl`, the file the desktop app reads. Write the full path, with no `~` or `$HOME`.

   Each `wrappable` row gets this `command` and `args`. Keep the entry name and every other key, such as `env`, `cwd`, and `type`. A `remote` or `already wrapped` row of a plugin gets no wrap. Step 6 writes it as step 5.3 left it.

   ```json
   "<name>": {
     "command": "<BIN>",
     "args": ["proxy", "--audit-log", "<AUDIT>", "--", "<command>", "<arg>", "..."]
   }
   ```

   `<command>` is the upstream command from step 5. Put all of the old `args` after it. If the old entry has no `args`, end the list at `<command>`. To keep a custom policy for this row, put `"--policy"` and its absolute path before `"--"`.

   For each row, do these steps. `<file>` is the full path of the row's config file. Undo and Upgrade write their rows with the same steps.

   1. Back up the file before the row's write to it, with `command cp -pf '<file>' '<file>.bak-guardrail'`. `command` skips a `cp -i` alias, and `-p` keeps the file mode. The backup holds the file from right before the latest write. The plugin writer names the files that it backs up with this command.
   2. Write the row with the writer for its client, in the list below. Each writer gives its check and its rollback. The list is the only source of these. The client reference only names them.
   3. If the writer's write or its check fails, do the writer's rollback, show the command and its output, and go to the next row.

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

     `<<'JSON'` turns off shell expansion, so the entry needs only JSON escapes.

     Check: a Claude Code row has no re-parse. A failed `claude mcp remove` or a failed `add-json` is a failed write. Do not run `claude mcp get` here. It starts the server, and step 7 runs it as a check.

     Rollback: if `claude mcp remove` fails, run no `add-json` for the row, and report the row. If `add-json` fails, add the entry back the same way, as you read it before the remove, and report the row.
   - Claude Code, local scope. The user-scope writer, with `--scope local` in place of `--scope user`. Run both commands in the project folder of the entry. If that folder no longer exists, report `project folder gone` with its path, and change nothing in the row.
   - Codex. Edit `~/.codex/config.toml` in place. In `[mcp_servers.<name>]`, change only the values of `command` and `args`. If the table has no `args`, add it on the line after `command`. Do not touch any other key or subtable, such as `cwd`, `enabled`, or `[mcp_servers.<name>.env]`. Write each value as a TOML basic string, with `"` and `\` escaped. Then re-parse with `codex mcp get '<name>' --json > /dev/null`. If `codex` is not on `PATH`, re-parse with `python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' ~/.codex/config.toml`. If the re-parse fails, or neither command can run, restore the file with `command cp -f ~/.codex/config.toml.bak-guardrail ~/.codex/config.toml` and report the row.
   - Claude Code plugin. Never edit a plugin's own files, because a plugin update undoes the edit. Move the plugin's servers to user scope in its place, and record the move in `~/.local/state/mcp-guardrail/plugin-moves.json`. `<record>` is the full path of that file. The record is one JSON object. Each key is `<plugin>@<marketplace>`, and its value lists the server names that the move added. This writer changes `~/.claude.json`, `~/.claude/settings.json`, and the record, so back up all three first, each with the step 6.1 command, `command cp -pf '<file>' '<file>.bak-guardrail'`. Skip the record backup when the record does not exist.
     1. If the record does not exist, write it as `{}`. Add the plugin's key with the value `[]`. Re-parse the record with `python3 -m json.tool`. If that fails, restore the record with `command cp -f '<record>.bak-guardrail' '<record>'`. When this step created the record, there is no backup, so remove it with `command rm -f -- '<record>'`. Then report the row, and run no `claude` command for it.
     2. Run `claude plugin disable '<plugin>@<marketplace>' --scope user`.
     3. For each server of the plugin, run `claude mcp add-json` at user scope, through the heredoc of the user-scope writer. Use the entry that the top of step 6 gives the row: wrapped for a `wrappable` server, and with no wrap for a `remote` or `already wrapped` server. Run no `claude mcp remove` first, because step 5 found no server with that name. A failed `add-json` is the only failure of this item.
     4. After each `add-json` passes, back up the record with `command cp -pf '<record>' '<record>.bak-guardrail'`. Then append the server name to the plugin's key, and re-parse the record. The backup holds the record from right before the latest append.

     Roll back a failed plugin row in this way:
     - If `claude plugin disable` fails, run `claude plugin list --json`. If it still shows the plugin with `"enabled": true`, remove the plugin's key from the record. Else keep the key.
     - If an `add-json` fails, run the Undo of this plugin: `claude plugin enable`, then `claude mcp remove` for each server in its key, then remove the key. If `claude plugin enable` fails, stop there, and keep the added servers and the key.
     - If the backup before an append, the append, or its re-parse fails, run `claude mcp remove '<name>' --scope user` for the server just added. Then, if that backup passed, restore the record from it with `command cp -f '<record>.bak-guardrail' '<record>'`. A failed backup leaves the record unchanged. If the remove passed, do the rollback of a failed `add-json`. If the remove failed, stop, and report that server as moved and not recorded, with its remove command.
   - JSON clients. Edit the entry in place and keep every other key. Then re-parse with `python3 -m json.tool '<file>' > /dev/null`. If it fails, restore the file with `command cp -f '<file>.bak-guardrail' '<file>'` and report the row.

   Never write `~/.claude.json` or `~/.claude/settings.json` yourself, and never copy their backups over them. Change them only with the `claude` commands of step 6. Claude Code rewrites `~/.claude.json` while it runs, and `claude plugin disable` edits `~/.claude/settings.json`.

7. Check each wired row, then tell the user what to restart. This step writes nothing, so it never rolls back a row.

   1. Probe each row that has no `probe not run` note. Step 5.4 gives the notes. Build the probe from the row's new `args`:
      - The upstream is every token after the first `--`.
      - A `--policy <file>` or `--policy=<file>` before that `--` becomes `--policy '<file>'` in the probe, with `<file>` as the full path of the policy. Leave out `--audit-log` and `--session-id`, because `probe` takes neither.
      - Add `cd -- '<cwd>' &&` only when the entry has `cwd`. Add `env -- 'NAME=<value>'...` only when it has `env`.

      ```sh
      (cd -- '<cwd>' && env -- 'NAME=<value>' "<BIN>" probe --policy '<file>' -- '<command>' '<arg>')
      ```

      Give each probe call a timeout of 10 minutes. A probe exits 0 when the server lists the same tools directly and through the proxy.
   2. If a probe call reaches the 10-minute timeout, report `probe did not end` for the row. Then go to the next row.
   3. If a probe exits 1, find the cause in the stderr line that contains `mcp-guardrail-proxy: probe`, `mcp-guardrail-proxy: policy error`, or `mcp-guardrail-proxy: cannot start the async runtime`. Search for the text, because server output can come first on the same line. Then do these actions in order:
      1. If the cause is a timeout, and the upstream command is `npx`, `bun`, `uvx`, or `docker`, bare or as a full path, run the probe once more with `--timeout 240`. If the second probe exits 0, the row passes.
      2. Run the entry's own `command` and `args` in the form of the step 7.1 probe, with `< /dev/null`: `(cd -- '<cwd>' && env -- 'NAME=<value>' '<entry command>' '<entry arg>' < /dev/null)`. Add `cd` and `env` by the rules of step 7.1, and quote as in step 6. The proxy ends this run within about 6 s.
      3. Show the user every probe output and the output of that run.
      4. In the final report, offer the undo of the row: an Undo request that names the row. For a plugin row, offer the Undo of the whole plugin, and name its other servers, because that Undo removes them too. Do not wait for a reply.
      5. Go to the next row.

      When the user has the client open, name the client's own copy of the server as one possible cause, for example through a lock file or a port. Nobody has tested this case.
   4. For each Claude Code row, run `claude mcp get '<name>'`. It reports if the server connects. For a local-scope row, run it in the project folder of the entry.
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

Step 5 reads these files. The Writer and Re-parse columns only name the step 6 writer and its check. Step 6 gives the full steps and the rollback. "Tested" says where the facts in a row come from. A row marked "no" comes from the client's documentation, read on 2026-11-07, and nobody has wired that client with these steps. Check its documentation before you rely on the row. `<file>` in a command of this table is the full path of the row's config file, and `<name>` is the server name.

| Client | Config file | Where servers live | Writer | Re-parse | Restart | Tested |
|---|---|---|---|---|---|---|
| Claude Code, user scope | `~/.claude.json`, macOS and Linux | top-level `mcpServers` | the Claude Code user-scope writer in step 6: `claude mcp remove`, then `claude mcp add-json` | none. A failed `claude mcp remove` or `add-json` is a failed write. | start a new session. Step 7 runs `claude mcp get '<name>'`. | yes, install transcript |
| Claude Code, local scope | `~/.claude.json`, macOS and Linux | `projects.<project path>.mcpServers` | the Claude Code local-scope writer in step 6 | none, as for user scope | start a new session in that folder. Step 7 runs `claude mcp get '<name>'` in that folder. | yes, install transcript |
| Claude Code, plugin | the plugin's `installPath` from `claude plugin list --json`, for entries with `"scope": "user"`. The servers are in `<installPath>/.mcp.json`, at its top level or under `mcpServers`, or under `mcpServers` in `<installPath>/.claude-plugin/plugin.json`. | as in the file | the plugin writer in step 6 | `python3 -m json.tool` for the record. The `claude` commands have none. | start a new session | yes, install transcript. The `plugin.json` form is not tested. These paths are Claude Code internals that can change. A server list in another shape makes its rows `malformed`. |
| Codex | `~/.codex/config.toml`, macOS and Linux | `[mcp_servers.<name>]`, with `enabled = false` for a disabled server | the Codex writer in step 6 | `codex mcp get '<name>' --json > /dev/null`, else the `tomllib` command in step 6 | start a new session | yes, install transcript |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`, macOS only | `mcpServers` | the JSON writer in step 6 | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no, from the client's documentation |
| Cursor | `~/.cursor/mcp.json`, macOS and Linux | `mcpServers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no, from the client's documentation |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` on macOS, `~/.config/Code/User/mcp.json` on Linux | `servers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no. The documentation puts `mcp.json` in the user profile but does not give the path. A file with comments does not parse, so its entries are `malformed`. |
| Windsurf | `~/.codeium/windsurf/mcp_config.json`, macOS and Linux | `mcpServers`, with `"disabled": true` for a disabled server | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no. The path comes from the VS Code documentation, not checked against Windsurf's own documentation. |
| Gemini CLI | `~/.gemini/settings.json`, macOS and Linux | `mcpServers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | start a new session | no, from the client's documentation. The documentation puts server enablement in `~/.gemini/mcp-server-enablement.json`, which step 5 does not read. |

To undo a row, use [Undo](#undo).

## Undo

Undo needs no earlier backup. It rebuilds each original entry from its wrapped entry, so it works for a row wired in any pass, and it keeps edits made after the wiring. When the request names a client or a server, undo only those rows. A request that names the change needs no approval table.

Undo uses these values. `<file>` is the full path of the row's config file. `<name>` is a server name. `<record>` is the full path of `~/.local/state/mcp-guardrail/plugin-moves.json`, and each of its keys has the form `<plugin>@<marketplace>`. Undo needs no `<BIN>` and no `<AUDIT>`, because each rebuilt entry holds neither.

1. Run the step 5 scan. The rows to undo are the `already wrapped` rows. Leave an `already wrapped` row in a plugin's own file alone, and report it with its file. No writer changes a plugin's own file. Read the plugin move record, `~/.local/state/mcp-guardrail/plugin-moves.json`. A user-scope server whose name is in a record key belongs to that plugin's move, not to a user-scope row.
2. Rebuild each row. The new `command` is the first token after the first `--` in `args`. The new `args` is every token after that one, or `[]` when there is none. Keep every other key as it is now.
3. Write each rebuilt row with steps 6.1 to 6.3 and the step 6 writer for its client, with the rebuilt entry in place of the wrapped one. That writer gives the check, the rollback, and the `project folder gone` case.
4. Undo each plugin move that the request covers, one record key at a time:
   1. Run `claude plugin enable '<plugin>@<marketplace>' --scope user`. If it fails, stop for this plugin, keep its key, and report it.
   2. Run `claude mcp remove '<name>' --scope user` for each name in the key. Report a name that is no longer there.
   3. Back up the record with `command cp -pf '<record>' '<record>.bak-guardrail'`, remove the key, and re-parse the record with `python3 -m json.tool`. If the re-parse fails, restore the record with `command cp -f '<record>.bak-guardrail' '<record>'`, and report the plugin.

   If the request covers Claude Code and the record does not exist, say so. Then rebuild each wrapped user-scope server as a user-scope row, and enable no plugin. Tell the user to run `claude plugin enable` for each plugin they want back.
5. Report each row that now has a full path where the original had a bare or relative command. Then name the clients to restart, with the restart from the client reference.

## Upgrade

Do these steps in order when the user asks for an upgrade.

Upgrade uses these values. `<BIN>` is the full path that the step 3 block prints in item 1.4. `<file>` is the full path of the row's config file in steps 6.1 to 6.3, and of the policy file in a step 7 probe. `<SRC>` comes from step 4.1 in item 4. Item 5 runs the steps again from step 5, and step 6 sets `<AUDIT>`.

1. Upgrade the binary by the method that installed it:
   1. Run the `BIN` line of step 3, then `printf '%s\n' "$BIN"`, in one shell.
   2. If the printed path is the full path of `~/.local/bin/mcp-guardrail-proxy`, the binary is the prebuilt binary. Install the new release with the prebuilt binary block after step 7.
   3. Else run step 2 again. When the installed binary came from another commit, cargo prints `Replaced package` and replaces it. When it came from the same commit, cargo prints `is already installed, use --force to override`, exits 0, and keeps the binary. Both were observed in a sandbox on 2026-11-07.
   4. Run the step 3 block, which tests the binary. `<BIN>` in the items that follow is the full path that this block printed.
   5. If both `$HOME/.local/bin/mcp-guardrail-proxy` and `${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}/bin/mcp-guardrail-proxy` exist, report that `<BIN>` is the copy that the step 3 block picks, and that the other copy is shadowed. Remove neither copy.
2. Run the step 5 scan. Probe each `already wrapped` row by the rules of step 7. A failed probe gets the step 7 actions.
3. Re-wire each `already wrapped` row whose `command` is not `<BIN>`. Such a row runs another copy of the binary, for example after a switch between `cargo install` and the prebuilt binary.
   - Set only `command` to `<BIN>`. Keep `args`, `env`, `cwd`, and every other key.
   - Write the row with steps 6.1 to 6.3 and the step 6 writer for its client. That writer gives the check, the rollback, and the `project folder gone` case. A moved plugin server is a user-scope row here.
   - Leave an `already wrapped` row in a plugin's own file alone, and report it with its file. No writer changes a plugin's own file.
   - The server names do not change, so the plugin move record stays valid.
4. On macOS, upgrade the app: run step 4 again from step 4.1. If step 4.1 picks the current clone, it does not pull it. Then say in the report that you did not pull that clone. Tell the user to pull it and ask for the upgrade again to get a newer app.
5. After a plugin update, run the Undo of that plugin, then run the steps again from step 5. The moved servers keep the `installPath` that step 5.3 wrote into them.
6. After a runtime upgrade, such as a new Node version from a version manager, probe the rows again as in item 2, to check each full path that step 6 wrote.

Policy files from an earlier version still load, because the policy format does not change.

## Uninstall

`INSTALL.md` owns these paths, and Uninstall removes only them:

- `~/Applications/MCP Guardrail.app`
- `~/.local/state/mcp-guardrail/`, which holds the audit log and `plugin-moves.json`
- each `<file>.bak-guardrail`
- the binary, at the cargo path of step 3 or at `~/.local/bin/mcp-guardrail-proxy`

The user owns the removal of `~/.local/share/mcp-guardrail/src`, because a clone can hold their own work.

Do these steps in order. Ask no question.

Uninstall uses one value, `<file>`, the full path of a config file. It needs no `<BIN>`, because item 1 finds each binary path.

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

8. For each config file in the client reference for this platform, and for `~/.claude/settings.json`, remove `<file>.bak-guardrail` if it exists. Use `command rm -f -- '<file>.bak-guardrail'`, with `<file>` as the full path of the config file.
9. Run `cargo uninstall tauri-cli` only when the user's request names `tauri-cli`.
