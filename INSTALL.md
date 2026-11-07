# Install

An agent that follows these steps builds the binary, tests it, builds the desktop app on macOS, finds your MCP servers, and asks you once before it edits any MCP client config. You can also do the steps yourself.

## Steps

Agents: do the steps in order. If a step fails, stop. Show the user the command and its full output. Do not guess a fix.

Two kinds of failure end only one row of the approved table, not the run:

- In step 6, and in the writes of Undo, a failed row is rolled back and shown. Then the next row runs.
- In step 7, a failed row is never rolled back. It gets the step 7 actions for a failed probe. Then the next row runs.

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

   Run this block in one shell. The builds take several minutes, so give the command a timeout of at least 10 minutes.

   ```sh
   cargo install tauri-cli --version "^2" --locked
   git clone https://github.com/bostonaholic/mcp-guardrail-proxy
   cd mcp-guardrail-proxy/desktop
   cargo tauri build --bundles app
   open "target/release/bundle/macos/MCP Guardrail.app"
   mkdir -p ~/.local/state/mcp-guardrail
   ```

5. Find the servers. Read the configs yourself, and do not ask for a client or a path.

   1. Read each config file in the [client reference](#client-reference) for this platform. Skip a file that does not exist.
   2. Give each server entry one status. Check the statuses in this order, and use the first that applies:
      - `already wrapped`: `command` equals `mcp-guardrail-proxy` or ends in `/mcp-guardrail-proxy`. Also, `args` starts with `proxy` and holds at least one token after its first `--`.
      - `remote`: the entry has a `type` that is not `stdio`. Or it has a `url`, `httpUrl`, or `serverUrl` key, even an empty one, and no `command`.
      - `disabled`: the client does not start the entry. That means `enabled = false`, `"disabled": true`, or a local-scope entry whose project folder does not exist.
      - `malformed`: the file does not parse, so every entry in it is `malformed`. Or the entry has neither `command` nor a remote key. Or `command` is not a string. Or `args` is present and is not a list of strings. Or an `env` key is empty or holds `=`. Or `command` passes the `already wrapped` test for `command` and `args` does not, with the note `runs the proxy binary in another form`.
      - `wrappable`: every other entry. An entry with no `args` key is `wrappable`.
   3. Work out the new upstream command of each `wrappable` entry, in this order:
      - A bare command, one with no `/`, becomes the output of `sh -c 'command -v -- "$1"' sh '<command>'` when that output starts with `/`. Else keep it, with the note `not found on PATH`. When `env` sets `PATH`, keep the bare command, with the note `uses the entry's PATH`. GUI clients often lack `npx`, `bun`, `uvx`, and `docker` on their `PATH`, so the absolute path matters.
      - A relative command, one with a `/` that does not start with `/`, becomes `<cwd>/<command>` when `cwd` starts with `/`. Keep `cwd` in the entry. Else keep the command, with the note `relative command`.
      - Keep every other client variable, such as `${HOME}`, as written. The client expands it before it starts the proxy.
      - Docker with `-e NAME` and an `env` block works unchanged, because the proxy passes its environment to the upstream. Add the note `Docker with -e, the env passes through`.
   4. Add these notes where they apply:
      - `an arg names mcp-guardrail-proxy`, when an arg equals `mcp-guardrail-proxy` or ends in `/mcp-guardrail-proxy`. Such an entry can run the proxy through an outer command, such as `env`. Wrapping it again still works.
      - `probe not run: <reason>`, when step 7 cannot start the entry as its client does. The reasons are `client variable` (a `$` in `command`, `args`, an `env` value, or `cwd`), `cwd is not absolute`, `relative command` (the command is still relative), and `relative argument` (an arg starts with `./` or `../`, and no `cwd` starts with `/`). Step 6 still wires the row.
   5. Show the user one table with the columns `#`, `Client`, `Config file`, `Scope`, `Server`, `Status`, and `Note`. List every entry you found, with one status each.
   6. Below the table, list each `wrappable` row. These rows are the default selection. For each, give the exact new entry or command from step 6, every file it changes, and each backup path.
   7. End the message with one request: reply yes to apply the listed rows, or name the rows to leave out.
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
   - JSON clients. Edit the entry in place and keep every other key. Then re-parse with `python3 -m json.tool '<file>' > /dev/null`. If it fails, restore the file with `command cp -f '<file>.bak-guardrail' '<file>'` and report the row.

   Never write `~/.claude.json` yourself. Claude Code rewrites it while it runs, and only the `claude` CLI writes it safely. For the same reason, never copy its backup over it.

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
      4. In the final report, offer the undo of the row: an Undo request that names the row. Do not wait for a reply.
      5. Go to the next row.

      A server that holds a lock file or a port can fail its probe while a client runs its own copy of it. Name this as one possible cause when the user has the client open.
   4. For each Claude Code row, run `claude mcp get '<name>'`. It reports if the server connects.
   5. Give the final report. List each wired row with its probe result, or the reason no probe ran. List the tools that the probe shows as `deny` or `require-approval` in a tainted session. Name the rows that have only probe evidence, and the clients to restart, with the restart from the client reference. For Claude Code, say that a new session is necessary, because the current session keeps the old server.

The binary embeds `policies/default-policy.toml`. To change the rules, copy that file, edit the copy, and pass it with `--policy`. Run `check-policy --policy <file>` on the edited copy before you wire it in.

From a clone, run `cargo install --path . --locked` in place of step 2, and leave out `git clone` in step 4.

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
| Codex | `~/.codex/config.toml`, macOS and Linux | `[mcp_servers.<name>]`, with `enabled = false` for a disabled server | the TOML recipe in step 6 | `codex mcp get '<name>' --json > /dev/null` | start a new session | yes, install transcript |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`, macOS only | `mcpServers` | the JSON writer in step 6 | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no, from the client's documentation |
| Cursor | `~/.cursor/mcp.json`, macOS and Linux | `mcpServers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no, from the client's documentation |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` on macOS, `~/.config/Code/User/mcp.json` on Linux | `servers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no. The documentation puts `mcp.json` in the user profile but does not give the path. A file with comments does not parse, so its entries are `malformed`. |
| Windsurf | `~/.codeium/windsurf/mcp_config.json`, macOS and Linux | `mcpServers`, with `"disabled": true` for a disabled server | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | quit and reopen | no. The path comes from the VS Code documentation, not checked against Windsurf's own documentation. |
| Gemini CLI | `~/.gemini/settings.json`, macOS and Linux | `mcpServers` | the JSON writer | `python3 -m json.tool '<file>' > /dev/null` | start a new session | no, from the client's documentation. `gemini mcp disable` records a disabled server in `~/.gemini/mcp-server-enablement.json`, which step 5 does not read. |

To undo a row, use [Undo](#undo).

## Undo

Undo needs no backup. It rebuilds each original entry from its wrapped entry, so it works for a row wired in any pass, and it keeps edits made after the wiring. When the request names a client or a server, undo only those rows. A request that names the change needs no approval table.

1. Run the step 5 scan. The rows to undo are the `already wrapped` rows.
2. Rebuild each row. The new `command` is the first token after the first `--` in `args`. The new `args` is every token after that one, or `[]` when there is none. Keep every other key as it is now.
3. Write each row:
   - Claude Code, user or local scope: read the entry from `~/.claude.json`, but never write that file. Run `claude mcp remove '<name>' --scope <scope>`. Then run `claude mcp add-json` with the rebuilt entry through the heredoc of step 6, with the same `--scope`. For local scope, run both commands in the project folder of the entry. If that folder no longer exists, report `project folder gone` with its path, and change nothing in the row. If `add-json` fails, add the wrapped entry back as you read it, and report the row.
   - Codex and the JSON clients: back up the file with `command cp -pf '<file>' '<file>.bak-guardrail'`. Set `command` and `args` of the row to the rebuilt values. Re-parse the file with the command in its client reference row. If the re-parse fails, run `command cp -f '<file>.bak-guardrail' '<file>'` and report the row.
4. Report each row that now has a full path where the original had a bare or relative command. That path runs the same program. Then name the clients to restart, with the restart from the client reference.
