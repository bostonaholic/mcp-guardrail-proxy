# Install

An agent that follows these steps builds the binary, tests it, and asks you before it edits your MCP client config. You can also do the steps yourself.

## Steps

Agents: do the steps in order. If a step fails, stop. Show the user the command and its full output. Do not guess a fix.

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

4. Wire one MCP server. Ask the user which client to edit and which server entry in its config to guard. If you do not know where that client keeps its config, ask the user for the file path. The proxy wraps only stdio servers, so if the entry has a `url` and no `command`, stop and tell the user. Show the user the new entry and wait for a yes. Copy the config file to a backup, then change the entry:

   ```json
   "<name>": {
     "command": "<BIN>",
     "args": ["proxy", "--", "<old command>", "<old args...>"]
   }
   ```

   Use the full path from step 3. JSON does not expand `~` or `$HOME`, and GUI clients such as Claude Desktop often do not have `~/.cargo/bin` on their `PATH`. Put the old `command` and all of the old `args` after `"--"`. If the old entry has no `args`, end the list at `<old command>`. To use a custom policy file, put `"--policy"` and its absolute path before `"--"`.

   Keep the entry name and all other keys, such as `env`. For a TOML config, set the same `command` and `args` keys in the table of that server. The upstream server gets the environment of the proxy.

5. Tell the user to restart the client. The guarded server must list the same tools as before. If it does not, run `"<BIN>" check-policy` with the `command` value from the entry, plus any `--policy` from its `args`. Then run the full `command` and `args` of the entry in a shell with `< /dev/null`. Show the user both outputs. A line that starts with `mcp-guardrail-proxy:` names the failure. To undo the change, copy the backup over the config file.

To write audit lines to a file, create its directory, then add `"--audit-log"` and the full file path to `args` before `"--"`. See [Audit log](README.md#audit-log).

The binary embeds `policies/default-policy.toml`. To change the rules, copy that file, edit the copy, and pass it with `--policy`. Run `check-policy --policy <file>` on the edited copy before you wire it in.

From a clone, run `cargo install --path . --locked` in place of step 2.

## Optional: desktop app

Agents: skip this section unless the user asks for the desktop app.

The steps above install only the proxy. The tray app shows sessions and recent calls and notifies you when a call is blocked. It builds from a clone, and these steps are for macOS. See [desktop/README.md](desktop/README.md).

1. Install the Tauri CLI.

   ```sh
   cargo install tauri-cli --version "^2" --locked
   ```

2. Build and open the app. The build takes several minutes, so give the command a timeout of at least 10 minutes.

   ```sh
   git clone https://github.com/bostonaholic/mcp-guardrail-proxy
   cd mcp-guardrail-proxy/desktop
   cargo tauri build --bundles app
   open "target/release/bundle/macos/MCP Guardrail.app"
   ```

3. Send audit lines to the file the app reads. Run `mkdir -p ~/.local/state/mcp-guardrail`. In each guarded entry, add `"--audit-log"` and the full path of `~/.local/state/mcp-guardrail/audit.jsonl` to `args` before `"--"`. Show the user the new entry and wait for a yes, then tell the user to restart the client. Without this step the app stays empty.
