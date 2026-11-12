//! The MCP client table and the `INSTALL.md` step 5.2 and step 6 rules that the Servers tab
//! mirrors. Pure: no I/O, no UI.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Map, Value};

const PROXY_BINARY: &str = "mcp-guardrail-proxy";
const PROXY_SUFFIX: &str = "/mcp-guardrail-proxy";
const REMOTE_KEYS: [&str; 3] = ["url", "httpUrl", "serverUrl"];
const USER_SCOPE: &str = "user";
const CLAUDE_USER_KEY: &str = "mcpServers";
const CLAUDE_PROJECTS_KEY: &str = "projects";
const CODEX_KEY: &str = "mcp_servers";

/// Server entries by name, as one file's server key holds them.
type Servers = Map<String, Value>;

/// The platform whose client table applies. `Other` gets the Linux table, with no row selectable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    Other,
}

impl Platform {
    /// The platform of a `std::env::consts::OS` value.
    pub fn from_os(os: &str) -> Platform {
        match os {
            "macos" => Platform::MacOs,
            "linux" => Platform::Linux,
            _ => Platform::Other,
        }
    }
}

/// A client of the `INSTALL.md` client reference, by the name the page sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum ClientId {
    #[serde(rename = "claude_code_user")]
    ClaudeCodeUser,
    #[serde(rename = "claude_code_local")]
    ClaudeCodeLocal,
    #[serde(rename = "codex")]
    Codex,
    #[serde(rename = "claude_desktop")]
    ClaudeDesktop,
    #[serde(rename = "cursor")]
    Cursor,
    #[serde(rename = "vscode")]
    VsCode,
    #[serde(rename = "windsurf")]
    Windsurf,
    #[serde(rename = "gemini_cli")]
    GeminiCli,
}

impl ClientId {
    /// The client name the tab shows.
    pub fn label(self) -> &'static str {
        match self {
            ClientId::ClaudeCodeUser | ClientId::ClaudeCodeLocal => "Claude Code",
            ClientId::Codex => "Codex",
            ClientId::ClaudeDesktop => "Claude Desktop",
            ClientId::Cursor => "Cursor",
            ClientId::VsCode => "VS Code",
            ClientId::Windsurf => "Windsurf",
            ClientId::GeminiCli => "Gemini CLI",
        }
    }
}

/// One server, as the page names it to `wrap_servers`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ServerId {
    pub client: ClientId,
    pub project: Option<String>,
    pub name: String,
}

/// The step 5.2 statuses and the app-only `unreadable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Status {
    #[serde(rename = "already wrapped")]
    AlreadyWrapped,
    #[serde(rename = "remote")]
    Remote,
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "malformed")]
    Malformed,
    #[serde(rename = "wrappable")]
    Wrappable,
    #[serde(rename = "unreadable")]
    Unreadable,
}

impl Status {
    /// The status as the tab shows it, the same text as its serde name.
    pub fn name(self) -> &'static str {
        match self {
            Status::AlreadyWrapped => "already wrapped",
            Status::Remote => "remote",
            Status::Disabled => "disabled",
            Status::Malformed => "malformed",
            Status::Wrappable => "wrappable",
            Status::Unreadable => "unreadable",
        }
    }
}

/// Where a client file keeps its servers (`INSTALL.md` client reference).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `~/.claude.json`: user rows under top-level `mcpServers`, local rows under
    /// `projects.<project path>.mcpServers`.
    ClaudeJson,
    /// `~/.codex/config.toml`: one `[mcp_servers.<name>]` table per server.
    CodexToml,
    /// A JSON file with every server under one top-level key.
    Json { client: ClientId, key: &'static str },
}

/// One config file of the client table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientFile {
    pub path: PathBuf,
    pub layout: Layout,
}

impl ClientFile {
    /// The client of a row that stands for the whole file.
    fn file_client(&self) -> ClientId {
        match self.layout {
            Layout::ClaudeJson => ClientId::ClaudeCodeUser,
            Layout::CodexToml => ClientId::Codex,
            Layout::Json { client, .. } => client,
        }
    }

    fn serves(&self, client: ClientId) -> bool {
        match self.layout {
            Layout::ClaudeJson => {
                matches!(client, ClientId::ClaudeCodeUser | ClientId::ClaudeCodeLocal)
            }
            Layout::CodexToml => client == ClientId::Codex,
            Layout::Json { client: owner, .. } => owner == client,
        }
    }
}

/// The rows of the `INSTALL.md` client reference under `home`, without the plugin row.
pub fn client_files(platform: Platform, home: &Path) -> Vec<ClientFile> {
    let json = |relative: &str, client: ClientId, key: &'static str| ClientFile {
        path: home.join(relative),
        layout: Layout::Json { client, key },
    };
    let vscode = match platform {
        Platform::MacOs => "Library/Application Support/Code/User/mcp.json",
        Platform::Linux | Platform::Other => ".config/Code/User/mcp.json",
    };
    let mut files = vec![
        ClientFile {
            path: home.join(".claude.json"),
            layout: Layout::ClaudeJson,
        },
        ClientFile {
            path: home.join(".codex/config.toml"),
            layout: Layout::CodexToml,
        },
    ];
    if platform == Platform::MacOs {
        files.push(json(
            "Library/Application Support/Claude/claude_desktop_config.json",
            ClientId::ClaudeDesktop,
            "mcpServers",
        ));
    }
    files.extend([
        json(".cursor/mcp.json", ClientId::Cursor, "mcpServers"),
        json(vscode, ClientId::VsCode, "servers"),
        json(
            ".codeium/windsurf/mcp_config.json",
            ClientId::Windsurf,
            "mcpServers",
        ),
        json(".gemini/settings.json", ClientId::GeminiCli, "mcpServers"),
    ]);
    files
}

/// The table file of `client`, or `None` when this platform's table has no such client.
pub fn client_file(platform: Platform, home: &Path, client: ClientId) -> Option<ClientFile> {
    client_files(platform, home)
        .into_iter()
        .find(|file| file.serves(client))
}

/// One row of the Servers tab.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServerRow {
    pub id: ServerId,
    pub client: String,
    pub scope: String,
    pub file: String,
    pub server: String,
    pub status: Status,
    pub reason: Option<String>,
    pub selectable: bool,
}

/// The row that stands for a whole file the scan cannot list entries from.
pub fn file_row(file: &ClientFile, status: Status, reason: String) -> ServerRow {
    let client = file.file_client();
    ServerRow {
        id: ServerId {
            client,
            project: None,
            name: String::new(),
        },
        client: client.label().to_string(),
        scope: USER_SCOPE.to_string(),
        file: file.path.display().to_string(),
        server: String::new(),
        status,
        reason: Some(reason),
        selectable: false,
    }
}

/// What one file gives the scan: the count of wrapped entries and a row for every other entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileScan {
    pub wrapped: usize,
    pub rows: Vec<ServerRow>,
}

/// One server entry of a parsed file.
struct Entry {
    id: ServerId,
    value: Value,
    project_exists: bool,
}

/// Classifies every entry of one file, with no row blocker. The scan passes its blockers to
/// `scan_text_with`, so only the classifier tests call this form.
#[cfg(test)]
pub fn scan_text(file: &ClientFile, text: &str, folder_exists: &dyn Fn(&Path) -> bool) -> FileScan {
    scan_text_with(file, text, folder_exists, &|_, _| None)
}

/// Classifies every entry of one file. A file that does not parse, or whose server key holds
/// no table, gives one `malformed` row whose reason quotes no file text. `blocker` can take the
/// checkbox from a `wrappable` row, with its reason.
pub fn scan_text_with(
    file: &ClientFile,
    text: &str,
    folder_exists: &dyn Fn(&Path) -> bool,
    blocker: &dyn Fn(&ServerId, &Value) -> Option<RowBlocker>,
) -> FileScan {
    let entries = match entries_of(file, text, folder_exists) {
        Ok(entries) => entries,
        Err(reason) => {
            return FileScan {
                wrapped: 0,
                rows: vec![file_row(file, Status::Malformed, reason)],
            };
        }
    };
    let mut scan = FileScan::default();
    for entry in entries {
        let (status, note) = classify(&entry.value, entry.project_exists);
        if status == Status::AlreadyWrapped {
            scan.wrapped += 1;
            continue;
        }
        let blocked = match status {
            Status::Wrappable => blocker(&entry.id, &entry.value),
            _ => None,
        };
        let selectable = status == Status::Wrappable && blocked.is_none();
        let reason = blocked.map(|blocked| blocked.to_string()).or(note);
        let scope = match &entry.id.project {
            Some(project) => format!("local: {project}"),
            None => USER_SCOPE.to_string(),
        };
        scan.rows.push(ServerRow {
            client: entry.id.client.label().to_string(),
            scope,
            file: file.path.display().to_string(),
            server: entry.id.name.clone(),
            status,
            reason,
            selectable,
            id: entry.id,
        });
    }
    scan
}

fn entries_of(
    file: &ClientFile,
    text: &str,
    folder_exists: &dyn Fn(&Path) -> bool,
) -> Result<Vec<Entry>, String> {
    match file.layout {
        Layout::CodexToml => {
            let document = parse_toml(text)?;
            let servers = toml_servers(&document)?;
            Ok(user_entries(ClientId::Codex, servers))
        }
        Layout::Json { client, key } => {
            let document = parse_json(text)?;
            let servers = json_servers(&document, key)?.cloned().unwrap_or_default();
            Ok(user_entries(client, servers))
        }
        Layout::ClaudeJson => {
            let document = parse_json(text)?;
            let user = json_servers(&document, CLAUDE_USER_KEY)?
                .cloned()
                .unwrap_or_default();
            let mut entries = user_entries(ClientId::ClaudeCodeUser, user);
            for (project, servers) in claude_projects(&document)? {
                let project_exists = folder_exists(Path::new(&project));
                entries.extend(servers.into_iter().map(|(name, value)| Entry {
                    id: ServerId {
                        client: ClientId::ClaudeCodeLocal,
                        project: Some(project.clone()),
                        name,
                    },
                    value,
                    project_exists,
                }));
            }
            Ok(entries)
        }
    }
}

fn user_entries(client: ClientId, servers: Servers) -> Vec<Entry> {
    servers
        .into_iter()
        .map(|(name, value)| Entry {
            id: ServerId {
                client,
                project: None,
                name,
            },
            value,
            project_exists: true,
        })
        .collect()
}

/// A parse error names only its place: a `serde_json` or `toml_edit` message can quote the
/// value at that place, such as an `env` token.
fn not_parsed(line: usize, column: usize) -> String {
    format!("does not parse at line {line}, column {column}")
}

fn parse_json(text: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|error| not_parsed(error.line(), error.column()))
}

fn parse_toml(text: &str) -> Result<toml_edit::DocumentMut, String> {
    text.parse::<toml_edit::DocumentMut>().map_err(|error| {
        let start = error.span().map_or(0, |span| span.start);
        let (line, column) = line_and_column(text, start);
        not_parsed(line, column)
    })
}

/// The 1-based line and byte column of a byte offset.
fn line_and_column(text: &str, offset: usize) -> (usize, usize) {
    let before = &text.as_bytes()[..offset.min(text.len())];
    let line = before.iter().filter(|byte| **byte == b'\n').count() + 1;
    let line_start = before
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    (line, before.len() - line_start + 1)
}

fn not_a_table(key: &str) -> String {
    format!("the {key} key does not hold a table of servers")
}

fn json_servers<'a>(document: &'a Value, key: &str) -> Result<Option<&'a Servers>, String> {
    match document.get(key) {
        None => Ok(None),
        Some(Value::Object(servers)) => Ok(Some(servers)),
        Some(_) => Err(not_a_table(key)),
    }
}

/// The local-scope servers of `~/.claude.json`, by project path.
fn claude_projects(document: &Value) -> Result<Vec<(String, Servers)>, String> {
    let projects = match document.get(CLAUDE_PROJECTS_KEY) {
        None => return Ok(Vec::new()),
        Some(Value::Object(projects)) => projects,
        Some(_) => return Err(not_a_table(CLAUDE_PROJECTS_KEY)),
    };
    let mut found = Vec::new();
    for (project, settings) in projects {
        match settings.get(CLAUDE_USER_KEY) {
            None => {}
            Some(Value::Object(servers)) => found.push((project.clone(), servers.clone())),
            Some(_) => {
                return Err(not_a_table(&format!(
                    "{CLAUDE_PROJECTS_KEY}.{project}.{CLAUDE_USER_KEY}"
                )));
            }
        }
    }
    Ok(found)
}

fn toml_servers(document: &toml_edit::DocumentMut) -> Result<Servers, String> {
    match document.get(CODEX_KEY) {
        None => Ok(Servers::new()),
        Some(item) => match item.as_table_like() {
            Some(servers) => Ok(servers
                .iter()
                .map(|(name, server)| (name.to_string(), toml_item_to_json(server)))
                .collect()),
            None => Err(not_a_table(CODEX_KEY)),
        },
    }
}

/// The same keys and values as JSON, so one classifier serves TOML and JSON files.
fn toml_item_to_json(item: &toml_edit::Item) -> Value {
    match item {
        toml_edit::Item::None => Value::Null,
        toml_edit::Item::Value(value) => toml_value_to_json(value),
        toml_edit::Item::Table(table) => Value::Object(
            table
                .iter()
                .map(|(key, item)| (key.to_string(), toml_item_to_json(item)))
                .collect(),
        ),
        toml_edit::Item::ArrayOfTables(tables) => Value::Array(
            tables
                .iter()
                .map(|table| {
                    Value::Object(
                        table
                            .iter()
                            .map(|(key, item)| (key.to_string(), toml_item_to_json(item)))
                            .collect(),
                    )
                })
                .collect(),
        ),
    }
}

fn toml_value_to_json(value: &toml_edit::Value) -> Value {
    match value {
        toml_edit::Value::String(text) => Value::String(text.value().clone()),
        toml_edit::Value::Integer(number) => Value::from(*number.value()),
        toml_edit::Value::Float(number) => {
            serde_json::Number::from_f64(*number.value()).map_or(Value::Null, Value::Number)
        }
        toml_edit::Value::Boolean(flag) => Value::Bool(*flag.value()),
        toml_edit::Value::Datetime(time) => Value::String(time.value().to_string()),
        toml_edit::Value::Array(items) => {
            Value::Array(items.iter().map(toml_value_to_json).collect())
        }
        toml_edit::Value::InlineTable(table) => Value::Object(
            table
                .iter()
                .map(|(key, value)| (key.to_string(), toml_value_to_json(value)))
                .collect(),
        ),
    }
}

fn is_proxy_command(command: &str) -> bool {
    command == PROXY_BINARY || command.ends_with(PROXY_SUFFIX)
}

/// `Some` only for a list of strings.
fn string_list(value: Option<&Value>) -> Option<Vec<&str>> {
    value?.as_array()?.iter().map(Value::as_str).collect()
}

/// The `already wrapped` test of `INSTALL.md` step 5.2.
pub fn is_already_wrapped(entry: &Value) -> bool {
    let proxy = entry
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(is_proxy_command);
    let wrapped_args = string_list(entry.get("args")).is_some_and(|args| {
        args.first() == Some(&"proxy")
            && args
                .iter()
                .position(|arg| *arg == "--")
                .is_some_and(|dashes| dashes + 1 < args.len())
    });
    proxy && wrapped_args
}

fn is_remote(entry: &Value) -> bool {
    let typed_remote = entry
        .get("type")
        .is_some_and(|kind| kind.as_str() != Some("stdio"));
    let url_only =
        entry.get("command").is_none() && REMOTE_KEYS.iter().any(|key| entry.get(*key).is_some());
    typed_remote || url_only
}

fn is_disabled(entry: &Value) -> bool {
    entry.get("enabled") == Some(&Value::Bool(false))
        || entry.get("disabled") == Some(&Value::Bool(true))
}

/// The `malformed` rules of `INSTALL.md` step 5.2, in order. The note names keys, never values.
fn malformed_note(entry: &Value) -> Option<&'static str> {
    let Some(command) = entry.get("command") else {
        return Some("no command and no remote key");
    };
    let Some(command) = command.as_str() else {
        return Some("command is not a string");
    };
    if entry.get("args").is_some() && string_list(entry.get("args")).is_none() {
        return Some("args is not a list of strings");
    }
    let bad_env_key = entry
        .get("env")
        .and_then(Value::as_object)
        .is_some_and(|env| env.keys().any(|key| key.is_empty() || key.contains('=')));
    if bad_env_key {
        return Some("an env key is empty or holds =");
    }
    if is_proxy_command(command) {
        return Some("runs the proxy binary in another form");
    }
    None
}

/// The status of `INSTALL.md` step 5.2, checked in its order, with a note for the reason.
fn classify(entry: &Value, project_exists: bool) -> (Status, Option<String>) {
    if is_already_wrapped(entry) {
        return (Status::AlreadyWrapped, None);
    }
    if is_remote(entry) {
        return (Status::Remote, None);
    }
    if is_disabled(entry) {
        return (Status::Disabled, None);
    }
    if !project_exists {
        return (Status::Disabled, Some("project folder gone".to_string()));
    }
    match malformed_note(entry) {
        Some(note) => (Status::Malformed, Some(note.to_string())),
        None => (Status::Wrappable, None),
    }
}

/// What a fresh read of a client file holds for one requested server.
pub enum Found {
    /// The file does not parse, or its server key holds no table. The text names only a key or
    /// a place in the file.
    NotParsed(String),
    Missing,
    Entry {
        status: Status,
        value: Value,
    },
}

/// The entry of `id` in `text`, classified as the scan classifies it.
pub fn find_entry(
    file: &ClientFile,
    text: &str,
    id: &ServerId,
    folder_exists: &dyn Fn(&Path) -> bool,
) -> Found {
    let entries = match entries_of(file, text, folder_exists) {
        Ok(entries) => entries,
        Err(reason) => return Found::NotParsed(reason),
    };
    match entries.into_iter().find(|entry| entry.id == *id) {
        None => Found::Missing,
        Some(entry) => Found::Entry {
            status: classify(&entry.value, entry.project_exists).0,
            value: entry.value,
        },
    }
}

/// The file text with one entry wrapped, and the step 5.3 notes that the wrap gave the row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewText {
    pub text: String,
    pub notes: Vec<String>,
}

/// Why the app cannot build the new text. The reason names keys, never values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditError {
    pub reason: String,
}

fn edit_error(reason: &str) -> EditError {
    EditError {
        reason: reason.to_string(),
    }
}

/// The upstream command and the notes of `INSTALL.md` steps 5.3 and 5.4.
fn upstream_command(
    entry: &Value,
    command: &str,
    lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> (String, Vec<String>) {
    let mut notes = Vec::new();
    let upstream = if !command.contains('/') {
        let entry_sets_path = entry
            .get("env")
            .and_then(Value::as_object)
            .is_some_and(|env| env.contains_key("PATH"));
        let found = lookup(command)
            .and_then(|path| path.to_str().map(str::to_string))
            .filter(|path| path.starts_with('/'));
        match found {
            _ if entry_sets_path => {
                notes.push("uses the entry's PATH".to_string());
                command.to_string()
            }
            Some(path) => path,
            None => {
                notes.push("not found on PATH".to_string());
                command.to_string()
            }
        }
    } else if !command.starts_with('/') {
        match entry.get("cwd").and_then(Value::as_str) {
            Some(cwd) if cwd.starts_with('/') => {
                format!("{}/{command}", cwd.trim_end_matches('/'))
            }
            _ => {
                notes.push("relative command".to_string());
                command.to_string()
            }
        }
    } else {
        command.to_string()
    };
    let names_proxy = string_list(entry.get("args"))
        .is_some_and(|args| args.iter().any(|arg| is_proxy_command(arg)));
    if names_proxy {
        notes.push("an arg names mcp-guardrail-proxy".to_string());
    }
    (upstream, notes)
}

/// The `args` of the `INSTALL.md` step 6 entry.
fn wrapped_args(audit_log: &str, upstream: String, old_args: &[&str]) -> Vec<String> {
    let mut args = vec![
        "proxy".to_string(),
        "--audit-log".to_string(),
        audit_log.to_string(),
        "--".to_string(),
        upstream,
    ];
    args.extend(old_args.iter().map(|arg| arg.to_string()));
    args
}

/// The step 6 `command` and `args` of an entry, and the notes they gave.
struct Wrap {
    args: Vec<String>,
    notes: Vec<String>,
}

fn wrap_of(
    entry: &Value,
    audit_log: &str,
    lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<Wrap, EditError> {
    let command = entry
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| edit_error("the entry has no command string"))?;
    let old_args = match entry.get("args") {
        None => Vec::new(),
        Some(_) => string_list(entry.get("args"))
            .ok_or_else(|| edit_error("the entry's args is not a list of strings"))?,
    };
    let (upstream, notes) = upstream_command(entry, command, lookup);
    Ok(Wrap {
        args: wrapped_args(audit_log, upstream, &old_args),
        notes,
    })
}

/// The new text of `file` with the entry `name` wrapped, parsed and classified in memory. A
/// failure here comes before any write.
pub fn checked_new_text(
    file: &ClientFile,
    text: &str,
    name: &str,
    bin: &str,
    audit_log: &str,
    lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<NewText, EditError> {
    let id = ServerId {
        client: file.file_client(),
        project: None,
        name: name.to_string(),
    };
    let entry = match find_entry(file, text, &id, &|_| true) {
        Found::Entry { value, .. } => value,
        Found::Missing => return Err(edit_error("the entry is not in the file")),
        Found::NotParsed(reason) => return Err(EditError { reason }),
    };
    let wrap = wrap_of(&entry, audit_log, lookup)?;
    let new_text = match file.layout {
        Layout::Json { key, .. } => splice_json(text, key, name, bin, &wrap.args)?,
        Layout::CodexToml => edit_toml(text, name, bin, &wrap.args)?,
        Layout::ClaudeJson => {
            return Err(edit_error(
                "~/.claude.json changes only through the claude command",
            ));
        }
    };
    match find_entry(file, &new_text, &id, &|_| true) {
        Found::Entry {
            status: Status::AlreadyWrapped,
            ..
        } => Ok(NewText {
            text: new_text,
            notes: wrap.notes,
        }),
        _ => Err(edit_error(
            "the new text does not hold the entry in its wrapped form",
        )),
    }
}

/// Values by key, each a slice of the text that was parsed.
type RawMap<'a> = BTreeMap<String, &'a RawValue>;

fn raw_map<'a>(json: &'a str, what: &str) -> Result<RawMap<'a>, EditError> {
    serde_json::from_str(json).map_err(|_| edit_error(&format!("{what} is not a JSON object")))
}

/// The byte range of `raw` in `text`. `raw` borrows from `text`, so its offset is the distance
/// between the two pointers. A range outside `text` is an error, never a panic.
fn span_in(text: &str, raw: &RawValue) -> Result<Range<usize>, EditError> {
    let value = raw.get();
    let start = (value.as_ptr() as usize)
        .checked_sub(text.as_ptr() as usize)
        .ok_or_else(|| edit_error("a value lies outside the file text"))?;
    let range = start..start + value.len();
    match text.get(range.clone()) {
        Some(found) if found == value => Ok(range),
        _ => Err(edit_error("a value lies outside the file text")),
    }
}

/// Replaces the `command` and `args` values of one entry and keeps every other byte. With no
/// `args`, one `args` member goes right after the `command` value.
fn splice_json(
    text: &str,
    key: &str,
    name: &str,
    bin: &str,
    args: &[String],
) -> Result<String, EditError> {
    let top = raw_map(text, "the file")?;
    let servers = top
        .get(key)
        .ok_or_else(|| edit_error(&format!("the file has no {key} key")))?;
    let servers = raw_map(servers.get(), &format!("the {key} key"))?;
    let entry = servers
        .get(name)
        .ok_or_else(|| edit_error("the entry is not in the file"))?;
    let entry = raw_map(entry.get(), "the entry")?;
    let command = entry
        .get("command")
        .ok_or_else(|| edit_error("the entry has no command"))?;
    let command = span_in(text, command)?;
    let bin = serde_json::to_string(bin).map_err(|_| edit_error("the binary path"))?;
    let args_json = serde_json::to_string(args).map_err(|_| edit_error("the new args"))?;
    let mut edits = vec![(command.clone(), bin)];
    match entry.get("args") {
        Some(old_args) => edits.push((span_in(text, old_args)?, args_json)),
        None => edits.push((command.end..command.end, format!(",\"args\":{args_json}"))),
    }
    edits.sort_by_key(|(range, _)| range.start);
    let mut spliced = String::with_capacity(text.len() + 256);
    let mut copied = 0;
    for (range, replacement) in edits {
        spliced.push_str(
            text.get(copied..range.start)
                .ok_or_else(|| edit_error("the command and args values overlap"))?,
        );
        spliced.push_str(&replacement);
        copied = range.end;
    }
    spliced.push_str(
        text.get(copied..)
            .ok_or_else(|| edit_error("a value lies outside the file text"))?,
    );
    Ok(spliced)
}

/// A TOML basic string. The default form of `toml_edit` can pick a literal string for a value
/// that holds a backslash, and `INSTALL.md` step 6 asks for basic strings with `"` and `\` escaped.
fn basic_string(value: &str) -> Result<toml_edit::Value, EditError> {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            '\r' => quoted.push_str("\\r"),
            other if other.is_control() => quoted.push_str(&format!("\\u{:04X}", u32::from(other))),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
        .parse()
        .map_err(|_| edit_error("a new value is not a TOML string"))
}

/// Replaces one value and keeps the old value's decor, which holds the spaces around it and a
/// comment after it. A missing key goes at the end of the table.
fn set_toml_value(entry: &mut dyn toml_edit::TableLike, key: &str, mut value: toml_edit::Value) {
    match entry.get_mut(key) {
        Some(toml_edit::Item::Value(old)) => {
            *value.decor_mut() = old.decor().clone();
            *old = value;
        }
        _ => {
            entry.insert(key, toml_edit::Item::Value(value));
        }
    }
}

/// Sets `command` and `args` of `[mcp_servers.<name>]` and keeps every other key, subtable,
/// and comment. `toml_edit` writes a line end after each key-value line and table header.
fn edit_toml(text: &str, name: &str, bin: &str, args: &[String]) -> Result<String, EditError> {
    let mut document = parse_toml(text).map_err(|reason| EditError { reason })?;
    let entry = document
        .get_mut(CODEX_KEY)
        .and_then(toml_edit::Item::as_table_like_mut)
        .and_then(|servers| servers.get_mut(name))
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| edit_error("the entry is not a table in the file"))?;
    let mut new_args = toml_edit::Array::new();
    for arg in args {
        new_args.push_formatted(basic_string(arg)?);
    }
    new_args.fmt();
    set_toml_value(entry, "command", basic_string(bin)?);
    set_toml_value(entry, "args", toml_edit::Value::Array(new_args));
    Ok(document.to_string())
}

/// A file as one open read saw it. `mode` holds the permission bits only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileState {
    pub bytes: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// What the read after the rename shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readback {
    /// The file holds the new text.
    Wrapped,
    /// The file holds the first read.
    Original,
    /// The read failed, or the file holds other bytes, which another program wrote.
    Unrecovered,
}

pub fn judge_readback(read: Option<&[u8]>, new_text: &[u8], first: &[u8]) -> Readback {
    match read {
        Some(bytes) if bytes == new_text => Readback::Wrapped,
        Some(bytes) if bytes == first => Readback::Original,
        _ => Readback::Unrecovered,
    }
}

/// The restart step of the `INSTALL.md` client reference after a wrap.
pub fn restart_step(id: &ServerId) -> String {
    let label = id.client.label();
    match (id.client, &id.project) {
        (ClientId::ClaudeCodeLocal, Some(project)) => {
            format!("Start a new {label} session in {project}.")
        }
        (ClientId::ClaudeCodeUser | ClientId::ClaudeCodeLocal | ClientId::Codex, _)
        | (ClientId::GeminiCli, _) => format!("Start a new {label} session."),
        _ => format!("Quit and reopen {label}."),
    }
}

/// The top-level keys of `expected` that `stored` lacks or holds with another value, never a
/// value. A stored entry can have more keys, because nothing records which keys `claude` adds.
pub fn holds(stored: &Value, expected: &Value) -> Result<(), Vec<String>> {
    let differ: Vec<String> = expected
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, value)| stored.get(key.as_str()) != Some(*value))
        .map(|(key, _)| key.clone())
        .collect();
    if differ.is_empty() {
        Ok(())
    } else {
        Err(differ)
    }
}

/// The Claude Code entry that `claude mcp add-json` gets: the original with the step 6
/// `command` and `args`, and every other key kept.
pub fn wrapped_entry(
    entry: &Value,
    bin: &str,
    audit_log: &str,
    lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(Value, Vec<String>), EditError> {
    let wrap = wrap_of(entry, audit_log, lookup)?;
    let mut wrapped = entry.clone();
    let fields = wrapped
        .as_object_mut()
        .ok_or_else(|| edit_error("the entry is not an object"))?;
    fields.insert("command".to_string(), Value::from(bin));
    fields.insert("args".to_string(), Value::from(wrap.args));
    Ok((wrapped, wrap.notes))
}

/// The longest JSON text that the app passes to `claude` as one argument. Linux limits one
/// argument to 128 KiB, and macOS limits the argument list and the environment together, so
/// this cap leaves room for the rest. The add-back sends the original, so both texts must fit.
pub const MAX_ADD_JSON_BYTES: usize = 65_536;

/// Why one row gets no checkbox. `Display` is the window text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowBlocker {
    NameRefused,
    NoClaude,
    TooLong,
}

impl fmt::Display for RowBlocker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RowBlocker::NameRefused => formatter.write_str(
                "The name is empty or starts with -, so claude cannot take it as a server name.",
            ),
            RowBlocker::NoClaude => formatter.write_str(
                "Cannot find claude on your PATH, so the app cannot wrap Claude Code servers.",
            ),
            RowBlocker::TooLong => formatter
                .write_str("The entry is over 64 KiB, too long for the app to pass to claude."),
        }
    }
}

fn json_len(value: &Value) -> usize {
    serde_json::to_string(value).map_or(usize::MAX, |text| text.len())
}

/// Why `claude` cannot take a Claude Code row, or the app could not add it back. `claude`
/// reads a name that starts with `-` as an option.
pub fn claude_code_blocker(
    name: &str,
    entry: &Value,
    bin: &str,
    audit_log: &str,
    lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> Option<RowBlocker> {
    if name.is_empty() || name.starts_with('-') {
        return Some(RowBlocker::NameRefused);
    }
    if lookup("claude").is_none() {
        return Some(RowBlocker::NoClaude);
    }
    let too_long = match wrapped_entry(entry, bin, audit_log, lookup) {
        Ok((wrapped, _)) => {
            json_len(&wrapped) > MAX_ADD_JSON_BYTES || json_len(entry) > MAX_ADD_JSON_BYTES
        }
        Err(_) => json_len(entry) > MAX_ADD_JSON_BYTES,
    };
    too_long.then_some(RowBlocker::TooLong)
}

/// The shortest `args` token that the app hides. Shorter tokens, such as `-y` and `1`, would
/// hide words of the line that you act on.
pub const MIN_HIDDEN_ARG_BYTES: usize = 4;
const HIDDEN_MARK: &[u8] = b"[hidden]";

/// Each non-empty `env` value and each `args` token of 4 bytes or more, raw and in the form
/// that `serde_json` writes inside a string, with no quotes.
pub fn hidden_forms(entry: &Value) -> Vec<Vec<u8>> {
    let env_values = entry
        .get("env")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty());
    let args = string_list(entry.get("args")).unwrap_or_default();
    let arg_values = args
        .into_iter()
        .filter(|arg| arg.len() >= MIN_HIDDEN_ARG_BYTES);
    let mut forms = Vec::new();
    for value in env_values.chain(arg_values) {
        forms.push(value.as_bytes().to_vec());
        let escaped = serde_json::to_string(value).unwrap_or_default();
        if let Some(inner) = escaped.get(1..escaped.len().saturating_sub(1))
            && inner != value
        {
            forms.push(inner.as_bytes().to_vec());
        }
    }
    forms
}

/// Marks each byte inside any match of any form, at every start offset, so matches that
/// overlap are hidden whole. Each run of marked bytes becomes `[hidden]`.
fn redact(output: &[u8], forms: &[Vec<u8>]) -> Vec<u8> {
    let mut marked = vec![false; output.len()];
    for start in 0..output.len() {
        for form in forms.iter().filter(|form| !form.is_empty()) {
            let end = start + form.len();
            if output.get(start..end) == Some(form.as_slice())
                && let Some(span) = marked.get_mut(start..end)
            {
                span.fill(true);
            }
        }
    }
    let mut redacted = Vec::with_capacity(output.len());
    let mut in_run = false;
    for (byte, hidden) in output.iter().zip(&marked) {
        if *hidden && !in_run {
            redacted.extend_from_slice(HIDDEN_MARK);
        }
        if !*hidden {
            redacted.push(*byte);
        }
        in_run = *hidden;
    }
    redacted
}

/// The fixed text in place of a line that still holds a hidden value.
const HIDDEN_LINE: &str = "The output held a hidden value, so the app does not show it.";

fn holds_bytes(text: &[u8], part: &[u8]) -> bool {
    text.windows(part.len()).any(|window| window == part)
}

/// The last non-empty line of a whole child output, with each hidden form hidden. A line that
/// still holds a hidden form, such as one that `[hidden]` completed, gives the fixed text. That
/// last test runs on the exact line that the app shows. The redaction runs on the whole output
/// before the line split, so a value with line ends is hidden whole.
pub fn shown_line(output: &[u8], forms: &[Vec<u8>]) -> Option<String> {
    let redacted = redact(output, forms);
    let text = String::from_utf8_lossy(&redacted);
    let line = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())?
        .trim();
    if forms.iter().any(|form| holds_bytes(line.as_bytes(), form)) {
        return Some(HIDDEN_LINE.to_string());
    }
    Some(line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    const HOME: &str = "/home/me";
    const BIN: &str = "/Users/me/.cargo/bin/mcp-guardrail-proxy";
    const AUDIT: &str = "/Users/me/.local/state/mcp-guardrail/audit.jsonl";
    const HIDDEN_LINE: &str = "The output held a hidden value, so the app does not show it.";

    /// The table entry for a path from the `INSTALL.md` client reference, under `HOME`.
    fn table_file(platform: Platform, relative: &str) -> ClientFile {
        let home = Path::new(HOME);
        let found = client_files(platform, home)
            .into_iter()
            .find(|file| file.path == home.join(relative));
        assert_eq!(
            found.as_ref().map(|file| file.path.clone()),
            Some(home.join(relative)),
            "INSTALL.md:241-249: the client table lists ~/{relative}"
        );
        found.expect("the assertion above found the file")
    }

    fn project_folder_exists(path: &Path) -> bool {
        path == Path::new("/projects/here")
    }

    /// A login PATH that holds `npx` and `env`, and a `weird` whose full path is not UTF-8.
    fn login_lookup(name: &str) -> Option<PathBuf> {
        match name {
            "npx" => Some(PathBuf::from("/opt/homebrew/bin/npx")),
            "env" => Some(PathBuf::from("/usr/bin/env")),
            "claude" => Some(PathBuf::from("/opt/homebrew/bin/claude")),
            "weird" => Some(PathBuf::from(OsString::from_vec(
                b"/opt/\xffbin/weird".to_vec(),
            ))),
            _ => None,
        }
    }

    type Lookup = dyn Fn(&str) -> Option<PathBuf>;

    fn no_claude_lookup(_name: &str) -> Option<PathBuf> {
        None
    }

    fn row_summary(scan: &FileScan) -> Vec<(String, Status)> {
        let mut rows: Vec<(String, Status)> = scan
            .rows
            .iter()
            .map(|row| (row.server.clone(), row.status))
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }

    struct StatusCase {
        label: &'static str,
        file: &'static str,
        text: &'static str,
        wrapped: usize,
        rows: &'static [(&'static str, Status)],
        reason_has: Option<&'static str>,
        reason_lacks: Option<&'static str>,
    }

    const CURSOR: &str = ".cursor/mcp.json";
    const VSCODE_MACOS: &str = "Library/Application Support/Code/User/mcp.json";
    const WINDSURF: &str = ".codeium/windsurf/mcp_config.json";
    const GEMINI: &str = ".gemini/settings.json";
    const CODEX: &str = ".codex/config.toml";
    const CLAUDE_JSON: &str = ".claude.json";

    const STATUS_CASES: [StatusCase; 39] = [
        StatusCase {
            label: "INSTALL.md:107 already wrapped: bare proxy command, proxy args with an upstream",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "mcp-guardrail-proxy", "args": ["proxy", "--audit-log", "/a.jsonl", "--", "npx"]}}}"#,
            wrapped: 1,
            rows: &[],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:107 already wrapped: a command that ends in /mcp-guardrail-proxy",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy", "--", "npx", "-y"]}}}"#,
            wrapped: 1,
            rows: &[],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:107 not wrapped: a name that only ends in mcp-guardrail-proxy",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "/opt/bin/not-mcp-guardrail-proxy", "args": ["proxy", "--", "npx"]}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:108 remote: a type other than stdio",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"type": "sse", "command": "npx"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Remote)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:108 remote: an empty url and no command",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"url": ""}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Remote)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:108 remote: httpUrl and no command",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"httpUrl": "https://mcp.example.com/mcp"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Remote)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:108 remote: serverUrl and no command",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"serverUrl": "https://mcp.example.com/sse"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Remote)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:108 not remote: a url beside a command",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"url": "https://x.example.com", "command": "npx"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:108 not remote: type stdio",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"type": "stdio", "command": "npx"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:109 disabled: \"disabled\": true in JSON",
            file: WINDSURF,
            text: r#"{"mcpServers": {"s": {"command": "npx", "disabled": true}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Disabled)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:109 not disabled: \"disabled\": false",
            file: WINDSURF,
            text: r#"{"mcpServers": {"s": {"command": "npx", "disabled": false}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:109 disabled: enabled = false in TOML",
            file: CODEX,
            text: "[mcp_servers.s]\ncommand = \"npx\"\nenabled = false\n",
            wrapped: 0,
            rows: &[("s", Status::Disabled)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:109 disabled: a local-scope entry whose project folder does not exist",
            file: CLAUDE_JSON,
            text: r#"{"projects": {"/projects/gone": {"mcpServers": {"gone-s": {"command": "npx"}}}, "/projects/here": {"mcpServers": {"here-s": {"command": "npx"}}}}}"#,
            wrapped: 0,
            rows: &[("gone-s", Status::Disabled), ("here-s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 malformed: no command and no remote key",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"args": ["-y"]}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Malformed)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 malformed: a command that is not a string",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": ["npx"]}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Malformed)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 malformed: args that is a string",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx", "args": "-y"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Malformed)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 malformed: args that holds a number",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx", "args": ["-y", 1]}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Malformed)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 malformed: an empty env key",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx", "env": {"": "v"}}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Malformed)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 malformed: an env key that holds =",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx", "env": {"A=B": "v"}}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Malformed)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 malformed: the proxy command with no token after --",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "/opt/bin/mcp-guardrail-proxy", "args": ["proxy", "--audit-log", "/a.jsonl", "--"]}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Malformed)],
            reason_has: Some("runs the proxy binary in another form"),
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 malformed: the proxy command with args that do not start with proxy",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "mcp-guardrail-proxy", "args": ["check-policy"]}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Malformed)],
            reason_has: Some("runs the proxy binary in another form"),
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:111 wrappable: an entry with no args key",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:111 wrappable: an entry with \"args\": []",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx", "args": []}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:107-108 order: already wrapped comes before remote",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "/opt/bin/mcp-guardrail-proxy", "args": ["proxy", "--", "npx"], "type": "http"}}}"#,
            wrapped: 1,
            rows: &[],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:108-109 order: remote comes before disabled",
            file: WINDSURF,
            text: r#"{"mcpServers": {"s": {"type": "http", "url": "https://x.example.com", "disabled": true}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Remote)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:108-109 order: a remote local entry with a gone project stays remote",
            file: CLAUDE_JSON,
            text: r#"{"projects": {"/projects/gone": {"mcpServers": {"gone-remote": {"url": "https://x.example.com"}}}}}"#,
            wrapped: 0,
            rows: &[("gone-remote", Status::Remote)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:109-110 order: disabled comes before malformed",
            file: WINDSURF,
            text: r#"{"mcpServers": {"s": {"command": 5, "disabled": true}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Disabled)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "a file with no server key gives no rows",
            file: CURSOR,
            text: r#"{"theme": "dark"}"#,
            wrapped: 0,
            rows: &[],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "a server key that holds {} gives no rows",
            file: CURSOR,
            text: r#"{"mcpServers": {}}"#,
            wrapped: 0,
            rows: &[],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:241-249 server key: mcpServers for Gemini CLI",
            file: GEMINI,
            text: r#"{"mcpServers": {"s": {"command": "npx"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:241-249 server key: servers for VS Code",
            file: VSCODE_MACOS,
            text: r#"{"servers": {"s": {"command": "npx"}}}"#,
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:241-249 server key: VS Code does not read mcpServers",
            file: VSCODE_MACOS,
            text: r#"{"mcpServers": {"s": {"command": "npx"}}}"#,
            wrapped: 0,
            rows: &[],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:241-249 server key: [mcp_servers.<name>] for Codex",
            file: CODEX,
            text: "model = \"o3\"\n\n[mcp_servers.s]\ncommand = \"npx\"\nargs = [\"-y\"]\n",
            wrapped: 0,
            rows: &[("s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:241-242 server key: top-level mcpServers and projects.<path>.mcpServers for Claude Code",
            file: CLAUDE_JSON,
            text: r#"{"mcpServers": {"user-s": {"command": "npx"}}, "projects": {"/projects/here": {"mcpServers": {"here-s": {"command": "npx"}}}}}"#,
            wrapped: 0,
            rows: &[("here-s", Status::Wrappable), ("user-s", Status::Wrappable)],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:110 a file that does not parse: one malformed row with the line and the column",
            file: VSCODE_MACOS,
            text: "{\n  // comment\n  \"servers\": {}\n}",
            wrapped: 0,
            rows: &[("", Status::Malformed)],
            reason_has: Some("does not parse at line 2, column 3"),
            reason_lacks: Some("comment"),
        },
        StatusCase {
            label: "INSTALL.md:110 a file that does not parse: the reason quotes no env value",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx", "env": {"TOKEN": "sk-live-abc123" "B": "1"}}}}"#,
            wrapped: 0,
            rows: &[("", Status::Malformed)],
            reason_has: Some("does not parse at line 1, column "),
            reason_lacks: Some("sk-live-abc123"),
        },
        StatusCase {
            label: "INSTALL.md:110 a TOML file that does not parse: one malformed row",
            file: CODEX,
            text: "[mcp_servers.s]\ncommand = \"npx\nargs = [\"tok-in-toml-99\"]\n",
            wrapped: 0,
            rows: &[("", Status::Malformed)],
            reason_has: Some("does not parse at line 2, column "),
            reason_lacks: Some("tok-in-toml-99"),
        },
        StatusCase {
            label: "INSTALL.md:107 Claude Desktop counts a wrapped entry",
            file: "Library/Application Support/Claude/claude_desktop_config.json",
            text: r#"{"mcpServers": {"s": {"command": "/x/mcp-guardrail-proxy", "args": ["proxy", "--", "uvx", "tool"]}}}"#,
            wrapped: 1,
            rows: &[],
            reason_has: None,
            reason_lacks: None,
        },
        StatusCase {
            label: "INSTALL.md:107 Codex counts a wrapped entry",
            file: CODEX,
            text: "[mcp_servers.s]\ncommand = \"/x/mcp-guardrail-proxy\"\nargs = [\"proxy\", \"--\", \"npx\"]\n",
            wrapped: 1,
            rows: &[],
            reason_has: None,
            reason_lacks: None,
        },
    ];

    #[test]
    fn each_entry_gets_the_install_step_5_2_status() {
        for case in STATUS_CASES {
            let file = table_file(Platform::MacOs, case.file);
            let scan = scan_text(&file, case.text, &project_folder_exists);
            assert_eq!(
                scan.wrapped, case.wrapped,
                "{}: the wrapped count",
                case.label
            );
            let expected: Vec<(String, Status)> = case
                .rows
                .iter()
                .map(|(server, status)| (server.to_string(), *status))
                .collect();
            assert_eq!(
                row_summary(&scan),
                expected,
                "{}: the listed rows",
                case.label
            );
            let reason = scan
                .rows
                .first()
                .and_then(|row| row.reason.clone())
                .unwrap_or_default();
            assert!(
                case.reason_has.is_none_or(|text| reason.contains(text)),
                "{}: the reason {reason:?} must hold {:?}",
                case.label,
                case.reason_has
            );
            assert!(
                case.reason_lacks.is_none_or(|text| !reason.contains(text)),
                "{}: the reason {reason:?} must not quote {:?}",
                case.label,
                case.reason_lacks
            );
        }
        for (status, name) in [
            (Status::AlreadyWrapped, "already wrapped"),
            (Status::Remote, "remote"),
            (Status::Disabled, "disabled"),
            (Status::Malformed, "malformed"),
            (Status::Wrappable, "wrappable"),
            (Status::Unreadable, "unreadable"),
        ] {
            assert_eq!(
                serde_json::to_value(status).ok(),
                Some(json!(name)),
                "INSTALL.md:107-111: the page shows the status {name}"
            );
        }
    }

    struct JsonWrapCase {
        label: &'static str,
        file: &'static str,
        text: &'static str,
        audit: &'static str,
        expected: &'static str,
        notes: &'static [&'static str],
    }

    const JSON_WRAP_CASES: [JsonWrapCase; 12] = [
        JsonWrapCase {
            label: "args after command: only the two values change",
            file: CURSOR,
            text: r#"{
  "mcpServers": {
    "s": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "ghp_secret"}
    }
  }
}
"#,
            audit: AUDIT,
            expected: r#"{
  "mcpServers": {
    "s": {
      "command": "/Users/me/.cargo/bin/mcp-guardrail-proxy",
      "args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","/opt/homebrew/bin/npx","-y","@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "ghp_secret"}
    }
  }
}
"#,
            notes: &[],
        },
        JsonWrapCase {
            label: "args before command: the text before, between, and after keeps its order",
            file: VSCODE_MACOS,
            text: r#"{"servers": {"other": {"command": "uvx"}, "s": {"args": ["serve"], "type": "stdio", "command": "npx"}}}"#,
            audit: AUDIT,
            expected: r#"{"servers": {"other": {"command": "uvx"}, "s": {"args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","/opt/homebrew/bin/npx","serve"], "type": "stdio", "command": "/Users/me/.cargo/bin/mcp-guardrail-proxy"}}}"#,
            notes: &[],
        },
        JsonWrapCase {
            label: "no args: one args member goes right after the command value",
            file: WINDSURF,
            text: r#"{"mcpServers": {"s": {"command": "npx", "env": {"A": "1"}}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy","args":["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","/opt/homebrew/bin/npx"], "env": {"A": "1"}}}}"#,
            notes: &[],
        },
        JsonWrapCase {
            label: "\"args\": []: the upstream is the command alone",
            file: GEMINI,
            text: r#"{"mcpServers": {"s": {"command": "npx", "args": []}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","/opt/homebrew/bin/npx"]}}}"#,
            notes: &[],
        },
        JsonWrapCase {
            label: "INSTALL.md:119 a bare command not on the PATH stays bare",
            file: "Library/Application Support/Claude/claude_desktop_config.json",
            text: r#"{"mcpServers": {"s": {"command": "uvx", "args": ["tool"]}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","uvx","tool"]}}}"#,
            notes: &["not found on PATH"],
        },
        JsonWrapCase {
            label: "INSTALL.md:119 a bare command with PATH in env stays bare",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx", "env": {"PATH": "/custom/bin"}}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy","args":["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","npx"], "env": {"PATH": "/custom/bin"}}}}"#,
            notes: &["uses the entry's PATH"],
        },
        JsonWrapCase {
            label: "INSTALL.md:120 a relative command with a full cwd becomes <cwd>/<command>",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "bin/server", "args": [], "cwd": "/srv/app"}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","/srv/app/bin/server"], "cwd": "/srv/app"}}}"#,
            notes: &[],
        },
        JsonWrapCase {
            label: "INSTALL.md:120 a relative command with no cwd stays",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "./server", "args": []}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","./server"]}}}"#,
            notes: &["relative command"],
        },
        JsonWrapCase {
            label: "INSTALL.md:120 a relative command with a relative cwd stays",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "bin/server", "args": [], "cwd": "app"}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","bin/server"], "cwd": "app"}}}"#,
            notes: &["relative command"],
        },
        JsonWrapCase {
            label: "INSTALL.md:127 an arg that names the proxy adds its note",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "env", "args": ["/usr/local/bin/mcp-guardrail-proxy", "serve"]}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","/usr/bin/env","/usr/local/bin/mcp-guardrail-proxy","serve"]}}}"#,
            notes: &["an arg names mcp-guardrail-proxy"],
        },
        JsonWrapCase {
            label: "a resolved upstream path that is not UTF-8 stays bare",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "weird", "args": []}}}"#,
            audit: AUDIT,
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy","--audit-log","/Users/me/.local/state/mcp-guardrail/audit.jsonl","--","weird"]}}}"#,
            notes: &["not found on PATH"],
        },
        JsonWrapCase {
            label: "an audit log path with a quote, a backslash, a space, and non-ASCII text comes out JSON-escaped",
            file: CURSOR,
            text: r#"{"mcpServers": {"s": {"command": "npx", "args": []}}}"#,
            audit: "/Users/me/logs \"q\" \\b/sp é/audit.jsonl",
            expected: r#"{"mcpServers": {"s": {"command": "/Users/me/.cargo/bin/mcp-guardrail-proxy", "args": ["proxy","--audit-log","/Users/me/logs \"q\" \\b/sp é/audit.jsonl","--","/opt/homebrew/bin/npx"]}}}"#,
            notes: &[],
        },
    ];

    #[test]
    fn each_wrappable_json_entry_becomes_the_step_6_entry() {
        for case in JSON_WRAP_CASES {
            let file = table_file(Platform::MacOs, case.file);
            let wrapped = checked_new_text(&file, case.text, "s", BIN, case.audit, &login_lookup)
                .map_err(|error| format!("{error:?}"));
            let expected_notes: Vec<String> =
                case.notes.iter().map(|note| note.to_string()).collect();
            assert_eq!(
                wrapped,
                Ok(NewText {
                    text: case.expected.to_string(),
                    notes: expected_notes,
                }),
                "{}: the whole new file text and the notes",
                case.label
            );
            let rescan = scan_text(&file, case.expected, &project_folder_exists);
            assert_eq!(
                rescan.wrapped, 1,
                "{}: the new entry classifies already wrapped",
                case.label
            );
        }
    }

    struct CodexWrapCase {
        label: &'static str,
        text: &'static str,
        audit: &'static str,
        expected: &'static str,
    }

    const CODEX_WRAP_CASES: [CodexWrapCase; 6] = [
        CodexWrapCase {
            label: "a table with args: only command and args change",
            text: "# Codex config\nmodel = \"o3\"\n\n[mcp_servers.files]\ncommand = \"npx\"\nargs = [\"-y\", \"@scope/files\"]\ncwd = \"/w\"\n",
            audit: AUDIT,
            expected: "# Codex config\nmodel = \"o3\"\n\n[mcp_servers.files]\ncommand = \"/Users/me/.cargo/bin/mcp-guardrail-proxy\"\nargs = [\"proxy\", \"--audit-log\", \"/Users/me/.local/state/mcp-guardrail/audit.jsonl\", \"--\", \"/opt/homebrew/bin/npx\", \"-y\", \"@scope/files\"]\ncwd = \"/w\"\n",
        },
        CodexWrapCase {
            label: "a table with no args: args goes at the end of the table",
            text: "[mcp_servers.files]\ncommand = \"npx\"\ncwd = \"/w\"\n\n[mcp_servers.other]\ncommand = \"uvx\"\n",
            audit: AUDIT,
            expected: "[mcp_servers.files]\ncommand = \"/Users/me/.cargo/bin/mcp-guardrail-proxy\"\ncwd = \"/w\"\nargs = [\"proxy\", \"--audit-log\", \"/Users/me/.local/state/mcp-guardrail/audit.jsonl\", \"--\", \"/opt/homebrew/bin/npx\"]\n\n[mcp_servers.other]\ncommand = \"uvx\"\n",
        },
        CodexWrapCase {
            label: "a comment after command stays",
            text: "[mcp_servers.files]\ncommand = \"npx\"  # the runner\nargs = [\"-y\"]\n",
            audit: AUDIT,
            expected: "[mcp_servers.files]\ncommand = \"/Users/me/.cargo/bin/mcp-guardrail-proxy\"  # the runner\nargs = [\"proxy\", \"--audit-log\", \"/Users/me/.local/state/mcp-guardrail/audit.jsonl\", \"--\", \"/opt/homebrew/bin/npx\", \"-y\"]\n",
        },
        CodexWrapCase {
            label: "an [mcp_servers.<name>.env] subtable stays",
            text: "[mcp_servers.files]\ncommand = \"npx\"\nargs = [\"-y\"]\n\n[mcp_servers.files.env]\nTOKEN = \"t-123\"\n",
            audit: AUDIT,
            expected: "[mcp_servers.files]\ncommand = \"/Users/me/.cargo/bin/mcp-guardrail-proxy\"\nargs = [\"proxy\", \"--audit-log\", \"/Users/me/.local/state/mcp-guardrail/audit.jsonl\", \"--\", \"/opt/homebrew/bin/npx\", \"-y\"]\n\n[mcp_servers.files.env]\nTOKEN = \"t-123\"\n",
        },
        CodexWrapCase {
            label: "a file with no final line end gains one",
            text: "[mcp_servers.files]\ncommand = \"npx\"\nargs = [\"-y\"]",
            audit: AUDIT,
            expected: "[mcp_servers.files]\ncommand = \"/Users/me/.cargo/bin/mcp-guardrail-proxy\"\nargs = [\"proxy\", \"--audit-log\", \"/Users/me/.local/state/mcp-guardrail/audit.jsonl\", \"--\", \"/opt/homebrew/bin/npx\", \"-y\"]\n",
        },
        CodexWrapCase {
            label: "INSTALL.md:184 a value with a quote and a backslash is an escaped basic string",
            text: "[mcp_servers.files]\ncommand = \"npx\"\nargs = []\n",
            audit: "/Users/me/logs \"q\" \\b/audit.jsonl",
            expected: "[mcp_servers.files]\ncommand = \"/Users/me/.cargo/bin/mcp-guardrail-proxy\"\nargs = [\"proxy\", \"--audit-log\", \"/Users/me/logs \\\"q\\\" \\\\b/audit.jsonl\", \"--\", \"/opt/homebrew/bin/npx\"]\n",
        },
    ];

    #[test]
    fn each_wrappable_codex_entry_becomes_the_step_6_entry() {
        let file = table_file(Platform::MacOs, CODEX);
        for case in CODEX_WRAP_CASES {
            let wrapped =
                checked_new_text(&file, case.text, "files", BIN, case.audit, &login_lookup)
                    .map(|new| new.text)
                    .map_err(|error| format!("{error:?}"));
            assert_eq!(
                wrapped,
                Ok(case.expected.to_string()),
                "{}: the whole new file text",
                case.label
            );
            let rescan = scan_text(&file, case.expected, &project_folder_exists);
            assert_eq!(
                rescan.wrapped, 1,
                "{}: the new table classifies already wrapped",
                case.label
            );
        }
    }

    /// An entry whose wrapped form, as the compact JSON text passed to `claude`, has exactly
    /// `wrapped_len` bytes. The wrapped form is the step 6 entry of `INSTALL.md:146-155`.
    fn entry_with_wrapped_len(wrapped_len: usize) -> Value {
        let wrapped_with_no_pad = json!({
            "command": BIN,
            "args": ["proxy", "--audit-log", AUDIT, "--", "/usr/bin/tool"],
            "env": {"PAD": ""},
        });
        let fixed = serde_json::to_string(&wrapped_with_no_pad)
            .expect("serialize the wrapped entry")
            .len();
        json!({"command": "/usr/bin/tool", "env": {"PAD": "p".repeat(wrapped_len - fixed)}})
    }

    #[test]
    fn each_claude_code_blocker_removes_the_checkbox_with_its_reason() {
        let clean = json!({"command": "/usr/bin/tool", "args": ["--port", "5432"]});
        let rows: [(&str, &str, Value, &Lookup, bool); 7] = [
            ("an empty name", "", clean.clone(), &login_lookup, false),
            (
                "a name that starts with -",
                "-db",
                clean.clone(),
                &login_lookup,
                false,
            ),
            (
                "no claude on the PATH",
                "db",
                clean.clone(),
                &no_claude_lookup,
                false,
            ),
            (
                "a wrapped text of 65,536 bytes",
                "db",
                entry_with_wrapped_len(65_536),
                &login_lookup,
                true,
            ),
            (
                "a wrapped text of 65,537 bytes",
                "db",
                entry_with_wrapped_len(65_537),
                &login_lookup,
                false,
            ),
            (
                "an original text over 65,536 bytes",
                "db",
                json!({"command": "/usr/bin/tool", "env": {"PAD": "p".repeat(65_600)}}),
                &login_lookup,
                false,
            ),
            (
                "a row that passes every check",
                "db",
                clean,
                &login_lookup,
                true,
            ),
        ];
        for (label, name, entry, lookup, selectable) in rows {
            assert_eq!(
                claude_code_blocker(name, &entry, BIN, AUDIT, lookup).is_none(),
                selectable,
                "{label}: selectable"
            );
        }
        assert_eq!(
            claude_code_blocker(
                "db",
                &entry_with_wrapped_len(65_537),
                BIN,
                AUDIT,
                &login_lookup
            )
            .map(|blocker| blocker.to_string()),
            Some("The entry is over 64 KiB, too long for the app to pass to claude.".to_string()),
            "the reason of an entry over the cap"
        );
    }

    #[test]
    fn an_entry_holds_another_when_it_has_each_key_with_an_equal_value() {
        let expected = json!({
            "command": BIN,
            "args": ["proxy", "--", "/usr/bin/tool"],
            "env": {"TOKEN": "tok-12345678"},
            "cwd": "/srv/db",
        });
        let rows = [
            ("an equal entry holds", expected.clone(), Ok(())),
            (
                "a stored entry with one more key holds",
                json!({
                    "command": BIN,
                    "args": ["proxy", "--", "/usr/bin/tool"],
                    "env": {"TOKEN": "tok-12345678"},
                    "cwd": "/srv/db",
                    "type": "stdio",
                }),
                Ok(()),
            ),
            (
                "a missing key fails and names the key",
                json!({
                    "command": BIN,
                    "args": ["proxy", "--", "/usr/bin/tool"],
                    "env": {"TOKEN": "tok-12345678"},
                }),
                Err(vec!["cwd".to_string()]),
            ),
            (
                "a changed env value fails and names env with no value",
                json!({
                    "command": BIN,
                    "args": ["proxy", "--", "/usr/bin/tool"],
                    "env": {"TOKEN": "tok-other-999"},
                    "cwd": "/srv/db",
                }),
                Err(vec!["env".to_string()]),
            ),
        ];
        for (label, stored, result) in rows {
            assert_eq!(holds(&stored, &expected), result, "{label}");
        }
    }

    /// A distinctive three-line `env` value. The filler, the tail line, and `[hidden]` share no
    /// byte with it but the line end, and no shown line can hold a line end.
    const MULTI_LINE_VALUE: &str = "QWXZ#1@9\nKVJY$2%8\nPQRU&3*7";
    const FILLER_LINE: &str = "abcdefghijklmnopqrs\n";
    const TAIL_LINE: &str = "\nthe last line";

    /// One output per offset from 0 to 300: filler, then the value, with or without a line after.
    fn offset_cases() -> Vec<(String, Vec<u8>)> {
        let filler = FILLER_LINE.repeat(16);
        let mut cases = Vec::new();
        for offset in 0..=300 {
            for tail in ["", TAIL_LINE] {
                let output = format!("{}{MULTI_LINE_VALUE}{tail}", &filler[..offset]);
                let label = format!("offset {offset}, tail {:?}", !tail.is_empty());
                cases.push((label, output.into_bytes()));
            }
        }
        cases
    }

    fn four_byte_parts(value: &str) -> Vec<Vec<u8>> {
        value.as_bytes().windows(4).map(<[u8]>::to_vec).collect()
    }

    fn holds_part(shown: &str, part: &[u8]) -> bool {
        shown
            .as_bytes()
            .windows(part.len())
            .any(|window| window == part)
    }

    #[test]
    fn shown_child_output_never_holds_a_hidden_value() {
        let forms =
            hidden_forms(&json!({"command": "/usr/bin/tool", "env": {"KEY": MULTI_LINE_VALUE}}));
        let parts = four_byte_parts(MULTI_LINE_VALUE);
        for (label, output) in offset_cases() {
            let shown = shown_line(&output, &forms).unwrap_or_default();
            assert!(
                parts.iter().all(|part| !holds_part(&shown, part)),
                "{label}: the shown line {shown:?} holds a 4-byte part of the value"
            );
        }

        let rows: [(&str, Value, &[u8], Option<&str>); 6] = [
            (
                "overlapping values secret123 and 123456 give one [hidden] and no 456",
                json!({"command": "/usr/bin/tool", "env": {"A": "secret123", "B": "123456"}}),
                b"secret123456\n",
                Some("[hidden]"),
            ),
            (
                "a replacement that completes a form gives the fixed text",
                json!({"command": "/usr/bin/tool", "env": {"A": "abcd", "B": "den]zz"}}),
                b"abcdzz\n",
                Some(HIDDEN_LINE),
            ),
            (
                "a value with a quote and a line end, printed JSON-escaped, is hidden",
                json!({"command": "/usr/bin/tool", "env": {"A": "tok\"en\nline2x"}}),
                br#"error: {"env":{"A":"tok\"en\nline2x"}}
"#,
                Some(r#"error: {"env":{"A":"[hidden]"}}"#),
            ),
            (
                "an args token of 3 bytes shows",
                json!({"command": "/usr/bin/tool", "args": ["abc", "tokenvalue"]}),
                b"failed at abc\n",
                Some("failed at abc"),
            ),
            (
                "an args token of 4 bytes or more is hidden",
                json!({"command": "/usr/bin/tool", "args": ["abc", "tokenvalue"]}),
                b"failed at abc with tokenvalue\n",
                Some("failed at abc with [hidden]"),
            ),
            (
                "a 1-byte env value is hidden",
                json!({"command": "/usr/bin/tool", "env": {"K": "Z"}}),
                b"Z failed\n",
                Some("[hidden] failed"),
            ),
        ];
        for (label, entry, output, expected) in rows {
            assert_eq!(
                shown_line(output, &hidden_forms(&entry)).as_deref(),
                expected,
                "{label}"
            );
        }
    }
}
