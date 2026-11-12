//! Reads the MCP client config files under the home folder for the Servers tab, and wraps the
//! rows that the page selects.
// Red-suite placeholder: every body below is a stub that returns an empty or refusing value.
// IMPLEMENT replaces each body and removes this allow.
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::io::{Seek, SeekFrom};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};
use serde::Serialize;

use crate::clients::{
    ClientFile, ClientId, FileState, Found, Layout, Platform, Readback, ServerId, ServerRow,
    Status, checked_new_text, client_file, client_files, file_row, find_entry, judge_readback,
    restart_step, scan_text, shown_line, writer_blocker,
};

const PROXY_NAME: &str = "mcp-guardrail-proxy";
const BUSY: &str = "A wrap is already running.";
const CHANGED: &str = "changed while the app wrapped it. Scan again.";
const BACKUP_SUFFIX: &str = ".bak-guardrail";
const LOG_PREFIX: &str = "mcp-guardrail-desktop:";
/// The mode of every file the app creates before it gives the file its final mode.
const OWNER_ONLY: u32 = 0o600;
const PERMISSION_BITS: u32 = 0o7777;
const EXECUTE_BITS: u32 = 0o111;

/// What the scan and the wrap read from the app's environment, passed as values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEnv {
    pub home: PathBuf,
    pub platform: Platform,
    pub path: Option<OsString>,
    pub cargo_install_root: Option<OsString>,
    pub cargo_home: Option<OsString>,
    pub audit_log_path: PathBuf,
    pub shell: Option<OsString>,
}

/// What the Servers tab shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServersView {
    pub wrapped: usize,
    pub rows: Vec<ServerRow>,
    pub binary: Option<String>,
    pub audit_log_path: String,
    pub problem: Option<String>,
    pub notes: Vec<String>,
}

const PLUGIN_NOTE: &str =
    "Claude Code plugin servers are not listed here. The install steps in INSTALL.md wrap them.";
const SCAN_STOPPED: &str = "The scan stopped on an internal error.";

impl ServersView {
    /// A view with no rows that shows only `problem`.
    pub fn problem_only(problem: String) -> ServersView {
        ServersView {
            wrapped: 0,
            rows: Vec::new(),
            binary: None,
            audit_log_path: String::new(),
            problem: Some(problem),
            notes: Vec::new(),
        }
    }

    /// The view after a scan task panicked. It never holds the panic text, which can quote
    /// config text.
    pub fn stopped() -> ServersView {
        ServersView::problem_only(SCAN_STOPPED.to_string())
    }
}

/// One client file as the scan found it.
enum FileRead {
    Missing,
    Text(String),
    Unreadable(String),
}

/// Reads a client file whole, with no size cap, because `~/.claude.json` holds project history
/// and a cap would hide its servers. Metadata comes before the open, because an open of a named
/// pipe blocks until a writer appears. `fs::metadata` follows a symlink, so a dotfile link gives
/// its target.
fn read_client_file(path: &Path) -> FileRead {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return FileRead::Missing,
        Err(error) => return FileRead::Unreadable(format!("cannot be read: {error}")),
    };
    let kind = metadata.file_type();
    if kind.is_dir() {
        return FileRead::Unreadable("is a folder, not a file".to_string());
    }
    if kind.is_fifo() {
        return FileRead::Unreadable("is a named pipe, not a file".to_string());
    }
    if !kind.is_file() {
        return FileRead::Unreadable("is not a regular file".to_string());
    }
    match fs::read(path) {
        Err(error) => FileRead::Unreadable(format!("cannot be read: {error}")),
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => FileRead::Text(text),
            Err(_) => FileRead::Unreadable("is not UTF-8 text".to_string()),
        },
    }
}

/// Lists every entry of the client files under `env.home` that is not wrapped.
pub fn scan(env: &HostEnv) -> ServersView {
    let mut view = ServersView {
        wrapped: 0,
        rows: Vec::new(),
        binary: None,
        audit_log_path: env.audit_log_path.display().to_string(),
        problem: None,
        notes: Vec::new(),
    };
    for file in client_files(env.platform, &env.home) {
        let read = read_client_file(&file.path);
        if file.layout == Layout::ClaudeJson && !matches!(read, FileRead::Missing) {
            view.notes.push(PLUGIN_NOTE.to_string());
        }
        match read {
            FileRead::Missing => {}
            FileRead::Unreadable(cause) => {
                view.rows.push(file_row(&file, Status::Unreadable, cause));
            }
            FileRead::Text(text) => {
                let found = scan_text(&file, &text, &|folder| folder.is_dir());
                view.wrapped += found.wrapped;
                view.rows.extend(found.rows);
            }
        }
    }
    let login = login_path(env);
    view.notes.extend(login.note);
    let path = login.path.as_deref();
    view.binary = find_binary(env, path).and_then(|bin| bin.to_str().map(str::to_string));
    let wrap_on = match ready(env, path) {
        Ok(_) => true,
        Err(refusal) => {
            view.problem = Some(refusal.to_string());
            false
        }
    };
    for row in &mut view.rows {
        if row.status != Status::Wrappable {
            continue;
        }
        match writer_blocker(row.id.client) {
            Some(blocker) => row.reason = Some(blocker.to_string()),
            None => row.selectable = wrap_on,
        }
    }
    view
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Wrapped,
    Skipped,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WrapResult {
    pub id: ServerId,
    pub client: String,
    pub server: String,
    pub outcome: Outcome,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WrapReport {
    pub results: Vec<WrapResult>,
}

/// Why Wrap is off for every row. `Display` is the window text.
#[derive(Debug)]
enum WrapRefusal {
    Platform,
    NoBinary {
        cargo: PathBuf,
    },
    BinaryNotUtf8 {
        path: PathBuf,
    },
    AuditNotUtf8 {
        path: PathBuf,
    },
    AuditEmpty,
    AuditRelative {
        path: String,
    },
    AuditNoFileName {
        path: String,
    },
    AuditNamesBackup {
        path: String,
    },
    AuditLinkToMissing,
    AuditNamesClient {
        path: String,
        file: PathBuf,
    },
    AuditIsFolder {
        path: String,
    },
    AuditNotAFile {
        path: String,
    },
    AuditCannotOpen {
        path: String,
        error: io::Error,
    },
    CheckPolicy {
        bin: String,
        how: String,
        line: Option<String>,
    },
}

impl fmt::Display for WrapRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const CHOOSE: &str = "Choose another audit log path.";
        match self {
            Self::Platform => f.write_str("The app wraps servers on macOS and Linux only."),
            Self::NoBinary { cargo } => write!(
                f,
                "Cannot find {PROXY_NAME} on your PATH or at {}. Install it with steps 2 and 3 of INSTALL.md.",
                cargo.display()
            ),
            Self::BinaryNotUtf8 { path } => write!(
                f,
                "The path of {PROXY_NAME}, {}, is not UTF-8, so the app cannot write it into a config file. Install the binary in a folder whose path is UTF-8.",
                path.display()
            ),
            Self::AuditNotUtf8 { path } => write!(
                f,
                "The audit log path {} is not UTF-8, so the app cannot write it into a config file. {CHOOSE}",
                path.display()
            ),
            Self::AuditEmpty => write!(f, "The audit log path is empty. {CHOOSE}"),
            Self::AuditRelative { path } => write!(
                f,
                "The audit log path {path} is not a full path that starts with /. {CHOOSE}"
            ),
            Self::AuditNoFileName { path } => {
                write!(f, "The audit log path {path} names no file. {CHOOSE}")
            }
            Self::AuditNamesBackup { path } => write!(
                f,
                "The audit log path {path} names a backup or a kept copy of a client config, and a wrapped server would write audit lines into it. {CHOOSE}"
            ),
            Self::AuditLinkToMissing => write!(
                f,
                "The audit log path is a link to a file that does not exist. Create that file, or choose another audit log path."
            ),
            Self::AuditNamesClient { path, file } => write!(
                f,
                "The audit log path {path} is the client config {}, and a wrapped server would write audit lines into it. {CHOOSE}",
                file.display()
            ),
            Self::AuditIsFolder { path } => write!(
                f,
                "The audit log {path} is a folder. A wrapped server could not open it, so the app wrapped nothing. Set a log file path in the General tab."
            ),
            Self::AuditNotAFile { path } => write!(
                f,
                "The audit log {path} is not a regular file. A wrapped server could not open it, so the app wrapped nothing. Set a log file path in the General tab."
            ),
            Self::AuditCannotOpen { path, error } => write!(
                f,
                "A wrapped server could not open the audit log {path}: {error}. The app wrapped nothing."
            ),
            Self::CheckPolicy { bin, how, line } => {
                write!(f, "{bin} check-policy {how}, so the app wrapped nothing.")?;
                match line {
                    Some(line) => write!(f, " Its last line: {line}"),
                    None => Ok(()),
                }
            }
        }
    }
}

/// The binary and the audit log path that every row of a wrap writes.
struct Ready {
    bin: String,
    audit_log: String,
}

/// The checks that turn Wrap off for every row. None of them creates a file or a folder, so
/// the scan runs them too.
fn ready(env: &HostEnv, path: Option<&OsStr>) -> Result<Ready, WrapRefusal> {
    if env.platform == Platform::Other {
        return Err(WrapRefusal::Platform);
    }
    let bin = match find_binary(env, path) {
        None => {
            return Err(WrapRefusal::NoBinary {
                cargo: cargo_binary(env),
            });
        }
        Some(found) => found
            .into_os_string()
            .into_string()
            .map_err(|raw| WrapRefusal::BinaryNotUtf8 { path: raw.into() })?,
    };
    if let Some(refusal) = audit_log_refusal(env) {
        return Err(refusal);
    }
    let audit_log = env
        .audit_log_path
        .to_str()
        .ok_or_else(|| WrapRefusal::AuditNotUtf8 {
            path: env.audit_log_path.clone(),
        })?
        .to_string();
    Ok(Ready { bin, audit_log })
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && metadata.permissions().mode() & EXECUTE_BITS != 0
    })
}

/// The first executable regular file `name` in the folders of `path`, as `command -v` finds it.
fn find_on_path(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path?)
        .filter(|folder| folder.is_absolute())
        .map(|folder| folder.join(name))
        .find(|candidate| is_executable_file(candidate))
}

fn non_empty(value: &Option<OsString>) -> Option<PathBuf> {
    value
        .as_ref()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// `${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}/bin/mcp-guardrail-proxy`, where install
/// step 2 puts the binary.
fn cargo_binary(env: &HostEnv) -> PathBuf {
    non_empty(&env.cargo_install_root)
        .or_else(|| non_empty(&env.cargo_home))
        .unwrap_or_else(|| env.home.join(".cargo"))
        .join("bin")
        .join(PROXY_NAME)
}

/// The binary that install step 3 finds: the first on `path`, else the cargo install folder.
pub fn find_binary(env: &HostEnv, path: Option<&OsStr>) -> Option<PathBuf> {
    find_on_path(PROXY_NAME, path).or_else(|| {
        let cargo = cargo_binary(env);
        is_executable_file(&cargo).then_some(cargo)
    })
}

/// The path as the OS resolves it, also when its end does not exist yet: the canonical form of
/// the nearest folder that exists, joined with the rest, where each `..` drops the part before
/// it, as `create_dir_all` and an open resolve it.
fn resolved(path: &Path) -> PathBuf {
    let parts: Vec<Component<'_>> = path.components().collect();
    for keep in (1..parts.len()).rev() {
        let base: PathBuf = parts[..keep].iter().collect();
        let Ok(mut resolved) = fs::canonicalize(&base) else {
            continue;
        };
        for part in &parts[keep..] {
            match part {
                Component::ParentDir => {
                    resolved.pop();
                }
                Component::CurDir => {}
                other => resolved.push(other.as_os_str()),
            }
        }
        return resolved;
    }
    path.to_path_buf()
}

/// A default macOS volume ignores case, so `~/.Cursor/MCP.json` is `~/.cursor/mcp.json`.
fn same_ignoring_ascii_case(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .as_bytes()
        .eq_ignore_ascii_case(right.as_os_str().as_bytes())
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn names_backup(name: &OsStr) -> bool {
    name.to_string_lossy().contains(BACKUP_SUFFIX)
}

/// A proxy appends audit lines to its log. So the log must not be a client file of the table,
/// whether that file exists or not, nor a backup or a kept copy, directly or through a link.
fn audit_log_refusal(env: &HostEnv) -> Option<WrapRefusal> {
    let path = &env.audit_log_path;
    let Some(text) = path.to_str() else {
        return Some(WrapRefusal::AuditNotUtf8 { path: path.clone() });
    };
    if text.is_empty() {
        return Some(WrapRefusal::AuditEmpty);
    }
    let shown = text.to_string();
    if !path.is_absolute() {
        return Some(WrapRefusal::AuditRelative { path: shown });
    }
    let Some(name) = path.file_name() else {
        return Some(WrapRefusal::AuditNoFileName { path: shown });
    };
    if names_backup(name) {
        return Some(WrapRefusal::AuditNamesBackup { path: shown });
    }
    let is_link = fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_symlink());
    let target = fs::metadata(path);
    if is_link
        && target
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
    {
        return Some(WrapRefusal::AuditLinkToMissing);
    }
    let audit = resolved(path);
    let clients = client_files(env.platform, &env.home);
    let named = clients
        .iter()
        .find(|file| same_ignoring_ascii_case(&audit, &resolved(&file.path)));
    if let Some(file) = named {
        return Some(WrapRefusal::AuditNamesClient {
            path: shown,
            file: file.path.clone(),
        });
    }
    let Ok(target) = target else {
        return None;
    };
    let linked = clients
        .iter()
        .find(|file| fs::metadata(&file.path).is_ok_and(|client| same_file(&client, &target)));
    if let Some(file) = linked {
        return Some(WrapRefusal::AuditNamesClient {
            path: shown,
            file: file.path.clone(),
        });
    }
    let real_name = fs::canonicalize(path)
        .ok()
        .and_then(|real| real.file_name().map(OsStr::to_os_string));
    if real_name.is_some_and(|name| names_backup(&name)) {
        return Some(WrapRefusal::AuditNamesBackup { path: shown });
    }
    None
}

/// Makes sure a proxy can open the audit log, with the open of `JsonlAuditSink::create`
/// in the proxy's `telemetry.rs`. A missing log becomes an empty file, as the first proxy start
/// would make it. Metadata comes first, because an open of a named pipe blocks.
fn prepare_audit_log(path: &Path) -> Result<(), WrapRefusal> {
    let shown = path.display().to_string();
    let cannot_open = |error: io::Error| WrapRefusal::AuditCannotOpen {
        path: shown.clone(),
        error,
    };
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            return Err(WrapRefusal::AuditIsFolder {
                path: shown.clone(),
            });
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(WrapRefusal::AuditNotAFile {
                path: shown.clone(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(cannot_open(error)),
    }
    if let Some(folder) = path.parent() {
        fs::create_dir_all(folder).map_err(cannot_open)?;
    }
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(OWNER_ONLY)
        .open(path)
        .map(drop)
        .map_err(cannot_open)
}

/// Wraps the requested rows, one at a time in request order. A problem with one row is a row
/// result. The `Err` text refuses the whole request before any write.
pub fn wrap_request(
    lock: &Mutex<()>,
    env: &HostEnv,
    rows: &[ServerId],
    unix_secs: u64,
) -> Result<WrapReport, String> {
    // The lock guards no data, and each row keeps its original before its change, so a lock
    // that a panic poisoned is free.
    let _running = match lock.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return Err(BUSY.to_string()),
    };
    if rows.is_empty() {
        return Ok(WrapReport {
            results: Vec::new(),
        });
    }
    let started = Instant::now();
    let login = login_path(env);
    let login = login.path.as_deref();
    let ready = ready(env, login).map_err(|refusal| refusal.to_string())?;
    check_policy(&ready.bin, login).map_err(|refusal| refusal.to_string())?;
    prepare_audit_log(&env.audit_log_path).map_err(|refusal| refusal.to_string())?;
    let results: Vec<WrapResult> = rows
        .iter()
        .map(|id| {
            let inputs = RowInputs {
                env,
                id,
                bin: &ready.bin,
                audit_log: &ready.audit_log,
                login_path: login,
                unix_secs,
            };
            let mut kept_copy = None;
            let result = row_result(id, wrap_row(&inputs, &mut kept_copy));
            if result.outcome == Outcome::Failed {
                eprintln!(
                    "{LOG_PREFIX} wrap failed: {} {}: {}",
                    result.client, result.server, result.message
                );
            }
            result
        })
        .collect();
    log_summary(&results, started.elapsed());
    Ok(WrapReport { results })
}

fn row_result(id: &ServerId, end: RowEnd) -> WrapResult {
    WrapResult {
        id: id.clone(),
        client: id.client.label().to_string(),
        server: id.name.clone(),
        outcome: end.outcome,
        message: end.message,
    }
}

fn log_summary(results: &[WrapResult], elapsed: Duration) {
    let count = |outcome: Outcome| {
        results
            .iter()
            .filter(|result| result.outcome == outcome)
            .count()
    };
    eprintln!(
        "{LOG_PREFIX} wrap: {} wrapped, {} skipped, {} failed in {} ms",
        count(Outcome::Wrapped),
        count(Outcome::Skipped),
        count(Outcome::Failed),
        elapsed.as_millis()
    );
}

/// How one row ended. `unrecovered` is an end that no read confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowEnd {
    pub outcome: Outcome,
    pub message: String,
    pub unrecovered: bool,
}

fn skipped(message: String) -> RowEnd {
    RowEnd {
        outcome: Outcome::Skipped,
        message,
        unrecovered: false,
    }
}

/// A row that failed before its change. A kept copy is no longer needed, so it goes.
fn failed_before(kept_copy: Option<&Path>, message: String) -> RowEnd {
    RowEnd {
        outcome: Outcome::Failed,
        message: match kept_copy {
            Some(kept) => with_kept_copy_removed(kept, message),
            None => message,
        },
        unrecovered: false,
    }
}

/// An end that a read confirmed removes the kept copy. A failed remove keeps the outcome and
/// names the copy, which holds the `env` values.
fn with_kept_copy_removed(kept_copy: &Path, message: String) -> String {
    match fs::remove_file(kept_copy) {
        Ok(()) => message,
        Err(error) => format!(
            "{message} The app could not remove {}, which holds your env values: {error}. Remove it.",
            kept_copy.display()
        ),
    }
}

fn no_longer_in(name: &str, file: &Path) -> String {
    format!("Not wrapped: {name} is no longer in {}.", file.display())
}

/// What one row of a wrap needs besides its first read.
pub struct RowInputs<'a> {
    pub env: &'a HostEnv,
    pub id: &'a ServerId,
    pub bin: &'a str,
    pub audit_log: &'a str,
    pub login_path: Option<&'a OsStr>,
    pub unix_secs: u64,
}

impl RowInputs<'_> {
    fn file(&self) -> Option<ClientFile> {
        client_file(self.env.platform, &self.env.home, self.id.client)
    }
}

fn real_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn backup_path(listed: &Path) -> PathBuf {
    suffixed(listed, BACKUP_SUFFIX)
}

/// The bytes, mode, owner, and group of a file, all from one open.
fn read_state(path: &Path) -> io::Result<FileState> {
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::other("it is not a regular file"));
    }
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(FileState {
        bytes,
        mode: metadata.mode() & PERMISSION_BITS,
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}

/// Claude Code rewrites `~/.claude.json` while it runs, so only `claude` may change it
/// (`INSTALL.md` step 6), also through a link from another client path.
fn is_claude_json(env: &HostEnv, real: &Path) -> bool {
    let Some(claude) = client_file(env.platform, &env.home, ClientId::ClaudeCodeUser) else {
        return false;
    };
    if fs::canonicalize(&claude.path).is_ok_and(|path| path == real) {
        return true;
    }
    match (fs::metadata(&claude.path), fs::metadata(real)) {
        (Ok(claude), Ok(other)) => same_file(&claude, &other),
        _ => false,
    }
}

fn wrap_row(inputs: &RowInputs<'_>, kept_copy: &mut Option<PathBuf>) -> RowEnd {
    let id = inputs.id;
    let Some(file) = inputs.file() else {
        return skipped(format!(
            "Not wrapped: the app reads no {} config on this platform.",
            id.client.label()
        ));
    };
    if let Some(blocker) = writer_blocker(id.client) {
        return skipped(format!("Not wrapped: {blocker}"));
    }
    let real = real_path(&file.path);
    if is_claude_json(inputs.env, &real) {
        return failed_before(
            None,
            format!(
                "{} is ~/.claude.json, which changes only through the claude command, so the app left it as it is.",
                file.path.display()
            ),
        );
    }
    match read_state(&real) {
        Ok(first) => wrap_row_from(inputs, first, kept_copy),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            skipped(no_longer_in(&id.name, &file.path))
        }
        Err(error) => failed_before(
            None,
            format!(
                "Cannot read {}: {error}. The app left it as it is.",
                file.path.display()
            ),
        ),
    }
}

/// The row after its first read. Before the rename, a failure leaves the file as the first read
/// found it. The rename is the only write to the file in a row.
pub fn wrap_row_from(
    inputs: &RowInputs<'_>,
    first: FileState,
    kept_copy: &mut Option<PathBuf>,
) -> RowEnd {
    let id = inputs.id;
    let Some(file) = inputs.file() else {
        return skipped(format!(
            "Not wrapped: the app reads no {} config on this platform.",
            id.client.label()
        ));
    };
    let listed = &file.path;
    let shown = listed.display();
    let real = real_path(listed);
    let Ok(text) = std::str::from_utf8(&first.bytes) else {
        return failed_before(
            None,
            format!("{shown} is not UTF-8 text, so the app left it as it is."),
        );
    };
    match find_entry(&file, text, id, &|folder| folder.is_dir()) {
        Found::NotParsed(reason) => {
            return skipped(format!("Not wrapped: {shown} {reason}. Scan again."));
        }
        Found::Missing => return skipped(no_longer_in(&id.name, listed)),
        Found::Entry { status, .. } if status != Status::Wrappable => {
            return skipped(format!("Not wrapped: the entry is {} now.", status.name()));
        }
        Found::Entry { .. } => {}
    }
    let lookup = |name: &str| find_on_path(name, inputs.login_path);
    let new = match checked_new_text(&file, text, &id.name, inputs.bin, inputs.audit_log, &lookup) {
        Ok(new) => new,
        Err(error) => {
            return failed_before(
                None,
                format!(
                    "The app could not build the new entry: {}. It left {shown} as it was.",
                    error.reason
                ),
            );
        }
    };
    if let Err(error) = write_backup(listed, &first) {
        return failed_before(None, write_failure(&error, listed, &backup_path(listed)));
    }
    let kept = match create_kept_copy(listed, &first.bytes, inputs.unix_secs) {
        Ok(kept) => kept,
        Err((kept, error)) => {
            return failed_before(
                None,
                format!(
                    "Cannot create the kept copy {}: {error}. The app left {shown} as it was.",
                    kept.display()
                ),
            );
        }
    };
    *kept_copy = Some(kept.clone());
    let temp = suffixed(&real, &format!(".{}.tmp", std::process::id()));
    if let Err(error) = write_temp(&temp, new.text.as_bytes(), first.gid, first.mode) {
        return failed_before(Some(&kept), write_failure(&error, listed, &temp));
    }
    if !read_state(&real).is_ok_and(|now| now == first) {
        let _ = fs::remove_file(&temp);
        return failed_before(Some(&kept), format!("{shown} {CHANGED}"));
    }
    if fs::rename(&temp, &real).is_err() {
        let _ = fs::remove_file(&temp);
    }
    let readback = fs::read(&real).ok();
    let mut end = end_file_row(
        inputs,
        new.text.as_bytes(),
        &first,
        readback.as_deref(),
        &kept,
    );
    if end.outcome == Outcome::Wrapped && !new.notes.is_empty() {
        end.message
            .push_str(&format!(" Notes: {}.", new.notes.join(", ")));
    }
    end
}

/// Judges a file row by what the read after the rename holds, never by the rename's result.
pub fn end_file_row(
    inputs: &RowInputs<'_>,
    new_text: &[u8],
    first: &FileState,
    readback: Option<&[u8]>,
    kept_copy: &Path,
) -> RowEnd {
    let listed = inputs.file().map(|file| file.path).unwrap_or_default();
    let shown = listed.display();
    let kept = kept_copy.display();
    match judge_readback(readback, new_text, &first.bytes) {
        Readback::Wrapped => RowEnd {
            outcome: Outcome::Wrapped,
            message: with_kept_copy_removed(
                kept_copy,
                format!(
                    "Wrapped. Backup: {}. {}",
                    backup_path(&listed).display(),
                    restart_step(inputs.id)
                ),
            ),
            unrecovered: false,
        },
        Readback::Original => RowEnd {
            outcome: Outcome::Failed,
            message: with_kept_copy_removed(
                kept_copy,
                format!("The app could not replace {shown}, so the file is as it was."),
            ),
            unrecovered: false,
        },
        Readback::Unrecovered => RowEnd {
            outcome: Outcome::Failed,
            message: match readback {
                None => format!(
                    "The app cannot read {shown} after its write. Its original is in {kept}. Scan again."
                ),
                Some(_) => format!(
                    "{shown} changed after the app wrote it, so the app left it as it is. Its original is in {kept}. Scan again."
                ),
            },
            unrecovered: true,
        },
    }
}

/// A temp file that could not take the group of the file it replaces.
#[derive(Debug)]
struct GroupRefused(io::Error);

impl fmt::Display for GroupRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot set the group: {}", self.0)
    }
}

impl std::error::Error for GroupRefused {}

fn is_group_refusal(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<GroupRefused>())
}

fn write_failure(error: &io::Error, listed: &Path, target: &Path) -> String {
    if is_group_refusal(error) {
        format!(
            "The app cannot give the new file the group of {}, so it left the file as it was.",
            listed.display()
        )
    } else {
        format!(
            "Cannot write {}: {error}. The app left {} as it was.",
            target.display(),
            listed.display()
        )
    }
}

/// Opens a new temp file with mode 0600 before its first byte, so no other user can read a copy
/// of a `0600` file. `create_new` refuses a name that exists, which also stops a write through a
/// link. The group of the file it replaces comes right after the open, because a new file takes
/// the folder's or the process's group, and members of that group could read a `0640` file.
pub fn open_temp(path: &Path, gid: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(OWNER_ONLY)
        .open(path)?;
    if let Err(error) = std::os::unix::fs::fchown(&file, None, Some(gid)) {
        let _ = fs::remove_file(path);
        return Err(io::Error::new(error.kind(), GroupRefused(error)));
    }
    Ok(file)
}

/// Writes and syncs a temp file, then gives it the mode of the file it replaces. On any error
/// the temp file goes.
fn write_temp(path: &Path, bytes: &[u8], gid: u32, mode: u32) -> io::Result<()> {
    let mut file = open_temp(path, gid)?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(mode)));
    if written.is_err() {
        let _ = fs::remove_file(path);
    }
    written
}

/// `<file>.bak-guardrail` beside the listed path, as step 6.1 names it. The rename replaces a
/// link at that name and never writes through it.
fn write_backup(listed: &Path, first: &FileState) -> io::Result<()> {
    let backup = backup_path(listed);
    let temp = suffixed(&backup, &format!(".{}.tmp", std::process::id()));
    write_temp(&temp, &first.bytes, first.gid, first.mode)?;
    fs::rename(&temp, &backup).inspect_err(|_| {
        let _ = fs::remove_file(&temp);
    })
}

/// The original under a name that no later backup write reaches, kept until a read confirms
/// the row's end. `create_new` fails when any file or link has the name.
fn create_kept_copy(
    listed: &Path,
    bytes: &[u8],
    unix_secs: u64,
) -> Result<PathBuf, (PathBuf, io::Error)> {
    let kept = suffixed(listed, &format!("{BACKUP_SUFFIX}-{unix_secs}"));
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(OWNER_ONLY)
        .open(&kept)
    {
        Ok(file) => file,
        Err(error) => return Err((kept, error)),
    };
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&kept);
        return Err((kept, error));
    }
    Ok(kept)
}

pub fn run_rows(
    _env: &HostEnv,
    _rows: &[ServerId],
    _row: &mut dyn FnMut(&ServerId, &mut Option<PathBuf>) -> RowEnd,
) -> Vec<WrapResult> {
    Vec::new()
}

/// The PATH that the login shell printed, or the app's own PATH with a note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginPath {
    pub path: Option<OsString>,
    pub note: Option<String>,
}

/// Each half of the marker is one `printf` argument, so a shell that echoes its command line
/// prints no whole marker before the PATH.
const PRINT_PATH: &str = r#"printf "%s%s\n" "__MCP_GUARDRAIL_PATH__=" "$PATH""#;
const PATH_MARKER: &[u8] = b"__MCP_GUARDRAIL_PATH__=";
const FALLBACK_SHELL: &str = "/bin/sh";
const LOGIN_PATH_NOTE: &str = "The app could not read the PATH of your login shell, so it looks for programs on its own PATH.";
pub const LOGIN_SHELL_TIMEOUT: Duration = Duration::from_secs(10);

/// The PATH that `"$SHELL" -i -l` sets up, where version managers add folders. A macOS app that
/// Finder starts has a short PATH that lacks them. `-i` reads `.zshrc` and `.bashrc`.
pub fn login_path(env: &HostEnv) -> LoginPath {
    let shell = env
        .shell
        .as_deref()
        .map(Path::new)
        .filter(|shell| shell.is_absolute())
        .unwrap_or(Path::new(FALLBACK_SHELL));
    let mut command = Command::new(shell);
    command
        .args(["-i", "-l", "-c", PRINT_PATH])
        .env("HOME", &env.home);
    let printed = match run_child(&mut command, LOGIN_SHELL_TIMEOUT) {
        Ok(ChildRun {
            exit: Some(status),
            stdout: ChildOutput::Whole(stdout),
            ..
        }) if status.success() => marker_path(&stdout),
        _ => None,
    };
    match printed {
        Some(path) => LoginPath {
            path: Some(OsString::from_vec(path)),
            note: None,
        },
        None => LoginPath {
            path: env.path.clone(),
            note: Some(LOGIN_PATH_NOTE.to_string()),
        },
    }
}

/// The text after the last marker, up to the end of that line. Startup files can print before
/// it, and a startup line can hold the marker too.
fn marker_path(stdout: &[u8]) -> Option<Vec<u8>> {
    let start = stdout
        .windows(PATH_MARKER.len())
        .rposition(|window| window == PATH_MARKER)?
        + PATH_MARKER.len();
    let rest = &stdout[start..];
    let end = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(rest.len());
    Some(rest[..end].to_vec())
}

/// One output stream of a child: the whole text, or why the app kept none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChildOutput {
    Whole(Vec<u8>),
    TooLong,
    Dropped,
}

/// A child's end. `exit` is `None` when the app killed it at its timeout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildRun {
    pub exit: Option<ExitStatus>,
    pub stdout: ChildOutput,
    pub stderr: ChildOutput,
}

/// The most bytes the app keeps of one child output stream.
const MAX_CHILD_OUTPUT: u64 = 65_536;
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Runs `command` in a new session, with stdin at end of file and each output stream in an
/// unnamed temp file. It waits only for the direct child, so a descendant that keeps a stream
/// open cannot hold the scan, the wrap, or the wrap lock. At `timeout` it kills the child's
/// process group, reaps the child, and keeps no output, because the kill can stop a write in
/// the middle of a value.
pub fn run_child(command: &mut Command, timeout: Duration) -> io::Result<ChildRun> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    // SAFETY: the hook runs between fork and exec, where only async-signal-safe calls are
    // sound. `setsid` is one, and the closure allocates nothing and takes no lock. A new
    // session has no controlling terminal, so an `-i` shell cannot stop to wait for one.
    unsafe {
        command.pre_exec(|| rustix::process::setsid().map(drop).map_err(io::Error::from));
    }
    let mut child = command.spawn()?;
    let started = Instant::now();
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(error) => {
                stop_child(&mut child);
                return Err(error);
            }
        }
        let waited = started.elapsed();
        if waited >= timeout {
            stop_child(&mut child);
            break None;
        }
        std::thread::sleep(CHILD_POLL_INTERVAL.min(timeout - waited));
    };
    let ended = exit.is_some();
    Ok(ChildRun {
        exit,
        stdout: kept_output(stdout, ended)?,
        stderr: kept_output(stderr, ended)?,
    })
}

/// The child leads its own process group, and the group id stays its pid until the app reaps
/// it, so the kill reaches no other process.
fn stop_child(child: &mut Child) {
    let _ = rustix::process::kill_process_group(Pid::from_child(child), Signal::KILL);
    let _ = child.wait();
}

/// The whole stream, or none of it. A cut stream could end in part of a value.
fn kept_output(mut file: File, ended: bool) -> io::Result<ChildOutput> {
    if !ended {
        return Ok(ChildOutput::Dropped);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_CHILD_OUTPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CHILD_OUTPUT {
        return Ok(ChildOutput::TooLong);
    }
    Ok(ChildOutput::Whole(bytes))
}

const POLICY_OK: &[u8] = b"policy OK:";
pub const CHECK_POLICY_TIMEOUT: Duration = Duration::from_secs(10);

/// How a child ended, for a message.
fn exit_text(exit: Option<ExitStatus>, timeout: Duration) -> String {
    match exit {
        None => format!("did not end within {} s", timeout.as_secs()),
        Some(status) => match (status.code(), status.signal()) {
            (Some(code), _) => format!("exited with status {code}"),
            (None, Some(signal)) => format!("stopped on signal {signal}"),
            (None, None) => "stopped".to_string(),
        },
    }
}

/// Install step 3 runs the same test. It stops a wrap that would point
/// every server at a binary that cannot start, such as one that macOS quarantines.
fn check_policy(bin: &str, path: Option<&OsStr>) -> Result<(), WrapRefusal> {
    let mut command = Command::new(bin);
    command.arg("check-policy");
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let run = run_child(&mut command, CHECK_POLICY_TIMEOUT).map_err(|error| {
        WrapRefusal::CheckPolicy {
            bin: bin.to_string(),
            how: format!("could not start: {error}"),
            line: None,
        }
    })?;
    let how = match (&run.exit, &run.stdout) {
        (Some(status), ChildOutput::Whole(stdout))
            if status.success() && stdout.starts_with(POLICY_OK) =>
        {
            return Ok(());
        }
        (Some(status), ChildOutput::TooLong) if status.success() => {
            "printed more than 64 KiB".to_string()
        }
        (Some(status), _) if status.success() => "did not print policy OK:".to_string(),
        (exit, _) => exit_text(*exit, CHECK_POLICY_TIMEOUT),
    };
    let line = match &run.stderr {
        ChildOutput::Whole(stderr) => shown_line(stderr, &[]),
        ChildOutput::TooLong | ChildOutput::Dropped => None,
    };
    Err(WrapRefusal::CheckPolicy {
        bin: bin.to_string(),
        how,
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::{ClientId, Status};
    use serde_json::{Value, json};
    use std::fs;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::sync::{Arc, mpsc};
    use std::time::Instant;

    const SECS: u64 = 1_794_355_200;
    const OK_PROXY: &str = "#!/bin/sh\nif [ \"$1\" = check-policy ]; then\n  echo 'policy OK: policies/default-policy.toml: 12 rules, 3 taint sources'\n  exit 0\nfi\nexit 0\n";
    const CURSOR: &str = ".cursor/mcp.json";
    const CURSOR_TEXT: &str = r#"{"mcpServers": {"files": {"command": "npx", "args": ["-y", "@scope/files"], "env": {"TOKEN": "tok-12345678"}}}}"#;
    const WINDSURF: &str = ".codeium/windsurf/mcp_config.json";
    const WINDSURF_TEXT: &str = r#"{"mcpServers": {"notes": {"command": "npx"}}}"#;
    const PLUGIN_NOTE: &str = "Claude Code plugin servers are not listed here. The install steps in INSTALL.md wrap them.";
    const CHANGED: &str = "changed while the app wrapped it. Scan again.";
    const STOPPED_FILE: &str = "Not wrapped: an earlier row could not confirm";
    const STOPPED_FILE_END: &str = "Read the result of that row.";
    const CAP_REASON: &str = "The entry is over 64 KiB, too long for the app to pass to claude.";
    const SECRET: &str = "tok-12345678";

    /// Puts something other than a readable file at a client path.
    type Prepare = fn(&Path);
    /// Links a client path to `~/.claude.json`.
    type Link = fn(&Path, &Path);
    /// Changes one field of a first read, or says that this machine cannot.
    type Change = fn(&mut FileState) -> bool;

    fn write_script(path: &Path, body: &[u8]) {
        fs::create_dir_all(path.parent().expect("a script folder"))
            .expect("create the script folder");
        fs::write(path, body).expect("write the stub script");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("make the stub executable");
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set the file mode");
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).map_or(0, |metadata| metadata.mode() & 0o7777)
    }

    fn gid_of(path: &Path) -> u32 {
        fs::metadata(path).map_or(u32::MAX, |metadata| metadata.gid())
    }

    fn mkfifo(path: &Path) {
        let status = Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo makes {}", path.display());
    }

    fn runs_as_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    fn groups_of_user() -> Vec<u32> {
        let mut groups: Vec<u32> = rustix::process::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(|group| group.as_raw())
            .collect();
        groups.push(rustix::process::getegid().as_raw());
        groups
    }

    fn other_group_of_user(not: u32) -> Option<u32> {
        groups_of_user().into_iter().find(|group| *group != not)
    }

    fn group_user_is_not_in() -> u32 {
        groups_of_user().into_iter().max().unwrap_or(0) + 1
    }

    /// The group that a new file in `folder` gets from the OS.
    fn new_file_group(folder: &Path) -> u32 {
        let probe = folder.join("group-probe");
        fs::write(&probe, "").expect("write the group probe");
        let group = gid_of(&probe);
        fs::remove_file(&probe).expect("remove the group probe");
        group
    }

    fn file_state(path: &Path) -> FileState {
        let metadata = fs::metadata(path).expect("read the file metadata");
        FileState {
            bytes: fs::read(path).expect("read the file"),
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        }
    }

    fn names_in(folder: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(folder)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn no_temp_or_kept_copy(folder: &Path) -> bool {
        names_in(folder)
            .iter()
            .all(|name| !name.ends_with(".tmp") && !name.contains(".bak-guardrail-"))
    }

    /// Every path under `root` with its type, mode, and bytes. A link is listed, not followed.
    fn tree(root: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        walk(root, root, &mut lines);
        lines.sort();
        lines
    }

    fn walk(root: &Path, folder: &Path, lines: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(folder) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let name = path
                .strip_prefix(root)
                .unwrap_or(path.as_path())
                .display()
                .to_string();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(&path).unwrap_or_default();
                lines.push(format!("{name} -> {}", target.display()));
            } else if metadata.is_dir() {
                lines.push(format!("{name}/"));
                walk(root, &path, lines);
            } else if metadata.is_file() {
                let bytes = fs::read(&path).unwrap_or_default();
                lines.push(format!(
                    "{name} {:o} {}",
                    metadata.mode() & 0o7777,
                    String::from_utf8_lossy(&bytes)
                ));
            } else {
                lines.push(format!("{name} (special)"));
            }
        }
    }

    /// Runs `work` on its own thread, so a call that blocks fails the test instead of hanging it.
    fn within<T: Send + 'static>(
        limit: Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver.recv_timeout(limit).ok()
    }

    fn wait_until(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < limit {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        condition()
    }

    fn login_shell_script(login: &[u8]) -> Vec<u8> {
        let mut body =
            b"#!/bin/sh\nprintf 'startup line\\n'\nprintf '%s%s\\n' '__MCP_GUARDRAIL_PATH__=' '"
                .to_vec();
        body.extend_from_slice(login);
        body.extend_from_slice(b"'\n");
        body
    }

    /// A temp root with a home folder, a `bin` folder that holds a passing proxy stub and an
    /// `npx` stub, and a login shell stub that prints `<bin>:/usr/bin:/bin` as the PATH.
    struct Sandbox {
        _dir: tempfile::TempDir,
        root: PathBuf,
        home: PathBuf,
        bin: PathBuf,
        shell: PathBuf,
        login: OsString,
    }

    fn sandbox() -> Sandbox {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let root = dir.path().to_path_buf();
        let home = root.join("home");
        fs::create_dir_all(&home).expect("create the sandbox home");
        let bin = root.join("bin");
        write_script(&bin.join("mcp-guardrail-proxy"), OK_PROXY.as_bytes());
        write_script(&bin.join("npx"), b"#!/bin/sh\nexit 0\n");
        let login = OsString::from(format!("{}:/usr/bin:/bin", bin.display()));
        let shell = root.join("login-shell");
        write_script(&shell, &login_shell_script(login.as_bytes()));
        Sandbox {
            _dir: dir,
            root,
            home,
            bin,
            shell,
            login,
        }
    }

    impl Sandbox {
        fn env(&self) -> HostEnv {
            HostEnv {
                home: self.home.clone(),
                platform: Platform::MacOs,
                path: Some(self.login.clone()),
                cargo_install_root: None,
                cargo_home: None,
                audit_log_path: self.home.join(".local/state/mcp-guardrail/audit.jsonl"),
                shell: Some(self.shell.clone().into_os_string()),
            }
        }

        fn with_login_path(mut self, login: OsString) -> Sandbox {
            write_script(&self.shell, &login_shell_script(login.as_bytes()));
            self.login = login;
            self
        }

        fn bin_text(&self) -> String {
            self.bin.join("mcp-guardrail-proxy").display().to_string()
        }

        fn npx_text(&self) -> String {
            self.bin.join("npx").display().to_string()
        }

        fn audit_text(&self) -> String {
            self.env().audit_log_path.display().to_string()
        }

        fn login_text(&self) -> String {
            self.login.to_string_lossy().into_owned()
        }

        fn put(&self, relative: &str, text: &str) -> PathBuf {
            let path = self.home.join(relative);
            fs::create_dir_all(path.parent().expect("a parent folder"))
                .expect("create the client folder");
            fs::write(&path, text).expect("write the client file");
            path
        }

        fn kept_copy(&self, relative: &str) -> PathBuf {
            self.home.join(format!("{relative}.bak-guardrail-{SECS}"))
        }
    }

    /// `CURSOR_TEXT` with the step 6 entry of `INSTALL.md:146-155`, spliced in place.
    fn wrapped_cursor_text(sb: &Sandbox) -> String {
        format!(
            r#"{{"mcpServers": {{"files": {{"command": "{bin}", "args": ["proxy","--audit-log","{audit}","--","{npx}","-y","@scope/files"], "env": {{"TOKEN": "tok-12345678"}}}}}}}}"#,
            bin = sb.bin_text(),
            audit = sb.audit_text(),
            npx = sb.npx_text(),
        )
    }

    fn server(client: ClientId, name: &str) -> ServerId {
        ServerId {
            client,
            project: None,
            name: name.to_string(),
        }
    }

    fn outcomes(report: &Result<WrapReport, String>) -> Vec<Outcome> {
        report.as_ref().map_or_else(
            |_| Vec::new(),
            |report| report.results.iter().map(|result| result.outcome).collect(),
        )
    }

    /// Every result message, one per line, or the refusal text.
    fn messages(report: &Result<WrapReport, String>) -> String {
        match report {
            Ok(report) => report
                .results
                .iter()
                .map(|result| result.message.clone())
                .collect::<Vec<_>>()
                .join("\n"),
            Err(error) => error.clone(),
        }
    }

    fn listed_rows(view: &ServersView) -> Vec<(String, String, String, String)> {
        let mut rows: Vec<(String, String, String, String)> = view
            .rows
            .iter()
            .map(|row| {
                (
                    row.server.clone(),
                    row.client.clone(),
                    row.scope.clone(),
                    row.file.clone(),
                )
            })
            .collect();
        rows.sort();
        rows
    }

    fn listed_ids(view: &ServersView) -> Vec<ServerId> {
        let mut ids: Vec<ServerId> = view.rows.iter().map(|row| row.id.clone()).collect();
        ids.sort_by(|left, right| left.name.cmp(&right.name));
        ids
    }

    fn statuses(view: &ServersView) -> Vec<(String, Status)> {
        let mut rows: Vec<(String, Status)> = view
            .rows
            .iter()
            .map(|row| (row.server.clone(), row.status))
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }

    fn selectable(view: &ServersView) -> Vec<(String, bool)> {
        let mut rows: Vec<(String, bool)> = view
            .rows
            .iter()
            .map(|row| (row.server.clone(), row.selectable))
            .collect();
        rows.sort();
        rows
    }

    struct RowSetup {
        env: HostEnv,
        id: ServerId,
        bin: String,
        audit: String,
        login: OsString,
    }

    impl RowSetup {
        fn new(sb: &Sandbox, id: ServerId) -> RowSetup {
            RowSetup {
                env: sb.env(),
                id,
                bin: sb.bin_text(),
                audit: sb.audit_text(),
                login: sb.login.clone(),
            }
        }

        fn inputs(&self) -> RowInputs<'_> {
            RowInputs {
                env: &self.env,
                id: &self.id,
                bin: &self.bin,
                audit_log: &self.audit,
                login_path: Some(&self.login),
                unix_secs: SECS,
            }
        }
    }

    #[test]
    fn a_scan_lists_each_unwrapped_entry_under_home() {
        let sb = sandbox();
        let view = scan(&sb.env());
        assert!(view.rows.is_empty(), "no client file: no rows");
        assert_eq!(view.wrapped, 0, "no client file: the found-no-config state");
        assert_eq!(view.problem, None, "no client file: no problem");
        assert!(
            !view.notes.iter().any(|note| note == PLUGIN_NOTE),
            "no ~/.claude.json: no plugin note"
        );

        let sb = sandbox();
        sb.put(
            CURSOR,
            r#"{"mcpServers": {"a": {"command": "/x/mcp-guardrail-proxy", "args": ["proxy", "--", "npx"]}, "b": {"command": "mcp-guardrail-proxy", "args": ["proxy", "--audit-log", "/a.jsonl", "--", "uvx"]}}}"#,
        );
        sb.put(
            ".gemini/settings.json",
            r#"{"mcpServers": {"c": {"command": "/x/mcp-guardrail-proxy", "args": ["proxy", "--", "node"]}}}"#,
        );
        let view = scan(&sb.env());
        assert_eq!(view.wrapped, 3, "every entry wrapped: the count");
        assert!(view.rows.is_empty(), "every entry wrapped: no rows");
        assert_eq!(view.problem, None, "every entry wrapped: no problem");

        let sb = sandbox();
        let project = sb.root.join("project");
        fs::create_dir_all(&project).expect("create the project folder");
        let project_text = project.display().to_string();
        sb.put(
            ".claude.json",
            &json!({
                "mcpServers": {"cc-user": {"command": "npx"}},
                "projects": {project_text.clone(): {"mcpServers": {"cc-local": {"command": "npx"}}}},
            })
            .to_string(),
        );
        sb.put(
            ".codex/config.toml",
            "[mcp_servers.codex-srv]\ncommand = \"npx\"\n",
        );
        sb.put(
            "Library/Application Support/Claude/claude_desktop_config.json",
            r#"{"mcpServers": {"desktop-srv": {"command": "npx"}}}"#,
        );
        sb.put(
            CURSOR,
            r#"{"mcpServers": {"cursor-srv": {"command": "npx"}}}"#,
        );
        sb.put(
            "Library/Application Support/Code/User/mcp.json",
            r#"{"servers": {"vscode-srv": {"command": "npx"}}}"#,
        );
        sb.put(
            WINDSURF,
            r#"{"mcpServers": {"windsurf-srv": {"command": "npx"}}}"#,
        );
        sb.put(
            ".gemini/settings.json",
            r#"{"mcpServers": {"gemini-srv": {"command": "npx"}}}"#,
        );
        let view = scan(&sb.env());
        let file = |relative: &str| sb.home.join(relative).display().to_string();
        let row = |server: &str, client: &str, scope: &str, relative: &str| {
            (
                server.to_string(),
                client.to_string(),
                scope.to_string(),
                file(relative),
            )
        };
        let local_scope = format!("local: {project_text}");
        assert_eq!(
            listed_rows(&view),
            vec![
                row("cc-local", "Claude Code", &local_scope, ".claude.json"),
                row("cc-user", "Claude Code", "user", ".claude.json"),
                row("codex-srv", "Codex", "user", ".codex/config.toml"),
                row("cursor-srv", "Cursor", "user", CURSOR),
                row(
                    "desktop-srv",
                    "Claude Desktop",
                    "user",
                    "Library/Application Support/Claude/claude_desktop_config.json"
                ),
                row("gemini-srv", "Gemini CLI", "user", ".gemini/settings.json"),
                row(
                    "vscode-srv",
                    "VS Code",
                    "user",
                    "Library/Application Support/Code/User/mcp.json"
                ),
                row("windsurf-srv", "Windsurf", "user", WINDSURF),
            ],
            "one file for each client: client, scope, server, and file of each row"
        );
        assert_eq!(
            listed_ids(&view),
            vec![
                ServerId {
                    client: ClientId::ClaudeCodeLocal,
                    project: Some(project_text.clone()),
                    name: "cc-local".to_string(),
                },
                server(ClientId::ClaudeCodeUser, "cc-user"),
                server(ClientId::Codex, "codex-srv"),
                server(ClientId::Cursor, "cursor-srv"),
                server(ClientId::ClaudeDesktop, "desktop-srv"),
                server(ClientId::GeminiCli, "gemini-srv"),
                server(ClientId::VsCode, "vscode-srv"),
                server(ClientId::Windsurf, "windsurf-srv"),
            ],
            "one file for each client: the id the page sends back"
        );
        assert!(
            view.notes.iter().any(|note| note == PLUGIN_NOTE),
            "~/.claude.json exists: the plugin note"
        );

        let unreadable: [(&str, Prepare); 3] = [
            ("a folder", |path| {
                fs::create_dir_all(path).expect("create a folder at the client path")
            }),
            ("a named pipe", mkfifo),
            ("a file that is not UTF-8", |path| {
                fs::write(path, b"{\"mcpServers\": {\"s\": {\"command\": \"\xff\"}}}")
                    .expect("write bytes that are not UTF-8")
            }),
        ];
        for (label, prepare) in unreadable {
            let sb = sandbox();
            let cursor = sb.home.join(CURSOR);
            fs::create_dir_all(cursor.parent().expect("the Cursor folder"))
                .expect("create the Cursor folder");
            prepare(&cursor);
            let env = sb.env();
            let view = within(Duration::from_secs(30), move || scan(&env))
                .unwrap_or_else(|| panic!("{label}: the scan returns, with no block"));
            assert_eq!(
                statuses(&view),
                vec![(String::new(), Status::Unreadable)],
                "{label}: one unreadable row"
            );
            assert_eq!(
                view.rows.first().map(|row| row.file.clone()),
                Some(cursor.display().to_string()),
                "{label}: the row names the file"
            );
            assert!(
                view.rows
                    .first()
                    .and_then(|row| row.reason.as_deref())
                    .is_some_and(|reason| !reason.is_empty()),
                "{label}: the row gives the cause"
            );
        }

        let sb = sandbox();
        let cursor = sb.put(CURSOR, r#"{"mcpServers": {"s": {"command": "npx"}}}"#);
        set_mode(&cursor, 0o000);
        if fs::read(&cursor).is_ok() {
            eprintln!("skip the mode 000 case: this test runs as root, which reads any file");
        } else {
            let view = scan(&sb.env());
            assert_eq!(
                statuses(&view),
                vec![(String::new(), Status::Unreadable)],
                "a file the app cannot read: one unreadable row"
            );
        }
        set_mode(&cursor, 0o600);

        let sb = sandbox();
        let target = sb.root.join("dots/cursor.json");
        fs::create_dir_all(target.parent().expect("the dots folder")).expect("create dots");
        fs::write(&target, r#"{"mcpServers": {"linked": {"command": "npx"}}}"#)
            .expect("write the link target");
        fs::create_dir_all(sb.home.join(".cursor")).expect("create the Cursor folder");
        symlink(&target, sb.home.join(CURSOR)).expect("link the Cursor file");
        let view = scan(&sb.env());
        assert_eq!(
            statuses(&view),
            vec![("linked".to_string(), Status::Wrappable)],
            "a client file that is a symlink: the scan reads its target"
        );

        let sb = sandbox();
        let history = "h".repeat(1_100_000);
        let big = sb.put(
            ".claude.json",
            &json!({
                "mcpServers": {"big-user": {"command": "npx"}},
                "projects": {"/history": {"history": history}},
            })
            .to_string(),
        );
        assert!(
            fs::metadata(&big).map_or(0, |metadata| metadata.len()) > 1_048_576,
            "the fixture is over 1 MiB"
        );
        let view = scan(&sb.env());
        assert_eq!(
            statuses(&view),
            vec![("big-user".to_string(), Status::Wrappable)],
            "a ~/.claude.json over 1 MiB: read whole, and its rows listed"
        );

        let platforms: [(Platform, &[(&str, &str)]); 2] = [
            (
                Platform::Linux,
                &[("vscode-linux", ".config/Code/User/mcp.json")],
            ),
            (
                Platform::MacOs,
                &[
                    (
                        "desktop-srv",
                        "Library/Application Support/Claude/claude_desktop_config.json",
                    ),
                    (
                        "vscode-mac",
                        "Library/Application Support/Code/User/mcp.json",
                    ),
                ],
            ),
        ];
        for (platform, expected) in platforms {
            let sb = sandbox();
            sb.put(
                "Library/Application Support/Claude/claude_desktop_config.json",
                r#"{"mcpServers": {"desktop-srv": {"command": "npx"}}}"#,
            );
            sb.put(
                "Library/Application Support/Code/User/mcp.json",
                r#"{"servers": {"vscode-mac": {"command": "npx"}}}"#,
            );
            sb.put(
                ".config/Code/User/mcp.json",
                r#"{"servers": {"vscode-linux": {"command": "npx"}}}"#,
            );
            let env = HostEnv {
                platform,
                ..sb.env()
            };
            let mut found: Vec<(String, String)> = scan(&env)
                .rows
                .iter()
                .map(|row| (row.server.clone(), row.file.clone()))
                .collect();
            found.sort();
            let expected: Vec<(String, String)> = expected
                .iter()
                .map(|(server, relative)| {
                    (
                        server.to_string(),
                        sb.home.join(relative).display().to_string(),
                    )
                })
                .collect();
            assert_eq!(
                found, expected,
                "{platform:?}: Claude Desktop only on macOS, and the VS Code path of the platform"
            );
        }
    }

    #[test]
    fn a_json_row_wraps_once_or_leaves_its_file_as_found() {
        // A wrap of a 0644 file.
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        set_mode(&cursor, 0o644);
        let first = file_state(&cursor);
        let backup = sb.home.join(".cursor/mcp.json.bak-guardrail");
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "a wrap: {report:?}"
        );
        assert_eq!(
            fs::read_to_string(&cursor).ok(),
            Some(wrapped_cursor_text(&sb)),
            "a wrap: the file holds the step 6 entry, every other byte as it was"
        );
        assert_eq!(
            fs::read(&backup).ok(),
            Some(first.bytes.clone()),
            "a wrap: .bak-guardrail holds the first read"
        );
        assert_eq!(mode_of(&backup), 0o644, "a wrap: the backup keeps the mode");
        assert_eq!(
            gid_of(&backup),
            first.gid,
            "a wrap: the backup keeps the group"
        );
        assert_eq!(mode_of(&cursor), 0o644, "a wrap: the file keeps its mode");
        assert_eq!(
            gid_of(&cursor),
            first.gid,
            "a wrap: the file keeps its group"
        );
        assert_eq!(
            names_in(&sb.home.join(".cursor")),
            vec!["mcp.json".to_string(), "mcp.json.bak-guardrail".to_string()],
            "a wrap: no kept copy and no temp file stay"
        );
        let message = messages(&report);
        assert!(
            message.contains(&backup.display().to_string())
                && message.contains("Quit and reopen Cursor"),
            "a wrap: the message names the backup and the restart step: {message}"
        );

        // A 0600 file, and a temp file from the helper before its first byte.
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        set_mode(&cursor, 0o600);
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "0600: {report:?}"
        );
        assert_eq!(mode_of(&cursor), 0o600, "0600: the result keeps mode 0600");
        assert_eq!(
            mode_of(&sb.home.join(".cursor/mcp.json.bak-guardrail")),
            0o600,
            "0600: the backup keeps mode 0600"
        );
        let probe = sb.home.join(".cursor/probe.tmp");
        let opened = open_temp(&probe, gid_of(&cursor))
            .and_then(|file| file.metadata())
            .map(|metadata| (metadata.mode() & 0o7777, metadata.len()))
            .map_err(|error| error.to_string());
        assert_eq!(
            opened,
            Ok((0o600, 0)),
            "a temp file from the helper has mode 0600 before its first byte"
        );

        // A 0640 file with another group of the test user.
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        match other_group_of_user(new_file_group(&sb.home.join(".cursor"))) {
            None => eprintln!("skip the other-group case: the test user has one group"),
            Some(group) => {
                std::os::unix::fs::chown(&cursor, None, Some(group))
                    .expect("give the file another group of the test user");
                set_mode(&cursor, 0o640);
                let report = wrap_request(
                    &Mutex::new(()),
                    &sb.env(),
                    &[server(ClientId::Cursor, "files")],
                    SECS,
                );
                let backup = sb.home.join(".cursor/mcp.json.bak-guardrail");
                assert_eq!(
                    outcomes(&report),
                    vec![Outcome::Wrapped],
                    "0640: {report:?}"
                );
                assert_eq!(
                    (gid_of(&cursor), mode_of(&cursor)),
                    (group, 0o640),
                    "0640: the result keeps the group and the mode"
                );
                assert_eq!(
                    (gid_of(&backup), mode_of(&backup)),
                    (group, 0o640),
                    "0640: the backup keeps the group and the mode"
                );
            }
        }

        // A group that the test user is not in.
        if runs_as_root() {
            eprintln!("skip the foreign-group case: root can set any group");
        } else {
            let sb = sandbox();
            let cursor = sb.put(CURSOR, CURSOR_TEXT);
            set_mode(&cursor, 0o600);
            let mut first = file_state(&cursor);
            first.gid = group_user_is_not_in();
            let setup = RowSetup::new(&sb, server(ClientId::Cursor, "files"));
            let mut kept = None;
            let end = wrap_row_from(&setup.inputs(), first, &mut kept);
            assert_eq!(end.outcome, Outcome::Failed, "a foreign group: {end:?}");
            assert!(
                !end.unrecovered,
                "a foreign group: the row fails before its change"
            );
            assert!(
                end.message.contains("cannot give the new file the group"),
                "a foreign group: the message says why: {}",
                end.message
            );
            assert_eq!(
                fs::read_to_string(&cursor).ok().as_deref(),
                Some(CURSOR_TEXT),
                "a foreign group: the file does not change"
            );
            assert!(
                no_temp_or_kept_copy(&sb.home.join(".cursor")),
                "a foreign group: no temp file stays: {:?}",
                names_in(&sb.home.join(".cursor"))
            );
        }

        // A client file that is a symlink.
        let sb = sandbox();
        let target = sb.root.join("dots/cursor.json");
        fs::create_dir_all(target.parent().expect("the dots folder")).expect("create dots");
        fs::write(&target, CURSOR_TEXT).expect("write the link target");
        fs::create_dir_all(sb.home.join(".cursor")).expect("create the Cursor folder");
        let cursor = sb.home.join(CURSOR);
        symlink(&target, &cursor).expect("link the Cursor file");
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "a symlink: {report:?}"
        );
        assert!(
            fs::symlink_metadata(&cursor).is_ok_and(|metadata| metadata.file_type().is_symlink()),
            "a symlink: the link stays"
        );
        assert_eq!(
            fs::read_to_string(&target).ok(),
            Some(wrapped_cursor_text(&sb)),
            "a symlink: the target holds the new text"
        );

        // A client file that is ~/.claude.json through a symlink or a hard link.
        let links: [(&str, Link); 2] = [
            ("a symlink", |claude, cursor| {
                symlink(claude, cursor).expect("link the Cursor file to ~/.claude.json")
            }),
            ("a hard link", |claude, cursor| {
                fs::hard_link(claude, cursor).expect("hard link the Cursor file to ~/.claude.json")
            }),
        ];
        for (label, link) in links {
            let sb = sandbox();
            let claude_text = r#"{"mcpServers": {"files": {"command": "npx"}}}"#;
            let claude = sb.put(".claude.json", claude_text);
            fs::create_dir_all(sb.home.join(".cursor")).expect("create the Cursor folder");
            link(&claude, &sb.home.join(CURSOR));
            let report = wrap_request(
                &Mutex::new(()),
                &sb.env(),
                &[server(ClientId::Cursor, "files")],
                SECS,
            );
            assert_eq!(
                outcomes(&report),
                vec![Outcome::Failed],
                "~/.claude.json through {label}: {report:?}"
            );
            assert_eq!(
                fs::read_to_string(&claude).ok().as_deref(),
                Some(claude_text),
                "~/.claude.json through {label}: no write"
            );
            assert_eq!(
                names_in(&sb.home.join(".cursor")),
                vec!["mcp.json".to_string()],
                "~/.claude.json through {label}: no backup, no kept copy, no temp file"
            );
        }

        // A first read that differs from the file in bytes, mode, owner, or group.
        let changes: [(&str, Change); 4] = [
            ("bytes", |first| {
                first.bytes.push(b' ');
                true
            }),
            ("mode", |first| {
                first.mode = 0o644;
                true
            }),
            ("owner", |first| {
                first.uid += 1;
                true
            }),
            ("group", |first| match other_group_of_user(first.gid) {
                Some(group) => {
                    first.gid = group;
                    true
                }
                None => false,
            }),
        ];
        for (label, change) in changes {
            let sb = sandbox();
            let cursor = sb.put(CURSOR, CURSOR_TEXT);
            set_mode(&cursor, 0o600);
            let mut first = file_state(&cursor);
            if !change(&mut first) {
                eprintln!("skip the {label} change: the test user has one group");
                continue;
            }
            let setup = RowSetup::new(&sb, server(ClientId::Cursor, "files"));
            let mut kept = None;
            let end = wrap_row_from(&setup.inputs(), first, &mut kept);
            assert_eq!(end.outcome, Outcome::Failed, "a changed {label}: {end:?}");
            assert!(
                end.message.contains(CHANGED),
                "a changed {label}: the message: {}",
                end.message
            );
            assert_eq!(
                fs::read_to_string(&cursor).ok().as_deref(),
                Some(CURSOR_TEXT),
                "a changed {label}: the file keeps its bytes"
            );
            assert_eq!(
                mode_of(&cursor),
                0o600,
                "a changed {label}: the file keeps its mode"
            );
            assert!(
                no_temp_or_kept_copy(&sb.home.join(".cursor")),
                "a changed {label}: no temp file or kept copy stays: {:?}",
                names_in(&sb.home.join(".cursor"))
            );
        }

        // A temp name that exists.
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        let real = fs::canonicalize(&cursor).expect("resolve the Cursor file");
        let temp = PathBuf::from(format!("{}.{}.tmp", real.display(), std::process::id()));
        fs::write(&temp, "another program's file").expect("write the temp name");
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a temp name that exists"
        );
        assert_eq!(
            fs::read_to_string(&cursor).ok().as_deref(),
            Some(CURSOR_TEXT),
            "a temp name that exists: the file does not change"
        );
        assert_eq!(
            fs::read_to_string(&temp).ok().as_deref(),
            Some("another program's file"),
            "a temp name that exists: that name does not change"
        );

        // A kept copy name that exists.
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        let kept = sb.kept_copy(CURSOR);
        fs::write(&kept, "an older kept copy").expect("write the kept copy name");
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a kept copy name that exists"
        );
        assert_eq!(
            fs::read_to_string(&cursor).ok().as_deref(),
            Some(CURSOR_TEXT),
            "a kept copy name that exists: the file does not change"
        );
        assert_eq!(
            fs::read_to_string(&kept).ok().as_deref(),
            Some("an older kept copy"),
            "a kept copy name that exists: that copy does not change"
        );

        // A backup write that fails.
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        sb.put(
            ".cursor/mcp.json.bak-guardrail/keep",
            "a folder at the backup name",
        );
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a failed backup write"
        );
        assert_eq!(
            fs::read_to_string(&cursor).ok().as_deref(),
            Some(CURSOR_TEXT),
            "a failed backup write: the file does not change"
        );

        // A readback that equals the first read.
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        set_mode(&cursor, 0o600);
        let first = file_state(&cursor);
        let kept = sb.kept_copy(CURSOR);
        fs::write(&kept, CURSOR_TEXT).expect("write the kept copy");
        set_mode(&kept, 0o600);
        let setup = RowSetup::new(&sb, server(ClientId::Cursor, "files"));
        let new_text = wrapped_cursor_text(&sb);
        let end = end_file_row(
            &setup.inputs(),
            new_text.as_bytes(),
            &first,
            Some(&first.bytes),
            &kept,
        );
        assert_eq!(
            (end.outcome, end.unrecovered),
            (Outcome::Failed, false),
            "a readback of the first read: failed and confirmed: {end:?}"
        );
        assert!(
            !kept.exists(),
            "a readback of the first read: the kept copy is gone"
        );

        // A readback that matches neither text.
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        let first = file_state(&cursor);
        let other = r#"{"mcpServers": {"files": {"command": "npx"}, "added": {"command": "uvx"}}}"#;
        fs::write(&cursor, other).expect("write another program's text");
        let kept = sb.kept_copy(CURSOR);
        fs::write(&kept, CURSOR_TEXT).expect("write the kept copy");
        set_mode(&kept, 0o600);
        let setup = RowSetup::new(&sb, server(ClientId::Cursor, "files"));
        let new_text = wrapped_cursor_text(&sb);
        let end = end_file_row(
            &setup.inputs(),
            new_text.as_bytes(),
            &first,
            Some(other.as_bytes()),
            &kept,
        );
        assert_eq!(
            (end.outcome, end.unrecovered),
            (Outcome::Failed, true),
            "a readback of other bytes: unrecovered: {end:?}"
        );
        assert_eq!(
            (kept.exists(), mode_of(&kept)),
            (true, 0o600),
            "a readback of other bytes: the kept copy stays with mode 0600"
        );
        assert!(
            end.message.contains(&kept.display().to_string()),
            "a readback of other bytes: the message names the kept copy: {}",
            end.message
        );
        assert_eq!(
            fs::read_to_string(&cursor).ok().as_deref(),
            Some(other),
            "a readback of other bytes: the app makes no second write"
        );

        // An entry that is gone, now already wrapped, or now remote.
        let skips = [
            (
                "gone",
                r#"{"mcpServers": {"other": {"command": "npx"}}}"#,
                "no longer in",
            ),
            (
                "already wrapped",
                r#"{"mcpServers": {"files": {"command": "/x/mcp-guardrail-proxy", "args": ["proxy", "--", "npx"]}}}"#,
                "already wrapped",
            ),
            (
                "remote",
                r#"{"mcpServers": {"files": {"url": "https://mcp.example.com"}}}"#,
                "remote",
            ),
        ];
        for (label, text, message_has) in skips {
            let sb = sandbox();
            let cursor = sb.put(CURSOR, text);
            let report = wrap_request(
                &Mutex::new(()),
                &sb.env(),
                &[server(ClientId::Cursor, "files")],
                SECS,
            );
            assert_eq!(
                outcomes(&report),
                vec![Outcome::Skipped],
                "{label}: {report:?}"
            );
            assert!(
                messages(&report).contains(message_has),
                "{label}: the message says why: {}",
                messages(&report)
            );
            assert_eq!(
                fs::read_to_string(&cursor).ok().as_deref(),
                Some(text),
                "{label}: the file does not change"
            );
        }
        let sb = sandbox();
        let cursor = sb.put(CURSOR, r#"{"mcpServers": {"other": {"command": "npx"}}}"#);
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert!(
            messages(&report).contains(&cursor.display().to_string()),
            "gone: the message names the file: {}",
            messages(&report)
        );

        // Two rows of one file in the same second.
        let sb = sandbox();
        sb.put(
            CURSOR,
            r#"{"mcpServers": {"files": {"command": "npx"}, "docs": {"command": "npx", "args": ["docs"]}}}"#,
        );
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[
                server(ClientId::Cursor, "files"),
                server(ClientId::Cursor, "docs"),
            ],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped, Outcome::Wrapped],
            "two rows of one file in the same second: {report:?}"
        );
        assert_eq!(
            scan(&sb.env()).wrapped,
            2,
            "two rows of one file: both wrapped"
        );
    }

    struct AuditCase {
        label: &'static str,
        /// Builds the case under the sandbox and gives the audit log path.
        prepare: fn(&Sandbox) -> PathBuf,
        problem_has: Option<&'static str>,
    }

    const LINK_TO_MISSING: &str = "The audit log path is a link to a file that does not exist.";

    const SCAN_REFUSALS: [AuditCase; 15] = [
        AuditCase {
            label: "a path that is not UTF-8",
            prepare: |sb| sb.root.join(OsStr::from_bytes(b"logs-\xff/audit.jsonl")),
            problem_has: None,
        },
        AuditCase {
            label: "an empty path",
            prepare: |_| PathBuf::new(),
            problem_has: None,
        },
        AuditCase {
            label: "a relative path",
            prepare: |_| PathBuf::from("audit.jsonl"),
            problem_has: None,
        },
        AuditCase {
            label: "a client file that exists",
            prepare: |sb| sb.put(CURSOR, r#"{"mcpServers": {}}"#),
            problem_has: None,
        },
        AuditCase {
            label: "a client file that does not exist, ~/.cursor/mcp.json with no Cursor",
            prepare: |sb| sb.home.join(CURSOR),
            problem_has: None,
        },
        AuditCase {
            label: "a path under a folder link to ~/.cursor",
            prepare: |sb| {
                fs::create_dir_all(sb.home.join(".cursor")).expect("create the Cursor folder");
                symlink(sb.home.join(".cursor"), sb.home.join("dots"))
                    .expect("link a folder to ~/.cursor");
                sb.home.join("dots/mcp.json")
            },
            problem_has: None,
        },
        AuditCase {
            label: "a missing folder under a link to the home folder",
            prepare: |sb| {
                symlink(&sb.home, sb.root.join("home-link")).expect("link to the home folder");
                sb.root.join("home-link/.cursor/mcp.json")
            },
            problem_has: None,
        },
        AuditCase {
            label: "a .. after a missing folder",
            prepare: |sb| sb.home.join("missing/../.cursor/mcp.json"),
            problem_has: None,
        },
        AuditCase {
            label: "a path that differs in ASCII case",
            prepare: |sb| sb.home.join(".Cursor/MCP.json"),
            problem_has: None,
        },
        AuditCase {
            label: "a symlink to a client file",
            prepare: |sb| {
                let cursor = sb.put(CURSOR, r#"{"mcpServers": {}}"#);
                let link = sb.home.join("audit-link.jsonl");
                symlink(cursor, &link).expect("link the audit path to a client file");
                link
            },
            problem_has: None,
        },
        AuditCase {
            label: "a hard link to a client file",
            prepare: |sb| {
                let cursor = sb.put(CURSOR, r#"{"mcpServers": {}}"#);
                let link = sb.home.join("audit-hard.jsonl");
                fs::hard_link(cursor, &link).expect("hard link the audit path to a client file");
                link
            },
            problem_has: None,
        },
        AuditCase {
            label: "a file name that holds .bak-guardrail",
            prepare: |sb| sb.home.join("logs/audit.bak-guardrail.jsonl"),
            problem_has: None,
        },
        AuditCase {
            label: "a symlink to a backup",
            prepare: |sb| {
                let backup = sb.put(".cursor/mcp.json.bak-guardrail", r#"{"mcpServers": {}}"#);
                fs::create_dir_all(sb.home.join("logs")).expect("create the logs folder");
                let link = sb.home.join("logs/audit.jsonl");
                symlink(backup, &link).expect("link the audit path to a backup");
                link
            },
            problem_has: None,
        },
        AuditCase {
            label: "a symlink to a kept copy",
            prepare: |sb| {
                let kept = sb.put(
                    ".cursor/mcp.json.bak-guardrail-1794355200",
                    r#"{"mcpServers": {}}"#,
                );
                fs::create_dir_all(sb.home.join("logs")).expect("create the logs folder");
                let link = sb.home.join("logs/audit.jsonl");
                symlink(kept, &link).expect("link the audit path to a kept copy");
                link
            },
            problem_has: None,
        },
        AuditCase {
            label: "a symlink to a missing file",
            prepare: |sb| {
                fs::create_dir_all(sb.home.join("logs")).expect("create the logs folder");
                let link = sb.home.join("logs/audit.jsonl");
                symlink(sb.home.join("nowhere.jsonl"), &link)
                    .expect("link the audit path to a missing file");
                link
            },
            problem_has: Some(LINK_TO_MISSING),
        },
    ];

    const WRAP_REFUSALS: [AuditCase; 3] = [
        AuditCase {
            label: "a folder",
            prepare: |sb| {
                let folder = sb.home.join("logs");
                fs::create_dir_all(&folder).expect("create a folder at the audit path");
                folder
            },
            problem_has: Some("is a folder"),
        },
        AuditCase {
            label: "an audit folder that cannot be created",
            prepare: |sb| {
                sb.put("plain", "a file where a folder must go")
                    .join("sub/audit.jsonl")
            },
            problem_has: Some("os error"),
        },
        AuditCase {
            label: "a named pipe",
            prepare: |sb| {
                let pipe = sb.home.join("audit.jsonl");
                mkfifo(&pipe);
                pipe
            },
            problem_has: None,
        },
    ];

    #[test]
    fn a_wrap_request_runs_only_when_the_binary_and_audit_log_pass() {
        for case in SCAN_REFUSALS {
            let sb = sandbox();
            sb.put(WINDSURF, WINDSURF_TEXT);
            let env = HostEnv {
                audit_log_path: (case.prepare)(&sb),
                ..sb.env()
            };
            let before = tree(&sb.root);
            let view = scan(&env);
            let problem = view.problem.clone().unwrap_or_default();
            assert!(
                !problem.is_empty(),
                "{}: the scan names why Wrap is off",
                case.label
            );
            assert!(
                case.problem_has.is_none_or(|text| problem.contains(text)),
                "{}: the problem {problem:?}",
                case.label
            );
            assert_eq!(
                selectable(&view),
                vec![("notes".to_string(), false)],
                "{}: the scan turns Wrap off",
                case.label
            );
            let report = wrap_request(
                &Mutex::new(()),
                &env,
                &[server(ClientId::Windsurf, "notes")],
                SECS,
            );
            assert!(
                report.is_err(),
                "{}: the wrap refuses: {report:?}",
                case.label
            );
            assert!(
                case.problem_has
                    .is_none_or(|text| messages(&report).contains(text)),
                "{}: the refusal {report:?}",
                case.label
            );
            assert_eq!(
                tree(&sb.root),
                before,
                "{}: no file or folder is created or changed",
                case.label
            );
        }

        for case in WRAP_REFUSALS {
            let sb = sandbox();
            sb.put(WINDSURF, WINDSURF_TEXT);
            let env = HostEnv {
                audit_log_path: (case.prepare)(&sb),
                ..sb.env()
            };
            let before = tree(&sb.root);
            let report = within(Duration::from_secs(30), move || {
                wrap_request(
                    &Mutex::new(()),
                    &env,
                    &[server(ClientId::Windsurf, "notes")],
                    SECS,
                )
            })
            .unwrap_or_else(|| panic!("{}: the wrap returns, with no block", case.label));
            assert!(
                report.is_err(),
                "{}: the wrap refuses: {report:?}",
                case.label
            );
            assert!(
                case.problem_has
                    .is_none_or(|text| messages(&report).contains(text)),
                "{}: the refusal names the cause: {report:?}",
                case.label
            );
            assert_eq!(tree(&sb.root), before, "{}: no file changes", case.label);
        }

        if runs_as_root() {
            eprintln!("skip the read-only log case: root opens any file for append");
        } else {
            let sb = sandbox();
            sb.put(WINDSURF, WINDSURF_TEXT);
            let log = sb.put(".local/state/mcp-guardrail/audit.jsonl", "");
            set_mode(&log, 0o444);
            let before = tree(&sb.root);
            let report = wrap_request(
                &Mutex::new(()),
                &sb.env(),
                &[server(ClientId::Windsurf, "notes")],
                SECS,
            );
            assert!(
                messages(&report).contains("os error") && report.is_err(),
                "a log that does not open for append: the OS error: {report:?}"
            );
            assert_eq!(
                tree(&sb.root),
                before,
                "a log that does not open: no file changes"
            );
        }

        let sb = sandbox();
        sb.put(WINDSURF, WINDSURF_TEXT);
        fs::remove_file(sb.bin.join("mcp-guardrail-proxy")).expect("remove the proxy stub");
        let view = scan(&sb.env());
        let cargo_path = sb
            .home
            .join(".cargo/bin/mcp-guardrail-proxy")
            .display()
            .to_string();
        let problem = view.problem.clone().unwrap_or_default();
        assert_eq!(view.binary, None, "no binary: binary is null");
        assert!(
            problem.contains("mcp-guardrail-proxy")
                && problem.contains("PATH")
                && problem.contains(&cargo_path),
            "no binary: the problem names the binary and both places: {problem:?}"
        );
        assert_eq!(
            selectable(&view),
            vec![("notes".to_string(), false)],
            "no binary: no row is selectable"
        );
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Windsurf, "notes")],
            SECS,
        );
        assert_eq!(
            report.err(),
            view.problem,
            "no binary: wrap_servers returns the same text as an Err"
        );

        let sb = sandbox();
        let odd_bin = sb.root.join(OsStr::from_bytes(b"bin-\xff"));
        match fs::create_dir_all(&odd_bin) {
            Err(error) => eprintln!(
                "skip the binary path that is not UTF-8: this file system refuses the name: {error}"
            ),
            Ok(()) => {
                write_script(&odd_bin.join("mcp-guardrail-proxy"), OK_PROXY.as_bytes());
                fs::remove_file(sb.bin.join("mcp-guardrail-proxy")).expect("remove the proxy stub");
                let mut login = odd_bin.into_os_string().into_vec();
                login.extend_from_slice(b":/usr/bin:/bin");
                let sb = sb.with_login_path(OsString::from_vec(login));
                sb.put(WINDSURF, WINDSURF_TEXT);
                let view = scan(&sb.env());
                assert!(
                    view.problem.is_some(),
                    "a binary path that is not UTF-8: Wrap is off"
                );
                assert_eq!(
                    selectable(&view),
                    vec![("notes".to_string(), false)],
                    "a binary path that is not UTF-8: no row is selectable"
                );
                let report = wrap_request(
                    &Mutex::new(()),
                    &sb.env(),
                    &[server(ClientId::Windsurf, "notes")],
                    SECS,
                );
                assert!(
                    report.is_err(),
                    "a binary path that is not UTF-8: the wrap refuses"
                );
            }
        }

        let sb = sandbox();
        sb.put(WINDSURF, WINDSURF_TEXT);
        let log = sb.env().audit_log_path;
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Windsurf, "notes")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "a missing log: {report:?}"
        );
        assert_eq!(
            (
                fs::metadata(&log).map(|metadata| metadata.len()).ok(),
                mode_of(&log)
            ),
            (Some(0), 0o600),
            "a missing log: the wrap creates it empty with mode 0600"
        );

        let sb = sandbox();
        sb.put(WINDSURF, WINDSURF_TEXT);
        let env = HostEnv {
            platform: Platform::Other,
            ..sb.env()
        };
        assert_eq!(
            selectable(&scan(&env)),
            vec![("notes".to_string(), false)],
            "a platform other than macOS or Linux: no row is selectable"
        );

        let sb = sandbox();
        let windsurf = sb.put(WINDSURF, WINDSURF_TEXT);
        let lock = Mutex::new(());
        let busy = {
            let _running = lock.try_lock().expect("take the wrap lock");
            wrap_request(
                &lock,
                &sb.env(),
                &[server(ClientId::Windsurf, "notes")],
                SECS,
            )
        };
        assert_eq!(
            busy,
            Err("A wrap is already running.".to_string()),
            "a second call while a wrap runs"
        );
        assert_eq!(
            fs::read_to_string(&windsurf).ok().as_deref(),
            Some(WINDSURF_TEXT),
            "a second call: no file changes"
        );

        let sb = sandbox();
        let lock = Arc::new(Mutex::new(()));
        let poisoner = Arc::clone(&lock);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.lock();
            panic!("poison the wrap lock");
        })
        .join();
        assert!(lock.is_poisoned(), "the fixture poisons the lock");
        assert_eq!(
            wrap_request(&lock, &sb.env(), &[], SECS).map(|report| report.results.len()),
            Ok(0),
            "a poisoned lock counts as free"
        );

        let sb = sandbox();
        let windsurf = sb.put(WINDSURF, WINDSURF_TEXT);
        assert_eq!(
            wrap_request(&Mutex::new(()), &sb.env(), &[], SECS).map(|report| report.results.len()),
            Ok(0),
            "an empty request: an empty report"
        );
        assert_eq!(
            names_in(&sb.home.join(".codeium/windsurf")),
            vec!["mcp_config.json".to_string()],
            "an empty request: no backup or kept copy"
        );
        assert_eq!(
            fs::read_to_string(&windsurf).ok().as_deref(),
            Some(WINDSURF_TEXT),
            "an empty request: no client file changes"
        );

        assert!(
            serde_json::from_value::<ServerId>(
                json!({"client": "zed", "project": null, "name": "x"})
            )
            .is_err(),
            "a request that names an unknown client: serde refuses it"
        );
        assert_eq!(
            serde_json::from_value::<ServerId>(
                json!({"client": "cursor", "project": null, "name": "github"})
            )
            .ok(),
            Some(server(ClientId::Cursor, "github")),
            "a known client name parses"
        );

        let sb = sandbox();
        sb.put(
            "Library/Application Support/Claude/claude_desktop_config.json",
            r#"{"mcpServers": {"desktop-srv": {"command": "npx"}}}"#,
        );
        sb.put(
            CURSOR,
            r#"{"mcpServers": {"cursor-srv": {"command": "npx"}}}"#,
        );
        sb.put(
            "Library/Application Support/Code/User/mcp.json",
            r#"{"servers": {"vscode-srv": {"command": "npx"}}}"#,
        );
        sb.put(
            WINDSURF,
            r#"{"mcpServers": {"windsurf-srv": {"command": "npx"}}}"#,
        );
        sb.put(
            ".gemini/settings.json",
            r#"{"mcpServers": {"gemini-srv": {"command": "npx"}}}"#,
        );
        let view = scan(&sb.env());
        assert_eq!(view.problem, None, "every check passes: no problem");
        assert_eq!(
            view.binary,
            Some(sb.bin_text()),
            "every check passes: the tab shows the binary a wrap uses"
        );
        assert_eq!(
            view.audit_log_path,
            sb.audit_text(),
            "every check passes: the tab shows the audit log a wrap uses"
        );
        assert_eq!(
            selectable(&view),
            vec![
                ("cursor-srv".to_string(), true),
                ("desktop-srv".to_string(), true),
                ("gemini-srv".to_string(), true),
                ("vscode-srv".to_string(), true),
                ("windsurf-srv".to_string(), true),
            ],
            "every check passes: each wrappable JSON row is selectable"
        );
    }

    fn sh(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        command
    }

    fn exit_code(run: &ChildRun) -> Option<i32> {
        run.exit.and_then(|status| status.code())
    }

    fn pid_in(path: &Path) -> Option<rustix::process::Pid> {
        let text = fs::read_to_string(path).ok()?;
        rustix::process::Pid::from_raw(text.trim().parse().ok()?)
    }

    fn process_is_gone(pid: rustix::process::Pid) -> bool {
        rustix::process::test_kill_process(pid).is_err()
    }

    #[test]
    fn a_child_ends_within_its_time_bound_and_keeps_whole_output_or_none() {
        let run = run_child(
            &mut sh("printf out; printf err >&2; exit 3"),
            Duration::from_secs(10),
        )
        .map_err(|error| error.to_string());
        assert_eq!(
            run.as_ref()
                .map(|run| (exit_code(run), run.stdout.clone(), run.stderr.clone())),
            Ok((
                Some(3),
                ChildOutput::Whole(b"out".to_vec()),
                ChildOutput::Whole(b"err".to_vec())
            )),
            "a short exit gives both streams"
        );

        let run = run_child(
            &mut sh("/usr/bin/head -c 65536 /dev/zero"),
            Duration::from_secs(10),
        )
        .map(|run| run.stdout)
        .map_err(|error| error.to_string());
        assert_eq!(
            run,
            Ok(ChildOutput::Whole(vec![0; 65_536])),
            "stdout of exactly 65,536 bytes is read whole"
        );
        let run = run_child(
            &mut sh("/usr/bin/head -c 65537 /dev/zero"),
            Duration::from_secs(10),
        )
        .map(|run| run.stdout)
        .map_err(|error| error.to_string());
        assert_eq!(
            run,
            Ok(ChildOutput::TooLong),
            "stdout of 65,537 bytes gives no text"
        );

        let dir = tempfile::tempdir().expect("create a temp dir");
        let child_pid = dir.path().join("child.pid");
        let grandchild_pid = dir.path().join("grandchild.pid");
        let script = format!(
            "echo $$ > '{}'; printf partial; printf partial >&2; sleep 30 & echo $! > '{}'; wait",
            child_pid.display(),
            grandchild_pid.display()
        );
        let run = run_child(&mut sh(&script), Duration::from_millis(500))
            .map(|run| (run.exit, run.stdout, run.stderr))
            .map_err(|error| error.to_string());
        assert_eq!(
            run,
            Ok((None, ChildOutput::Dropped, ChildOutput::Dropped)),
            "a child past its timeout keeps no text for either stream"
        );
        let child = pid_in(&child_pid);
        assert!(
            child.is_some_and(process_is_gone),
            "the app reaps the child it killed"
        );
        let grandchild = pid_in(&grandchild_pid);
        assert!(
            grandchild
                .is_some_and(|pid| wait_until(Duration::from_secs(5), || process_is_gone(pid))),
            "the grandchild in the child's process group is gone too"
        );

        let dir = tempfile::tempdir().expect("create a temp dir");
        let holder_pid = dir.path().join("holder.pid");
        let script = format!(
            "sleep 30 & echo $! > '{}'; printf done",
            holder_pid.display()
        );
        let start = Instant::now();
        let run = run_child(&mut sh(&script), Duration::from_secs(20))
            .map(|run| (exit_code(&run), run.stdout))
            .map_err(|error| error.to_string());
        let elapsed = start.elapsed();
        if let Some(pid) = pid_in(&holder_pid) {
            let _ = Command::new("kill")
                .arg("-9")
                .arg(pid.as_raw_pid().to_string())
                .status();
        }
        assert_eq!(
            run,
            Ok((Some(0), ChildOutput::Whole(b"done".to_vec()))),
            "a descendant that holds stdout open does not hold the app"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the return waits for the child only, not its descendant: {elapsed:?}"
        );

        let run = run_child(&mut sh("cat; printf done"), Duration::from_secs(10))
            .map(|run| (exit_code(&run), run.stdout))
            .map_err(|error| error.to_string());
        assert_eq!(
            run,
            Ok((Some(0), ChildOutput::Whole(b"done".to_vec()))),
            "a child that reads stdin gets end of file at once"
        );

        let dir = tempfile::tempdir().expect("create a temp dir");
        let pid_file = dir.path().join("child.pid");
        let go = dir.path().join("go");
        let script = format!(
            "echo $$ > '{pid}'; i=0; while [ ! -f '{go}' ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i + 1)); done",
            pid = pid_file.display(),
            go = go.display()
        );
        let runner = std::thread::spawn(move || {
            run_child(&mut sh(&script), Duration::from_secs(30)).map(|run| exit_code(&run))
        });
        let started = wait_until(Duration::from_secs(10), || pid_in(&pid_file).is_some());
        let ids = pid_in(&pid_file).map(|pid| {
            (
                pid,
                rustix::process::getpgid(Some(pid)).ok(),
                rustix::process::getsid(Some(pid)).ok(),
            )
        });
        fs::write(&go, "").expect("let the child end");
        let ended = runner.join().expect("the runner thread ends");
        assert!(started, "the child starts");
        assert!(
            ids.is_some_and(|(pid, group, session)| group == Some(pid) && session == Some(pid)),
            "the child leads a new session: its process group id and session id equal its pid: {ids:?}"
        );
        assert_eq!(
            ended.map_err(|error| error.to_string()),
            Ok(Some(0)),
            "the session child exits 0"
        );
    }

    #[test]
    fn the_login_shell_path_finds_the_binary_and_bare_commands() {
        let sb = sandbox();
        write_script(
            &sb.shell,
            b"#!/bin/sh\nprintf 'Welcome!\\n__MCP_GUARDRAIL_PATH__=/wrong/first\\nmotd\\n'\nprintf '__MCP_GUARDRAIL_PATH__=/right/bin:/also/bin\\ntrailing noise\\n'\n",
        );
        assert_eq!(
            login_path(&sb.env()),
            LoginPath {
                path: Some(OsString::from("/right/bin:/also/bin")),
                note: None,
            },
            "the PATH is the text after the last marker, up to the end of that line"
        );

        for (label, shell) in [
            ("an unset SHELL", None),
            ("a relative SHELL", Some(OsString::from("sh"))),
        ] {
            let sb = sandbox();
            let env = HostEnv { shell, ..sb.env() };
            let found = login_path(&env);
            assert_eq!(found.note, None, "{label}: /bin/sh prints the marker");
            assert!(
                found.path.is_some_and(|path| !path.is_empty()),
                "{label}: /bin/sh gives a PATH"
            );
        }

        let failing_shells: [(&str, &[u8]); 2] = [
            (
                "a shell that exits non-zero",
                b"#!/bin/sh\nprintf '__MCP_GUARDRAIL_PATH__=/from/shell\\n'\nexit 3\n",
            ),
            (
                "a shell that prints over 64 KiB",
                b"#!/bin/sh\n/usr/bin/head -c 70000 /dev/zero | /usr/bin/tr '\\0' 'x'\nprintf '\\n__MCP_GUARDRAIL_PATH__=/from/shell\\n'\n",
            ),
        ];
        for (label, body) in failing_shells {
            let sb = sandbox();
            write_script(&sb.shell, body);
            let found = login_path(&sb.env());
            assert_eq!(found.path, sb.env().path, "{label}: the app's own PATH");
            assert!(found.note.is_some(), "{label}: a note says so");
        }

        let sb = sandbox();
        let install_root = sb.root.join("install-root");
        let cargo_home = sb.root.join("cargo-home");
        write_script(
            &install_root.join("bin/mcp-guardrail-proxy"),
            OK_PROXY.as_bytes(),
        );
        write_script(
            &cargo_home.join("bin/mcp-guardrail-proxy"),
            OK_PROXY.as_bytes(),
        );
        write_script(
            &sb.home.join(".cargo/bin/mcp-guardrail-proxy"),
            OK_PROXY.as_bytes(),
        );
        let empty = sb.root.join("empty-bin");
        fs::create_dir_all(&empty).expect("create an empty PATH folder");
        let empty = empty.into_os_string();
        let env = HostEnv {
            cargo_install_root: Some(install_root.clone().into_os_string()),
            cargo_home: Some(cargo_home.clone().into_os_string()),
            ..sb.env()
        };
        assert_eq!(
            find_binary(&env, Some(&sb.login)),
            Some(sb.bin.join("mcp-guardrail-proxy")),
            "a binary on the login PATH comes before the cargo path"
        );
        assert_eq!(
            find_binary(&env, Some(&empty)),
            Some(install_root.join("bin/mcp-guardrail-proxy")),
            "with none on the PATH: CARGO_INSTALL_ROOT first"
        );
        let env = HostEnv {
            cargo_install_root: None,
            ..env
        };
        assert_eq!(
            find_binary(&env, Some(&empty)),
            Some(cargo_home.join("bin/mcp-guardrail-proxy")),
            "with none on the PATH and no CARGO_INSTALL_ROOT: CARGO_HOME"
        );
        let env = HostEnv {
            cargo_home: None,
            ..env
        };
        assert_eq!(
            find_binary(&env, Some(&empty)),
            Some(sb.home.join(".cargo/bin/mcp-guardrail-proxy")),
            "with neither variable: $HOME/.cargo"
        );

        let sb = sandbox();
        let cursor = sb.put(CURSOR, r#"{"mcpServers": {"files": {"command": "npx"}}}"#);
        let env = HostEnv {
            path: Some(OsString::from("/usr/bin:/bin")),
            ..sb.env()
        };
        let report = wrap_request(
            &Mutex::new(()),
            &env,
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "a wrap with the login PATH: {report:?}"
        );
        let written: Value = fs::read_to_string(&cursor)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        assert_eq!(
            written["mcpServers"]["files"],
            json!({
                "command": sb.bin_text(),
                "args": ["proxy", "--audit-log", sb.audit_text(), "--", sb.npx_text()],
            }),
            "a bare npx on the login PATH goes into the entry as its full path"
        );
    }

    #[test]
    fn a_wrap_starts_only_after_check_policy_passes() {
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Cursor, "files")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "exit 0 with policy OK: the wrap runs: {report:?}"
        );
        assert_eq!(
            fs::read_to_string(&cursor).ok(),
            Some(wrapped_cursor_text(&sb)),
            "exit 0 with policy OK: the file is wrapped"
        );

        let refusals: [(&str, &str, Option<&str>, Option<&str>); 3] = [
            (
                "exit 1",
                "#!/bin/sh\necho 'loading policies/default-policy.toml' >&2\necho 'error: rule block-exfil has no pattern' >&2\necho '' >&2\nexit 1\n",
                Some("error: rule block-exfil has no pattern"),
                Some("loading policies/default-policy.toml"),
            ),
            (
                "stdout over 64 KiB",
                "#!/bin/sh\nprintf 'policy OK: '\n/usr/bin/head -c 70000 /dev/zero | /usr/bin/tr '\\0' 'x'\nexit 0\n",
                None,
                None,
            ),
            (
                "stdout without the policy OK: start",
                "#!/bin/sh\necho 'all good: 12 rules'\nexit 0\n",
                None,
                None,
            ),
        ];
        for (label, proxy, error_has, error_lacks) in refusals {
            let sb = sandbox();
            write_script(&sb.bin.join("mcp-guardrail-proxy"), proxy.as_bytes());
            sb.put(CURSOR, CURSOR_TEXT);
            let before = tree(&sb.root);
            let report = wrap_request(
                &Mutex::new(()),
                &sb.env(),
                &[server(ClientId::Cursor, "files")],
                SECS,
            );
            assert!(report.is_err(), "{label}: the wrap refuses: {report:?}");
            assert!(
                error_has.is_none_or(|text| messages(&report).contains(text)),
                "{label}: the refusal shows the last non-empty stderr line: {report:?}"
            );
            assert!(
                error_lacks.is_none_or(|text| !messages(&report).contains(text)),
                "{label}: the refusal shows only the last line: {report:?}"
            );
            assert_eq!(
                tree(&sb.root),
                before,
                "{label}: every client file, backup, kept copy name, and the audit folder stay as they were"
            );
        }
    }

    /// A stub row that ends as its name says. `panic-late` makes its kept copy first.
    fn stub_end(id: &ServerId, slot: &mut Option<PathBuf>, kept: &Path) -> RowEnd {
        let name = id.name.as_str();
        if name.starts_with("panic-early") {
            panic!("panic text that quotes {SECRET}");
        }
        if name.starts_with("panic-late") {
            fs::write(kept, CURSOR_TEXT).expect("write the stub kept copy");
            *slot = Some(kept.to_path_buf());
            panic!("panic text that quotes {SECRET}");
        }
        let (outcome, unrecovered) = match name.split('-').next() {
            Some("wrapped") => (Outcome::Wrapped, false),
            Some("before") => (Outcome::Failed, false),
            Some("lost") => (Outcome::Failed, true),
            _ => (Outcome::Skipped, false),
        };
        RowEnd {
            outcome,
            message: format!("stub end of {name}"),
            unrecovered,
        }
    }

    /// A Cursor file, a Windsurf file, and a Gemini file that links to the Cursor file.
    fn stop_sandbox() -> Sandbox {
        let sb = sandbox();
        let cursor = sb.put(CURSOR, CURSOR_TEXT);
        sb.put(WINDSURF, WINDSURF_TEXT);
        fs::create_dir_all(sb.home.join(".gemini")).expect("create the Gemini folder");
        symlink(&cursor, sb.home.join(".gemini/settings.json")).expect("link Gemini to Cursor");
        sb
    }

    fn run_stub_rows(sb: &Sandbox, rows: &[ServerId]) -> (Vec<WrapResult>, Vec<String>) {
        let env = sb.env();
        let kept = sb.kept_copy(CURSOR);
        let mut ran = Vec::new();
        let results = run_rows(&env, rows, &mut |id, slot| {
            ran.push(id.name.clone());
            stub_end(id, slot, &kept)
        });
        (results, ran)
    }

    fn ends(results: &[WrapResult]) -> Vec<(String, Outcome)> {
        results
            .iter()
            .map(|result| (result.id.name.clone(), result.outcome))
            .collect()
    }

    fn end_of(name: &str, outcome: Outcome) -> (String, Outcome) {
        (name.to_string(), outcome)
    }

    fn message_of(results: &[WrapResult], name: &str) -> String {
        results
            .iter()
            .find(|result| result.id.name == name)
            .map(|result| result.message.clone())
            .unwrap_or_default()
    }

    #[test]
    fn each_row_end_decides_if_later_rows_of_its_file_run() {
        let sb = stop_sandbox();
        let (results, ran) = run_stub_rows(
            &sb,
            &[
                server(ClientId::Cursor, "wrapped-1"),
                server(ClientId::Cursor, "before-2"),
                server(ClientId::Cursor, "wrapped-3"),
            ],
        );
        assert_eq!(
            ends(&results),
            vec![
                end_of("wrapped-1", Outcome::Wrapped),
                end_of("before-2", Outcome::Failed),
                end_of("wrapped-3", Outcome::Wrapped),
            ],
            "a confirmed end and a failure before the change let later rows of the file run"
        );
        assert_eq!(ran, ["wrapped-1", "before-2", "wrapped-3"], "every row ran");

        let sb = stop_sandbox();
        let (results, ran) = run_stub_rows(
            &sb,
            &[
                server(ClientId::Cursor, "lost-1"),
                server(ClientId::Cursor, "wrapped-2"),
                server(ClientId::Windsurf, "wrapped-3"),
                server(ClientId::Cursor, "wrapped-4"),
            ],
        );
        assert_eq!(
            ends(&results),
            vec![
                end_of("lost-1", Outcome::Failed),
                end_of("wrapped-2", Outcome::Skipped),
                end_of("wrapped-3", Outcome::Wrapped),
                end_of("wrapped-4", Outcome::Skipped),
            ],
            "an unrecovered end skips later rows of its file, and rows of other files run"
        );
        assert_eq!(ran, ["lost-1", "wrapped-3"], "only rows of other files ran");
        let skipped = message_of(&results, "wrapped-2");
        assert!(
            skipped.contains(STOPPED_FILE) && skipped.ends_with(STOPPED_FILE_END),
            "the skip message: {skipped}"
        );

        let sb = stop_sandbox();
        let (results, ran) = run_stub_rows(
            &sb,
            &[
                server(ClientId::Cursor, "lost-1"),
                server(ClientId::GeminiCli, "wrapped-2"),
            ],
        );
        assert_eq!(
            ends(&results),
            vec![
                end_of("lost-1", Outcome::Failed),
                end_of("wrapped-2", Outcome::Skipped),
            ],
            "two listed paths that resolve to one real file share the stop"
        );
        assert_eq!(ran, ["lost-1"], "the linked file's row did not run");

        let sb = stop_sandbox();
        let (results, ran) = run_stub_rows(
            &sb,
            &[
                server(ClientId::Cursor, "panic-early-1"),
                server(ClientId::Windsurf, "wrapped-2"),
                server(ClientId::Cursor, "wrapped-3"),
            ],
        );
        assert_eq!(
            ends(&results),
            vec![
                end_of("panic-early-1", Outcome::Failed),
                end_of("wrapped-2", Outcome::Wrapped),
                end_of("wrapped-3", Outcome::Skipped),
            ],
            "a panic fails its row and stops its file"
        );
        assert_eq!(
            ran,
            ["panic-early-1", "wrapped-2"],
            "rows of other files still ran"
        );
        let panicked = message_of(&results, "panic-early-1");
        assert!(
            panicked.contains("no change")
                && !panicked.contains("panic text")
                && !panicked.contains(SECRET),
            "a panic before the kept copy: the no-change text, with no panic text: {panicked}"
        );

        let sb = stop_sandbox();
        let kept = sb.kept_copy(CURSOR);
        let (results, _) = run_stub_rows(&sb, &[server(ClientId::Cursor, "panic-late-1")]);
        assert_eq!(
            ends(&results),
            vec![end_of("panic-late-1", Outcome::Failed)],
            "a panic after the kept copy fails its row"
        );
        let panicked = message_of(&results, "panic-late-1");
        assert!(
            panicked.contains(&kept.display().to_string())
                && !panicked.contains("panic text")
                && !panicked.contains(SECRET),
            "a panic after the kept copy: the message names it, with no panic text: {panicked}"
        );
        assert!(
            kept.exists(),
            "a panic after the kept copy: the kept copy stays"
        );

        let sb = stop_sandbox();
        let (results, _) = run_stub_rows(
            &sb,
            &[
                server(ClientId::Windsurf, "wrapped-1"),
                server(ClientId::Cursor, "wrapped-2"),
                server(ClientId::Windsurf, "wrapped-3"),
            ],
        );
        assert_eq!(
            ends(&results),
            vec![
                end_of("wrapped-1", Outcome::Wrapped),
                end_of("wrapped-2", Outcome::Wrapped),
                end_of("wrapped-3", Outcome::Wrapped),
            ],
            "the results come in request order"
        );

        let sb = stop_sandbox();
        let lock = Mutex::new(());
        let (results, _) = {
            let _running = lock.try_lock().expect("take the wrap lock");
            run_stub_rows(&sb, &[server(ClientId::Cursor, "panic-early-1")])
        };
        assert_eq!(
            ends(&results),
            vec![end_of("panic-early-1", Outcome::Failed)],
            "after a row panic, the call loop returns its results"
        );
        assert_eq!(
            wrap_request(&lock, &sb.env(), &[], SECS).map(|report| report.results.len()),
            Ok(0),
            "after a row panic, a second call gets the lock"
        );
    }

    fn original_db() -> Value {
        json!({"command": "/usr/bin/db-server", "args": ["--port", "5432"], "env": {"DB_TOKEN": SECRET}})
    }

    /// `original_db` as the step 6 entry of `INSTALL.md:146-155`.
    fn wrapped_db(sb: &Sandbox) -> Value {
        json!({
            "command": sb.bin_text(),
            "args": ["proxy", "--audit-log", sb.audit_text(), "--", "/usr/bin/db-server", "--port", "5432"],
            "env": {"DB_TOKEN": SECRET},
        })
    }

    fn claude_text(user: Value) -> String {
        serde_json::to_string_pretty(&json!({"numStartups": 7, "mcpServers": user}))
            .expect("serialize ~/.claude.json")
    }

    struct ClaudeCall {
        /// The text the call leaves in `~/.claude.json`, or `None` to leave the file as it is.
        state: Option<String>,
        exit: u8,
        stderr: Vec<u8>,
    }

    fn call(state: Option<String>, exit: u8) -> ClaudeCall {
        ClaudeCall {
            state,
            exit,
            stderr: Vec::new(),
        }
    }

    /// Puts a stub `claude` on the login PATH. Call N copies its state over `~/.claude.json`,
    /// prints its stderr, exits with its status, and logs its arguments, working folder, `PWD`,
    /// `PATH`, the traffic variable, and whether the backup and the kept copy exist.
    fn install_claude(sb: &Sandbox, calls: Vec<ClaudeCall>) -> PathBuf {
        let stub = sb.root.join("claude-stub");
        fs::create_dir_all(&stub).expect("create the stub folder");
        for (index, step) in calls.into_iter().enumerate() {
            let n = index + 1;
            if let Some(state) = step.state {
                fs::write(stub.join(format!("state-{n}")), state).expect("write a stub state");
            }
            fs::write(stub.join(format!("exit-{n}")), step.exit.to_string())
                .expect("write a stub exit");
            fs::write(stub.join(format!("stderr-{n}")), step.stderr).expect("write a stub stderr");
        }
        let claude_json = sb.home.join(".claude.json");
        let script = format!(
            r#"#!/bin/sh
d='{stub}'
n=$(/bin/cat "$d/count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$d/count"
{{
  echo "call $n"
  for a in "$@"; do printf 'arg=%s\n' "$a"; done
  printf 'pwd=%s\n' "$(pwd -P)"
  printf 'PWD=%s\n' "$PWD"
  printf 'PATH=%s\n' "$PATH"
  printf 'TRAFFIC=%s\n' "$CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"
  if [ -f '{claude}.bak-guardrail' ]; then echo backup=yes; else echo backup=no; fi
  if [ -f '{kept}' ]; then echo kept=yes; else echo kept=no; fi
}} >> "$d/log"
if [ -f "$d/state-$n" ]; then /bin/cp "$d/state-$n" '{claude}'; fi
if [ -f "$d/stderr-$n" ]; then /bin/cat "$d/stderr-$n" >&2; fi
if [ -f "$d/exit-$n" ]; then exit "$(/bin/cat "$d/exit-$n")"; fi
exit 0
"#,
            stub = stub.display(),
            claude = claude_json.display(),
            kept = sb.kept_copy(".claude.json").display(),
        );
        write_script(&sb.bin.join("claude"), script.as_bytes());
        stub
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    struct CallLog {
        args: Vec<String>,
        pwd: String,
        pwd_env: String,
        path: String,
        traffic: String,
        backup: String,
        kept: String,
    }

    fn claude_calls(stub: &Path) -> Vec<CallLog> {
        let text = fs::read_to_string(stub.join("log")).unwrap_or_default();
        let mut calls: Vec<CallLog> = Vec::new();
        for line in text.lines() {
            if line.starts_with("call ") {
                calls.push(CallLog::default());
                continue;
            }
            let Some(log) = calls.last_mut() else {
                continue;
            };
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            match key {
                "arg" => log.args.push(value.to_string()),
                "pwd" => log.pwd = value.to_string(),
                "PWD" => log.pwd_env = value.to_string(),
                "PATH" => log.path = value.to_string(),
                "TRAFFIC" => log.traffic = value.to_string(),
                "backup" => log.backup = value.to_string(),
                "kept" => log.kept = value.to_string(),
                _ => {}
            }
        }
        calls
    }

    /// The name, the JSON entry, and the scope words of an `add-json` call.
    fn add_json(log: &CallLog) -> Option<(String, Value, Vec<String>)> {
        match log.args.as_slice() {
            [mcp, add, name, entry, rest @ ..] if mcp == "mcp" && add == "add-json" => Some((
                name.clone(),
                serde_json::from_str(entry).ok()?,
                rest.to_vec(),
            )),
            _ => None,
        }
    }

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    fn stored_user_entry(sb: &Sandbox, name: &str) -> Value {
        fs::read_to_string(sb.home.join(".claude.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .map(|file| file["mcpServers"][name].clone())
            .unwrap_or_default()
    }

    fn user_db() -> ServerId {
        server(ClientId::ClaudeCodeUser, "db")
    }

    fn wrap_one(sb: &Sandbox, id: ServerId) -> Result<WrapReport, String> {
        wrap_request(&Mutex::new(()), &sb.env(), &[id], SECS)
    }

    /// The text with the sandbox root replaced, so a number in a temp path cannot match.
    fn without_root(sb: &Sandbox, text: &str) -> String {
        text.replace(&sb.root.display().to_string(), "<root>")
    }

    #[test]
    fn a_claude_code_row_ends_by_what_claude_json_holds() {
        // User scope.
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        let stub = install_claude(
            &sb,
            vec![
                call(Some(claude_text(json!({}))), 0),
                call(Some(claude_text(json!({"db": wrapped_db(&sb)}))), 0),
            ],
        );
        let report = wrap_one(&sb, user_db());
        let calls = claude_calls(&stub);
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "user scope: {report:?}"
        );
        assert_eq!(
            calls.first().map(|log| log.args.clone()),
            Some(strings(&["mcp", "remove", "db", "--scope", "user"])),
            "user scope: the remove call"
        );
        assert_eq!(
            calls
                .first()
                .map(|log| (log.backup.clone(), log.kept.clone())),
            Some(("yes".to_string(), "yes".to_string())),
            "user scope: the backup and the kept copy exist before the remove"
        );
        assert_eq!(
            calls.get(1).and_then(add_json),
            Some((
                "db".to_string(),
                wrapped_db(&sb),
                strings(&["--scope", "user"])
            )),
            "user scope: the add-json call sends the step 6 entry"
        );
        assert_eq!(calls.len(), 2, "user scope: two calls");
        assert!(
            calls
                .iter()
                .all(|log| log.path == sb.login_text() && log.traffic == "1"),
            "each child has the login PATH and CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1: {calls:?}"
        );
        assert!(
            !sb.kept_copy(".claude.json").exists(),
            "user scope: the kept copy is gone at the end"
        );
        assert!(
            messages(&report).contains("Start a new Claude Code session"),
            "user scope: the message says to start a new session: {}",
            messages(&report)
        );

        // Local scope.
        let sb = sandbox();
        let real = sb.root.join("project-real");
        fs::create_dir_all(&real).expect("create the project folder");
        let link = sb.root.join("project-link");
        symlink(&real, &link).expect("link the project folder");
        let project = link.display().to_string();
        let local_file = |entry: Value| {
            serde_json::to_string_pretty(&json!({
                "projects": {project.clone(): {"mcpServers": entry}},
            }))
            .expect("serialize ~/.claude.json")
        };
        sb.put(
            ".claude.json",
            &local_file(json!({"local-db": original_db()})),
        );
        let stub = install_claude(
            &sb,
            vec![
                call(Some(local_file(json!({}))), 0),
                call(Some(local_file(json!({"local-db": wrapped_db(&sb)}))), 0),
            ],
        );
        let report = wrap_one(
            &sb,
            ServerId {
                client: ClientId::ClaudeCodeLocal,
                project: Some(project.clone()),
                name: "local-db".to_string(),
            },
        );
        let calls = claude_calls(&stub);
        let real_text = fs::canonicalize(&real)
            .expect("resolve the project folder")
            .display()
            .to_string();
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "local scope: {report:?}"
        );
        assert_eq!(
            calls.first().map(|log| log.args.clone()),
            Some(strings(&["mcp", "remove", "local-db", "--scope", "local"])),
            "local scope: the remove call"
        );
        assert_eq!(
            calls.get(1).and_then(add_json),
            Some((
                "local-db".to_string(),
                wrapped_db(&sb),
                strings(&["--scope", "local"])
            )),
            "local scope: the add-json call"
        );
        assert!(
            calls.len() == 2
                && calls
                    .iter()
                    .all(|log| log.pwd == real_text && log.pwd_env == project),
            "local scope: the project folder is the working folder and PWD: {calls:?}"
        );
        assert!(
            messages(&report).contains(&project),
            "local scope: the message names the folder: {}",
            messages(&report)
        );

        // A name with a space and a quote.
        let sb = sandbox();
        let name = "my 'db' server";
        sb.put(".claude.json", &claude_text(json!({name: original_db()})));
        let stub = install_claude(
            &sb,
            vec![
                call(Some(claude_text(json!({}))), 0),
                call(Some(claude_text(json!({name: wrapped_db(&sb)}))), 0),
            ],
        );
        let report = wrap_one(&sb, server(ClientId::ClaudeCodeUser, name));
        let calls = claude_calls(&stub);
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "an odd name: {report:?}"
        );
        assert_eq!(
            calls.first().map(|log| log.args.clone()),
            Some(strings(&["mcp", "remove", name, "--scope", "user"])),
            "a name with a space and a quote reaches claude as one argument"
        );

        // A local-scope project that is no longer a key under projects.
        let sb = sandbox();
        sb.put(
            ".claude.json",
            &json!({"projects": {"/projects/other": {"mcpServers": {"db": original_db()}}}})
                .to_string(),
        );
        let stub = install_claude(&sb, vec![call(None, 0)]);
        let report = wrap_one(
            &sb,
            ServerId {
                client: ClientId::ClaudeCodeLocal,
                project: Some("/projects/gone".to_string()),
                name: "db".to_string(),
            },
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Skipped],
            "a gone project: {report:?}"
        );
        assert!(
            messages(&report).contains("no longer in")
                && messages(&report).contains(&sb.home.join(".claude.json").display().to_string()),
            "a gone project: the message: {}",
            messages(&report)
        );
        assert!(
            claude_calls(&stub).is_empty(),
            "a gone project: no claude call"
        );

        // The selected entry changed between the first read and the remove.
        let changed_files = [
            ("gone", claude_text(json!({}))),
            (
                "different",
                claude_text(
                    json!({"db": {"command": "/usr/bin/db-server", "args": ["--port", "5432"], "env": {"DB_TOKEN": "tok-other-999"}}}),
                ),
            ),
            (
                "one more env key",
                claude_text(
                    json!({"db": {"command": "/usr/bin/db-server", "args": ["--port", "5432"], "env": {"DB_TOKEN": SECRET, "EXTRA": "x"}}}),
                ),
            ),
            ("a file that does not parse", "{not json".to_string()),
        ];
        for (label, now) in changed_files {
            let sb = sandbox();
            let claude = sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
            let first = file_state(&claude);
            fs::write(&claude, now).expect("change ~/.claude.json after the first read");
            let stub = install_claude(&sb, vec![call(None, 0), call(None, 0)]);
            let setup = RowSetup::new(&sb, user_db());
            let mut kept = None;
            let end = wrap_row_from(&setup.inputs(), first, &mut kept);
            assert_eq!(end.outcome, Outcome::Failed, "{label}: {end:?}");
            assert!(
                end.message.contains(CHANGED),
                "{label}: the message: {}",
                end.message
            );
            assert!(
                claude_calls(&stub).is_empty(),
                "{label}: the stub gets no call"
            );
            assert!(
                !sb.kept_copy(".claude.json").exists(),
                "{label}: no kept copy stays"
            );
        }

        // An entry over the cap at wrap time.
        let sb = sandbox();
        let big = json!({"command": "/usr/bin/db-server", "env": {"PAD": "p".repeat(70_000)}});
        sb.put(".claude.json", &claude_text(json!({"db": big})));
        let backup = sb.put(".claude.json.bak-guardrail", "an older backup");
        let stub = install_claude(&sb, vec![call(None, 0)]);
        let report = wrap_one(&sb, user_db());
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Skipped],
            "over the cap: {report:?}"
        );
        assert!(
            messages(&report).contains(CAP_REASON),
            "over the cap: the reason: {}",
            messages(&report)
        );
        assert!(
            claude_calls(&stub).is_empty(),
            "over the cap: the stub gets no call"
        );
        assert_eq!(
            fs::read_to_string(&backup).ok().as_deref(),
            Some("an older backup"),
            "over the cap: the backup does not change"
        );
        assert!(
            !sb.kept_copy(".claude.json").exists(),
            "over the cap: no kept copy exists"
        );

        // A remove that exits 0 and leaves the original entry.
        let sb = sandbox();
        let original_text = claude_text(json!({"db": original_db()}));
        let claude = sb.put(".claude.json", &original_text);
        let stub = install_claude(&sb, vec![call(None, 0)]);
        let report = wrap_one(&sb, user_db());
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a remove that left the entry"
        );
        assert_eq!(
            claude_calls(&stub).len(),
            1,
            "a remove that left the entry: one call"
        );
        assert_eq!(
            fs::read_to_string(&claude).ok(),
            Some(original_text),
            "a remove that left the entry: nothing changed"
        );
        assert!(
            !sb.kept_copy(".claude.json").exists(),
            "a remove that left the entry: the read confirms the original, so the kept copy goes"
        );

        // A remove that fails and leaves no entry.
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        let stub = install_claude(
            &sb,
            vec![
                call(Some(claude_text(json!({}))), 1),
                call(Some(claude_text(json!({"db": original_db()}))), 0),
            ],
        );
        let report = wrap_one(&sb, user_db());
        let calls = claude_calls(&stub);
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a failed remove: {report:?}"
        );
        assert_eq!(
            calls.get(1).and_then(add_json),
            Some((
                "db".to_string(),
                original_db(),
                strings(&["--scope", "user"])
            )),
            "a failed remove that left no entry: the add-back sends the original"
        );
        assert_eq!(
            stored_user_entry(&sb, "db"),
            original_db(),
            "a failed remove: the original is back"
        );

        // A remove that leaves the entry in another form.
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        let stub = install_claude(
            &sb,
            vec![call(
                Some(claude_text(
                    json!({"db": {"command": "/usr/bin/db-server"}}),
                )),
                0,
            )],
        );
        let report = wrap_one(&sb, user_db());
        let kept = sb.kept_copy(".claude.json");
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "another form: {report:?}"
        );
        assert_eq!(
            claude_calls(&stub).len(),
            1,
            "another form: no more calls run"
        );
        assert!(kept.exists(), "another form: the kept copy stays");
        assert!(
            messages(&report).contains(&kept.display().to_string()),
            "another form: the message names the kept copy: {}",
            messages(&report)
        );

        // An add-json that exits non-zero but stores the sent entry.
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        let stub = install_claude(
            &sb,
            vec![
                call(Some(claude_text(json!({}))), 0),
                call(Some(claude_text(json!({"db": wrapped_db(&sb)}))), 1),
            ],
        );
        let report = wrap_one(&sb, user_db());
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "an add-json that failed but stored the entry: {report:?}"
        );
        assert_eq!(
            claude_calls(&stub).len(),
            2,
            "a stored add-json: no add-back"
        );

        // An add-json that fails and stores nothing.
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        let stub = install_claude(
            &sb,
            vec![
                call(Some(claude_text(json!({}))), 0),
                call(None, 1),
                call(Some(claude_text(json!({"db": original_db()}))), 0),
            ],
        );
        let report = wrap_one(&sb, user_db());
        let calls = claude_calls(&stub);
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a failed add-json: {report:?}"
        );
        assert_eq!(
            calls.get(2).and_then(add_json),
            Some((
                "db".to_string(),
                original_db(),
                strings(&["--scope", "user"])
            )),
            "a failed add-json that stored nothing: the add-back runs"
        );
        assert!(
            !sb.kept_copy(".claude.json").exists(),
            "a confirmed add-back: the kept copy goes"
        );

        // A failed add-back.
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        let stub = install_claude(
            &sb,
            vec![
                call(Some(claude_text(json!({}))), 0),
                call(None, 1),
                call(None, 1),
            ],
        );
        let report = wrap_one(&sb, user_db());
        let kept = sb.kept_copy(".claude.json");
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a failed add-back: {report:?}"
        );
        assert_eq!(
            claude_calls(&stub).len(),
            3,
            "a failed add-back: three calls"
        );
        assert!(
            messages(&report).contains("Server db is removed, and the app could not add it back.")
                && messages(&report).contains(&kept.display().to_string()),
            "a failed add-back: the message names the kept copy: {}",
            messages(&report)
        );
        assert!(kept.exists(), "a failed add-back: the kept copy stays");

        // An add-json that drops cwd.
        let sb = sandbox();
        let mut with_cwd = original_db();
        with_cwd["cwd"] = json!("/srv/db-home");
        sb.put(".claude.json", &claude_text(json!({"db": with_cwd})));
        let stub = install_claude(
            &sb,
            vec![
                call(Some(claude_text(json!({}))), 0),
                call(Some(claude_text(json!({"db": wrapped_db(&sb)}))), 0),
            ],
        );
        let report = wrap_one(&sb, user_db());
        let kept = sb.kept_copy(".claude.json");
        let message = messages(&report);
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a dropped cwd: {report:?}"
        );
        assert_eq!(
            claude_calls(&stub).len(),
            2,
            "a dropped cwd: no more calls run"
        );
        assert!(
            message.contains("cwd")
                && !message.contains("/srv/db-home")
                && message.contains(&kept.display().to_string()),
            "a dropped cwd: the message names cwd and the kept copy, with no value: {message}"
        );
        assert!(kept.exists(), "a dropped cwd: the kept copy stays");

        // A ~/.claude.json that does not parse after a call.
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        let stub = install_claude(&sb, vec![call(Some("{not json".to_string()), 0)]);
        let report = wrap_one(&sb, user_db());
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "no parse after a call"
        );
        assert_eq!(
            claude_calls(&stub).len(),
            1,
            "no parse after a call: no more calls run"
        );
        assert!(
            sb.kept_copy(".claude.json").exists(),
            "no parse after a call: the kept copy stays"
        );

        // A failed call shows its exit status, and no secret from its output.
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        install_claude(
            &sb,
            vec![ClaudeCall {
                state: None,
                exit: 97,
                stderr: format!("{SECRET}\n").into_bytes(),
            }],
        );
        let report = wrap_one(&sb, user_db());
        let message = without_root(&sb, &messages(&report));
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a failed call: {report:?}"
        );
        assert!(
            message.contains("97") && !message.contains(SECRET),
            "a failed call shows its exit status and none of its secret output: {message}"
        );

        // After an unrecovered row, the next Claude Code row is skipped.
        let sb = sandbox();
        let search = json!({"command": "/usr/bin/search-server"});
        sb.put(
            ".claude.json",
            &claude_text(json!({"db": original_db(), "search": search.clone()})),
        );
        let stub = install_claude(
            &sb,
            vec![call(
                Some(claude_text(
                    json!({"db": {"command": "/usr/bin/db-server"}, "search": search}),
                )),
                0,
            )],
        );
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[user_db(), server(ClientId::ClaudeCodeUser, "search")],
            SECS,
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed, Outcome::Skipped],
            "an unrecovered Claude Code row stops the next: {report:?}"
        );
        assert!(
            messages(&report).contains(STOPPED_FILE),
            "the skipped Claude Code row: {}",
            messages(&report)
        );
        assert_eq!(
            claude_calls(&stub).len(),
            1,
            "the skipped row starts no call"
        );
    }

    #[test]
    fn a_codex_row_wraps_through_the_file_write() {
        let sb = sandbox();
        let codex = sb.put(
            ".codex/config.toml",
            "[mcp_servers.files]\ncommand = \"npx\"\nargs = [\"-y\", \"@scope/files\"]\n",
        );
        set_mode(&codex, 0o600);
        let view = scan(&sb.env());
        assert_eq!(
            selectable(&view),
            vec![("files".to_string(), true)],
            "a wrappable Codex row is selectable once the binary and the audit log pass"
        );
        let report = wrap_request(
            &Mutex::new(()),
            &sb.env(),
            &[server(ClientId::Codex, "files")],
            SECS,
        );
        let expected = format!(
            "[mcp_servers.files]\ncommand = \"{bin}\"\nargs = [\"proxy\", \"--audit-log\", \"{audit}\", \"--\", \"{npx}\", \"-y\", \"@scope/files\"]\n",
            bin = sb.bin_text(),
            audit = sb.audit_text(),
            npx = sb.npx_text(),
        );
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Wrapped],
            "a Codex wrap: {report:?}"
        );
        assert_eq!(
            fs::read_to_string(&codex).ok(),
            Some(expected),
            "a Codex wrap: the table holds the step 6 entry"
        );
        assert_eq!(
            mode_of(&codex),
            0o600,
            "a Codex wrap: the file keeps mode 0600"
        );
        assert_eq!(
            names_in(&sb.home.join(".codex")),
            vec![
                "config.toml".to_string(),
                "config.toml.bak-guardrail".to_string()
            ],
            "a Codex wrap: a backup, and no kept copy or temp file"
        );
    }

    /// Output of exactly `len` bytes whose last line is `last`.
    fn output_of_len(len: usize, last: &str) -> Vec<u8> {
        let tail = format!("\n{last}\n");
        let mut output = "w".repeat(len - tail.len()).into_bytes();
        output.extend_from_slice(tail.as_bytes());
        output
    }

    fn failed_add_json_sandbox(add_json_exit: u8, add_json_stderr: Vec<u8>) -> Sandbox {
        let sb = sandbox();
        sb.put(".claude.json", &claude_text(json!({"db": original_db()})));
        install_claude(
            &sb,
            vec![
                call(Some(claude_text(json!({}))), 0),
                ClaudeCall {
                    state: None,
                    exit: add_json_exit,
                    stderr: add_json_stderr,
                },
                call(Some(claude_text(json!({"db": original_db()}))), 0),
            ],
        );
        sb
    }

    #[test]
    fn a_failed_claude_call_shows_its_last_line_or_why_not() {
        let sb = failed_add_json_sandbox(
            1,
            format!("warming up\nerror: cannot store {SECRET} now\n").into_bytes(),
        );
        let report = wrap_one(&sb, user_db());
        let message = messages(&report);
        assert_eq!(
            outcomes(&report),
            vec![Outcome::Failed],
            "a failed add-json: {report:?}"
        );
        assert!(
            message.contains("error: cannot store [hidden] now") && !message.contains(SECRET),
            "the last line shows with the env value hidden: {message}"
        );

        let sb = failed_add_json_sandbox(1, output_of_len(65_536, "error: the cause line"));
        let report = wrap_one(&sb, user_db());
        assert!(
            messages(&report).contains("error: the cause line"),
            "output of exactly 65,536 bytes shows a line: {}",
            messages(&report)
        );

        let sb = failed_add_json_sandbox(97, output_of_len(65_537, "error: the cause line"));
        let report = wrap_one(&sb, user_db());
        let message = without_root(&sb, &messages(&report));
        assert!(
            message.contains("97")
                && message.contains("too long")
                && !message.contains("error: the cause line"),
            "output of 65,537 bytes shows the exit status and says the output was too long: {message}"
        );
    }
}
