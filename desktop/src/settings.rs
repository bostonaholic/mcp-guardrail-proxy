//! The app's own settings: what the window shows and what the poll thread watches.

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// The path and switch the poll thread uses. It is the channel message.
#[derive(Clone, Debug, PartialEq)]
pub struct EffectiveSettings {
    pub audit_log_path: PathBuf,
    pub notifications: bool,
}

/// What the window shows.
#[derive(Serialize)]
pub struct SettingsView {
    audit_log_path: String,
    path_from_variable: bool,
    notifications: bool,
    problem: Option<String>,
}

/// Why a save was refused. `Display` gives the message the window shows.
#[derive(Debug, PartialEq)]
pub enum SettingsError {
    EmptyPath,
    RelativePath,
    NotAFile { path: String },
    CannotRead { path: String, error: String },
    PathFromVariable,
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("Enter the full path of the audit log file."),
            Self::RelativePath => {
                f.write_str("Enter a full path that starts with /. The app does not expand ~.")
            }
            Self::NotAFile { path } => {
                write!(f, "{path} is not a file. Enter the path of the audit log file.")
            }
            Self::CannotRead { path, error } => write!(f, "Cannot read {path}: {error}."),
            Self::PathFromVariable => f.write_str(
                "MCP_GUARDRAIL_AUDIT_LOG sets the path for this launch. Launch the app without it to save a path.",
            ),
        }
    }
}

pub struct SettingsStore {
    audit_log_path: PathBuf,
    path_from_variable: bool,
}

impl SettingsStore {
    /// `variable` is the `MCP_GUARDRAIL_AUDIT_LOG` value from launch. Any set value wins, even an
    /// empty one, so a person who sets it keeps the behavior the README documents.
    pub fn load(_file: PathBuf, variable: Option<PathBuf>, default_path: PathBuf) -> Self {
        Self {
            path_from_variable: variable.is_some(),
            audit_log_path: variable.unwrap_or(default_path),
        }
    }

    pub fn effective(&self) -> EffectiveSettings {
        EffectiveSettings {
            audit_log_path: self.audit_log_path.clone(),
            notifications: true,
        }
    }

    pub fn view(&self) -> SettingsView {
        SettingsView {
            audit_log_path: self.audit_log_path.display().to_string(),
            path_from_variable: self.path_from_variable,
            notifications: true,
            problem: None,
        }
    }

    /// Refuses the save while the variable sets the path, so the rule holds even if the page
    /// does not disable the field.
    pub fn set_audit_log_path(&mut self, text: &str) -> Result<(), SettingsError> {
        if self.path_from_variable {
            return Err(SettingsError::PathFromVariable);
        }
        self.audit_log_path = checked_audit_log_path(text)?;
        Ok(())
    }
}

/// The trimmed path, if the app can watch it. A file that does not exist yet passes, because a
/// proxy creates the log when it starts.
fn checked_audit_log_path(text: &str) -> Result<PathBuf, SettingsError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(SettingsError::EmptyPath);
    }
    let path = Path::new(text);
    if !path.is_absolute() {
        return Err(SettingsError::RelativePath);
    }
    let cannot_read = |error: io::Error| SettingsError::CannotRead {
        path: text.to_string(),
        error: error.to_string(),
    };
    // Metadata comes before the open: opening a named pipe would block until a writer appears.
    match fs::metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(path.to_path_buf()),
        Err(error) => return Err(cannot_read(error)),
        Ok(metadata) if !metadata.is_file() => {
            return Err(SettingsError::NotAFile {
                path: text.to_string(),
            });
        }
        Ok(_) => {}
    }
    File::open(path).map_err(cannot_read)?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_paths_keep_the_previous_settings() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let previous = dir.path().join("previous.jsonl");
        let folder = dir.path().to_path_buf();
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "").expect("write a regular file");
        let under_a_file = plain.join("audit.jsonl");
        let under_a_file_error = std::fs::metadata(&under_a_file)
            .expect_err("a path under a regular file has no metadata")
            .to_string();
        let rows = [
            (
                "empty",
                String::new(),
                "Enter the full path of the audit log file.".to_string(),
            ),
            (
                "whitespace only",
                " \t ".to_string(),
                "Enter the full path of the audit log file.".to_string(),
            ),
            (
                "a relative path",
                "audit.jsonl".to_string(),
                "Enter a full path that starts with /. The app does not expand ~.".to_string(),
            ),
            (
                "a path that starts with ~",
                "~/audit.jsonl".to_string(),
                "Enter a full path that starts with /. The app does not expand ~.".to_string(),
            ),
            (
                "the root folder",
                "/".to_string(),
                "/ is not a file. Enter the path of the audit log file.".to_string(),
            ),
            (
                "a temp folder",
                folder.display().to_string(),
                format!(
                    "{} is not a file. Enter the path of the audit log file.",
                    folder.display()
                ),
            ),
            (
                "a device",
                "/dev/null".to_string(),
                "/dev/null is not a file. Enter the path of the audit log file.".to_string(),
            ),
            (
                "a path under a regular file",
                under_a_file.display().to_string(),
                format!(
                    "Cannot read {}: {under_a_file_error}.",
                    under_a_file.display()
                ),
            ),
        ];
        for (label, text, message) in rows {
            let config = tempfile::tempdir().expect("create a config dir");
            let mut store =
                SettingsStore::load(config.path().join("settings.json"), None, previous.clone());
            assert_eq!(
                store
                    .set_audit_log_path(&text)
                    .map_err(|error| error.to_string()),
                Err(message),
                "{label}: the window shows this message"
            );
            assert_eq!(
                store.effective().audit_log_path,
                previous,
                "{label}: the previous path stays"
            );
        }
    }

    #[test]
    fn accepted_paths_become_the_effective_path() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let default_path = dir.path().join("default.jsonl");
        let readable = dir.path().join("readable.jsonl");
        std::fs::write(&readable, "{}\n").expect("write a readable log");
        let not_yet = dir.path().join("not-yet.jsonl");
        let rows = [
            (
                "a readable file",
                readable.display().to_string(),
                readable.clone(),
            ),
            (
                "a file that does not exist yet",
                not_yet.display().to_string(),
                not_yet.clone(),
            ),
            (
                "a readable path with spaces around it",
                format!("  {}\t", readable.display()),
                readable.clone(),
            ),
        ];
        for (label, text, expected) in rows {
            let config = tempfile::tempdir().expect("create a config dir");
            let mut store = SettingsStore::load(
                config.path().join("settings.json"),
                None,
                default_path.clone(),
            );
            assert_eq!(
                store
                    .set_audit_log_path(&text)
                    .map_err(|error| error.to_string()),
                Ok(()),
                "{label}: the save works"
            );
            assert_eq!(
                store.effective().audit_log_path,
                expected,
                "{label}: the trimmed path is the effective path"
            );
        }
    }

    #[test]
    fn a_path_save_is_refused_while_the_variable_is_set() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let variable = dir.path().join("from-variable.jsonl");
        let readable = dir.path().join("readable.jsonl");
        std::fs::write(&readable, "{}\n").expect("write a readable log");
        let mut store = SettingsStore::load(
            dir.path().join("config").join("settings.json"),
            Some(variable.clone()),
            dir.path().join("default.jsonl"),
        );
        assert_eq!(
            store
                .set_audit_log_path(readable.to_str().expect("a UTF-8 temp path"))
                .map_err(|error| error.to_string()),
            Err("MCP_GUARDRAIL_AUDIT_LOG sets the path for this launch. Launch the app without it to save a path.".to_string()),
            "the command refuses the save even if the page does not"
        );
        assert_eq!(
            store.effective().audit_log_path,
            variable,
            "the variable path stays"
        );
        assert!(
            store.view().path_from_variable,
            "the window must say that the variable sets the path"
        );
    }
}
