//! The app's own settings: what the window shows and what the poll thread watches.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The path and switch the poll thread uses. It is the channel message.
#[derive(Clone, Debug, PartialEq)]
pub struct EffectiveSettings {
    pub audit_log_path: PathBuf,
    pub notifications: bool,
}

/// The contents of `settings.json`. A missing field takes its default, and the load ignores
/// unknown fields, so an older app can still read a file that a newer one wrote.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct SavedSettings {
    audit_log_path: Option<PathBuf>,
    notifications: bool,
}

impl Default for SavedSettings {
    fn default() -> Self {
        Self {
            audit_log_path: None,
            notifications: true,
        }
    }
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
    CannotSave { file: String, error: String },
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
            Self::CannotSave { file, error } => {
                write!(f, "Cannot save settings to {file}: {error}.")
            }
        }
    }
}

pub struct SettingsStore {
    file: PathBuf,
    variable: Option<PathBuf>,
    default_path: PathBuf,
    saved: SavedSettings,
    /// Why the launch load fell back to the defaults. The next save clears it.
    problem: Option<String>,
}

impl SettingsStore {
    /// `variable` is the `MCP_GUARDRAIL_AUDIT_LOG` value from launch. Any set value wins, even an
    /// empty one, so a person who sets it keeps the behavior the README documents.
    ///
    /// A `file` that the app cannot use gives the defaults and a problem for the window. A
    /// missing file is a first launch, so it gives the defaults with no problem.
    pub fn load(file: PathBuf, variable: Option<PathBuf>, default_path: PathBuf) -> Self {
        let loaded = match fs::read_to_string(&file) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SavedSettings::default()),
            Err(error) => Err(error.to_string()),
            Ok(text) => parsed_settings(&text),
        };
        let (saved, problem) = match loaded {
            Ok(saved) => (saved, None),
            Err(error) => (
                SavedSettings::default(),
                Some(format!(
                    "Cannot read the settings file {}: {error}. The app uses the defaults. A save replaces the file.",
                    file.display()
                )),
            ),
        };
        Self {
            file,
            variable,
            default_path,
            saved,
            problem,
        }
    }

    pub fn effective(&self) -> EffectiveSettings {
        EffectiveSettings {
            audit_log_path: self.effective_path(),
            notifications: self.saved.notifications,
        }
    }

    pub fn view(&self) -> SettingsView {
        SettingsView {
            audit_log_path: self.effective_path().display().to_string(),
            path_from_variable: self.variable.is_some(),
            notifications: self.saved.notifications,
            problem: self.problem.clone(),
        }
    }

    /// Refuses the save while the variable sets the path, so the rule holds even if the page
    /// does not disable the field.
    pub fn set_audit_log_path(&mut self, text: &str) -> Result<(), SettingsError> {
        if self.variable.is_some() {
            return Err(SettingsError::PathFromVariable);
        }
        let path = checked_audit_log_path(text)?;
        self.commit(SavedSettings {
            audit_log_path: Some(path),
            ..self.saved.clone()
        })
    }

    /// Works while the variable sets the path. The file keeps the saved path, never the
    /// variable's.
    pub fn set_notifications(&mut self, on: bool) -> Result<(), SettingsError> {
        self.commit(SavedSettings {
            notifications: on,
            ..self.saved.clone()
        })
    }

    fn effective_path(&self) -> PathBuf {
        effective_path(self.variable.as_deref(), &self.saved, &self.default_path)
    }

    /// Writes `next`, and only then takes it as the current settings, so a failed save changes
    /// nothing.
    fn commit(&mut self, next: SavedSettings) -> Result<(), SettingsError> {
        let cannot_save = |error: String| SettingsError::CannotSave {
            file: self.file.display().to_string(),
            error,
        };
        let bytes =
            serde_json::to_vec_pretty(&next).map_err(|error| cannot_save(error.to_string()))?;
        write_atomically(&self.file, &bytes).map_err(|error| cannot_save(error.to_string()))?;
        self.saved = next;
        self.problem = None;
        Ok(())
    }
}

/// Blank text holds no settings, so it gives the defaults and is not a corrupt file.
fn parsed_settings(text: &str) -> Result<SavedSettings, String> {
    if text.trim().is_empty() {
        return Ok(SavedSettings::default());
    }
    let saved: SavedSettings = serde_json::from_str(text).map_err(|error| error.to_string())?;
    if saved
        .audit_log_path
        .as_deref()
        .is_some_and(Path::is_relative)
    {
        return Err("audit_log_path is not a full path".to_string());
    }
    Ok(saved)
}

/// Any set variable wins, even an empty one, then the saved path, then the default.
fn effective_path(variable: Option<&Path>, saved: &SavedSettings, default_path: &Path) -> PathBuf {
    variable
        .or(saved.audit_log_path.as_deref())
        .unwrap_or(default_path)
        .to_path_buf()
}

/// Replaces `file` by a rename, so a crash leaves the old or the new file whole, never a torn
/// one. The rename also replaces a symlink at `file` and never writes through it. The pid in
/// the temp name keeps two instances of the app off one temp file.
fn write_atomically(file: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(folder) = file.parent() {
        fs::create_dir_all(folder)?;
    }
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let written = (|| -> io::Result<()> {
        let mut out = File::create(&tmp)?;
        out.write_all(bytes)?;
        out.sync_all()?;
        fs::rename(&tmp, file)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
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

    #[cfg(unix)]
    #[test]
    fn a_saved_path_survives_a_reload_and_is_the_only_file_written() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let default_path = dir.path().join("default.jsonl");
        let log = dir.path().join("audit.jsonl");
        std::fs::write(&log, "{}\n").expect("write a readable log");

        let no_folder = dir.path().join("no-folder").join("config");

        let older = dir.path().join("older").join("config");
        std::fs::create_dir_all(&older).expect("create the config folder");
        std::fs::write(
            older.join("settings.json"),
            r#"{"audit_log_path": "/older/audit.jsonl", "notifications": true}"#,
        )
        .expect("write an older settings file");

        let symlinked = dir.path().join("symlinked").join("config");
        std::fs::create_dir_all(&symlinked).expect("create the config folder");
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "bytes outside the config folder").expect("write the target");
        std::os::unix::fs::symlink(&outside, symlinked.join("settings.json"))
            .expect("link settings.json to a file outside the folder");

        let rows = [
            ("no config folder", no_folder),
            ("an older settings.json", older),
            ("a symlink at settings.json", symlinked),
        ];
        for (label, config) in rows {
            let file = config.join("settings.json");
            let mut store = SettingsStore::load(file.clone(), None, default_path.clone());
            assert_eq!(
                store
                    .set_audit_log_path(log.to_str().expect("a UTF-8 temp path"))
                    .map_err(|error| error.to_string()),
                Ok(()),
                "{label}: the save works"
            );
            let reloaded = SettingsStore::load(file.clone(), None, default_path.clone());
            assert_eq!(
                reloaded.effective().audit_log_path,
                log,
                "{label}: a reload watches the saved path"
            );
            let mut names: Vec<String> = std::fs::read_dir(&config)
                .expect("read the config folder")
                .map(|entry| {
                    entry
                        .expect("a config folder entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            names.sort();
            assert_eq!(
                names,
                ["settings.json"],
                "{label}: the config folder holds only settings.json"
            );
            assert!(
                std::fs::symlink_metadata(&file)
                    .expect("settings.json exists")
                    .file_type()
                    .is_file(),
                "{label}: settings.json is a regular file"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&outside).expect("read the symlink target"),
            "bytes outside the config folder",
            "the save never writes through the symlink"
        );
    }

    #[test]
    fn the_effective_path_is_the_variable_then_the_saved_path_then_the_default() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let default_path = dir.path().join("default.jsonl");
        let saved = dir.path().join("saved.json");
        std::fs::write(&saved, r#"{"audit_log_path": "/saved/audit.jsonl"}"#)
            .expect("write a saved settings file");
        let absent = dir.path().join("absent.json");
        let unknown_field = dir.path().join("unknown-field.json");
        std::fs::write(
            &unknown_field,
            r#"{"audit_log_path": "/saved/audit.jsonl", "theme": "dark"}"#,
        )
        .expect("write a settings file from a newer app");
        let rows = [
            (
                "the variable and a saved path",
                saved.clone(),
                Some(PathBuf::from("/variable/audit.jsonl")),
                PathBuf::from("/variable/audit.jsonl"),
                true,
            ),
            (
                "a saved path only",
                saved.clone(),
                None,
                PathBuf::from("/saved/audit.jsonl"),
                false,
            ),
            ("no file", absent, None, default_path.clone(), false),
            (
                "an empty variable and a saved path",
                saved.clone(),
                Some(PathBuf::from("")),
                PathBuf::from(""),
                true,
            ),
            (
                "a saved file with an unknown field",
                unknown_field,
                None,
                PathBuf::from("/saved/audit.jsonl"),
                false,
            ),
        ];
        for (label, file, variable, expected_path, expected_from_variable) in rows {
            let store = SettingsStore::load(file, variable, default_path.clone());
            assert_eq!(
                store.effective().audit_log_path,
                expected_path,
                "{label}: the effective path"
            );
            assert_eq!(
                store.view().path_from_variable,
                expected_from_variable,
                "{label}: whether the variable sets the path"
            );
        }
    }

    #[test]
    fn a_failed_save_keeps_the_previous_settings() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let blocker = dir.path().join("config");
        std::fs::write(&blocker, "a regular file where the config folder goes")
            .expect("write a regular file");
        let file = blocker.join("settings.json");
        let default_path = dir.path().join("default.jsonl");
        let log = dir.path().join("audit.jsonl");
        std::fs::write(&log, "{}\n").expect("write a readable log");
        let os_error = std::fs::create_dir_all(&blocker)
            .expect_err("a regular file blocks the config folder")
            .to_string();
        let mut store = SettingsStore::load(file.clone(), None, default_path.clone());
        assert_eq!(
            store
                .set_audit_log_path(log.to_str().expect("a UTF-8 temp path"))
                .map_err(|error| error.to_string()),
            Err(format!(
                "Cannot save settings to {}: {os_error}.",
                file.display()
            )),
            "the window shows the save failure"
        );
        assert_eq!(
            store.effective().audit_log_path,
            default_path,
            "the poll thread keeps the previous path"
        );
        assert_eq!(
            store.view().audit_log_path,
            default_path.display().to_string(),
            "the window keeps the previous path"
        );
    }

    #[test]
    fn notifications_off_survives_a_reload_and_keeps_the_saved_path() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let default_path = dir.path().join("default.jsonl");
        let variable = dir.path().join("from-variable.jsonl");
        let with_saved = dir.path().join("with-saved");
        std::fs::create_dir_all(&with_saved).expect("create the config folder");
        std::fs::write(
            with_saved.join("settings.json"),
            r#"{"audit_log_path": "/saved/audit.jsonl", "notifications": true}"#,
        )
        .expect("write a saved settings file");
        let without_saved = dir.path().join("without-saved");
        let rows = [
            (
                "a saved path",
                with_saved.join("settings.json"),
                PathBuf::from("/saved/audit.jsonl"),
            ),
            (
                "no saved path",
                without_saved.join("settings.json"),
                default_path.clone(),
            ),
        ];
        for (label, file, expected_path) in rows {
            let mut store =
                SettingsStore::load(file.clone(), Some(variable.clone()), default_path.clone());
            assert_eq!(
                store
                    .set_notifications(false)
                    .map_err(|error| error.to_string()),
                Ok(()),
                "{label}: the toggle works while the variable is set"
            );
            let reloaded = SettingsStore::load(file, None, default_path.clone());
            assert_eq!(
                reloaded.effective().audit_log_path,
                expected_path,
                "{label}: the variable path never reaches settings.json"
            );
            assert!(
                !reloaded.effective().notifications,
                "{label}: notifications stay off after a reload"
            );
        }
    }

    #[test]
    fn a_missing_or_blank_file_gives_the_defaults_without_a_problem() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let default_path = dir.path().join("default.jsonl");
        let missing = dir.path().join("missing.json");
        let empty = dir.path().join("empty.json");
        std::fs::write(&empty, "").expect("write an empty file");
        let whitespace = dir.path().join("whitespace.json");
        std::fs::write(&whitespace, " \n\t\n").expect("write a whitespace file");
        let braces = dir.path().join("braces.json");
        std::fs::write(&braces, "{}").expect("write an empty object");
        let rows = [
            ("a missing file", missing),
            ("a file of 0 bytes", empty),
            ("a whitespace-only file", whitespace),
            ("{}", braces),
        ];
        for (label, file) in rows {
            let view = SettingsStore::load(file, None, default_path.clone()).view();
            assert_eq!(
                view.audit_log_path,
                default_path.display().to_string(),
                "{label}: the default path"
            );
            assert!(view.notifications, "{label}: notifications default to on");
            assert_eq!(view.problem, None, "{label}: no banner");
        }
    }

    #[test]
    fn a_corrupt_file_gives_the_defaults_and_a_problem() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let default_path = dir.path().join("default.jsonl");
        let invalid_json = dir.path().join("invalid.json");
        std::fs::write(&invalid_json, r#"{"audit_log_path": "#).expect("write invalid JSON");
        let wrong_type = dir.path().join("wrong-type.json");
        std::fs::write(&wrong_type, r#"{"notifications": "yes"}"#).expect("write a wrong type");
        let relative = dir.path().join("relative.json");
        std::fs::write(
            &relative,
            r#"{"audit_log_path": "logs/audit.jsonl", "notifications": false}"#,
        )
        .expect("write a relative saved path");
        let folder = dir.path().join("a-folder").join("settings.json");
        std::fs::create_dir_all(&folder).expect("create a folder at the settings path");
        let rows = [
            ("invalid JSON", invalid_json),
            ("a wrong field type", wrong_type),
            ("a relative audit_log_path", relative),
            ("a folder at the settings path", folder),
        ];
        for (label, file) in rows {
            let prefix = format!("Cannot read the settings file {}: ", file.display());
            let view = SettingsStore::load(file, None, default_path.clone()).view();
            assert_eq!(
                view.audit_log_path,
                default_path.display().to_string(),
                "{label}: the default path"
            );
            assert!(view.notifications, "{label}: notifications default to on");
            assert!(
                view.problem
                    .as_deref()
                    .is_some_and(|problem| problem.starts_with(&prefix)),
                "{label}: {:?} must start with {prefix:?}",
                view.problem
            );
            assert!(
                view.problem.as_deref().is_some_and(|problem| problem
                    .ends_with(". The app uses the defaults. A save replaces the file.")),
                "{label}: {:?} must end with the banner's promise",
                view.problem
            );
        }
    }

    #[test]
    fn a_save_clears_the_problem() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let file = dir.path().join("settings.json");
        std::fs::write(&file, "not json").expect("write a corrupt settings file");
        let default_path = dir.path().join("default.jsonl");
        let log = dir.path().join("audit.jsonl");
        std::fs::write(&log, "{}\n").expect("write a readable log");
        let mut store = SettingsStore::load(file.clone(), None, default_path.clone());
        assert!(
            store.view().problem.is_some(),
            "the corrupt file shows a banner before the save"
        );
        assert_eq!(
            store
                .set_audit_log_path(log.to_str().expect("a UTF-8 temp path"))
                .map_err(|error| error.to_string()),
            Ok(()),
            "the save works"
        );
        assert_eq!(store.view().problem, None, "the save clears the banner");
        assert_eq!(
            SettingsStore::load(file, None, default_path).view().problem,
            None,
            "the replaced file loads with no banner"
        );
    }
}
