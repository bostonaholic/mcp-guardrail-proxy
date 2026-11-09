//! The update settings in `settings.json` inside the folder the caller passes: the chosen mode
//! and the two saved version bounds. The app passes its own `updates` folder, so this file never
//! shares a path with the General tab's `settings.json`.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use semver::Version;
use serde_json::{Map, Value};

use crate::update::{SaveRequest, UpdateMode};

const FILE_NAME: &str = "settings.json";
const MODE_KEY: &str = "update_mode";
const TOLD_KEY: &str = "notified_version";
const FAILED_KEY: &str = "failed_version";
const FIRST_RUN_NOTE: &str = "Using the default setting. Choose one to save it.";

/// What `settings.json` holds. Every key is optional.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Settings {
    /// Present only after the person chose a mode, so the first-run note stays until they do.
    pub update_mode: Option<UpdateMode>,
    pub notified_version: Option<Version>,
    pub failed_version: Option<Version>,
}

/// Reads `dir/settings.json`, and a note for the window when the default mode is in use. A
/// missing, unreadable, or invalid file never fails: it gives the default and a note that says
/// why, and an unreadable or invalid one also writes one stderr line.
pub fn load(dir: &Path) -> (Settings, Option<String>) {
    let path = dir.join(FILE_NAME);
    let (settings, problem) = read(&path);
    if let Err(reason) = problem {
        eprintln!(
            "mcp-guardrail-desktop: update settings {} could not be read: {reason}",
            path.display()
        );
        let note =
            format!("The saved update setting could not be read: {reason}. The app uses Notify.");
        return (settings, Some(note));
    }
    let note = settings
        .update_mode
        .is_none()
        .then(|| FIRST_RUN_NOTE.to_string());
    (settings, note)
}

/// The settings a save writes: the request's mode when it holds one, else the file's mode, and
/// the higher of each version bound in semver order.
pub fn merge(on_disk: Settings, request: &SaveRequest) -> Settings {
    Settings {
        update_mode: request.mode.or(on_disk.update_mode),
        notified_version: on_disk
            .notified_version
            .max(request.remembered.told.clone()),
        failed_version: on_disk
            .failed_version
            .max(request.remembered.failed.clone()),
    }
}

/// Merges `request` with the file on disk and replaces the file. A missing or unreadable file
/// counts as empty. The write goes to a temporary file named for this process, so two app
/// processes never write the same file, and the rename publishes only a complete file. A failed
/// save removes its temporary file before it returns the error.
pub fn save(dir: &Path, request: &SaveRequest) -> io::Result<()> {
    let path = dir.join(FILE_NAME);
    let merged = merge(read(&path).0, request);
    fs::create_dir_all(dir)?;
    let temporary = dir.join(format!("{FILE_NAME}.{}.tmp", std::process::id()));
    let saved =
        write_synced(&temporary, &to_json(&merged)).and_then(|()| fs::rename(&temporary, &path));
    if saved.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    saved
}

/// The window note for a save that failed. The values stay in memory until the app quits.
pub fn save_failed_note(error: &io::Error) -> String {
    format!(
        "Update settings could not be saved: {error}. They hold until MCP Guardrail quits. Choose a mode to try again."
    )
}

/// What the file holds, and the reason when the file or its mode could not be read. A missing
/// file reads as empty with no problem. The version keys of a file whose mode is bad still load,
/// and a version that is not semver reads as empty.
fn read(path: &Path) -> (Settings, Result<(), String>) {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return (Settings::default(), Ok(()));
        }
        Err(error) => return (Settings::default(), Err(error.to_string())),
    };
    let fields: Map<String, Value> = match serde_json::from_str(&text) {
        Ok(fields) => fields,
        Err(error) => return (Settings::default(), Err(error.to_string())),
    };
    let version = |key: &str| {
        fields
            .get(key)
            .and_then(Value::as_str)
            .and_then(|text| Version::parse(text).ok())
    };
    let mut settings = Settings {
        update_mode: None,
        notified_version: version(TOLD_KEY),
        failed_version: version(FAILED_KEY),
    };
    let Some(mode) = fields.get(MODE_KEY) else {
        return (settings, Ok(()));
    };
    // The same decoder Tauri uses for the `set_update_mode` argument, so the file accepts
    // exactly the values the window can send.
    match serde_json::from_value::<UpdateMode>(mode.clone()) {
        Ok(mode) => {
            settings.update_mode = Some(mode);
            (settings, Ok(()))
        }
        Err(error) => (settings, Err(format!("{MODE_KEY}: {error}"))),
    }
}

/// Writes only the keys that hold a value, with versions as strings.
fn to_json(settings: &Settings) -> String {
    let mut fields = Map::new();
    if let Some(mode) = settings.update_mode {
        let mode = serde_json::to_value(mode).expect("a mode serializes as a string");
        fields.insert(MODE_KEY.to_string(), mode);
    }
    for (key, version) in [
        (TOLD_KEY, &settings.notified_version),
        (FAILED_KEY, &settings.failed_version),
    ] {
        if let Some(version) = version {
            fields.insert(key.to_string(), Value::String(version.to_string()));
        }
    }
    serde_json::to_string_pretty(&fields).expect("a map of strings serializes")
}

/// Creates or truncates `path`, writes `text`, and syncs it, so a power loss after the rename
/// cannot leave an empty settings file.
fn write_synced(path: &Path, text: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::Remembered;
    use std::fs;

    const FIRST_RUN_NOTE: &str = "Using the default setting. Choose one to save it.";
    const ERROR_NOTE_START: &str = "The saved update setting could not be read: ";
    const ERROR_NOTE_END: &str = ". The app uses Notify.";

    struct LoadRow {
        name: &'static str,
        /// Leaves the directory as the last run would.
        prepare: fn(&Path),
        mode: UpdateMode,
        notified_version: Option<&'static str>,
        failed_version: Option<&'static str>,
        has_note: bool,
        note_starts_with: &'static str,
        note_ends_with: &'static str,
    }

    fn write_settings(dir: &Path, text: &str) {
        fs::write(dir.join("settings.json"), text).expect("write the fixture settings file");
    }

    fn save_works(dir: &Path, request: SaveRequest) {
        save(dir, &request).expect("the setup save works");
    }

    const LOAD_ROWS: [LoadRow; 8] = [
        LoadRow {
            name: "a saved off",
            prepare: |dir| {
                save_works(
                    dir,
                    SaveRequest {
                        mode: Some(UpdateMode::Off),
                        remembered: Remembered::default(),
                    },
                )
            },
            mode: UpdateMode::Off,
            notified_version: None,
            failed_version: None,
            has_note: false,
            note_starts_with: "",
            note_ends_with: "",
        },
        LoadRow {
            name: "no file",
            prepare: |_| {},
            mode: UpdateMode::Notify,
            notified_version: None,
            failed_version: None,
            has_note: true,
            note_starts_with: FIRST_RUN_NOTE,
            note_ends_with: FIRST_RUN_NOTE,
        },
        LoadRow {
            name: "a first-run bounds save, so only notified_version",
            prepare: |dir| {
                save_works(
                    dir,
                    SaveRequest {
                        mode: None,
                        remembered: Remembered {
                            told: Some(Version::new(0, 4, 0)),
                            failed: None,
                        },
                    },
                )
            },
            mode: UpdateMode::Notify,
            notified_version: Some("0.4.0"),
            failed_version: None,
            has_note: true,
            note_starts_with: FIRST_RUN_NOTE,
            note_ends_with: FIRST_RUN_NOTE,
        },
        LoadRow {
            name: "a file that is not JSON",
            prepare: |dir| write_settings(dir, "not json"),
            mode: UpdateMode::Notify,
            notified_version: None,
            failed_version: None,
            has_note: true,
            note_starts_with: ERROR_NOTE_START,
            note_ends_with: ERROR_NOTE_END,
        },
        LoadRow {
            name: "an update_mode of weekly",
            prepare: |dir| {
                write_settings(
                    dir,
                    r#"{"update_mode": "weekly", "notified_version": "0.4.0", "failed_version": "0.3.0"}"#,
                )
            },
            mode: UpdateMode::Notify,
            notified_version: Some("0.4.0"),
            failed_version: Some("0.3.0"),
            has_note: true,
            note_starts_with: ERROR_NOTE_START,
            note_ends_with: ERROR_NOTE_END,
        },
        LoadRow {
            name: "an unknown key",
            prepare: |dir| write_settings(dir, r#"{"update_mode": "install", "window": "left"}"#),
            mode: UpdateMode::Install,
            notified_version: None,
            failed_version: None,
            has_note: false,
            note_starts_with: "",
            note_ends_with: "",
        },
        LoadRow {
            name: "saved notified_version and failed_version",
            prepare: |dir| {
                save_works(
                    dir,
                    SaveRequest {
                        mode: Some(UpdateMode::Notify),
                        remembered: Remembered {
                            told: Some(Version::new(0, 5, 0)),
                            failed: Some(Version::new(0, 4, 0)),
                        },
                    },
                )
            },
            mode: UpdateMode::Notify,
            notified_version: Some("0.5.0"),
            failed_version: Some("0.4.0"),
            has_note: false,
            note_starts_with: "",
            note_ends_with: "",
        },
        LoadRow {
            name: "version keys that are not semver",
            prepare: |dir| {
                write_settings(
                    dir,
                    r#"{"update_mode": "notify", "notified_version": "soon", "failed_version": "v0.4"}"#,
                )
            },
            mode: UpdateMode::Notify,
            notified_version: None,
            failed_version: None,
            has_note: false,
            note_starts_with: "",
            note_ends_with: "",
        },
    ];

    #[test]
    fn the_next_launch_loads_the_saved_mode_or_notify_with_a_note() {
        for row in LOAD_ROWS {
            let dir = tempfile::tempdir().expect("make a temp dir");
            (row.prepare)(dir.path());
            let (settings, note) = load(dir.path());
            assert_eq!(
                settings.update_mode.unwrap_or_default(),
                row.mode,
                "{}: the mode the next launch uses",
                row.name
            );
            assert_eq!(
                settings.notified_version.map(|v| v.to_string()).as_deref(),
                row.notified_version,
                "{}: notified_version",
                row.name
            );
            assert_eq!(
                settings.failed_version.map(|v| v.to_string()).as_deref(),
                row.failed_version,
                "{}: failed_version",
                row.name
            );
            assert_eq!(note.is_some(), row.has_note, "{}: {note:?}", row.name);
            let note = note.unwrap_or_default();
            assert!(
                note.starts_with(row.note_starts_with) && note.ends_with(row.note_ends_with),
                "{}: note {note:?}",
                row.name
            );
        }

        let request = SaveRequest {
            mode: Some(UpdateMode::Off),
            remembered: Remembered::default(),
        };

        let root = tempfile::tempdir().expect("make a temp dir");
        fs::write(root.path().join("blocker"), "a file, not a directory").expect("write");
        let under_a_file = root.path().join("blocker").join("config");
        assert!(
            save(&under_a_file, &request).is_err(),
            "a save whose directory cannot be made must report its error"
        );

        let dir = tempfile::tempdir().expect("make a temp dir");
        fs::create_dir(dir.path().join("settings.json")).expect("make settings.json a directory");
        assert!(
            save(dir.path(), &request).is_err(),
            "a save whose rename fails must report its error"
        );
        let temporary = dir
            .path()
            .join(format!("settings.json.{}.tmp", std::process::id()));
        assert!(
            !temporary.exists(),
            "a failed save must remove {}",
            temporary.display()
        );
    }

    fn settings(
        mode: Option<UpdateMode>,
        notified: Option<Version>,
        failed: Option<Version>,
    ) -> Settings {
        Settings {
            update_mode: mode,
            notified_version: notified,
            failed_version: failed,
        }
    }

    fn request(
        mode: Option<UpdateMode>,
        told: Option<Version>,
        failed: Option<Version>,
    ) -> SaveRequest {
        SaveRequest {
            mode,
            remembered: Remembered { told, failed },
        }
    }

    #[test]
    fn a_bounds_save_keeps_a_later_choice_from_another_process() {
        let rows = [
            (
                "a request with no mode keeps the file's off and raises notified_version",
                settings(Some(UpdateMode::Off), None, None),
                request(None, Some(Version::new(0, 4, 0)), None),
                settings(Some(UpdateMode::Off), Some(Version::new(0, 4, 0)), None),
            ),
            (
                "a request with a mode writes that mode",
                settings(Some(UpdateMode::Off), None, None),
                request(Some(UpdateMode::Install), None, None),
                settings(Some(UpdateMode::Install), None, None),
            ),
            (
                "the higher notified_version wins in semver order",
                settings(None, Some(Version::new(0, 9, 0)), None),
                request(None, Some(Version::new(0, 10, 0)), None),
                settings(None, Some(Version::new(0, 10, 0)), None),
            ),
            (
                "a lower request bound keeps the file's higher bound",
                settings(None, Some(Version::new(0, 5, 0)), None),
                request(None, Some(Version::new(0, 4, 0)), None),
                settings(None, Some(Version::new(0, 5, 0)), None),
            ),
            (
                "the higher failed_version wins in semver order",
                settings(None, None, Some(Version::new(0, 9, 0))),
                request(None, None, Some(Version::new(0, 10, 0))),
                settings(None, None, Some(Version::new(0, 10, 0))),
            ),
            (
                "neither side holds a mode, so the result has none",
                settings(None, Some(Version::new(0, 4, 0)), None),
                request(
                    None,
                    Some(Version::new(0, 4, 0)),
                    Some(Version::new(0, 3, 0)),
                ),
                settings(
                    None,
                    Some(Version::new(0, 4, 0)),
                    Some(Version::new(0, 3, 0)),
                ),
            ),
        ];
        for (name, on_disk, request, expected) in rows {
            assert_eq!(merge(on_disk, &request), expected, "{name}");
        }
    }
}
