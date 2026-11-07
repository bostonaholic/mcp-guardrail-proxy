//! The app's own settings: what the window shows and what the poll thread watches.

use std::path::PathBuf;

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

    pub fn set_audit_log_path(&mut self, text: &str) {
        self.audit_log_path = PathBuf::from(text);
    }
}
