//! The saved read mark: how many of one log's blocked calls the person has marked read. It
//! has its own file, so saving it never replaces the settings files.

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::settings::write_atomically;

/// The contents of `read-mark.json`. The mark counts from the first blocked call of the named
/// log, so it means nothing for another log.
#[derive(Serialize, Deserialize)]
struct SavedMark {
    audit_log_path: String,
    read_blocked: u64,
}

/// The mark saved for `log_path`, or 0 when the file is missing, cannot be read, or holds
/// another log's mark. 0 leaves every blocked call unread, so a lost mark never hides one.
pub fn load(file: &Path, log_path: &str) -> u64 {
    let text = match fs::read_to_string(file) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return 0,
        Err(error) => {
            eprintln!(
                "mcp-guardrail-desktop: cannot read {}: {error}",
                file.display()
            );
            return 0;
        }
    };
    match serde_json::from_str::<SavedMark>(&text) {
        Ok(saved) if saved.audit_log_path == log_path => saved.read_blocked,
        Ok(_) => 0,
        Err(error) => {
            eprintln!(
                "mcp-guardrail-desktop: cannot read {}: {error}",
                file.display()
            );
            0
        }
    }
}

pub fn save(file: &Path, log_path: &str, read_blocked: u64) -> io::Result<()> {
    let saved = SavedMark {
        audit_log_path: log_path.to_string(),
        read_blocked,
    };
    write_atomically(file, &serde_json::to_vec_pretty(&saved)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_mark_loads_for_its_own_log_only() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let file = dir.path().join("state").join("read-mark.json");
        assert_eq!(load(&file, "/logs/a.jsonl"), 0, "no file yet");
        save(&file, "/logs/a.jsonl", 4).expect("save the mark");
        assert_eq!(load(&file, "/logs/a.jsonl"), 4);
        assert_eq!(load(&file, "/logs/b.jsonl"), 0, "another log starts unread");
        save(&file, "/logs/b.jsonl", 1).expect("save the mark");
        assert_eq!(load(&file, "/logs/b.jsonl"), 1);
        assert_eq!(load(&file, "/logs/a.jsonl"), 0, "one mark, for one log");
    }

    #[test]
    fn a_file_the_app_cannot_parse_leaves_every_call_unread() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let file = dir.path().join("read-mark.json");
        fs::write(&file, "{ not json").expect("write the file");
        assert_eq!(load(&file, "/logs/a.jsonl"), 0);
        save(&file, "/logs/a.jsonl", 2).expect("the next save replaces the file");
        assert_eq!(load(&file, "/logs/a.jsonl"), 2);
    }
}
