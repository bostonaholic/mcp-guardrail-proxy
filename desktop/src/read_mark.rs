//! The read mark: which of one log's blocked calls the person has marked read, and the file
//! that keeps it between launches. The file is its own, so saving it never replaces the
//! settings files.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::settings::write_atomically;

/// A set of one log's blocked calls. A call is named by its place among the log's blocked
/// calls, counted from 1, because audit lines have no id. Pure: no I/O.
///
/// Two marks that name the same calls are equal: `new` always builds the same fields for them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadMark {
    /// The first `through` blocked calls.
    through: u64,
    /// The calls after the first one left out. Each is above `through + 1`.
    beyond: BTreeSet<u64>,
}

impl ReadMark {
    /// The first `through` blocked calls and the calls in `beyond`. A call numbered 0 names
    /// nothing and is dropped.
    pub fn new(through: u64, beyond: impl IntoIterator<Item = u64>) -> Self {
        let mut through = through;
        let mut beyond: BTreeSet<u64> = beyond.into_iter().filter(|call| *call > through).collect();
        while beyond.remove(&(through + 1)) {
            through += 1;
        }
        Self { through, beyond }
    }

    /// The first `count` blocked calls: what a "mark all" names when the screen showed `count`.
    pub fn through(count: u64) -> Self {
        Self::new(count, [])
    }

    /// The calls `calls` names: the rows a person selected.
    pub fn of(calls: impl IntoIterator<Item = u64>) -> Self {
        Self::new(0, calls)
    }

    pub fn contains(&self, call: u64) -> bool {
        (1..=self.through).contains(&call) || self.beyond.contains(&call)
    }

    /// How many calls the mark names.
    pub fn count(&self) -> u64 {
        self.through + self.beyond.len() as u64
    }

    /// Whether every call the mark names is one of a log's first `blocked` blocked calls.
    pub fn fits(&self, blocked: u64) -> bool {
        self.beyond.last().copied().unwrap_or(self.through) <= blocked
    }

    /// The calls either mark names.
    pub fn union(&self, other: &Self) -> Self {
        Self::new(
            self.through.max(other.through),
            self.beyond.union(&other.beyond).copied(),
        )
    }
}

/// The contents of `read-mark.json`. The mark names calls by their place in the named log, so
/// it means nothing for another log.
#[derive(Serialize, Deserialize)]
struct SavedMark {
    audit_log_path: String,
    /// The first `read_blocked` blocked calls are read.
    read_blocked: u64,
    /// The read calls after the first unread one.
    #[serde(default)]
    read_after: Vec<u64>,
}

/// The mark saved for `log_path`, or an empty mark when the file is missing, cannot be read,
/// or holds another log's mark. An empty mark leaves every blocked call unread, so a lost
/// mark never hides one.
pub fn load(file: &Path, log_path: &str) -> ReadMark {
    let text = match fs::read_to_string(file) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ReadMark::default(),
        Err(error) => {
            eprintln!(
                "mcp-guardrail-desktop: cannot read {}: {error}",
                file.display()
            );
            return ReadMark::default();
        }
    };
    match serde_json::from_str::<SavedMark>(&text) {
        Ok(saved) if saved.audit_log_path == log_path => {
            ReadMark::new(saved.read_blocked, saved.read_after)
        }
        Ok(_) => ReadMark::default(),
        Err(error) => {
            eprintln!(
                "mcp-guardrail-desktop: cannot read {}: {error}",
                file.display()
            );
            ReadMark::default()
        }
    }
}

pub fn save(file: &Path, log_path: &str, mark: &ReadMark) -> io::Result<()> {
    let saved = SavedMark {
        audit_log_path: log_path.to_string(),
        read_blocked: mark.through,
        read_after: mark.beyond.iter().copied().collect(),
    };
    write_atomically(file, &serde_json::to_vec_pretty(&saved)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calls(mark: &ReadMark, up_to: u64) -> Vec<u64> {
        (0..=up_to).filter(|call| mark.contains(*call)).collect()
    }

    #[test]
    fn a_mark_names_the_first_calls_and_the_selected_ones() {
        let mark = ReadMark::new(2, [5, 7]);
        assert_eq!(calls(&mark, 9), [1, 2, 5, 7]);
        assert_eq!(mark.count(), 4);
        assert!(mark.fits(7), "the log holds call 7");
        assert!(!mark.fits(6), "the log has no call 7");
        assert_eq!(calls(&ReadMark::default(), 9), [0; 0]);
        assert!(ReadMark::default().fits(0));
    }

    #[test]
    fn marks_that_name_the_same_calls_are_equal() {
        assert_eq!(ReadMark::of([2, 1, 3]), ReadMark::through(3));
        assert_eq!(ReadMark::new(1, [3, 2, 1, 0]), ReadMark::through(3));
        assert_eq!(ReadMark::of([0]), ReadMark::default());
        assert_ne!(ReadMark::of([2]), ReadMark::through(2));
    }

    #[test]
    fn a_union_names_the_calls_of_both_marks() {
        let selected = ReadMark::of([2, 4]);
        assert_eq!(calls(&selected.union(&ReadMark::of([1])), 9), [1, 2, 4]);
        assert_eq!(
            selected.union(&ReadMark::through(3)),
            ReadMark::through(4),
            "marking all through 3 joins the selected call 4"
        );
        assert_eq!(selected.union(&selected), selected);
    }

    #[test]
    fn a_saved_mark_loads_for_its_own_log_only() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let file = dir.path().join("state").join("read-mark.json");
        let none = ReadMark::default();
        assert_eq!(load(&file, "/logs/a.jsonl"), none, "no file yet");
        let mark = ReadMark::new(4, [6, 9]);
        save(&file, "/logs/a.jsonl", &mark).expect("save the mark");
        assert_eq!(load(&file, "/logs/a.jsonl"), mark);
        assert_eq!(
            load(&file, "/logs/b.jsonl"),
            none,
            "another log starts unread"
        );
        save(&file, "/logs/b.jsonl", &ReadMark::through(1)).expect("save the mark");
        assert_eq!(load(&file, "/logs/b.jsonl"), ReadMark::through(1));
        assert_eq!(load(&file, "/logs/a.jsonl"), none, "one mark, for one log");
    }

    #[test]
    fn a_file_with_only_a_count_loads_as_the_first_calls() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let file = dir.path().join("read-mark.json");
        fs::write(
            &file,
            r#"{"audit_log_path":"/logs/a.jsonl","read_blocked":3}"#,
        )
        .expect("write the file");
        assert_eq!(load(&file, "/logs/a.jsonl"), ReadMark::through(3));
    }

    #[test]
    fn a_file_the_app_cannot_parse_leaves_every_call_unread() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let file = dir.path().join("read-mark.json");
        fs::write(&file, "{ not json").expect("write the file");
        assert_eq!(load(&file, "/logs/a.jsonl"), ReadMark::default());
        save(&file, "/logs/a.jsonl", &ReadMark::through(2))
            .expect("the next save replaces the file");
        assert_eq!(load(&file, "/logs/a.jsonl"), ReadMark::through(2));
    }
}
