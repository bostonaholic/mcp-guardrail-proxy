//! Follows an append-only file by polling, which behaves the same on every platform.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

/// How far reading has got, mirrored from `specs/AuditLogTail.tla`. It polls by size, so it
/// finds a rotation only by seeing the file gone or shorter than the offset.
#[derive(Clone, Debug, Default)]
pub struct TailCursor {
    offset: u64,
    partial: Vec<u8>,
}

impl TailCursor {
    /// A poll found no file, so the bytes the cursor counted are gone.
    pub fn on_missing(&mut self) {
        self.restart();
    }

    /// A poll opened a file of `len` bytes. Returns where to read from.
    pub fn on_opened(&mut self, len: u64) -> u64 {
        if len < self.offset {
            self.restart();
        }
        self.offset
    }

    /// A poll read `bytes` from the returned position. Returns the lines they completed.
    pub fn on_read(&mut self, bytes: &[u8]) -> Vec<String> {
        self.offset += bytes.len() as u64;
        self.partial.extend_from_slice(bytes);
        self.take_complete_lines()
    }

    fn restart(&mut self) {
        self.offset = 0;
        self.partial.clear();
    }

    fn take_complete_lines(&mut self) -> Vec<String> {
        let Some(last_newline) = self.partial.iter().rposition(|byte| *byte == b'\n') else {
            return Vec::new();
        };
        let rest = self.partial.split_off(last_newline + 1);
        let complete = std::mem::replace(&mut self.partial, rest);
        String::from_utf8_lossy(&complete)
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// Reads whole lines appended to `path` since the last call.
pub struct Tail {
    path: PathBuf,
    cursor: TailCursor,
}

impl Tail {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cursor: TailCursor::default(),
        }
    }

    /// The new complete lines. A missing file has none yet, since the proxy creates it. A file
    /// that disappeared or shrank was rotated or truncated, so reading restarts from its
    /// beginning.
    pub fn read_new_lines(&mut self) -> io::Result<Vec<String>> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.cursor.on_missing();
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        let start = self.cursor.on_opened(file.metadata()?.len());
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(self.cursor.on_read(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::spec_graph::{SpecGraph, Step, tla_bool};

    fn append(path: &std::path::Path, text: &str) {
        let mut file = File::options()
            .append(true)
            .create(true)
            .open(path)
            .expect("open the log");
        file.write_all(text.as_bytes()).expect("append to the log");
    }

    #[test]
    fn a_missing_file_has_no_lines_until_it_appears() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let path = dir.path().join("audit.jsonl");
        let mut tail = Tail::new(path.clone());
        assert!(tail.read_new_lines().expect("read").is_empty());
        append(&path, "one\n");
        assert_eq!(tail.read_new_lines().expect("read"), ["one"]);
    }

    #[test]
    fn returns_each_line_once_and_holds_a_partial_line_back() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let path = dir.path().join("audit.jsonl");
        let mut tail = Tail::new(path.clone());
        append(&path, "one\ntw");
        assert_eq!(tail.read_new_lines().expect("read"), ["one"]);
        assert!(tail.read_new_lines().expect("read").is_empty());
        append(&path, "o\nthree\n");
        assert_eq!(tail.read_new_lines().expect("read"), ["two", "three"]);
    }

    #[test]
    fn restarts_when_the_file_shrinks() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let path = dir.path().join("audit.jsonl");
        let mut tail = Tail::new(path.clone());
        append(&path, "a long first line\n");
        tail.read_new_lines().expect("read");
        std::fs::write(&path, "new\n").expect("truncate the log");
        assert_eq!(tail.read_new_lines().expect("read"), ["new"]);
    }

    #[test]
    fn restarts_when_the_file_was_gone_at_a_poll() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let path = dir.path().join("audit.jsonl");
        let mut tail = Tail::new(path.clone());
        append(&path, "old\n");
        assert_eq!(tail.read_new_lines().expect("read"), ["old"]);
        std::fs::remove_file(&path).expect("remove the log");
        assert!(tail.read_new_lines().expect("read").is_empty());
        append(&path, "a longer first line\n");
        assert_eq!(
            tail.read_new_lines().expect("read"),
            ["a longer first line"]
        );
    }

    /// The bytes after `start` in the spec's file, which ends in a newline unless `midLine`.
    fn file_bytes(step: &Step<'_>, start: u64) -> Vec<u8> {
        let len: u64 = step.to["fileLen"].parse().expect("fileLen is a number");
        let mut bytes = vec![b'x'; (len - start) as usize];
        if step.to["midLine"] == "FALSE" {
            if let Some(last) = bytes.last_mut() {
                *last = b'\n';
            }
        }
        bytes
    }

    fn apply(cursor: &mut TailCursor, step: &Step<'_>) {
        let len = || step.to["fileLen"].parse().expect("fileLen is a number");
        match step.action {
            "Create" | "AppendContent" | "AppendNewline" | "Truncate" | "Remove" => {}
            "PollMissing" => cursor.on_missing(),
            "PollRead" => {
                let start = cursor.on_opened(len());
                cursor.on_read(&file_bytes(step, start));
            }
            "PollReadFails" => {
                cursor.on_opened(len());
            }
            other => panic!("unknown action {other}"),
        }
    }

    #[test]
    fn cursor_matches_every_edge_of_the_spec() {
        let graph = SpecGraph::parse(include_str!("../../specs/graphs/AuditLogTail.graph"));
        let walked = graph.walk(
            TailCursor::default(),
            |cursor| {
                vec![
                    ("offset", cursor.offset.to_string()),
                    ("held", tla_bool(!cursor.partial.is_empty())),
                ]
            },
            apply,
        );
        assert!(walked > 0);
    }
}
