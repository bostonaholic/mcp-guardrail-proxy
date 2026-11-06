//! Follows an append-only file by polling, which behaves the same on every platform.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

/// Reads whole lines appended to `path` since the last call.
pub struct Tail {
    path: PathBuf,
    offset: u64,
    partial: Vec<u8>,
}

impl Tail {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            partial: Vec::new(),
        }
    }

    /// The new complete lines. A missing file has none yet, since the proxy creates it. A file
    /// that shrank was rotated or truncated, so reading restarts from its beginning.
    pub fn read_new_lines(&mut self) -> io::Result<Vec<String>> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        if file.metadata()?.len() < self.offset {
            self.offset = 0;
            self.partial.clear();
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let mut bytes = Vec::new();
        self.offset += file.read_to_end(&mut bytes)? as u64;
        self.partial.extend_from_slice(&bytes);
        Ok(self.take_complete_lines())
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

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
}
