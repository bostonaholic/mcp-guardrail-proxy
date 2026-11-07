//! The child stderr splitter, mirrored from `specs/LineSplitter.tla`.

/// Cuts a byte stream into lines of at most `cap` bytes. A longer line becomes several lines,
/// so a cut can fall inside a multi-byte UTF-8 character.
#[derive(Clone, Debug)]
pub struct LineSplitter {
    cap: usize,
    pending: Vec<u8>,
}

impl LineSplitter {
    /// A splitter at the start of a stream.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            pending: Vec::new(),
        }
    }

    /// The bytes waiting for the end of their line.
    pub fn pending(&self) -> &[u8] {
        &self.pending
    }

    /// Takes all of `chunk`, passing each finished line to `emit`.
    pub fn push(&mut self, chunk: &[u8], emit: &mut impl FnMut(&[u8])) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let newline = rest.iter().position(|byte| *byte == b'\n');
            let (content, after) = match newline {
                Some(at) => (&rest[..at], &rest[at + 1..]),
                None => (rest, &rest[rest.len()..]),
            };
            self.take_content(content, emit);
            if newline.is_some() {
                self.emit_pending(emit);
            }
            rest = after;
        }
    }

    /// The stream ended: passes any bytes after the last newline to `emit`.
    pub fn finish(&mut self, emit: &mut impl FnMut(&[u8])) {
        if !self.pending.is_empty() {
            self.emit_pending(emit);
        }
    }

    fn take_content(&mut self, mut content: &[u8], emit: &mut impl FnMut(&[u8])) {
        while !content.is_empty() {
            if self.pending.len() == self.cap {
                self.emit_pending(emit);
            }
            let room = self.cap - self.pending.len();
            let (part, rest) = content.split_at(room.min(content.len()));
            self.pending.extend_from_slice(part);
            content = rest;
        }
    }

    fn emit_pending(&mut self, emit: &mut impl FnMut(&[u8])) {
        emit(&self.pending);
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::spec_graph::{SpecGraph, tla_bool};

    const SPEC_CAP: usize = 2;

    /// The splitter and what its last step wrote.
    #[derive(Clone)]
    struct Walked {
        splitter: LineSplitter,
        emitted: Option<usize>,
    }

    #[test]
    fn splitter_matches_every_edge_of_the_spec() {
        let walked = SpecGraph::parse(include_str!("../../specs/graphs/LineSplitter.graph")).walk(
            Walked {
                splitter: LineSplitter::new(SPEC_CAP),
                emitted: None,
            },
            |walked| {
                vec![
                    ("pending", walked.splitter.pending().len().to_string()),
                    ("emitted", tla_bool(walked.emitted.is_some())),
                    ("emittedLen", walked.emitted.unwrap_or(0).to_string()),
                ]
            },
            |walked, step| {
                let mut emitted = None;
                let mut emit = |line: &[u8]| emitted = Some(line.len());
                match step.action {
                    "Content" => walked.splitter.push(b"x", &mut emit),
                    "Newline" => walked.splitter.push(b"\n", &mut emit),
                    "End" => walked.splitter.finish(&mut emit),
                    other => panic!("unknown action {other}"),
                }
                walked.emitted = emitted;
            },
        );
        assert!(walked > 0);
    }

    /// Feeds `stream` in chunks of `size` and lists each line as text.
    fn lines_in_chunks(stream: &[u8], size: usize, cap: usize) -> Vec<String> {
        let mut splitter = LineSplitter::new(cap);
        let mut lines = Vec::new();
        let mut emit = |line: &[u8]| lines.push(String::from_utf8_lossy(line).into_owned());
        for chunk in stream.chunks(size) {
            splitter.push(chunk, &mut emit);
        }
        splitter.finish(&mut emit);
        lines
    }

    /// The spec feeds one byte at a time; the proxy feeds whole buffers.
    #[test]
    fn chunk_size_never_changes_the_lines() {
        let stream = b"ab\nabcdefg\n\nabc\nz";
        let by_byte = lines_in_chunks(stream, 1, 3);
        assert_eq!(by_byte, ["ab", "abc", "def", "g", "", "abc", "z"]);
        for size in 2..=stream.len() {
            assert_eq!(
                lines_in_chunks(stream, size, 3),
                by_byte,
                "chunk size {size}"
            );
        }
    }
}
