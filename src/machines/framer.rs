//! The capped line reader, mirrored from `specs/LineFramer.tla`.

/// Where the framer stands in the current line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramerPhase {
    /// No byte of a new line has arrived. The last line's bytes stay readable until one does.
    AtLineStart,
    /// The line fits so far, and its bytes are held.
    InLine,
    /// The line passed the cap. Its bytes are thrown away through the next newline.
    Discarding,
}

/// How a line ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineEnd {
    /// The whole line is in [`LineFramer::line`]. A final line may lack its newline.
    Complete,
    /// The line was longer than the cap, and its bytes are gone.
    Oversize,
    /// The stream ended with no further bytes.
    Eof,
}

/// Splits a byte stream into lines, never holding more than `cap` bytes of one.
#[derive(Clone, Debug)]
pub struct LineFramer {
    cap: usize,
    phase: FramerPhase,
    line: Vec<u8>,
}

impl LineFramer {
    /// A framer at the start of a stream.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            phase: FramerPhase::AtLineStart,
            line: Vec::new(),
        }
    }

    /// The current phase.
    pub fn phase(&self) -> FramerPhase {
        self.phase
    }

    /// The bytes of the current line, or of the last one until the next `push`.
    pub fn line(&self) -> &[u8] {
        &self.line
    }

    /// Takes the bytes that `line` would return.
    pub fn take_line(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.line)
    }

    /// Reads `chunk` up to and including its first newline. Returns how many bytes that was,
    /// and how the line ended when the newline was there.
    pub fn push(&mut self, chunk: &[u8]) -> (usize, Option<LineEnd>) {
        if self.phase == FramerPhase::AtLineStart {
            self.line.clear();
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let content = &chunk[..newline.unwrap_or(chunk.len())];
        self.take_content(content);
        let consumed = content.len() + usize::from(newline.is_some());
        (consumed, newline.map(|_| self.end_line()))
    }

    /// The stream ended: reports the line in progress, or `Eof` when there is none.
    pub fn finish(&mut self) -> LineEnd {
        if self.phase == FramerPhase::AtLineStart {
            self.line.clear();
            return LineEnd::Eof;
        }
        self.end_line()
    }

    fn take_content(&mut self, content: &[u8]) {
        if content.is_empty() || self.phase == FramerPhase::Discarding {
            return;
        }
        if self.line.len() + content.len() > self.cap {
            self.phase = FramerPhase::Discarding;
            self.line.clear();
        } else {
            self.phase = FramerPhase::InLine;
            self.line.extend_from_slice(content);
        }
    }

    fn end_line(&mut self) -> LineEnd {
        let end = if self.phase == FramerPhase::Discarding {
            LineEnd::Oversize
        } else {
            LineEnd::Complete
        };
        self.phase = FramerPhase::AtLineStart;
        end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::spec_graph::SpecGraph;

    const SPEC_CAP: usize = 2;

    /// The framer and what its last step returned.
    #[derive(Clone)]
    struct Walked {
        framer: LineFramer,
        emitted: &'static str,
    }

    fn emitted_name(end: Option<LineEnd>) -> &'static str {
        match end {
            None => "None",
            Some(LineEnd::Complete) => "Complete",
            Some(LineEnd::Oversize) => "Oversize",
            Some(LineEnd::Eof) => "Eof",
        }
    }

    #[test]
    fn framer_matches_every_edge_of_the_spec() {
        let walked = SpecGraph::parse(include_str!("../../specs/graphs/LineFramer.graph")).walk(
            Walked {
                framer: LineFramer::new(SPEC_CAP),
                emitted: "None",
            },
            |walked| {
                vec![
                    ("phase", format!("{:?}", walked.framer.phase())),
                    ("held", walked.framer.line().len().to_string()),
                    ("emitted", walked.emitted.to_string()),
                ]
            },
            |walked, step| {
                let end = match step.action {
                    "Content" => walked.framer.push(b"x").1,
                    "Newline" => walked.framer.push(b"\n").1,
                    "End" => Some(walked.framer.finish()),
                    other => panic!("unknown action {other}"),
                };
                walked.emitted = emitted_name(end);
            },
        );
        assert!(walked > 0);
    }

    /// Feeds `stream` in chunks of `size` and lists each line as text.
    fn lines_in_chunks(stream: &[u8], size: usize, cap: usize) -> Vec<String> {
        let mut framer = LineFramer::new(cap);
        let mut lines = Vec::new();
        let mut record = |end: LineEnd, framer: &LineFramer| match end {
            LineEnd::Complete => lines.push(String::from_utf8_lossy(framer.line()).into_owned()),
            LineEnd::Oversize => lines.push("<oversize>".to_string()),
            LineEnd::Eof => {}
        };
        for chunk in stream.chunks(size) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let (consumed, end) = framer.push(rest);
                rest = &rest[consumed..];
                if let Some(end) = end {
                    record(end, &framer);
                }
            }
        }
        let end = framer.finish();
        record(end, &framer);
        lines
    }

    /// The spec feeds one byte at a time; the proxy feeds whole buffers.
    #[test]
    fn chunk_size_never_changes_the_lines() {
        let stream = b"ab\nabc\n\nabcdefg\nz";
        let by_byte = lines_in_chunks(stream, 1, 3);
        assert_eq!(by_byte, ["ab", "abc", "", "<oversize>", "z"]);
        for size in 2..=stream.len() {
            assert_eq!(
                lines_in_chunks(stream, size, 3),
                by_byte,
                "chunk size {size}"
            );
        }
    }
}
