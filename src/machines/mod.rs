//! Pure state machines behind the proxy's I/O. Each one holds no I/O of its own, so its
//! transitions can be walked edge by edge against the state graph TLC produces from its spec.
//!
//! | Machine | Spec |
//! |---|---|
//! | [`call::CallPhase`] | `specs/CallJudgment.tla` |
//! | [`framer::LineFramer`] | `specs/LineFramer.tla` |
//! | [`session::SessionLifecycle`] | `specs/SessionLifecycle.tla` |
//! | [`splitter::LineSplitter`] | `specs/LineSplitter.tla` |
//!
//! `specs/README.md` lists every machine in the repository and how each one is checked.

pub mod call;
pub mod framer;
pub mod session;
#[cfg(test)]
pub(crate) mod spec_graph;
pub mod splitter;
