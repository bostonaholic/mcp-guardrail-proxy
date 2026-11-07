//! The end of a proxy session, mirrored from `specs/SessionLifecycle.tla`.

/// How far the session has come. It only moves forward, except that any phase can skip ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    /// Host input, the child, the relays, and the writer all run.
    Relaying,
    /// Child stdin is closed, and the child has a grace period to exit.
    ExitGrace,
    /// The child was killed, and the session waits to reap it.
    Killing,
    /// The child is gone, and the relays get a bounded time to finish.
    Draining,
    /// Only the writer is left, emptying the queue.
    Flushing,
    /// Nothing is left. [`SessionLifecycle::outcome`] holds the result.
    Finished,
}

/// Why host input stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputEnd {
    /// Host input is still running.
    None,
    /// The host closed its output.
    HostEof,
    /// Reading from the host failed.
    ReadFailed,
    /// A write to child stdin failed.
    ForwardFailed,
    /// Writing to the host failed.
    HostOutputClosed,
    /// The child exited while input was running.
    ChildExitedFirst,
}

/// The child output relays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayState {
    /// They still read child output.
    Running,
    /// They reached EOF on both pipes.
    Done,
    /// The drain time ran out while something still held a pipe open.
    Abandoned,
}

/// The task that writes queued lines to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterState {
    /// It still writes.
    Open,
    /// The queue closed, and every line in it was written.
    Drained,
    /// A write to the host failed.
    Failed,
}

/// What ended the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    /// The session ended without a fault in the proxy's pipes.
    Clean,
    /// A forward write failed, and the child's exit code explains it.
    ChildRefusedInput,
    /// Reading from the host failed.
    HostInputFailed,
    /// Writing to the host failed.
    HostOutputFailed,
    /// Waiting on or killing the child failed.
    ChildWaitFailed,
}

/// What the driver reports to the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// Host input reached EOF.
    HostEof,
    /// Reading host input failed.
    HostReadFailed,
    /// A write to child stdin failed.
    ForwardFailed,
    /// The child exited.
    ChildExited,
    /// Waiting on or killing the child failed.
    ChildWaitFailed,
    /// The current phase's timer ran out.
    TimerElapsed,
    /// The relays finished.
    RelaysFinished,
    /// The writer emptied a closed queue.
    WriterDrained,
    /// The writer failed.
    WriterFailed,
}

/// What the driver must do after an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEffect {
    /// Nothing.
    None,
    /// Drop the host input task, which closes child stdin.
    StopInput,
    /// Kill the child.
    KillChild,
    /// Drop the host input task, then kill the child.
    StopInputAndKill,
    /// Drop the relays and report the pipe that is still open.
    AbandonRelays,
}

/// Decides how a session ends, whatever order its tasks stop in.
#[derive(Clone, Copy, Debug)]
pub struct SessionLifecycle {
    phase: SessionPhase,
    input_end: InputEnd,
    relays: RelayState,
    writer: WriterState,
    child_lost: bool,
}

impl Default for SessionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionLifecycle {
    /// A session with everything running.
    pub fn new() -> Self {
        Self {
            phase: SessionPhase::Relaying,
            input_end: InputEnd::None,
            relays: RelayState::Running,
            writer: WriterState::Open,
            child_lost: false,
        }
    }

    /// The current phase.
    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    /// Why host input stopped.
    pub fn input_end(&self) -> InputEnd {
        self.input_end
    }

    /// The relays' state.
    pub fn relays(&self) -> RelayState {
        self.relays
    }

    /// The writer's state.
    pub fn writer(&self) -> WriterState {
        self.writer
    }

    /// Whether waiting on the child failed.
    pub fn child_lost(&self) -> bool {
        self.child_lost
    }

    /// Whether the driver should watch for the child's exit.
    pub fn child_running(&self) -> bool {
        matches!(
            self.phase,
            SessionPhase::Relaying | SessionPhase::ExitGrace | SessionPhase::Killing
        )
    }

    /// The result of a finished session, in order of blame: host output, then the child wait,
    /// then host input. `None` until the session finishes.
    pub fn outcome(&self) -> Option<SessionOutcome> {
        if self.phase != SessionPhase::Finished {
            return None;
        }
        Some(if self.writer == WriterState::Failed {
            SessionOutcome::HostOutputFailed
        } else if self.child_lost {
            SessionOutcome::ChildWaitFailed
        } else if self.input_end == InputEnd::ForwardFailed {
            SessionOutcome::ChildRefusedInput
        } else if self.input_end == InputEnd::ReadFailed {
            SessionOutcome::HostInputFailed
        } else {
            SessionOutcome::Clean
        })
    }

    /// Applies `event` and says what the driver must do. An event the phase cannot see is
    /// ignored: the driver polls a task only while the machine expects it.
    pub fn on(&mut self, event: SessionEvent) -> SessionEffect {
        use SessionEvent as Event;
        use SessionPhase as Phase;
        match (self.phase, event) {
            (Phase::Relaying, Event::HostEof) => self.enter_exit_grace(InputEnd::HostEof),
            (Phase::Relaying, Event::HostReadFailed) => self.enter_exit_grace(InputEnd::ReadFailed),
            (Phase::Relaying, Event::ForwardFailed) => {
                self.enter_exit_grace(InputEnd::ForwardFailed)
            }
            (Phase::Relaying, Event::ChildExited | Event::ChildWaitFailed) => {
                self.input_end = InputEnd::ChildExitedFirst;
                self.child_gone(event);
                SessionEffect::StopInput
            }
            (Phase::ExitGrace | Phase::Killing, Event::ChildExited | Event::ChildWaitFailed) => {
                self.child_gone(event);
                SessionEffect::None
            }
            (Phase::ExitGrace, Event::TimerElapsed) => {
                self.phase = Phase::Killing;
                SessionEffect::KillChild
            }
            (Phase::Draining, Event::TimerElapsed) => {
                self.relays = RelayState::Abandoned;
                self.phase = self.after_relays();
                SessionEffect::AbandonRelays
            }
            (Phase::Relaying, Event::WriterFailed) => {
                self.writer = WriterState::Failed;
                self.input_end = InputEnd::HostOutputClosed;
                self.phase = Phase::Killing;
                SessionEffect::StopInputAndKill
            }
            (phase, Event::WriterFailed) if phase != Phase::Finished => {
                self.writer = WriterState::Failed;
                self.finish_if_flushing();
                SessionEffect::None
            }
            (phase, Event::WriterDrained) if phase != Phase::Finished => {
                debug_assert!(
                    phase != Phase::Relaying && self.relays != RelayState::Running,
                    "the queue closed while a sender was alive"
                );
                self.writer = WriterState::Drained;
                self.finish_if_flushing();
                SessionEffect::None
            }
            (phase, Event::RelaysFinished) if phase != Phase::Finished => {
                self.relays = RelayState::Done;
                if phase == Phase::Draining {
                    self.phase = self.after_relays();
                }
                SessionEffect::None
            }
            _ => SessionEffect::None,
        }
    }

    fn enter_exit_grace(&mut self, end: InputEnd) -> SessionEffect {
        self.input_end = end;
        self.phase = SessionPhase::ExitGrace;
        SessionEffect::None
    }

    fn child_gone(&mut self, event: SessionEvent) {
        self.child_lost = event == SessionEvent::ChildWaitFailed;
        self.phase = if self.relays == RelayState::Running {
            SessionPhase::Draining
        } else {
            self.after_relays()
        };
    }

    fn after_relays(&self) -> SessionPhase {
        if self.writer == WriterState::Open {
            SessionPhase::Flushing
        } else {
            SessionPhase::Finished
        }
    }

    fn finish_if_flushing(&mut self) {
        if self.phase == SessionPhase::Flushing {
            self.phase = SessionPhase::Finished;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::spec_graph::{SpecGraph, Step, tla_bool};

    /// The machine, and what its effects did to the world.
    #[derive(Clone)]
    struct Walked {
        session: SessionLifecycle,
        kill_sent: bool,
        input_stopped: bool,
    }

    fn event_of(action: &str) -> Option<SessionEvent> {
        Some(match action {
            "HostEof" => SessionEvent::HostEof,
            "HostReadFails" => SessionEvent::HostReadFailed,
            "ForwardFails" => SessionEvent::ForwardFailed,
            "ChildExits" | "ChildDiesOnKill" => SessionEvent::ChildExited,
            "ChildWaitFails" => SessionEvent::ChildWaitFailed,
            "GraceElapses" | "DrainElapses" => SessionEvent::TimerElapsed,
            "RelaysFinish" => SessionEvent::RelaysFinished,
            "WriterFails" => SessionEvent::WriterFailed,
            "WriterDrains" => SessionEvent::WriterDrained,
            // The machine cannot see a write stall in the host input task.
            "ForwardBlocks" | "ForwardResumes" => return None,
            other => panic!("unknown action {other}"),
        })
    }

    fn project(walked: &Walked) -> Vec<(&'static str, String)> {
        let session = &walked.session;
        let outcome = session
            .outcome()
            .map_or("None".to_string(), |outcome| format!("{outcome:?}"));
        let input = if walked.input_stopped {
            "Stopped"
        } else {
            "Running"
        };
        vec![
            ("phase", format!("{:?}", session.phase())),
            ("inputEnd", format!("{:?}", session.input_end())),
            ("input", input.to_string()),
            ("relays", format!("{:?}", session.relays())),
            ("writer", format!("{:?}", session.writer())),
            ("childLost", tla_bool(session.child_lost())),
            ("outcome", outcome),
            ("killSent", tla_bool(walked.kill_sent)),
        ]
    }

    fn apply(walked: &mut Walked, step: &Step<'_>) {
        let Some(event) = event_of(step.action) else {
            return;
        };
        let input_ended = matches!(
            event,
            SessionEvent::HostEof | SessionEvent::HostReadFailed | SessionEvent::ForwardFailed
        );
        walked.input_stopped |= input_ended;
        match walked.session.on(event) {
            SessionEffect::None | SessionEffect::AbandonRelays => {}
            SessionEffect::StopInput => walked.input_stopped = true,
            SessionEffect::KillChild => walked.kill_sent = true,
            SessionEffect::StopInputAndKill => {
                walked.input_stopped = true;
                walked.kill_sent = true;
            }
        }
    }

    fn walk_start() -> Walked {
        Walked {
            session: SessionLifecycle::new(),
            kill_sent: false,
            input_stopped: false,
        }
    }

    #[test]
    fn lifecycle_matches_every_edge_of_the_spec() {
        let graph = SpecGraph::parse(include_str!("../../specs/graphs/SessionLifecycle.graph"));
        assert!(graph.walk(walk_start(), project, apply) > 0);
    }

    #[test]
    fn a_finished_session_ignores_late_events() {
        let mut session = SessionLifecycle::new();
        for event in [
            SessionEvent::HostEof,
            SessionEvent::RelaysFinished,
            SessionEvent::ChildExited,
            SessionEvent::WriterDrained,
        ] {
            session.on(event);
        }
        assert_eq!(session.outcome(), Some(SessionOutcome::Clean));
        for event in [
            SessionEvent::WriterFailed,
            SessionEvent::ChildWaitFailed,
            SessionEvent::TimerElapsed,
        ] {
            assert_eq!(session.on(event), SessionEffect::None);
        }
        assert_eq!(session.outcome(), Some(SessionOutcome::Clean));
    }
}
