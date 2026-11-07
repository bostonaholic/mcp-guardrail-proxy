--------------------------- MODULE SessionLifecycle ---------------------------
(***************************************************************************)
(* The end of a proxy session, from src/machines/session.rs and its driver *)
(* run_session in src/proxy.rs. Host input, the child, the output relays,   *)
(* and the host writer run at once and end in any order. The session must   *)
(* reap the child, write or give up on every queued line, and return.       *)
(*                                                                          *)
(* phase through writer are the Rust machine. The rest is the world around  *)
(* it: forwardBlocked means a write to child stdin cannot finish, because   *)
(* the child stopped reading.                                               *)
(***************************************************************************)
VARIABLES phase,                 \* see Phases
          inputEnd,              \* why host input stopped, see InputEnds
          input,                 \* "Running" | "Stopped"
          relays,                \* "Running" | "Done" | "Abandoned"
          writer,                \* "Open" | "Drained" | "Failed"
          childLost,             \* waiting on the child failed
          outcome,               \* see Outcomes
          killSent,              \* the driver killed the child
          child,                 \* "Running" | "Exited" | "Lost"
          forwardBlocked,        \* host input is stuck in a child stdin write
          graceElapsed           \* ghost: the exit grace ran out

vars == <<phase, inputEnd, input, relays, writer, childLost, outcome, killSent,
          child, forwardBlocked, graceElapsed>>

Phases    == {"Relaying", "ExitGrace", "Killing", "Draining", "Flushing", "Finished"}
InputEnds == {"None", "HostEof", "ReadFailed", "ForwardFailed", "HostOutputClosed",
              "ChildExitedFirst"}
Outcomes  == {"None", "Clean", "ChildRefusedInput", "HostInputFailed",
              "HostOutputFailed", "ChildWaitFailed"}

TypeOK ==
  /\ phase \in Phases
  /\ inputEnd \in InputEnds
  /\ input \in {"Running", "Stopped"}
  /\ relays \in {"Running", "Done", "Abandoned"}
  /\ writer \in {"Open", "Drained", "Failed"}
  /\ childLost \in BOOLEAN
  /\ outcome \in Outcomes
  /\ killSent \in BOOLEAN
  /\ child \in {"Running", "Exited", "Lost"}
  /\ forwardBlocked \in BOOLEAN
  /\ graceElapsed \in BOOLEAN

Init ==
  /\ phase = "Relaying"
  /\ inputEnd = "None"
  /\ input = "Running"
  /\ relays = "Running"
  /\ writer = "Open"
  /\ childLost = FALSE
  /\ outcome = "None"
  /\ killSent = FALSE
  /\ child = "Running"
  /\ forwardBlocked = FALSE
  /\ graceElapsed = FALSE

\* What proxy.rs returns: host output first, then the child wait, then input.
OutcomeOf(w, lost, end) ==
  CASE w = "Failed"             -> "HostOutputFailed"
    [] lost                     -> "ChildWaitFailed"
    [] end = "ForwardFailed"    -> "ChildRefusedInput"
    [] end = "ReadFailed"       -> "HostInputFailed"
    [] OTHER                    -> "Clean"

\* Every action ends with this, so outcome is set on the step into Finished.
SettleOutcome ==
  outcome' = IF phase' = "Finished" THEN OutcomeOf(writer', childLost', inputEnd') ELSE "None"

\* Where the session goes once the child is gone and the relays are not running.
AfterRelays(w) == IF w = "Open" THEN "Flushing" ELSE "Finished"

\* Where the session goes when the child is gone.
AfterChild == IF relays = "Running" THEN "Draining" ELSE AfterRelays(writer)

\* Host input ends by itself; returning closes child stdin.
InputStops(end) ==
  /\ phase = "Relaying"
  /\ phase' = "ExitGrace"
  /\ inputEnd' = end
  /\ input' = "Stopped"
  /\ forwardBlocked' = FALSE
  /\ UNCHANGED <<relays, writer, childLost, killSent, child, graceElapsed>>
  /\ SettleOutcome

\* A blocked input is inside a write and cannot see the host.
HostEof       == ~forwardBlocked /\ InputStops("HostEof")
HostReadFails == ~forwardBlocked /\ InputStops("ReadFailed")
ForwardFails  == phase = "Relaying" /\ InputStops("ForwardFailed")

ForwardBlocks ==
  /\ phase = "Relaying"
  /\ ~forwardBlocked
  /\ forwardBlocked' = TRUE
  /\ UNCHANGED <<phase, inputEnd, input, relays, writer, childLost, outcome, killSent,
                 child, graceElapsed>>

ForwardResumes ==
  /\ phase = "Relaying"
  /\ forwardBlocked
  /\ forwardBlocked' = FALSE
  /\ UNCHANGED <<phase, inputEnd, input, relays, writer, childLost, outcome, killSent,
                 child, graceElapsed>>

\* The child goes away, by itself or because it was killed.
ChildGone(next) ==
  /\ child = "Running"
  /\ child' = next
  /\ childLost' = (next = "Lost")
  /\ inputEnd' = IF phase = "Relaying" THEN "ChildExitedFirst" ELSE inputEnd
  /\ input' = "Stopped"
  /\ forwardBlocked' = FALSE
  /\ phase' = AfterChild
  /\ UNCHANGED <<relays, writer, killSent, graceElapsed>>
  /\ SettleOutcome

ChildExits      == child = "Running" /\ ChildGone("Exited")
ChildWaitFails  == child = "Running" /\ ChildGone("Lost")
ChildDiesOnKill == killSent /\ ChildGone("Exited")

GraceElapses ==
  /\ phase = "ExitGrace"
  /\ phase' = "Killing"
  /\ killSent' = TRUE
  /\ graceElapsed' = TRUE
  /\ UNCHANGED <<inputEnd, input, relays, writer, childLost, child, forwardBlocked>>
  /\ SettleOutcome

RelaysFinish ==
  /\ relays = "Running"
  /\ relays' = "Done"
  /\ phase' = IF phase = "Draining" THEN AfterRelays(writer) ELSE phase
  /\ UNCHANGED <<inputEnd, input, writer, childLost, killSent, child, forwardBlocked,
                 graceElapsed>>
  /\ SettleOutcome

\* A descendant can hold the child's pipes open forever.
DrainElapses ==
  /\ phase = "Draining"
  /\ relays' = "Abandoned"
  /\ phase' = AfterRelays(writer)
  /\ UNCHANGED <<inputEnd, input, writer, childLost, killSent, child, forwardBlocked,
                 graceElapsed>>
  /\ SettleOutcome

\* Host output fails. While relaying, this stops input wherever it is stuck.
WriterFails ==
  /\ writer = "Open"
  /\ phase /= "Finished"
  /\ writer' = "Failed"
  /\ IF phase = "Relaying"
       THEN /\ phase' = "Killing"
            /\ inputEnd' = "HostOutputClosed"
            /\ input' = "Stopped"
            /\ forwardBlocked' = FALSE
            /\ killSent' = TRUE
       ELSE /\ phase' = IF phase = "Flushing" THEN "Finished" ELSE phase
            /\ UNCHANGED <<inputEnd, input, forwardBlocked, killSent>>
  /\ UNCHANGED <<relays, childLost, child, graceElapsed>>
  /\ SettleOutcome

\* The queue closes when its last sender goes, then the writer empties it.
WriterDrains ==
  /\ writer = "Open"
  /\ input = "Stopped"
  /\ relays /= "Running"
  /\ writer' = "Drained"
  /\ phase' = IF phase = "Flushing" THEN "Finished" ELSE phase
  /\ UNCHANGED <<inputEnd, input, relays, childLost, killSent, child, forwardBlocked,
                 graceElapsed>>
  /\ SettleOutcome

Next ==
  \/ HostEof
  \/ HostReadFails
  \/ ForwardFails
  \/ ForwardBlocks
  \/ ForwardResumes
  \/ ChildExits
  \/ ChildWaitFails
  \/ ChildDiesOnKill
  \/ GraceElapses
  \/ RelaysFinish
  \/ DrainElapses
  \/ WriterFails
  \/ WriterDrains

\* Timers fire, a killed child dies, and a live host reads its output. A child
\* may ignore EOF, relays may never finish, and the host may hold stdin open.
Fairness ==
  /\ WF_vars(GraceElapses)
  /\ WF_vars(DrainElapses)
  /\ WF_vars(ChildDiesOnKill)
  /\ WF_vars(WriterDrains)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------

\* The session never returns with the child still running.
FinishedMeansChildGone == phase = "Finished" => child /= "Running"

\* While the child runs, the session is in a phase that watches it.
RunningChildIsWatched ==
  child = "Running" => phase \in {"Relaying", "ExitGrace", "Killing"}

\* The exit grace starts only after the child got stdin EOF.
GraceFollowsStdinClose == phase = "ExitGrace" => input = "Stopped"

\* A kill needs a spent grace or a host that is gone.
KillIsEntitled == killSent => (graceElapsed \/ inputEnd = "HostOutputClosed")

\* The queue closes only when nothing can send to it.
FlushingMeansQueueClosed ==
  phase \in {"Flushing", "Finished"} => (input = "Stopped" /\ relays /= "Running")

\* The session returns only after every queued line is written or host output failed.
NoQueuedLineAbandoned == phase = "Finished" => writer /= "Open"

\* An exit status exists for each outcome that reports one.
OutcomeHasItsStatus ==
  outcome \in {"Clean", "ChildRefusedInput"} => child = "Exited"

\* A failed host writer always wins, as `written?` did.
HostOutputFailureIsReported ==
  (phase = "Finished" /\ writer = "Failed") => outcome = "HostOutputFailed"

\* Once the session starts to end, it ends.
LeavingRelayingFinishes == (phase /= "Relaying") ~> (phase = "Finished")

\* A dead host ends the session, even with host input stuck in a child write.
WriterFailureFinishes == (writer = "Failed") ~> (phase = "Finished")

=============================================================================
