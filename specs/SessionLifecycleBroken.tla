------------------------ MODULE SessionLifecycleBroken ------------------------
(***************************************************************************)
(* A deliberately broken variant, and the behavior before the machine was  *)
(* explicit: a writer failure reached host input through the closed queue, *)
(* and input only looked at the queue between frames. Stuck in a child      *)
(* stdin write, it never saw the failure, so nothing killed the child.      *)
(* TLC must report WriterFailureFinishes.                                   *)
(***************************************************************************)
EXTENDS SessionLifecycle

WriterFailsUnnoticed ==
  /\ writer = "Open"
  /\ phase = "Relaying"
  /\ forwardBlocked
  /\ writer' = "Failed"
  /\ UNCHANGED <<phase, inputEnd, input, relays, childLost, outcome, killSent, child,
                 forwardBlocked, graceElapsed>>

BrokenSpec == Init /\ [][Next \/ WriterFailsUnnoticed]_vars /\ Fairness

=============================================================================
