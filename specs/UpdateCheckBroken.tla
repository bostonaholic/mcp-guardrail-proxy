-------------------------- MODULE UpdateCheckBroken --------------------------
(***************************************************************************)
(* A deliberately broken variant: the schedule ignores the mode, so a tick *)
(* in Off still starts a check. TLC must report NoAutomaticRequestWhenOff. *)
(***************************************************************************)
EXTENDS UpdateCheck

CheckDueIgnoresMode ==
  /\ phase = "Idle"
  /\ mode = "Off"
  /\ phase' = "Checking"
  /\ trigger' = "Auto"
  /\ request' = "Check"
  /\ notice' = "None"
  /\ UNCHANGED <<mode, canInstall, known, told, failed>>

BrokenSpec == Init /\ [][Next \/ CheckDueIgnoresMode]_vars

=============================================================================
