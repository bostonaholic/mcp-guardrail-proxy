------------------------- MODULE DashboardWatchBroken -------------------------
(***************************************************************************)
(* A deliberately broken variant, and the behavior before the machine was  *)
(* explicit. Two bugs: a poll publishes only on audit events or an error   *)
(* change, so a malformed line never updates the counter; and the launch   *)
(* read's error is not remembered, so its banner stays after the file       *)
(* recovers. TLC must report ScreenIsCurrent.                               *)
(***************************************************************************)
EXTENDS DashboardWatch

MalformedLineUnpublished ==
  /\ revision < MaxRevision
  /\ error' = "None"
  /\ shownError' = "None"
  /\ revision' = revision + 1
  /\ published' = FALSE
  /\ mayAlert' = FALSE
  /\ UNCHANGED <<phase, shownRevision, alertedOnHistory>>

BannerOutlivesError ==
  /\ shownError /= "None"
  /\ error' = "None"
  /\ published' = FALSE
  /\ mayAlert' = FALSE
  /\ UNCHANGED <<phase, shownError, shownRevision, revision, alertedOnHistory>>

BrokenSpec == Init /\ [][Next \/ MalformedLineUnpublished \/ BannerOutlivesError]_vars

=============================================================================
