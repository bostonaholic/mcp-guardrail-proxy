-------------------------- MODULE AuditLogTailBroken --------------------------
(***************************************************************************)
(* A deliberately broken variant, and the behavior before the machine was  *)
(* explicit: a poll that finds no file keeps the old offset. A new log     *)
(* that grows past that offset then loses its first lines.                  *)
(* TLC must report CursorTracksCurrentFile.                                 *)
(***************************************************************************)
EXTENDS AuditLogTail

PollMissingKeepsOffset ==
  /\ ~exists
  /\ rotated' = FALSE
  /\ UNCHANGED <<offset, held, exists, fileLen, midLine, generation, cursorGen>>

BrokenSpec == Init /\ [][Next \/ PollMissingKeepsOffset]_vars

=============================================================================
