------------------------------ MODULE LineWriter ------------------------------
(***************************************************************************)
(* The line boundary in SharedLineWriter (LineBoundary, src/telemetry.rs).  *)
(* The audit log and child stderr share one destination, and a write can   *)
(* fail halfway. After a failure the writer must end the torn line before  *)
(* the next one, or an audit line would join the bytes in front of it.      *)
(*                                                                          *)
(* dest is the truth about the destination; boundary is what the writer     *)
(* believes. A failure that wrote nothing still counts as torn, because the *)
(* writer cannot tell how far it got. The cost is one blank line.           *)
(***************************************************************************)
VARIABLES boundary,              \* "AtLineStart" | "Torn"
          dest,                  \* "LineEnded" | "Partial"
          joined                 \* ghost: a line began after a partial line

vars == <<boundary, dest, joined>>

TypeOK ==
  /\ boundary \in {"AtLineStart", "Torn"}
  /\ dest \in {"LineEnded", "Partial"}
  /\ joined \in BOOLEAN

Init ==
  /\ boundary = "AtLineStart"
  /\ dest = "LineEnded"
  /\ joined = FALSE

\* Whether the bytes of this attempt's line land on a partial line.
LandsOnPartial == dest = "Partial" /\ boundary = "AtLineStart"

\* A torn writer repairs the boundary first, then writes the line.
WriteSucceeds ==
  /\ joined' = (joined \/ LandsOnPartial)
  /\ dest' = "LineEnded"
  /\ boundary' = "AtLineStart"

\* The repair newline fails. Nothing reaches the destination.
RepairFails ==
  /\ boundary = "Torn"
  /\ UNCHANGED vars

\* Part of the line reaches the destination, and then the write fails.
WriteTears ==
  /\ joined' = (joined \/ LandsOnPartial)
  /\ dest' = "Partial"
  /\ boundary' = "Torn"

\* The write fails with nothing of the line written.
WriteFailsEmpty ==
  /\ dest' = IF boundary = "Torn" THEN "LineEnded" ELSE dest
  /\ boundary' = "Torn"
  /\ UNCHANGED joined

\* The whole line lands, and then the flush fails.
FlushFails ==
  /\ joined' = (joined \/ LandsOnPartial)
  /\ dest' = "LineEnded"
  /\ boundary' = "Torn"

Next == WriteSucceeds \/ RepairFails \/ WriteTears \/ WriteFailsEmpty \/ FlushFails

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* A partial line never joins the line after it.
NoJoinedLines == ~joined

\* The writer always knows about a partial line.
TornIsTracked == dest = "Partial" => boundary = "Torn"

=============================================================================
