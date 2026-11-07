--------------------------- MODULE LineWriterBroken ---------------------------
(***************************************************************************)
(* A deliberately broken variant: the writer records success before the    *)
(* write, so a torn write leaves it believing the line ended.               *)
(* TLC must report TornIsTracked.                                           *)
(***************************************************************************)
EXTENDS LineWriter

TearUnnoticed ==
  /\ joined' = (joined \/ LandsOnPartial)
  /\ dest' = "Partial"
  /\ boundary' = "AtLineStart"

BrokenSpec == Init /\ [][Next \/ TearUnnoticed]_vars

=============================================================================
