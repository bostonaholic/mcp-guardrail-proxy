--------------------------- MODULE LineFramerBroken ---------------------------
(***************************************************************************)
(* A deliberately broken variant: the machine reports Oversize the moment  *)
(* a line passes Cap and starts over. The rest of the long line then comes *)
(* out as a frame. TLC must report CompleteIsWholeLine.                     *)
(***************************************************************************)
EXTENDS LineFramer

ReportOversizeEarly ==
  /\ phase = "InLine"
  /\ held = Cap
  /\ phase' = "AtLineStart"
  /\ held' = 0
  /\ emitted' = "Oversize"
  /\ lineLen' = Cap + 1
  /\ lineDone' = FALSE

BrokenSpec == Init /\ [][Next \/ ReportOversizeEarly]_vars

=============================================================================
