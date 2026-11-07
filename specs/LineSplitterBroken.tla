-------------------------- MODULE LineSplitterBroken --------------------------
(***************************************************************************)
(* A deliberately broken variant: a cut loses the byte that caused it.     *)
(* TLC must report BytesAreConserved.                                       *)
(***************************************************************************)
EXTENDS LineSplitter

CutDropsByte ==
  /\ ~ended
  /\ bytesIn < MaxBytes
  /\ pending = Cap
  /\ bytesIn' = bytesIn + 1
  /\ pending' = 0
  /\ emitted' = TRUE
  /\ emittedLen' = Cap
  /\ bytesOut' = bytesOut + Cap
  /\ UNCHANGED ended

BrokenSpec == Init /\ [][Next \/ CutDropsByte]_vars

=============================================================================
