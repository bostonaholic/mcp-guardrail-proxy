------------------------------ MODULE LineFramer ------------------------------
(***************************************************************************)
(* The capped line reader in src/machines/framer.rs. It splits a byte      *)
(* stream into lines, holds at most Cap bytes, and throws away the rest of  *)
(* a longer line. Host frames and child stdout both pass through it, so a   *)
(* tail of an oversize line must never come out as a frame of its own.      *)
(*                                                                          *)
(* lineLen and lineDone are ghosts: they watch the physical line, whatever  *)
(* the machine believes.                                                    *)
(***************************************************************************)
EXTENDS Naturals

CONSTANT Cap                     \* LineFramer.cfg: Cap = 2

VARIABLES phase,                 \* "AtLineStart" | "InLine" | "Discarding"
          held,                  \* bytes of the current line in memory
          emitted,               \* what the last step returned
          lineLen,               \* ghost: physical line length, saturated at Cap + 1
          lineDone               \* ghost: the last physical line has ended

vars == <<phase, held, emitted, lineLen, lineDone>>

Phases    == {"AtLineStart", "InLine", "Discarding"}
Emissions == {"None", "Complete", "Oversize", "Eof"}

TypeOK ==
  /\ phase \in Phases
  /\ held \in 0..Cap
  /\ emitted \in Emissions
  /\ lineLen \in 0..(Cap + 1)
  /\ lineDone \in BOOLEAN

Init ==
  /\ phase = "AtLineStart"
  /\ held = 0
  /\ emitted = "None"
  /\ lineLen = 0
  /\ lineDone = TRUE

Saturated(n) == IF n > Cap THEN Cap + 1 ELSE n

\* One byte that is not a newline. At the start of a line the previous line's
\* bytes, kept for the caller until now, go away.
Content ==
  /\ emitted /= "Eof"
  /\ LET heldBefore == IF phase = "AtLineStart" THEN 0 ELSE held
         lenBefore  == IF lineDone THEN 0 ELSE lineLen
     IN /\ lineLen' = Saturated(lenBefore + 1)
        /\ IF phase = "Discarding" \/ heldBefore = Cap
             THEN /\ phase' = "Discarding"
                  /\ held' = 0
             ELSE /\ phase' = "InLine"
                  /\ held' = heldBefore + 1
  /\ emitted' = "None"
  /\ lineDone' = FALSE

\* A newline ends the line, whichever way it went.
Newline ==
  /\ emitted /= "Eof"
  /\ phase' = "AtLineStart"
  /\ emitted' = IF phase = "Discarding" THEN "Oversize" ELSE "Complete"
  /\ held' = IF phase = "InLine" THEN held ELSE 0
  /\ lineLen' = IF lineDone THEN 0 ELSE lineLen
  /\ lineDone' = TRUE

\* The stream ends. A final line may lack its newline.
End ==
  /\ emitted /= "Eof"
  /\ phase' = "AtLineStart"
  /\ emitted' = CASE phase = "AtLineStart" -> "Eof"
                  [] phase = "InLine"      -> "Complete"
                  [] phase = "Discarding"  -> "Oversize"
  /\ held' = IF phase = "InLine" THEN held ELSE 0
  /\ lineLen' = IF lineDone THEN 0 ELSE lineLen
  /\ lineDone' = TRUE

Next == Content \/ Newline \/ End

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* Memory stays bounded however long the line is.
DiscardingHoldsNothing == phase = "Discarding" => held = 0

\* A frame is a whole physical line: never a head, never a tail.
CompleteIsWholeLine == emitted = "Complete" => (held = lineLen /\ lineLen <= Cap)

\* A line is reported oversize only when it was.
OversizeIsLong == emitted = "Oversize" => (lineLen = Cap + 1 /\ held = 0)

\* Every ended line leaves the machine ready for the next one.
LineEndResynchronizes == emitted \in {"Complete", "Oversize"} => phase = "AtLineStart"

=============================================================================
