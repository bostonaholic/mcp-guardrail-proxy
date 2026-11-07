----------------------------- MODULE LineSplitter -----------------------------
(***************************************************************************)
(* The child stderr splitter in src/machines/splitter.rs. It relays every  *)
(* byte and cuts lines longer than Cap into lines of Cap bytes, so the     *)
(* child never blocks on a full pipe and the proxy never holds a long      *)
(* line. bytesIn and bytesOut are ghost counters, bounded by MaxBytes.      *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Cap,                   \* LineSplitter.cfg: Cap = 2
          MaxBytes               \* LineSplitter.cfg: MaxBytes = 5

VARIABLES pending,               \* bytes of the current line in memory
          emitted,               \* the last step wrote a line
          emittedLen,            \* that line's length, 0 when none
          ended,                 \* the stream has ended
          bytesIn,               \* ghost: content bytes taken
          bytesOut               \* ghost: content bytes written

vars == <<pending, emitted, emittedLen, ended, bytesIn, bytesOut>>

TypeOK ==
  /\ pending \in 0..Cap
  /\ emitted \in BOOLEAN
  /\ emittedLen \in 0..Cap
  /\ ended \in BOOLEAN
  /\ bytesIn \in 0..MaxBytes
  /\ bytesOut \in 0..MaxBytes

Init ==
  /\ pending = 0
  /\ emitted = FALSE
  /\ emittedLen = 0
  /\ ended = FALSE
  /\ bytesIn = 0
  /\ bytesOut = 0

\* One byte that is not a newline. A full line is cut first.
Content ==
  /\ ~ended
  /\ bytesIn < MaxBytes
  /\ bytesIn' = bytesIn + 1
  /\ IF pending = Cap
       THEN /\ pending' = 1
            /\ emitted' = TRUE
            /\ emittedLen' = Cap
            /\ bytesOut' = bytesOut + Cap
       ELSE /\ pending' = pending + 1
            /\ emitted' = FALSE
            /\ emittedLen' = 0
            /\ UNCHANGED bytesOut
  /\ UNCHANGED ended

\* A newline writes the line, even an empty one.
Newline ==
  /\ ~ended
  /\ pending' = 0
  /\ emitted' = TRUE
  /\ emittedLen' = pending
  /\ bytesOut' = bytesOut + pending
  /\ UNCHANGED <<ended, bytesIn>>

\* The stream ends. Bytes after the last newline still go out.
End ==
  /\ ~ended
  /\ ended' = TRUE
  /\ pending' = 0
  /\ emitted' = (pending > 0)
  /\ emittedLen' = pending
  /\ bytesOut' = bytesOut + pending
  /\ UNCHANGED bytesIn

Next == Content \/ Newline \/ End

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* No byte is lost, duplicated, or invented.
BytesAreConserved == bytesIn = bytesOut + pending

\* Nothing stays behind after the stream ends.
EndFlushes == ended => pending = 0

=============================================================================
