----------------------------- MODULE AuditLogTail -----------------------------
(***************************************************************************)
(* The desktop app's cursor over the audit log (desktop/src/tail.rs). It   *)
(* polls by size, so it finds a rotation only when it sees the file gone   *)
(* or smaller than the cursor.                                              *)
(*                                                                          *)
(* One assumption: a replacement file does not grow past the old cursor     *)
(* between two polls. Polling by size cannot see that, so the guard on      *)
(* Append states it. The proxy only appends, so only an outside rotation    *)
(* inside one 500 ms poll can break it.                                     *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxLen,                \* AuditLogTail.cfg: MaxLen = 3
          MaxGen                 \* AuditLogTail.cfg: MaxGen = 3

VARIABLES offset,                \* bytes of the file already read
          held,                  \* a partial line waits for its newline
          exists,                \* the file is there
          fileLen,               \* its length
          midLine,               \* its last byte is not a newline
          generation,            \* ghost: which file this is
          cursorGen,             \* ghost: the file that offset counts bytes of
          rotated                \* ghost: the file changed identity since the last poll

vars == <<offset, held, exists, fileLen, midLine, generation, cursorGen, rotated>>

TypeOK ==
  /\ offset \in 0..MaxLen
  /\ held \in BOOLEAN
  /\ exists \in BOOLEAN
  /\ fileLen \in 0..MaxLen
  /\ midLine \in BOOLEAN
  /\ generation \in 1..MaxGen
  /\ cursorGen \in 1..MaxGen
  /\ rotated \in BOOLEAN

Init ==
  /\ offset = 0
  /\ held = FALSE
  /\ exists = FALSE
  /\ fileLen = 0
  /\ midLine = FALSE
  /\ generation = 1
  /\ cursorGen = 1
  /\ rotated = FALSE

Create ==
  /\ ~exists
  /\ exists' = TRUE
  /\ UNCHANGED <<offset, held, fileLen, midLine, generation, cursorGen, rotated>>

AppendsWithinView == ~rotated \/ fileLen + 1 < offset

Append(endsLine) ==
  /\ exists
  /\ fileLen < MaxLen
  /\ AppendsWithinView
  /\ fileLen' = fileLen + 1
  /\ midLine' = ~endsLine
  /\ UNCHANGED <<offset, held, exists, generation, cursorGen, rotated>>

AppendContent == exists /\ Append(FALSE)
AppendNewline == exists /\ Append(TRUE)

Truncate ==
  /\ exists
  /\ fileLen > 0
  /\ generation < MaxGen
  /\ fileLen' = 0
  /\ midLine' = FALSE
  /\ generation' = generation + 1
  /\ rotated' = TRUE
  /\ UNCHANGED <<offset, held, exists, cursorGen>>

Remove ==
  /\ exists
  /\ generation < MaxGen
  /\ exists' = FALSE
  /\ fileLen' = 0
  /\ midLine' = FALSE
  /\ generation' = generation + 1
  /\ rotated' = TRUE
  /\ UNCHANGED <<offset, held, cursorGen>>

\* A poll finds no file: whatever the cursor counted is gone.
PollMissing ==
  /\ ~exists
  /\ offset' = 0
  /\ held' = FALSE
  /\ cursorGen' = generation
  /\ rotated' = FALSE
  /\ UNCHANGED <<exists, fileLen, midLine, generation>>

\* A poll opens the file. A shorter file restarts the cursor, then it reads to the end.
PollRead ==
  /\ exists
  /\ LET restart == fileLen < offset
         start   == IF restart THEN 0 ELSE offset
     IN /\ offset' = fileLen
        /\ held' = IF fileLen > start THEN midLine
                   ELSE IF restart THEN FALSE ELSE held
  /\ cursorGen' = generation
  /\ rotated' = FALSE
  /\ UNCHANGED <<exists, fileLen, midLine, generation>>

\* A poll opens the file, and then the read fails. A restart still counts.
PollReadFails ==
  /\ exists
  /\ fileLen < offset
  /\ offset' = 0
  /\ held' = FALSE
  /\ cursorGen' = generation
  /\ rotated' = FALSE
  /\ UNCHANGED <<exists, fileLen, midLine, generation>>

Next ==
  \/ Create
  \/ AppendContent
  \/ AppendNewline
  \/ Truncate
  \/ Remove
  \/ PollMissing
  \/ PollRead
  \/ PollReadFails

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* After a poll, the cursor counts bytes of the current file, or none.
CursorTracksCurrentFile == ~rotated => (offset = 0 \/ cursorGen = generation)

\* After a poll, the cursor is inside the file, so nothing gets skipped.
CursorStaysInFile == ~rotated => offset <= fileLen

\* A partial line never carries over from a file that is gone.
PartialBelongsToFile == (held /\ ~rotated) => (offset > 0 /\ cursorGen = generation)

=============================================================================
