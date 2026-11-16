---------------------------- MODULE DashboardWatch ----------------------------
(***************************************************************************)
(* The desktop app's poll loop (desktop/src/watch.rs). After each poll it  *)
(* decides whether to publish a snapshot and whether a blocked call may    *)
(* raise a notification. The first successful read loads history, so it    *)
(* must stay silent. revision counts changes to the dashboard state.        *)
(*                                                                         *)
(* It also keeps the read mark: which of the log's blocked calls the       *)
(* person has marked read. A call is named by its place among the log's    *)
(* blocked calls, counted from 1. The unread count is the rest. The mark   *)
(* saved by an earlier run loads at launch, and the history read settles   *)
(* it.                                                                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS MaxRevision,           \* DashboardWatch.cfg: MaxRevision = 3
          MaxBlocked             \* DashboardWatch.cfg: MaxBlocked = 2

VARIABLES phase,                 \* "Starting" | "LoadingHistory" | "Live"
          shownError,            \* the error on screen
          shownRevision,         \* the dashboard revision on screen
          shownUnread,           \* the unread count on screen
          error,                 \* the last poll's error
          revision,              \* the dashboard's revision
          blocked,               \* the blocked calls the dashboard has counted
          savedRead,             \* the read mark an earlier run saved
          readCalls,             \* the blocked calls marked read
          published,             \* the last step published
          mayAlert,              \* the last poll may notify
          saveRequested,         \* the last step asked to save the read mark
          alertedOnHistory,      \* ghost: a history read was allowed to notify
          markedRead             \* ghost: the calls of this log the person marked read

vars == <<phase, shownError, shownRevision, shownUnread, error, revision, blocked,
          savedRead, readCalls, published, mayAlert, saveRequested,
          alertedOnHistory, markedRead>>

Errors == {"None", "E1", "E2"}

\* Every set of blocked calls a mark can name.
Marks == SUBSET (1..MaxBlocked)

TypeOK ==
  /\ phase \in {"Starting", "LoadingHistory", "Live"}
  /\ shownError \in Errors
  /\ shownRevision \in 0..MaxRevision
  /\ shownUnread \in 0..MaxBlocked
  /\ error \in Errors
  /\ revision \in 0..MaxRevision
  /\ blocked \in 0..MaxBlocked
  /\ savedRead \in Marks
  /\ readCalls \in Marks
  /\ published \in BOOLEAN
  /\ mayAlert \in BOOLEAN
  /\ saveRequested \in BOOLEAN
  /\ alertedOnHistory \in BOOLEAN
  /\ markedRead \in Marks

Init ==
  /\ phase = "Starting"
  /\ shownError = "None"
  /\ shownRevision = 0
  /\ shownUnread = 0
  /\ error = "None"
  /\ revision = 0
  /\ blocked = 0
  /\ savedRead = {}
  /\ readCalls = {}
  /\ published = FALSE
  /\ mayAlert = FALSE
  /\ saveRequested = FALSE
  /\ alertedOnHistory = FALSE
  /\ markedRead = {}

\* How many blocked calls are not marked read. A mark larger than the count
\* leaves none.
Unread(count, read) ==
  IF count >= Cardinality(read) THEN count - Cardinality(read) ELSE 0

\* Launch: the read mark an earlier run saved for this log loads. {} means none.
Open ==
  /\ phase = "Starting"
  /\ savedRead' \in Marks
  /\ phase' = "LoadingHistory"
  /\ published' = FALSE
  /\ mayAlert' = FALSE
  /\ saveRequested' = FALSE
  /\ UNCHANGED <<shownError, shownRevision, shownUnread, error, revision, blocked,
                 readCalls, alertedOnHistory, markedRead>>

\* The mark after a read that worked and left count blocked calls. The history
\* read settles it: a saved mark that names a call the log does not hold
\* belongs to another file, so nothing is read. Later reads keep the mark.
MarkAfter(count) ==
  IF phase = "LoadingHistory"
  THEN IF savedRead \subseteq 1..count THEN savedRead ELSE {}
  ELSE readCalls

\* One poll ended with error e and left the dashboard at nextRevision, with
\* nextBlocked blocked calls and the calls nextRead read.
Settle(e, nextRevision, nextBlocked, nextRead) ==
  /\ error' = e
  /\ revision' = nextRevision
  /\ blocked' = nextBlocked
  /\ readCalls' = nextRead
  /\ published' = \/ e /= shownError
                  \/ nextRevision /= shownRevision
                  \/ Unread(nextBlocked, nextRead) /= shownUnread
  /\ shownError' = e
  /\ shownRevision' = nextRevision
  /\ shownUnread' = Unread(nextBlocked, nextRead)
  /\ saveRequested' = FALSE
  /\ UNCHANGED savedRead

\* The read worked. A notification needs a read after the history read.
MayAlertIfLive ==
  /\ mayAlert' = (phase = "Live")
  /\ alertedOnHistory' = (alertedOnHistory \/ (mayAlert' /\ phase = "LoadingHistory"))

\* The read worked and left count blocked calls.
ReadWorked(count) ==
  /\ MayAlertIfLive
  /\ markedRead' = IF phase = "LoadingHistory" THEN MarkAfter(count) ELSE markedRead
  /\ phase' = "Live"

PollFails(e) ==
  /\ phase /= "Starting"
  /\ Settle(e, revision, blocked, readCalls)
  /\ mayAlert' = FALSE
  /\ UNCHANGED <<phase, alertedOnHistory, markedRead>>

\* The read worked and brought nothing that changes the dashboard.
PollQuiet ==
  /\ phase /= "Starting"
  /\ Settle("None", revision, blocked, MarkAfter(blocked))
  /\ ReadWorked(blocked)

\* The read brought lines that change the dashboard, audit events or malformed
\* ones, and left count blocked calls.
PollNewLines(count) ==
  /\ phase /= "Starting"
  /\ revision < MaxRevision
  /\ count >= blocked
  /\ Settle("None", revision + 1, count, MarkAfter(count))
  /\ ReadWorked(count)

\* The person marks read the blocked calls seen, which their screen showed:
\* the rows they selected, or 1..n when the screen showed n blocked calls and
\* they marked all. The mark only grows, and only within the log's calls.
MarkRead(seen) ==
  /\ seen \subseteq 1..blocked
  /\ ~(seen \subseteq readCalls)
  /\ readCalls' = readCalls \union seen
  /\ markedRead' = readCalls \union seen
  /\ shownUnread' = Unread(blocked, readCalls \union seen)
  /\ published' = TRUE
  /\ saveRequested' = TRUE
  /\ mayAlert' = FALSE
  /\ UNCHANGED <<phase, shownError, shownRevision, error, revision, blocked,
                 savedRead, alertedOnHistory>>

\* A mark that would move nothing: every call it names is read, or it names a
\* call the log never held.
MarkReadIgnored ==
  /\ phase /= "Starting"
  /\ published' = FALSE
  /\ saveRequested' = FALSE
  /\ mayAlert' = FALSE
  /\ UNCHANGED <<phase, shownError, shownRevision, shownUnread, error, revision,
                 blocked, savedRead, readCalls, alertedOnHistory, markedRead>>

Next ==
  \/ Open
  \/ PollFails("E1")
  \/ PollFails("E2")
  \/ PollQuiet
  \/ \E count \in 0..MaxBlocked : PollNewLines(count)
  \/ \E seen \in Marks : MarkRead(seen)
  \/ MarkReadIgnored

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* After every step the screen shows the current state, so no banner sticks
\* and no counter lags until the next audit event.
ScreenIsCurrent ==
  /\ shownError = error
  /\ shownRevision = revision
  /\ shownUnread = Unread(blocked, readCalls)

\* Lines that were in the log at launch never raise a notification.
HistoryStaysSilent == ~alertedOnHistory

\* The mark names only calls the log holds, so each new blocked call is unread.
MarkFitsTheLog == readCalls \subseteq 1..blocked

\* Once the history read has settled the mark, no poll unmarks a call.
MarkIsNotLost == phase = "Live" => markedRead \subseteq readCalls

\* Only a mark that grew asks for a save.
SaveFollowsAMark == saveRequested => (published /\ readCalls /= {})

=============================================================================
