---------------------------- MODULE DashboardWatch ----------------------------
(***************************************************************************)
(* The desktop app's poll loop (desktop/src/watch.rs). After each poll it  *)
(* decides whether to publish a snapshot and whether a blocked call may    *)
(* raise a notification. The first successful read loads history, so it    *)
(* must stay silent. revision counts changes to the dashboard state.        *)
(*                                                                         *)
(* It also keeps the read mark: how many of the log's blocked calls the    *)
(* person has marked read. The unread count is the rest. The mark saved    *)
(* by an earlier run loads at launch, and the history read settles it.     *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxRevision,           \* DashboardWatch.cfg: MaxRevision = 3
          MaxBlocked             \* DashboardWatch.cfg: MaxBlocked = 2

VARIABLES phase,                 \* "Starting" | "LoadingHistory" | "Live"
          shownError,            \* the error on screen
          shownRevision,         \* the dashboard revision on screen
          shownUnread,           \* the unread count on screen
          error,                 \* the last poll's error
          revision,              \* the dashboard's revision
          blocked,               \* the blocked calls the dashboard has counted
          savedCount,            \* the read mark an earlier run saved
          readBlocked,           \* the blocked calls marked read
          published,             \* the last step published
          mayAlert,              \* the last poll may notify
          saveRequested,         \* the last step asked to save the read mark
          alertedOnHistory,      \* ghost: a history read was allowed to notify
          markedRead             \* ghost: the calls of this log the person marked read

vars == <<phase, shownError, shownRevision, shownUnread, error, revision, blocked,
          savedCount, readBlocked, published, mayAlert, saveRequested,
          alertedOnHistory, markedRead>>

Errors == {"None", "E1", "E2"}

TypeOK ==
  /\ phase \in {"Starting", "LoadingHistory", "Live"}
  /\ shownError \in Errors
  /\ shownRevision \in 0..MaxRevision
  /\ shownUnread \in 0..MaxBlocked
  /\ error \in Errors
  /\ revision \in 0..MaxRevision
  /\ blocked \in 0..MaxBlocked
  /\ savedCount \in 0..MaxBlocked
  /\ readBlocked \in 0..MaxBlocked
  /\ published \in BOOLEAN
  /\ mayAlert \in BOOLEAN
  /\ saveRequested \in BOOLEAN
  /\ alertedOnHistory \in BOOLEAN
  /\ markedRead \in 0..MaxBlocked

Init ==
  /\ phase = "Starting"
  /\ shownError = "None"
  /\ shownRevision = 0
  /\ shownUnread = 0
  /\ error = "None"
  /\ revision = 0
  /\ blocked = 0
  /\ savedCount = 0
  /\ readBlocked = 0
  /\ published = FALSE
  /\ mayAlert = FALSE
  /\ saveRequested = FALSE
  /\ alertedOnHistory = FALSE
  /\ markedRead = 0

\* The blocked calls not marked read. A mark above the count leaves none.
Unread(count, read) == IF count >= read THEN count - read ELSE 0

\* Launch: the read mark an earlier run saved for this log loads. 0 means none.
Open ==
  /\ phase = "Starting"
  /\ savedCount' \in 0..MaxBlocked
  /\ phase' = "LoadingHistory"
  /\ published' = FALSE
  /\ mayAlert' = FALSE
  /\ saveRequested' = FALSE
  /\ UNCHANGED <<shownError, shownRevision, shownUnread, error, revision, blocked,
                 readBlocked, alertedOnHistory, markedRead>>

\* The mark after a read that worked and left count blocked calls. The history
\* read settles it: a saved mark above the log's count belongs to another file,
\* so nothing is read. Later reads keep the mark.
MarkAfter(count) ==
  IF phase = "LoadingHistory"
  THEN IF savedCount <= count THEN savedCount ELSE 0
  ELSE readBlocked

\* One poll ended with error e and left the dashboard at nextRevision, with
\* nextBlocked blocked calls and nextRead of them read.
Settle(e, nextRevision, nextBlocked, nextRead) ==
  /\ error' = e
  /\ revision' = nextRevision
  /\ blocked' = nextBlocked
  /\ readBlocked' = nextRead
  /\ published' = \/ e /= shownError
                  \/ nextRevision /= shownRevision
                  \/ Unread(nextBlocked, nextRead) /= shownUnread
  /\ shownError' = e
  /\ shownRevision' = nextRevision
  /\ shownUnread' = Unread(nextBlocked, nextRead)
  /\ saveRequested' = FALSE
  /\ UNCHANGED savedCount

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
  /\ Settle(e, revision, blocked, readBlocked)
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

\* The person marks read the first seen blocked calls, the count their screen
\* showed. It moves the mark forward, and only within the log's count.
MarkRead(seen) ==
  /\ readBlocked < seen
  /\ seen <= blocked
  /\ readBlocked' = seen
  /\ markedRead' = seen
  /\ shownUnread' = blocked - seen
  /\ published' = TRUE
  /\ saveRequested' = TRUE
  /\ mayAlert' = FALSE
  /\ UNCHANGED <<phase, shownError, shownRevision, error, revision, blocked,
                 savedCount, alertedOnHistory>>

\* A mark that would move nothing: none unread, or a count the log never held.
MarkReadIgnored ==
  /\ phase /= "Starting"
  /\ published' = FALSE
  /\ saveRequested' = FALSE
  /\ mayAlert' = FALSE
  /\ UNCHANGED <<phase, shownError, shownRevision, shownUnread, error, revision,
                 blocked, savedCount, readBlocked, alertedOnHistory, markedRead>>

Next ==
  \/ Open
  \/ PollFails("E1")
  \/ PollFails("E2")
  \/ PollQuiet
  \/ \E count \in 0..MaxBlocked : PollNewLines(count)
  \/ \E seen \in 1..MaxBlocked : MarkRead(seen)
  \/ MarkReadIgnored

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* After every step the screen shows the current state, so no banner sticks
\* and no counter lags until the next audit event.
ScreenIsCurrent ==
  /\ shownError = error
  /\ shownRevision = revision
  /\ shownUnread = Unread(blocked, readBlocked)

\* Lines that were in the log at launch never raise a notification.
HistoryStaysSilent == ~alertedOnHistory

\* The mark never passes the log's blocked calls, so each new one is unread.
MarkFitsTheLog == readBlocked <= blocked

\* Once the history read has settled the mark, no poll moves it back.
MarkIsNotLost == phase = "Live" => readBlocked >= markedRead

\* Only a mark that moved asks for a save.
SaveFollowsAMark == saveRequested => (published /\ readBlocked > 0)

=============================================================================
