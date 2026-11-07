---------------------------- MODULE DashboardWatch ----------------------------
(***************************************************************************)
(* The desktop app's poll loop (desktop/src/watch.rs). After each poll it  *)
(* decides whether to publish a snapshot and whether a blocked call may    *)
(* raise a notification. The first successful read loads history, so it    *)
(* must stay silent. revision counts changes to the dashboard state.        *)
(***************************************************************************)
EXTENDS Naturals

CONSTANT MaxRevision             \* DashboardWatch.cfg: MaxRevision = 3

VARIABLES phase,                 \* "LoadingHistory" | "Live"
          shownError,            \* the error on screen
          shownRevision,         \* the dashboard revision on screen
          error,                 \* the last poll's error
          revision,              \* the dashboard's revision
          published,             \* the last poll published
          mayAlert,              \* the last poll may notify
          alertedOnHistory       \* ghost: a history read was allowed to notify

vars == <<phase, shownError, shownRevision, error, revision, published, mayAlert,
          alertedOnHistory>>

Errors == {"None", "E1", "E2"}

TypeOK ==
  /\ phase \in {"LoadingHistory", "Live"}
  /\ shownError \in Errors
  /\ shownRevision \in 0..MaxRevision
  /\ error \in Errors
  /\ revision \in 0..MaxRevision
  /\ published \in BOOLEAN
  /\ mayAlert \in BOOLEAN
  /\ alertedOnHistory \in BOOLEAN

Init ==
  /\ phase = "LoadingHistory"
  /\ shownError = "None"
  /\ shownRevision = 0
  /\ error = "None"
  /\ revision = 0
  /\ published = FALSE
  /\ mayAlert = FALSE
  /\ alertedOnHistory = FALSE

\* One poll ended with error e and left the dashboard at nextRevision.
Settle(e, nextRevision) ==
  /\ error' = e
  /\ revision' = nextRevision
  /\ published' = (e /= shownError \/ nextRevision /= shownRevision)
  /\ shownError' = e
  /\ shownRevision' = nextRevision

\* The read worked. A notification needs a read after the history read.
MayAlertIfLive ==
  /\ mayAlert' = (phase = "Live")
  /\ alertedOnHistory' = (alertedOnHistory \/ (mayAlert' /\ phase = "LoadingHistory"))

PollFails(e) ==
  /\ Settle(e, revision)
  /\ mayAlert' = FALSE
  /\ UNCHANGED <<phase, alertedOnHistory>>

\* The read worked and brought nothing that changes the dashboard.
PollQuiet ==
  /\ Settle("None", revision)
  /\ MayAlertIfLive
  /\ phase' = "Live"

\* The read brought lines that change the dashboard, audit events or malformed ones.
PollNewLines ==
  /\ revision < MaxRevision
  /\ Settle("None", revision + 1)
  /\ MayAlertIfLive
  /\ phase' = "Live"

Next ==
  \/ PollFails("E1")
  \/ PollFails("E2")
  \/ PollQuiet
  \/ PollNewLines

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* After every poll the screen shows the current state, so no banner sticks
\* and no counter lags until the next audit event.
ScreenIsCurrent == shownError = error /\ shownRevision = revision

\* Lines that were in the log at launch never raise a notification.
HistoryStaysSilent == ~alertedOnHistory

=============================================================================
