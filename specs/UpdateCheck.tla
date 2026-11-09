----------------------------- MODULE UpdateCheck -----------------------------
(***************************************************************************)
(* The desktop app's update machine (desktop/src/update.rs). It decides    *)
(* when to check for a newer release, when to install one, and when to     *)
(* tell the person. told and failed are the saved version bounds: a        *)
(* version at or below told raises no second notice, and a version at or  *)
(* below failed never installs automatically. request and notice are what  *)
(* the last step sent. The clock is abstract: CheckDue is the tick that    *)
(* finds a check due.                                                       *)
(***************************************************************************)
EXTENDS Naturals

VARIABLES mode,        \* "Off" | "Notify" | "Install"
          canInstall,  \* this copy can replace itself
          phase,       \* "Starting" | "Idle" | "Checking" | "Installing" | "Installed"
          trigger,     \* who started the running request: "None" | "Auto" | "Manual"
          known,       \* the newer version the last check found
          told,        \* the highest version the person was told about
          failed,      \* the highest version whose install failed
          request,     \* the request the last step sent
          notice       \* the OS notice the last step sent

vars == <<mode, canInstall, phase, trigger, known, told, failed, request, notice>>

Modes == {"Off", "Notify", "Install"}
Versions == {"None", "V1", "V2"}
Newer == {"V1", "V2"}

Rank(v) == CASE v = "None" -> 0 [] v = "V1" -> 1 [] v = "V2" -> 2

\* A version is above a bound when the bound is empty or lower.
Above(v, bound) == Rank(v) > Rank(bound)

Higher(a, b) == IF Rank(a) >= Rank(b) THEN a ELSE b

TypeOK ==
  /\ mode \in Modes
  /\ canInstall \in BOOLEAN
  /\ phase \in {"Starting", "Idle", "Checking", "Installing", "Installed"}
  /\ trigger \in {"None", "Auto", "Manual"}
  /\ known \in Versions
  /\ told \in Versions
  /\ failed \in Versions
  /\ request \in {"None", "Check", "Install"}
  /\ notice \in {"None", "Available", "Installed", "InstallFailed"}

Init ==
  /\ mode = "Notify"
  /\ canInstall = FALSE
  /\ phase = "Starting"
  /\ trigger = "None"
  /\ known = "None"
  /\ told = "None"
  /\ failed = "None"
  /\ request = "None"
  /\ notice = "None"

\* Launch: the saved mode and bounds load. A copy that cannot install never
\* reads failed, so it stays empty there.
Start ==
  /\ phase = "Starting"
  /\ mode' \in Modes
  /\ canInstall' \in BOOLEAN
  /\ told' \in Versions
  /\ failed' \in IF canInstall' THEN Versions ELSE {"None"}
  /\ phase' = "Idle"
  /\ trigger' = "None"
  /\ known' = "None"
  /\ request' = "None"
  /\ notice' = "None"

\* The schedule finds a check due. Off makes no automatic request.
CheckDue ==
  /\ phase /= "Starting"
  /\ request' = IF phase = "Idle" /\ mode /= "Off" THEN "Check" ELSE "None"
  /\ phase' = IF phase = "Idle" /\ mode /= "Off" THEN "Checking" ELSE phase
  /\ trigger' = IF phase = "Idle" /\ mode /= "Off" THEN "Auto" ELSE trigger
  /\ notice' = "None"
  /\ UNCHANGED <<mode, canInstall, known, told, failed>>

\* The tray item or the Check now button.
ManualCheck ==
  /\ phase /= "Starting"
  /\ request' = IF phase = "Idle" THEN "Check" ELSE "None"
  /\ phase' = IF phase = "Idle" THEN "Checking" ELSE phase
  /\ trigger' = IF phase = "Idle" THEN "Manual" ELSE trigger
  /\ notice' = "None"
  /\ UNCHANGED <<mode, canInstall, known, told, failed>>

\* The Install button. It ignores failed, so a press retries on purpose.
ManualInstall ==
  /\ phase /= "Starting"
  /\ request' = IF phase = "Idle" /\ known /= "None" /\ canInstall THEN "Install" ELSE "None"
  /\ phase' = IF phase = "Idle" /\ known /= "None" /\ canInstall THEN "Installing" ELSE phase
  /\ trigger' = IF phase = "Idle" /\ known /= "None" /\ canInstall THEN "Manual" ELSE trigger
  /\ notice' = "None"
  /\ UNCHANGED <<mode, canInstall, known, told, failed>>

\* A mode change in any phase. It never starts a request.
ChooseMode(m) ==
  /\ phase /= "Starting"
  /\ m /= mode
  /\ mode' = m
  /\ request' = "None"
  /\ notice' = "None"
  /\ UNCHANGED <<canInstall, phase, trigger, known, told, failed>>

\* The check found v. The mode applies in the same step, so no Idle state
\* sits between "found" and "install started". A manual result counts as
\* told, because the window shows it; an automatic result after a switch to
\* Off tells nobody.
CheckFindsNewer(v) ==
  /\ phase = "Checking"
  /\ known' = v
  /\ IF mode = "Install" /\ canInstall /\ Above(v, failed)
       THEN /\ phase' = "Installing"
            /\ request' = "Install"
            /\ notice' = "None"
            /\ UNCHANGED <<trigger, told>>
       ELSE /\ phase' = "Idle"
            /\ trigger' = "None"
            /\ request' = "None"
            /\ IF Above(v, told) /\ (trigger = "Manual" \/ mode /= "Off")
                 THEN /\ told' = v
                      /\ notice' = IF trigger = "Auto" THEN "Available" ELSE "None"
                 ELSE /\ notice' = "None"
                      /\ UNCHANGED told
  /\ UNCHANGED <<mode, canInstall, failed>>

CheckFindsNone ==
  /\ phase = "Checking"
  /\ known' = "None"
  /\ phase' = "Idle"
  /\ trigger' = "None"
  /\ request' = "None"
  /\ notice' = "None"
  /\ UNCHANGED <<mode, canInstall, told, failed>>

\* known stays, so a newer version found earlier is still on screen.
CheckFails ==
  /\ phase = "Checking"
  /\ phase' = "Idle"
  /\ trigger' = "None"
  /\ request' = "None"
  /\ notice' = "None"
  /\ UNCHANGED <<mode, canInstall, known, told, failed>>

InstallWorks ==
  /\ phase = "Installing"
  /\ phase' = "Installed"
  /\ trigger' = "None"
  /\ request' = "None"
  /\ notice' = IF trigger = "Auto" THEN "Installed" ELSE "None"
  /\ UNCHANGED <<mode, canInstall, known, told, failed>>

\* A failed install raises both bounds to at least its version.
InstallFails ==
  /\ phase = "Installing"
  /\ failed' = Higher(failed, known)
  /\ told' = Higher(told, known)
  /\ phase' = "Idle"
  /\ trigger' = "None"
  /\ request' = "None"
  /\ notice' = IF trigger = "Auto" THEN "InstallFailed" ELSE "None"
  /\ UNCHANGED <<mode, canInstall, known>>

Next ==
  \/ Start
  \/ CheckDue
  \/ ManualCheck
  \/ ManualInstall
  \/ \E m \in Modes : ChooseMode(m)
  \/ \E v \in Newer : CheckFindsNewer(v)
  \/ CheckFindsNone
  \/ CheckFails
  \/ InstallWorks
  \/ InstallFails

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* Off makes no request that the person did not start.
NoAutomaticRequestWhenOff == (request /= "None" /\ trigger = "Auto") => mode /= "Off"

\* A request starts from Idle, or it is the check result that starts an install.
OneRequestAtATime ==
  [][request' /= "None" => (phase = "Idle" \/ (phase = "Checking" /\ phase' = "Installing"))]_vars

\* An install needs canInstall, and either the Install button or Install mode
\* with a version above failed.
InstallOnlyWhenAllowed ==
  [][request' = "Install" =>
       /\ canInstall
       /\ (phase = "Idle" \/ (mode = "Install" /\ Above(known', failed)))]_vars

\* Only a request the schedule started raises an OS notice, when it ends.
OnlyTheScheduleNotifies ==
  [][notice' /= "None" =>
       /\ trigger = "Auto"
       /\ phase \in {"Checking", "Installing"}
       /\ phase' \in {"Idle", "Installed"}]_vars

\* An Available notice needs a version above told and sets told to it, and
\* told never falls, so no version is announced twice.
EachVersionToldOnce ==
  [][/\ notice' = "Available" => (Above(known', told) /\ told' = known')
     /\ Rank(told') >= Rank(told)]_vars

\* failed never falls, and a failed install raises it to its version.
EachInstallOutcomeOnce ==
  [][/\ Rank(failed') >= Rank(failed)
     /\ (phase = "Installing" /\ phase' = "Idle") => Rank(failed') >= Rank(known)]_vars

=============================================================================
