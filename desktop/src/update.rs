//! When to check for updates, when to install one, and what to tell the person, mirrored from
//! `specs/UpdateCheck.tla`. Pure: no I/O, no UI.

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::audit::Alert;

pub const RELEASE_PAGE_URL: &str =
    "https://github.com/bostonaholic/mcp-guardrail-proxy/releases/latest";

/// The wait after a check that worked, manual or automatic.
const SUCCESS_WAIT_MS: u64 = 24 * 60 * 60 * 1000;
/// The wait after a check that failed, so a laptop that launched offline tries again soon.
const FAILURE_WAIT_MS: u64 = 60 * 60 * 1000;
/// The most characters of a remote or error string that reach the screen or a notice.
const MAX_SHOWN_CHARS: usize = 200;

/// The saved setting. `Notify` is the default when nothing is saved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateMode {
    Off,
    #[default]
    Notify,
    Install,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdatePhase {
    Idle,
    Checking,
    Installing,
    /// An install finished. Only a mode choice changes anything until the app restarts.
    Installed,
}

/// Who started the running request. Only an automatic request raises an OS notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Auto,
    Manual,
}

/// The saved version bounds. Neither ever falls.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Remembered {
    /// The highest version the person was told about. A version at or below it raises no notice.
    pub told: Option<Version>,
    /// The highest version whose install failed. A version at or below it never installs
    /// automatically.
    pub failed: Option<Version>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UpdateEvent {
    /// The 60-second clock. It starts a check only when one is due.
    Tick,
    ManualCheck,
    ManualInstall,
    ChooseMode(UpdateMode),
    CheckFoundNewer(Version),
    CheckFoundNone,
    CheckFailed(String),
    InstallWorked,
    InstallFailed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateRequest {
    Check,
    Install(Version),
}

/// What to write to the settings file. Every save carries both bounds.
#[derive(Clone, Debug, PartialEq)]
pub struct SaveRequest {
    /// `Some` only from a mode choice, so a bounds save never puts back an older choice that
    /// another app process has since replaced.
    pub mode: Option<UpdateMode>,
    pub remembered: Remembered,
}

/// What one step must do. Each field is empty when the step has nothing to do there.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UpdateActions {
    pub request: Option<UpdateRequest>,
    pub notice: Option<Alert>,
    pub save: Option<SaveRequest>,
}

/// What the window shows. Every string is built here, and remote text is cut to 200 characters.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UpdateView {
    pub current_version: String,
    pub mode: UpdateMode,
    /// Always `None` from [`UpdateMachine::view`]; the caller that loads and saves the settings
    /// sets it.
    pub settings_note: Option<String>,
    pub status: String,
    pub busy: bool,
    pub available: Option<String>,
    pub can_install: bool,
    /// Set exactly when `can_install` is false. It names the release page.
    pub install_note: Option<String>,
    pub restart_ready: bool,
}

/// What a click on the tray item does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayClick {
    StartCheck,
    OpenWindow,
    Restart,
    Nothing,
}

/// The tray item. Its label is fixed text, never remote text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrayItem {
    pub label: &'static str,
    pub enabled: bool,
    pub click: TrayClick,
}

/// What the last finished step found, so the status line can say it.
#[derive(Clone, Debug, PartialEq)]
enum LastResult {
    NotChecked,
    UpToDate,
    Found,
    CheckFailed(String),
    InstallFailed(String),
}

#[derive(Clone, Debug)]
pub struct UpdateMachine {
    mode: UpdateMode,
    can_install: bool,
    phase: UpdatePhase,
    trigger: Option<Trigger>,
    known: Option<Version>,
    told: Option<Version>,
    failed: Option<Version>,
    last_attempt_ms: Option<u64>,
    wait_ms: u64,
    last_result: LastResult,
}

impl UpdateMachine {
    /// A machine at launch, with the saved mode and bounds. It sends nothing, so loading the
    /// saved values never saves them.
    pub fn new(mode: UpdateMode, remembered: Remembered, can_install: bool) -> Self {
        Self {
            mode,
            can_install,
            phase: UpdatePhase::Idle,
            trigger: None,
            known: None,
            told: remembered.told,
            failed: remembered.failed,
            last_attempt_ms: None,
            wait_ms: SUCCESS_WAIT_MS,
            last_result: LastResult::NotChecked,
        }
    }

    /// Applies one event at wall-clock `now_ms`. An event that does not apply in the current
    /// phase changes nothing and returns empty actions.
    pub fn handle(&mut self, now_ms: u64, event: UpdateEvent) -> UpdateActions {
        use UpdateEvent as Event;
        use UpdatePhase as Phase;
        match (self.phase, event) {
            (_, Event::ChooseMode(mode)) => {
                self.mode = mode;
                UpdateActions {
                    save: Some(self.save_request(Some(mode))),
                    ..UpdateActions::default()
                }
            }
            (Phase::Idle, Event::Tick)
                if self.mode != UpdateMode::Off
                    && check_due(now_ms, self.last_attempt_ms, self.wait_ms) =>
            {
                self.start_check(now_ms, Trigger::Auto)
            }
            (Phase::Idle, Event::ManualCheck) => self.start_check(now_ms, Trigger::Manual),
            (Phase::Idle, Event::ManualInstall) if self.can_install => match self.known.clone() {
                Some(version) => {
                    self.phase = Phase::Installing;
                    self.trigger = Some(Trigger::Manual);
                    request(UpdateRequest::Install(version))
                }
                None => UpdateActions::default(),
            },
            (Phase::Checking, Event::CheckFoundNewer(version)) => self.found_newer(version),
            (Phase::Checking, Event::CheckFoundNone) => {
                self.known = None;
                self.wait_ms = SUCCESS_WAIT_MS;
                self.last_result = LastResult::UpToDate;
                self.settle(Phase::Idle);
                UpdateActions::default()
            }
            (Phase::Checking, Event::CheckFailed(reason)) => {
                self.wait_ms = FAILURE_WAIT_MS;
                self.last_result = LastResult::CheckFailed(clip(&reason));
                self.settle(Phase::Idle);
                UpdateActions::default()
            }
            (Phase::Installing, Event::InstallWorked) => {
                let notice = self.notice_if_auto(installed_notice);
                self.settle(Phase::Installed);
                UpdateActions {
                    notice,
                    ..UpdateActions::default()
                }
            }
            (Phase::Installing, Event::InstallFailed(reason)) => self.install_failed(&reason),
            _ => UpdateActions::default(),
        }
    }

    /// The window's view. `current_version` is the running app's version.
    pub fn view(&self, current_version: &str) -> UpdateView {
        UpdateView {
            current_version: current_version.to_string(),
            mode: self.mode,
            settings_note: None,
            status: self.status(current_version),
            busy: matches!(self.phase, UpdatePhase::Checking | UpdatePhase::Installing),
            available: self.known.as_ref().map(shown_version),
            can_install: self.can_install,
            install_note: (!self.can_install).then(|| {
                format!(
                    "This copy cannot install updates itself. Download new versions from {RELEASE_PAGE_URL}"
                )
            }),
            restart_ready: self.phase == UpdatePhase::Installed,
        }
    }

    /// The tray item for the current phase.
    pub fn tray_item(&self) -> TrayItem {
        match (self.phase, &self.known) {
            (UpdatePhase::Idle, None) => TrayItem {
                label: "Check for Updates…",
                enabled: true,
                click: TrayClick::StartCheck,
            },
            (UpdatePhase::Idle, Some(_)) => TrayItem {
                label: "Update Available…",
                enabled: true,
                click: TrayClick::OpenWindow,
            },
            (UpdatePhase::Checking, _) => TrayItem {
                label: "Checking for Updates…",
                enabled: false,
                click: TrayClick::Nothing,
            },
            (UpdatePhase::Installing, _) => TrayItem {
                label: "Installing Update…",
                enabled: false,
                click: TrayClick::Nothing,
            },
            (UpdatePhase::Installed, _) => TrayItem {
                label: "Restart to Update",
                enabled: true,
                click: TrayClick::Restart,
            },
        }
    }

    fn start_check(&mut self, now_ms: u64, trigger: Trigger) -> UpdateActions {
        self.phase = UpdatePhase::Checking;
        self.trigger = Some(trigger);
        self.last_attempt_ms = Some(now_ms);
        request(UpdateRequest::Check)
    }

    /// The install rule: in Install mode, a copy that can install moves straight from
    /// `Checking` to `Installing`, with no `Idle` step where a click could start another request.
    fn found_newer(&mut self, version: Version) -> UpdateActions {
        self.known = Some(version.clone());
        self.wait_ms = SUCCESS_WAIT_MS;
        self.last_result = LastResult::Found;
        if self.mode == UpdateMode::Install && self.can_install && above(&version, &self.failed) {
            self.phase = UpdatePhase::Installing;
            return request(UpdateRequest::Install(version));
        }
        // A manual result counts as told, because the window shows it. An automatic result
        // after a switch to Off tells nobody.
        let someone_sees_it = self.trigger == Some(Trigger::Manual) || self.mode != UpdateMode::Off;
        if !(above(&version, &self.told) && someone_sees_it) {
            self.settle(UpdatePhase::Idle);
            return UpdateActions::default();
        }
        self.told = Some(version);
        let notice = self.notice_if_auto(|version| available_notice(version, self.can_install));
        self.settle(UpdatePhase::Idle);
        UpdateActions {
            notice,
            save: Some(self.save_request(None)),
            ..UpdateActions::default()
        }
    }

    fn install_failed(&mut self, reason: &str) -> UpdateActions {
        let version = self
            .known
            .clone()
            .expect("an install always has the version it installs");
        let failed_rose = raise(&mut self.failed, &version);
        let told_rose = raise(&mut self.told, &version);
        self.last_result = LastResult::InstallFailed(clip(reason));
        let notice = self.notice_if_auto(install_failed_notice);
        self.settle(UpdatePhase::Idle);
        UpdateActions {
            notice,
            save: (failed_rose || told_rose).then(|| self.save_request(None)),
            ..UpdateActions::default()
        }
    }

    /// Ends the running request.
    fn settle(&mut self, phase: UpdatePhase) {
        self.phase = phase;
        self.trigger = None;
    }

    fn notice_if_auto(&self, notice: impl FnOnce(&Version) -> Alert) -> Option<Alert> {
        match (&self.trigger, &self.known) {
            (Some(Trigger::Auto), Some(version)) => Some(notice(version)),
            _ => None,
        }
    }

    fn save_request(&self, mode: Option<UpdateMode>) -> SaveRequest {
        SaveRequest {
            mode,
            remembered: Remembered {
                told: self.told.clone(),
                failed: self.failed.clone(),
            },
        }
    }

    fn status(&self, current_version: &str) -> String {
        let known = self.known.as_ref().map(shown_version).unwrap_or_default();
        match (self.phase, &self.last_result) {
            (UpdatePhase::Checking, _) => "Checking for updates…".to_string(),
            (UpdatePhase::Installing, _) => format!("Installing {known}…"),
            (UpdatePhase::Installed, _) => {
                format!("{known} is installed. Restart MCP Guardrail to use it.")
            }
            (UpdatePhase::Idle, LastResult::NotChecked) => "Not checked yet.".to_string(),
            (UpdatePhase::Idle, LastResult::UpToDate) => {
                format!("MCP Guardrail {} is up to date.", clip(current_version))
            }
            (UpdatePhase::Idle, LastResult::Found) if self.last_install_failed() => format!(
                "Version {known} is available. Its last install failed, so press Install to try again."
            ),
            (UpdatePhase::Idle, LastResult::Found) => format!("Version {known} is available."),
            (UpdatePhase::Idle, LastResult::CheckFailed(reason)) => {
                format!("The check failed: {reason}")
            }
            (UpdatePhase::Idle, LastResult::InstallFailed(reason)) => {
                format!("{known} did not install: {reason}")
            }
        }
    }

    /// The known version will not install automatically, so only the Install button tries it.
    fn last_install_failed(&self) -> bool {
        self.can_install
            && self
                .known
                .as_ref()
                .is_some_and(|version| !above(version, &self.failed))
    }
}

/// Whether a check is due. A check is due when none ran yet, when the clock moved back past the
/// last attempt, or when at least `wait_ms` has passed since it.
pub fn check_due(now_ms: u64, last_attempt_ms: Option<u64>, wait_ms: u64) -> bool {
    last_attempt_ms.is_none_or(|last| {
        now_ms
            .checked_sub(last)
            .is_none_or(|elapsed| elapsed >= wait_ms)
    })
}

/// Whether this copy can replace itself: a build with the `self-install` feature that runs as a
/// macOS app or as a Linux AppImage. `os` is a `std::env::consts::OS` value, and `appimage` is
/// whether the AppImage runtime set `APPIMAGE`.
pub fn can_install(self_install: bool, os: &str, appimage: bool) -> bool {
    self_install && (os == "macos" || (os == "linux" && appimage))
}

/// The release manifest's platform key for `std::env::consts` `os` and `arch` values, or `None`
/// for a platform that no release builds. The release script `render-update-manifest` holds the
/// same table.
pub fn manifest_key(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("darwin-aarch64"),
        ("macos", "x86_64") => Some("darwin-x86_64"),
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("linux", "aarch64") => Some("linux-aarch64"),
        _ => None,
    }
}

fn request(request: UpdateRequest) -> UpdateActions {
    UpdateActions {
        request: Some(request),
        ..UpdateActions::default()
    }
}

/// A version is above a bound when the bound is empty or lower in semver order.
fn above(version: &Version, bound: &Option<Version>) -> bool {
    bound.as_ref().is_none_or(|bound| version > bound)
}

/// Raises `bound` to at least `version`. Returns whether it rose.
fn raise(bound: &mut Option<Version>, version: &Version) -> bool {
    let rises = above(version, bound);
    if rises {
        *bound = Some(version.clone());
    }
    rises
}

/// The first 200 characters, cut at a character boundary.
fn clip(text: &str) -> String {
    text.chars().take(MAX_SHOWN_CHARS).collect()
}

fn shown_version(version: &Version) -> String {
    clip(&version.to_string())
}

fn available_notice(version: &Version, can_install: bool) -> Alert {
    let body = if can_install {
        "Open MCP Guardrail to install it."
    } else {
        "Download it from the release page."
    };
    Alert {
        title: format!("MCP Guardrail {} is available", shown_version(version)),
        body: body.to_string(),
    }
}

fn installed_notice(version: &Version) -> Alert {
    Alert {
        title: format!("MCP Guardrail {} is installed", shown_version(version)),
        body: "Restart MCP Guardrail to use it.".to_string(),
    }
}

fn install_failed_notice(version: &Version) -> Alert {
    Alert {
        title: format!("MCP Guardrail {} did not install", shown_version(version)),
        body: "Open MCP Guardrail to try again.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_graph::{SpecGraph, Step, tla_bool};

    /// The spec's two versions, `V1` below `V2`.
    const V1: Version = Version::new(0, 4, 0);
    const V2: Version = Version::new(0, 5, 0);

    /// A fixed wall clock, 2023-11-14T22:13:20Z.
    const T0: u64 = 1_700_000_000_000;
    const HOUR_MS: u64 = 60 * 60 * 1000;
    const DAY_MS: u64 = 24 * HOUR_MS;

    /// The machine, or `None` before `Start`, with what the last step returned.
    #[derive(Clone)]
    struct Walked {
        machine: Option<UpdateMachine>,
        actions: UpdateActions,
        now_ms: u64,
    }

    fn spec_mode(name: &str) -> UpdateMode {
        match name {
            "Off" => UpdateMode::Off,
            "Notify" => UpdateMode::Notify,
            "Install" => UpdateMode::Install,
            other => panic!("unknown mode {other}"),
        }
    }

    fn spec_version(name: &str) -> Option<Version> {
        match name {
            "None" => None,
            "V1" => Some(V1),
            "V2" => Some(V2),
            other => panic!("unknown version {other}"),
        }
    }

    fn version_name(version: &Option<Version>) -> String {
        match version {
            None => "None".to_string(),
            Some(v) if *v == V1 => "V1".to_string(),
            Some(v) if *v == V2 => "V2".to_string(),
            Some(v) => format!("unexpected version {v}"),
        }
    }

    fn request_name(request: &Option<UpdateRequest>) -> String {
        match request {
            None => "None",
            Some(UpdateRequest::Check) => "Check",
            Some(UpdateRequest::Install(_)) => "Install",
        }
        .to_string()
    }

    /// The notice kind, read from the title the person sees.
    fn notice_name(notice: &Option<Alert>) -> String {
        match notice {
            None => "None".to_string(),
            Some(alert) if alert.title.ends_with(" is available") => "Available".to_string(),
            Some(alert) if alert.title.ends_with(" is installed") => "Installed".to_string(),
            Some(alert) if alert.title.ends_with(" did not install") => "InstallFailed".to_string(),
            Some(alert) => format!("unexpected notice {:?}", alert.title),
        }
    }

    fn project(walked: &Walked) -> Vec<(&'static str, String)> {
        let Some(machine) = &walked.machine else {
            return [
                ("phase", "Starting"),
                ("mode", "Notify"),
                ("canInstall", "FALSE"),
                ("trigger", "None"),
                ("known", "None"),
                ("told", "None"),
                ("failed", "None"),
                ("request", "None"),
                ("notice", "None"),
            ]
            .map(|(name, value)| (name, value.to_string()))
            .to_vec();
        };
        let trigger = machine
            .trigger
            .map_or("None".to_string(), |trigger| format!("{trigger:?}"));
        vec![
            ("phase", format!("{:?}", machine.phase)),
            ("mode", format!("{:?}", machine.mode)),
            ("canInstall", tla_bool(machine.can_install)),
            ("trigger", trigger),
            ("known", version_name(&machine.known)),
            ("told", version_name(&machine.told)),
            ("failed", version_name(&machine.failed)),
            ("request", request_name(&walked.actions.request)),
            ("notice", notice_name(&walked.actions.notice)),
        ]
    }

    fn apply(walked: &mut Walked, step: &Step<'_>) {
        let event = match step.action {
            "Start" => {
                let remembered = Remembered {
                    told: spec_version(&step.to["told"]),
                    failed: spec_version(&step.to["failed"]),
                };
                let can_install = step.to["canInstall"] == "TRUE";
                walked.machine = Some(UpdateMachine::new(
                    spec_mode(&step.to["mode"]),
                    remembered,
                    can_install,
                ));
                walked.actions = UpdateActions::default();
                return;
            }
            "CheckDue" => {
                walked.now_ms += DAY_MS + 1;
                UpdateEvent::Tick
            }
            "ManualCheck" => UpdateEvent::ManualCheck,
            "ManualInstall" => UpdateEvent::ManualInstall,
            "ChooseMode" => UpdateEvent::ChooseMode(spec_mode(&step.to["mode"])),
            "CheckFindsNewer" => UpdateEvent::CheckFoundNewer(
                spec_version(&step.to["known"]).expect("CheckFindsNewer finds a version"),
            ),
            "CheckFindsNone" => UpdateEvent::CheckFoundNone,
            "CheckFails" => UpdateEvent::CheckFailed("connection refused".to_string()),
            "InstallWorks" => UpdateEvent::InstallWorked,
            "InstallFails" => UpdateEvent::InstallFailed("signature did not verify".to_string()),
            other => panic!("unknown action {other}"),
        };
        let machine = walked
            .machine
            .as_mut()
            .expect("every action after Start has a machine");
        let told_before = machine.told.clone();
        let failed_before = machine.failed.clone();
        walked.actions = machine.handle(walked.now_ms, event);

        // Decision 21: a step saves exactly when it chooses a mode or raises a bound. Every
        // save carries both bounds, and only a mode choice carries a mode.
        let chose_mode = step.action == "ChooseMode";
        let bound_rose = machine.told > told_before || machine.failed > failed_before;
        let expected_save = (chose_mode || bound_rose).then(|| SaveRequest {
            mode: chose_mode.then(|| spec_mode(&step.to["mode"])),
            remembered: Remembered {
                told: machine.told.clone(),
                failed: machine.failed.clone(),
            },
        });
        assert_eq!(
            walked.actions.save, expected_save,
            "{}: the save breaks the save rule, from a machine with told {told_before:?} and failed {failed_before:?}",
            step.action
        );
    }

    #[test]
    fn update_machine_matches_every_edge_of_the_spec() {
        let graph = SpecGraph::parse(include_str!("../../specs/graphs/UpdateCheck.graph"));
        let walked = graph.walk(
            Walked {
                machine: None,
                actions: UpdateActions::default(),
                now_ms: T0,
            },
            project,
            apply,
        );
        assert!(walked > 0);
    }

    /// A Notify-mode machine after `events`, all at `T0`.
    fn machine_after(
        remembered: Remembered,
        can_install: bool,
        events: Vec<UpdateEvent>,
    ) -> UpdateMachine {
        let mut machine = UpdateMachine::new(UpdateMode::Notify, remembered, can_install);
        for event in events {
            machine.handle(T0, event);
        }
        machine
    }

    struct StatusRow {
        name: &'static str,
        remembered: Remembered,
        can_install: bool,
        events: Vec<UpdateEvent>,
        status: String,
        busy: bool,
        restart_ready: bool,
        install_note: Option<&'static str>,
        tray: TrayItem,
    }

    const CHECK_ITEM: TrayItem = TrayItem {
        label: "Check for Updates…",
        enabled: true,
        click: TrayClick::StartCheck,
    };
    const AVAILABLE_ITEM: TrayItem = TrayItem {
        label: "Update Available…",
        enabled: true,
        click: TrayClick::OpenWindow,
    };

    #[test]
    fn each_update_state_shows_one_status_line_and_tray_label() {
        let rows = [
            StatusRow {
                name: "not checked yet",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![],
                status: "Not checked yet.".to_string(),
                busy: false,
                restart_ready: false,
                install_note: None,
                tray: CHECK_ITEM,
            },
            StatusRow {
                name: "checking",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![UpdateEvent::ManualCheck],
                status: "Checking for updates…".to_string(),
                busy: true,
                restart_ready: false,
                install_note: None,
                tray: TrayItem {
                    label: "Checking for Updates…",
                    enabled: false,
                    click: TrayClick::Nothing,
                },
            },
            StatusRow {
                name: "up to date",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![UpdateEvent::ManualCheck, UpdateEvent::CheckFoundNone],
                status: "MCP Guardrail 0.3.0 is up to date.".to_string(),
                busy: false,
                restart_ready: false,
                install_note: None,
                tray: CHECK_ITEM,
            },
            StatusRow {
                name: "available",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![UpdateEvent::ManualCheck, UpdateEvent::CheckFoundNewer(V1)],
                status: "Version 0.4.0 is available.".to_string(),
                busy: false,
                restart_ready: false,
                install_note: None,
                tray: AVAILABLE_ITEM,
            },
            StatusRow {
                name: "check failed",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![
                    UpdateEvent::ManualCheck,
                    UpdateEvent::CheckFailed("connection refused".to_string()),
                ],
                status: "The check failed: connection refused".to_string(),
                busy: false,
                restart_ready: false,
                install_note: None,
                tray: CHECK_ITEM,
            },
            StatusRow {
                name: "a 300-character multibyte reason keeps 200 characters",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![
                    UpdateEvent::ManualCheck,
                    UpdateEvent::CheckFailed("€".repeat(300)),
                ],
                status: format!("The check failed: {}", "€".repeat(200)),
                busy: false,
                restart_ready: false,
                install_note: None,
                tray: CHECK_ITEM,
            },
            StatusRow {
                name: "installing",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![
                    UpdateEvent::ManualCheck,
                    UpdateEvent::CheckFoundNewer(V1),
                    UpdateEvent::ManualInstall,
                ],
                status: "Installing 0.4.0…".to_string(),
                busy: true,
                restart_ready: false,
                install_note: None,
                tray: TrayItem {
                    label: "Installing Update…",
                    enabled: false,
                    click: TrayClick::Nothing,
                },
            },
            StatusRow {
                name: "installed",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![
                    UpdateEvent::ManualCheck,
                    UpdateEvent::CheckFoundNewer(V1),
                    UpdateEvent::ManualInstall,
                    UpdateEvent::InstallWorked,
                ],
                status: "0.4.0 is installed. Restart MCP Guardrail to use it.".to_string(),
                busy: false,
                restart_ready: true,
                install_note: None,
                tray: TrayItem {
                    label: "Restart to Update",
                    enabled: true,
                    click: TrayClick::Restart,
                },
            },
            StatusRow {
                name: "install failed",
                remembered: Remembered::default(),
                can_install: true,
                events: vec![
                    UpdateEvent::ManualCheck,
                    UpdateEvent::CheckFoundNewer(V1),
                    UpdateEvent::ManualInstall,
                    UpdateEvent::InstallFailed("signature did not verify".to_string()),
                ],
                status: "0.4.0 did not install: signature did not verify".to_string(),
                busy: false,
                restart_ready: false,
                install_note: None,
                tray: AVAILABLE_ITEM,
            },
            StatusRow {
                name: "available after a saved failed install",
                remembered: Remembered {
                    told: None,
                    failed: Some(V1),
                },
                can_install: true,
                events: vec![UpdateEvent::ManualCheck, UpdateEvent::CheckFoundNewer(V1)],
                status:
                    "Version 0.4.0 is available. Its last install failed, so press Install to try again."
                        .to_string(),
                busy: false,
                restart_ready: false,
                install_note: None,
                tray: AVAILABLE_ITEM,
            },
            StatusRow {
                name: "a copy that cannot install",
                remembered: Remembered::default(),
                can_install: false,
                events: vec![],
                status: "Not checked yet.".to_string(),
                busy: false,
                restart_ready: false,
                install_note: Some(
                    "This copy cannot install updates itself. Download new versions from https://github.com/bostonaholic/mcp-guardrail-proxy/releases/latest",
                ),
                tray: CHECK_ITEM,
            },
        ];
        for row in rows {
            let machine = machine_after(row.remembered, row.can_install, row.events);
            let view = machine.view("0.3.0");
            assert_eq!(view.status, row.status, "{}: status", row.name);
            assert_eq!(view.busy, row.busy, "{}: busy", row.name);
            assert_eq!(
                view.restart_ready, row.restart_ready,
                "{}: restart_ready",
                row.name
            );
            assert_eq!(
                view.can_install, row.can_install,
                "{}: can_install",
                row.name
            );
            assert_eq!(
                view.install_note.as_deref(),
                row.install_note,
                "{}: install_note",
                row.name
            );
            assert_eq!(machine.tray_item(), row.tray, "{}: tray item", row.name);
        }
    }

    /// A Notify-mode machine that can install, after each `(now_ms, event)` in `before`.
    fn machine_handled(before: Vec<(u64, UpdateEvent)>) -> UpdateMachine {
        let mut machine = UpdateMachine::new(UpdateMode::Notify, Remembered::default(), true);
        for (now_ms, event) in before {
            machine.handle(now_ms, event);
        }
        machine
    }

    struct StepRow {
        name: &'static str,
        before: Vec<(u64, UpdateEvent)>,
        now_ms: u64,
        event: UpdateEvent,
        actions: UpdateActions,
    }

    const SENDS_A_CHECK: UpdateActions = UpdateActions {
        request: Some(UpdateRequest::Check),
        notice: None,
        save: None,
    };
    const DOES_NOTHING: UpdateActions = UpdateActions {
        request: None,
        notice: None,
        save: None,
    };

    #[test]
    fn steps_outside_the_spec_return_their_designed_actions() {
        let rows = [
            StepRow {
                name: "the first tick sends a check",
                before: vec![],
                now_ms: T0,
                event: UpdateEvent::Tick,
                actions: SENDS_A_CHECK,
            },
            StepRow {
                name: "1 ms before 24 hours after a manual check that worked",
                before: vec![
                    (T0, UpdateEvent::ManualCheck),
                    (T0, UpdateEvent::CheckFoundNone),
                ],
                now_ms: T0 + DAY_MS - 1,
                event: UpdateEvent::Tick,
                actions: DOES_NOTHING,
            },
            StepRow {
                name: "exactly 24 hours after a manual check that worked",
                before: vec![
                    (T0, UpdateEvent::ManualCheck),
                    (T0, UpdateEvent::CheckFoundNone),
                ],
                now_ms: T0 + DAY_MS,
                event: UpdateEvent::Tick,
                actions: SENDS_A_CHECK,
            },
            StepRow {
                name: "1 ms before 1 hour after a failed check",
                before: vec![
                    (T0, UpdateEvent::Tick),
                    (T0, UpdateEvent::CheckFailed("offline".to_string())),
                ],
                now_ms: T0 + HOUR_MS - 1,
                event: UpdateEvent::Tick,
                actions: DOES_NOTHING,
            },
            StepRow {
                name: "exactly 1 hour after a failed check",
                before: vec![
                    (T0, UpdateEvent::Tick),
                    (T0, UpdateEvent::CheckFailed("offline".to_string())),
                ],
                now_ms: T0 + HOUR_MS,
                event: UpdateEvent::Tick,
                actions: SENDS_A_CHECK,
            },
            StepRow {
                name: "the clock behind the last check",
                before: vec![
                    (T0, UpdateEvent::ManualCheck),
                    (T0, UpdateEvent::CheckFoundNone),
                ],
                now_ms: T0 - 60_000,
                event: UpdateEvent::Tick,
                actions: SENDS_A_CHECK,
            },
            StepRow {
                name: "u64::MAX after a check at 0 ms",
                before: vec![
                    (0, UpdateEvent::ManualCheck),
                    (0, UpdateEvent::CheckFoundNone),
                ],
                now_ms: u64::MAX,
                event: UpdateEvent::Tick,
                actions: SENDS_A_CHECK,
            },
            StepRow {
                name: "a choice of the mode already in effect saves it",
                before: vec![],
                now_ms: T0,
                event: UpdateEvent::ChooseMode(UpdateMode::Notify),
                actions: UpdateActions {
                    request: None,
                    notice: None,
                    save: Some(SaveRequest {
                        mode: Some(UpdateMode::Notify),
                        remembered: Remembered::default(),
                    }),
                },
            },
        ];
        for row in rows {
            let mut machine = machine_handled(row.before);
            assert_eq!(
                machine.handle(row.now_ms, row.event),
                row.actions,
                "{}",
                row.name
            );
        }
    }

    const CAN_INSTALL_ROWS: [(&str, bool, &str, bool, bool); 5] = [
        (
            "no feature on macOS, as for a clone build",
            false,
            "macos",
            false,
            false,
        ),
        ("the feature on macOS", true, "macos", false, true),
        (
            "the feature on Linux in an AppImage",
            true,
            "linux",
            true,
            true,
        ),
        (
            "the feature on Linux outside an AppImage, as for a .deb or .rpm",
            true,
            "linux",
            false,
            false,
        ),
        (
            "no feature on Linux in an AppImage",
            false,
            "linux",
            true,
            false,
        ),
    ];

    #[test]
    fn only_a_self_install_build_run_as_a_mac_app_or_an_appimage_can_install() {
        for (name, self_install, os, appimage, expected) in CAN_INSTALL_ROWS {
            assert_eq!(can_install(self_install, os, appimage), expected, "{name}");
        }
    }

    const MANIFEST_KEY_ROWS: [(&str, &str, Option<&str>); 5] = [
        ("macos", "aarch64", Some("darwin-aarch64")),
        ("macos", "x86_64", Some("darwin-x86_64")),
        ("linux", "x86_64", Some("linux-x86_64")),
        ("linux", "aarch64", Some("linux-aarch64")),
        ("windows", "x86_64", None),
    ];

    #[test]
    fn manifest_key_names_the_platforms_the_release_manifest_uses() {
        for (os, arch, expected) in MANIFEST_KEY_ROWS {
            assert_eq!(manifest_key(os, arch), expected, "{os} {arch}");
        }
    }
}
