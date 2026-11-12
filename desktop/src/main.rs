//! Tray app: watches the proxy's audit log, notifies on blocked calls, and checks for its own
//! updates. It also reads the MCP client config files that `INSTALL.md` lists, for the Servers
//! tab. It writes its own settings files and, when it installs an update, the new version of
//! itself. A Wrap press on the Servers tab also writes client config files, their backups, and
//! kept copies, and creates the audit log's folder and file. The Servers tab starts your login
//! shell to read its PATH, and a Wrap press starts `mcp-guardrail-proxy check-policy`. It never
//! talks to a proxy, so it cannot weaken one, and the proxy runs the same without it. Only
//! `updater.rs` reaches the network.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod audit;
mod clients;
mod monitor;
mod notify;
mod servers;
mod settings;
#[cfg(test)]
#[path = "../../src/machines/spec_graph.rs"]
mod spec_graph;
mod tail;
mod update;
mod update_settings;
mod updater;
mod watch;

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use audit::{Snapshot, tray_status};
use clients::{Platform, ServerId};
use monitor::Monitor;
use serde::{Deserialize, Serialize};
use servers::{HostEnv, ServersView, WrapReport};
use settings::{EffectiveSettings, SettingsStore, SettingsView, chosen_folder_log_path};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use update::{
    RELEASE_PAGE_URL, Remembered, SaveRequest, TrayClick, TrayItem, UpdateEvent, UpdateMachine,
    UpdateMode, UpdateView,
};

const LOG_PATH_VARIABLE: &str = "MCP_GUARDRAIL_AUDIT_LOG";
/// The path the README's quick start uses, relative to the home folder.
const DEFAULT_AUDIT_LOG: &str = ".local/state/mcp-guardrail/audit.jsonl";
const SETTINGS_FILE: &str = "settings.json";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const TRAY_ID: &str = "main";
const WATCHER_STOPPED: &str =
    "Saved. The log watcher stopped. Relaunch the app to apply the change.";
/// The update settings sit in their own folder, so an update save never replaces the General
/// tab's `settings.json`, and a General tab save never replaces the update file.
const UPDATE_SETTINGS_DIR: &str = "updates";
const UPDATES_ITEM_ID: &str = "updates";
const SETTINGS_ITEM_ID: &str = "settings";
const SETTINGS_WINDOW: &str = "settings";
const SETTINGS_PAGE: &str = "settings.html";
const SETTINGS_TITLE: &str = "Settings";
const SETTINGS_WIDTH: f64 = 640.0;
const SETTINGS_HEIGHT: f64 = 440.0;
/// Tells an open Settings window which tab to show. A new window reads its tab from the URL.
const SETTINGS_TAB_EVENT: &str = "settings-tab";
/// Lets the dashboard drop its settings banner after a save in the Settings window.
const SETTINGS_CHANGED_EVENT: &str = "settings-changed";
const TICK_INTERVAL: Duration = Duration::from_secs(60);
const WRAP_STOPPED: &str = "The wrap stopped on an internal error. Scan again before you wrap.";

#[cfg(target_os = "macos")]
const OPEN_URL_PROGRAM: &str = "open";
#[cfg(not(target_os = "macos"))]
const OPEN_URL_PROGRAM: &str = "xdg-open";

type SharedSnapshot = Arc<Mutex<Snapshot>>;

/// Lets one wrap run at a time.
struct WrapLock(Arc<Mutex<()>>);

/// A tab of the Settings window. The page names a tab when it calls `open_settings`, and the
/// command refuses any other name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum SettingsTab {
    General,
    Updates,
    Servers,
}

impl SettingsTab {
    /// The name the page uses: the URL fragment of a new window, and the tab event's payload.
    fn name(self) -> &'static str {
        match self {
            SettingsTab::General => "general",
            SettingsTab::Updates => "updates",
            SettingsTab::Servers => "servers",
        }
    }
}

/// One lock covers the store and the poll thread's channel, so the thread gets settings in the
/// order the window sets them.
struct SettingsState {
    store: SettingsStore,
    sender: Sender<EffectiveSettings>,
}

/// What the window and the tray item show about updates.
#[derive(Clone, PartialEq)]
struct UpdateScreen {
    view: UpdateView,
    tray: TrayItem,
}

/// The tray menu reads the tray item's click from here, because only `UpdateWatch` holds the
/// machine.
type SharedUpdates = Arc<Mutex<UpdateScreen>>;

/// Sends events to `UpdateWatch`, which owns the update machine.
struct UpdateInbox(Sender<UpdateEvent>);

impl UpdateInbox {
    fn send(&self, event: UpdateEvent) {
        // The send fails only when the update thread is gone, as the app quits.
        let _ = self.0.send(event);
    }
}

#[tauri::command]
fn snapshot(state: tauri::State<'_, SharedSnapshot>) -> Snapshot {
    state.lock().expect("the snapshot lock").clone()
}

#[tauri::command]
fn settings(state: tauri::State<'_, Mutex<SettingsState>>) -> SettingsView {
    state.lock().expect("the settings lock").store.view()
}

#[tauri::command]
fn set_audit_log_path(
    app: AppHandle,
    path: String,
    state: tauri::State<'_, Mutex<SettingsState>>,
) -> Result<SettingsView, String> {
    let mut state = state.lock().expect("the settings lock");
    state
        .store
        .set_audit_log_path(&path)
        .map_err(|error| error.to_string())?;
    let _ = app.emit(SETTINGS_CHANGED_EVENT, ());
    state
        .sender
        .send(state.store.effective())
        .map_err(|_| WATCHER_STOPPED.to_string())?;
    Ok(state.store.view())
}

#[tauri::command]
fn set_notifications(
    app: AppHandle,
    on: bool,
    state: tauri::State<'_, Mutex<SettingsState>>,
) -> Result<SettingsView, String> {
    let mut state = state.lock().expect("the settings lock");
    state
        .store
        .set_notifications(on)
        .map_err(|error| error.to_string())?;
    let _ = app.emit(SETTINGS_CHANGED_EVENT, ());
    state
        .sender
        .send(state.store.effective())
        .map_err(|_| WATCHER_STOPPED.to_string())?;
    Ok(state.store.view())
}

/// The panel picks a folder, not a file, so a log that no proxy has created yet can be chosen.
/// `async` and `spawn_blocking` keep the panel's wait off two threads. A sync command runs on
/// the main thread, where `blocking_pick_folder` would wait on itself. A wait in the async task
/// would hold one of the runtime's workers until the person closes the panel. The settings lock
/// is held only to read the start folder, so no other command waits on the panel.
#[tauri::command]
async fn choose_audit_log_path(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Mutex<SettingsState>>,
) -> Result<Option<String>, String> {
    let folder = state
        .lock()
        .expect("the settings lock")
        .store
        .chooser_folder();
    let chosen = tauri::async_runtime::spawn_blocking(move || {
        let mut panel = window
            .dialog()
            .file()
            .set_parent(&window)
            .set_title("Choose the audit log folder");
        if let Some(folder) = folder {
            panel = panel.set_directory(folder);
        }
        panel.blocking_pick_folder()
    })
    .await
    .map_err(|error| format!("Cannot open the file chooser: {error}"))?;
    let Some(folder) = chosen else {
        return Ok(None);
    };
    let folder = folder.into_path().map_err(|error| error.to_string())?;
    chosen_folder_log_path(folder)
        .map(Some)
        .map_err(|error| error.to_string())
}

/// Runs `task` on a blocking thread, so a slow file or child process never holds the main
/// thread or a runtime worker. A panic gives `fixed`, never the panic text, because a panic text
/// can quote config text, such as an `env` token. `supervise` in `updater.rs` passes its panic
/// text on, which is safe there only because update errors hold no config text.
async fn run_blocking<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static, fixed: T) -> T {
    tauri::async_runtime::spawn_blocking(task)
        .await
        .unwrap_or(fixed)
}

/// What the scan reads from the app's own environment and settings.
fn host_env(app: &AppHandle, home: PathBuf) -> HostEnv {
    let audit_log_path = app
        .state::<Mutex<SettingsState>>()
        .lock()
        .expect("the settings lock")
        .store
        .effective()
        .audit_log_path;
    HostEnv {
        home,
        platform: Platform::from_os(std::env::consts::OS),
        path: std::env::var_os("PATH"),
        cargo_install_root: std::env::var_os("CARGO_INSTALL_ROOT"),
        cargo_home: std::env::var_os("CARGO_HOME"),
        audit_log_path,
        shell: std::env::var_os("SHELL"),
    }
}

fn home_folder_problem(error: tauri::Error) -> String {
    format!("Cannot find your home folder: {error}")
}

#[tauri::command]
async fn servers(app: AppHandle) -> ServersView {
    let home = match app.path().home_dir() {
        Ok(home) => home,
        Err(error) => return ServersView::problem_only(home_folder_problem(error)),
    };
    let env = host_env(&app, home);
    run_blocking(move || servers::scan(&env), ServersView::stopped()).await
}

#[tauri::command]
async fn wrap_servers(
    app: AppHandle,
    rows: Vec<ServerId>,
    lock: tauri::State<'_, WrapLock>,
) -> Result<WrapReport, String> {
    let home = app.path().home_dir().map_err(home_folder_problem)?;
    let env = host_env(&app, home);
    let lock = Arc::clone(&lock.0);
    let unix_secs = now_ms() / 1000;
    run_blocking(
        move || servers::wrap_request(&lock, &env, &rows, unix_secs),
        Err(WRAP_STOPPED.to_string()),
    )
    .await
}

#[tauri::command]
fn update_status(state: tauri::State<'_, SharedUpdates>) -> UpdateView {
    state.lock().expect("the update screen lock").view.clone()
}

#[tauri::command]
fn check_for_updates(inbox: tauri::State<'_, UpdateInbox>) {
    inbox.send(UpdateEvent::ManualCheck);
}

#[tauri::command]
fn set_update_mode(mode: UpdateMode, inbox: tauri::State<'_, UpdateInbox>) {
    inbox.send(UpdateEvent::ChooseMode(mode));
}

#[tauri::command]
fn install_update(inbox: tauri::State<'_, UpdateInbox>) {
    inbox.send(UpdateEvent::ManualInstall);
}

#[tauri::command]
fn restart_to_update(app: AppHandle, state: tauri::State<'_, SharedUpdates>) {
    let ready = state
        .lock()
        .expect("the update screen lock")
        .view
        .restart_ready;
    if ready {
        app.restart();
    }
}

#[tauri::command]
fn open_release_page() -> Result<(), String> {
    std::process::Command::new(OPEN_URL_PROGRAM)
        .arg(RELEASE_PAGE_URL)
        .spawn()
        .map(drop)
        .map_err(|error| error.to_string())
}

/// Async, because Tauri warns that a window built inside a synchronous command can deadlock.
#[tauri::command]
async fn open_settings(app: AppHandle, tab: SettingsTab) -> Result<(), String> {
    show_settings(&app, tab).map_err(|error| error.to_string())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Builds the Settings window on first use. Closing it only hides it, so later calls reuse it.
fn show_settings(app: &AppHandle, tab: SettingsTab) -> tauri::Result<()> {
    let window = match app.get_webview_window(SETTINGS_WINDOW) {
        Some(window) => {
            app.emit_to(SETTINGS_WINDOW, SETTINGS_TAB_EVENT, tab)?;
            window
        }
        None => {
            let page = format!("{SETTINGS_PAGE}#{}", tab.name());
            WebviewWindowBuilder::new(app, SETTINGS_WINDOW, WebviewUrl::App(page.into()))
                .title(SETTINGS_TITLE)
                .inner_size(SETTINGS_WIDTH, SETTINGS_HEIGHT)
                .resizable(false)
                .maximizable(false)
                .center()
                .build()?
        }
    };
    window.show()?;
    window.set_focus()
}

fn show_settings_from_tray(app: &AppHandle, tab: SettingsTab) {
    if let Err(error) = show_settings(app, tab) {
        eprintln!("mcp-guardrail-desktop: the Settings window could not open: {error}");
    }
}

/// The tray items whose text changes after launch.
struct TrayItems {
    status: MenuItem<tauri::Wry>,
    updates: MenuItem<tauri::Wry>,
}

fn build_tray(app: &AppHandle, status: &str, updates: TrayItem) -> tauri::Result<TrayItems> {
    let status_item = MenuItem::with_id(app, "status", status, false, None::<&str>)?;
    let updates_item = MenuItem::with_id(
        app,
        UPDATES_ITEM_ID,
        updates.label,
        updates.enabled,
        None::<&str>,
    )?;
    let settings_item = MenuItem::with_id(app, SETTINGS_ITEM_ID, "Settings…", true, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open MCP Guardrail", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[&status_item, &updates_item, &settings_item, &open, &quit],
    )?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(tauri::include_image!("icons/tray.png"))
        .icon_as_template(true)
        .tooltip(status)
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            UPDATES_ITEM_ID => click_updates_item(app),
            SETTINGS_ITEM_ID => show_settings_from_tray(app, SettingsTab::General),
            "open" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(TrayItems {
        status: status_item,
        updates: updates_item,
    })
}

/// A tray check also opens the Updates tab, so its result reaches the person.
fn click_updates_item(app: &AppHandle) {
    let click = app
        .state::<SharedUpdates>()
        .lock()
        .expect("the update screen lock")
        .tray
        .click;
    match click {
        TrayClick::StartCheck => {
            app.state::<UpdateInbox>().send(UpdateEvent::ManualCheck);
            show_settings_from_tray(app, SettingsTab::Updates);
        }
        TrayClick::OpenWindow => show_settings_from_tray(app, SettingsTab::Updates),
        TrayClick::Restart => app.restart(),
        TrayClick::Nothing => {}
    }
}

fn publish(
    app: &AppHandle,
    shared: &SharedSnapshot,
    status_item: &MenuItem<tauri::Wry>,
    next: Snapshot,
) {
    let status = tray_status(&next);
    let _ = status_item.set_text(&status);
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(&status));
    }
    *shared.lock().expect("the snapshot lock") = next;
    let _ = app.emit("dashboard-updated", ());
}

/// Polls until the settings channel closes. A settings message applies at once, between two
/// polls. A read error stays on screen, and polling continues so the app recovers.
fn watch_log(
    app: AppHandle,
    shared: SharedSnapshot,
    status_item: MenuItem<tauri::Wry>,
    mut monitor: Monitor,
    settings: Receiver<EffectiveSettings>,
) {
    loop {
        match settings.recv_timeout(POLL_INTERVAL) {
            Ok(next) => {
                if let Some(snapshot) = monitor.apply(&next) {
                    publish(&app, &shared, &status_item, snapshot);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let polled = monitor.poll();
                if let Some(snapshot) = polled.snapshot {
                    publish(&app, &shared, &status_item, snapshot);
                }
                if let Some(alert) = polled.alert {
                    notify::send(&app, &alert);
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Wall-clock milliseconds. A clock before 1970 reads as 0.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Sends `Tick` every `TICK_INTERVAL` until the update thread is gone.
fn tick(inbox: Sender<UpdateEvent>) {
    loop {
        std::thread::sleep(TICK_INTERVAL);
        if inbox.send(UpdateEvent::Tick).is_err() {
            return;
        }
    }
}

/// The update thread: it owns the machine and carries out what each event's step asks for.
struct UpdateWatch {
    app: AppHandle,
    shared: SharedUpdates,
    item: MenuItem<tauri::Wry>,
    results: Sender<UpdateEvent>,
    update_settings_dir: PathBuf,
    current_version: String,
}

impl UpdateWatch {
    /// Handles events until the channel closes. `settings_note` starts as the launch note.
    fn run(
        &self,
        mut machine: UpdateMachine,
        events: Receiver<UpdateEvent>,
        mut settings_note: Option<String>,
    ) {
        for event in events {
            if let UpdateEvent::CheckFailed(reason) | UpdateEvent::InstallFailed(reason) = &event {
                eprintln!("mcp-guardrail-desktop: update failed: {reason}");
            }
            let actions = machine.handle(now_ms(), event);
            if let Some(request) = actions.request {
                updater::start(&self.app, request, self.results.clone());
            }
            if let Some(save) = actions.save {
                settings_note = self.save(&save);
            }
            if let Some(notice) = actions.notice {
                notify::send(&self.app, &notice);
            }
            self.show(update_screen(
                &machine,
                &self.current_version,
                settings_note.clone(),
            ));
        }
    }

    /// Saves, and returns the settings note that follows. A failed save keeps the values in
    /// memory, so the machine still acts on them until the app quits.
    fn save(&self, save: &SaveRequest) -> Option<String> {
        match update_settings::save(&self.update_settings_dir, save) {
            Ok(()) => None,
            Err(error) => {
                eprintln!("mcp-guardrail-desktop: update settings could not be saved: {error}");
                Some(update_settings::save_failed_note(&error))
            }
        }
    }

    /// Menu item calls wait for the main thread, and the main thread takes the screen lock in
    /// the tray handler and the commands. So the lock is released before the menu changes,
    /// or the two threads can wait on each other forever.
    fn show(&self, screen: UpdateScreen) {
        let tray = screen.tray;
        {
            let mut shown = self.shared.lock().expect("the update screen lock");
            if *shown == screen {
                return;
            }
            *shown = screen;
        }
        let _ = self.item.set_text(tray.label);
        let _ = self.item.set_enabled(tray.enabled);
        let _ = self.app.emit("updates-changed", ());
    }
}

fn update_screen(
    machine: &UpdateMachine,
    current_version: &str,
    settings_note: Option<String>,
) -> UpdateScreen {
    UpdateScreen {
        view: UpdateView {
            settings_note,
            ..machine.view(current_version)
        },
        tray: machine.tray_item(),
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(updater::plugin())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            settings,
            set_audit_log_path,
            set_notifications,
            choose_audit_log_path,
            update_status,
            check_for_updates,
            set_update_mode,
            install_update,
            restart_to_update,
            open_release_page,
            open_settings,
            servers,
            wrap_servers
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            notify::request_permission();

            let config_dir = app.path().app_config_dir()?;
            let store = SettingsStore::load(
                config_dir.join(SETTINGS_FILE),
                std::env::var_os(LOG_PATH_VARIABLE).map(PathBuf::from),
                app.path().home_dir()?.join(DEFAULT_AUDIT_LOG),
            );
            let (monitor, first) = Monitor::open(&store.effective());

            let update_settings_dir = config_dir.join(UPDATE_SETTINGS_DIR);
            let (saved, settings_note) = update_settings::load(&update_settings_dir);
            let can_install = update::can_install(
                cfg!(feature = "self-install"),
                std::env::consts::OS,
                std::env::var_os("APPIMAGE").is_some(),
            );
            let machine = UpdateMachine::new(
                saved.update_mode.unwrap_or_default(),
                Remembered {
                    told: saved.notified_version,
                    failed: saved.failed_version,
                },
                can_install,
            );
            let current_version = app.package_info().version.to_string();
            let first_updates = update_screen(&machine, &current_version, settings_note.clone());
            let first_tray = first_updates.tray;
            let updates: SharedUpdates = Arc::new(Mutex::new(first_updates));
            let (inbox, events) = mpsc::channel();
            app.manage(updates.clone());
            app.manage(UpdateInbox(inbox.clone()));

            let tray = build_tray(app.handle(), &tray_status(&first), first_tray)?;
            let shared: SharedSnapshot = Arc::new(Mutex::new(first));
            app.manage(shared.clone());
            let (sender, receiver) = mpsc::channel();
            app.manage(Mutex::new(SettingsState { store, sender }));
            app.manage(WrapLock(Arc::new(Mutex::new(()))));

            let handle = app.handle().clone();
            let status_item = tray.status;
            std::thread::spawn(move || {
                watch_log(handle, shared, status_item, monitor, receiver);
            });

            let update_watch = UpdateWatch {
                app: app.handle().clone(),
                shared: updates,
                item: tray.updates,
                results: inbox.clone(),
                update_settings_dir,
                current_version,
            };
            std::thread::spawn(move || update_watch.run(machine, events, settings_note));
            std::thread::spawn(move || tick(inbox));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the app failed to start");
}

#[cfg(test)]
mod tests {
    use super::{SettingsTab, run_blocking};
    use serde_json::json;

    #[test]
    fn each_tab_parses_from_its_name_and_serializes_back_to_it() {
        for (name, tab) in [
            ("general", SettingsTab::General),
            ("updates", SettingsTab::Updates),
            ("servers", SettingsTab::Servers),
        ] {
            assert_eq!(
                serde_json::from_value::<SettingsTab>(json!(name)).ok(),
                Some(tab),
                "{name} parses"
            );
            assert_eq!(tab.name(), name, "{name}: the page fragment");
            assert_eq!(
                serde_json::to_value(tab).ok(),
                Some(json!(name)),
                "{name}: the tab event payload"
            );
        }
    }

    #[test]
    fn a_name_outside_the_fixed_set_is_refused() {
        for name in [
            "",
            "General",
            "UPDATES",
            "advanced",
            "general ",
            "updates#x",
        ] {
            assert!(
                serde_json::from_value::<SettingsTab>(json!(name)).is_err(),
                "{name:?} must be refused"
            );
        }
        assert!(
            serde_json::from_value::<SettingsTab>(json!(1)).is_err(),
            "a number must be refused"
        );
    }

    #[test]
    fn a_panicking_blocking_task_returns_its_fixed_value() {
        let fixed = "The scan stopped on an internal error.".to_string();
        let after_panic = tauri::async_runtime::block_on(run_blocking(
            || -> String { panic!("a config value tok-12345678 in the panic text") },
            fixed.clone(),
        ));
        assert_eq!(
            after_panic, fixed,
            "a task that panics gives exactly the caller's fixed value, never the panic text"
        );
        let returned = tauri::async_runtime::block_on(run_blocking(
            || "the task's own value".to_string(),
            fixed,
        ));
        assert_eq!(
            returned, "the task's own value",
            "a task that returns gives its own value"
        );
    }
}
