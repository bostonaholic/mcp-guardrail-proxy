//! Read-only tray app: watches the proxy's audit log and notifies on blocked calls.
//! It never talks to a proxy, so it cannot weaken one, and the proxy runs the same without it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod audit;
mod monitor;
mod notify;
mod settings;
#[cfg(test)]
#[path = "../../src/machines/spec_graph.rs"]
mod spec_graph;
mod tail;
mod watch;

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use audit::{Snapshot, tray_status};
use monitor::Monitor;
use settings::{EffectiveSettings, SettingsStore, SettingsView};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

const LOG_PATH_VARIABLE: &str = "MCP_GUARDRAIL_AUDIT_LOG";
/// The path the README's quick start uses, relative to the home folder.
const DEFAULT_AUDIT_LOG: &str = ".local/state/mcp-guardrail/audit.jsonl";
const SETTINGS_FILE: &str = "settings.json";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const TRAY_ID: &str = "main";
const WATCHER_STOPPED: &str = "The log watcher stopped. Relaunch the app.";

type SharedSnapshot = Arc<Mutex<Snapshot>>;

/// One lock covers the store and the poll thread's channel, so the thread gets settings in the
/// order the window sets them.
struct SettingsState {
    store: SettingsStore,
    sender: Sender<EffectiveSettings>,
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
    path: String,
    state: tauri::State<'_, Mutex<SettingsState>>,
) -> Result<SettingsView, String> {
    let mut state = state.lock().expect("the settings lock");
    state.store.set_audit_log_path(&path);
    state
        .sender
        .send(state.store.effective())
        .map_err(|_| WATCHER_STOPPED.to_string())?;
    Ok(state.store.view())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn build_tray(app: &AppHandle, status: &str) -> tauri::Result<MenuItem<tauri::Wry>> {
    let status_item = MenuItem::with_id(app, "status", status, false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open MCP Guardrail", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status_item, &open, &quit])?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(tauri::include_image!("icons/tray.png"))
        .icon_as_template(true)
        .tooltip(status)
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(status_item)
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            settings,
            set_audit_log_path
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

            let store = SettingsStore::load(
                app.path().app_config_dir()?.join(SETTINGS_FILE),
                std::env::var_os(LOG_PATH_VARIABLE).map(PathBuf::from),
                app.path().home_dir()?.join(DEFAULT_AUDIT_LOG),
            );
            let (monitor, first) = Monitor::open(&store.effective());
            let status_item = build_tray(app.handle(), &tray_status(&first))?;
            let shared: SharedSnapshot = Arc::new(Mutex::new(first));
            app.manage(shared.clone());
            let (sender, receiver) = mpsc::channel();
            app.manage(Mutex::new(SettingsState { store, sender }));

            let handle = app.handle().clone();
            std::thread::spawn(move || {
                watch_log(handle, shared, status_item, monitor, receiver);
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the app failed to start");
}
