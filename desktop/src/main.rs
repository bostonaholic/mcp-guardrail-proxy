//! Read-only tray app: watches the proxy's audit log and notifies on blocked calls.
//! It never talks to a proxy, so it cannot weaken one, and the proxy runs the same without it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod audit;
mod notify;
#[cfg(test)]
#[path = "../../src/machines/spec_graph.rs"]
mod spec_graph;
mod tail;
mod watch;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use audit::{AuditEvent, Dashboard, Snapshot, alert_for, tray_status};
use tail::Tail;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use watch::Watch;

const LOG_PATH_VARIABLE: &str = "MCP_GUARDRAIL_AUDIT_LOG";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const TRAY_ID: &str = "main";

type SharedSnapshot = Arc<Mutex<Snapshot>>;

#[tauri::command]
fn snapshot(state: tauri::State<'_, SharedSnapshot>) -> Snapshot {
    state.lock().expect("the snapshot lock").clone()
}

/// The override, or the path the README's quick start uses.
fn audit_log_path(home: PathBuf) -> PathBuf {
    std::env::var_os(LOG_PATH_VARIABLE).map_or_else(
        || home.join(".local/state/mcp-guardrail/audit.jsonl"),
        PathBuf::from,
    )
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

/// Reads the log into the dashboard. Returns the new audit events and any read error.
fn poll_log(tail: &mut Tail, dashboard: &mut Dashboard) -> (Vec<AuditEvent>, Option<String>) {
    match tail.read_new_lines() {
        Ok(lines) => (dashboard.apply_lines(&lines), None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    }
}

/// Polls forever. A read error stays on screen, and polling continues so the app recovers.
fn watch_log(
    app: AppHandle,
    shared: SharedSnapshot,
    status_item: MenuItem<tauri::Wry>,
    mut tail: Tail,
    mut dashboard: Dashboard,
    mut watch: Watch,
    log_path: String,
) {
    loop {
        std::thread::sleep(POLL_INTERVAL);
        let (events, error) = poll_log(&mut tail, &mut dashboard);
        let actions = watch.after_poll(dashboard.revision(), error.as_deref());
        if actions.publish {
            publish(
                &app,
                &shared,
                &status_item,
                dashboard.snapshot(&log_path, error),
            );
        }
        if actions.may_alert {
            if let Some(alert) = alert_for(&events) {
                notify::send(&app, &alert);
            }
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![snapshot])
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

            let path = audit_log_path(app.path().home_dir()?);
            let log_path = path.display().to_string();
            let mut tail = Tail::new(path);
            let mut dashboard = Dashboard::default();
            let mut watch = Watch::new();
            // Lines already in the log are history: the first read that works loads them, and
            // `watch` keeps them from raising a notification.
            let (_, source_error) = poll_log(&mut tail, &mut dashboard);
            watch.after_poll(dashboard.revision(), source_error.as_deref());
            let first = dashboard.snapshot(&log_path, source_error);
            let status_item = build_tray(app.handle(), &tray_status(&first))?;
            let shared: SharedSnapshot = Arc::new(Mutex::new(first));
            app.manage(shared.clone());

            let handle = app.handle().clone();
            std::thread::spawn(move || {
                watch_log(
                    handle,
                    shared,
                    status_item,
                    tail,
                    dashboard,
                    watch,
                    log_path,
                );
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the app failed to start");
}
