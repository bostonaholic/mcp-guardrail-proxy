//! The only module that reaches the network: it starts an update check or install and always
//! sends exactly one result event back.

use std::future::Future;
use std::sync::mpsc::Sender;
use std::time::Duration;

use semver::Version;
use tauri::AppHandle;
use tauri::plugin::TauriPlugin;
use tauri_plugin_updater::{Config, Update, UpdaterExt};

use crate::update::{UpdateEvent, UpdateRequest, manifest_key};

/// The plugin's whole-request limit for a manifest read, from connect to the end of the body.
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
/// The plugin's whole-request limit for the payload download.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const DIFFERENT_RELEASE: &str = "A different release is now available. Start a new check.";

/// The updater plugin, configured by `plugins.updater` in `tauri.conf.json`.
pub fn plugin() -> TauriPlugin<tauri::Wry, Config> {
    tauri_plugin_updater::Builder::new().build()
}

/// Runs `request` in the background and sends its one result event to `results`.
pub fn start(app: &AppHandle, request: UpdateRequest, results: Sender<UpdateEvent>) {
    match request {
        UpdateRequest::Check => supervise(check(app.clone()), UpdateEvent::CheckFailed, results),
        UpdateRequest::Install(version) => supervise(
            install(app.clone(), version),
            UpdateEvent::InstallFailed,
            results,
        ),
    }
}

/// Returns at once. A supervising task runs `effect` as its own task and then sends exactly one
/// event: the effect's own, or `on_panic` with the panic text when the effect panics. It sends
/// only after the effect has ended, so the machine never leaves `Checking` or `Installing`
/// while plugin work still runs. Then it drops `results`.
pub fn supervise<F>(effect: F, on_panic: fn(String) -> UpdateEvent, results: Sender<UpdateEvent>)
where
    F: Future<Output = UpdateEvent> + Send + 'static,
{
    tauri::async_runtime::spawn(async move {
        let event = tauri::async_runtime::spawn(effect)
            .await
            .unwrap_or_else(|error| on_panic(error.to_string()));
        // The send fails only when the update thread is gone, as the app quits.
        let _ = results.send(event);
    });
}

async fn check(app: AppHandle) -> UpdateEvent {
    match find_update(&app).await {
        Ok(Some(update)) => match Version::parse(&update.version) {
            Ok(version) => UpdateEvent::CheckFoundNewer(version),
            Err(error) => UpdateEvent::CheckFailed(format!(
                "the release version {:?} is not semver: {error}",
                update.version
            )),
        },
        Ok(None) => UpdateEvent::CheckFoundNone,
        Err(reason) => UpdateEvent::CheckFailed(reason),
    }
}

/// Checks again first, so the install never pairs `version` with a payload from a release
/// that replaced it since the last check.
async fn install(app: AppHandle, version: Version) -> UpdateEvent {
    match install_version(&app, &version).await {
        Ok(()) => UpdateEvent::InstallWorked,
        Err(reason) => UpdateEvent::InstallFailed(reason),
    }
}

async fn install_version(app: &AppHandle, version: &Version) -> Result<(), String> {
    let mut update = match find_update(app).await? {
        Some(update) if Version::parse(&update.version).is_ok_and(|found| found == *version) => {
            update
        }
        _ => return Err(DIFFERENT_RELEASE.to_string()),
    };
    update.timeout = Some(INSTALL_TIMEOUT);
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| error.to_string())
}

/// Reads the release manifest. `Ok(None)` means this copy is up to date.
async fn find_update(app: &AppHandle) -> Result<Option<Update>, String> {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    let target =
        manifest_key(os, arch).ok_or_else(|| format!("no release is built for {os} {arch}"))?;
    let updater = app
        .updater_builder()
        .target(target)
        .timeout(CHECK_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())?;
    updater.check().await.map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    async fn panicking_install() -> UpdateEvent {
        panic!("install task panicked")
    }

    #[test]
    fn an_effect_task_always_ends_in_one_result_event() {
        let (results, events) = mpsc::channel();
        supervise(panicking_install(), UpdateEvent::InstallFailed, results);
        let first = events.recv_timeout(WAIT);
        assert!(
            matches!(first, Ok(UpdateEvent::InstallFailed(_))),
            "a panicking install sends one InstallFailed, got {first:?}"
        );
        assert_eq!(
            events.recv_timeout(WAIT),
            Err(RecvTimeoutError::Disconnected),
            "a panicking install sends no second event and drops the sender"
        );

        let (results, events) = mpsc::channel();
        supervise(
            async { UpdateEvent::CheckFoundNone },
            UpdateEvent::CheckFailed,
            results,
        );
        assert_eq!(
            events.recv_timeout(WAIT),
            Ok(UpdateEvent::CheckFoundNone),
            "a returning check sends its own event"
        );
        assert_eq!(
            events.recv_timeout(WAIT),
            Err(RecvTimeoutError::Disconnected),
            "a returning check sends no second event and drops the sender"
        );
    }
}
