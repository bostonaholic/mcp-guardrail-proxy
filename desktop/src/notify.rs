//! Desktop notifications. macOS uses `UNUserNotificationCenter` directly: the Tauri plugin's
//! macOS path goes through the deprecated `NSUserNotification` and reports permission as granted
//! without asking. Other platforms use the plugin.
//!
//! Failures go to stderr. They never reach the proxy, which does not depend on this app.

use crate::audit::Alert;

#[cfg(target_os = "macos")]
pub use macos::{request_permission, send};

#[cfg(not(target_os = "macos"))]
pub use plugin::{request_permission, send};

#[cfg(target_os = "macos")]
mod macos {
    use std::time::{SystemTime, UNIX_EPOCH};

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_user_notifications::{
        UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
        UNUserNotificationCenter,
    };
    use tauri::AppHandle;

    use super::Alert;

    fn describe(error: *mut NSError) -> Option<String> {
        // SAFETY: the framework passes either null or a valid NSError for the callback's duration.
        unsafe { error.as_ref() }.map(|error| error.localizedDescription().to_string())
    }

    /// Shows the system prompt the first time. Later launches answer from the saved setting.
    pub fn request_permission() {
        let done = RcBlock::new(|granted: Bool, error: *mut NSError| {
            eprintln!(
                "mcp-guardrail-desktop: notification permission granted={} error={:?}",
                granted.as_bool(),
                describe(error)
            );
        });
        UNUserNotificationCenter::currentNotificationCenter()
            .requestAuthorizationWithOptions_completionHandler(
                UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
                &done,
            );
    }

    pub fn send(_app: &AppHandle, alert: &Alert) {
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(&alert.title));
        content.setBody(&NSString::from_str(&alert.body));
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis());
        let identifier = NSString::from_str(&format!("blocked-{millis}"));
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &identifier,
            &content,
            None,
        );
        let done = RcBlock::new(|error: *mut NSError| {
            if let Some(error) = describe(error) {
                eprintln!("mcp-guardrail-desktop: notification failed: {error}");
            }
        });
        UNUserNotificationCenter::currentNotificationCenter()
            .addNotificationRequest_withCompletionHandler(&request, Some(&done));
    }
}

#[cfg(not(target_os = "macos"))]
mod plugin {
    use tauri::AppHandle;
    use tauri_plugin_notification::NotificationExt;

    use super::Alert;

    pub fn request_permission() {}

    pub fn send(app: &AppHandle, alert: &Alert) {
        let shown = app
            .notification()
            .builder()
            .title(&alert.title)
            .body(&alert.body)
            .show();
        if let Err(error) = shown {
            eprintln!("mcp-guardrail-desktop: notification failed: {error}");
        }
    }
}
