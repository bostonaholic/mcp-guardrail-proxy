// Audit fields carry text an attacker can influence, such as tool names and URIs.
// Every value reaches the page through textContent, never as HTML.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const byId = (id) => document.getElementById(id);
const time = (ms) => new Date(ms).toLocaleTimeString();

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function fillRows(tbody, rows) {
  tbody.replaceChildren(
    ...rows.map((cells) => {
      const tr = document.createElement("tr");
      tr.append(...cells);
      return tr;
    }),
  );
}

function showBanner(element, text) {
  element.hidden = !text;
  element.textContent = text || "";
}

let latest = null;

function render() {
  if (!latest) return;
  const { sessions, events } = latest;
  byId("log-path").textContent = latest.log_path;
  showBanner(byId("source-error"), latest.source_error && `Cannot read the audit log: ${latest.source_error}`);
  showBanner(byId("malformed"), latest.malformed_lines > 0 && `${latest.malformed_lines} audit lines could not be read. The audit format may have changed.`);
  byId("stat-sessions").textContent = sessions.length;
  byId("stat-tainted").textContent = sessions.filter((s) => s.taint_level === "Tainted").length;
  byId("stat-calls").textContent = latest.total_calls;
  byId("stat-blocked").textContent = latest.total_blocked;
  fillRows(byId("sessions"), sessions.map((s) => [
    cell(s.session_id), cell(s.taint_level, s.taint_level), cell(s.calls), cell(s.blocked), cell(time(s.last_seen_ms)),
  ]));
  const shown = byId("blocked-only").checked ? events.filter((e) => !e.forwarded) : events;
  fillRows(byId("events"), shown.map((e) => [
    cell(time(e.timestamp_ms)), cell(e.tool_name), cell(e.decision, e.decision), cell(e.rule_id), cell(e.reason),
  ]));
  byId("empty").hidden = events.length > 0;
}

async function refresh() {
  latest = await invoke("snapshot");
  render();
}

function showSettings(view) {
  byId("path-input").value = view.audit_log_path;
  byId("path-input").disabled = view.path_from_variable;
  byId("path-save").disabled = view.path_from_variable;
  byId("path-variable-note").hidden = !view.path_from_variable;
  byId("notifications").checked = view.notifications;
  showBanner(byId("settings-problem"), view.problem);
}

async function loadSettings() {
  showSettings(await invoke("settings"));
}

byId("path-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    showSettings(await invoke("set_audit_log_path", { path: byId("path-input").value }));
    showBanner(byId("save-error"), null);
  } catch (message) {
    showBanner(byId("save-error"), String(message));
  }
});

byId("notifications").addEventListener("change", async (event) => {
  try {
    showSettings(await invoke("set_notifications", { on: event.target.checked }));
    showBanner(byId("save-error"), null);
  } catch (message) {
    showBanner(byId("save-error"), String(message));
    loadSettings();
  }
});

function renderUpdates(view) {
  byId("update-version").textContent = view.current_version;
  for (const button of document.querySelectorAll(".mode")) {
    button.setAttribute("aria-pressed", String(button.dataset.mode === view.mode));
  }
  byId("update-status").textContent = view.status;
  showBanner(byId("settings-note"), view.settings_note);
  showBanner(byId("install-note"), view.install_note);
  byId("check-now").disabled = view.busy;
  byId("install").hidden = !view.can_install;
  byId("install").disabled = !view.available || view.busy;
  byId("restart").hidden = !view.restart_ready;
  byId("open-release-page").hidden = view.can_install;
}

async function refreshUpdates() {
  renderUpdates(await invoke("update_status"));
}

// A press on the mode already in effect also saves it, so the first-run note can clear.
for (const button of document.querySelectorAll(".mode")) {
  button.addEventListener("click", () => invoke("set_update_mode", { mode: button.dataset.mode }));
}
byId("check-now").addEventListener("click", () => invoke("check_for_updates"));
byId("install").addEventListener("click", () => invoke("install_update"));
byId("restart").addEventListener("click", () => invoke("restart_to_update"));
byId("open-release-page").addEventListener("click", async () => {
  showBanner(byId("open-error"), "");
  try {
    await invoke("open_release_page");
  } catch (error) {
    showBanner(byId("open-error"), `Cannot open the release page: ${error}`);
  }
});

byId("blocked-only").addEventListener("change", render);
listen("dashboard-updated", refresh);
listen("updates-changed", refreshUpdates);
refresh();
loadSettings();
refreshUpdates();
