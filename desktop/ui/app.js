// Audit fields carry text an attacker can influence, such as tool names and URIs.
// Every value reaches the page through textContent, never as HTML.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const byId = (id) => document.getElementById(id);
const time = (ms) => new Date(ms).toLocaleTimeString();
const dateTime = (ms) => new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });

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
    cell(s.session_id), cell(s.taint_level, s.taint_level), cell(s.calls), cell(s.blocked), cell(dateTime(s.last_seen_ms)),
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

async function refreshSettingsProblem() {
  const view = await invoke("settings");
  showBanner(byId("settings-problem"), view.problem);
}

function openSettings() {
  invoke("open_settings", { tab: "general" });
}

// The app has no menu bar, so the page handles the Settings shortcut itself.
document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === ",") {
    event.preventDefault();
    openSettings();
  }
});

byId("open-settings").addEventListener("click", openSettings);
byId("blocked-only").addEventListener("change", render);
listen("dashboard-updated", refresh);
listen("settings-changed", refreshSettingsProblem);
refresh();
refreshSettingsProblem();
