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

// The blocked numbers of the unread rows the person ticked.
const selected = new Set();

// Only a blocked call is read or unread. A forwarded call gets an empty cell, and an unread
// call gets a checkbox that selects it for Mark selected as read.
function readCell(event) {
  if (event.forwarded) return cell("");
  if (!event.unread) return cell("Read", "read");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.id = `select-${event.blocked_number}`;
  box.checked = selected.has(event.blocked_number);
  box.addEventListener("change", () => {
    if (box.checked) selected.add(event.blocked_number);
    else selected.delete(event.blocked_number);
    byId("mark-selected").disabled = selected.size === 0;
  });
  const label = document.createElement("label");
  label.append(box, "Unread");
  const td = cell("", "unread");
  td.append(label);
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
  byId("stat-unread").textContent = latest.unread_blocked;
  // A selected row that is now read, or that left the list, is no longer selected.
  const unread = new Set(events.filter((e) => e.unread).map((e) => e.blocked_number));
  for (const call of selected) if (!unread.has(call)) selected.delete(call);
  byId("mark-selected").disabled = selected.size === 0;
  byId("mark-all").disabled = latest.unread_blocked === 0;
  fillRows(byId("sessions"), sessions.map((s) => [
    cell(s.session_id), cell(s.taint_level, s.taint_level), cell(s.calls), cell(s.blocked), cell(dateTime(s.last_seen_ms)),
  ]));
  const shown = byId("blocked-only").checked ? events.filter((e) => !e.forwarded) : events;
  fillRows(byId("events"), shown.map((e) => [
    cell(time(e.timestamp_ms)), cell(e.tool_name), cell(e.decision, e.decision), readCell(e), cell(e.rule_id), cell(e.reason),
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

// The app marks read only the blocked calls this page shows: a call that arrives after this
// snapshot stays unread.
function markAllRead() {
  if (!latest) return;
  invoke("mark_blocked_read", { logPath: latest.log_path, seenBlocked: latest.total_blocked });
}

function markSelectedRead() {
  if (!latest) return;
  invoke("mark_calls_read", { logPath: latest.log_path, calls: [...selected] });
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
byId("mark-selected").addEventListener("click", markSelectedRead);
byId("mark-all").addEventListener("click", markAllRead);
listen("dashboard-updated", refresh);
listen("settings-changed", refreshSettingsProblem);
refresh();
refreshSettingsProblem();
