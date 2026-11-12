// Update status and notes can carry text from the release feed, and errors can carry paths.
// Every value reaches the page through textContent or a form value, never as HTML.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const byId = (id) => document.getElementById(id);

function showBanner(element, text) {
  element.hidden = !text;
  element.textContent = text || "";
}

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

const tabs = [...document.querySelectorAll('[role="tab"]')];

function selectedTab() {
  return tabs.find((tab) => tab.getAttribute("aria-selected") === "true");
}

// An unknown name selects the first tab, so a bad fragment or payload never hides every panel.
function selectTab(name, { focus = false } = {}) {
  const chosen = tabs.find((tab) => tab.dataset.tab === name) || tabs[0];
  for (const tab of tabs) {
    const selected = tab === chosen;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    byId(tab.getAttribute("aria-controls")).hidden = !selected;
  }
  if (focus) chosen.focus();
  if (chosen.dataset.tab === "servers") scanServers();
}

for (const tab of tabs) {
  tab.addEventListener("click", () => selectTab(tab.dataset.tab));
}

byId("tabs").addEventListener("keydown", (event) => {
  const index = tabs.indexOf(document.activeElement);
  if (index < 0) return;
  const last = tabs.length - 1;
  const next = {
    ArrowLeft: index === 0 ? last : index - 1,
    ArrowRight: index === last ? 0 : index + 1,
    Home: 0,
    End: last,
  }[event.key];
  if (next === undefined) return;
  event.preventDefault();
  selectTab(tabs[next].dataset.tab, { focus: true });
});

// The app has no menu bar, so the page handles the Settings shortcut itself.
document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === ",") {
    event.preventDefault();
    invoke("open_settings", { tab: selectedTab().dataset.tab });
  }
});

function showSettings(view) {
  byId("path-input").value = view.audit_log_path;
  byId("path-input").disabled = view.path_from_variable;
  byId("path-save").disabled = view.path_from_variable;
  byId("path-choose").disabled = view.path_from_variable;
  byId("path-variable-note").hidden = !view.path_from_variable;
  byId("notifications").checked = view.notifications;
}

async function loadSettings() {
  showSettings(await invoke("settings"));
}

async function savePath(text) {
  try {
    showSettings(await invoke("set_audit_log_path", { path: text }));
    showBanner(byId("save-error"), null);
  } catch (message) {
    showBanner(byId("save-error"), String(message));
  }
}

byId("path-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await savePath(byId("path-input").value);
});

byId("path-choose").addEventListener("click", async () => {
  try {
    const path = await invoke("choose_audit_log_path");
    if (path === null) return;
    byId("path-input").value = path;
    await savePath(path);
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
  // After an install, only Restart has an effect until the app restarts.
  const acceptsRequests = !view.busy && !view.restart_ready;
  byId("check-now").disabled = !acceptsRequests;
  byId("install").hidden = !view.can_install;
  byId("install").disabled = !view.available || !acceptsRequests;
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

// Server names, paths, and reasons come from config files that other programs write.
let serverRows = [];
let wrapping = false;

function checkedServerIds() {
  return [...document.querySelectorAll('#servers-rows input[type="checkbox"]:checked')].map(
    (box) => serverRows[Number(box.dataset.index)].id,
  );
}

function updateWrapButton() {
  byId("servers-wrap").disabled = wrapping || checkedServerIds().length === 0;
}

// The id comes from the row index only, never from a server name.
function wrapCell(row, index) {
  const td = document.createElement("td");
  if (!row.selectable) return td;
  const box = document.createElement("input");
  box.type = "checkbox";
  box.id = `wrap-row-${index}`;
  box.dataset.index = String(index);
  box.checked = true;
  box.setAttribute("aria-label", `Wrap ${row.client} ${row.server}`);
  box.addEventListener("change", updateWrapButton);
  td.append(box);
  return td;
}

function showResultLines(lines) {
  byId("servers-results").replaceChildren(
    ...lines.map((line) => {
      const li = document.createElement("li");
      li.textContent = line;
      return li;
    }),
  );
}

function renderServers(view) {
  serverRows = view.rows;
  byId("servers-binary").textContent = view.binary || "not found";
  byId("servers-audit-log").textContent = view.audit_log_path;
  const count = view.wrapped === 1 ? "1 server is" : `${view.wrapped} servers are`;
  byId("servers-summary").textContent = `${count} wrapped in the proxy.`;
  byId("servers-notes").replaceChildren(
    ...view.notes.map((note) => {
      const li = document.createElement("li");
      li.textContent = note;
      return li;
    }),
  );
  showBanner(byId("servers-problem"), view.problem);
  let empty = null;
  if (view.rows.length === 0) {
    empty = view.wrapped === 0 ? "The app found no MCP client config." : "Every server it found is wrapped.";
  }
  showBanner(byId("servers-empty"), empty);
  fillRows(
    byId("servers-rows"),
    view.rows.map((row, index) => [
      wrapCell(row, index),
      cell(row.client),
      cell(row.scope),
      cell(row.server),
      cell(row.status),
      cell(row.reason || ""),
    ]),
  );
  updateWrapButton();
}

async function scanServers() {
  renderServers(await invoke("servers"));
}

function setWrapping(on) {
  wrapping = on;
  byId("servers-scan").disabled = on;
  updateWrapButton();
}

// The result lines stay after the scan that follows a wrap, until the next Wrap or Scan press.
byId("servers-scan").addEventListener("click", async () => {
  showResultLines([]);
  await scanServers();
});

byId("servers-wrap").addEventListener("click", async () => {
  const rows = checkedServerIds();
  showResultLines(["Wrapping…"]);
  setWrapping(true);
  try {
    const report = await invoke("wrap_servers", { rows });
    showResultLines(report.results.map((result) => `${result.client} ${result.server}: ${result.message}`));
    await scanServers();
  } catch (message) {
    showResultLines([]);
    showBanner(byId("servers-problem"), String(message));
  } finally {
    setWrapping(false);
  }
});

selectTab(location.hash.slice(1));
listen("settings-tab", (event) => selectTab(event.payload));
listen("updates-changed", refreshUpdates);
loadSettings();
refreshUpdates();
