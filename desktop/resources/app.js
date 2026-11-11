"use strict";

const $ = id => document.getElementById(id);
const icon = name => { const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg"); const use = document.createElementNS(svg.namespaceURI, "use"); use.setAttribute("href", "#i-" + name); svg.append(use); return svg; };
const state = { settings: null, catalog: [], presets: {}, credentials: {}, endpoint: {}, dirty: false, running: false, latestProgress: null, frame: null, lastPercent: 0, logKey: "", railKey: "", keyDrafts: {}, currentTab: "collectors", toastTimer: null, result: null, rememberedConfig: null };
const providerNames = { offline: "Offline local summary", openai: "OpenAI", gemini: "Google Gemini", anthropic: "Anthropic" };

async function native(method, ...args) {
  if (!window.pywebview?.api?.[method]) throw new Error("The native desktop bridge is unavailable. Open POLARIS through polaris.exe or python main.py.");
  return await window.pywebview.api[method](...args);
}
function toast(message, error = false) {
  $("toast").textContent = message; $("toast").classList.toggle("error", error); $("toast").hidden = false;
  clearTimeout(state.toastTimer); state.toastTimer = setTimeout(() => { $("toast").hidden = true; }, error ? 6500 : 3600);
}
function showView(name) {
  document.querySelectorAll("main>.view").forEach(view => { view.hidden = view.id !== name + "-view"; });
  window.scrollTo({ top: 0 });
}
function setDetailsExpanded(expanded) {
  const hasResult = !!state.result;
  $("processing-details").hidden = !hasResult && !expanded;
  for (const id of ["run-details", "operation-details", "result-details"]) $(id).hidden = hasResult && !expanded;
  $("processing-view").classList.toggle("has-result", hasResult);
  $("processing-view").classList.toggle("compact-results", hasResult && !expanded);
  $("toggle-processing-details").setAttribute("aria-controls", hasResult ? "run-details operation-details result-details" : "processing-details");
  $("toggle-processing-details").setAttribute("aria-expanded", String(expanded));
  $("details-toggle-label").textContent = hasResult ? expanded ? "Hide diagnostics" : "Show diagnostics" : expanded ? "Hide details" : "Show details";
  if (expanded) $("activity-log").scrollTop = $("activity-log").scrollHeight;
}
function dirty() { state.dirty = true; $("save-status").textContent = "Unsaved changes · retained while switching views"; renderSetup(); }
function captureSettings() {
  if (!state.settings) return;
  Object.assign(state.settings, { ai_enabled: $("ai-enabled").checked, ai_provider: $("ai-provider").value, ai_model: $("ai-model").value.trim(), parse: $("parse-enabled").checked, output_dir: $("output-folder").value.trim(), examiner: $("examiner").value.trim(), description: $("description").value.trim() });
  state.settings.ai_models ||= {}; state.settings.ai_models[state.settings.ai_provider] = state.settings.ai_model;
}
function hydrateSettings() {
  const settings = state.settings;
  $("examiner").value = settings.examiner; $("description").value = settings.description; $("output-folder").value = settings.output_dir; $("parse-enabled").checked = settings.parse;
  $("ai-enabled").checked = settings.ai_enabled; $("ai-provider").value = settings.ai_provider; $("ai-model").value = settings.ai_model;
  $("api-key").value = state.keyDrafts[settings.ai_provider] || ""; $("api-key").type = "password"; $("show-key").setAttribute("aria-pressed", "false");
  applyMotion(); renderAI(); renderCollectors(); renderSetup();
}
function customized() { const preset = state.presets[state.settings.profile] || []; return preset.length !== state.settings.modules.length || preset.some(id => !state.settings.modules.includes(id)); }
function profileLabel() { return (state.settings.profile === "quick" ? "Quick Acquisition" : "Full Acquisition") + (customized() ? " — Customized" : ""); }
function renderSetup() {
  if (!state.settings) return;
  const active = state.settings.profile;
  for (const mode of ["quick", "full"]) {
    $(mode + "-card").classList.toggle("selected", mode === active); $(mode + "-card").setAttribute("aria-checked", String(mode === active));
    $(mode + "-count").textContent = mode === active ? state.settings.modules.length : state.presets[mode].length;
    $(mode + "-custom").hidden = mode !== active || !customized();
  }
  $("profile-summary").textContent = profileLabel(); $("collector-summary").textContent = state.settings.modules.length + " collectors";
  $("ai-summary").textContent = state.settings.ai_enabled ? "AI · " + providerNames[state.settings.ai_provider] : "AI assistance off";
  $("setup-output").textContent = "CASE STORAGE / " + state.settings.output_dir;
  $("permission-summary").textContent = state.endpoint.admin ? "ADMINISTRATOR · FULL ACCESS" : "STANDARD USER · SOME COLLECTORS REQUIRE ADMIN";
  $("review-acquisition").disabled = state.settings.modules.length === 0 || state.running;
  $("module-selection-label").textContent = `${state.settings.modules.length} of ${state.catalog.length} supported collectors enabled${customized() ? " · Customized profile" : ""}.`;
  $("tab-count").textContent = state.settings.modules.length;
}
function choosePreset(mode) { captureSettings(); state.settings.profile = mode; state.settings.modules = [...state.presets[mode]]; dirty(); renderCollectors(); }
function renderCollectors() {
  const query = $("collector-search").value.trim().toLowerCase(); const list = $("collector-list"); list.replaceChildren();
  const matches = state.catalog.filter(module => `${module.name} ${module.description} ${module.category}`.toLowerCase().includes(query));
  if (!matches.length) { const p = document.createElement("p"); p.textContent = "No collectors match your search."; p.className = "muted"; list.append(p); return; }
  for (const module of matches) {
    const enabled = state.settings.modules.includes(module.id);
    const row = document.createElement("label"); row.className = "collector-row" + (enabled ? " enabled" : ""); row.dataset.module = module.id;
    const glyph = document.createElement("span"); glyph.className = "collector-icon"; glyph.append(icon(module.category === "network" ? "screen" : module.category === "execution" ? "bolt" : module.category === "persistence" ? "shield" : "database"));
    const info = document.createElement("span"); info.className = "collector-info"; const title = document.createElement("strong"); title.textContent = module.name;
    const description = document.createElement("p"); description.textContent = module.description;
    const meta = document.createElement("span"); meta.className = "collector-meta"; const category = document.createElement("span"); category.textContent = module.category.replaceAll("_", " ").toUpperCase(); meta.append(category);
    if (module.sensitive) { const tag = document.createElement("span"); tag.className = "sensitive"; tag.textContent = "SENSITIVE EVIDENCE"; meta.append(tag); }
    if (module.dependencies.length) { const dependency = document.createElement("span"); dependency.textContent = "REQUIRES " + module.dependencies.join(", "); meta.append(dependency); }
    info.append(title, description, meta);
    const permission = document.createElement("span"); permission.className = "collector-permission"; permission.textContent = module.privileges === "admin" ? "ADMIN" : "USER";
    const input = document.createElement("input"); input.type = "checkbox"; input.className = "toggle-input"; input.checked = enabled; input.setAttribute("aria-label", "Enable " + module.name);
    const toggle = document.createElement("span"); toggle.className = "toggle"; toggle.setAttribute("aria-hidden", "true");
    const caption = document.createElement("span"); caption.className = "toggle-caption"; caption.textContent = enabled ? "ON" : "OFF";
    input.addEventListener("change", () => {
      if (!input.checked && state.settings.modules.length === 1) { input.checked = true; toast("Keep at least one collector enabled.", true); return; }
      const requiredBy = state.catalog.filter(m => state.settings.modules.includes(m.id) && m.dependencies.includes(module.id));
      if (!input.checked && requiredBy.length) { input.checked = true; toast("Required by " + requiredBy.map(m => m.name).join(", ") + ". Disable that collector first.", true); return; }
      state.settings.modules = input.checked ? [...state.settings.modules, module.id] : state.settings.modules.filter(id => id !== module.id);
      row.classList.toggle("enabled", input.checked); caption.textContent = input.checked ? "ON" : "OFF"; dirty();
    });
    row.append(glyph, info, permission, input, toggle, caption); list.append(row);
  }
}
function showTab(name) {
  captureSettings(); state.currentTab = name;
  for (const tab of ["collectors", "ai"]) { $(tab + "-tab").classList.toggle("active", tab === name); $(tab + "-tab").setAttribute("aria-selected", String(tab === name)); $(tab + "-section").hidden = tab !== name; }
}
function setConnectionStatus(kind, message) {
  const status = $("connection-status"); status.className = "connection-status " + kind; status.replaceChildren();
  const dot = document.createElement("span"); dot.className = "status-dot" + (kind === "" ? " muted-dot" : ""); status.append(dot, document.createTextNode(message));
}
function renderAI() {
  const provider = $("ai-provider").value; const offline = provider === "offline";
  $("external-ai-fields").hidden = offline; $("model-label").hidden = offline; $("offline-ai-description").hidden = !offline;
  const credentials = state.credentials[provider];
  setConnectionStatus("", credentials?.configured ? "A protected or session key is available. Test the connection to validate it." : "AI provider not configured.");
  $("api-key").placeholder = credentials?.configured ? "Stored key available · enter a key to replace it" : "Paste your API key";
  $("key-storage-status").textContent = credentials?.persistent ? "Key protected with Windows DPAPI for this Windows account." : "Keys remain in this session until saved with Windows DPAPI protection.";
}
async function saveConfiguration() {
  captureSettings(); const button = $("save-configuration"); button.disabled = true;
  try {
    const response = await native("save_configuration", state.settings, $("api-key").value, $("remember-key").checked);
    if (!response.ok) throw new Error(response.error);
    state.credentials[state.settings.ai_provider] = response.credential; $("api-key").value = ""; delete state.keyDrafts[state.settings.ai_provider];
    state.dirty = false; state.rememberedConfig = structuredClone(state.settings); $("save-status").textContent = "Configuration saved"; renderAI(); toast("Configuration saved. Your API key is kept separate from preferences."); return true;
  } catch (error) { toast(error.message, true); $("save-status").textContent = "Configuration could not be saved"; return false; } finally { button.disabled = false; }
}
async function testConnection() {
  captureSettings(); const button = $("test-connection"); button.disabled = true; setConnectionStatus("testing", "Validating API connection… No forensic evidence is sent.");
  const provider = state.settings.ai_provider; const model = state.settings.ai_model;
  try {
    const response = await native("test_connection", provider, model, $("api-key").value);
    if (provider !== $("ai-provider").value || model !== $("ai-model").value.trim()) return;
    if (response.ok) { state.credentials[provider] = { configured: true, persistent: state.credentials[provider]?.persistent || false }; setConnectionStatus("connected", response.message); }
    else setConnectionStatus("failed", response.error || "Connection failed. Check the key, model and network.");
  } catch (error) { setConnectionStatus("failed", error.message); } finally { button.disabled = false; }
}
function reviewAcquisition() {
  captureSettings(); if (!state.settings.modules.length) { toast("Enable at least one collector.", true); return; }
  const summary = $("acquisition-summary"); summary.replaceChildren();
  const keyAvailable = state.credentials[state.settings.ai_provider]?.configured || $("api-key").value.trim();
  const aiLabel = !state.settings.ai_enabled ? "Disabled" : state.settings.ai_provider === "offline" ? "Enabled · local summary" : keyAvailable && state.settings.ai_model ? "Enabled · approval after collection" : "Skipped until key & model are configured";
  for (const [label, value] of [["Acquisition profile", profileLabel()], ["Collectors enabled", String(state.settings.modules.length)], ["Collectors disabled", String(state.catalog.length - state.settings.modules.length)], ["Artifact parsing", state.settings.parse ? "Enabled" : "Raw acquisition only"], ["AI assistance", aiLabel], ["AI provider", providerNames[state.settings.ai_provider]], ["Output folder", state.settings.output_dir]]) { const dt = document.createElement("dt"); dt.textContent = label; const dd = document.createElement("dd"); dd.textContent = value; summary.append(dt, dd); }
  const notices = [];
  if (state.settings.profile === "full") notices.push("Full acquisition may take longer and collect more data.");
  if (state.settings.modules.some(id => id.startsWith("browser_"))) notices.push("Browser collection includes browsing visits, downloads, bookmarks, recorded searches, extensions and site permissions from this Windows account. Browser passwords, cookies, autofill and session data are excluded. Collect only within your authorized investigation scope.");
  if (state.settings.modules.includes("sensitive_files")) notices.push("The sensitive-file collector includes credential, key and wallet files, and may scan beyond standard artifact locations.");
  if (!state.endpoint.admin && state.catalog.some(m => m.privileges === "admin" && state.settings.modules.includes(m.id))) notices.push("Administrator-only collectors will be skipped in the current standard-user session.");
  $("scope-notice").textContent = notices.join(" "); $("elevate").hidden = state.endpoint.admin || !state.catalog.some(m => m.privileges === "admin" && state.settings.modules.includes(m.id));
  $("summary-dialog").showModal();
}
async function startAcquisition() {
  const button = $("confirm-start"); if (state.running) return;
  if (!$("case-id").checkValidity()) { $("case-id").reportValidity(); return; }
  button.disabled = true;
  try {
    captureSettings(); state.running = true; state.result = null; state.latestProgress = null; state.lastPercent = 0; state.logKey = ""; state.railKey = "";
    if (state.frame) { cancelAnimationFrame(state.frame); state.frame = null; }
    $("summary-dialog").close(); $("activity-log").replaceChildren(); $("stage-rail").replaceChildren(); $("result-panel").hidden = true;
    $("processing-panel").className = "glass processing-panel"; $("progress-fill").style.setProperty("--progress", "0%"); $("progress-track").classList.add("indeterminate"); $("progress-track").removeAttribute("aria-valuenow"); $("progress-percentage").textContent = "—"; $("processed-modules").textContent = `0 / ${state.settings.modules.length}`; $("elapsed-time").textContent = "0s";
    $("cancel-acquisition").hidden = false; $("cancel-acquisition").disabled = false; $("run-heading").textContent = "Following the evidence."; $("run-eyebrow").textContent = "LIVE EVIDENCE ACQUISITION"; $("run-subtitle").textContent = "Your selected collectors are running in the background."; $("processing-title").textContent = "Executing Background Processes..."; $("processing-icon").replaceChildren(); $("processing-icon").append(icon("layers").firstChild);
    setDetailsExpanded(false); showView("processing");
    const response = await native("start_acquisition", state.settings, $("case-id").value, $("api-key").value);
    if (!response.ok) throw new Error(response.error);
  } catch (error) { state.running = false; showView("setup"); renderSetup(); toast(error.message, true); } finally { button.disabled = false; }
}
function formatDuration(seconds) { const value = Math.floor(Math.max(0, seconds)); return value >= 3600 ? `${Math.floor(value / 3600)}h ${Math.floor(value % 3600 / 60)}m` : value >= 60 ? `${Math.floor(value / 60)}m ${value % 60}s` : `${value}s`; }
function recordOperation(event) {
  const key = event.operation + "|" + event.detail;
  if (key !== state.logKey) { state.logKey = key; const li = document.createElement("li"); li.textContent = event.operation + (event.detail ? " · " + event.detail : ""); $("activity-log").append(li); while ($("activity-log").children.length > 12) $("activity-log").firstChild.remove(); $("activity-log").scrollTop = $("activity-log").scrollHeight; }
}
function renderProgress(event) {
  const terminal = ["COMPLETED", "FAILED", "CANCELLED"].includes(event.state);
  $("live-state").textContent = event.state; $("current-operation").textContent = event.operation; $("progress-detail").textContent = event.error || event.detail || event.operation;
  $("elapsed-time").textContent = formatDuration(event.elapsed_seconds);
  if (event.stage === "collecting" && event.total) $("processed-modules").textContent = `${event.completed} / ${event.total}`;
  if (event.percentage === null) { $("progress-percentage").textContent = "—"; $("progress-track").classList.add("indeterminate"); $("progress-track").removeAttribute("aria-valuenow"); $("work-count").textContent = "Workload not yet known"; }
  else { const percentage = terminal && (event.workflow_completed || event.state === "COMPLETED") ? 100 : Math.min(99.9, event.percentage); state.lastPercent = percentage; $("progress-percentage").textContent = `${percentage === 100 ? 100 : Math.floor(percentage)}%`; $("progress-fill").style.setProperty("--progress", percentage + "%"); $("progress-track").classList.remove("indeterminate"); $("progress-track").setAttribute("aria-valuenow", String(percentage)); $("work-count").textContent = terminal ? "Processing finished" : event.total ? `${event.completed} / ${event.total} stage units` : "Completed weighted work"; }
  $("eta-label").hidden = !(event.eta_seconds > 0); if (event.eta_seconds > 0) $("eta-label").textContent = formatDuration(event.eta_seconds) + " remaining";
  recordOperation(event);
  const railKey = JSON.stringify(event.stages);
  if (railKey !== state.railKey) { state.railKey = railKey; $("stage-rail").replaceChildren(); for (const stage of event.stages) { const item = document.createElement("span"); item.className = "stage-item " + stage.state; const marker = document.createElement("span"); marker.className = "stage-marker"; marker.textContent = stage.state === "completed" ? "✓" : ""; item.append(marker, document.createTextNode(stage.label.toUpperCase())); $("stage-rail").append(item); } }
  if (terminal) { $("processing-panel").classList.add("terminal", event.workflow_completed ? "completed" : event.state.toLowerCase()); $("processing-title").textContent = event.operation; $("cancel-acquisition").hidden = true; }
}
function renderResult(result) {
  state.running = false; state.result = result; $("result-panel").hidden = false;
  if (state.frame) { cancelAnimationFrame(state.frame); state.frame = null; }
  if (state.latestProgress) renderProgress(state.latestProgress);
  const workflowCompleted = result.workflow_completed || result.state === "COMPLETED";
  $("processing-panel").classList.remove("completed", "failed", "cancelled");
  $("processing-panel").classList.add("terminal", workflowCompleted && result.completion_reason !== "integrity_gaps" ? "completed" : result.state.toLowerCase());
  if (workflowCompleted) { state.lastPercent = 100; $("progress-percentage").textContent = "100%"; $("progress-fill").style.setProperty("--progress", "100%"); $("progress-track").classList.remove("indeterminate"); $("progress-track").setAttribute("aria-valuenow", "100"); $("work-count").textContent = "Processing finished"; $("eta-label").hidden = true; }
  const completed = result.state === "COMPLETED"; const cancelled = result.state === "CANCELLED";
  const heading = completed ? "Investigation complete" : cancelled ? "Acquisition cancelled" : workflowCompleted && result.completion_reason === "integrity_gaps" ? "Reports ready — review integrity" : workflowCompleted ? "Finished with collection gaps" : "Acquisition stopped";
  $("run-heading").textContent = heading; $("run-eyebrow").textContent = completed ? "EVIDENCE PRESERVED" : cancelled ? "SAFE CANCELLATION" : "REVIEW THE DIAGNOSTICS";
  $("run-subtitle").textContent = completed ? "Your reports and evidence package are ready." : "Available evidence and diagnostic information have been preserved.";
  $("processing-title").textContent = workflowCompleted && result.completion_reason !== "integrity_gaps" ? "Acquisition complete" : heading;
  $("result-title").textContent = heading; $("result-description").textContent = result.error || (result.warnings?.length ? result.warnings.join(" · ") : "Selected acquisition operations completed and the archive was saved.");
  $("result-icon").replaceChildren(icon(completed ? "check" : cancelled ? "stop" : "warning"));
  $("result-stats").replaceChildren(); for (const [name, count] of [["files acquired", result.artifact_count], ["hashes verified", result.verified_count], ["findings", result.finding_count], ["timeline events", result.event_count]]) { if (count !== undefined) { const span = document.createElement("span"); span.textContent = count + " " + name; $("result-stats").append(span); } }
  $("case-location").textContent = result.case_dir || "No case folder was created."; $("case-location").hidden = !result.case_dir;
  $("open-report").hidden = !result.outputs?.report; $("open-folder").disabled = !result.case_dir; $("open-archive").hidden = !result.outputs?.archive;
  $("open-verification").hidden = !result.outputs?.verification;
  $("processed-modules").textContent = result.modules?.length ? `${result.modules.length} / ${state.settings.modules.length}` : $("processed-modules").textContent;
  $("cancel-acquisition").hidden = true; if ($("consent-dialog").open) $("consent-dialog").close();
  setDetailsExpanded(false);
  if (result.output_open_errors?.length) toast(result.output_open_errors.join(" · "), true);
}
function receive(event) {
  if (event.type === "progress") { recordOperation(event.data); state.latestProgress = event.data; if (!state.frame) state.frame = requestAnimationFrame(() => { state.frame = null; renderProgress(state.latestProgress); }); }
  else if (event.type === "result") renderResult(event.data);
  else if (event.type === "consent") { $("evidence-preview").textContent = event.data.prompt; $("consent-dialog").showModal(); }
  else if (event.type === "close_requested") { if (state.running) { if (!$("close-dialog").open) $("close-dialog").showModal(); } else if (state.dirty) { if (!$("unsaved-dialog").open) $("unsaved-dialog").showModal(); } else native("request_close"); }
}
window.Polaris = { receive };

const video = $("background-video"); const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
function maskArtwork() {
  // The supplied artwork's sample panel starts at 73% of its height. Calculate
  // the rendered cover rectangle, so its entire panel is masked at every ratio.
  const width = video.videoWidth || $("background-image").naturalWidth || 1672; const height = video.videoHeight || $("background-image").naturalHeight || 941;
  const scale = Math.max(innerWidth / width, innerHeight / height); const renderedHeight = height * scale;
  const start = Math.max(0, (innerHeight - renderedHeight) / 2 + renderedHeight * .715);
  $("artwork-mask").style.top = start + "px"; $("artwork-gradient").style.top = Math.max(0, start - 100) + "px"; $("artwork-gradient").style.height = Math.min(start, 100) + "px";
}
function applyMotion() {
  const reduced = !!state.settings?.reduced_motion || reduceMotion.matches; document.body.classList.toggle("reduced-motion", reduced); $("motion-toggle").setAttribute("aria-pressed", String(reduced));
  if (reduced) { video.pause(); video.classList.remove("playing"); }
  else { video.muted = true; video.loop = true; const play = video.play(); if (play) play.catch(() => video.classList.remove("playing")); }
}
video.addEventListener("playing", () => { if (!document.body.classList.contains("reduced-motion")) video.classList.add("playing"); });
video.addEventListener("error", () => video.classList.remove("playing")); video.addEventListener("loadedmetadata", maskArtwork); $("background-image").addEventListener("load", maskArtwork); window.addEventListener("resize", maskArtwork); reduceMotion.addEventListener("change", applyMotion); maskArtwork();

async function bootstrap() {
  try {
    const data = await native("bootstrap"); Object.assign(state, { settings: data.settings, catalog: data.collectors, presets: data.presets, credentials: data.credentials, endpoint: data.endpoint });
    state.rememberedConfig = structuredClone(data.settings); $("endpoint-name").textContent = data.endpoint.hostname + " / " + data.endpoint.os;
    $("remember-key").disabled = !data.persistent_secrets_supported; $("remember-key").checked = data.persistent_secrets_supported;
    hydrateSettings(); showView("setup");
  } catch (error) { $("loading-message").textContent = error.message; $("loading-view").querySelector("p").textContent = "Unable to open the investigation workspace"; $("loading-view").querySelector(".loading-orbit").style.animation = "none"; }
}

for (const mode of ["quick", "full"]) $(mode + "-card").addEventListener("click", () => choosePreset(mode));
$("more-options").addEventListener("click", () => { showView("options"); });
$("back-to-setup").addEventListener("click", () => { captureSettings(); renderSetup(); showView("setup"); });
$("brand-home").addEventListener("click", event => { event.preventDefault(); if (!state.running && state.settings) { captureSettings(); renderSetup(); showView("setup"); } });
$("collectors-tab").addEventListener("click", () => showTab("collectors")); $("ai-tab").addEventListener("click", () => showTab("ai"));
$("collector-search").addEventListener("input", renderCollectors); $("reset-quick").addEventListener("click", () => choosePreset("quick")); $("enable-all").addEventListener("click", () => { captureSettings(); state.settings.profile = "full"; state.settings.modules = state.catalog.map(module => module.id); dirty(); renderCollectors(); });
$("disable-optional").addEventListener("click", () => { const minimum = state.catalog.find(m => m.id === "system_info") || state.catalog[0]; if (minimum) { state.settings.modules = [minimum.id]; dirty(); renderCollectors(); toast("Optional collectors disabled. " + minimum.name + " remains enabled to keep a valid acquisition plan."); } });
for (const id of ["examiner", "description", "output-folder", "parse-enabled", "ai-enabled", "ai-model"]) $(id).addEventListener("input", () => { captureSettings(); dirty(); if (id === "ai-model") setConnectionStatus("", "Model changed. Test the connection to validate it."); });
$("api-key").addEventListener("input", () => { state.keyDrafts[$("ai-provider").value] = $("api-key").value; dirty(); setConnectionStatus("", "Key entered for this session. Test the connection to validate it."); });
$("ai-provider").addEventListener("change", () => { const old = state.settings.ai_provider; state.keyDrafts[old] = $("api-key").value; state.settings.ai_models ||= {}; state.settings.ai_models[old] = $("ai-model").value.trim(); state.settings.ai_provider = $("ai-provider").value; $("ai-model").value = state.settings.ai_models[state.settings.ai_provider] || ""; $("api-key").value = state.keyDrafts[state.settings.ai_provider] || ""; $("api-key").type = "password"; $("show-key").setAttribute("aria-pressed", "false"); $("model-list").replaceChildren(); captureSettings(); renderAI(); dirty(); });
$("show-key").addEventListener("click", () => { const show = $("api-key").type === "password"; $("api-key").type = show ? "text" : "password"; $("show-key").setAttribute("aria-pressed", String(show)); $("show-key").setAttribute("aria-label", show ? "Hide entered API key" : "Show entered API key"); });
$("save-configuration").addEventListener("click", saveConfiguration); $("test-connection").addEventListener("click", testConnection);
$("remember-key").addEventListener("change", dirty);
$("load-models").addEventListener("click", async () => { const button = $("load-models"); button.disabled = true; const provider = $("ai-provider").value; try { const result = await native("list_models", provider, $("api-key").value); if (!result.ok) throw new Error(result.error); if (provider !== $("ai-provider").value) return; $("model-list").replaceChildren(...result.models.map(model => { const option = document.createElement("option"); option.value = model; return option; })); toast(result.models.length + " current model identifiers loaded. Choose a model or enter one manually."); } catch (error) { toast(error.message, true); } finally { button.disabled = false; } });
$("clear-key").addEventListener("click", async () => { try { const provider = $("ai-provider").value; const result = await native("clear_api_key", provider); if (!result.ok) throw new Error(result.error); $("api-key").value = ""; delete state.keyDrafts[provider]; state.credentials[provider] = { configured: false, persistent: false }; renderAI(); toast("API key cleared from the session and protected storage."); } catch (error) { toast(error.message, true); } });
$("browse-output").addEventListener("click", async () => { try { const folder = await native("choose_output_folder"); if (folder) { $("output-folder").value = folder; captureSettings(); dirty(); } } catch (error) { toast(error.message, true); } });
$("reset-defaults").addEventListener("click", () => { if (state.dirty && !window.confirm("Restore Quick collector defaults and disable AI? Your unsaved preferences will be replaced. Entered keys remain in this session.")) return; captureSettings(); state.settings.profile = "quick"; state.settings.modules = [...state.presets.quick]; state.settings.ai_enabled = false; state.settings.ai_provider = "offline"; state.settings.ai_model = ""; state.settings.parse = true; state.settings.reduced_motion = false; hydrateSettings(); dirty(); toast("Quick defaults restored. Save Configuration to keep them."); });
$("review-acquisition").addEventListener("click", reviewAcquisition); $("confirm-start").addEventListener("click", startAcquisition);
document.querySelectorAll("#summary-dialog .dialog-close").forEach(button => button.addEventListener("click", () => $("summary-dialog").close()));
$("elevate").addEventListener("click", async () => { try { captureSettings(); const response = await native("restart_elevated", state.settings); if (!response.ok) throw new Error(response.error); } catch (error) { toast(error.message, true); } });
$("cancel-acquisition").addEventListener("click", async () => { try { const response = await native("cancel_acquisition"); if (!response.ok) throw new Error(response.error); $("cancel-acquisition").disabled = true; toast(response.message); } catch (error) { toast(error.message, true); } });
$("toggle-processing-details").addEventListener("click", () => setDetailsExpanded($("toggle-processing-details").getAttribute("aria-expanded") !== "true"));
for (const [id, kind] of [["open-report", "report"], ["open-folder", "folder"], ["open-archive", "archive"], ["open-verification", "verification"]]) $(id).addEventListener("click", async () => { try { const response = await native("open_output", kind); if (!response.ok) throw new Error(response.error); } catch (error) { toast(error.message, true); } });
$("new-investigation").addEventListener("click", () => { $("case-id").value = ""; showView("setup"); renderSetup(); });
async function respondConsent(approved) { try { const result = await native("respond_ai_consent", approved); if (!result.ok) throw new Error(result.error); $("consent-dialog").close(); $("evidence-preview").textContent = ""; } catch (error) { toast(error.message, true); } }
$("approve-ai").addEventListener("click", () => respondConsent(true)); $("decline-ai").addEventListener("click", () => respondConsent(false)); $("consent-dialog").addEventListener("cancel", event => { event.preventDefault(); respondConsent(false); });
$("keep-running").addEventListener("click", () => $("close-dialog").close()); $("cancel-and-close").addEventListener("click", async () => { $("close-dialog").close(); await native("request_close", true); });
$("keep-editing").addEventListener("click", () => $("unsaved-dialog").close());
$("discard-close").addEventListener("click", () => native("request_close"));
$("save-close").addEventListener("click", async () => { if (await saveConfiguration()) await native("request_close"); });
$("fullscreen").addEventListener("click", async () => { try { await native("toggle_fullscreen"); } catch (error) { toast(error.message, true); } });
$("motion-toggle").addEventListener("click", () => { if (state.settings) { state.settings.reduced_motion = !state.settings.reduced_motion; applyMotion(); dirty(); } });
document.addEventListener("keydown", event => { if (event.key === "F11") { event.preventDefault(); $("fullscreen").click(); } });
if (window.pywebview?.api) bootstrap(); else window.addEventListener("pywebviewready", bootstrap, { once: true });
