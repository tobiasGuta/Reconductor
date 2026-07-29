"use strict";

const state = {
  data: null,
  selectedProgram: localStorage.getItem("reconductor.program") || "",
  view: "overview",
  loading: false,
  timer: null,
  modalAction: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function element(tag, className = "", text = "") {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== "") item.textContent = String(text);
  return item;
}

function setChildren(target, ...children) {
  target.replaceChildren(...children.filter(Boolean));
}

function shortID(value) {
  return value ? String(value).slice(0, 8) : "—";
}

function formatTime(value, includeDate = false) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return new Intl.DateTimeFormat(undefined, includeDate
    ? { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }
    : { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(date);
}

function relativeTime(value) {
  if (!value) return "Not started";
  const seconds = Math.round((new Date(value).valueOf() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const ranges = [[60, "second"], [60, "minute"], [24, "hour"], [7, "day"], [4.345, "week"], [12, "month"], [Infinity, "year"]];
  let amount = seconds;
  for (const [limit, unit] of ranges) {
    if (Math.abs(amount) < limit) return formatter.format(Math.round(amount), unit);
    amount /= limit;
  }
  return formatter.format(Math.round(amount), "year");
}

function statusBadge(status) {
  const normalized = String(status || "unknown").toLowerCase();
  let tone = "neutral";
  if (["succeeded", "completed", "approved", "open", "confirmed"].includes(normalized)) tone = "";
  if (["pending", "running", "queued", "paused", "paused_operator", "paused_for_approval", "awaiting_approval", "new", "needs_manual_review", "moderate", "medium"].includes(normalized)) tone = "warning";
  if (["failed", "retryable", "rejected", "cancelled", "critical", "high"].includes(normalized)) tone = "danger";
  return element("span", `status-badge ${tone}`.trim(), normalized.replaceAll("_", " "));
}

function empty(message) {
  return element("div", "empty-copy", message);
}

function showView(name) {
  state.view = name;
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $$(".view").forEach((item) => item.classList.toggle("active", item.dataset.viewPanel === name));
  $(".sidebar").classList.remove("open");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function loadData({ quiet = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  if (!quiet) $("#refresh-button").classList.add("loading");
  try {
    const query = state.selectedProgram ? `?program_id=${encodeURIComponent(state.selectedProgram)}` : "";
    const response = await fetch(`/api/v1/snapshot${query}`, { headers: { Accept: "application/json" }, cache: "no-store" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "The control plane did not return a valid snapshot.");
    state.data = body;
    if (body.selected_program_id) {
      state.selectedProgram = body.selected_program_id;
      localStorage.setItem("reconductor.program", state.selectedProgram);
    }
    render();
    setConnection(true);
  } catch (error) {
    setConnection(false);
    if (!state.data) {
      $("#loading-state").classList.add("hidden");
      $("#workspace").classList.add("hidden");
      $("#empty-state").classList.add("hidden");
      $("#error-state").classList.remove("hidden");
      $("#error-message").textContent = error.message;
    } else if (!quiet) {
      toast("Refresh failed. The last good snapshot remains visible.", true);
    }
  } finally {
    state.loading = false;
    $("#refresh-button").classList.remove("loading");
  }
}

function setConnection(online) {
  $("#connection-dot").className = `connection-dot ${online ? "online" : "offline"}`;
  $("#connection-label").textContent = online ? "Connected" : "Disconnected";
}

function render() {
  const data = state.data;
  $("#loading-state").classList.add("hidden");
  $("#error-state").classList.add("hidden");
  if (!data.programs?.length) {
    $("#workspace").classList.add("hidden");
    $("#empty-state").classList.remove("hidden");
    renderProgramSelect([]);
    return;
  }
  $("#empty-state").classList.add("hidden");
  $("#workspace").classList.remove("hidden");
  $("#updated-at").textContent = `Updated ${formatTime(data.generated_at)}`;
  renderProgramSelect(data.programs);
  renderNavCounts();
  renderOverview();
  renderRuns();
  renderSchedules();
  renderChangeInbox();
  renderAssets();
  renderFindings();
  renderApprovals();
  renderQueue();
  renderLogs();
}

function renderProgramSelect(programs) {
  const select = $("#program-select");
  const options = programs.map((program) => {
    const option = element("option", "", program.name);
    option.value = program.id;
    option.selected = program.id === state.selectedProgram;
    return option;
  });
  if (!options.length) {
    const option = element("option", "", "No programs");
    option.value = "";
    options.push(option);
  }
  setChildren(select, ...options);
}

function renderNavCounts() {
  const approvals = state.data.approvals?.filter((item) => item.decision === "pending").length || 0;
  const failed = state.data.queue?.dead_letters?.length || 0;
  const changes = state.data.change_items?.filter((item) => ["unreviewed", ""].includes(item.disposition || "unreviewed") && ["high", "medium"].includes(item.priority)).length || 0;
  setNavCount("#approval-nav-count", approvals);
  setNavCount("#queue-nav-count", failed);
  setNavCount("#changes-nav-count", changes);
}

function setNavCount(selector, count) {
  const item = $(selector);
  item.textContent = count > 99 ? "99+" : String(count);
  item.classList.toggle("hidden", count === 0);
}

function renderOverview() {
  const data = state.data;
  const selected = data.programs.find((item) => item.id === data.selected_program_id);
  $("#overview-subtitle").textContent = selected ? `${selected.name} · ${selected.platform} · deterministic operator control` : "One trusted view of reconnaissance activity.";
  const activeRun = data.runs?.find((run) => ["running", "pending", "paused"].includes(run.status));
  const health = $("#run-health");
  health.className = `health-pill ${activeRun?.status === "paused" ? "warning" : activeRun ? "" : "neutral"}`.trim();
  setChildren(health, element("span"), element("strong", "", activeRun ? `${activeRun.status.replaceAll("_", " ")} · ${shortID(activeRun.id)}` : "No active run"));
  renderMetrics();
  renderWorkflow(data.runs?.[0]);
  renderScope();
  renderChanges();
  renderApprovalPreview();
  renderActivityPreview();
}

function renderMetrics() {
  const stats = state.data.stats || {};
  const queue = state.data.queue || {};
  const values = [
    ["Observed assets", stats.assets || 0, "Persisted identities", ""],
    ["Active runs", stats.active_runs || 0, "Pending, running, paused", stats.active_runs ? "" : ""],
    ["Awaiting approval", stats.pending_approvals || 0, "Human decision required", stats.pending_approvals ? "attention" : ""],
    ["Candidates", stats.candidates || 0, "Not yet verified", stats.candidates ? "attention" : ""],
    ["Verified open", stats.verified_findings || 0, "Confirmed findings", stats.verified_findings ? "danger" : ""],
    ["Failed delivery", (queue.dead_letters || []).length, `${queue.pending || 0} queue pending`, (queue.dead_letters || []).length ? "danger" : ""],
  ];
  setChildren($("#metric-grid"), ...values.map(([label, value, note, tone]) => {
    const card = element("article", `metric-card ${tone}`.trim());
    card.append(element("span", "metric-label", label), element("strong", "metric-value", value), element("small", "metric-note", note));
    return card;
  }));
}

function latestRunSteps(run) {
  if (!run) return [];
  const actual = (state.data.steps || []).filter((step) => step.workflow_run_id === run.id);
  const definition = state.data.workflow_definition?.steps || [];
  if (!definition.length) return actual.sort((a, b) => String(a.started_at || "").localeCompare(String(b.started_at || "")));
  return definition.map((defined) => actual.find((item) => item.step_definition_id === defined.id) || {
    step_definition_id: defined.id,
    capability: defined.capability,
    status: "pending",
    attempt_count: 0,
    approval_state: defined.approval_required ? "required" : "not_required",
    workflow_run_id: run.id,
  });
}

function renderWorkflow(run) {
  const summary = $("#workflow-summary");
  const rail = $("#workflow-rail");
  if (!run) {
    setChildren(summary, empty("No workflow runs have been recorded for this program."));
    rail.replaceChildren();
    return;
  }
  const left = element("div");
  left.append(element("strong", "", run.objective), element("small", "", `${run.workflow_name} · v${run.workflow_version}`));
  const right = element("div");
  right.append(statusBadge(run.status), element("small", "mono", `run ${shortID(run.id)}`));
  setChildren(summary, left, right);
  const steps = latestRunSteps(run);
  setChildren(rail, ...steps.map((step, index) => {
    const node = element("div", `workflow-node ${step.status}`);
    node.title = `${step.step_definition_id}: ${step.status}`;
    const dotText = step.status === "succeeded" ? "✓" : step.status === "running" ? "•" : step.status === "failed" ? "×" : String(index + 1);
    node.append(element("div", "node-dot", dotText), element("strong", "", step.step_definition_id), element("small", "", step.status.replaceAll("_", " ")));
    return node;
  }));
}

function renderScope() {
  const scope = state.data.scope;
  const target = $("#scope-content");
  if (!scope) {
    setChildren(target, empty("No scope snapshot is available."));
    return;
  }
  const stateBadge = $("#scope-state");
  stateBadge.textContent = scope.expands_scope && !scope.acknowledged_at ? "Expansion pending" : "Enforced";
  stateBadge.className = `status-badge ${scope.expands_scope && !scope.acknowledged_at ? "warning" : ""}`.trim();
  const facts = element("div", "scope-facts");
  const reference = element("div", "scope-reference");
  reference.append(element("span", "", "Source reference"), element("strong", "", scope.scope_reference));
  const counts = element("div", "scope-counts");
  for (const [label, value] of [["Include rules", scope.include_rule_count], ["Exclude rules", scope.exclude_rule_count]]) {
    const fact = element("div", "fact");
    fact.append(element("span", "", label), element("strong", "", value));
    counts.append(fact);
  }
  const digest = element("div", "digest");
  digest.append(element("span", "metric-label", "Target plan digest"), element("code", "", scope.target_plan_digest));
  facts.append(reference, counts, digest);
  const warnings = Array.isArray(scope.planning_warnings) ? scope.planning_warnings : [];
  if (warnings.length) {
    const warningList = element("div", "warning-list");
    warnings.slice(0, 3).forEach((warning) => warningList.append(element("div", "warning-row", typeof warning === "string" ? warning : JSON.stringify(warning))));
    facts.append(warningList);
  }
  setChildren(target, facts);
}

function changeRows() {
  const summary = state.data.latest_changes || {};
  return Array.isArray(summary.changes) ? summary.changes : [];
}

function renderChanges() {
  const rows = changeRows();
  const counts = { new: 0, changed: 0, removed: 0, new_or_changed: 0 };
  rows.forEach((item) => { if (item?.kind in counts) counts[item.kind] += 1; });
  if (counts.new_or_changed && !counts.new && !counts.changed) counts.changed = counts.new_or_changed;
  const wrap = element("div", "change-stats");
  [["new", counts.new], ["changed", counts.changed], ["removed", counts.removed]].forEach(([kind, count]) => {
    const item = element("div", `change-stat ${kind}`);
    item.append(element("strong", "", count), element("span", "", kind));
    wrap.append(item);
  });
  if (!rows.length) wrap.append();
  setChildren($("#changes-content"), wrap, !rows.length ? empty("No completed comparison is available yet.") : null);
}

function renderApprovalPreview() {
  const approvals = (state.data.approvals || []).filter((item) => item.decision === "pending");
  const target = $("#approval-preview");
  if (!approvals.length) {
    setChildren(target, empty("No capability is waiting for human approval."));
    return;
  }
  const item = approvals[0];
  const card = element("div", "list-card approval-card");
  const copy = element("div");
  copy.append(element("h3", "", item.reason), element("p", "", item.objective));
  const meta = element("div", "run-meta");
  meta.append(element("span", "", "Risk level"), element("strong", "severity medium", item.risk));
  const button = element("button", "primary-button", "Review decision");
  button.addEventListener("click", () => showView("approvals"));
  card.append(copy, meta, button);
  setChildren(target, card, approvals.length > 1 ? element("p", "empty-copy", `${approvals.length - 1} more request${approvals.length === 2 ? "" : "s"} waiting`) : null);
}

function renderActivityPreview() {
  const events = (state.data.audit_events || []).slice(0, 6);
  setChildren($("#activity-feed"), ...(events.length ? events.map(activityItem) : [empty("No audit events recorded.")]));
}

function activityItem(event) {
  const card = element("div", "activity-item");
  const marker = element("span", "activity-marker");
  const copy = element("div");
  copy.append(element("strong", "", event.safe_message || event.event_type), element("span", "", `${event.component} · ${relativeTime(event.occurred_at)}`));
  card.append(marker, copy);
  return card;
}

function renderRuns() {
  const target = $("#runs-list");
  const runs = state.data.runs || [];
  if (!runs.length) {
    setChildren(target, empty("No workflow runs have been persisted."));
    return;
  }
  setChildren(target, ...runs.map((run) => {
    const steps = (state.data.steps || []).filter((step) => step.workflow_run_id === run.id);
    const completed = steps.filter((step) => ["succeeded", "skipped"].includes(step.status)).length;
    const progress = steps.length ? Math.round((completed / steps.length) * 100) : 0;
    const card = element("article", "run-card");
    card.tabIndex = 0;
    card.setAttribute("role", "button");
    const copy = element("div");
    copy.append(element("h3", "", run.objective), element("p", "", `${run.workflow_name} · run ${shortID(run.id)}`));
    const status = element("div", "run-meta");
    status.append(element("span", "", "Status"), statusBadge(run.status));
    const timing = element("div", "run-meta");
    timing.append(element("span", "", "Started"), element("strong", "", relativeTime(run.started_at)));
    const finish = element("div", "run-meta");
    finish.append(element("span", "", "Progress"), element("strong", "", `${completed}/${steps.length}`));
    const bar = element("progress", "run-progress");
    bar.max = 100;
    bar.value = progress;
    bar.setAttribute("aria-label", `${progress}% complete`);
    copy.append(bar);
    card.append(copy, status, timing, finish);
    card.addEventListener("click", () => openRunDrawer(run));
    card.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openRunDrawer(run); } });
    return card;
  }));
}

function renderSchedules() {
  const schedules = state.data.schedules || [];
  const executions = state.data.scheduled_executions || [];
  const scheduleList = $("#schedule-list");
  if (!schedules.length) {
    setChildren(scheduleList, empty("No persistent schedules have been created."));
  } else {
    setChildren(scheduleList, ...schedules.map((item) => {
      const card = element("article", "list-card");
      const copy = element("div");
      copy.append(element("h3", "", item.name), element("p", "", `${item.workflow_name} · ${item.cron_expression} · ${item.timezone}`));
      const meta = element("div", "run-meta");
      meta.append(element("span", "", `Last ${item.last_run_at ? relativeTime(item.last_run_at) : "never"} · next`), element("strong", "", relativeTime(item.next_run_at)));
      const actions = element("div", "card-actions");
      const edit = element("button", "secondary-button", "Edit");
      edit.addEventListener("click", () => startScheduleEdit(item));
      const toggle = element("button", "secondary-button", item.enabled ? "Disable" : "Enable");
      toggle.addEventListener("click", () => postAction(`/api/v1/schedules/${encodeURIComponent(item.id)}/${item.enabled ? "disable" : "enable"}`, {}, `Schedule ${item.enabled ? "disabled" : "enabled"}.`));
      const runNow = element("button", "primary-button", "Run now");
      runNow.addEventListener("click", () => postAction(`/api/v1/schedules/${encodeURIComponent(item.id)}/run-now`, {}, "Run now queued."));
      actions.append(edit, toggle, runNow);
      card.append(copy, statusBadge(item.enabled ? "enabled" : "disabled"), meta, actions);
      return card;
    }));
  }
  const executionList = $("#scheduled-execution-list");
  if (!executions.length) {
    setChildren(executionList, empty("No scheduled executions have been recorded."));
    renderPendingScopeExpansions();
    return;
  }
  setChildren(executionList, ...executions.slice(0, 25).map((item) => {
    const card = element("article", "list-card");
    const copy = element("div");
    copy.append(element("h3", "", `${item.trigger_source.replaceAll("_", " ")} · ${formatTime(item.planned_at, true)}`), element("p", "", item.error_summary || `task ${shortID(item.task_id)} · run ${shortID(item.workflow_run_id)}`));
    const actions = element("div", "card-actions");
    if (["paused_for_approval", "paused_operator"].includes(item.status)) {
      const resume = element("button", "primary-button", "Resume");
      resume.addEventListener("click", () => postAction(`/api/v1/scheduled-executions/${encodeURIComponent(item.id)}/resume`, {}, "Scheduled execution queued for resume."));
      actions.append(resume);
    }
    card.append(copy, statusBadge(item.status), actions);
    return card;
  }));
  renderPendingScopeExpansions();
}

function startScheduleEdit(item) {
  const form = $("#schedule-form");
  form.elements.schedule_id.value = item.id;
  form.elements.name.value = item.name;
  form.elements.objective.value = item.objective;
  form.elements.workflow.value = item.workflow_name;
  form.elements.cron.value = item.cron_expression;
  form.elements.timezone.value = item.timezone;
  form.elements.headless.checked = Boolean(item.headless);
  $("#schedule-form-eyebrow").textContent = "Edit";
  $("#schedule-form-title").textContent = item.name;
  $("#schedule-submit").textContent = "Save schedule";
  $("#schedule-cancel").classList.remove("hidden");
  form.elements.name.focus();
}

function resetScheduleForm() {
  const form = $("#schedule-form");
  form.reset();
  form.elements.schedule_id.value = "";
  $("#schedule-form-eyebrow").textContent = "Create";
  $("#schedule-form-title").textContent = "New schedule";
  $("#schedule-submit").textContent = "Create schedule";
  $("#schedule-cancel").classList.add("hidden");
}

function renderPendingScopeExpansions() {
  const items = state.data.pending_scope_expansions || [];
  const target = $("#pending-scope-expansion-list");
  if (!items.length) {
    setChildren(target, empty("No scope expansion is waiting for acknowledgement."));
    return;
  }
  setChildren(target, ...items.map((item) => {
    const card = element("article", "list-card");
    const copy = element("div");
    copy.append(element("h3", "", `Scope ${shortID(item.id)}`), element("p", "", `Target plan ${item.target_plan_digest}`));
    const changes = element("div", "warning-list");
    const rows = [
      ["Added includes", item.added_include_digests],
      ["Removed includes", item.removed_include_digests],
      ["Added exclusions", item.added_exclude_digests],
      ["Removed exclusions", item.removed_exclude_digests],
    ];
    rows.forEach(([label, values]) => (values || []).forEach((value) => changes.append(element("div", "warning-row", `${label}: ${value}`))));
    (Array.isArray(item.planning_warnings) ? item.planning_warnings : []).forEach((warning) => changes.append(element("div", "warning-row", `Planning warning: ${typeof warning === "string" ? warning : JSON.stringify(warning)}`)));
    copy.append(changes);
    const review = element("button", "primary-button", "Review and acknowledge");
    review.addEventListener("click", () => openModal({
      eyebrow: "Authorization boundary",
      title: "Acknowledge this scope expansion?",
      description: "This records a separate operator acknowledgement. It does not queue or start a workflow.",
      details: [["Scope digest", item.scope_digest], ["Target plan digest", item.target_plan_digest], ["Created", formatTime(item.created_at, true)]],
      confirmLabel: "Acknowledge expansion",
      danger: false,
      action: () => postAction(`/api/v1/scope-versions/${encodeURIComponent(item.id)}/acknowledge`, {}, "Scope expansion acknowledged."),
    }));
    card.append(copy, statusBadge("pending"), review);
    return card;
  }));
}

function renderChangeInbox() {
  const items = state.data.change_items || [];
  const showLowPriority = $("#show-low-priority").checked;
  const visible = items.filter((item) => showLowPriority || ["high", "medium"].includes(item.priority) || item.disposition !== "unreviewed");
  if (!visible.length) {
    setChildren($("#change-inbox-list"), empty(showLowPriority ? "No change items are waiting." : "No high- or medium-priority unreviewed changes are waiting."));
    return;
  }
  setChildren($("#change-inbox-list"), ...visible.map((item) => {
    const card = element("article", "list-card");
    const copy = element("div");
    copy.append(element("h3", "", item.title), element("p", "", `${item.entity_type} · ${item.summary}`));
    const reasons = element("div", "warning-list");
    (Array.isArray(item.reasons) ? item.reasons : []).slice(0, 4).forEach((reason) => reasons.append(element("div", "warning-row", reason)));
    const note = element("input", "review-note");
    note.type = "text";
    note.placeholder = "Optional review note";
    note.value = item.review_note || "";
    note.setAttribute("aria-label", `Review note for ${item.title}`);
    copy.append(reasons, note);
    const meta = element("div", "run-meta");
    meta.append(element("span", "", item.kind), statusBadge(item.priority));
    const actions = element("div", "card-actions");
    for (const disposition of ["interesting", "investigating", "expected_change", "not_relevant", "resolved"]) {
      const button = element("button", disposition === "interesting" ? "primary-button" : "secondary-button", disposition.replaceAll("_", " "));
      button.addEventListener("click", () => postAction(`/api/v1/change-items/${encodeURIComponent(item.id)}/review`, { disposition, note: note.value.trim(), actor: "console-operator" }, "Change review saved."));
      actions.append(button);
    }
    card.append(copy, meta, statusBadge(item.disposition || "unreviewed"), actions);
    return card;
  }));
}

function openRunDrawer(run) {
  const steps = latestRunSteps(run);
  $("#drawer-title").textContent = run.objective;
  const content = $("#drawer-content");
  const overview = element("section", "detail-block");
  overview.append(element("h3", "", "Execution"));
  const details = element("dl", "modal-details");
  appendDetails(details, [["Run", run.id], ["Workflow", `${run.workflow_name} · v${run.workflow_version}`], ["Status", run.status], ["Trigger", run.trigger_source], ["Started", formatTime(run.started_at, true)], ["Completed", formatTime(run.completed_at, true)]]);
  overview.append(details);
  const stepBlock = element("section", "detail-block");
  stepBlock.append(element("h3", "", "Steps"));
  steps.forEach((step, index) => {
    const row = element("div", "step-detail");
    const copy = element("div");
    copy.append(element("strong", "", step.step_definition_id), element("small", "", `${step.capability} · ${step.attempt_count || 0} attempt${step.attempt_count === 1 ? "" : "s"}${step.error_classification ? ` · ${step.error_classification}` : ""}`));
    row.append(element("span", "step-index", String(index + 1).padStart(2, "0")), copy, statusBadge(step.status));
    stepBlock.append(row);
  });
  setChildren(content, overview, stepBlock);
  $("#drawer-backdrop").classList.remove("hidden");
  $("#detail-drawer").classList.add("open");
  $("#detail-drawer").setAttribute("aria-hidden", "false");
  $("#drawer-close").focus();
}

function closeDrawer() {
  $("#drawer-backdrop").classList.add("hidden");
  $("#detail-drawer").classList.remove("open");
  $("#detail-drawer").setAttribute("aria-hidden", "true");
}

function renderAssets() {
  const assets = state.data.assets || [];
  const types = [...new Set(assets.map((item) => item.type))].sort();
  const select = $("#asset-type-filter");
  const previous = select.value;
  const options = [element("option", "", "All types"), ...types.map((type) => element("option", "", type.replaceAll("_", " ")))];
  options.forEach((option, index) => { option.value = index === 0 ? "" : types[index - 1]; });
  setChildren(select, ...options);
  if (types.includes(previous)) select.value = previous;
  renderAssetTable();
}

function renderAssetTable() {
  const query = $("#asset-search").value.trim().toLowerCase();
  const type = $("#asset-type-filter").value;
  const assets = (state.data.assets || []).filter((item) => (!type || item.type === type) && (!query || item.canonical_value.toLowerCase().includes(query)));
  if (!assets.length) {
    setChildren($("#asset-table"), empty("No assets match this filter."));
    return;
  }
  const table = element("table", "data-table");
  const head = element("thead");
  const row = element("tr");
  ["Asset", "Type", "Source", "Observations", "Last seen"].forEach((label) => row.append(element("th", "", label)));
  head.append(row);
  const body = element("tbody");
  assets.forEach((asset) => {
    const tr = element("tr");
    const value = element("td"); value.append(element("strong", "", asset.canonical_value));
    tr.append(value, element("td", "", asset.type.replaceAll("_", " ")), element("td", "", asset.source_capability || "—"), element("td", "", asset.observation_count), element("td", "", relativeTime(asset.last_observed_at || asset.updated_at)));
    body.append(tr);
  });
  table.append(head, body);
  setChildren($("#asset-table"), table);
}

function renderFindings() {
  const candidates = state.data.candidate_findings || [];
  const verified = state.data.verified_findings || [];
  $("#candidate-count").textContent = candidates.length;
  $("#verified-count").textContent = verified.length;
  setChildren($("#candidate-list"), ...(candidates.length ? candidates.map((item) => findingCard(item, false)) : [empty("No candidate findings.")]));
  setChildren($("#verified-list"), ...(verified.length ? verified.map((item) => findingCard(item, true)) : [empty("No verified findings. Candidates are never promoted automatically.")]));
}

function findingCard(item, verified) {
  const card = element("div", "list-card finding-card");
  const copy = element("div");
  copy.append(element("h3", "", verified ? item.title : item.claimed_vulnerability), element("p", "", `${item.target || "Unknown target"}${verified ? "" : ` · ${item.template_id}`}`));
  const meta = element("div", "run-meta");
  meta.append(element("span", "", verified ? item.status : `${Math.round((item.detection_confidence || 0) * 100)}% detector confidence`), element("strong", `severity ${String(item.severity).toLowerCase()}`, item.severity));
  card.append(copy, meta);
  return card;
}

function renderApprovals() {
  const approvals = state.data.approvals || [];
  const target = $("#approval-list");
  if (!approvals.length) {
    setChildren(target, empty("No approval requests have been recorded."));
    return;
  }
  setChildren(target, ...approvals.map((item) => {
    const card = element("article", "list-card approval-card");
    const copy = element("div");
    copy.append(element("h3", "", item.reason), element("p", "", `${item.objective} · requested ${relativeTime(item.requested_at)}`));
    const meta = element("div", "run-meta");
    meta.append(element("span", "", "Risk / decision"), statusBadge(item.decision === "pending" ? item.risk : item.decision));
    const actions = element("div", "card-actions");
    if (item.decision === "pending") {
      const reject = element("button", "danger-button", "Reject");
      const approve = element("button", "primary-button", "Approve");
      reject.addEventListener("click", () => confirmApproval(item, "rejected"));
      approve.addEventListener("click", () => confirmApproval(item, "approved"));
      actions.append(reject, approve);
    } else {
      actions.append(element("span", "status-badge neutral", `Decided ${relativeTime(item.decided_at)}`));
    }
    card.append(copy, meta, actions);
    return card;
  }));
}

function confirmApproval(item, decision) {
  openModal({
    eyebrow: "Human authorization",
    title: `${decision === "approved" ? "Approve" : "Reject"} moderate-risk step?`,
    description: decision === "approved" ? "This records an explicit human authorization. The workflow may execute the gated capability when resumed." : "This records a rejection. The gated capability will not execute for this request.",
    details: [["Risk", item.risk], ["Reason", item.reason], ["Objective", item.objective], ["Request", shortID(item.request_id)]],
    confirmLabel: decision === "approved" ? "Approve step" : "Reject step",
    danger: decision === "rejected",
    action: () => postAction(`/api/v1/approvals/${encodeURIComponent(item.id)}/decision`, { decision, actor: "console-operator" }, `Approval ${decision}.`),
  });
}

function renderQueue() {
  const queue = state.data.queue || { dead_letters: [] };
  $("#pending-jobs").textContent = `${queue.pending || 0} pending`;
  const target = $("#queue-list");
  if (queue.error && !queue.dead_letters?.length) {
    setChildren(target, empty("Queue status is temporarily unavailable. Database-backed console data is still current."));
    return;
  }
  if (!queue.dead_letters?.length) {
    setChildren(target, empty("No jobs are waiting in the dead-letter stream."));
    return;
  }
  setChildren(target, ...queue.dead_letters.map((item) => {
    const card = element("article", "list-card queue-card");
    const copy = element("div");
    copy.append(element("h3", "", item.capability || "Unclassified job"), element("p", "", `${item.error || "No safe error classification"} · message ${item.message_id}`));
    const meta = element("div", "run-meta");
    meta.append(element("span", "", "Provider / attempts"), element("strong", "", `${item.provider || "—"} · ${item.attempt}`));
    const retry = element("button", "secondary-button", "Retry job");
    retry.addEventListener("click", () => confirmRetry(item));
    card.append(copy, meta, retry);
    return card;
  }));
}

function confirmRetry(item) {
  openModal({
    eyebrow: "Delivery recovery",
    title: "Return job to the queue?",
    description: "This resets the delivery attempt count and re-enqueues the existing validated job. Scope and policy checks still apply during execution.",
    details: [["Capability", item.capability || "Unknown"], ["Provider", item.provider || "Unknown"], ["Error", item.error || "Unavailable"], ["Message", item.message_id]],
    confirmLabel: "Retry job",
    action: () => postAction(`/api/v1/dead-letters/${encodeURIComponent(item.message_id)}/retry`, {}, "Job returned to the queue."),
  });
}

function renderLogs() {
  const tools = state.data.tool_runs || [];
  setChildren($("#tool-list"), ...(tools.length ? tools.map((item) => {
    const card = element("div", "list-card tool-card");
    const copy = element("div");
    copy.append(element("h3", "", `${item.provider}${item.tool_version ? ` · ${item.tool_version}` : ""}`), element("p", "", `${item.step_definition_id} · run ${shortID(item.workflow_run_id)} · ${relativeTime(item.started_at)}`));
    const args = element("pre", "args", JSON.stringify(item.sanitized_arguments || {}, null, 2));
    copy.append(args);
    const meta = element("div", "run-meta");
    const outcome = item.timed_out ? "timed out" : item.exit_code == null ? "running" : `exit ${item.exit_code}`;
    meta.append(element("span", "", `${item.artifact_count} safe artifacts`), statusBadge(item.timed_out || (item.exit_code != null && item.exit_code !== 0) ? "failed" : outcome === "running" ? "running" : "succeeded"));
    card.append(copy, meta);
    return card;
  }) : [empty("No provider executions have been recorded.")]));
  const events = state.data.audit_events || [];
  setChildren($("#audit-list"), ...(events.length ? events.map(activityItem) : [empty("No audit events recorded.")]));
}

function appendDetails(list, details) {
  details.forEach(([label, value]) => {
    list.append(element("dt", "", label), element("dd", "", value == null || value === "" ? "—" : value));
  });
}

function openModal(config) {
  state.modalAction = config.action;
  $("#modal-eyebrow").textContent = config.eyebrow;
  $("#modal-title").textContent = config.title;
  $("#modal-description").textContent = config.description;
  $("#modal-confirm").textContent = config.confirmLabel;
  $("#modal-confirm").className = config.danger ? "danger-button" : "primary-button";
  const details = $("#modal-details");
  details.replaceChildren();
  appendDetails(details, config.details);
  $("#action-modal").classList.remove("hidden");
  $("#modal-cancel").focus();
}

function closeModal() {
  state.modalAction = null;
  $("#action-modal").classList.add("hidden");
}

async function postAction(path, body, successMessage) {
  const button = $("#modal-confirm");
  button.disabled = true;
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Reconductor-Request": "operator-console", Accept: "application/json" },
      body: JSON.stringify(body),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "The operator action was not accepted.");
    closeModal();
    toast(successMessage);
    await loadData({ quiet: true });
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function toast(message, isError = false) {
  const item = element("div", `toast ${isError ? "error" : ""}`.trim(), message);
  $("#toast-region").append(item);
  setTimeout(() => item.remove(), 4500);
}

function bindEvents() {
  $$(".nav-item").forEach((item) => item.addEventListener("click", () => showView(item.dataset.view)));
  $$('[data-go-view]').forEach((item) => item.addEventListener("click", () => showView(item.dataset.goView)));
  $("#program-select").addEventListener("change", (event) => {
    state.selectedProgram = event.target.value;
    localStorage.setItem("reconductor.program", state.selectedProgram);
    loadData();
  });
  $("#refresh-button").addEventListener("click", () => loadData());
  $("#retry-load").addEventListener("click", () => loadData());
  $("#asset-search").addEventListener("input", renderAssetTable);
  $("#asset-type-filter").addEventListener("change", renderAssetTable);
  $("#show-low-priority").addEventListener("change", renderChangeInbox);
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer-backdrop").addEventListener("click", closeDrawer);
  $("#mobile-menu").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
  $("#modal-cancel").addEventListener("click", closeModal);
  $("#action-modal").addEventListener("click", (event) => { if (event.target === $("#action-modal")) closeModal(); });
  $("#modal-confirm").addEventListener("click", () => { if (state.modalAction) state.modalAction(); });
  $("#schedule-cancel").addEventListener("click", resetScheduleForm);
  $("#schedule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const scheduleID = String(form.get("schedule_id") || "");
    const body = {
      name: String(form.get("name") || ""),
      workflow_name: String(form.get("workflow") || ""),
      objective: String(form.get("objective") || ""),
      cron_expression: String(form.get("cron") || ""),
      timezone: String(form.get("timezone") || ""),
      headless: form.get("headless") === "on",
      actor: "console-operator",
    };
    if (!scheduleID) body.program_id = state.data?.selected_program_id || state.selectedProgram;
    try {
      const path = scheduleID ? `/api/v1/schedules/${encodeURIComponent(scheduleID)}/update` : "/api/v1/schedules";
      const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Reconductor-Request": "operator-console", Accept: "application/json" }, body: JSON.stringify(body) });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || "Schedule was not accepted.");
      resetScheduleForm();
      toast(scheduleID ? "Schedule updated." : "Schedule created.");
      await loadData({ quiet: true });
    } catch (error) {
      toast(error.message, true);
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (!$("#action-modal").classList.contains("hidden")) closeModal();
    else closeDrawer();
  });
}

bindEvents();
loadData();
state.timer = setInterval(() => loadData({ quiet: true }), 5000);
