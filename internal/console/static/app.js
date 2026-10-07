"use strict";

const state = {
  data: null,
  selectedProgram: localStorage.getItem("reconductor.program") || "",
  view: "overview",
  loading: false,
  timer: null,
  modalAction: null,
  modalGeneration: 0,
  exactApprovals: { items: [], nextCursor: "", id: "", detail: null, status: "locked", error: "", listGeneration: 0, detailGeneration: 0, decisionGeneration: 0, busy: false, modalOwner: false, returnFocus: null },
	operatorCredential: "",
	operatorVerificationGeneration: 0,
  drawer: {
    returnFocus: null,
    returnTarget: null,
    scrollLock: { locked: false, x: 0, y: 0 },
  },
  executionDetail: {
    id: "",
    status: "idle",
    data: null,
    error: "",
    controller: null,
  },
  runWorkspace: {
    selection: null,
    item: null,
    expandedChangeExecutionID: "",
    projection: { id: "", status: "idle", data: null, error: "" },
  },
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

const drawerTabbableSelector = [
  'button:not([disabled]):not([tabindex="-1"])',
  'a[href]:not([tabindex="-1"])',
  'input:not([disabled]):not([type="hidden"]):not([tabindex="-1"])',
  'select:not([disabled]):not([tabindex="-1"])',
  'textarea:not([disabled]):not([tabindex="-1"])',
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

function drawerTabbableElements(drawer) {
  return $$(drawerTabbableSelector, drawer).filter((item) => {
    if (item.tabIndex < 0 || item.hidden || item.getAttribute("aria-hidden") === "true") return false;
    return typeof item.getClientRects !== "function" || item.getClientRects().length > 0;
  });
}

function containDrawerTab(event, focusable, activeElement, fallback) {
  if (event.key !== "Tab") return false;
  const first = focusable[0] || null;
  const last = focusable[focusable.length - 1] || null;
  let target = null;
  if (!first) {
    target = fallback;
  } else if (focusable.length === 1) {
    target = first;
  } else if (event.shiftKey && (event.target === first || activeElement === first || !focusable.includes(activeElement))) {
    target = last;
  } else if (!event.shiftKey && (event.target === last || activeElement === last || !focusable.includes(activeElement))) {
    target = first;
  }
  if (!target) return false;
  event.preventDefault();
  target.focus();
  return true;
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

function statusBadge(status, label = "") {
  const normalized = String(status || "unknown").toLowerCase();
  let tone = "neutral";
  if (["succeeded", "completed", "approved", "open", "confirmed"].includes(normalized)) tone = "";
  if (["pending", "claimed", "running", "queued", "paused", "paused_operator", "paused_for_approval", "awaiting_approval", "new", "needs_manual_review", "moderate", "medium", "skipped_overlap"].includes(normalized)) tone = "warning";
  if (["failed", "retryable", "rejected", "cancelled", "critical", "high", "blocked_scope_change", "approval_rejected", "interrupted", "expired", "inconsistent"].includes(normalized)) tone = "danger";
  const text = normalized.replaceAll("_", " ");
  return element("span", `status-badge ${tone}`.trim(), label ? `${label}: ${text}` : text);
}

function empty(message) {
  return element("div", "empty-copy", message);
}

function showView(name, { focusWorkspace = false } = {}) {
  state.view = name;
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $$(".view").forEach((item) => item.classList.toggle("active", item.dataset.viewPanel === name));
  $(".sidebar").classList.remove("open");
  const reduceMotion = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" });
  if (name === "exact-approvals") return refreshExactApprovals();
  if (name === "runs") return activateRunWorkspace({ focus: focusWorkspace });
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
	const definition = state.data.workflow_topologies?.[run.id]?.steps || [];
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
	if (state.data.workflow_topologies?.[run.id]?.availability === "legacy_unavailable") {
    left.append(element("small", "", "Legacy topology unavailable · showing recorded steps only"));
  }
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
  return Array.isArray(state.data?.change_items) ? state.data.change_items : [];
}

function renderChanges() {
  const rows = changeRows();
  const counts = { new: 0, changed: 0, removed: 0 };
  rows.forEach((item) => {
    if (item?.kind === "new_or_changed") counts.changed += 1;
    else if (item?.kind in counts) counts[item.kind] += 1;
  });
  const wrap = element("div", "change-stats");
  [["new", counts.new], ["changed", counts.changed], ["removed", counts.removed]].forEach(([kind, count]) => {
    const item = element("div", `change-stat ${kind}`);
    item.append(element("strong", "", count), element("span", "", kind));
    wrap.append(item);
  });
  if (!rows.length) wrap.append();
  setChildren($("#changes-content"), wrap, !rows.length ? empty("No persistent changes are available yet.") : null);
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

const activeWorkspaceStatuses = new Set(["pending", "claimed", "running", "paused", "paused_operator", "paused_for_approval", "awaiting_approval"]);
const inspectorArtifactPreviewLimit = 3;
const initialChangeRowLimit = 16;

function runEntryKey(entry) {
  return entry ? `${entry.kind}:${entry.id}` : "";
}

function buildRunSelectorEntries(runs = [], executions = []) {
  const runsByID = new Map(runs.map((run) => [String(run.id), run]));
  const linkedRunIDs = new Set();
  const entries = executions.map((execution) => {
    const workflowRunID = execution.workflow_run_id ? String(execution.workflow_run_id) : "";
    const run = workflowRunID ? runsByID.get(workflowRunID) || null : null;
    if (run) linkedRunIDs.add(workflowRunID);
    return {
      kind: "execution",
      id: String(execution.id),
      executionId: String(execution.id),
      workflowRunId: workflowRunID,
      execution,
      run,
    };
  });
  runs.forEach((run) => {
    const id = String(run.id);
    if (linkedRunIDs.has(id)) return;
    entries.push({ kind: "workflow", id, executionId: "", workflowRunId: id, execution: null, run });
  });
  return entries;
}

function runWorkspaceEntries() {
  return buildRunSelectorEntries(state.data?.runs || [], state.data?.scheduled_executions || []);
}

function runEntryIsActive(entry) {
  return activeWorkspaceStatuses.has(String(entry.execution?.status || "").toLowerCase())
    || activeWorkspaceStatuses.has(String(entry.run?.status || "").toLowerCase());
}

function selectedRunEntry(entries = runWorkspaceEntries()) {
  const current = runEntryKey(state.runWorkspace.selection);
  return entries.find((entry) => runEntryKey(entry) === current) || entries.find(runEntryIsActive) || entries[0] || null;
}

function resetRunWorkspaceProjection() {
  state.runWorkspace.projection = { id: "", status: "idle", data: null, error: "" };
}

function setRunWorkspaceSelection(entry) {
  const previous = runEntryKey(state.runWorkspace.selection);
  const next = runEntryKey(entry);
  if (previous !== next) {
    cancelExecutionDetail();
    resetRunWorkspaceProjection();
    state.runWorkspace.item = null;
    state.runWorkspace.expandedChangeExecutionID = "";
  }
  state.runWorkspace.selection = entry ? { kind: entry.kind, id: entry.id } : null;
  if (!state.runWorkspace.item) {
    state.runWorkspace.item = entry
      ? { kind: entry.executionId ? "execution" : "workflow", id: entry.executionId || entry.workflowRunId }
      : null;
  }
}

function scheduleForExecution(execution) {
  return (state.data?.schedules || []).find((item) => String(item.id) === String(execution?.schedule_id || "")) || null;
}

function runEntryTitle(entry) {
  return entry?.run?.objective || scheduleForExecution(entry?.execution)?.name || "Scheduled execution";
}

function runEntrySteps(entry, projection = null) {
  if (projection) return Array.isArray(projection.steps) ? projection.steps : [];
  const runID = entry?.workflowRunId;
  return (state.data?.steps || []).filter((step) => String(step.workflow_run_id) === String(runID || ""));
}

function currentRunProjection(entry) {
  const cached = state.runWorkspace.projection;
  return entry?.executionId && cached.id === entry.executionId && cached.status === "ready" ? cached.data : null;
}

function exactID(left, right) {
  return left != null && right != null && String(left) === String(right);
}

function artifactCountText(count, truncated) {
  if (truncated) return count ? `${count} loaded` : "none in loaded subset";
  return `${count} artifact${count === 1 ? "" : "s"}`;
}

function projectionCollectionCountText(collection) {
  const value = collectionValue(collection);
  return value.truncated ? `${value.total} total · ${value.items.length} loaded` : `${value.total} total`;
}

function associatedCountText(count, collection) {
  return collection.truncated ? `${count} loaded` : String(count);
}

function availableDetails(details) {
  return details.filter(([, value]) => value != null && value !== "");
}

function inspectorNotice(role, message) {
  const notice = element("div", `inspector-notice${role === "alert" ? " error" : ""}`, message);
  notice.setAttribute("role", role);
  return notice;
}

function inspectorArtifactPreview(items, collection) {
  if (!items.length) return null;
  const block = element("section", "inspector-artifacts");
  block.append(element("h5", "", "Visible artifact references"));
  const list = element("div", "inspector-artifact-list");
  const shown = items.slice(0, inspectorArtifactPreviewLimit);
  shown.forEach((artifact) => {
    const row = element("div", "inspector-artifact-row");
    const summary = element("div");
    summary.append(
      element("strong", "", artifact.type || "Artifact reference"),
      element("span", "", [artifact.content_type || "Content type not recorded", formatBytes(artifact.size)].join(" · ")),
    );
    const facts = [];
    if (artifact.redaction_state) facts.push(`Redaction: ${artifact.redaction_state}`);
    if (artifact.created_at) facts.push(`Created ${formatTime(artifact.created_at, true)}`);
    if (artifact.expires_at) facts.push(`Expires ${formatTime(artifact.expires_at, true)}`);
    row.append(summary);
    if (facts.length) row.append(element("small", "", facts.join(" · ")));
    list.append(row);
  });
  block.append(list);
  const note = [];
  if (items.length > shown.length) note.push(`${shown.length} shown · ${items.length} loaded`);
  if (collection.truncated) note.push("projection collection truncated");
  if (note.length) block.append(element("p", "inspector-artifact-note", note.join(" · ")));
  return block;
}

function partitionRunRelationships(entry, projection = null) {
  const toolRuns = collectionValue(projection?.tool_runs);
  const approvals = collectionValue(projection?.approvals);
  const artifacts = collectionValue(projection?.artifacts);
  const artifactCollectionAvailable = projection?.artifacts != null;
  let workflow = projection?.workflow || entry?.run || null;
  if (entry?.executionId) {
    const linkedWorkflowID = projection ? projection.execution?.workflow_run_id : entry.workflowRunId;
    if (!workflow || !exactID(linkedWorkflowID, workflow.id)) workflow = null;
  }
  const steps = workflow
    ? runEntrySteps(entry, projection).filter((step) => exactID(step.workflow_run_id, workflow.id))
    : [];
  const associatedToolRuns = new Set();
  const associatedApprovals = new Set();
  const stepModels = steps.map((step) => {
    const stepToolRuns = toolRuns.items.filter((tool) => exactID(tool.step_run_id, step.id));
    const stepApprovals = approvals.items.filter((approval) => exactID(approval.step_run_id, step.id));
    stepToolRuns.forEach((tool) => associatedToolRuns.add(tool));
    stepApprovals.forEach((approval) => associatedApprovals.add(approval));
    return {
      step,
      artifacts: artifacts.items.filter((artifact) => exactID(artifact.step_run_id, step.id)),
      toolRuns: stepToolRuns.map((tool) => ({
        tool,
        artifacts: artifacts.items.filter((artifact) => exactID(artifact.tool_run_id, tool.id)
          && exactID(artifact.step_run_id, step.id)
          && exactID(artifact.workflow_run_id, workflow.id)),
      })),
      approvals: stepApprovals,
    };
  });
  return {
    workflow,
    steps: stepModels,
    toolRuns,
    approvals,
    artifacts,
    artifactCollectionAvailable,
    workflowArtifacts: workflow ? artifacts.items.filter((artifact) => exactID(artifact.workflow_run_id, workflow.id)) : [],
    unassociatedToolRuns: toolRuns.items.filter((tool) => !associatedToolRuns.has(tool)),
    unassociatedApprovals: approvals.items.filter((approval) => !associatedApprovals.has(approval)),
  };
}

function findRelationshipItem(relationships, kind, id) {
  for (const model of relationships.steps) {
    if (kind === "step" && exactID(model.step.id, id)) return model;
    if (kind === "tool") {
      const tool = model.toolRuns.find((item) => exactID(item.tool.id, id));
      if (tool) return { ...tool, step: model.step };
    }
    if (kind === "approval") {
      const approval = model.approvals.find((item) => exactID(item.id, id));
      if (approval) return { approval, step: model.step };
    }
  }
  return null;
}

function findProjectedChange(projection, id) {
  return collectionValue(projection?.change_items).items.find((item) => exactID(item.id, id)) || null;
}

function fallbackRunWorkspaceItem(entry) {
  return entry ? { kind: entry.executionId ? "execution" : "workflow", id: entry.executionId || entry.workflowRunId } : null;
}

function resolveRunWorkspaceItem(entry, relationships, projection = null) {
  const selection = state.runWorkspace.item;
  let available = false;
  if (selection?.kind === "execution") available = Boolean(entry?.executionId && exactID(selection.id, entry.executionId));
  else if (selection?.kind === "workflow") available = Boolean(relationships.workflow && exactID(selection.id, relationships.workflow.id));
  else if (["step", "tool", "approval"].includes(selection?.kind)) available = Boolean(findRelationshipItem(relationships, selection.kind, selection.id));
  else if (selection?.kind === "change") available = Boolean(findProjectedChange(projection, selection.id));
  if (!available) state.runWorkspace.item = fallbackRunWorkspaceItem(entry);
  return state.runWorkspace.item;
}

function runStatusBadges(entry, projection = null) {
  const schedulerStatus = projection ? projection.scheduler?.status : entry?.execution?.status;
  const workflowStatus = projection ? projection.workflow?.status : entry?.run?.status;
  const badges = [];
  if (schedulerStatus) badges.push(statusBadge(schedulerStatus, "Scheduler"));
  if (workflowStatus) badges.push(statusBadge(workflowStatus, "Workflow"));
  return badges;
}

function runStatusGroup(entry, projection = null) {
  const group = element("span", "run-status-group");
  group.append(...runStatusBadges(entry, projection));
  return group;
}

function renderRunSelector(entries, selected) {
  const target = $("#runs-list");
  if (!entries.length) {
    setChildren(target, empty("No scheduled executions or workflow runs have been persisted."));
    return;
  }
  setChildren(target, ...entries.map((entry) => {
    const steps = runEntrySteps(entry);
    const completed = steps.filter((step) => ["succeeded", "skipped"].includes(step.status)).length;
    const timing = entry.run?.started_at || entry.execution?.started_at || entry.execution?.planned_at;
    const button = element("button", "run-selector-item");
    button.type = "button";
    button.dataset.runSelection = runEntryKey(entry);
    if (entry.workflowRunId) button.dataset.runId = entry.workflowRunId;
    button.setAttribute("aria-pressed", String(runEntryKey(entry) === runEntryKey(selected)));
    button.append(element("strong", "", runEntryTitle(entry)), element("small", "", `${entry.kind === "execution" ? "execution" : "workflow"} ${shortID(entry.id)}`));
    const row = element("div", "run-selector-row");
    row.append(runStatusGroup(entry), element("span", "", steps.length ? `${completed}/${steps.length} steps · ${relativeTime(timing)}` : relativeTime(timing)));
    button.append(row);
    button.addEventListener("click", () => selectRunWorkspaceEntry(entry));
    return button;
  }));
}

function laneNode(kind, id, title, description, status, className = "") {
  const button = element("button", `lane-node ${className}`.trim());
  button.type = "button";
  button.dataset.workspaceItem = `${kind}:${id}`;
  button.setAttribute("aria-pressed", String(state.runWorkspace.item?.kind === kind && String(state.runWorkspace.item.id) === String(id)));
  const copy = element("span");
  copy.append(element("strong", "", title), element("small", "", description));
  button.append(copy);
  if (status != null && status !== "") button.append(statusBadge(status));
  button.addEventListener("click", () => selectRunWorkspaceItem(kind, id));
  return button;
}

function toolObservationText(tool) {
  const facts = [];
  if (tool.timed_out) facts.push("Timed out");
  facts.push(tool.completed_at ? `Completed ${formatTime(tool.completed_at, true)}` : "Not completed at observation");
  if (tool.exit_code != null) facts.push(`Exit ${tool.exit_code}`);
  return facts.join(" · ");
}

function toolLaneNode(model, artifactsTruncated, artifactCollectionAvailable) {
  const tool = model.tool;
  const provider = tool.provider || "Tool run";
  const version = tool.tool_version ? ` ${tool.tool_version}` : "";
  const button = laneNode("tool", tool.id, `${provider}${version}`, tool.capability || "No capability recorded", null, "lane-child-node lane-tool-node");
  const facts = element("span", "lane-child-facts");
  facts.append(element("small", "", toolObservationText(tool)));
  const refs = [];
  if (tool.stdout_artifact_id) refs.push("stdout ref");
  if (tool.stderr_artifact_id) refs.push("stderr ref");
  if (artifactCollectionAvailable) refs.push(`Artifacts: ${artifactCountText(model.artifacts.length, artifactsTruncated)}`);
  facts.append(element("small", "", refs.join(" · ")));
  button.append(facts);
  return button;
}

function approvalLaneNode(approval) {
  const button = laneNode("approval", approval.id, "Approval", approval.reason || "No reason recorded", approval.decision, "lane-child-node lane-approval-node");
  button.children[0].append(element("small", "", `Requested risk: ${approval.requested_risk_level || "not recorded"}`));
  return button;
}

function appendCollectionNotice(levels, label, collection) {
  if (!collection.truncated) return;
  levels.push(element("div", "lane-collection-notice", `${label}: ${collection.items.length} shown of ${collection.total}`));
}

function unassociatedRecordText(count, singular) {
  return `${count} loaded ${singular}${count === 1 ? "" : "s"} could not be associated with an available step`;
}

function groupedChangeCounts(items, field) {
  const groups = new Map();
  items.forEach((item) => {
    const value = String(item?.[field] || "Not recorded");
    groups.set(value, (groups.get(value) || 0) + 1);
  });
  return [...groups.entries()];
}

function changeCountGroup(items, field, label, truncated) {
  const block = element("section", "change-count-group");
  block.append(element("h5", "", `${truncated ? "Loaded changes" : "Execution changes"} by ${label}`));
  const counts = element("div", "change-count-chips");
  groupedChangeCounts(items, field).forEach(([value, count]) => {
    const chip = element("span", "change-count-chip");
    chip.append(element("strong", "", value.replaceAll("_", " ")), element("span", "", String(count)));
    counts.append(chip);
  });
  if (!counts.children.length) counts.append(element("span", "change-count-empty", "No loaded values"));
  block.append(counts);
  return block;
}

function renderExecutionChanges(entry, projection) {
  const block = element("section", "execution-changes");
  block.append(element("h4", "", "Execution changes"));
  if (!projection) {
    block.append(element("p", "execution-changes-unavailable", "Change collection unavailable without a coherent execution projection."));
    return block;
  }
  const changes = collectionValue(projection.change_items);
  const loaded = changes.items.length;
  const summary = element("div", "change-collection-summary");
  [["Exact total", changes.total], ["Loaded", loaded], ["Truncated", changes.truncated ? "Yes" : "No"]].forEach(([label, value]) => {
    const item = element("div", "change-summary-item");
    item.append(element("strong", "", String(value)), element("span", "", label));
    summary.append(item);
  });
  block.append(summary, element("p", "change-collection-note", changes.truncated
    ? `${loaded} of ${changes.total} changes loaded. Grouped counts cover the loaded subset only.`
    : `${loaded} of ${changes.total} changes loaded. The execution collection is complete.`));
  const groups = element("div", "change-count-groups");
  groups.append(
    changeCountGroup(changes.items, "kind", "kind", changes.truncated),
    changeCountGroup(changes.items, "entity_type", "entity type", changes.truncated),
    changeCountGroup(changes.items, "priority", "priority", changes.truncated),
  );
  block.append(groups);
  if (!loaded) {
    block.append(empty("No change items are linked to this execution."));
    return block;
  }
  const expanded = exactID(state.runWorkspace.expandedChangeExecutionID, entry.executionId);
  const visible = expanded ? changes.items : changes.items.slice(0, initialChangeRowLimit);
  const list = element("div", "change-row-list");
  visible.forEach((item) => {
    const button = element("button", "change-row");
    button.type = "button";
    button.dataset.workspaceItem = `change:${item.id}`;
    button.setAttribute("aria-pressed", String(state.runWorkspace.item?.kind === "change" && exactID(state.runWorkspace.item.id, item.id)));
    const copy = element("span", "change-row-copy");
    copy.append(
      element("strong", "", `${item.kind || "Change"} · ${item.entity_type || "entity"}`),
      element("small", "", `Observed ${formatTime(item.observed_at, true)} · Source capabilities: ${Array.isArray(item.source_capabilities) ? item.source_capabilities.length : 0}`),
    );
    button.append(copy, statusBadge(item.priority || "unknown"));
    button.addEventListener("click", () => selectRunWorkspaceItem("change", item.id));
    list.append(button);
  });
  block.append(list);
  if (loaded > initialChangeRowLimit) {
    const toggle = element("button", "change-expansion-control", expanded
      ? `Show first ${initialChangeRowLimit} changes`
      : `Show all ${loaded} loaded changes`);
    toggle.type = "button";
    toggle.dataset.workspaceControl = `change-expansion:${entry.executionId}`;
    toggle.setAttribute("aria-expanded", String(expanded));
    toggle.addEventListener("click", () => toggleExecutionChanges(entry.executionId));
    block.append(toggle);
  }
  return block;
}

function renderRunLane(entry, projection, relationships = partitionRunRelationships(entry, projection)) {
  const lane = $("#run-lane");
  if (!entry) {
    setChildren(lane, empty("Select a run to inspect its associated lineage."));
    return;
  }
  if (entry.executionId && state.runWorkspace.projection.id === entry.executionId && state.runWorkspace.projection.status === "loading") {
    setChildren(lane, empty("Loading the coherent execution observation…"));
    return;
  }
  const workflow = relationships.workflow;
  const levels = [];
  if (entry.executionId) {
    const execution = projection?.execution || entry.execution;
    const scheduler = projection?.scheduler || entry.execution;
    const level = element("div", "lane-level");
    level.append(element("span", "lane-label", "Execution"), laneNode("execution", entry.executionId, runEntryTitle(entry), `Execution ${shortID(entry.executionId)}`, scheduler?.status));
    levels.push(level);
  }
  if (workflow) {
    if (levels.length) levels.push(element("div", "lane-association", "Associated workflow"));
    const level = element("div", "lane-level");
    const workflowFacts = [`Run ${shortID(workflow.id)}`, `v${workflow.workflow_version || "—"}`];
    if (relationships.artifactCollectionAvailable) workflowFacts.push(`Artifacts: ${artifactCountText(relationships.workflowArtifacts.length, relationships.artifacts.truncated)}`);
    level.append(element("span", "lane-label", "Workflow run"), laneNode("workflow", workflow.id, workflow.definition_name || workflow.workflow_name || "Workflow run", workflowFacts.join(" · "), workflow.status));
    levels.push(level);
  } else if (entry.executionId) {
    levels.push(element("div", "lane-unavailable", "Associated workflow lineage is unavailable."));
  }
  appendCollectionNotice(levels, "Tool runs", relationships.toolRuns);
  appendCollectionNotice(levels, "Approvals", relationships.approvals);
  if (relationships.steps.length) {
    levels.push(element("div", "lane-association", "Associated steps · stable display order, not dependency order"));
    const level = element("div", "lane-level");
    const stepLabel = projection ? "Workflow steps" : "Loaded workflow steps";
    level.append(element("span", "lane-label", `${stepLabel} (${relationships.steps.length})`));
    const list = element("div", "lane-steps");
    relationships.steps.forEach((model, index) => {
      const step = model.step;
      const branch = element("section", "lane-step-branch");
      const stepFacts = [step.capability || "No capability recorded"];
      if (relationships.artifactCollectionAvailable) stepFacts.push(`Artifacts: ${artifactCountText(model.artifacts.length, relationships.artifacts.truncated)}`);
      branch.append(laneNode("step", step.id, step.step_definition_id || `Step ${index + 1}`, stepFacts.join(" · "), step.status));
      if (model.toolRuns.length || model.approvals.length) {
        const children = element("div", "lane-children");
        children.append(element("span", "lane-label", "Associated by exact step-run ID"));
        model.toolRuns.forEach((tool) => children.append(toolLaneNode(tool, relationships.artifacts.truncated, relationships.artifactCollectionAvailable)));
        model.approvals.forEach((approval) => children.append(approvalLaneNode(approval)));
        branch.append(children);
      }
      list.append(branch);
    });
    level.append(list);
    levels.push(level);
  }
  const unassociated = [];
  if (relationships.unassociatedToolRuns.length) unassociated.push(unassociatedRecordText(relationships.unassociatedToolRuns.length, "tool run"));
  if (relationships.unassociatedApprovals.length) unassociated.push(unassociatedRecordText(relationships.unassociatedApprovals.length, "approval"));
  if (unassociated.length) {
    const level = element("div", "lane-unassociated");
    level.append(element("span", "lane-label", "Unassociated loaded records"));
    unassociated.forEach((message) => level.append(element("p", "", message)));
    levels.push(level);
  }
  if (entry.executionId) levels.push(renderExecutionChanges(entry, projection));
  if (!levels.length) levels.push(empty("No associated workflow lineage is available yet."));
  setChildren(lane, ...levels);
}

function inspectorShell(title, subtitle, status, details, ids = [], counts = [], extras = []) {
  const block = element("section");
  const heading = element("div", "inspector-heading");
  const copy = element("div");
  copy.append(element("h4", "", title), element("p", "", subtitle));
  heading.append(copy);
  if (status != null && status !== "") heading.append(statusBadge(status));
  block.append(heading);
  const list = element("dl", "inspector-details");
  appendDetails(list, details);
  block.append(list);
  if (counts.length) {
    const countGrid = element("div", "inspector-counts");
    counts.forEach(([label, value]) => {
      const item = element("div", "inspector-count");
      item.append(element("strong", "", value), element("span", "", label));
      countGrid.append(item);
    });
    block.append(countGrid);
  }
  if (extras.length) block.append(...extras.filter(Boolean));
  if (ids.length) {
    const disclosure = element("details", "compact-disclosure");
    disclosure.append(element("summary", "", "Lineage and IDs"));
    const idList = element("dl", "inspector-details mono");
    appendDetails(idList, ids);
    disclosure.append(idList);
    block.append(disclosure);
  }
  return block;
}

function renderRunInspector(entry, projection, relationships = partitionRunRelationships(entry, projection)) {
  const target = $("#run-inspector");
  if (!entry || !state.runWorkspace.item) {
    setChildren(target, empty("Select an execution, workflow, step, tool run, approval, or change."));
    return;
  }
  const selection = state.runWorkspace.item;
  if (selection.kind === "execution") {
    if (!projection) {
      const execution = entry.execution || {};
      const projectionState = entry.executionId && state.runWorkspace.projection.id === entry.executionId ? state.runWorkspace.projection : null;
      const notices = [];
      if (projectionState?.status === "loading") notices.push(inspectorNotice("status", "Loading the coherent execution observation. Showing limited dashboard snapshot facts."));
      if (projectionState?.status === "error") notices.push(inspectorNotice("alert", "Coherent execution detail is unavailable. Showing limited dashboard snapshot facts."));
      setChildren(target, inspectorShell(runEntryTitle(entry), "Limited execution detail · dashboard snapshot", execution.status, [
        ["Trigger", execution.trigger_source], ["Planned", formatTime(execution.planned_at, true)], ["Started", formatTime(execution.started_at, true)],
        ["Completed", formatTime(execution.completed_at, true)], ["Attempts", execution.attempt_count],
        ["Workflow reference", execution.workflow_run_id ? "Recorded" : "Not recorded"],
      ], availableDetails([
        ["Execution ID", execution.id], ["Schedule ID", execution.schedule_id], ["Scope version ID", execution.scope_version_id],
        ["Task ID", execution.task_id], ["Workflow run ID", execution.workflow_run_id],
      ]), [], notices));
      return;
    }
    const execution = projection.execution || {};
    const scheduler = projection.scheduler || {};
    const trigger = projection.trigger || {};
    const task = projection.task || null;
    const workflow = projection.workflow || null;
    const issues = Array.isArray(projection.lineage?.issues) ? projection.lineage.issues : [];
    const toolRuns = collectionValue(projection.tool_runs);
    const approvals = collectionValue(projection.approvals);
    const artifacts = collectionValue(projection.artifacts);
    const candidates = collectionValue(projection.candidate_findings);
    const changes = collectionValue(projection.change_items);
    const workflowAvailability = execution.workflow_run_id
      ? (workflow ? "Reference recorded; linked workflow row available" : "Workflow reference recorded; linked workflow details unavailable")
      : "No workflow reference recorded";
    const executionCounts = workflow ? [
      ["Steps", `${Array.isArray(projection.steps) ? projection.steps.length : 0} total`],
      ["Tool runs", projectionCollectionCountText(toolRuns)], ["Approvals", projectionCollectionCountText(approvals)],
      ["Visible artifact references", projectionCollectionCountText(artifacts)],
      ["Unverified candidate references", projectionCollectionCountText(candidates)],
      ["Observations", `${projection.asset_observations?.total ?? 0} total`],
      ["Distinct observed assets", projection.asset_observations?.distinct_asset_count ?? 0],
    ] : [];
    executionCounts.push(["Change items", projectionCollectionCountText(changes)]);
    setChildren(target, inspectorShell(projection.current_schedule?.name || `Execution ${shortID(execution.id)}`, `Current schedule · coherent observation ${formatTime(projection.observed_at, true)}`, scheduler.status, availableDetails([
      ["Observed at", formatTime(projection.observed_at, true)], ["Trigger", trigger.source], ["Planned", formatTime(trigger.planned_at, true)],
      ["Started", formatTime(scheduler.started_at, true)], ["Completed", formatTime(scheduler.completed_at, true)], ["Attempts", scheduler.attempt_count],
      ["Lease state", scheduler.lease_state], ["Lease expires", scheduler.lease_expires_at ? formatTime(scheduler.lease_expires_at, true) : null],
      ["Error classification", scheduler.error_classification], ["Error summary", scheduler.error_summary],
      ["Task objective", task?.objective], ["Task status", task?.status], ["Workflow status", workflow?.status],
      ["Workflow linkage", workflowAvailability], ["Lineage diagnostics", issues.length ? issues.length : null],
    ]), availableDetails([
      ["Execution ID", execution.id], ["Schedule ID", execution.schedule_id], ["Program ID", execution.program_id],
      ["Scope version ID", execution.scope_version_id], ["Task ID", execution.task_id], ["Workflow run ID", execution.workflow_run_id],
    ]), executionCounts));
    return;
  }
  if (selection.kind === "workflow") {
    const workflow = relationships.workflow;
    if (!workflow) {
      setChildren(target, empty("The linked workflow run is unavailable."));
      return;
    }
    const task = projection?.task || null;
    if (!projection) {
      setChildren(target, inspectorShell(workflow.workflow_name || "Workflow run", "Limited run detail · dashboard snapshot", workflow.status, availableDetails([
        ["Version", workflow.workflow_version], ["Trigger", workflow.trigger_source], ["Started", formatTime(workflow.started_at, true)],
        ["Completed", formatTime(workflow.completed_at, true)], ["Task objective", entry.run?.objective],
      ]), availableDetails([["Workflow run ID", workflow.id], ["Task ID", workflow.task_id]])));
      return;
    }
    const toolRuns = collectionValue(projection.tool_runs);
    const approvals = collectionValue(projection.approvals);
    const artifacts = collectionValue(projection.artifacts);
    const candidates = collectionValue(projection.candidate_findings);
    setChildren(target, inspectorShell(workflow.definition_name || "Workflow run", `Execution projection · current definition context · observed ${formatTime(projection.observed_at, true)}`, workflow.status, availableDetails([
      ["Stored workflow version", workflow.workflow_version], ["Trigger", workflow.trigger_source], ["Started", formatTime(workflow.started_at, true)],
      ["Completed", formatTime(workflow.completed_at, true)], ["Task objective", task?.objective], ["Task status", task?.status],
      ["Previous workflow run", workflow.previous_run_id ? "Reference recorded" : "None recorded"],
      ["Scheduled execution", entry.executionId ? "Associated" : null],
    ]), availableDetails([
      ["Scheduled execution ID", entry.executionId], ["Workflow run ID", workflow.id], ["Workflow definition ID", workflow.workflow_definition_id],
      ["Task ID", workflow.task_id], ["Previous workflow run ID", workflow.previous_run_id],
    ]), [
      ["Steps", `${relationships.steps.length} total`], ["Tool runs", projectionCollectionCountText(toolRuns)],
      ["Approvals", projectionCollectionCountText(approvals)], ["Visible artifact references", projectionCollectionCountText(artifacts)],
      ["Unverified candidate references", projectionCollectionCountText(candidates)],
      ["Observations", `${projection.asset_observations?.total ?? 0} total`],
      ["Distinct observed assets", projection.asset_observations?.distinct_asset_count ?? 0],
    ], [inspectorArtifactPreview(relationships.workflowArtifacts, artifacts)]));
    return;
  }
  if (selection.kind === "change") {
    const change = findProjectedChange(projection, selection.id);
    if (!change) return;
    const sources = Array.isArray(change.source_capabilities) ? change.source_capabilities : [];
    const evidence = Array.isArray(change.evidence_artifact_ids) ? change.evidence_artifact_ids : [];
    setChildren(target, inspectorShell(`${change.kind || "Change"} · ${change.entity_type || "entity"}`, "Recorded execution change metadata", change.priority, [
      ["Kind", change.kind || "Not recorded"], ["Entity type", change.entity_type || "Not recorded"],
      ["Priority", change.priority || "Not recorded"], ["Source capabilities", sources.length ? sources.join(", ") : "None recorded"],
      ["Observed", formatTime(change.observed_at, true)], ["Created", formatTime(change.created_at, true)],
    ], [
      ["Change ID", change.id], ["Program ID", change.program_id], ["Workflow run ID", change.workflow_run_id],
      ["Scheduled execution ID", change.scheduled_execution_id], ["Evidence artifact IDs", evidence.length ? evidence.join(", ") : "None recorded"],
    ]));
    return;
  }
  if (selection.kind === "tool") {
    const model = findRelationshipItem(relationships, "tool", selection.id);
    if (!model) return;
    const tool = model.tool;
    const artifacts = relationships.artifacts;
    const artifactCounts = relationships.artifactCollectionAvailable
      ? [["Visible artifact references", associatedCountText(model.artifacts.length, artifacts)]]
      : [];
    setChildren(target, inspectorShell(`${tool.provider || "Tool run"}${tool.tool_version ? ` ${tool.tool_version}` : ""}`, "Recorded tool-run facts", null, [
      ["Provider", tool.provider], ["Tool version", tool.tool_version], ["Capability", tool.capability], ["Step definition", tool.step_definition_id],
      ["Started", formatTime(tool.started_at, true)], ["Completed", tool.completed_at ? formatTime(tool.completed_at, true) : "Not completed at observation"], ["Timed out", boolText(tool.timed_out)],
      ["Exit code", tool.exit_code == null ? "Not recorded" : tool.exit_code], ["Stdout reference", tool.stdout_artifact_id ? "Present" : "Not recorded"],
      ["Stderr reference", tool.stderr_artifact_id ? "Present" : "Not recorded"],
    ], availableDetails([
      ["Tool run ID", tool.id], ["Step run ID", tool.step_run_id], ["Step definition ID", tool.step_definition_id],
      ["Workflow run ID", model.step?.workflow_run_id], ["Stdout artifact ID", tool.stdout_artifact_id], ["Stderr artifact ID", tool.stderr_artifact_id],
    ]), artifactCounts, [relationships.artifactCollectionAvailable ? inspectorArtifactPreview(model.artifacts, artifacts) : null]));
    return;
  }
  if (selection.kind === "approval") {
    const model = findRelationshipItem(relationships, "approval", selection.id);
    if (!model) return;
    const approval = model.approval;
    setChildren(target, inspectorShell("Approval", `Requested risk: ${approval.requested_risk_level || "not recorded"}`, approval.decision, [
      ["Decision", approval.decision || "Not recorded"], ["Requested risk level", approval.requested_risk_level || "Not recorded"], ["Reason", approval.reason || "Not recorded"],
      ["Requested", formatTime(approval.requested_at, true)], ["Decided", formatTime(approval.decided_at, true)],
      ["Expiry", formatTime(approval.expires_at, true)], ["Actor", approval.decided_by || "Not recorded"],
    ], [["Approval ID", approval.id], ["Step run ID", approval.step_run_id], ["Task ID", approval.task_id]]));
    return;
  }
  const model = findRelationshipItem(relationships, "step", selection.id);
  if (!model) return;
  const step = model.step;
  const artifacts = relationships.artifacts;
  const childCounts = projection ? [
    ["Tool runs", associatedCountText(model.toolRuns.length, relationships.toolRuns)],
    ["Approvals", associatedCountText(model.approvals.length, relationships.approvals)],
    ["Visible artifact references", associatedCountText(model.artifacts.length, artifacts)],
  ] : [];
  setChildren(target, inspectorShell(step.step_definition_id || "Workflow step", step.capability || "No capability recorded", step.status, [
    ["Attempt count", step.attempt_count], ["Approval state", step.approval_state], ["Started", formatTime(step.started_at, true)],
    ["Completed", formatTime(step.completed_at, true)], ["Error classification", step.error_classification],
  ], availableDetails([
    ["Step run ID", step.id], ["Step definition ID", step.step_definition_id], ["Workflow run ID", step.workflow_run_id],
    ["Task ID", projection?.workflow?.task_id || projection?.task?.id],
  ]), childCounts, [projection ? inspectorArtifactPreview(model.artifacts, artifacts) : null]));
}

function renderRunWorkspace(entry) {
  const projection = currentRunProjection(entry);
  const relationships = partitionRunRelationships(entry, projection);
  resolveRunWorkspaceItem(entry, relationships, projection);
  const actions = $("#run-workspace-actions");
  if (!entry) {
    $("#run-workspace-eyebrow").textContent = "Run workspace";
    $("#run-workspace-title").textContent = "No runs available";
    $("#run-workspace-meta").textContent = "Create or schedule a workflow to begin.";
    actions.replaceChildren();
    renderRunLane(null, null);
    renderRunInspector(null, null);
    return;
  }
  const projected = Boolean(projection);
  const projectionState = entry.executionId && state.runWorkspace.projection.id === entry.executionId ? state.runWorkspace.projection : null;
  $("#run-workspace-eyebrow").textContent = entry.executionId ? "Scheduled execution" : "Workflow run";
  $("#run-workspace-title").textContent = projected ? (projection.current_schedule?.name || runEntryTitle(entry)) : runEntryTitle(entry);
  let stateCopy = "limited dashboard snapshot detail";
  if (projected) stateCopy = `observed ${formatTime(projection.observed_at, true)}`;
  else if (projectionState?.status === "loading") stateCopy = "loading coherent execution observation";
  else if (projectionState?.status === "error") stateCopy = projectionState.error;
  $("#run-workspace-meta").textContent = `${entry.kind === "execution" ? "Execution" : "Run"} ${entry.id} · ${stateCopy}`;
  const actionItems = runStatusBadges(entry, projection);
  if (projected) {
    const full = element("button", "secondary-button", "Full detail");
    full.type = "button";
    full.dataset.fullDetailId = entry.executionId;
    full.addEventListener("click", () => openExecutionDetail(entry.executionId, full, { selector: "[data-full-detail-id]", datasetKey: "fullDetailId", id: entry.executionId }));
    actionItems.push(full);
  } else if (projectionState?.status === "error") {
    const retry = element("button", "secondary-button", "Retry detail");
    retry.type = "button";
    retry.addEventListener("click", () => loadRunWorkspaceProjection(entry.executionId));
    actionItems.push(retry);
  } else if (!entry.executionId && entry.run) {
    const full = element("button", "secondary-button", "Full detail");
    full.type = "button";
    full.dataset.runId = entry.workflowRunId;
    full.addEventListener("click", () => openRunDrawer(entry.run, full));
    actionItems.push(full);
  }
  setChildren(actions, ...actionItems);
  renderRunLane(entry, projection, relationships);
  renderRunInspector(entry, projection, relationships);
}

function runWorkspaceItemKey(item = state.runWorkspace.item) {
  return item ? `${item.kind}:${item.id}` : "";
}

function runWorkspaceFocusKey(item = document.activeElement) {
  if (item?.dataset?.workspaceItem) return `item:${item.dataset.workspaceItem}`;
  if (item?.dataset?.workspaceControl) return `control:${item.dataset.workspaceControl}`;
  return "";
}

function focusRunWorkspaceControl(key) {
  if (!key) return false;
  const [kind, value] = key.split(/:(.*)/s);
  const controls = kind === "item" ? $$('[data-workspace-item]') : $$('[data-workspace-control]');
  const control = controls.find((item) => (kind === "item" ? item.dataset.workspaceItem : item.dataset.workspaceControl) === value);
  if (!control) return false;
  try {
    control.focus({ preventScroll: true });
  } catch (_error) {
    control.focus();
  }
  return true;
}

function focusRunWorkspaceItem(key = runWorkspaceItemKey()) {
  return focusRunWorkspaceControl(key ? `item:${key}` : "");
}

function toggleExecutionChanges(executionID) {
  state.runWorkspace.expandedChangeExecutionID = exactID(state.runWorkspace.expandedChangeExecutionID, executionID) ? "" : String(executionID);
  renderRunWorkspace(selectedRunEntry());
  focusRunWorkspaceControl(`control:change-expansion:${executionID}`);
}

function renderRuns() {
  const focusedControlKey = runWorkspaceFocusKey();
  const selectedItemKey = runWorkspaceItemKey();
  const entries = runWorkspaceEntries();
  const selected = selectedRunEntry(entries);
  if (selected && runEntryKey(selected) !== runEntryKey(state.runWorkspace.selection)) {
    state.runWorkspace.selection = { kind: selected.kind, id: selected.id };
    state.runWorkspace.item = { kind: selected.executionId ? "execution" : "workflow", id: selected.executionId || selected.workflowRunId };
    state.runWorkspace.expandedChangeExecutionID = "";
    if (state.runWorkspace.projection.id !== selected.executionId) resetRunWorkspaceProjection();
  } else if (!selected) {
    state.runWorkspace.selection = null;
    state.runWorkspace.item = null;
    state.runWorkspace.expandedChangeExecutionID = "";
    resetRunWorkspaceProjection();
  }
  renderRunSelector(entries, selected);
  renderRunWorkspace(selected);
  if (focusedControlKey && !focusRunWorkspaceControl(focusedControlKey) && focusedControlKey === `item:${selectedItemKey}`) {
    focusRunWorkspaceItem();
  }
}

function selectRunWorkspaceItem(kind, id) {
  state.runWorkspace.item = { kind, id: String(id) };
  renderRunWorkspace(selectedRunEntry());
  if (state.runWorkspace.item?.kind !== kind || !exactID(state.runWorkspace.item.id, id)) return;
  focusRunWorkspaceItem();
}

async function selectRunWorkspaceEntry(entry, { focus = false } = {}) {
  setRunWorkspaceSelection(entry);
  renderRuns();
  if (focus) $("#run-workspace-header").focus();
  if (!entry?.executionId) return;
  await loadRunWorkspaceProjection(entry.executionId);
}

function activateRunWorkspace({ focus = false } = {}) {
  const entry = selectedRunEntry();
  if (!entry) {
    renderRuns();
    return Promise.resolve();
  }
  return selectRunWorkspaceEntry(entry, { focus });
}

function openExecutionWorkspace(id) {
  const entry = runWorkspaceEntries().find((item) => item.executionId === String(id));
  if (!entry) return Promise.resolve();
  setRunWorkspaceSelection(entry);
  return showView("runs", { focusWorkspace: true });
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
    const workspace = element("button", "primary-button", "Open workspace");
    workspace.type = "button";
    workspace.dataset.workspaceExecutionId = String(item.id);
    workspace.addEventListener("click", () => openExecutionWorkspace(item.id));
    const details = element("button", "secondary-button", "View details");
    details.type = "button";
    details.dataset.executionId = String(item.id);
    details.addEventListener("click", () => openExecutionDetail(item.id, details));
    actions.append(workspace, details);
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
      button.addEventListener("click", () => postAction(`/api/v1/change-items/${encodeURIComponent(item.id)}/review`, { disposition, note: note.value.trim() }, "Change review saved."));
      actions.append(button);
    }
    card.append(copy, meta, statusBadge(item.disposition || "unreviewed"), actions);
    return card;
  }));
}

function openRunDrawer(run, opener = null) {
  cancelExecutionDetail();
  const steps = latestRunSteps(run);
  openDrawer({
    eyebrow: "Run detail",
    title: run.objective,
    returnFocus: opener,
    returnTarget: { selector: "[data-run-id]", datasetKey: "runId", id: String(run.id) },
  });
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
  $("#detail-drawer").setAttribute("aria-busy", "false");
}

function lockDrawerScroll() {
  if (state.drawer.scrollLock?.locked) return;
  const x = Number.isFinite(window.scrollX) ? window.scrollX : 0;
  const y = Number.isFinite(window.scrollY) ? window.scrollY : 0;
  state.drawer.scrollLock = { locked: true, x, y };
  document.documentElement.classList.add("detail-drawer-open");
  document.body.classList.add("detail-drawer-open");
  void document.documentElement.offsetHeight;
  window.scrollTo(x, y);
}

function preserveDrawerScrollPosition() {
  const lock = state.drawer.scrollLock;
  if (!lock?.locked || (window.scrollX === lock.x && window.scrollY === lock.y)) return;
  window.scrollTo(lock.x, lock.y);
}

function preventDrawerBackgroundScroll(event) {
  if (!state.drawer.scrollLock?.locked) return;
  event.preventDefault();
  preserveDrawerScrollPosition();
}

function unlockDrawerScroll() {
  const lock = state.drawer.scrollLock;
  document.documentElement.classList.remove("detail-drawer-open");
  document.body.classList.remove("detail-drawer-open");
  state.drawer.scrollLock = { locked: false, x: 0, y: 0 };
  if (lock?.locked) window.scrollTo(lock.x, lock.y);
}

function openDrawer({ eyebrow, title, returnFocus = null, returnTarget = null }) {
  state.drawer.returnFocus = returnFocus;
  state.drawer.returnTarget = returnTarget;
  lockDrawerScroll();
  $("#drawer-eyebrow").textContent = eyebrow;
  $("#drawer-title").textContent = title;
  $("#drawer-backdrop").classList.remove("hidden");
  const drawer = $("#detail-drawer");
  drawer.tabIndex = -1;
  drawer.classList.add("open");
  drawer.removeAttribute("inert");
  drawer.setAttribute("aria-hidden", "false");
  $("#drawer-close").focus();
}

function resetExecutionDetail() {
  state.executionDetail = { id: "", status: "idle", data: null, error: "", controller: null };
}

function cancelExecutionDetail() {
  const controller = state.executionDetail.controller;
  state.executionDetail.controller = null;
  if (controller) controller.abort();
  resetExecutionDetail();
}

function closeDrawer() {
  const returnTarget = state.drawer.returnTarget;
  const returnFocus = state.drawer.returnFocus;
  unlockDrawerScroll();
  cancelExecutionDetail();
  $("#drawer-backdrop").classList.add("hidden");
  const drawer = $("#detail-drawer");
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
  drawer.setAttribute("aria-busy", "false");
  drawer.setAttribute("inert", "");
  const currentReturnTarget = returnTarget
    ? $$(returnTarget.selector).find((item) => item.dataset[returnTarget.datasetKey] === returnTarget.id)
    : null;
  const target = currentReturnTarget || returnFocus;
  state.drawer = { returnFocus: null, returnTarget: null, scrollLock: { locked: false, x: 0, y: 0 } };
  if (target && typeof target.focus === "function") target.focus({ preventScroll: true });
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
    action: () => postAction(`/api/v1/approvals/${encodeURIComponent(item.id)}/decision`, { decision }, `Approval ${decision}.`),
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

function detailBlock(title, details = []) {
  const block = element("section", "detail-block");
  block.append(element("h3", "", title));
  if (details.length) {
    const list = element("dl", "modal-details detail-grid");
    appendDetails(list, details);
    block.append(list);
  }
  return block;
}

function detailSubsection(title, details) {
  const block = element("div", "detail-subsection");
  block.append(element("h4", "", title));
  const list = element("dl", "modal-details detail-grid");
  appendDetails(list, details);
  block.append(list);
  return block;
}

function boolText(value) {
  return value ? "Yes" : "No";
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function collectionValue(value) {
  const items = Array.isArray(value?.items) ? value.items : [];
  const total = Number.isFinite(Number(value?.total)) ? Number(value.total) : items.length;
  return { items, total, truncated: Boolean(value?.truncated) };
}

function appendCollectionSummary(block, collection) {
  const summary = element("div", "collection-summary");
  summary.append(element("span", "", `Showing ${collection.items.length} of ${collection.total}`));
  if (collection.truncated) summary.append(element("span", "status-badge warning", "Results truncated"));
  block.append(summary);
}

function appendEmptyOrItems(block, items, emptyMessage, renderItem) {
  if (!items.length) {
    block.append(empty(emptyMessage));
    return;
  }
  const list = element("div", "detail-item-list");
  items.forEach((item, index) => list.append(renderItem(item, index)));
  block.append(list);
}

const lineageIssueDescriptions = {
  scope_missing: "The referenced scope row was unavailable.",
  scope_program_mismatch: "The scope program does not match the execution program.",
  task_missing: "The referenced task row was unavailable.",
  task_program_mismatch: "The task program does not match the execution program.",
  workflow_missing: "The referenced workflow run was unavailable.",
  workflow_without_execution_task: "A workflow is linked while the execution has no task link.",
  workflow_task_mismatch: "The workflow task does not match the execution task.",
  workflow_definition_missing: "The referenced workflow definition was unavailable.",
  workflow_definition_mismatch: "Task and workflow definition links do not match.",
  workflow_definition_version_mismatch: "The workflow run version differs from the current definition version.",
  approval_lineage_inconsistent: "At least one approval has contradictory task lineage.",
  artifact_lineage_inconsistent: "At least one artifact has contradictory execution lineage.",
  candidate_finding_lineage_inconsistent: "At least one candidate has contradictory execution lineage.",
  asset_observation_lineage_inconsistent: "At least one observation has contradictory program lineage.",
  change_item_lineage_inconsistent: "At least one change item has contradictory execution lineage.",
};

function renderExecutionLoading(id) {
  $("#detail-drawer").setAttribute("aria-busy", "true");
  const loading = element("div", "detail-state");
  loading.setAttribute("role", "status");
  loading.setAttribute("aria-live", "polite");
  loading.append(element("div", "scanner-line"), element("h3", "", "Loading execution detail"), element("p", "", `Reading the coherent projection for execution ${id}.`));
  setChildren($("#drawer-content"), loading);
}

function renderExecutionError(message, id) {
  $("#detail-drawer").setAttribute("aria-busy", "false");
  const failure = element("div", "detail-state detail-error");
  failure.setAttribute("role", "alert");
  failure.append(element("h3", "", message), element("p", "", `Execution ${id}`));
  const retry = element("button", "secondary-button", "Retry");
  retry.type = "button";
  retry.addEventListener("click", () => openExecutionDetail(id, retry));
  failure.append(retry);
  setChildren($("#drawer-content"), failure);
}

function renderExecutionProjection(projection) {
  const execution = projection?.execution || {};
  const scheduler = projection?.scheduler || {};
  const trigger = projection?.trigger || {};
  const schedule = projection?.current_schedule || {};
  const program = projection?.current_program || {};
  const scope = projection?.scope || null;
  const task = projection?.task || null;
  const workflow = projection?.workflow || null;
  const steps = Array.isArray(projection?.steps) ? projection.steps : [];
  const issues = Array.isArray(projection?.lineage?.issues) ? projection.lineage.issues : [];

  $("#drawer-title").textContent = schedule.name || `Execution ${shortID(execution.id || state.executionDetail.id)}`;
  $("#detail-drawer").setAttribute("aria-busy", "false");

  const summary = detailBlock("Execution summary");
  const summaryHead = element("div", "detail-summary-head");
  const summaryCopy = element("div");
  summaryCopy.append(element("strong", "mono", execution.id || state.executionDetail.id), element("small", "", `Observed ${formatTime(projection?.observed_at, true)}`));
  summaryHead.append(summaryCopy, statusBadge(scheduler.status));
  summary.append(summaryHead);

  const blocks = [summary];
  if (issues.length) {
    const diagnostics = detailBlock("Lineage diagnostics");
    diagnostics.classList.add("diagnostic-block");
    const list = element("div", "warning-list");
    issues.forEach((issue) => {
      const row = element("div", "warning-row");
      row.append(element("strong", "mono", issue), element("span", "", lineageIssueDescriptions[issue] || "The projection reported a lineage inconsistency."));
      list.append(row);
    });
    diagnostics.append(list);
    blocks.push(diagnostics);
  }

  blocks.push(detailBlock("Scheduler status", [
    ["Status", scheduler.status],
    ["Trigger", trigger.source],
    ["Planned", formatTime(trigger.planned_at, true)],
    ["Started", formatTime(scheduler.started_at, true)],
    ["Completed", formatTime(scheduler.completed_at, true)],
    ["Attempts", scheduler.attempt_count],
    ["Lease state", scheduler.lease_state],
    ["Lease owner", scheduler.lease_owner],
    ["Lease expires", formatTime(scheduler.lease_expires_at, true)],
    ["Recovery protocol", scheduler.recovery_protocol_version],
    ["Error classification", scheduler.error_classification],
    ["Error summary", scheduler.error_summary],
    ["Execution created", formatTime(execution.created_at, true)],
    ["Execution updated", formatTime(execution.updated_at, true)],
  ]));

  const current = detailBlock("Current program / schedule");
  current.append(element("p", "detail-note", "Current schedule settings are mutable and are not an execution-time schedule snapshot."));
  current.append(detailSubsection("Program", [["Name", program.name], ["Platform", program.platform], ["Program ID", program.id]]));
  current.append(detailSubsection("Current schedule settings", [
    ["Name", schedule.name], ["Workflow", schedule.workflow_name], ["Objective", schedule.objective],
    ["Cron", schedule.cron_expression], ["Timezone", schedule.timezone], ["Enabled", boolText(schedule.enabled)],
    ["Headless", boolText(schedule.headless)], ["Created by", schedule.created_by],
    ["Last run", formatTime(schedule.last_run_at, true)], ["Next run", formatTime(schedule.next_run_at, true)],
  ]));
  blocks.push(current);

  const lineage = detailBlock("Lineage");
  lineage.append(detailSubsection("Execution links", [
    ["Execution ID", execution.id], ["Schedule ID", execution.schedule_id], ["Program ID", execution.program_id],
    ["Scope version ID", execution.scope_version_id || "Not linked"], ["Task ID", execution.task_id || "Not linked"],
    ["Workflow run ID", execution.workflow_run_id || "Not linked"],
  ]));
  if (scope) {
    const scopeDetails = detailSubsection("Scope", [
      ["ID", scope.id], ["Current scope reference", scope.scope_reference], ["Scope digest", scope.scope_digest],
      ["Target plan digest", scope.target_plan_digest], ["Expands scope", boolText(scope.expands_scope)],
      ["Acknowledged", formatTime(scope.acknowledged_at, true)], ["Created", formatTime(scope.created_at, true)],
    ]);
    scopeDetails.append(element("p", "detail-note", "Scope and target-plan digests are historical values on this scope row. Scope reference is current locator metadata and may have been repaired."));
    lineage.append(scopeDetails);
  } else {
    lineage.append(element("p", "empty-copy", `Scope: ${execution.scope_version_id ? "Unavailable" : "Not linked"}`));
  }
  lineage.append(task ? detailSubsection("Task", [
    ["ID", task.id], ["Objective", task.objective], ["Status", task.status], ["Requested by", task.requested_by],
    ["Workflow definition ID", task.workflow_definition_id], ["Schedule reference", task.schedule_reference],
    ["Cancelled", formatTime(task.cancelled_at, true)], ["Created", formatTime(task.created_at, true)], ["Updated", formatTime(task.updated_at, true)],
  ]) : element("p", "empty-copy", `Task: ${execution.task_id ? "Unavailable" : "Not linked"}`));
  lineage.append(workflow ? detailSubsection("Workflow run", [
    ["ID", workflow.id], ["Task ID", workflow.task_id], ["Workflow definition ID", workflow.workflow_definition_id],
    ["Definition name", workflow.definition_name], ["Workflow version", workflow.workflow_version], ["Status", workflow.status],
    ["Previous run ID", workflow.previous_run_id], ["Trigger", workflow.trigger_source],
    ["Started", formatTime(workflow.started_at, true)], ["Completed", formatTime(workflow.completed_at, true)],
  ]) : element("p", "empty-copy", `Workflow run: ${execution.workflow_run_id ? "Unavailable" : "Not linked"}`));
  blocks.push(lineage);

  const stepBlock = detailBlock("Workflow steps");
  appendEmptyOrItems(stepBlock, steps, "No workflow steps are linked to this execution.", (step, index) => {
    const row = element("div", "detail-item step-detail");
    const copy = element("div");
    copy.append(element("strong", "", step.step_definition_id || `Step ${index + 1}`), element("small", "", `${step.capability || "—"} · ${step.attempt_count || 0} attempt${step.attempt_count === 1 ? "" : "s"}`));
    const facts = element("dl", "compact-details");
    appendDetails(facts, [["Step ID", step.id], ["Workflow run", step.workflow_run_id], ["Approval", step.approval_state], ["Error", step.error_classification], ["Started", formatTime(step.started_at, true)], ["Completed", formatTime(step.completed_at, true)]]);
    copy.append(facts);
    row.append(element("span", "step-index", String(index + 1).padStart(2, "0")), copy, statusBadge(step.status));
    return row;
  });
  blocks.push(stepBlock);

  const toolRuns = collectionValue(projection?.tool_runs);
  const toolBlock = detailBlock("Tool runs");
  appendCollectionSummary(toolBlock, toolRuns);
  appendEmptyOrItems(toolBlock, toolRuns.items, "No tool runs are linked to this execution.", (item) => detailSubsection(`${item.provider || "Unknown provider"}${item.tool_version ? ` · ${item.tool_version}` : ""}`, [
    ["ID", item.id], ["Step run ID", item.step_run_id], ["Step definition", item.step_definition_id], ["Capability", item.capability],
    ["Started", formatTime(item.started_at, true)], ["Completed", formatTime(item.completed_at, true)],
    ["Exit code", item.exit_code], ["Timed out", boolText(item.timed_out)],
    ["Stdout artifact ID", item.stdout_artifact_id], ["Stderr artifact ID", item.stderr_artifact_id],
  ]));
  blocks.push(toolBlock);

  const approvals = collectionValue(projection?.approvals);
  const approvalBlock = detailBlock("Approvals");
  appendCollectionSummary(approvalBlock, approvals);
  appendEmptyOrItems(approvalBlock, approvals.items, "No approvals are linked to this execution.", (item) => detailSubsection(item.reason || `Approval ${shortID(item.id)}`, [
    ["ID", item.id], ["Step run ID", item.step_run_id], ["Task ID", item.task_id], ["Risk level", item.requested_risk_level],
    ["Decision", item.decision], ["Requested", formatTime(item.requested_at, true)], ["Decided by", item.decided_by],
    ["Decided", formatTime(item.decided_at, true)], ["Expires", formatTime(item.expires_at, true)],
  ]));
  blocks.push(approvalBlock);

  const artifacts = collectionValue(projection?.artifacts);
  const artifactBlock = detailBlock("Artifact references");
  artifactBlock.append(element("p", "detail-note", "Metadata only. Artifact contents are not retrieved by this console view."));
  appendCollectionSummary(artifactBlock, artifacts);
  appendEmptyOrItems(artifactBlock, artifacts.items, "No visible artifact references are linked to this execution.", (item) => detailSubsection(`${item.type || "Artifact"} · ${shortID(item.id)}`, [
    ["ID", item.id], ["Task ID", item.task_id], ["Workflow run ID", item.workflow_run_id], ["Step run ID", item.step_run_id],
    ["Tool run ID", item.tool_run_id], ["Content type", item.content_type], ["Size", formatBytes(item.size)],
    ["SHA-256", item.sha256], ["Redaction state", item.redaction_state], ["Created", formatTime(item.created_at, true)], ["Expires", formatTime(item.expires_at, true)],
  ]));
  blocks.push(artifactBlock);

  const candidates = collectionValue(projection?.candidate_findings);
  const candidateBlock = detailBlock("Candidate findings");
  candidateBlock.append(element("p", "detail-note", "Candidate metadata is separate from verified findings. Status and updated time reflect current candidate state. Verification provenance is not included in this projection."));
  appendCollectionSummary(candidateBlock, candidates);
  appendEmptyOrItems(candidateBlock, candidates.items, "No candidate findings are linked to this execution.", (item) => detailSubsection(`Candidate ${shortID(item.id)}`, [
    ["ID", item.id], ["Task ID", item.task_id], ["Workflow run ID", item.workflow_run_id], ["Target asset ID", item.target_asset_id],
    ["Source capability", item.source_capability], ["Detection confidence", `${Math.round((Number(item.detection_confidence) || 0) * 100)}%`],
    ["Current status", item.status], ["Evidence artifact IDs", (Array.isArray(item.evidence_artifact_ids) ? item.evidence_artifact_ids : []).join(", ")],
    ["Created", formatTime(item.created_at, true)], ["Current state updated", formatTime(item.updated_at, true)],
  ]));
  blocks.push(candidateBlock);

  blocks.push(detailBlock("Asset observation summary", [
    ["Observations", projection?.asset_observations?.total ?? 0],
    ["Distinct assets", projection?.asset_observations?.distinct_asset_count ?? 0],
  ]));

  const changes = collectionValue(projection?.change_items);
  const changeBlock = detailBlock("Change items");
  appendCollectionSummary(changeBlock, changes);
  appendEmptyOrItems(changeBlock, changes.items, "No change items are linked to this execution.", (item) => detailSubsection(`${item.kind || "Change"} · ${item.entity_type || "entity"}`, [
    ["ID", item.id], ["Program ID", item.program_id], ["Workflow run ID", item.workflow_run_id], ["Scheduled execution ID", item.scheduled_execution_id],
    ["Priority", item.priority], ["Source capabilities", (Array.isArray(item.source_capabilities) ? item.source_capabilities : []).join(", ")],
    ["Evidence artifact IDs", (Array.isArray(item.evidence_artifact_ids) ? item.evidence_artifact_ids : []).join(", ")],
    ["Observed", formatTime(item.observed_at, true)], ["Created", formatTime(item.created_at, true)],
  ]));
  blocks.push(changeBlock);

  if (!issues.length) {
    blocks.push(detailBlock("Projection diagnostics", [["Lineage issues reported", 0]]));
  }
  setChildren($("#drawer-content"), ...blocks);
}

async function requestExecutionProjection(id, { onLoading, onReady, onError }) {
  cancelExecutionDetail();
  const selectedID = String(id || "");
  const controller = new AbortController();
  state.executionDetail = { id: selectedID, status: "loading", data: null, error: "", controller };
  onLoading(selectedID);
  try {
    const response = await fetch(`/api/v1/scheduled-executions/${encodeURIComponent(selectedID)}`, {
      headers: { Accept: "application/json" },
      cache: "no-store",
      signal: controller.signal,
    });
    const body = await response.json().catch(() => null);
    if (state.executionDetail.controller !== controller || state.executionDetail.id !== selectedID) return;
    if (!response.ok) {
      const message = response.status === 404 ? "Scheduled execution no longer exists." : "Execution detail is temporarily unavailable.";
      state.executionDetail = { id: selectedID, status: "error", data: null, error: message, controller };
      onError(message, selectedID);
      return;
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("invalid execution detail response");
    state.executionDetail = { id: selectedID, status: "ready", data: body, error: "", controller };
    onReady(body, selectedID);
    return body;
  } catch (error) {
    if (error?.name === "AbortError") return;
    if (state.executionDetail.controller !== controller || state.executionDetail.id !== selectedID) return;
    const message = "Execution detail is temporarily unavailable.";
    state.executionDetail = { id: selectedID, status: "error", data: null, error: message, controller };
    onError(message, selectedID);
  }
}

async function loadRunWorkspaceProjection(id) {
  const selectedID = String(id || "");
  const cached = state.runWorkspace.projection;
  if (cached.id === selectedID && cached.status === "ready") {
    renderRuns();
    return cached.data;
  }
  if (cached.id === selectedID && cached.status === "loading" && state.executionDetail.id === selectedID && state.executionDetail.status === "loading") return null;
  state.runWorkspace.projection = { id: selectedID, status: "loading", data: null, error: "" };
  renderRuns();
  return requestExecutionProjection(selectedID, {
    onLoading() {},
    onReady(body) {
      if (selectedRunEntry()?.executionId !== selectedID) return;
      state.runWorkspace.projection = { id: selectedID, status: "ready", data: body, error: "" };
      if (!state.runWorkspace.item) state.runWorkspace.item = { kind: "execution", id: selectedID };
      renderRuns();
    },
    onError(message) {
      if (selectedRunEntry()?.executionId !== selectedID) return;
      state.runWorkspace.projection = { id: selectedID, status: "error", data: null, error: message };
      renderRuns();
    },
  });
}

async function openExecutionDetail(id, opener = null, returnTarget = null) {
  const selectedID = String(id || "");
  const cached = state.runWorkspace.projection.id === selectedID && state.runWorkspace.projection.status === "ready"
    ? state.runWorkspace.projection.data
    : null;
  if (cached) {
    cancelExecutionDetail();
    state.executionDetail = { id: selectedID, status: "ready", data: cached, error: "", controller: null };
    openDrawer({
      eyebrow: "Scheduled execution",
      title: `Execution ${shortID(selectedID)}`,
      returnFocus: opener,
      returnTarget: returnTarget || { selector: "[data-execution-id]", datasetKey: "executionId", id: selectedID },
    });
    renderExecutionProjection(cached);
    return cached;
  }
  return requestExecutionProjection(selectedID, {
    onLoading() {
      openDrawer({
        eyebrow: "Scheduled execution",
        title: `Execution ${shortID(selectedID)}`,
        returnFocus: opener,
        returnTarget: returnTarget || { selector: "[data-execution-id]", datasetKey: "executionId", id: selectedID },
      });
      renderExecutionLoading(selectedID);
    },
    onReady(body) {
      if (selectedRunEntry()?.executionId === selectedID) state.runWorkspace.projection = { id: selectedID, status: "ready", data: body, error: "" };
      renderExecutionProjection(body);
    },
    onError: renderExecutionError,
  });
}

function openModal(config) {
  state.modalGeneration++;
  state.exactApprovals.modalOwner = false;
  state.exactApprovals.returnFocus = null;
  state.modalAction = config.action;
  $("#modal-confirm").disabled = false;
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
  state.modalGeneration++;
  state.modalAction = null;
  $("#action-modal").classList.add("hidden");
  if (state.exactApprovals.modalOwner) {
    state.exactApprovals.modalOwner = false;
    const opener = state.exactApprovals.returnFocus;
    if (opener && opener.isConnected !== false) opener.focus();
    else $("#exact-approval-detail")?.focus();
    state.exactApprovals.returnFocus = null;
  }
}

async function postAction(path, body, successMessage) {
  const button = $("#modal-confirm");
  button.disabled = true;
  try {
	if (!state.operatorCredential) throw new Error("Unlock operator actions first.");
	const verificationGeneration = state.operatorVerificationGeneration;
    const response = await fetch(path, {
      method: "POST",
      headers: operatorMutationHeaders(),
      body: JSON.stringify(body),
    });
	if (response.status === 401 && verificationGeneration === state.operatorVerificationGeneration) lockOperatorActions();
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

function operatorMutationHeaders() {
	return { "Content-Type": "application/json", "X-Reconductor-Request": "operator-console", Accept: "application/json", Authorization: `Bearer ${state.operatorCredential}` };
}

function lockOperatorActions() {
	state.operatorCredential = "";
	clearExactReviews();
	const status = $("#operator-credential-status");
	if (status) status.textContent = "Actions locked";
}

async function verifyOperatorCredential(credential) {
	const generation = ++state.operatorVerificationGeneration;
	lockOperatorActions();
	try {
		const response = await fetch("/api/v1/operator/check", {
			headers: { Authorization: `Bearer ${credential}`, Accept: "application/json" }, cache: "no-store",
		});
		if (generation !== state.operatorVerificationGeneration) return null;
		if (!response.ok) return false;
		state.operatorCredential = credential;
		const status = $("#operator-credential-status");
		if (status) status.textContent = "Actions unlocked for this page";
		return true;
	} catch {
		return generation === state.operatorVerificationGeneration ? "unavailable" : null;
	}
}

function toast(message, isError = false) {
  const item = element("div", `toast ${isError ? "error" : ""}`.trim(), message);
  $("#toast-region").append(item);
  setTimeout(() => item.remove(), 4500);
}

async function submitOperatorCredential(event) {
	event.preventDefault();
	const input = $("#operator-credential");
	const credential = input.value;
	input.value = "";
	const verification = verifyOperatorCredential(credential);
	const generation = state.operatorVerificationGeneration;
	const result = await verification;
	if (generation !== state.operatorVerificationGeneration) return;
	if (result === true && state.view === "exact-approvals") await refreshExactApprovals();
	if (generation !== state.operatorVerificationGeneration) return;
	if (result === false) toast("Operator credential was not accepted.", true);
	if (result === "unavailable") toast("Could not check the operator credential.", true);
}

function bindEvents() {
	$("#operator-credential-form").addEventListener("submit", submitOperatorCredential);
  $$(".nav-item").forEach((item) => item.addEventListener("click", () => showView(item.dataset.view)));
  $$('[data-go-view]').forEach((item) => item.addEventListener("click", () => showView(item.dataset.goView)));
  $("#program-select").addEventListener("change", (event) => {
    state.selectedProgram = event.target.value;
    state.exactApprovals.id = "";
    clearExactReviews();
    if (state.view === "exact-approvals") void refreshExactApprovals();
    localStorage.setItem("reconductor.program", state.selectedProgram);
    loadData();
  });
  $("#refresh-button").addEventListener("click", () => state.view === "exact-approvals" ? refreshExactApprovals() : loadData());
  $("#retry-load").addEventListener("click", () => loadData());
  $("#asset-search").addEventListener("input", renderAssetTable);
  $("#asset-type-filter").addEventListener("change", renderAssetTable);
  $("#show-low-priority").addEventListener("change", renderChangeInbox);
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer-backdrop").addEventListener("click", closeDrawer);
  $("#drawer-backdrop").addEventListener("wheel", preventDrawerBackgroundScroll, { passive: false });
  $("#drawer-backdrop").addEventListener("touchmove", preventDrawerBackgroundScroll, { passive: false });
  window.addEventListener("scroll", preserveDrawerScrollPosition, { passive: true });
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
    };
    if (!scheduleID) body.program_id = state.data?.selected_program_id || state.selectedProgram;
    try {
	  if (!state.operatorCredential) throw new Error("Unlock operator actions first.");
	  const verificationGeneration = state.operatorVerificationGeneration;
      const path = scheduleID ? `/api/v1/schedules/${encodeURIComponent(scheduleID)}/update` : "/api/v1/schedules";
      const response = await fetch(path, { method: "POST", headers: operatorMutationHeaders(), body: JSON.stringify(body) });
	  if (response.status === 401 && verificationGeneration === state.operatorVerificationGeneration) lockOperatorActions();
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || "Schedule was not accepted.");
      resetScheduleForm();
      toast(scheduleID ? "Schedule updated." : "Schedule created.");
      await loadData({ quiet: true });
    } catch (error) {
      toast(error.message, true);
    }
  });
  document.addEventListener("keydown", handleDocumentKeydown);
}

function handleDocumentKeydown(event) {
  if (event.key === "Escape") {
    if (!$("#action-modal").classList.contains("hidden")) closeModal();
    else if ($("#detail-drawer").classList.contains("open")) closeDrawer();
    return;
  }
  const drawer = $("#detail-drawer");
  if (event.key !== "Tab" || !drawer.classList.contains("open")) return;
  containDrawerTab(event, drawerTabbableElements(drawer), document.activeElement, drawer);
}

// Exact review values are display-only server DTOs. Decisions send IDs and hash
// guards, never reconstructed requests, evidence, actor, or execution commands.
function clearExactReviews() {
  const exact = state.exactApprovals;
  const wasBusy = exact.busy;
  exact.listGeneration++;
  exact.detailGeneration++;
  exact.decisionGeneration++;
  exact.items = [];
  exact.nextCursor = "";
  exact.detail = null;
  exact.error = "";
  exact.status = "locked";
  exact.busy = false;
  if (exact.modalOwner) closeModal();
  if (wasBusy && !state.modalAction) {
    const confirm = $("#modal-confirm");
    if (confirm) confirm.disabled = false;
  }
  renderExactApprovals();
}

async function exactRead(path, generation) {
  const response = await fetch(path, { headers: { Authorization: `Bearer ${state.operatorCredential}`, Accept: "application/json" }, cache: "no-store" });
  if (generation !== state.operatorVerificationGeneration || !state.operatorCredential) return null;
  if (response.status === 401) { lockOperatorActions(); return null; }
  const body = await response.json();
  if (generation !== state.operatorVerificationGeneration || !state.operatorCredential) return null;
  if (!response.ok) throw new Error(body.error || "Exact review is unavailable.");
  return body;
}

async function refreshExactApprovals({ more = false } = {}) {
  if (!state.operatorCredential) { clearExactReviews(); return; }
  const exact = state.exactApprovals;
  const generation = state.operatorVerificationGeneration;
  const request = ++exact.listGeneration;
  const program = state.selectedProgram;
  const cursor = more ? exact.nextCursor : "";
  if (more && !cursor) return;
  try {
    const query = new URLSearchParams();
    if (program) query.set("program_id", program);
    if (cursor) query.set("after", cursor);
    const body = await exactRead(`/api/v1/exact-approvals?${query}`, generation);
    if (!body || generation !== state.operatorVerificationGeneration || request !== exact.listGeneration || program !== state.selectedProgram) return;
    const items = more ? [...exact.items, ...body.items] : body.items;
    exact.items = [...new Map(items.map((item) => [item.approval_id, item])).values()];
    exact.nextCursor = body.next_cursor || "";
    exact.error = "";
    if (!exact.detail) exact.status = "ready";
    renderExactApprovals();
    if (!more && exact.id) await openExactApproval(exact.id, { focus: false });
  } catch (error) {
    if (generation !== state.operatorVerificationGeneration || request !== exact.listGeneration) return;
    exact.items = [];
    exact.nextCursor = "";
    exact.detail = null;
    exact.status = "error";
    exact.error = error.message;
    renderExactApprovals();
  }
}

async function openExactApproval(id, { focus = true } = {}) {
  const exact = state.exactApprovals;
  const generation = state.operatorVerificationGeneration;
  const request = ++exact.detailGeneration;
  exact.id = String(id);
  exact.detail = null;
  exact.status = "loading";
  renderExactApprovals();
  if (!state.operatorCredential) { clearExactReviews(); return; }
  try {
    const body = await exactRead(`/api/v1/exact-approvals/${encodeURIComponent(id)}`, generation);
    if (!body || generation !== state.operatorVerificationGeneration || request !== exact.detailGeneration) return;
    exact.detail = body;
    exact.status = "ready";
    exact.error = "";
    renderExactApprovals();
    if (focus) $("#exact-review-heading")?.focus();
  } catch (error) {
    if (generation !== state.operatorVerificationGeneration || request !== exact.detailGeneration) return;
    exact.status = "error";
    exact.error = error.message;
    renderExactApprovals();
  }
}

function exactRequestFacts(detail) {
  const r = detail.request;
  return [["Approval ID", detail.approval_id], ["Frozen program ID", detail.program_id], ["Frozen action ID", detail.action_id], ["Method", r.method], ["Origin", `${r.scheme}://${r.host}:${r.port}`], ["Exact request target", r.request_target],
    ["Identity", r.identity], ["Maximum requests", r.max_requests], ["Redirects", r.redirects ? "enabled" : "disabled"],
    ["Retries", r.retries ? "enabled" : "disabled"], ["Headers", r.headers.length ? r.headers.join("\n") : "none"],
    ["Body", r.body], ["Action hash H", detail.action_hash], ["Review hash RH", detail.review_hash]];
}

function renderExactApprovals() {
  const list = $("#exact-approval-list");
  const panel = $("#exact-approval-detail");
  if (!list || !panel) return;
  const exact = state.exactApprovals;
  list.replaceChildren();
  panel.replaceChildren();
  if (!state.operatorCredential) {
    list.append(empty("Unlock operator actions to read exact approvals."));
    panel.append(empty("Frozen exact reviews require an operator credential."));
    return;
  }
  for (const item of exact.items) {
    const button = element("button", "secondary-button exact-review-item", `${item.approval_id} · ${item.status} · prepared ${formatTime(item.created_at, true)} · expires ${formatTime(item.expires_at, true)}`);
    button.type = "button";
    button.dataset.exactApprovalId = item.approval_id;
    button.disabled = exact.busy;
    button.setAttribute("aria-pressed", String(exact.id === item.approval_id));
    button.addEventListener("click", () => openExactApproval(item.approval_id));
    list.append(button);
  }
  if (!exact.items.length) list.append(empty(exact.error || "No exact approvals in this program."));
  if (exact.nextCursor) {
    const more = element("button", "secondary-button", "Load more exact approvals");
    more.type = "button";
    more.disabled = exact.busy;
    more.addEventListener("click", () => refreshExactApprovals({ more: true }));
    list.append(more);
  }
  if (!exact.detail) { panel.append(empty(exact.status === "loading" ? "Loading frozen review…" : exact.error || "Select an exact approval.")); return; }
  const detail = exact.detail;
  const heading = element("h2", "", "Exact action review");
  heading.id = "exact-review-heading";
  heading.tabIndex = -1;
  panel.append(heading, statusBadge(detail.status), element("p", "", `Recorded decision: ${detail.decision}. Expires ${formatTime(detail.expires_at, true)}.`));
  const facts = element("dl", "modal-details exact-request-facts");
  appendDetails(facts, exactRequestFacts(detail));
  const identity = element("dl", "modal-details");
  appendDetails(identity, [["Contract version", detail.contract_version], ["Capability revision", `${detail.capability} / ${detail.capability_revision}`], ["Task ID", detail.task_id], ["Workflow run ID", detail.workflow_run_id], ["Step run ID / attempt", `${detail.step_run_id} / ${detail.step_attempt}`], ["Bound execution identity X", detail.provider_attempt_id]]);
  panel.append(facts, element("h3", "", "Frozen proposal identity"), identity, element("h3", "", "Frozen review context"));
  const review = detail.review;
  for (const [label, value] of [["Purpose", review.purpose], ["Expected positive outcome", review.expected_positive_outcome], ["Expected negative outcome", review.expected_negative_outcome],
    ["Assumptions", review.assumptions.join("\n") || "none"], ["Missing evidence", review.missing_evidence.join("\n") || "none"],
    ["Proposal source", `${review.source_kind} · ${review.source_provider} · ${review.source_model}`]]) {
    panel.append(element("h4", "", label), element("p", "exact-prose", value));
  }
  panel.append(element("h3", "", "Evidence: frozen citations and current availability"));
  if (!review.citations.length) panel.append(empty("No frozen evidence citations."));
  for (const citation of review.citations) {
    const card = element("article", "exact-citation");
    card.append(element("h4", "", `${citation.role} evidence`));
    const facts = element("dl", "modal-details");
    appendDetails(facts, [["Frozen artifact ID", citation.artifact_id], ["Frozen SHA-256", citation.frozen_sha256], ["Frozen locator", citation.locator], ["Current availability", citation.current_availability]]);
    card.append(facts);
    panel.append(card);
  }
  panel.append(element("p", "", "Changes require a new action proposal. This surface records authorization only; it does not execute the request."));
  if (detail.decisionable) {
    const actions = element("div", "card-actions");
    for (const [decision, label] of [["rejected", "DENY"], ["approved", "ALLOW ONCE"]]) {
      const button = element("button", decision === "approved" ? "primary-button" : "danger-button", label);
      button.type = "button";
      button.disabled = exact.busy || (decision === "approved" && !detail.evidence_available);
      button.addEventListener("click", () => confirmExactDecision(detail, decision, button));
      actions.append(button);
    }
    panel.append(actions);
    if (!detail.evidence_available) panel.append(element("p", "", "Allow once is blocked while cited evidence is unavailable or restricted. The server verifies evidence again at decision time."));
  } else panel.append(element("p", "", "This approval is read-only; no further decision is available."));
}

function confirmExactDecision(detail, decision, opener = null) {
  if (!state.operatorCredential || !detail.decisionable || state.exactApprovals.busy || (decision === "approved" && !detail.evidence_available)) return;
  openModal({ eyebrow: "Exact authorization", title: decision === "approved" ? "Allow this exact action once?" : "Deny this exact action?",
    description: "This records authorization only. It does not execute the request. Changes require a new action proposal.",
    confirmLabel: decision === "approved" ? "ALLOW ONCE" : "DENY", danger: decision === "rejected", details: exactRequestFacts(detail),
    action: () => submitExactDecision(detail.approval_id, decision, detail.action_hash, detail.review_hash) });
  state.exactApprovals.modalOwner = true;
  state.exactApprovals.returnFocus = opener;
  $("#modal-confirm").disabled = false;
}

async function submitExactDecision(id, decision, actionHash, reviewHash) {
  const exact = state.exactApprovals;
  if (exact.busy || !state.operatorCredential) return;
  const generation = state.operatorVerificationGeneration;
  const request = ++exact.decisionGeneration;
  const modalGeneration = state.modalGeneration;
  exact.busy = true;
  $("#modal-confirm").disabled = true;
  renderExactApprovals();
  let message = "Exact decision could not be recorded. Review the current state.";
  let failed = true;
  try {
    const response = await fetch(`/api/v1/exact-approvals/${encodeURIComponent(id)}/decision`, {
      method: "POST", headers: operatorMutationHeaders(), body: JSON.stringify({ decision, action_hash: actionHash, review_hash: reviewHash }),
    });
    if (generation !== state.operatorVerificationGeneration || request !== exact.decisionGeneration) return;
    if (response.status === 401) { lockOperatorActions(); return; }
    const body = await response.json().catch(() => ({}));
    if (generation !== state.operatorVerificationGeneration || request !== exact.decisionGeneration) return;
    failed = !response.ok;
    message = body.message || body.error || message;
  } catch {
    if (generation !== state.operatorVerificationGeneration || request !== exact.decisionGeneration) return;
  } finally {
    if (generation === state.operatorVerificationGeneration && request === exact.decisionGeneration && state.operatorCredential) {
      const ownedModal = exact.modalOwner && modalGeneration === state.modalGeneration;
      if (ownedModal) closeModal();
      exact.busy = false;
      if (ownedModal || !state.modalAction) $("#modal-confirm").disabled = false;
      await refreshExactApprovals();
      if (generation === state.operatorVerificationGeneration && request === exact.decisionGeneration && state.operatorCredential) {
        if (state.view === "exact-approvals" && $("#action-modal").classList.contains("hidden")) $("#exact-approval-detail")?.focus();
        toast(message, failed);
      }
    }
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    refreshExactApprovals, openExactApproval, renderExactApprovals, confirmExactDecision, submitExactDecision, exactRequestFacts, clearExactReviews, openModal, closeModal, showView,
    artifactCountText,
    buildRunSelectorEntries,
    containDrawerTab,
    handleDocumentKeydown,
	latestRunSteps,
    partitionRunRelationships,
    state,
	verifyOperatorCredential,
	submitOperatorCredential,
	operatorMutationHeaders,
    closeDrawer,
    openExecutionWorkspace,
    openExecutionDetail,
    openRunDrawer,
    renderChanges,
    renderExecutionProjection,
    renderRuns,
    renderSchedules,
    selectRunWorkspaceEntry,
    selectRunWorkspaceItem,
  };
} else {
  bindEvents();
  loadData();
  state.timer = setInterval(() => loadData({ quiet: true }), 5000);
}
