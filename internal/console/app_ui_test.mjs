import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import test from "node:test";

class FakeClassList {
  constructor(owner) {
    this.owner = owner;
    this.values = new Set();
  }

  set(value) {
    this.values = new Set(String(value || "").split(/\s+/).filter(Boolean));
  }

  add(...values) {
    values.forEach((value) => this.values.add(value));
  }

  remove(...values) {
    values.forEach((value) => this.values.delete(value));
  }

  contains(value) {
    return this.values.has(value);
  }

  toggle(value, force) {
    const enabled = force === undefined ? !this.contains(value) : Boolean(force);
    if (enabled) this.add(value);
    else this.remove(value);
    return enabled;
  }

  toString() {
    return [...this.values].join(" ");
  }
}

class FakeElement {
  constructor(tagName, ownerDocument) {
    this.tagName = String(tagName).toUpperCase();
    this.ownerDocument = ownerDocument;
    this.children = [];
    this.parentElement = null;
    this.dataset = {};
    this.attributes = new Map();
    this.listeners = new Map();
    this.classList = new FakeClassList(this);
    this._text = "";
    this.disabled = false;
    this.tabIndex = 0;
    this.type = "";
  }

  set className(value) {
    this.classList.set(value);
  }

  get className() {
    return this.classList.toString();
  }

  set textContent(value) {
    this._text = String(value ?? "");
    this.children = [];
  }

  get textContent() {
    return this._text + this.children.map((child) => child.textContent).join("");
  }

  append(...children) {
    for (const child of children) {
      if (child == null) continue;
      const node = child instanceof FakeElement ? child : this.ownerDocument.createTextNode(String(child));
      node.parentElement = this;
      this.children.push(node);
    }
  }

  replaceChildren(...children) {
    this.children.forEach((child) => { child.parentElement = null; });
    this.children = [];
    this._text = "";
    this.append(...children);
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === "inert") this.inert = true;
    if (name.startsWith("data-")) {
      const key = name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      this.dataset[key] = String(value);
    }
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
    if (name === "inert") this.inert = false;
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  async click() {
    const event = { target: this, currentTarget: this, preventDefault() {} };
    await Promise.all((this.listeners.get("click") || []).map((listener) => listener(event)));
  }

  focus(options) {
    this.focusOptions = options;
    this.ownerDocument.activeElement = this;
  }

  remove() {
    if (!this.parentElement) return;
    this.parentElement.children = this.parentElement.children.filter((child) => child !== this);
    this.parentElement = null;
  }

  querySelectorAll(selector) {
    const descendants = [];
    const visit = (node) => {
      for (const child of node.children) {
        descendants.push(child);
        visit(child);
      }
    };
    visit(this);
    const dataMatch = selector.match(/^\[data-([a-z-]+)\]$/);
    if (dataMatch) {
      const key = dataMatch[1].replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      return descendants.filter((node) => node.dataset[key] !== undefined);
    }
    if (selector.startsWith(".")) return descendants.filter((node) => node.classList.contains(selector.slice(1)));
    if (selector.startsWith("button:not")) return descendants.filter((node) => node.tagName === "BUTTON" && !node.disabled && node.tabIndex !== -1);
    return [];
  }
}

class FakeDocument {
  constructor() {
    this.byID = new Map();
    this.activeElement = null;
    this.listeners = new Map();
    this.createdElements = [];
  }

  createElement(tagName) {
    const element = new FakeElement(tagName, this);
    this.createdElements.push(element);
    return element;
  }

  createTextNode(text) {
    const node = new FakeElement("#text", this);
    node.textContent = text;
    return node;
  }

  register(id, className = "") {
    const element = this.createElement("div");
    element.id = id;
    element.className = className;
    this.byID.set(id, element);
    return element;
  }

  querySelector(selector) {
    if (selector.startsWith("#")) return this.byID.get(selector.slice(1)) || null;
    if (selector.startsWith(".")) return this.createdElements.find((item) => item.classList.contains(selector.slice(1))) || null;
    return null;
  }

  querySelectorAll(selector) {
    const roots = [...this.byID.values()];
    const matches = [];
    const dataMatch = selector.match(/^\[data-([a-z-]+)\]$/);
    const dataKey = dataMatch ? dataMatch[1].replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()) : "";
    for (const root of roots) {
      if (dataKey && root.dataset[dataKey] !== undefined) matches.push(root);
      if (selector.startsWith(".") && root.classList.contains(selector.slice(1))) matches.push(root);
      matches.push(...root.querySelectorAll(selector));
    }
    return [...new Set(matches)];
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }
}

globalThis.localStorage = {
  getItem() { return ""; },
  setItem() {},
};
globalThis.window = { scrollTo() {} };
globalThis.document = new FakeDocument();

const require = createRequire(import.meta.url);
const app = require("./static/app.js");

function installDocument() {
  const document = new FakeDocument();
  document.register("schedule-list");
  document.register("scheduled-execution-list");
  document.register("runs-list");
  document.register("run-workspace-header");
  document.register("run-workspace-eyebrow");
  document.register("run-workspace-title");
  document.register("run-workspace-meta");
  document.register("run-workspace-actions");
  document.register("run-lane");
  document.register("run-inspector");
  document.register("pending-scope-expansion-list");
  document.register("test-sidebar", "sidebar");
  const runNav = document.register("test-run-nav", "nav-item");
  runNav.dataset.view = "runs";
  const runsView = document.register("test-runs-view", "view");
  runsView.dataset.viewPanel = "runs";
  document.register("drawer-backdrop", "backdrop hidden");
  const drawer = document.register("detail-drawer", "detail-drawer");
  drawer.setAttribute("inert", "");
  drawer.setAttribute("aria-hidden", "true");
  document.register("drawer-eyebrow");
  document.register("drawer-title");
  const close = document.register("drawer-close");
  close.tagName = "BUTTON";
  document.register("drawer-content");
  const confirm = document.register("modal-confirm");
  confirm.tagName = "BUTTON";
  document.register("action-modal", "modal-backdrop hidden");
  document.register("toast-region");
  globalThis.document = document;
  app.state.data = {
    schedules: [],
    scheduled_executions: [],
    runs: [],
    pending_scope_expansions: [],
    steps: [],
  };
  app.state.drawer = { returnFocus: null, returnTarget: null };
  app.state.executionDetail = { id: "", status: "idle", data: null, error: "", controller: null };
  app.state.runWorkspace = { selection: null, item: null, projection: { id: "", status: "idle", data: null, error: "" } };
  return document;
}

function execution(id, status = "completed") {
  return {
    id,
    schedule_id: "schedule-1",
    planned_at: "2026-08-08T14:00:00Z",
    trigger_source: "scheduled",
    status,
    task_id: "task-1",
    workflow_run_id: "run-1",
  };
}

function projection(id, name = "Nightly baseline") {
  return {
    observed_at: "2026-08-08T15:00:00Z",
    execution: {
      id,
      schedule_id: "schedule-1",
      program_id: "program-1",
      created_at: "2026-08-08T13:59:00Z",
      updated_at: "2026-08-08T15:00:00Z",
    },
    trigger: { source: "scheduled", planned_at: "2026-08-08T14:00:00Z" },
    scheduler: {
      status: "completed",
      attempt_count: 1,
      lease_state: "released",
      recovery_protocol_version: 1,
      started_at: "2026-08-08T14:00:05Z",
      completed_at: "2026-08-08T14:20:00Z",
    },
    current_schedule: {
      id: "schedule-1",
      program_id: "program-1",
      name,
      workflow_name: "authorized-web-baseline",
      objective: "Observe the approved baseline",
      cron_expression: "0 9 * * 1",
      timezone: "UTC",
      enabled: true,
      headless: false,
      created_by: "operator",
      next_run_at: "2026-08-15T14:00:00Z",
    },
    current_program: { id: "program-1", name: "Authorized program", platform: "web" },
    steps: [],
    tool_runs: {
      items: [{ id: "tool-1", step_run_id: "step-1", step_definition_id: "probe", capability: "http.probe", provider: "httpx", tool_version: "1.0", started_at: "2026-08-08T14:01:00Z", exit_code: 0, timed_out: false }],
      total: 2,
      truncated: true,
    },
    approvals: { items: [], total: 0, truncated: false },
    artifacts: { items: [], total: 0, truncated: false },
    candidate_findings: { items: [], total: 0, truncated: false },
    asset_observations: { total: 7, distinct_asset_count: 3 },
    change_items: { items: [], total: 0, truncated: false },
    lineage: { issues: [] },
  };
}

function workflowRun(id, status = "running", objective = `Objective ${id}`) {
  return {
    id,
    task_id: `task-${id}`,
    objective,
    workflow_name: "authorized-web-baseline",
    workflow_version: "1",
    status,
    trigger_source: "scheduled",
    started_at: "2026-08-08T14:00:05Z",
  };
}

function workspaceProjection(executionID, workflowRunID, name = "Workspace baseline") {
  const value = projection(executionID, name);
  value.execution.task_id = `task-${workflowRunID}`;
  value.execution.workflow_run_id = workflowRunID;
  value.task = { id: `task-${workflowRunID}`, objective: `Objective ${workflowRunID}`, status: "running", workflow_definition_id: "definition-1" };
  value.workflow = {
    id: workflowRunID,
    task_id: `task-${workflowRunID}`,
    workflow_definition_id: "definition-1",
    definition_name: "Authorized baseline",
    workflow_version: "1",
    status: "running",
    trigger_source: "scheduled",
    started_at: "2026-08-08T14:00:05Z",
    previous_run_id: `previous-${workflowRunID}`,
  };
  const firstStepID = `step-${workflowRunID}`;
  const secondStepID = `step-second-${workflowRunID}`;
  const firstToolID = `tool-first-${workflowRunID}`;
  const secondToolID = `tool-second-${workflowRunID}`;
  const otherToolID = `tool-other-${workflowRunID}`;
  value.steps = [
    {
      id: firstStepID,
      workflow_run_id: workflowRunID,
      step_definition_id: "probe",
      capability: "http.probe",
      status: "running",
      attempt_count: 1,
      approval_state: "pending",
      started_at: "2026-08-08T14:01:00Z",
    },
    {
      id: secondStepID,
      workflow_run_id: workflowRunID,
      step_definition_id: "collect",
      capability: "dns.collect",
      status: "succeeded",
      attempt_count: 1,
      approval_state: "not_required",
      started_at: "2026-08-08T14:02:00Z",
      completed_at: "2026-08-08T14:03:00Z",
    },
  ];
  value.tool_runs = {
    items: [
      { id: firstToolID, step_run_id: firstStepID, step_definition_id: "probe", capability: "http.probe", provider: "httpx", tool_version: "1.6.1", started_at: "2026-08-08T14:01:00Z", completed_at: "2026-08-08T14:01:30Z", exit_code: 0, timed_out: false, stdout_artifact_id: `artifact-first-${workflowRunID}` },
      { id: secondToolID, step_run_id: firstStepID, step_definition_id: "probe", capability: "http.probe", provider: "httpx", tool_version: "1.6.1", started_at: "2026-08-08T14:01:31Z", timed_out: false, stderr_artifact_id: `artifact-stderr-${workflowRunID}` },
      { id: otherToolID, step_run_id: secondStepID, step_definition_id: "collect", capability: "dns.collect", provider: "dnsx", tool_version: "1.2.2", started_at: "2026-08-08T14:02:00Z", completed_at: "2026-08-08T14:03:00Z", exit_code: 2, timed_out: true },
      { id: `tool-unassociated-${workflowRunID}`, step_run_id: `missing-step-${workflowRunID}`, step_definition_id: "probe", capability: "http.probe", provider: "fuzzy-provider-must-not-nest", tool_version: "9", started_at: "2026-08-08T14:04:00Z", timed_out: false },
    ],
    total: 6,
    truncated: true,
  };
  value.approvals = {
    items: [
      { id: `approval-${workflowRunID}`, step_run_id: firstStepID, task_id: `task-${workflowRunID}`, requested_risk_level: "moderate", reason: "Operator confirmation", requested_at: "2026-08-08T14:00:30Z", decision: "approved", decided_by: "operator-one", decided_at: "2026-08-08T14:00:45Z", expires_at: "2026-08-09T14:00:30Z" },
      { id: `approval-unassociated-${workflowRunID}`, step_run_id: `missing-step-${workflowRunID}`, task_id: `task-${workflowRunID}`, requested_risk_level: "moderate", reason: "Fuzzy approval must not nest", requested_at: "2026-08-08T14:04:00Z", decision: "pending" },
    ],
    total: 3,
    truncated: true,
  };
  value.artifacts = {
    items: [
      { id: `artifact-first-${workflowRunID}`, task_id: `task-${workflowRunID}`, workflow_run_id: workflowRunID, step_run_id: firstStepID, tool_run_id: firstToolID, type: "stdout", content_type: "text/plain", size: 20, redaction_state: "redacted", created_at: "2026-08-08T14:01:30Z", expires_at: "2026-08-09T14:01:30Z" },
      { id: `artifact-stderr-${workflowRunID}`, task_id: `task-${workflowRunID}`, workflow_run_id: workflowRunID, step_run_id: firstStepID, tool_run_id: secondToolID, type: "stderr", content_type: "text/plain", size: 10, redaction_state: "redacted", created_at: "2026-08-08T14:01:31Z" },
      { id: `artifact-other-${workflowRunID}`, task_id: `task-${workflowRunID}`, workflow_run_id: workflowRunID, step_run_id: secondStepID, tool_run_id: otherToolID, type: "result", content_type: "application/json", size: 30, redaction_state: "redacted", created_at: "2026-08-08T14:03:00Z" },
      { id: `artifact-inconsistent-${workflowRunID}`, task_id: `task-${workflowRunID}`, workflow_run_id: "different-workflow", step_run_id: firstStepID, tool_run_id: firstToolID, type: "result", content_type: "application/json", size: 40, redaction_state: "redacted", created_at: "2026-08-08T14:04:00Z" },
    ],
    total: 7,
    truncated: true,
  };
  return value;
}

function installProjectedWorkspace(detail) {
  const document = installDocument();
  const run = workflowRun(detail.workflow.id, detail.workflow.status, detail.task.objective);
  const scheduled = execution(detail.execution.id, detail.scheduler.status);
  scheduled.workflow_run_id = detail.workflow.id;
  app.state.data.runs = [run];
  app.state.data.scheduled_executions = [scheduled];
  app.state.runWorkspace.selection = { kind: "execution", id: detail.execution.id };
  app.state.runWorkspace.item = { kind: "execution", id: detail.execution.id };
  app.state.runWorkspace.projection = { id: detail.execution.id, status: "ready", data: detail, error: "" };
  app.renderRuns();
  return document;
}

function workspaceItem(document, kind, id) {
  const key = `${kind}:${id}`;
  return document.querySelectorAll("[data-workspace-item]").find((item) => item.dataset.workspaceItem === key);
}

function findButtons(root, label) {
  const found = [];
  const visit = (node) => {
    if (node.tagName === "BUTTON" && node.textContent === label) found.push(node);
    node.children.forEach(visit);
  };
  visit(root);
  return found;
}

function findElements(root, predicate) {
  const found = [];
  const visit = (node) => {
    if (predicate(node)) found.push(node);
    node.children.forEach(visit);
  };
  visit(root);
  return found;
}

function findByRole(root, role) {
  return findElements(root, (node) => node.getAttribute("role") === role);
}

function response(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return body; },
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function tabEvent(target, shiftKey = false) {
  return {
    key: "Tab",
    shiftKey,
    target,
    prevented: false,
    preventDefault() { this.prevented = true; },
  };
}

test("drawer focus containment keeps one control for Tab and Shift+Tab", () => {
  const document = installDocument();
  const close = document.querySelector("#drawer-close");
  for (const shiftKey of [false, true]) {
    document.activeElement = null;
    const event = tabEvent(close, shiftKey);
    assert.equal(app.containDrawerTab(event, [close], document.activeElement, document.querySelector("#detail-drawer")), true);
    assert.equal(event.prevented, true);
    assert.equal(document.activeElement, close);
  }
});

test("drawer focus containment wraps both multi-control boundaries", () => {
  const document = installDocument();
  const first = document.createElement("button");
  const middle = document.createElement("button");
  const last = document.createElement("button");
  const focusable = [first, middle, last];

  let event = tabEvent(last);
  assert.equal(app.containDrawerTab(event, focusable, last, document.querySelector("#detail-drawer")), true);
  assert.equal(event.prevented, true);
  assert.equal(document.activeElement, first);

  document.activeElement = null;
  event = tabEvent(first, true);
  assert.equal(app.containDrawerTab(event, focusable, document.activeElement, document.querySelector("#detail-drawer")), true);
  assert.equal(event.prevented, true);
  assert.equal(document.activeElement, last);
});

test("drawer focus containment leaves non-boundary Tab alone", () => {
  const document = installDocument();
  const first = document.createElement("button");
  const middle = document.createElement("button");
  const last = document.createElement("button");
  const event = tabEvent(middle);
  assert.equal(app.containDrawerTab(event, [first, middle, last], middle, document.querySelector("#detail-drawer")), false);
  assert.equal(event.prevented, false);
  assert.equal(document.activeElement, null);
});

test("drawer focus containment uses the drawer when it has no controls", () => {
  const document = installDocument();
  const drawer = document.querySelector("#detail-drawer");
  const event = tabEvent(drawer, true);
  assert.equal(app.containDrawerTab(event, [], null, drawer), true);
  assert.equal(event.prevented, true);
  assert.equal(document.activeElement, drawer);
});

test("composite run selector merges only authoritative workflow run ids", () => {
  const runs = [workflowRun("run-1"), workflowRun("run-2", "succeeded")];
  const linked = execution("execution-1");
  linked.workflow_run_id = "run-1";
  const unlinked = execution("execution-2", "pending");
  unlinked.workflow_run_id = null;

  const entries = app.buildRunSelectorEntries(runs, [linked, unlinked]);

  assert.equal(entries.length, 3);
  assert.equal(entries.filter((item) => item.executionId === "execution-1").length, 1);
  assert.equal(entries.find((item) => item.executionId === "execution-1").workflowRunId, "run-1");
  assert.equal(entries.find((item) => item.executionId === "execution-1").run, runs[0]);
  assert.ok(entries.find((item) => item.executionId === "execution-2" && item.workflowRunId === ""));
  assert.ok(entries.find((item) => item.kind === "workflow" && item.workflowRunId === "run-2"));
  assert.equal(entries.filter((item) => item.workflowRunId === "run-1").length, 1);
});

test("composite selector and projected header preserve independent scheduler and workflow statuses", async () => {
  const document = installDocument();
  const run = workflowRun("run-1", "failed");
  const scheduled = execution("execution-1", "completed");
  app.state.data.runs = [run];
  app.state.data.scheduled_executions = [scheduled];
  const detail = workspaceProjection("execution-1", "run-1");
  detail.scheduler.status = "completed";
  detail.workflow.status = "failed";
  globalThis.fetch = async () => response(200, detail);

  app.renderRuns();
  const selector = document.querySelectorAll("[data-run-selection]")[0];
  assert.match(selector.textContent, /Scheduler: completed/);
  assert.match(selector.textContent, /Workflow: failed/);

  const [entry] = app.buildRunSelectorEntries(app.state.data.runs, app.state.data.scheduled_executions);
  await app.selectRunWorkspaceEntry(entry);

  const actions = document.querySelector("#run-workspace-actions");
  assert.match(actions.textContent, /Scheduler: completed/);
  assert.match(actions.textContent, /Workflow: failed/);
});

test("scheduled workspace copy distinguishes idle snapshot state from an in-flight projection", async () => {
  const document = installDocument();
  const scheduled = execution("execution-1", "pending");
  app.state.data.scheduled_executions = [scheduled];
  let calls = 0;
  const pending = deferred();
  globalThis.fetch = () => {
    calls += 1;
    return pending.promise;
  };

  app.renderRuns();
  assert.equal(app.state.runWorkspace.projection.status, "idle");
  assert.match(document.querySelector("#run-workspace-meta").textContent, /limited dashboard snapshot detail/);
  assert.doesNotMatch(document.querySelector("#run-workspace-meta").textContent, /loading coherent/);
  assert.equal(calls, 0);

  const [entry] = app.buildRunSelectorEntries([], [scheduled]);
  const selecting = app.selectRunWorkspaceEntry(entry);
  assert.equal(calls, 1);
  assert.match(document.querySelector("#run-workspace-meta").textContent, /loading coherent execution observation/);
  pending.resolve(response(200, workspaceProjection("execution-1", "run-1")));
  await selecting;
});

test("snapshot fallback selection remains idle and causes no projection fan-out", () => {
  const document = installDocument();
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return response(200, workspaceProjection("unexpected", "run-unexpected"));
  };
  app.state.data.scheduled_executions = [execution("execution-A", "running")];
  app.renderRuns();
  assert.deepEqual(app.state.runWorkspace.selection, { kind: "execution", id: "execution-A" });

  app.state.data.scheduled_executions = [execution("execution-B", "pending")];
  app.renderRuns();

  assert.deepEqual(app.state.runWorkspace.selection, { kind: "execution", id: "execution-B" });
  assert.equal(app.state.runWorkspace.projection.status, "idle");
  assert.equal(calls, 0);
  assert.match(document.querySelector("#run-workspace-meta").textContent, /limited dashboard snapshot detail/);
  assert.doesNotMatch(document.querySelector("#run-workspace-meta").textContent, /loading coherent/);
});

test("workspace selection survives snapshot rerender by stable identity", async () => {
  const document = installDocument();
  globalThis.fetch = async () => { throw new Error("unscheduled selection must not fetch"); };
  app.state.data.runs = [workflowRun("run-1"), workflowRun("run-2", "succeeded")];
  app.renderRuns();
  const second = document.querySelectorAll("[data-run-selection]")[1];
  await second.click();
  assert.deepEqual(app.state.runWorkspace.selection, { kind: "workflow", id: "run-2" });

  app.state.data.runs = [workflowRun("run-1"), workflowRun("run-2", "succeeded", "Rerendered objective")];
  app.renderRuns();

  assert.deepEqual(app.state.runWorkspace.selection, { kind: "workflow", id: "run-2" });
  const selected = document.querySelectorAll("[data-run-selection]").find((item) => item.getAttribute("aria-pressed") === "true");
  assert.equal(selected.dataset.runSelection, "workflow:run-2");
  assert.match(selected.textContent, /Rerendered objective/);
});

test("scheduled workspace selection fetches once while rerender and local selection fetch zero", async () => {
  installDocument();
  const run = workflowRun("run-1");
  const scheduled = execution("execution-1");
  app.state.data.runs = [run];
  app.state.data.scheduled_executions = [scheduled];
  app.state.data.steps = [{ id: "snapshot-step", workflow_run_id: "run-1", step_definition_id: "snapshot", capability: "snapshot", status: "running", attempt_count: 1 }];
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    return response(200, workspaceProjection("execution-1", "run-1"));
  };
  app.renderRuns();
  const [entry] = app.buildRunSelectorEntries(app.state.data.runs, app.state.data.scheduled_executions);

  await app.selectRunWorkspaceEntry(entry);
  assert.deepEqual(calls, ["/api/v1/scheduled-executions/execution-1"]);

  app.renderRuns();
  app.selectRunWorkspaceItem("workflow", "run-1");
  app.selectRunWorkspaceItem("step", "step-run-1");
  assert.equal(calls.length, 1);
  assert.deepEqual(app.state.runWorkspace.item, { kind: "step", id: "step-run-1" });
});

test("relationship partitioning uses exact workflow, step, tool, approval, and artifact ids", () => {
  installDocument();
  const detail = workspaceProjection("execution-1", "run-1");
  const [entry] = app.buildRunSelectorEntries([workflowRun("run-1")], [execution("execution-1")]);
  const relationships = app.partitionRunRelationships(entry, detail);

  assert.equal(relationships.workflow.id, "run-1");
  assert.equal(relationships.steps.length, 2);
  assert.deepEqual(relationships.steps[0].toolRuns.map((item) => item.tool.id), ["tool-first-run-1", "tool-second-run-1"]);
  assert.deepEqual(relationships.steps[1].toolRuns.map((item) => item.tool.id), ["tool-other-run-1"]);
  assert.deepEqual(relationships.steps[0].approvals.map((item) => item.id), ["approval-run-1"]);
  assert.equal(relationships.steps[1].approvals.length, 0);
  assert.deepEqual(relationships.unassociatedToolRuns.map((item) => item.id), ["tool-unassociated-run-1"]);
  assert.deepEqual(relationships.unassociatedApprovals.map((item) => item.id), ["approval-unassociated-run-1"]);
  assert.deepEqual(relationships.steps[0].toolRuns[0].artifacts.map((item) => item.id), ["artifact-first-run-1"]);
  assert.equal(relationships.workflowArtifacts.some((item) => item.id === "artifact-inconsistent-run-1"), false);
});

test("missing exact workflow or step lineage creates no fabricated child association", () => {
  installDocument();
  const detail = workspaceProjection("execution-1", "run-1");
  detail.execution.workflow_run_id = "missing-workflow";
  const [entry] = app.buildRunSelectorEntries([workflowRun("run-1")], [execution("execution-1")]);
  const relationships = app.partitionRunRelationships(entry, detail);

  assert.equal(relationships.workflow, null);
  assert.equal(relationships.steps.length, 0);
  assert.equal(relationships.unassociatedToolRuns.length, detail.tool_runs.items.length);
  assert.equal(relationships.unassociatedApprovals.length, detail.approvals.items.length);
});

test("projected execution inspector shows coherent context, independent statuses, and truthful totals", async () => {
  const detail = workspaceProjection("execution-context", "run-context");
  detail.scheduler = {
    ...detail.scheduler,
    status: "running",
    attempt_count: 3,
    lease_state: "active",
    lease_owner: "internal-worker-must-stay-full-detail",
    lease_expires_at: "2026-08-08T15:05:00Z",
    recovery_protocol_version: 77,
    error_classification: "provider_unavailable",
    error_summary: "Safe retry context",
  };
  detail.task.objective = "Inspect the authorized target";
  detail.task.status = "paused";
  detail.workflow.status = "failed";
  detail.lineage.issues = ["workflow_task_mismatch", "artifact_lineage_inconsistent"];
  const document = installProjectedWorkspace(detail);
  const inspector = document.querySelector("#run-inspector");
  const text = inspector.textContent;

  assert.match(text, /running/);
  assert.match(text, /Attempts3/);
  assert.match(text, /Lease stateactive/);
  assert.match(text, /Lease expires/);
  assert.match(text, /Error classificationprovider_unavailable/);
  assert.match(text, /Error summarySafe retry context/);
  assert.match(text, /Task objectiveInspect the authorized target/);
  assert.match(text, /Task statuspaused/);
  assert.match(text, /Workflow statusfailed/);
  assert.match(text, /Observed at/);
  assert.match(text, /Lineage diagnostics2/);
  assert.doesNotMatch(text, /internal-worker-must-stay-full-detail|Recovery protocol|overall status/i);
  assert.match(text, /6 total · 4 loadedTool runs/);
  assert.match(text, /3 total · 2 loadedApprovals/);
  assert.match(text, /7 total · 4 loadedVisible artifact references/);
  assert.match(text, /0 totalUnverified candidate references/);
  assert.match(text, /7 totalObservations/);
  assert.match(text, /3Distinct observed assets/);
  assert.match(text, /0 totalChange items/);

  const disclosure = inspector.querySelectorAll(".compact-disclosure")[0];
  assert.ok(disclosure);
  assert.equal(findElements(disclosure, (node) => node.tagName === "DETAILS").length, 1);
  assert.equal(findElements(disclosure, (node) => node.tagName === "SUMMARY")[0].textContent, "Lineage and IDs");
  assert.match(disclosure.textContent, /Execution IDexecution-context/);
  assert.match(disclosure.textContent, /Program IDprogram-1/);
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return response(500, {}); };
  await disclosure.click();
  assert.equal(calls, 0);
});

test("projected workflow inspector adds workflow context without attributing execution changes", async () => {
  const detail = workspaceProjection("execution-workflow", "run-workflow");
  const document = installProjectedWorkspace(detail);
  await workspaceItem(document, "workflow", "run-workflow").click();
  const inspector = document.querySelector("#run-inspector");
  const text = inspector.textContent;

  assert.match(text, /Authorized baseline/);
  assert.match(text, /Stored workflow version1/);
  assert.match(text, /Task objectiveObjective run-workflow/);
  assert.match(text, /Previous workflow runReference recorded/);
  assert.match(text, /Scheduled executionAssociated/);
  assert.match(text, /2 totalSteps/);
  assert.match(text, /6 total · 4 loadedTool runs/);
  assert.match(text, /7 total · 4 loadedVisible artifact references/);
  assert.match(text, /7 totalObservations/);
  assert.doesNotMatch(text, /Change items/);
  assert.match(text, /Scheduled execution IDexecution-workflow/);
  assert.match(text, /Previous workflow run IDprevious-run-workflow/);
});

test("step inspector distinguishes exact child counts from loaded associations", async () => {
  let detail = workspaceProjection("execution-step-loaded", "run-step-loaded");
  let document = installProjectedWorkspace(detail);
  await workspaceItem(document, "step", "step-run-step-loaded").click();
  let inspector = document.querySelector("#run-inspector");
  assert.match(inspector.textContent, /2 loadedTool runs/);
  assert.match(inspector.textContent, /1 loadedApprovals/);
  assert.match(inspector.textContent, /3 loadedVisible artifact references/);

  detail = workspaceProjection("execution-step-exact", "run-step-exact");
  for (const collectionName of ["tool_runs", "approvals", "artifacts"]) {
    detail[collectionName].truncated = false;
    detail[collectionName].total = detail[collectionName].items.length;
  }
  document = installProjectedWorkspace(detail);
  await workspaceItem(document, "step", "step-run-step-exact").click();
  inspector = document.querySelector("#run-inspector");
  assert.match(inspector.textContent, /2Tool runs/);
  assert.match(inspector.textContent, /1Approvals/);
  assert.match(inspector.textContent, /3Visible artifact references/);
  assert.doesNotMatch(inspector.textContent, /loadedTool runs|loadedApprovals|loadedVisible artifact references/);
});

test("bounded collection and artifact copy distinguishes exact from loaded subsets", () => {
  const document = installProjectedWorkspace(workspaceProjection("execution-1", "run-1"));
  const laneText = document.querySelector("#run-lane").textContent;

  assert.match(laneText, /Tool runs: 4 shown of 6/);
  assert.match(laneText, /Approvals: 2 shown of 3/);
  assert.match(laneText, /Artifacts: 3 loaded/);
  assert.match(laneText, /Artifacts: 1 loaded/);
  assert.equal(app.artifactCountText(2, false), "2 artifacts");
  assert.equal(app.artifactCountText(0, false), "0 artifacts");
  assert.equal(app.artifactCountText(2, true), "2 loaded");
  assert.equal(app.artifactCountText(0, true), "none in loaded subset");
  assert.doesNotMatch(laneText, /0 artifacts/);

  const exactDetail = workspaceProjection("execution-exact", "run-exact");
  exactDetail.artifacts.truncated = false;
  exactDetail.artifacts.total = exactDetail.artifacts.items.length;
  const exactDocument = installProjectedWorkspace(exactDetail);
  const exactText = exactDocument.querySelector("#run-lane").textContent;
  assert.match(exactText, /Artifacts: 3 artifacts/);
  assert.match(exactText, /Artifacts: 1 artifact/);
  assert.doesNotMatch(exactText, /Artifacts: \d+ loaded/);
});

test("ready empty artifact collection preserves truthful zero counts", () => {
  const detail = workspaceProjection("execution-empty", "run-empty");
  detail.artifacts = { items: [], total: 0, truncated: false };
  const document = installProjectedWorkspace(detail);

  assert.match(workspaceItem(document, "workflow", "run-empty").textContent, /Artifacts: 0 artifacts/);
  assert.match(workspaceItem(document, "step", "step-run-empty").textContent, /Artifacts: 0 artifacts/);
  assert.match(workspaceItem(document, "tool", "tool-first-run-empty").textContent, /Artifacts: 0 artifacts/);
});

test("artifact metadata preview is capped, text-only, local, and qualified", async () => {
  const malicious = `<img src=x onerror="globalThis.compromised=true">`;
  const detail = workspaceProjection("execution-artifacts", "run-artifacts");
  const stepRunID = "step-run-artifacts";
  const toolRunID = "tool-first-run-artifacts";
  detail.artifacts = {
    items: Array.from({ length: 5 }, (_, index) => ({
      id: `artifact-preview-${index}`,
      task_id: "task-run-artifacts",
      workflow_run_id: "run-artifacts",
      step_run_id: stepRunID,
      tool_run_id: toolRunID,
      type: index === 0 ? malicious : `result-${index}`,
      content_type: "application/json",
      size: 1024 + index,
      redaction_state: "redacted",
      created_at: "2026-08-08T14:01:30Z",
      expires_at: "2026-08-09T14:01:30Z",
    })),
    total: 9,
    truncated: true,
  };
  const document = installProjectedWorkspace(detail);
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return response(500, {}); };

  await workspaceItem(document, "tool", toolRunID).click();
  const inspector = document.querySelector("#run-inspector");
  const preview = inspector.querySelectorAll(".inspector-artifacts")[0];
  assert.equal(preview.querySelectorAll(".inspector-artifact-row").length, 3);
  assert.match(preview.textContent, /3 shown · 5 loaded/);
  assert.match(preview.textContent, /projection collection truncated/);
  assert.match(preview.textContent, /application\/json · 1\.0 KiB/);
  assert.match(preview.textContent, /Redaction: redacted/);
  assert.match(preview.textContent, /Created/);
  assert.match(preview.textContent, /Expires/);
  assert.match(preview.textContent, /<img src=x/);
  assert.doesNotMatch(preview.textContent, /artifact-preview-/);
  assert.equal(document.createdElements.some((item) => item.tagName === "IMG"), false);
  assert.equal(document.querySelectorAll("[data-workspace-item]").some((item) => item.dataset.workspaceItem.startsWith("artifact:")), false);
  assert.equal(calls, 0);
});

test("unassociated loaded records are reported without becoming child nodes", () => {
  const document = installProjectedWorkspace(workspaceProjection("execution-1", "run-1"));
  const lane = document.querySelector("#run-lane");

  assert.match(lane.textContent, /1 loaded tool run could not be associated with an available step/);
  assert.match(lane.textContent, /1 loaded approval could not be associated with an available step/);
  assert.equal(workspaceItem(document, "tool", "tool-unassociated-run-1"), undefined);
  assert.equal(workspaceItem(document, "approval", "approval-unassociated-run-1"), undefined);
  assert.doesNotMatch(lane.textContent, /fuzzy-provider-must-not-nest|Fuzzy approval must not nest/);
});

test("tool selection is local, restores focus, and renders only recorded tool facts", async () => {
  const document = installProjectedWorkspace(workspaceProjection("execution-1", "run-1"));
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return response(500, {}); };
  const original = workspaceItem(document, "tool", "tool-first-run-1");

  await original.click();

  const current = workspaceItem(document, "tool", "tool-first-run-1");
  const inspector = document.querySelector("#run-inspector");
  assert.deepEqual(app.state.runWorkspace.item, { kind: "tool", id: "tool-first-run-1" });
  assert.equal(calls, 0);
  assert.notEqual(current, original);
  assert.equal(document.activeElement, current);
  assert.deepEqual(current.focusOptions, { preventScroll: true });
  assert.notEqual(document.activeElement, inspector);
  assert.equal(current.getAttribute("aria-pressed"), "true");
  assert.match(inspector.textContent, /httpx 1\.6\.1/);
  assert.match(inspector.textContent, /http\.probe/);
  assert.match(inspector.textContent, /Started/);
  assert.match(inspector.textContent, /Completed/);
  assert.match(inspector.textContent, /Exit code0/);
  assert.match(inspector.textContent, /Timed outNo/);
  assert.match(inspector.textContent, /Stdout referencePresent/);
  assert.match(inspector.textContent, /Step definitionprobe/);
  assert.match(inspector.textContent, /1 loadedVisible artifact references/);
  assert.match(inspector.textContent, /stdouttext\/plain · 20 B/);
  assert.doesNotMatch(inspector.textContent, /succeeded|failed|running/i);
  assert.match(document.querySelector("#run-lane").textContent, /Not completed at observation/);
  assert.match(document.querySelector("#run-lane").textContent, /Timed out.*Exit 2/);
});

test("tool inspector uses an exact visible-artifact count when the collection is complete", async () => {
  const detail = workspaceProjection("execution-tool-exact", "run-tool-exact");
  detail.artifacts.truncated = false;
  detail.artifacts.total = detail.artifacts.items.length;
  const document = installProjectedWorkspace(detail);

  await workspaceItem(document, "tool", "tool-first-run-tool-exact").click();

  const text = document.querySelector("#run-inspector").textContent;
  assert.match(text, /1Visible artifact references/);
  assert.doesNotMatch(text, /1 loadedVisible artifact references/);
  assert.doesNotMatch(text, /succeeded|failed|running/i);
});

test("approval selection is local and preserves decision separately from step approval state", async () => {
  const document = installProjectedWorkspace(workspaceProjection("execution-1", "run-1"));
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return response(500, {}); };
  const original = workspaceItem(document, "approval", "approval-run-1");

  await original.click();

  const current = workspaceItem(document, "approval", "approval-run-1");
  const inspector = document.querySelector("#run-inspector");
  assert.deepEqual(app.state.runWorkspace.item, { kind: "approval", id: "approval-run-1" });
  assert.equal(calls, 0);
  assert.equal(document.activeElement, current);
  assert.notEqual(current, original);
  assert.notEqual(document.activeElement, inspector);
  assert.equal(current.getAttribute("aria-pressed"), "true");
  assert.match(inspector.textContent, /Decisionapproved/);
  assert.match(inspector.textContent, /Requested risk levelmoderate/);
  assert.match(inspector.textContent, /Operator confirmation/);
  assert.match(inspector.textContent, /Actoroperator-one/);
  assert.match(inspector.textContent, /Requested/);
  assert.match(inspector.textContent, /Decided/);
  assert.match(inspector.textContent, /Expiry/);
  assert.match(inspector.textContent, /Approval IDapproval-run-1/);
  assert.match(inspector.textContent, /Step run IDstep-run-1/);
  assert.match(inspector.textContent, /Task IDtask-run-1/);
  assert.doesNotMatch(inspector.textContent, /Approval statepending/);
});

test("child selection survives rerender while exact id exists and falls back when it disappears", async () => {
  const detail = workspaceProjection("execution-1", "run-1");
  const document = installProjectedWorkspace(detail);
  await workspaceItem(document, "tool", "tool-other-run-1").click();
  const original = document.activeElement;

  app.state.data.runs = [workflowRun("run-1", "running", "Polling refresh")];
  app.renderRuns();
  assert.deepEqual(app.state.runWorkspace.item, { kind: "tool", id: "tool-other-run-1" });
  const current = workspaceItem(document, "tool", "tool-other-run-1");
  assert.equal(current.getAttribute("aria-pressed"), "true");
  assert.notEqual(current, original);
  assert.equal(document.activeElement, current);
  assert.deepEqual(current.focusOptions, { preventScroll: true });

  detail.tool_runs.items = detail.tool_runs.items.filter((item) => item.id !== "tool-other-run-1");
  app.renderRuns();
  assert.deepEqual(app.state.runWorkspace.item, { kind: "execution", id: "execution-1" });
  const fallback = workspaceItem(document, "execution", "execution-1");
  assert.equal(document.activeElement, fallback);
  assert.deepEqual(fallback.focusOptions, { preventScroll: true });
  assert.match(document.querySelector("#run-inspector").textContent, /Execution IDexecution-1/);
});

test("polling rerender preserves an unselected focused child without changing selection", async () => {
  const detail = workspaceProjection("execution-focus", "run-focus");
  const document = installProjectedWorkspace(detail);
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return response(500, {}); };
  await workspaceItem(document, "tool", "tool-first-run-focus").click();
  const selectedBefore = workspaceItem(document, "tool", "tool-first-run-focus");
  const focusedBefore = workspaceItem(document, "tool", "tool-other-run-focus");
  focusedBefore.focus();

  app.renderRuns();

  const selectedAfter = workspaceItem(document, "tool", "tool-first-run-focus");
  const focusedAfter = workspaceItem(document, "tool", "tool-other-run-focus");
  assert.deepEqual(app.state.runWorkspace.item, { kind: "tool", id: "tool-first-run-focus" });
  assert.notEqual(selectedAfter, selectedBefore);
  assert.notEqual(focusedAfter, focusedBefore);
  assert.equal(document.activeElement, focusedAfter);
  assert.notEqual(document.activeElement, selectedAfter);
  assert.deepEqual(focusedAfter.focusOptions, { preventScroll: true });
  assert.equal(calls, 0);

  detail.tool_runs.items = detail.tool_runs.items.filter((item) => item.id !== "tool-other-run-focus");
  app.renderRuns();
  assert.deepEqual(app.state.runWorkspace.item, { kind: "tool", id: "tool-first-run-focus" });
  assert.notEqual(document.activeElement, workspaceItem(document, "tool", "tool-first-run-focus"));
  assert.equal(calls, 0);
});

test("polling rerender leaves focus outside the relationship lane", async () => {
  const detail = workspaceProjection("execution-outside-focus", "run-outside-focus");
  const document = installProjectedWorkspace(detail);
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return response(500, {}); };
  await workspaceItem(document, "tool", "tool-first-run-outside-focus").click();
  const header = document.querySelector("#run-workspace-header");
  header.focus();

  app.renderRuns();

  assert.deepEqual(app.state.runWorkspace.item, { kind: "tool", id: "tool-first-run-outside-focus" });
  assert.equal(document.activeElement, header);
  assert.notEqual(document.activeElement, workspaceItem(document, "tool", "tool-first-run-outside-focus"));
  assert.equal(calls, 0);
});

test("loading clears projected children and workflow-only invalid children fall back to workflow", async () => {
  const detail = workspaceProjection("execution-1", "run-1");
  const document = installProjectedWorkspace(detail);
  await workspaceItem(document, "approval", "approval-run-1").click();
  app.state.runWorkspace.projection = { id: "execution-1", status: "loading", data: null, error: "" };
  app.renderRuns();
  assert.deepEqual(app.state.runWorkspace.item, { kind: "execution", id: "execution-1" });
  assert.match(document.querySelector("#run-lane").textContent, /Loading the coherent execution observation/);
  assert.equal(findByRole(document.querySelector("#run-inspector"), "status").length, 1);
  assert.doesNotMatch(document.querySelector("#run-inspector").textContent, /Visible artifact references|Unverified candidate references|Observations0 total/);
  assert.equal(workspaceItem(document, "approval", "approval-run-1"), undefined);

  installDocument();
  app.state.data.runs = [workflowRun("run-only")];
  app.state.runWorkspace.selection = { kind: "workflow", id: "run-only" };
  app.state.runWorkspace.item = { kind: "tool", id: "missing-tool" };
  app.renderRuns();
  assert.deepEqual(app.state.runWorkspace.item, { kind: "workflow", id: "run-only" });
});

test("tool provider version and approval reason remain text-only", async () => {
  const malicious = `<img src=x onerror="globalThis.compromised=true">`;
  const detail = workspaceProjection("execution-1", "run-1");
  detail.tool_runs.items[0].provider = malicious;
  detail.tool_runs.items[0].tool_version = malicious;
  detail.approvals.items[0].reason = malicious;
  const document = installProjectedWorkspace(detail);

  await workspaceItem(document, "tool", "tool-first-run-1").click();
  assert.match(document.querySelector("#run-inspector").textContent, /<img src=x/);
  await workspaceItem(document, "approval", "approval-run-1").click();
  assert.match(document.querySelector("#run-inspector").textContent, /<img src=x/);
  assert.equal(document.createdElements.some((item) => item.tagName === "IMG"), false);
});

test("execution inspector distinguishes a recorded workflow reference from unavailable linked details", () => {
  const detail = workspaceProjection("execution-missing-workflow", "run-missing-workflow");
  detail.workflow = null;
  detail.steps = [];
  const document = installDocument();
  const scheduled = execution("execution-missing-workflow", "completed");
  scheduled.workflow_run_id = "run-missing-workflow";
  app.state.data.scheduled_executions = [scheduled];
  app.state.runWorkspace.selection = { kind: "execution", id: detail.execution.id };
  app.state.runWorkspace.item = { kind: "execution", id: detail.execution.id };
  app.state.runWorkspace.projection = { id: detail.execution.id, status: "ready", data: detail, error: "" };

  app.renderRuns();

  const text = document.querySelector("#run-inspector").textContent;
  assert.match(text, /Workflow reference recorded; linked workflow details unavailable/);
  assert.doesNotMatch(text, /No workflow reference recorded/);
  assert.doesNotMatch(text, /Steps|Tool runs|Approvals|Visible artifact references|Unverified candidate references|Observations|Distinct observed assets/);
  assert.match(text, /0 totalChange items/);
});

test("late workspace execution A cannot overwrite selected execution B", async () => {
  const document = installDocument();
  const runA = workflowRun("run-A");
  const runB = workflowRun("run-B");
  const executionA = execution("execution-A");
  const executionB = execution("execution-B");
  executionA.workflow_run_id = "run-A";
  executionB.workflow_run_id = "run-B";
  app.state.data.runs = [runA, runB];
  app.state.data.scheduled_executions = [executionA, executionB];
  const requests = new Map();
  globalThis.fetch = (url) => {
    const pending = deferred();
    requests.set(url, pending);
    return pending.promise;
  };
  const entries = app.buildRunSelectorEntries(app.state.data.runs, app.state.data.scheduled_executions);

  const first = app.selectRunWorkspaceEntry(entries[0]);
  const second = app.selectRunWorkspaceEntry(entries[1]);
  requests.get("/api/v1/scheduled-executions/execution-B").resolve(response(200, workspaceProjection("execution-B", "run-B", "Execution B")));
  await second;
  requests.get("/api/v1/scheduled-executions/execution-A").resolve(response(200, workspaceProjection("execution-A", "run-A", "Execution A")));
  await first;

  assert.equal(app.state.runWorkspace.projection.id, "execution-B");
  assert.equal(document.querySelector("#run-workspace-title").textContent, "Execution B");
  assert.doesNotMatch(document.querySelector("#run-inspector").textContent, /Execution A/);
});

test("unscheduled workflow run renders limited detail without projection fetch", async () => {
  const document = installDocument();
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return response(500, {}); };
  const run = workflowRun("run-only");
  app.state.data.runs = [run];
  app.state.data.steps = [{ id: "step-run-only", workflow_run_id: "run-only", step_definition_id: "snapshot", capability: "snapshot", status: "running", attempt_count: 1 }];
  app.renderRuns();
  const [entry] = app.buildRunSelectorEntries([run], []);

  await app.selectRunWorkspaceEntry(entry);

  assert.equal(calls, 0);
  assert.match(document.querySelector("#run-workspace-meta").textContent, /limited dashboard snapshot detail/i);
  assert.match(document.querySelector("#run-inspector").textContent, /Limited run detail/);
  assert.ok(workspaceItem(document, "workflow", "run-only"));
  assert.ok(workspaceItem(document, "step", "step-run-only"));
  assert.match(document.querySelector("#run-lane").textContent, /Loaded workflow steps \(1\)/);
  assert.doesNotMatch(document.querySelector("#run-lane").textContent, /Artifacts:/);
  assert.doesNotMatch(document.querySelector("#run-inspector").textContent, /Visible artifact|Candidate|Observations|Scheduled execution/);
  app.selectRunWorkspaceItem("step", "step-run-only");
  assert.doesNotMatch(document.querySelector("#run-inspector").textContent, /Tool runs|Approvals|Visible artifact references/);
});

test("projection error keeps snapshot lineage without claiming zero artifacts", async () => {
  const document = installDocument();
  const run = workflowRun("run-1");
  const scheduled = execution("execution-1");
  app.state.data.runs = [run];
  app.state.data.scheduled_executions = [scheduled];
  app.state.data.steps = [{ id: "step-run-1", workflow_run_id: "run-1", step_definition_id: "snapshot", capability: "snapshot", status: "running", attempt_count: 1 }];
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return response(500, {}); };
  const [entry] = app.buildRunSelectorEntries(app.state.data.runs, app.state.data.scheduled_executions);

  await app.selectRunWorkspaceEntry(entry);

  assert.equal(calls, 1);
  assert.equal(app.state.runWorkspace.projection.status, "error");
  assert.match(document.querySelector("#run-workspace-meta").textContent, /temporarily unavailable/i);
  assert.equal(findByRole(document.querySelector("#run-inspector"), "alert").length, 1);
  assert.ok(workspaceItem(document, "workflow", "run-1"));
  assert.ok(workspaceItem(document, "step", "step-run-1"));
  assert.doesNotMatch(document.querySelector("#run-lane").textContent, /Artifacts:/);
});

test("Schedules Open workspace selects and focuses the exact execution", async () => {
  const document = installDocument();
  const run = workflowRun("run-1");
  app.state.data.runs = [run];
  app.state.data.scheduled_executions = [execution("execution-1")];
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    return response(200, workspaceProjection("execution-1", "run-1"));
  };
  app.renderRuns();
  app.renderSchedules();

  const [openWorkspace] = findButtons(document.querySelector("#scheduled-execution-list"), "Open workspace");
  await openWorkspace.click();

  assert.equal(app.state.view, "runs");
  assert.deepEqual(app.state.runWorkspace.selection, { kind: "execution", id: "execution-1" });
  assert.equal(document.activeElement, document.querySelector("#run-workspace-header"));
  assert.deepEqual(calls, ["/api/v1/scheduled-executions/execution-1"]);
});

test("Full detail uses the loaded workspace projection without a second fetch", async () => {
  const document = installDocument();
  const run = workflowRun("run-1");
  app.state.data.runs = [run];
  app.state.data.scheduled_executions = [execution("execution-1")];
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return response(200, workspaceProjection("execution-1", "run-1", "Cached detail"));
  };
  const [entry] = app.buildRunSelectorEntries(app.state.data.runs, app.state.data.scheduled_executions);
  await app.selectRunWorkspaceEntry(entry);
  const [fullDetail] = findButtons(document.querySelector("#run-workspace-actions"), "Full detail");

  await fullDetail.click();

  assert.equal(calls, 1);
  assert.equal(document.querySelector("#detail-drawer").getAttribute("aria-hidden"), "false");
  assert.match(document.querySelector("#drawer-content").textContent, /Cached detail|execution-1/);
});

test("workspace selector lane and inspector keep server strings text-only", async () => {
  const document = installDocument();
  const malicious = `<img src=x onerror="globalThis.compromised=true">`;
  const run = workflowRun("run-1", "running", malicious);
  app.state.data.runs = [run];
  app.state.data.scheduled_executions = [execution("execution-1")];
  globalThis.fetch = async () => response(200, workspaceProjection("execution-1", "run-1", malicious));
  const [entry] = app.buildRunSelectorEntries(app.state.data.runs, app.state.data.scheduled_executions);

  await app.selectRunWorkspaceEntry(entry);

  assert.equal(document.querySelector("#run-workspace-title").textContent, malicious);
  assert.match(document.querySelector("#runs-list").textContent, /<img src=x/);
  assert.equal(document.createdElements.some((item) => item.tagName === "IMG"), false);
});

test("scheduled execution detail is explicit and uses the execution id", async () => {
  const document = installDocument();
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return response(200, projection("execution/one"));
  };
  app.state.data.scheduled_executions = [execution("execution/one")];

  app.renderSchedules();
  assert.equal(calls.length, 0, "ordinary schedule rendering must not fetch detail");
  const list = document.querySelector("#scheduled-execution-list");
  const [details] = findButtons(list, "View details");
  assert.ok(details);
  assert.equal(details.dataset.executionId, "execution/one");

  await details.click();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/v1/scheduled-executions/execution%2Fone");
  assert.deepEqual(calls[0].options.headers, { Accept: "application/json" });
  assert.equal(calls[0].options.cache, "no-store");
  assert.equal("X-Reconductor-Request" in calls[0].options.headers, false);
  assert.match(document.querySelector("#drawer-content").textContent, /Authorized program/);
  assert.match(document.querySelector("#drawer-content").textContent, /httpx/);
});

test("projection rendering handles null lineage, empty collections, and truncation", async () => {
  const document = installDocument();
  globalThis.fetch = async () => response(200, projection("execution-1"));

  await app.openExecutionDetail("execution-1");

  const text = document.querySelector("#drawer-content").textContent;
  assert.match(text, /Scope: Not linked/);
  assert.match(text, /Task: Not linked/);
  assert.match(text, /Workflow run: Not linked/);
  assert.match(text, /No approvals are linked/);
  assert.match(text, /Results truncated/);
  assert.match(text, /Observations7/);
});

test("candidate and scope copy preserves current-versus-historical semantics", async () => {
  const document = installDocument();
  const body = projection("execution-1");
  body.scope = {
    id: "scope-1",
    program_id: "program-1",
    scope_reference: "current-scope-locator",
    scope_digest: "historic-scope-digest",
    target_plan_digest: "historic-plan-digest",
    expands_scope: false,
    created_at: "2026-08-08T13:00:00Z",
  };
  body.candidate_findings = {
    items: [{ id: "candidate-1", task_id: "task-1", workflow_run_id: "run-1", target_asset_id: "asset-1", source_capability: "scan", detection_confidence: 0.8, status: "confirmed", evidence_artifact_ids: [], created_at: "2026-08-08T14:00:00Z", updated_at: "2026-08-08T15:00:00Z" }],
    total: 1,
    truncated: false,
  };
  globalThis.fetch = async () => response(200, body);

  await app.openExecutionDetail("execution-1");

  const text = document.querySelector("#drawer-content").textContent;
  assert.match(text, /Candidate metadata is separate from verified findings/);
  assert.match(text, /Status and updated time reflect current candidate state/);
  assert.match(text, /Verification provenance is not included/);
  assert.doesNotMatch(text, /Candidate metadata is unverified/);
  assert.match(text, /Current state updated/);
  assert.match(text, /Scope and target-plan digests are historical values/);
  assert.match(text, /Scope reference is current locator metadata and may have been repaired/);
});

test("missing linked lineage is rendered as unavailable without inventing a cause", async () => {
  const document = installDocument();
  const body = projection("execution-1");
  body.execution.scope_version_id = "scope-missing";
  body.execution.task_id = "task-missing";
  body.execution.workflow_run_id = "workflow-missing";
  globalThis.fetch = async () => response(200, body);

  await app.openExecutionDetail("execution-1");

  const text = document.querySelector("#drawer-content").textContent;
  assert.match(text, /Scope: Unavailable/);
  assert.match(text, /Task: Unavailable/);
  assert.match(text, /Workflow run: Unavailable/);
});

test("detail failures are safe and distinguish not found", async (t) => {
  await t.test("404", async () => {
    const document = installDocument();
    globalThis.fetch = async () => response(404, { error: "internal wrapped sentinel" });
    await app.openExecutionDetail("missing");
    const text = document.querySelector("#drawer-content").textContent;
    assert.match(text, /Scheduled execution no longer exists/);
    assert.doesNotMatch(text, /internal wrapped sentinel/);
  });

  for (const [name, fetcher] of [
    ["500", async () => response(500, { error: "database sentinel" })],
    ["invalid json", async () => ({ ok: true, status: 200, async json() { throw new Error("bad json"); } })],
    ["network", async () => { throw new Error("socket sentinel"); }],
  ]) {
    await t.test(name, async () => {
      const document = installDocument();
      globalThis.fetch = fetcher;
      await app.openExecutionDetail("execution-1");
      const text = document.querySelector("#drawer-content").textContent;
      assert.match(text, /Execution detail is temporarily unavailable/);
      assert.doesNotMatch(text, /sentinel|bad json/);
    });
  }
});

test("late response A cannot overwrite execution B", async () => {
  const document = installDocument();
  const requests = new Map();
  globalThis.fetch = (url) => {
    const pending = deferred();
    requests.set(url, pending);
    return pending.promise;
  };

  const first = app.openExecutionDetail("A");
  const second = app.openExecutionDetail("B");
  requests.get("/api/v1/scheduled-executions/B").resolve(response(200, projection("B", "Execution B")));
  await second;
  requests.get("/api/v1/scheduled-executions/A").resolve(response(200, projection("A", "Execution A")));
  await first;

  assert.equal(document.querySelector("#drawer-title").textContent, "Execution B");
  assert.doesNotMatch(document.querySelector("#drawer-content").textContent, /Execution A/);
});

test("closing aborts detail and prevents a late render", async () => {
  const document = installDocument();
  const pending = deferred();
  let signal;
  globalThis.fetch = (_url, options) => {
    signal = options.signal;
    return pending.promise;
  };

  const loading = app.openExecutionDetail("late");
  app.closeDrawer();
  assert.equal(signal.aborted, true);
  pending.resolve(response(200, projection("late", "Late result")));
  await loading;

  assert.equal(document.querySelector("#detail-drawer").getAttribute("aria-hidden"), "true");
  assert.doesNotMatch(document.querySelector("#drawer-content").textContent, /Late result/);
});

test("scheduled detail restores focus to the current rerendered button", async () => {
  const document = installDocument();
  globalThis.fetch = async () => response(200, projection("execution-1"));
  app.state.data.scheduled_executions = [execution("execution-1")];
  app.renderSchedules();
  const firstButton = findButtons(document.querySelector("#scheduled-execution-list"), "View details")[0];

  await firstButton.click();
  const drawer = document.querySelector("#detail-drawer");
  assert.equal(drawer.inert, false);
  assert.equal(drawer.getAttribute("aria-hidden"), "false");

  app.renderSchedules();
  const currentButton = findButtons(document.querySelector("#scheduled-execution-list"), "View details")[0];
  assert.notEqual(currentButton, firstButton);
  app.closeDrawer();

  assert.equal(document.activeElement, currentButton);
  assert.equal(drawer.inert, true);
  assert.equal(drawer.getAttribute("aria-hidden"), "true");
});

test("workflow detail restores focus to the current rerendered run card", () => {
  const document = installDocument();
  const run = { id: "run-1", objective: "Existing workflow detail", workflow_name: "baseline", workflow_version: "1", status: "succeeded", trigger_source: "operator" };
  app.state.data.runs = [run];
  app.renderRuns();
  const firstCard = document.querySelector("#runs-list").children[0];

  app.openRunDrawer(run, firstCard);
  app.renderRuns();
  const currentCard = document.querySelector("#runs-list").children[0];
  assert.notEqual(currentCard, firstCard);
  app.closeDrawer();

  assert.equal(document.activeElement, currentCard);
  assert.equal(document.querySelector("#detail-drawer").inert, true);
  assert.equal(document.querySelector("#detail-drawer").getAttribute("aria-hidden"), "true");
});

test("resume remains independent and workflow-run detail still uses the drawer", async () => {
  const document = installDocument();
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return response(409, { error: "expected test rejection" });
  };
  app.state.data.scheduled_executions = [execution("paused-1", "paused_operator")];
  app.renderSchedules();
  const list = document.querySelector("#scheduled-execution-list");
  const [resume] = findButtons(list, "Resume");
  const [details] = findButtons(list, "View details");
  assert.ok(resume);
  assert.ok(details);

  await resume.click();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/v1/scheduled-executions/paused-1/resume");
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.headers["X-Reconductor-Request"], "operator-console");

  app.state.data.steps = [{ workflow_run_id: "run-1", step_definition_id: "probe", capability: "http.probe", status: "succeeded", attempt_count: 1 }];
  app.openRunDrawer({ id: "run-1", objective: "Existing workflow detail", workflow_name: "baseline", workflow_version: "1", status: "succeeded", trigger_source: "operator" });
  assert.equal(document.querySelector("#drawer-eyebrow").textContent, "Run detail");
  assert.match(document.querySelector("#drawer-content").textContent, /Existing workflow detail|probe/);
});

test("server-controlled strings remain text-only", async () => {
  const document = installDocument();
  const malicious = `<img src=x onerror="globalThis.compromised=true">`;
  globalThis.fetch = async () => response(200, projection("execution-1", malicious));
  await app.openExecutionDetail("execution-1");

  assert.equal(document.querySelector("#drawer-title").textContent, malicious);
  assert.equal(document.createdElements.some((item) => item.tagName === "IMG"), false);
  const source = await readFile(new URL("./static/app.js", import.meta.url), "utf8");
  for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("]) {
    assert.equal(source.includes(forbidden), false, `app.js must not contain ${forbidden}`);
  }
});
