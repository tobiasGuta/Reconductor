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

  focus() {
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
  };
  value.steps = [{
    id: `step-${workflowRunID}`,
    workflow_run_id: workflowRunID,
    step_definition_id: "probe",
    capability: "http.probe",
    status: "running",
    attempt_count: 1,
    approval_state: "not_required",
    started_at: "2026-08-08T14:01:00Z",
  }];
  return value;
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
  app.renderRuns();
  const [entry] = app.buildRunSelectorEntries([run], []);

  await app.selectRunWorkspaceEntry(entry);

  assert.equal(calls, 0);
  assert.match(document.querySelector("#run-workspace-meta").textContent, /limited dashboard snapshot detail/i);
  assert.match(document.querySelector("#run-inspector").textContent, /Limited run detail/);
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
