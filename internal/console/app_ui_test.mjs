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
    if (selector === "[data-execution-id]") return descendants.filter((node) => node.dataset.executionId !== undefined);
    if (selector === "[data-run-id]") return descendants.filter((node) => node.dataset.runId !== undefined);
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
    return null;
  }

  querySelectorAll(selector) {
    const roots = [...this.byID.values()];
    const matches = [];
    for (const root of roots) {
      if (selector === "[data-execution-id]" && root.dataset.executionId !== undefined) matches.push(root);
      if (selector === "[data-run-id]" && root.dataset.runId !== undefined) matches.push(root);
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
globalThis.document = new FakeDocument();

const require = createRequire(import.meta.url);
const app = require("./static/app.js");

function installDocument() {
  const document = new FakeDocument();
  document.register("schedule-list");
  document.register("scheduled-execution-list");
  document.register("runs-list");
  document.register("pending-scope-expansion-list");
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
    pending_scope_expansions: [],
    steps: [],
  };
  app.state.drawer = { returnFocus: null, returnTarget: null };
  app.state.executionDetail = { id: "", status: "idle", data: null, error: "", controller: null };
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
