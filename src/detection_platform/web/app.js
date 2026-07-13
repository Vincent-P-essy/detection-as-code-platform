"use strict";

const byId = (id) => document.getElementById(id);

async function request(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
  return payload;
}

function displayNumber(value) {
  return value === null ? "n/a" : Number(value).toFixed(3);
}

function replaceList(element, values) {
  element.replaceChildren();
  values.forEach((value) => {
    const item = document.createElement("li");
    item.textContent = value;
    element.append(item);
  });
}

function render(report) {
  const summary = report.summary;
  byId("rules").textContent = summary.rule_count;
  byId("promote").textContent = summary.promote_count;
  byId("hold").textContent = summary.hold_count;
  byId("reject").textContent = summary.reject_count;
  byId("tests").textContent = `${Math.round(summary.unit_test_pass_rate * 100)}%`;
  byId("digest").textContent = report.functional_sha256;

  const body = byId("rule-body");
  body.replaceChildren();
  report.rules.forEach((item) => {
    const row = document.createElement("tr");
    const values = [
      item.rule.id,
      item.rule.engine,
      item.lifecycle.resulting_state,
      displayNumber(item.metrics.precision),
      displayNumber(item.metrics.recall),
      displayNumber(item.metrics.false_positive_rate),
      `${item.metrics.latency_ms.p95.toFixed(3)} ms`,
      item.lifecycle.decision,
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      if (index === 7) cell.className = `decision ${String(value).toLowerCase()}`;
      row.append(cell);
    });
    body.append(row);
  });

  replaceList(byId("diagnostics"), [
    `Silent rules: ${report.diagnostics.silent_rules.join(", ") || "none"}`,
    `Noisy rules: ${report.diagnostics.noisy_rules.join(", ") || "none"}`,
    `Redundant pairs: ${report.diagnostics.redundant_pairs.length}`,
    `Expired rules: ${report.diagnostics.expired_rules.join(", ") || "none"}`,
  ]);
  replaceList(byId("coverage"), [
    `Engines: ${report.coverage.engines.join(", ")}`,
    `Declared ATT&CK: ${report.coverage.declared_mitre_techniques.join(", ")}`,
    `Promotable ATT&CK: ${report.coverage.promotable_mitre_techniques.join(", ")}`,
    `Promotable ratio: ${(report.coverage.promotable_technique_ratio * 100).toFixed(1)}%`,
  ]);

  const audit = byId("audit");
  audit.replaceChildren();
  report.audit.forEach((entry) => {
    const line = document.createElement("div");
    line.className = "audit-entry";
    line.textContent = `${entry.sequence} · ${entry.timestamp} · ${entry.event_type} · ${entry.rule_id} · ${entry.entry_hash}`;
    audit.append(line);
  });
}

async function replay() {
  const button = byId("run");
  const error = byId("error");
  button.disabled = true;
  error.hidden = true;
  try {
    const report = await request("/api/v1/replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ as_of: byId("as-of").value }),
    });
    render(report);
  } catch (reason) {
    error.textContent = reason instanceof Error ? reason.message : String(reason);
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

async function boot() {
  try {
    const health = await request("/api/v1/health");
    byId("health").textContent = health.status === "ok" ? "READY / SIMULATION" : "UNAVAILABLE";
    byId("run").addEventListener("click", replay);
  } catch (reason) {
    byId("health").textContent = "UNAVAILABLE";
    byId("error").textContent = reason instanceof Error ? reason.message : String(reason);
    byId("error").hidden = false;
  }
}

window.addEventListener("DOMContentLoaded", boot);
