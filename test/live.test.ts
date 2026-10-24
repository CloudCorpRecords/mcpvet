/**
 * Tests for the 0.2.0 live checks: probe parity, exact-hash
 * fingerprints, and the derived risk score, plus the canonical
 * negative controls (auth refusal is a pass, a timeout is no signal).
 * The fixture servers are raw JSON-RPC stdio servers with no deps;
 * they are executed, which is exactly what live mode is for.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { vetLive } from "../src/live.js";
import { vetPath } from "../src/vet.js";
import { diffObservations, classifyProbeError } from "../src/probe.js";
import { loadFingerprints, matchFingerprints } from "../src/fingerprints.js";
import { buildRiskAssessment, hashText, hashToolSet } from "../src/signals.js";
import type { ProbeObservation } from "../src/types.js";

const LIVE = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "live");
const fixture = (name: string) => join(LIVE, name);
const node = (script: string, env?: Record<string, string>) => ({
  command: process.execPath,
  args: [fixture(script)],
  env,
});

function driftSpec(mode: string): { spec: ReturnType<typeof node>; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mcpvet-drift-"));
  const state = join(dir, "state.txt");
  writeFileSync(state, "0");
  return {
    spec: node("drifting-server.mjs", { FIXTURE_STATE: state, DRIFT_MODE: mode }),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

describe("hashing and score derivation (unit)", () => {
  const tools = [
    { name: "b_tool", description: "B", inputSchema: { type: "object", properties: {} } },
    { name: "a_tool", description: "A", inputSchema: { type: "object", properties: { x: { type: "string" } } } },
  ];

  it("hashToolSet is order-insensitive and content-sensitive", () => {
    const h1 = hashToolSet(tools);
    const h2 = hashToolSet([...tools].reverse());
    assert.equal(h1, h2);
    const changed = tools.map((t) => (t.name === "a_tool" ? { ...t, description: "A!" } : t));
    assert.notEqual(hashToolSet(changed), h1);
    const schemaChanged = tools.map((t) =>
      t.name === "a_tool"
        ? { ...t, inputSchema: { type: "object", properties: { x: { type: "number" } } } }
        : t,
    );
    assert.notEqual(hashToolSet(schemaChanged), h1);
  });

  it("buildRiskAssessment derives from signals and ignores control weight", () => {
    const r = buildRiskAssessment([
      { id: "a", kind: "parity", severity: "high", weight: 25, detail: "", probed: "", observed: "" },
      { id: "b", kind: "control", severity: "info", weight: 0, detail: "", probed: "", observed: "" },
      { id: "c", kind: "fingerprint", severity: "medium", weight: 20, detail: "", probed: "", observed: "" },
    ]);
    assert.equal(r.score, 45);
    assert.equal(r.band, "elevated");
    assert.equal(r.signals.length, 3);
  });

  it("classifyProbeError separates auth refusals and timeouts from errors", () => {
    assert.equal(classifyProbeError(new Error("McpError: Unauthorized: a valid API key is required")), "auth-refused");
    assert.equal(classifyProbeError(new Error("HTTP 401 from upstream")), "auth-refused");
    assert.equal(classifyProbeError(new Error("AbortError: The operation was aborted")), "timeout");
    assert.equal(classifyProbeError(new Error("request timed out after 15000ms")), "timeout");
    assert.equal(classifyProbeError(new Error("spawn node ENOENT")), "error");
  });
});

describe("diffObservations (unit)", () => {
  const base: ProbeObservation = {
    serverName: "s",
    serverVersion: "1.0.0",
    capabilities: { tools: {} },
    tools: [{ name: "alpha", description: "Alpha", inputSchema: { type: "object", properties: {} } }],
  };

  it("a stable server diffs clean", () => {
    assert.deepEqual(diffObservations(base, structuredClone(base)), []);
  });

  it("each drift kind lands on its own field", () => {
    const named = { ...base, serverName: "s-alt" };
    assert.deepEqual(diffObservations(base, named).map((d) => d.field), ["server.name"]);
    const versioned = { ...base, serverVersion: "1.0.1" };
    assert.deepEqual(diffObservations(base, versioned).map((d) => d.field), ["server.version"]);
    const added = { ...base, tools: [...base.tools, { name: "extra", description: "E", inputSchema: {} }] };
    assert.deepEqual(diffObservations(base, added).map((d) => d.field), ["tools.added"]);
    const desc = { ...base, tools: [{ name: "alpha", description: "Alpha v2", inputSchema: base.tools[0].inputSchema }] };
    assert.deepEqual(diffObservations(base, desc).map((d) => d.field), ["tools.alpha.description"]);
    const schema = { ...base, tools: [{ name: "alpha", description: "Alpha", inputSchema: { type: "object", properties: { y: { type: "string" } } } }] };
    assert.deepEqual(diffObservations(base, schema).map((d) => d.field), ["tools.alpha.inputSchema"]);
  });
});

describe("fingerprints (unit)", () => {
  it("the seeded entries load and match the fingerprinted observation exactly", async () => {
    const { probeServer } = await import("../src/probe.js");
    const outcome = await probeServer(node("fingerprinted-server.mjs"), 15000);
    assert.equal(outcome.status, "ok");
    const matches = matchFingerprints(outcome.observation as ProbeObservation, loadFingerprints());
    assert.deepEqual(matches.map((m) => m.entry.id).sort(), [
      "fixture-hidden-tool-description",
      "fixture-mismatch-toolset",
    ]);
  });

  it("a one-character description change defeats the exact match", async () => {
    const { probeServer } = await import("../src/probe.js");
    const outcome = await probeServer(node("fingerprinted-server.mjs"), 15000);
    const obs = structuredClone(outcome.observation as ProbeObservation);
    const hidden = obs.tools.find((t) => t.name === "hidden_tool") as { description?: string };
    hidden.description = "Undocumented extra tool ";
    const matches = matchFingerprints(obs, loadFingerprints());
    assert.deepEqual(matches, [], "exact match must not tolerate a trailing space");
    void hashText;
  });
});

describe("static reports carry the derived risk score", () => {
  const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

  it("evil-skill findings become signals and the score derives from them", () => {
    const r = vetPath(join(FIX, "evil-skill"));
    assert.equal(r.verdict, "DO-NOT-INSTALL", "verdict rules are unchanged by the score");
    assert.equal(r.risk.signals.length, r.findings.length);
    assert.ok(r.risk.signals.every((s) => s.kind === "static"));
    assert.ok(r.risk.score >= 50 && r.risk.band === "high", JSON.stringify(r.risk));
    const cred = r.risk.signals.find((s) => s.id === "static:SCRIPT-CRED-EXFIL");
    assert.ok(cred && cred.weight === 40, "a critical finding weighs 40");
  });

  it("clean-server scores zero with only zero-weight signals", () => {
    const r = vetPath(join(FIX, "clean-server"));
    assert.equal(r.risk.score, 0);
    assert.equal(r.risk.band, "none");
  });
});

describe("live probe fixtures", () => {
  it("an honest server verdicts VETTED with no signals and a consistent parity", async () => {
    const r = await vetLive(node("honest-server.mjs"));
    assert.equal(r.verdict, "VETTED", JSON.stringify(r, null, 2));
    assert.equal(r.probes.first.status, "ok");
    assert.equal(r.probes.second.status, "ok");
    assert.equal(r.parity.consistent, true);
    assert.equal(r.risk.score, 0);
    assert.equal(r.risk.signals.filter((s) => s.kind !== "control").length, 0);
    assert.deepEqual(r.fingerprints.matchedEntryIds, []);
  });

  it("a tool-list-drifting server earns a parity signal and verdicts REVIEW", async () => {
    const { spec, cleanup } = driftSpec("tools");
    try {
      const r = await vetLive(spec);
      assert.equal(r.verdict, "REVIEW", JSON.stringify(r, null, 2));
      assert.equal(r.parity.consistent, false);
      assert.ok(r.parity.diffs.some((d) => d.field === "tools.added" && d.second.includes("extra_tool")));
      const sig = r.risk.signals.find((s) => s.kind === "parity");
      assert.ok(sig, "expected a parity signal");
      assert.match(sig.observed, /tools\.added/);
      assert.ok(r.risk.score >= 20);
    } finally {
      cleanup();
    }
  });

  it("a fingerprinted server matches the seeds, scores them, and does NOT hard-fail", async () => {
    const r = await vetLive(node("fingerprinted-server.mjs"));
    assert.deepEqual([...r.fingerprints.matchedEntryIds].sort(), [
      "fixture-hidden-tool-description",
      "fixture-mismatch-toolset",
    ]);
    assert.equal(r.risk.signals.filter((s) => s.kind === "fingerprint").length, 2);
    assert.equal(r.risk.score, 30);
    assert.equal(r.risk.band, "elevated");
    assert.equal(r.parity.consistent, true, "the fingerprinted fixture itself is stable");
    assert.equal(r.verdict, "REVIEW");
    assert.notEqual(r.verdict, "DO-NOT-INSTALL", "a fingerprint match alone must never hard-fail");
  });

  it("a single low-weight fingerprint entry by itself still cannot hard-fail", async () => {
    const onlyDesc = loadFingerprints().filter((e) => e.id === "fixture-hidden-tool-description");
    const r = await vetLive(node("fingerprinted-server.mjs"), { entries: onlyDesc });
    assert.equal(r.risk.score, 10);
    assert.equal(r.verdict, "REVIEW");
  });

  it("negative control: an auth-refused probe is recorded as a pass", async () => {
    const r = await vetLive(node("auth-server.mjs"));
    assert.equal(r.probes.first.status, "auth-refused", JSON.stringify(r.probes));
    assert.equal(r.probes.second.status, "auth-refused");
    const controls = r.risk.signals.filter((s) => s.kind === "control");
    assert.equal(controls.length, 2, "one recorded pass per refused probe");
    assert.ok(controls.every((s) => s.weight === 0 && s.id === "probe-auth"));
    assert.equal(r.risk.signals.filter((s) => s.kind !== "control").length, 0);
    assert.equal(r.risk.score, 0);
    assert.equal(r.verdict, "VETTED", "an auth wall is a pass, not a finding");
  });

  it("negative control: a timeout records no signal at all", async () => {
    const r = await vetLive(node("slow-server.mjs"), { timeoutMs: 700 });
    assert.equal(r.probes.first.status, "timeout", JSON.stringify(r.probes));
    assert.equal(r.probes.second.status, "timeout");
    assert.equal(r.risk.signals.length, 0, "a timeout is no signal, not even a control");
    assert.equal(r.risk.score, 0);
    assert.ok(r.notes.some((n) => /NO SIGNAL/.test(n)));
    assert.equal(r.verdict, "REVIEW", "inconclusive is reported, never passed off as vetted evidence");
  });
});

describe("adversarial parity mutations", () => {
  const cases: { mode: string; field: string }[] = [
    { mode: "name", field: "server.name" },
    { mode: "version", field: "server.version" },
    { mode: "description", field: "tools.alpha.description" },
    { mode: "schema", field: "tools.alpha.inputSchema" },
  ];
  for (const c of cases) {
    it(`drift in ${c.mode} only is caught on ${c.field}`, async () => {
      const { spec, cleanup } = driftSpec(c.mode);
      try {
        const r = await vetLive(spec);
        assert.equal(r.parity.consistent, false, JSON.stringify(r.parity, null, 2));
        assert.ok(
          r.parity.diffs.some((d) => d.field === c.field),
          `expected a diff on ${c.field}, got ${JSON.stringify(r.parity.diffs)}`,
        );
        assert.ok(r.risk.signals.some((s) => s.kind === "parity"));
        assert.equal(r.verdict, "REVIEW");
      } finally {
        cleanup();
      }
    });
  }
});
