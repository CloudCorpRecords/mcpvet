/**
 * Edge case coverage for the derived risk score and exact-hash
 * fingerprints (0.2.0 surfaces that live.test.ts exercises only on
 * their happy paths):
 *
 * - bandForScore at every band boundary, on both sides.
 * - buildRiskAssessment capping at 100, flooring at 0, ignoring
 *   control signals even when one carries a nonzero weight, and
 *   refusing to let a non-finite weight poison the whole score:
 *   fingerprint entries are data, and a malformed entry weight
 *   must degrade to no contribution, never to a NaN score whose
 *   band silently falls through to high.
 * - canonicalJson and hashToolSet: nested object key order inside
 *   a tool input schema must not change the tool set hash (the
 *   schema is the same schema), while array order inside the
 *   schema must, because canonical JSON preserves array order.
 * - matchFingerprints gating: a server name or version mismatch
 *   defeats an otherwise exact hash match, a missing tool or an
 *   undefined description defeats a description hash, and an
 *   entry carrying only identity fields matches nothing, because
 *   a match requires at least one exact hash aspect.
 * - findingToSignal: severity weights for every severity, and the
 *   probed field with and without a line number.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SEVERITY_WEIGHTS,
  bandForScore,
  buildRiskAssessment,
  canonicalJson,
  findingToSignal,
  hashToolSet,
} from "../src/signals.js";
import { matchFingerprints, type FingerprintEntry } from "../src/fingerprints.js";
import { hashText } from "../src/signals.js";
import type { ProbeObservation, Signal } from "../src/types.js";

function signal(partial: Partial<Signal>): Signal {
  return { id: "s", kind: "static", severity: "low", weight: 4, detail: "", probed: "", observed: "", ...partial };
}

describe("bandForScore boundaries", () => {
  it("maps both sides of every boundary", () => {
    assert.equal(bandForScore(0), "none");
    assert.equal(bandForScore(-5), "none");
    assert.equal(bandForScore(1), "low");
    assert.equal(bandForScore(19), "low");
    assert.equal(bandForScore(20), "elevated");
    assert.equal(bandForScore(49), "elevated");
    assert.equal(bandForScore(50), "high");
    assert.equal(bandForScore(100), "high");
  });
});

describe("buildRiskAssessment edge cases", () => {
  it("an empty signal list scores zero in band none", () => {
    const r = buildRiskAssessment([]);
    assert.equal(r.score, 0);
    assert.equal(r.band, "none");
    assert.deepEqual(r.signals, []);
  });

  it("caps the summed score at 100 however large the weights", () => {
    const r = buildRiskAssessment([signal({ weight: 70 }), signal({ weight: 70 }), signal({ weight: 70 })]);
    assert.equal(r.score, 100);
    assert.equal(r.band, "high");
  });

  it("ignores control signals even when a control carries a nonzero weight", () => {
    const r = buildRiskAssessment([
      signal({ id: "c", kind: "control", severity: "info", weight: 90 }),
      signal({ id: "a", weight: 10 }),
    ]);
    assert.equal(r.score, 10);
    assert.equal(r.band, "low");
    assert.equal(r.signals.length, 2, "the control signal stays on the record; it just weighs nothing");
  });

  it("never lets the score go below zero", () => {
    const r = buildRiskAssessment([signal({ weight: -30 }), signal({ weight: 10 })]);
    assert.equal(r.score, 0);
    assert.equal(r.band, "none");
  });

  it("a non-finite weight contributes nothing instead of poisoning the score", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      const r = buildRiskAssessment([signal({ id: "bad", weight: bad }), signal({ id: "good", weight: 25 })]);
      assert.equal(r.score, 25, `weight ${String(bad)} must not poison the score`);
      assert.equal(r.band, "elevated");
      assert.ok(Number.isFinite(r.score));
    }
  });
});

describe("canonicalJson and hashToolSet", () => {
  it("canonicalJson sorts object keys recursively and preserves array order", () => {
    assert.equal(canonicalJson({ b: 1, a: { d: 4, c: 3 } }), canonicalJson({ a: { c: 3, d: 4 }, b: 1 }));
    assert.notEqual(canonicalJson({ a: [1, 2] }), canonicalJson({ a: [2, 1] }));
    assert.equal(canonicalJson(null), "null");
  });

  it("a schema whose nested keys are merely reordered hashes identically", () => {
    const a = [{ name: "t", description: "T", inputSchema: { type: "object", properties: { x: { type: "string", format: "date" } }, required: ["x"] } }];
    const b = [{ name: "t", description: "T", inputSchema: { required: ["x"], properties: { x: { format: "date", type: "string" } }, type: "object" } }];
    assert.equal(hashToolSet(a), hashToolSet(b));
  });

  it("a schema whose array order changes hashes differently", () => {
    const a = [{ name: "t", description: "T", inputSchema: { type: "object", required: ["x", "y"] } }];
    const b = [{ name: "t", description: "T", inputSchema: { type: "object", required: ["y", "x"] } }];
    assert.notEqual(hashToolSet(a), hashToolSet(b));
  });

  it("a missing description and an empty description hash the same", () => {
    const a = [{ name: "t", inputSchema: { type: "object" } }];
    const b = [{ name: "t", description: "", inputSchema: { type: "object" } }];
    assert.equal(hashToolSet(a), hashToolSet(b));
  });
});

describe("matchFingerprints gating", () => {
  const obs: ProbeObservation = {
    serverName: "srv",
    serverVersion: "1.0.0",
    capabilities: { tools: {} },
    tools: [{ name: "alpha", description: "Alpha", inputSchema: { type: "object" } }],
  };
  const toolSetHash = hashToolSet(obs.tools);
  const descHash = hashText("Alpha");
  const entry = (partial: Partial<FingerprintEntry>): FingerprintEntry => ({
    id: "e1",
    label: "entry",
    weight: 10,
    provenance: "test",
    ...partial,
  });

  it("matches on an exact tool set hash and on an exact description hash", () => {
    assert.equal(matchFingerprints(obs, [entry({ toolSetHash })]).length, 1);
    const byDesc = matchFingerprints(obs, [entry({ toolDescriptionHashes: [{ tool: "alpha", sha256: descHash }] })]);
    assert.equal(byDesc.length, 1);
    assert.match(byDesc[0].matchedAspects.join(" "), /description hash of tool "alpha"/);
  });

  it("a server name or version gate defeats an otherwise exact hash match", () => {
    assert.deepEqual(matchFingerprints(obs, [entry({ toolSetHash, serverName: "other" })]), []);
    assert.deepEqual(matchFingerprints(obs, [entry({ toolSetHash, serverVersion: "9.9.9" })]), []);
    assert.equal(matchFingerprints(obs, [entry({ toolSetHash, serverName: "srv", serverVersion: "1.0.0" })]).length, 1);
  });

  it("a missing tool or an undefined description defeats a description hash", () => {
    assert.deepEqual(matchFingerprints(obs, [entry({ toolDescriptionHashes: [{ tool: "ghost", sha256: descHash }] })]), []);
    const noDesc: ProbeObservation = { ...obs, tools: [{ name: "alpha", inputSchema: { type: "object" } }] };
    assert.deepEqual(matchFingerprints(noDesc, [entry({ toolDescriptionHashes: [{ tool: "alpha", sha256: descHash }] })]), []);
  });

  it("an identity-only entry matches nothing: a match needs a hash aspect", () => {
    assert.deepEqual(matchFingerprints(obs, [entry({ serverName: "srv", serverVersion: "1.0.0" })]), []);
    assert.deepEqual(matchFingerprints(obs, [entry({})]), []);
  });

  it("one matching description hash among several wanted still matches, with one aspect", () => {
    const matches = matchFingerprints(obs, [
      entry({ toolDescriptionHashes: [{ tool: "alpha", sha256: descHash }, { tool: "ghost", sha256: descHash }] }),
    ]);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].matchedAspects.length, 1);
  });
});

describe("findingToSignal", () => {
  it("carries the severity weight table and formats probed with and without a line", () => {
    assert.deepEqual(SEVERITY_WEIGHTS, { critical: 40, high: 25, medium: 10, low: 4, info: 0 });
    const withLine = findingToSignal({ rule: "R1", severity: "critical", file: "a.ts", line: 7, evidence: "ev", detail: "d" });
    assert.equal(withLine.id, "static:R1");
    assert.equal(withLine.kind, "static");
    assert.equal(withLine.weight, 40);
    assert.equal(withLine.probed, "a.ts:7");
    const noLine = findingToSignal({ rule: "R2", severity: "info", file: "b.ts", line: 0, evidence: "ev", detail: "d" });
    assert.equal(noLine.weight, 0);
    assert.equal(noLine.probed, "b.ts");
  });
});
