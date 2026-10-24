/**
 * Signal accounting for the server-level risk score.
 *
 * The score is derived from an append-only signal list, never kept as a
 * mutating counter: buildRiskAssessment() sums the weights of the signals
 * it is handed, so every point of score traces to a recorded signal with
 * its provenance (what was probed, what came back). Control signals are
 * recorded passes (for example a probe refused for auth reasons); they
 * weigh 0 and exist so the record shows the probe happened and passed.
 *
 * This module also owns the exact hashing used by fingerprint matching:
 * canonical JSON (object keys sorted recursively) hashed with sha256.
 * Fingerprints are exact matches over these hashes, never patterns.
 */
import { createHash } from "node:crypto";
import type { Finding, RiskAssessment, RiskBand, Severity, Signal } from "./types.js";

/** Score contribution per finding severity. */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 25,
  medium: 10,
  low: 4,
  info: 0,
};

export function bandForScore(score: number): RiskBand {
  if (score <= 0) return "none";
  if (score < 20) return "low";
  if (score < 50) return "elevated";
  return "high";
}

/** Derive the risk assessment from a signal list. Pure and deterministic. */
export function buildRiskAssessment(signals: Signal[]): RiskAssessment {
  let sum = 0;
  for (const s of signals) {
    if (s.kind === "control") continue;
    sum += s.weight;
  }
  const score = Math.min(100, sum);
  return { score, band: bandForScore(score), signals };
}

/** Express one static finding as a signal, preserving its evidence. */
export function findingToSignal(f: Finding): Signal {
  return {
    id: `static:${f.rule}`,
    kind: "static",
    severity: f.severity,
    weight: SEVERITY_WEIGHTS[f.severity],
    detail: f.detail,
    probed: f.line ? `${f.file}:${f.line}` : f.file,
    observed: f.evidence,
  };
}

/** JSON with object keys sorted recursively; array order is preserved. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export interface ToolShape {
  name: string;
  description?: string;
  inputSchema: unknown;
}

/**
 * Hash of a server's whole tool set: the canonical JSON of the tools
 * sorted by name, each reduced to name, description, and input schema.
 * Any change to any of the three changes the hash; that is the point.
 */
export function hashToolSet(tools: ToolShape[]): string {
  const reduced = tools
    .map((t) => ({ name: t.name, description: t.description ?? "", inputSchema: t.inputSchema ?? null }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return sha256Hex(canonicalJson(reduced));
}

/** Hash of one exact text (a tool description, byte for byte). */
export function hashText(text: string): string {
  return sha256Hex(text);
}
