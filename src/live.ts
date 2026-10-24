/**
 * Live vetting orchestration: probe parity, fingerprint matching, and
 * the server-level risk score over the signals both produce.
 *
 * Verdict rules for live evidence (0.2.0): any scoring signal makes the
 * verdict REVIEW; a clean double probe, or probes refused for auth
 * reasons (recorded passes), verdict VETTED; no usable evidence at all
 * verdicts REVIEW as inconclusive. Live evidence NEVER yields
 * DO-NOT-INSTALL in this version: one fingerprint match, or even several
 * live signals together, are grounds for a human look, not a hard fail.
 */
import type { LiveReport, ParityDiff, Signal, Verdict } from "./types.js";
import { VERSION } from "./vet.js";
import { loadFingerprints, matchFingerprints, type FingerprintEntry } from "./fingerprints.js";
import { DEFAULT_PROBE_TIMEOUT_MS, probeParity, type ProbeSpec } from "./probe.js";
import { buildRiskAssessment } from "./signals.js";

export type { ProbeSpec };

function severityForWeight(weight: number): Signal["severity"] {
  return weight >= 20 ? "medium" : "low";
}

function paritySignals(diffs: ParityDiff[], probed: string, at: string): Signal[] {
  const groups: { test: (f: string) => boolean; severity: Signal["severity"]; weight: number; label: string }[] = [
    {
      test: (f) => f.startsWith("server."),
      severity: "high", weight: 25, label: "server identity drifted between identical probes",
    },
    {
      test: (f) => f === "tools.added" || f === "tools.removed",
      severity: "high", weight: 20, label: "tool set drifted between identical probes",
    },
    {
      test: (f) => f.endsWith(".inputSchema"),
      severity: "high", weight: 20, label: "a tool input schema drifted between identical probes",
    },
    {
      test: (f) => f.endsWith(".description"),
      severity: "medium", weight: 10, label: "a tool description drifted between identical probes",
    },
  ];
  const signals: Signal[] = [];
  for (const g of groups) {
    const hits = diffs.filter((d) => g.test(d.field));
    if (!hits.length) continue;
    signals.push({
      id: "probe-parity",
      kind: "parity",
      severity: g.severity,
      weight: g.weight,
      detail: `Probe parity: ${g.label}. A stable server answers two identical probes identically; drift is the rug-pull shape.`,
      probed,
      observed: hits.map((d) => `${d.field}: "${d.first}" -> "${d.second}"`).join("; "),
      at,
    });
  }
  return signals;
}

export async function vetLive(
  spec: ProbeSpec,
  opts: { timeoutMs?: number; entries?: FingerprintEntry[] } = {},
): Promise<LiveReport> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
  const target = [spec.command, ...(spec.args ?? [])].join(" ");
  const probedDesc = `live probe of "${target}" (initialize + tools/list)`;
  const notes: string[] = [
    "Live mode EXECUTES the server command (twice, once per probe). Static vetting never executes target code; this mode is separate for exactly that reason.",
    "Live evidence never yields DO-NOT-INSTALL in mcpvet 0.2.0; the harshest live verdict is REVIEW.",
  ];
  const { first, second, diffs } = await probeParity(spec, timeoutMs);
  const signals: Signal[] = [];

  const outcomes = [
    { label: "first", outcome: first },
    { label: "second", outcome: second },
  ];
  for (const { label, outcome } of outcomes) {
    const at = new Date().toISOString();
    if (outcome.status === "auth-refused") {
      signals.push({
        id: "probe-auth",
        kind: "control",
        severity: "info",
        weight: 0,
        detail: `The ${label} probe was refused for auth reasons: recorded as a PASS on that probe. A server that demands credentials before answering is doing the minimum right.`,
        probed: probedDesc,
        observed: outcome.error ?? "auth refusal",
        at,
      });
    } else if (outcome.status === "timeout") {
      notes.push(`The ${label} probe timed out after ${timeoutMs} ms: recorded as NO SIGNAL. A timeout is not evidence about the server.`);
    } else if (outcome.status === "error") {
      notes.push(`The ${label} probe failed: ${outcome.error ?? "unknown error"}`);
    }
  }

  const observation = first.observation ?? second.observation;
  const matchedEntryIds: string[] = [];
  if (observation) {
    const entries = opts.entries ?? loadFingerprints();
    for (const match of matchFingerprints(observation, entries)) {
      matchedEntryIds.push(match.entry.id);
      signals.push({
        id: `fingerprint:${match.entry.id}`,
        kind: "fingerprint",
        severity: severityForWeight(match.entry.weight),
        weight: match.entry.weight,
        detail: `Exact fingerprint match: ${match.entry.label}. A match adds score; by itself it never hard-fails a server. Provenance: ${match.entry.provenance}`,
        probed: probedDesc,
        observed: `matched ${match.matchedAspects.join(", ")} against entry ${match.entry.id}`,
        at: new Date().toISOString(),
      });
    }
  }

  const bothOk = first.status === "ok" && second.status === "ok";
  if (bothOk && diffs.length > 0) {
    signals.push(...paritySignals(diffs, probedDesc, new Date().toISOString()));
  }

  const risk = buildRiskAssessment(signals);
  const hasScoringSignal = signals.some((s) => s.kind !== "control" && s.weight > 0);
  const anyOk = first.status === "ok" || second.status === "ok";
  const anyAuthPass = signals.some((s) => s.kind === "control");
  let verdict: Verdict;
  if (hasScoringSignal) {
    verdict = "REVIEW";
  } else if (anyOk || anyAuthPass) {
    verdict = "VETTED";
  } else {
    verdict = "REVIEW";
    notes.push("Inconclusive: neither probe produced usable evidence, so there is nothing to vet on. Inconclusive is not a pass.");
  }

  return {
    tool: "mcpvet",
    version: VERSION,
    mode: "live",
    target,
    command: spec.command,
    args: spec.args ?? [],
    verdict,
    probes: {
      first: { status: first.status, error: first.error },
      second: { status: second.status, error: second.error },
    },
    observation,
    parity: { applicable: bothOk, consistent: bothOk && diffs.length === 0, diffs },
    fingerprints: { matchedEntryIds },
    risk,
    notes,
  };
}

export function renderLiveReport(r: LiveReport): string {
  const out: string[] = [];
  out.push(`mcpvet ${r.version} (live probe): ${r.target}`);
  out.push(`verdict: ${r.verdict}`);
  out.push(`probes: first=${r.probes.first.status}, second=${r.probes.second.status}`);
  if (r.observation) {
    out.push(
      `server: ${r.observation.serverName || "(no name)"} ${r.observation.serverVersion || ""} tools [${r.observation.tools.map((t) => t.name).join(", ")}]`,
    );
  }
  out.push(
    r.parity.applicable
      ? `parity: ${r.parity.consistent ? "consistent across both probes" : `${r.parity.diffs.length} diff(s)`}`
      : "parity: not applicable (a probe did not complete)",
  );
  for (const d of r.parity.diffs) out.push(`  diff ${d.field}: "${d.first}" -> "${d.second}"`);
  out.push(`fingerprints matched: ${r.fingerprints.matchedEntryIds.length ? r.fingerprints.matchedEntryIds.join(", ") : "none"}`);
  out.push(`risk: score ${r.risk.score}/100 (${r.risk.band}) from ${r.risk.signals.length} signal(s)`);
  for (const n of r.notes) out.push(`note: ${n}`);
  if (r.risk.signals.length) {
    out.push("");
    out.push("signals:");
    for (const s of r.risk.signals) {
      out.push(`- [${s.kind}] ${s.id} (weight ${s.weight}): ${s.detail}`);
      out.push(`  observed: ${s.observed}`);
    }
  }
  return out.join("\n");
}
