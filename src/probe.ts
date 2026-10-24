/**
 * Live probing of a stdio MCP server, the dynamic counterpart to the
 * static vetting in vet.ts. A probe SPAWNS the server command; that is
 * why it lives behind its own command and tool instead of being folded
 * into vet_path, whose contract is that scanned code never executes.
 *
 * The parity check probes twice (initialize plus tools/list each time)
 * and diffs the two observations. NOT-scored rules, explicit: a probe
 * refused for auth reasons is classified "auth-refused" and recorded by
 * the caller as a pass on that probe, and a timeout is classified
 * "timeout" and records no signal at all.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ParityDiff, ProbeObservation, ProbeStatus } from "./types.js";
import { canonicalJson } from "./signals.js";

export interface ProbeSpec {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface ProbeOutcome {
  status: ProbeStatus;
  observation?: ProbeObservation;
  error?: string;
}

export const DEFAULT_PROBE_TIMEOUT_MS = 15000;

const AUTH_RE = /\b(401|403)\b|unauthori[sz]ed|forbidden|authentication|access denied|api[- ]?key (is )?(required|invalid|missing)|invalid api[- ]?key|missing api[- ]?key/i;
const TIMEOUT_RE = /abort|timed out|timeout|requesttimeout/i;

/** Classify a probe failure. Deterministic keyword classification. */
export function classifyProbeError(err: unknown): ProbeStatus {
  const msg = err instanceof Error ? `${err.name} ${err.message}` : String(err);
  if (TIMEOUT_RE.test(msg)) return "timeout";
  if (AUTH_RE.test(msg)) return "auth-refused";
  return "error";
}

/** Run one probe: spawn, initialize, list tools, close. */
export async function probeServer(
  spec: ProbeSpec,
  timeoutMs: number = DEFAULT_PROBE_TIMEOUT_MS,
): Promise<ProbeOutcome> {
  const transport = new StdioClientTransport({
    command: spec.command,
    args: spec.args ?? [],
    env: spec.env,
    cwd: spec.cwd,
    stderr: "pipe",
  });
  const client = new Client({ name: "mcpvet-probe", version: "0.2.0" });
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    await client.connect(transport, { signal: ac.signal, timeout: timeoutMs });
    const listed = await client.listTools(undefined, { signal: ac.signal, timeout: timeoutMs });
    const impl = client.getServerVersion();
    const observation: ProbeObservation = {
      serverName: impl?.name ?? "",
      serverVersion: impl?.version ?? "",
      capabilities: client.getServerCapabilities() ?? null,
      tools: listed.tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    };
    return { status: "ok", observation };
  } catch (err) {
    return {
      status: classifyProbeError(err),
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
    try {
      await client.close();
    } catch {
      // The child may already be gone; closing is best-effort.
    }
  }
}

export interface ParityResult {
  first: ProbeOutcome;
  second: ProbeOutcome;
  /** Diffs between the two observations; empty unless both probes ran ok. */
  diffs: ParityDiff[];
}

/** Probe twice and diff the observations. */
export async function probeParity(
  spec: ProbeSpec,
  timeoutMs: number = DEFAULT_PROBE_TIMEOUT_MS,
): Promise<ParityResult> {
  const first = await probeServer(spec, timeoutMs);
  const second = await probeServer(spec, timeoutMs);
  const diffs =
    first.status === "ok" && second.status === "ok" && first.observation && second.observation
      ? diffObservations(first.observation, second.observation)
      : [];
  return { first, second, diffs };
}

function short(value: string): string {
  return value.length > 200 ? `${value.slice(0, 200)}...` : value;
}

/**
 * Diff two probe observations. Catches identity drift (name, version,
 * capabilities), tool set drift (added or removed tools), and per-tool
 * drift (description text or input schema). Pure and deterministic.
 */
export function diffObservations(a: ProbeObservation, b: ProbeObservation): ParityDiff[] {
  const diffs: ParityDiff[] = [];
  if (a.serverName !== b.serverName) {
    diffs.push({ field: "server.name", first: a.serverName, second: b.serverName });
  }
  if (a.serverVersion !== b.serverVersion) {
    diffs.push({ field: "server.version", first: a.serverVersion, second: b.serverVersion });
  }
  const capA = canonicalJson(a.capabilities ?? null);
  const capB = canonicalJson(b.capabilities ?? null);
  if (capA !== capB) {
    diffs.push({ field: "server.capabilities", first: short(capA), second: short(capB) });
  }
  const byNameA = new Map(a.tools.map((t) => [t.name, t]));
  const byNameB = new Map(b.tools.map((t) => [t.name, t]));
  const added = [...byNameB.keys()].filter((n) => !byNameA.has(n)).sort();
  const removed = [...byNameA.keys()].filter((n) => !byNameB.has(n)).sort();
  if (added.length) diffs.push({ field: "tools.added", first: "", second: added.join(", ") });
  if (removed.length) diffs.push({ field: "tools.removed", first: removed.join(", "), second: "" });
  for (const name of [...byNameA.keys()].sort()) {
    const ta = byNameA.get(name) as NonNullable<ReturnType<typeof byNameA.get>>;
    const tb = byNameB.get(name);
    if (!tb) continue;
    if ((ta.description ?? "") !== (tb.description ?? "")) {
      diffs.push({
        field: `tools.${name}.description`,
        first: short(ta.description ?? ""),
        second: short(tb.description ?? ""),
      });
    }
    const schemaA = canonicalJson(ta.inputSchema ?? null);
    const schemaB = canonicalJson(tb.inputSchema ?? null);
    if (schemaA !== schemaB) {
      diffs.push({ field: `tools.${name}.inputSchema`, first: short(schemaA), second: short(schemaB) });
    }
  }
  return diffs;
}
