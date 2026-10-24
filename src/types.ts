/**
 * mcpvet types.
 *
 * A VetReport is the static, pre-install verdict on one MCP server,
 * npm package, or agent skill. Every finding carries evidence: the file,
 * the line, the rule id, and the text that matched. Nothing in a report
 * is inferred silently, and no scanned code is ever executed.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Verdict = "VETTED" | "REVIEW" | "DO-NOT-INSTALL";

export type TargetKind = "server" | "skill" | "mixed" | "package" | "unknown";

export interface Finding {
  rule: string;
  severity: Severity;
  file: string;
  /** 1-based line number, or 0 when the finding is not line-bound. */
  line: number;
  evidence: string;
  detail: string;
}

export interface CapabilityHit {
  kind: "filesystem" | "network" | "env" | "shell" | "credential";
  file: string;
  line: number;
  evidence: string;
}

export interface ToolInfo {
  name: string;
  description?: string;
  file: string;
  line: number;
}

export interface VetReport {
  tool: "mcpvet";
  version: string;
  target: string;
  kind: TargetKind;
  name: string;
  packageVersion: string;
  verdict: Verdict;
  counts: Record<"critical" | "high" | "medium" | "low" | "info" | "total", number>;
  inventory: {
    declaredTools: string[];
    tools: ToolInfo[];
    resources: string[];
    prompts: string[];
    declaredName: string;
    serverName: string;
  };
  capabilities: CapabilityHit[];
  findings: Finding[];
  /** Risk score derived from the findings, expressed as signals. */
  risk: RiskAssessment;
  caps: {
    maxFiles: number;
    filesScanned: number;
    filesSkipped: number;
    truncated: boolean;
  };
  notes: string[];
}

/** Minimal fetch surface so tests can inject registry fixtures. */
export interface FetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export type FetchFn = (
  url: string,
  init?: { headers?: Record<string, string> },
) => Promise<FetchResponse>;

/**
 * Signals and the server-level risk score (0.2.0).
 *
 * A Signal is one recorded observation: what was probed, what came back,
 * and (for live probes) when. The risk score is DERIVED from the signal
 * list on read; it is never a mutating counter, and every point of score
 * traces to a signal in the list. Signals inform the verdict bands, they
 * do not replace them.
 */
export type SignalKind = "static" | "fingerprint" | "parity" | "control";

export interface Signal {
  /** Check that produced the signal, e.g. "static:SCRIPT-CRED-EXFIL". */
  id: string;
  kind: SignalKind;
  severity: Severity;
  /** Score contribution. Control signals (recorded passes) weigh 0. */
  weight: number;
  detail: string;
  /** What was probed: a file and line, or a probe description. */
  probed: string;
  /** What came back: finding evidence, or the recorded diff. */
  observed: string;
  /** ISO timestamp. Set for live-probe signals; static scans stay byte deterministic and omit it. */
  at?: string;
}

export type RiskBand = "none" | "low" | "elevated" | "high";

export interface RiskAssessment {
  /** 0 to 100, derived as the capped sum of non-control signal weights. */
  score: number;
  band: RiskBand;
  signals: Signal[];
}

/** One tool as presented by a live server during a probe. */
export interface LiveToolObservation {
  name: string;
  description?: string;
  inputSchema: unknown;
}

/** What one live probe observed: server identity plus its tool list. */
export interface ProbeObservation {
  serverName: string;
  serverVersion: string;
  capabilities: unknown;
  tools: LiveToolObservation[];
}

export interface ParityDiff {
  /** Dotted field path, e.g. "server.name" or "tools.alpha.inputSchema". */
  field: string;
  first: string;
  second: string;
}

export type ProbeStatus = "ok" | "auth-refused" | "timeout" | "error";

export interface ProbeOutcomeSummary {
  status: ProbeStatus;
  error?: string;
}

/**
 * Report of a live probe run (the `probe` command). Unlike VetReport,
 * producing one EXECUTED the target server command, twice. Live evidence
 * alone never yields DO-NOT-INSTALL in this version: the harshest live
 * verdict is REVIEW.
 */
export interface LiveReport {
  tool: "mcpvet";
  version: string;
  mode: "live";
  target: string;
  command: string;
  args: string[];
  verdict: Verdict;
  probes: { first: ProbeOutcomeSummary; second: ProbeOutcomeSummary };
  observation?: ProbeObservation;
  parity: { applicable: boolean; consistent: boolean; diffs: ParityDiff[] };
  fingerprints: { matchedEntryIds: string[] };
  risk: RiskAssessment;
  notes: string[];
}
