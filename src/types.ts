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
