/**
 * mcpvet core: static, pre-install vetting of MCP servers and agent skills.
 *
 * Reads a local directory (an MCP server, a SKILL.md skill, or a mix) or
 * npm registry metadata for a package name, and produces a deterministic
 * VetReport. Scanned code is only ever read as text; nothing is executed,
 * imported, or installed.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative, resolve } from "node:path";
import type {
  CapabilityHit,
  FetchFn,
  Finding,
  Severity,
  ToolInfo,
  VetReport,
} from "./types.js";
import { CREDENTIAL_ENV_RE, CREDENTIAL_STORE_RE, typosquatMatch } from "./known.js";

export const VERSION = "0.1.1";

export const MAX_FILES = 2000;
const MAX_FILE_BYTES = 512 * 1024;
const SCAN_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".sh", ".bash",
  ".json", ".md", ".yml", ".yaml", ".toml", ".txt",
]);
const SKIP_DIRS = new Set(["node_modules", ".git"]);

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

interface FileText {
  rel: string;
  abs: string;
  text: string;
  lines: string[];
}

function walk(root: string): { files: FileText[]; scanned: number; skipped: number; truncated: boolean } {
  const out: FileText[] = [];
  let skipped = 0;
  let truncated = false;
  const stack: string[] = [root];
  const dirs: string[] = [];
  // Deterministic breadth order: collect dirs sorted, then files sorted.
  while (stack.length) {
    const dir = stack.shift() as string;
    dirs.push(dir);
    let entries: string[] = [];
    try {
      entries = readdirSync(dir).sort();
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = join(dir, e);
      let st;
      try {
        st = statSync(p);
      } catch {
        skipped++;
        continue;
      }
      if (st.isSymbolicLink()) {
        skipped++;
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(e)) stack.push(p);
        continue;
      }
      if (!st.isFile()) continue;
      if (!SCAN_EXTS.has(extname(e).toLowerCase()) && e !== "SKILL.md" && !e.startsWith(".")) {
        // Extensionless scripts (bin shims, hooks) are still audited.
        if (st.size > 64 * 1024) { skipped++; continue; }
      }
      if (out.length >= MAX_FILES) {
        truncated = true;
        skipped++;
        continue;
      }
      if (st.size > MAX_FILE_BYTES) {
        skipped++;
        continue;
      }
      let text: string;
      try {
        text = readFileSync(p, "utf8");
      } catch {
        skipped++;
        continue;
      }
      if (text.includes("\u0000")) { skipped++; continue; }
      out.push({ rel: relative(root, p) || basename(p), abs: p, text, lines: text.split(/\r?\n/) });
    }
  }
  out.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return { files: out, scanned: out.length, skipped, truncated };
}

function firstHit(lines: string[], re: RegExp): { line: number; evidence: string } | null {
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) return { line: i + 1, evidence: lines[i].trim().slice(0, 200) };
  }
  return null;
}

const CAP_PATTERNS: { kind: CapabilityHit["kind"]; re: RegExp }[] = [
  { kind: "filesystem", re: /\b(fs|node:fs)\b|readFile|createReadStream|\bpathlib\b|read_text\s*\(|\bopen\s*\([^)]*['"]r/ },
  { kind: "network", re: /\bfetch\s*\(|axios|https?\.(request|get)\s*\(|\brequests\.(get|post|put|delete|request)\b|urllib|XMLHttpRequest|\bWebSocket\b|net\.connect|socket\.createConnection|\bcurl\b|\bwget\b/ },
  { kind: "env", re: /process\.env|os\.environ|os\.getenv|getenv\s*\(|import\.meta\.env/ },
  { kind: "shell", re: /child_process|execSync|execFile|\bspawn\s*\(|(?<![\w.])exec\s*\(|subprocess\.|os\.system|os\.popen|shell\s*=\s*True|Popen\s*\(/ },
  { kind: "credential", re: CREDENTIAL_STORE_RE },
];

/** Instruction and exfil language patterns for descriptions and SKILL.md. */
const DESC_PATTERNS: { rule: string; severity: Severity; re: RegExp; detail: string }[] = [
  {
    rule: "DESC-EXFIL", severity: "high",
    re: /\b(send|post|upload|forward|transmit|deliver|exfiltrate)\b[^.\n]{0,100}\b(contents? of|credential|secret|token|api[ _-]?key|password|\.env\b|environment variable)/i,
    detail: "Text instructs sending credential material or file contents to another destination.",
  },
  {
    rule: "DESC-EXFIL", severity: "high",
    re: /\b(contents? of|read|cat|collect|gather)\b[^.\n]{0,60}\b(\.env\b|~\/\.ssh|~\/\.aws|credentials|id_rsa)\b[^.\n]{0,80}\b(send|post|upload|forward|transmit|http)/i,
    detail: "Text pairs reading credential stores with sending the contents onward.",
  },
  {
    rule: "DESC-INSTRUCTION", severity: "medium",
    re: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|system)\b[^.\n]{0,30}\b(instruction|prompt|rule|direction)/i,
    detail: "Text instructs the agent to override prior instructions.",
  },
  {
    rule: "DESC-INSTRUCTION", severity: "medium",
    re: /\bdo not (tell|inform|mention|notify|alert)\b[^.\n]{0,30}\b(user|human|owner|operator)\b/i,
    detail: "Text instructs the agent to hide its actions from the user.",
  },
  {
    rule: "DESC-INSTRUCTION", severity: "medium",
    re: /\bwithout (telling|informing|asking|notifying)\b[^.\n]{0,30}\b(user|human|owner|operator|permission)\b/i,
    detail: "Text instructs the agent to act without the user's knowledge.",
  },
  {
    rule: "DESC-COMMAND", severity: "medium",
    re: /\b(run|execute|invoke)\b[^.\n]{0,60}\b(curl|wget|bash|sh|powershell|chmod \+x)\b/i,
    detail: "Text instructs the agent to run a shell command, in a description rather than in code.",
  },
];

function parseJsonSafe(text: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item === "string") out.push(item);
    else if (item && typeof item === "object" && typeof (item as { name?: unknown }).name === "string") {
      out.push((item as { name: string }).name);
    }
  }
  return out;
}

const CONFIG_BASENAMES = new Set([
  "claude_desktop_config.json", ".mcp.json", "mcp.json", "mcp_settings.json",
]);

function isConfigFile(rel: string): boolean {
  const base = basename(rel);
  if (CONFIG_BASENAMES.has(base)) return true;
  if (/(^|\/)\.cursor\/mcp\.json$/.test(rel)) return true;
  if (/(^|\/)\.vscode\/mcp\.json$/.test(rel)) return true;
  return false;
}


interface ServerEntry {
  name: string;
  command: string;
  args: string[];
  env: Record<string, unknown>;
  file: string;
  line: number;
}

function auditConfig(
  findings: Finding[],
  f: FileText,
  entries: ServerEntry[],
): void {
  const obj = parseJsonSafe(f.text);
  if (!obj) {
    findings.push({
      rule: "CONFIG-UNPARSEABLE", severity: "low", file: f.rel, line: 0,
      evidence: "file is not parseable JSON",
      detail: "A client config file that cannot be parsed cannot be audited; treat as unreviewed.",
    });
    return;
  }
  const servers = (obj.mcpServers ?? obj.servers) as Record<string, unknown> | undefined;
  if (!servers || typeof servers !== "object") return;
  for (const [name, raw] of Object.entries(servers)) {
    if (!raw || typeof raw !== "object") continue;
    const entry = raw as Record<string, unknown>;
    const command = typeof entry.command === "string" ? entry.command : "";
    const args = asStringArray(entry.args);
    const env = (entry.env && typeof entry.env === "object")
      ? (entry.env as Record<string, unknown>) : {};
    const lineHit = firstHit(f.lines, new RegExp(`"${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
    const line = lineHit ? lineHit.line : 1;
    entries.push({ name, command, args, env, file: f.rel, line });
    const shape = `${command} ${args.join(" ")}`.trim();

    findings.push({
      rule: "CONFIG-AUTOSTART", severity: "info", file: f.rel, line,
      evidence: shape.slice(0, 200) || name,
      detail: `Server "${name}" auto-starts whenever the client loads this config.`,
    });

    if (/\|\s*(sudo\s+)?(sh|bash|zsh)\b/.test(shape) || /\b(curl|wget)\b[^|]*\|\s*(sh|bash)/.test(shape)) {
      findings.push({
        rule: "CONFIG-CURL-PIPE", severity: "critical", file: f.rel, line,
        evidence: shape.slice(0, 200),
        detail: "Autostart command pipes a remote download straight into a shell.",
      });
    }
    if (/^(sh|bash|zsh|cmd|powershell)(\.exe)?$/.test(command.trim()) || /\s-c\s/.test(shape)) {
      findings.push({
        rule: "CONFIG-SHELL-WRAPPER", severity: "medium", file: f.rel, line,
        evidence: shape.slice(0, 200),
        detail: "Server is launched through a shell wrapper, so the effective command is whatever the shell string says.",
      });
    }
    if (/^npx(\.cmd)?$/.test(command.trim())) {
      const pkgArg = args.find((a) => !a.startsWith("-"));
      const hasYes = args.includes("-y") || args.includes("--yes");
      const pinned = pkgArg ? /@\d+\.\d+\.\d+/.test(pkgArg) || /@\d+$/.test(pkgArg.split("@").pop() ?? "") && /@[^/]+$/.test(pkgArg) : false;
      const versioned = pkgArg ? /^(@[^/]+\/)?[^@/]+@\d/.test(pkgArg) : false;
      if (hasYes && !versioned) {
        findings.push({
          rule: "CONFIG-UNPINNED-NPX", severity: "high", file: f.rel, line,
          evidence: shape.slice(0, 200),
          detail: "Autostart runs npx -y on an unpinned package: whatever publishes that name next runs on this machine.",
        });
      } else if (!versioned && pkgArg) {
        findings.push({
          rule: "CONFIG-UNPINNED-NPX", severity: "medium", file: f.rel, line,
          evidence: shape.slice(0, 200),
          detail: "Autostart runs an npx package with no version pin.",
        });
      }
      void pinned;
    }
    if (pkgNameFromArgs(args)) {
      const pkg = pkgNameFromArgs(args) as string;
      const typo = typosquatMatch(pkg.split("/").pop() as string);
      if (typo) {
        findings.push({
          rule: "TYPOSQUAT", severity: "high", file: f.rel, line,
          evidence: pkg,
          detail: `Config launches package "${pkg}", edit distance ${typo.distance} from well-known "${typo.known}".`,
        });
      }
    }
    const envKeys = Object.keys(env);
    const credKeys = envKeys.filter((k) => CREDENTIAL_ENV_RE.test(k));
    if (envKeys.length >= 6 && credKeys.length >= 3) {
      findings.push({
        rule: "CONFIG-ENV-HARVEST", severity: "high", file: f.rel, line,
        evidence: `env block with ${envKeys.length} keys, ${credKeys.length} credential-shaped: ${credKeys.slice(0, 6).join(", ")}`,
        detail: "Config hands the server a wide env block sweeping in credential-shaped names it may not need.",
      });
    } else if (credKeys.length >= 1) {
      findings.push({
        rule: "CONFIG-ENV-HARVEST", severity: "medium", file: f.rel, line,
        evidence: `credential-shaped env keys passed to server: ${credKeys.slice(0, 6).join(", ")}`,
        detail: "Config passes credential-shaped env values to the server at autostart.",
      });
    }
    const envText = JSON.stringify(env);
    if (/process\.env|\$\{env:|"\*"|"\.\.\."/.test(envText) || /\.\.\./.test(shape)) {
      findings.push({
        rule: "CONFIG-ENV-PASSTHROUGH", severity: "high", file: f.rel, line,
        evidence: shape.slice(0, 200),
        detail: "Config appears to pass the client's whole environment through to the server.",
      });
    }
  }
}

function pkgNameFromArgs(args: string[]): string | null {
  const a = args.find((x) => !x.startsWith("-") && x !== "-y" && x !== "--yes");
  return a ?? null;
}

function auditInstallScripts(
  findings: Finding[],
  file: string,
  scripts: Record<string, unknown>,
): void {
  for (const key of ["preinstall", "install", "postinstall", "prepare"]) {
    const cmd = scripts[key];
    if (typeof cmd !== "string" || !cmd.trim()) continue;
    if (/\b(curl|wget)\b[^|]*\|\s*(sh|bash)/.test(cmd) || /\/dev\/tcp\//.test(cmd)) {
      findings.push({
        rule: "INSTALL-DROPPER", severity: "critical", file, line: 0,
        evidence: `${key}: ${cmd.slice(0, 200)}`,
        detail: "Install script pipes a remote download into a shell; it runs before any vetting of the server itself can help.",
      });
    } else if (/\b(curl|wget|fetch|node\s+-e|powershell|chmod\s+\+x)\b/.test(cmd)) {
      findings.push({
        rule: "INSTALL-SCRIPT", severity: "high", file, line: 0,
        evidence: `${key}: ${cmd.slice(0, 200)}`,
        detail: "Install script fetches remote content or executes inline code at install time.",
      });
    } else {
      findings.push({
        rule: "INSTALL-SCRIPT", severity: "medium", file, line: 0,
        evidence: `${key}: ${cmd.slice(0, 200)}`,
        detail: "Package runs a script at install time; it executes with the installer's full permissions.",
      });
    }
  }
}

function scanScriptShapes(
  findings: Finding[],
  f: FileText,
  capsHere: CapabilityHit[],
): void {
  const kinds = new Set(capsHere.map((c) => c.kind));
  const t = f.text;
  if (/\/dev\/tcp\/|bash\s+-i\s+>&|nc\s+(-e|--exec)\b|socket[^\n]*dup2|pty\.spawn/.test(t)) {
    findings.push({
      rule: "SCRIPT-REVERSE-SHELL", severity: "critical", file: f.rel,
      line: (firstHit(f.lines, /\/dev\/tcp\/|bash\s+-i\s+>&|nc\s+(-e|--exec)\b|dup2|pty\.spawn/) ?? { line: 0 }).line,
      evidence: (firstHit(f.lines, /\/dev\/tcp\/|bash\s+-i\s+>&|nc\s+(-e|--exec)\b|dup2|pty\.spawn/) ?? { evidence: "" }).evidence,
      detail: "Bundled script has the shape of a reverse shell: an interactive shell bound to a network socket.",
    });
  }
  if (kinds.has("credential") && kinds.has("network")) {
    findings.push({
      rule: "SCRIPT-CRED-EXFIL", severity: "critical", file: f.rel,
      line: capsHere.find((c) => c.kind === "credential")?.line ?? 0,
      evidence: `credential read and network send in the same file (${f.rel})`,
      detail: "One bundled file both reads a credential store and makes network requests: the credential-stealer shape behind the ClawHavoc skill wave.",
    });
  }
  const persistRe = /SessionStart|settings\.json|\.claude[\\/]+settings|crontab|LaunchAgents|systemctl\s+enable|folderOpen|\.vscode[\\/]+tasks\.json|CurrentVersion[\\/]+Run\b|login item/i;
  const persistHit = firstHit(f.lines, persistRe);
  if (persistHit && (/\b(write|append|copy|cp|tee|Set-Content|Add-Content|fs\.|open\s*\()\b/.test(t) || extname(f.rel) === ".sh")) {
    findings.push({
      rule: "SCRIPT-PERSISTENCE", severity: "high", file: f.rel, line: persistHit.line,
      evidence: persistHit.evidence,
      detail: "Bundled script touches an agent or OS persistence location (session hooks, scheduled tasks, autostart entries).",
    });
  }
  if (kinds.has("network") && kinds.has("shell") && /\b(chmod\s+\+x|exec|spawn|system|popen)\b/.test(t)) {
    findings.push({
      rule: "SCRIPT-DROPPER", severity: "high", file: f.rel, line: 0,
      evidence: `network fetch combined with code execution in ${f.rel}`,
      detail: "Script downloads content and executes code: the dropper shape used by install-time malware.",
    });
  }
}

// Download-and-execute shapes declared as text anywhere in a package:
// a remote download piped or substituted straight into a shell or another
// interpreter, or downloaded and then run on the same line. The ClawHavoc
// skill wave carried this shape as a prerequisite step inside SKILL.md
// prose, where the script-shape rules above never look because they only
// run on script files and the description rules only grade prose commands
// at medium. A pipe into a shell is the same shape the config audit and
// the install script audit already grade critical, so it is critical here
// too, in whatever file declares it.
// The pipe and chained forms require a remote reference (a URL scheme or
// a dotted host with a path) between the downloader and the execution
// step. A bare downloader name followed by a shell word is not enough:
// that looser shape also matches alternation lists inside other tools'
// pattern literals, which are documentation of the shape, not the shape.
const DOWNLOAD_EXEC_RES: RegExp[] = [
  /\b(curl|wget)\b[^|\n]*?(?:https?:\/\/|ftp:\/\/|[\w.-]+\.[a-z]{2,}\/)[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|fish|python3?|node|perl|ruby)\b/,
  /\b(sh|bash|zsh|dash|fish)\b[^\n]*<\(\s*(curl|wget)\b/,
  /\b(sh|bash|zsh|dash|fish)\b[^\n]*\$\(\s*(curl|wget)\b/,
  /\beval\b[^\n]*\$\(\s*(curl|wget)\b/,
  /\b(curl|wget)\b[^&\n]*?(?:https?:\/\/|ftp:\/\/|[\w.-]+\.[a-z]{2,}\/)[^&\n]*&&\s*(sudo\s+)?(sh|bash|zsh|dash)\s/,
  /\b(curl|wget)\b[^&\n]*?(?:https?:\/\/|ftp:\/\/|[\w.-]+\.[a-z]{2,}\/)[^&\n]*&&\s*(sudo\s+)?\.\/[\w.-]+\.(sh|bash)\b/,
];

function scanDownloadExec(findings: Finding[], f: FileText): void {
  // Client configs and package.json install scripts already grade this
  // exact shape critical under CONFIG-CURL-PIPE and INSTALL-DROPPER;
  // do not double-count the same line under a second rule.
  if (isConfigFile(f.rel) || basename(f.rel) === "package.json") return;
  let best: { line: number; evidence: string } | null = null;
  for (const re of DOWNLOAD_EXEC_RES) {
    const hit = firstHit(f.lines, re);
    if (hit && (!best || hit.line < best.line)) best = hit;
  }
  if (!best) return;
  findings.push({
    rule: "DOC-DOWNLOAD-EXEC", severity: "critical", file: f.rel, line: best.line,
    evidence: best.evidence,
    detail: "Package text declares a download-and-execute step: a remote download is piped or substituted straight into a shell or interpreter, so remote code runs with the user's permissions before the skill or server is ever used. This is the download-and-execute prerequisite shape from the ClawHavoc skill wave, graded critical like the same shape in autostart configs and install scripts.",
  });
}


export function vetPath(rootInput: string): VetReport {
  const root = resolve(rootInput);
  const findings: Finding[] = [];
  const notes: string[] = [];
  const { files, scanned, skipped, truncated } = walk(root);
  if (truncated) {
    notes.push(`File walk hit the cap of ${MAX_FILES} files; the remainder was not scanned. The cap is reported, not silent.`);
  }

  const byRel = new Map(files.map((f) => [f.rel, f]));
  const pkgFile = byRel.get("package.json");
  const pkg = pkgFile ? parseJsonSafe(pkgFile.text) : null;
  const serverJsonFile = byRel.get("server.json");
  const serverJson = serverJsonFile ? parseJsonSafe(serverJsonFile.text) : null;
  const skillFile = files.find((f) => basename(f.rel) === "SKILL.md");

  const kind: VetReport["kind"] = skillFile && (pkg || serverJson)
    ? "mixed"
    : skillFile
      ? "skill"
      : pkg || serverJson
        ? "server"
        : files.some((f) => isConfigFile(f.rel))
          ? "server"
          : "unknown";
  if (kind === "unknown") {
    notes.push("No package.json, server.json, SKILL.md, or client config found; the target was scanned as loose files only.");
  }

  // Inventory: declared tools.
  const declaredTools = new Set<string>();
  let declaredName = "";
  if (serverJson) {
    for (const t of asStringArray(serverJson.tools)) declaredTools.add(t);
    if (typeof serverJson.name === "string") declaredName = serverJson.name;
  }
  if (pkg) {
    for (const t of asStringArray(pkg.mcpTools)) declaredTools.add(t);
    for (const t of asStringArray(pkg.tools)) declaredTools.add(t);
    const mcpField = pkg.mcp as Record<string, unknown> | undefined;
    if (mcpField) for (const t of asStringArray(mcpField.tools)) declaredTools.add(t);
  }
  for (const f of files) {
    if (/(^|\/)(tools|manifest)\.json$/.test(f.rel) && f.rel !== "package.json") {
      const obj = parseJsonSafe(f.text);
      if (obj) for (const t of asStringArray(obj.tools)) declaredTools.add(t);
    }
  }

  // Inventory: actual tools, resources, prompts from source.
  const tools: ToolInfo[] = [];
  const seenTools = new Set<string>();
  const resources = new Set<string>();
  const prompts = new Set<string>();
  const descTexts: { text: string; line: number; file: string }[] = [];
  const addTool = (name: string, description: string | undefined, file: string, line: number) => {
    if (!name || seenTools.has(name)) return;
    seenTools.add(name);
    tools.push({ name, description, file, line });
    if (description) descTexts.push({ text: description, line, file });
  };

  for (const f of files) {
    const ext = extname(f.rel).toLowerCase();
    if (![".ts", ".js", ".mjs", ".cjs", ".tsx", ".py"].includes(ext)) continue;
    f.lines.forEach((lineText, idx) => {
      const line = idx + 1;
      let m: RegExpExecArray | null;
      const toolRe = /\.tool\(\s*["'`]([\w.:-]+)["'`]\s*(?:,\s*["'`]([^"'`]{0,600})["'`])?/g;
      while ((m = toolRe.exec(lineText))) addTool(m[1], m[2], f.rel, line);
      const regRe = /registerTool\(\s*["'`]([\w.:-]+)["'`]/g;
      while ((m = regRe.exec(lineText))) addTool(m[1], undefined, f.rel, line);
      const resRe = /\.(resource|registerResource)\(\s*["'`]([\w.:/-]+)["'`]/g;
      while ((m = resRe.exec(lineText))) resources.add(m[2]);
      const promptRe = /\.(prompt|registerPrompt)\(\s*["'`]([\w.:-]+)["'`]/g;
      while ((m = promptRe.exec(lineText))) prompts.add(m[2]);
      if (ext === ".py") {
        const pyRe = /^\s*(?:async\s+)?def\s+(\w+)\s*\(/;
        const pm = pyRe.exec(lineText);
        if (pm && idx > 0 && /@\w+\.tool\(/.test(f.lines[idx - 1])) {
          addTool(pm[1], undefined, f.rel, line);
        }
      }
    });
    // JSON-shaped tool tables embedded in source or data files.
    if (f.text.includes('"tools"')) {
      const obj = parseJsonSafe(f.text);
      if (obj) {
        for (const t of asStringArray(obj.tools)) {
          const raw = (obj.tools as unknown[]).find(
            (x) => x && typeof x === "object" && (x as { name?: string }).name === t,
          ) as { description?: string } | undefined;
          addTool(t, raw?.description, f.rel, 0);
        }
      }
    }
  }
  tools.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  // Capabilities, per file then aggregated.
  const capabilities: CapabilityHit[] = [];
  const capKinds = new Set<CapabilityHit["kind"]>();
  for (const f of files) {
    const ext = extname(f.rel).toLowerCase();
    if ([".md", ".txt"].includes(ext) && basename(f.rel) !== "SKILL.md") continue;
    const here: CapabilityHit[] = [];
    for (const p of CAP_PATTERNS) {
      const hit = firstHit(f.lines, p.re);
      if (hit) {
        const cap = { kind: p.kind, file: f.rel, line: hit.line, evidence: hit.evidence };
        here.push(cap);
        capabilities.push(cap);
        capKinds.add(p.kind);
      }
    }
    if ([".sh", ".bash", ".js", ".mjs", ".cjs", ".py", ".ts"].includes(ext) || !ext) {
      scanScriptShapes(findings, f, here);
    }
  }
  capabilities.sort((a, b) => a.file.localeCompare(b.file) || a.kind.localeCompare(b.kind));

  // Download-and-execute declarations can sit in any file in the package:
  // SKILL.md prerequisites, READMEs, bundled scripts, or plain docs.
  for (const f of files) scanDownloadExec(findings, f);

  // SKILL.md audit.
  let skillName = "";
  if (skillFile) {
    const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(skillFile.text);
    if (fm) {
      const nm = /^name:\s*(.+)$/m.exec(fm[1]);
      if (nm) skillName = nm[1].trim().replace(/^["']|["']$/g, "");
      const dm = /^description:\s*(.+)$/m.exec(fm[1]);
      if (dm) descTexts.push({ text: dm[1].trim(), line: 2, file: skillFile.rel });
    }
    skillFile.lines.forEach((text, idx) => {
      descTexts.push({ text, line: idx + 1, file: skillFile.rel });
    });
  }
  const seenDesc = new Set<string>();
  for (const d of descTexts) {
    for (const p of DESC_PATTERNS) {
      if (!p.re.test(d.text)) continue;
      const key = `${p.rule}|${d.file}|${d.line}|${p.detail}`;
      if (seenDesc.has(key)) continue;
      seenDesc.add(key);
      findings.push({
        rule: p.rule, severity: p.severity, file: d.file, line: d.line,
        evidence: d.text.trim().slice(0, 200), detail: p.detail,
      });
    }
  }
  if (pkg && typeof pkg.description === "string") {
    const d = { text: pkg.description, line: 0, file: "package.json" };
    for (const p of DESC_PATTERNS) {
      if (p.re.test(d.text)) {
        findings.push({
          rule: p.rule, severity: p.severity, file: d.file, line: 0,
          evidence: d.text.slice(0, 200), detail: p.detail,
        });
      }
    }
  }

  // Config file audit.
  const entries: ServerEntry[] = [];
  for (const f of files) {
    if (isConfigFile(f.rel)) auditConfig(findings, f, entries);
  }

  // Install scripts in package.json.
  if (pkg && pkg.scripts && typeof pkg.scripts === "object") {
    auditInstallScripts(findings, "package.json", pkg.scripts as Record<string, unknown>);
  }

  // Dangerous capability combinations (target level).
  const capEvidence = (k: CapabilityHit["kind"]) => {
    const c = capabilities.find((x) => x.kind === k);
    return c ? `${c.file}:${c.line} ${c.evidence}` : "";
  };
  if (capKinds.has("credential") && capKinds.has("network")) {
    const sameFile = capabilities.some(
      (c) => c.kind === "credential" &&
        capabilities.some((n) => n.kind === "network" && n.file === c.file),
    );
    if (!sameFile) {
      // Same-file credential plus network is SCRIPT-CRED-EXFIL (critical).
      // Split across files it is still a dangerous combination, one tier down.
      findings.push({
        rule: "CAP-CRED-EGRESS", severity: "high", file: "(target)", line: 0,
        evidence: `credential: ${capEvidence("credential")} | network: ${capEvidence("network")}`,
        detail: "Target touches a credential store in one component and has network egress in another: the pieces of a stealer, separated. Combined they can still move credentials off the machine.",
      });
    }
  }
  if (capKinds.has("filesystem") && capKinds.has("network")) {
    findings.push({
      rule: "CAP-FS-NET", severity: "high", file: "(target)", line: 0,
      evidence: `filesystem: ${capEvidence("filesystem")} | network: ${capEvidence("network")}`,
      detail: "Target can both read the filesystem and make network requests: any file it reads can leave the machine.",
    });
  }
  if (capKinds.has("env") && capKinds.has("network")) {
    findings.push({
      rule: "CAP-ENV-NET", severity: "high", file: "(target)", line: 0,
      evidence: `env: ${capEvidence("env")} | network: ${capEvidence("network")}`,
      detail: "Target reads environment variables and has network egress: env values (where API keys live) can be sent out.",
    });
  }
  if (capKinds.has("shell") && (tools.length > 0 || kind === "skill")) {
    const shellTool = tools.find((t) => /shell|exec|command|terminal|bash|run/i.test(t.name));
    findings.push({
      rule: "CAP-SHELL-TOOL", severity: "high", file: "(target)", line: 0,
      evidence: shellTool
        ? `tool "${shellTool.name}" at ${shellTool.file}:${shellTool.line}; shell capability: ${capEvidence("shell")}`
        : `shell capability: ${capEvidence("shell")}`,
      detail: "Shell execution is reachable from this target's tool surface: a prompt injection becomes arbitrary command execution.",
    });
  }

  // Declared vs actual mismatches.
  if (declaredTools.size > 0) {
    const actual = new Set(tools.map((t) => t.name));
    for (const name of [...declaredTools].sort()) {
      if (!actual.has(name)) {
        findings.push({
          rule: "MISMATCH-DECLARED-MISSING", severity: "medium", file: "(manifest)", line: 0,
          evidence: `declared tool "${name}" has no matching registration`,
          detail: "A tool is declared in the manifest but absent from the code: the manifest overstates or the build is stale.",
        });
      }
    }
    for (const t of tools) {
      if (!declaredTools.has(t.name)) {
        findings.push({
          rule: "MISMATCH-UNDECLARED", severity: "high", file: t.file, line: t.line,
          evidence: `tool "${t.name}" is registered but not declared in any manifest`,
          detail: "An undeclared tool is a hidden capability: users consent to the declared list, not to this one.",
        });
      }
    }
  }

  // Name, version, pinning.
  const pkgName = typeof pkg?.name === "string" ? pkg.name : "";
  const pkgVersion = typeof pkg?.version === "string" ? pkg.version : "";
  const serverVersion = typeof serverJson?.version === "string" ? serverJson.version : "";
  const targetName = skillName || pkgName || declaredName || basename(root);
  if (serverJson && pkg) {
    if (serverVersion && pkgVersion && serverVersion !== pkgVersion) {
      findings.push({
        rule: "MISMATCH-VERSION", severity: "medium", file: "server.json", line: 0,
        evidence: `server.json version ${serverVersion} vs package.json version ${pkgVersion}`,
        detail: "Manifest and package disagree on the version; one of them is stale.",
      });
    }
    if (declaredName && pkgName) {
      const seg = declaredName.split("/").pop() as string;
      const pkgSeg = pkgName.split("/").pop() as string;
      if (seg !== pkgSeg && !declaredName.endsWith(pkgSeg)) {
        findings.push({
          rule: "MISMATCH-NAME", severity: "medium", file: "server.json", line: 0,
          evidence: `server.json name ${declaredName} vs package name ${pkgName}`,
          detail: "Registry name and package name point at different identities.",
        });
      }
    }
  }
  if (pkg && !pkgVersion) {
    findings.push({
      rule: "PIN-MISSING", severity: "medium", file: "package.json", line: 0,
      evidence: "package.json has no version field",
      detail: "No version to pin: an installer cannot tell the user exactly what they are getting.",
    });
  }
  if (pkgVersion === "latest" || pkgVersion === "*") {
    findings.push({
      rule: "PIN-MISSING", severity: "high", file: "package.json", line: 0,
      evidence: `version is "${pkgVersion}"`,
      detail: "Version is a moving tag, not a pin.",
    });
  }
  if (serverJson && Array.isArray(serverJson.packages)) {
    for (const p of serverJson.packages as Record<string, unknown>[]) {
      if (!p || typeof p !== "object") continue;
      const id = typeof p.identifier === "string" ? p.identifier : "";
      if (p.registryType === "npm" && !p.version) {
        findings.push({
          rule: "PIN-MISSING", severity: "medium", file: "server.json", line: 0,
          evidence: `npm package ${id} in server.json carries no version`,
          detail: "Registry entry installs whatever is latest at install time.",
        });
      }
      if (p.registryType === "oci" && /:(latest)?$/.test(id) && !/:\d/.test(id)) {
        findings.push({
          rule: "PIN-MISSING", severity: "medium", file: "server.json", line: 0,
          evidence: `OCI package ${id} carries no version tag`,
          detail: "Container reference is unpinned.",
        });
      }
    }
  }

  // Typosquat on every name the target claims.
  const nameCandidates: { name: string; file: string }[] = [];
  if (pkgName) nameCandidates.push({ name: pkgName, file: "package.json" });
  if (declaredName) nameCandidates.push({ name: declaredName, file: "server.json" });
  if (skillName) nameCandidates.push({ name: skillName, file: "SKILL.md" });
  const seenTypo = new Set<string>();
  for (const c of nameCandidates) {
    for (const form of [c.name, c.name.split("/").pop() as string]) {
      const typo = typosquatMatch(form);
      if (typo && !seenTypo.has(form)) {
        seenTypo.add(form);
        findings.push({
          rule: "TYPOSQUAT", severity: "high", file: c.file, line: 0,
          evidence: `"${form}" is edit distance ${typo.distance} from well-known "${typo.known}"`,
          detail: "Name imitates a well-known MCP server at a small edit distance: the typosquat shape used to catch install typos.",
        });
      }
    }
  }

  return finishReport({
    target: rootInput,
    kind,
    name: targetName,
    packageVersion: pkgVersion || serverVersion,
    findings,
    tools,
    declaredTools: [...declaredTools].sort(),
    resources: [...resources].sort(),
    prompts: [...prompts].sort(),
    declaredName,
    serverName: declaredName,
    capabilities,
    caps: { maxFiles: MAX_FILES, filesScanned: scanned, filesSkipped: skipped, truncated },
    notes,
  });
}

interface PartialReport {
  target: string;
  kind: VetReport["kind"];
  name: string;
  packageVersion: string;
  findings: Finding[];
  tools: ToolInfo[];
  declaredTools: string[];
  resources: string[];
  prompts: string[];
  declaredName: string;
  serverName: string;
  capabilities: CapabilityHit[];
  caps: VetReport["caps"];
  notes: string[];
}

function finishReport(p: PartialReport): VetReport {
  const dedup = new Map<string, Finding>();
  for (const f of p.findings) {
    const key = `${f.rule}|${f.severity}|${f.file}|${f.line}|${f.evidence}`;
    if (!dedup.has(key)) dedup.set(key, f);
  }
  const findings = [...dedup.values()].sort((a, b) =>
    SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) ||
    (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) ||
    a.line - b.line ||
    (a.rule < b.rule ? -1 : 1),
  );
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
  for (const f of findings) counts[f.severity]++;
  const verdict: VetReport["verdict"] =
    counts.critical > 0 ? "DO-NOT-INSTALL"
    : counts.high > 0 || counts.medium > 0 ? "REVIEW"
    : "VETTED";
  return {
    tool: "mcpvet",
    version: VERSION,
    target: p.target,
    kind: p.kind,
    name: p.name,
    packageVersion: p.packageVersion,
    verdict,
    counts,
    inventory: {
      declaredTools: p.declaredTools,
      tools: p.tools,
      resources: p.resources,
      prompts: p.prompts,
      declaredName: p.declaredName,
      serverName: p.serverName,
    },
    capabilities: p.capabilities,
    findings,
    caps: p.caps,
    notes: p.notes,
  };
}

/** Split "name@version" respecting scoped names. */
export function splitNameVersion(spec: string): { name: string; version: string | null } {
  const at = spec.lastIndexOf("@");
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) || null };
  return { name: spec, version: null };
}

/**
 * Vet an npm package by registry metadata only. The tarball is never
 * downloaded and no package code is ever executed; the checks run on the
 * published manifest (name, version, description, install scripts).
 */
export async function vetPackage(spec: string, fetchFn: FetchFn): Promise<VetReport> {
  const { name, version } = splitNameVersion(spec.trim());
  const findings: Finding[] = [];
  const notes: string[] = [
    "Package vetting uses npm registry metadata only: the tarball is not downloaded and no package code is executed. Capability and tool inventory checks need a local copy; run vet on the extracted directory for those.",
  ];
  const url = `https://registry.npmjs.org/${name.replace("/", "%2F")}`;
  const res = await fetchFn(url, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`npm registry lookup for "${name}" failed with HTTP ${res.status}`);
  }
  const meta = (await res.json()) as Record<string, unknown>;
  const distTags = (meta["dist-tags"] ?? {}) as Record<string, string>;
  const versions = (meta.versions ?? {}) as Record<string, Record<string, unknown>>;
  const wanted = version ?? distTags.latest ?? "";
  const manifest = versions[wanted];
  if (!manifest) {
    throw new Error(`npm registry has no version "${wanted}" for "${name}"`);
  }
  if (!version) {
    findings.push({
      rule: "PIN-MISSING", severity: "medium", file: "(registry)", line: 0,
      evidence: `no version requested; latest is ${wanted}`,
      detail: "Installing by bare name takes whatever is latest at install time.",
    });
  }
  if (version === "latest" || version === "*") {
    findings.push({
      rule: "PIN-MISSING", severity: "high", file: "(registry)", line: 0,
      evidence: `requested version is "${version}"`,
      detail: "Version spec is a moving tag, not a pin.",
    });
  }
  const typoForms = [name, name.split("/").pop() as string];
  const seenTypo = new Set<string>();
  for (const form of typoForms) {
    const typo = typosquatMatch(form);
    if (typo && !seenTypo.has(form)) {
      seenTypo.add(form);
      findings.push({
        rule: "TYPOSQUAT", severity: "high", file: "(registry)", line: 0,
        evidence: `"${form}" is edit distance ${typo.distance} from well-known "${typo.known}"`,
        detail: "Package name imitates a well-known MCP server at a small edit distance.",
      });
    }
  }
  if (manifest.scripts && typeof manifest.scripts === "object") {
    auditInstallScripts(findings, "(registry package.json)", manifest.scripts as Record<string, unknown>);
  }
  if (typeof manifest.description === "string") {
    for (const p of DESC_PATTERNS) {
      if (p.re.test(manifest.description)) {
        findings.push({
          rule: p.rule, severity: p.severity, file: "(registry)", line: 0,
          evidence: manifest.description.slice(0, 200), detail: p.detail,
        });
      }
    }
  }
  return finishReport({
    target: spec,
    kind: "package",
    name,
    packageVersion: wanted,
    findings,
    tools: [],
    declaredTools: [],
    resources: [],
    prompts: [],
    declaredName: "",
    serverName: "",
    capabilities: [],
    caps: { maxFiles: MAX_FILES, filesScanned: 0, filesSkipped: 0, truncated: false },
    notes,
  });
}

export function renderReport(r: VetReport): string {
  const out: string[] = [];
  out.push(`mcpvet ${r.version}: ${r.target}`);
  out.push(`kind: ${r.kind}  name: ${r.name || "(unknown)"}  version: ${r.packageVersion || "(none)"}`);
  out.push(`verdict: ${r.verdict}`);
  out.push(
    `findings: ${r.counts.total} (critical ${r.counts.critical}, high ${r.counts.high}, medium ${r.counts.medium}, low ${r.counts.low}, info ${r.counts.info})`,
  );
  out.push(
    `inventory: declared tools [${r.inventory.declaredTools.join(", ")}]; actual tools [${r.inventory.tools.map((t) => t.name).join(", ")}]; resources [${r.inventory.resources.join(", ")}]; prompts [${r.inventory.prompts.join(", ")}]`,
  );
  const capKinds = [...new Set(r.capabilities.map((c) => c.kind))].sort();
  out.push(`capabilities: ${capKinds.length ? capKinds.join(", ") : "none detected"}`);
  out.push(`files scanned: ${r.caps.filesScanned} (skipped ${r.caps.filesSkipped}, cap ${r.caps.maxFiles}${r.caps.truncated ? ", TRUNCATED at cap" : ""})`);
  for (const n of r.notes) out.push(`note: ${n}`);
  if (r.findings.length) {
    out.push("");
    out.push("findings:");
    for (const f of r.findings) {
      out.push(`- [${f.severity}] ${f.rule} ${f.file}${f.line ? `:${f.line}` : ""}: ${f.detail}`);
      out.push(`  evidence: ${f.evidence}`);
    }
  }
  return out.join("\n");
}
