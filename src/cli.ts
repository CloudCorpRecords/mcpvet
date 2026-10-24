#!/usr/bin/env node
/**
 * mcpvet CLI.
 *
 *   mcpvet vet [path] [--json]
 *   mcpvet vet-package <name[@version]> [--json]
 *   mcpvet probe [--timeout-ms <ms>] [--json] -- <command> [args...]
 *   mcpvet mcp
 *   mcpvet --version
 *
 * Exit codes: 0 VETTED, 1 REVIEW or DO-NOT-INSTALL, 2 usage or setup
 * error, 141 when the reader closed the output pipe early.
 *
 * Every report goes through emit(), which waits for stdout to flush
 * before the exit code takes effect: the factory emit contract in
 * FACTORY-NOTES.md. Calling process.exit() right after console.log()
 * truncates piped output past one pipe buffer (64 KiB on Linux) while
 * still exiting 0, which is how agents and CI silently lose reports.
 */
import { renderReport, VERSION, vetPackage, vetPath } from "./vet.js";
import { renderLiveReport, vetLive } from "./live.js";
import type { LiveReport, VetReport } from "./types.js";

function exitBrokenPipe(): never {
  process.exit(141);
}

process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") exitBrokenPipe();
  throw err;
});

/** Write one full report and resolve only after stdout has flushed it. */
async function emit(text: string, code: number): Promise<void> {
  process.exitCode = code;
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${text}\n`, (err) => {
      if (!err) {
        resolve();
        return;
      }
      if ((err as NodeJS.ErrnoException).code === "EPIPE") exitBrokenPipe();
      reject(err);
    });
  });
}

function usage(): never {
  console.error(`Usage:
  mcpvet vet [path] [--json]
  mcpvet vet-package <name[@version]> [--json]
  mcpvet probe [--timeout-ms <ms>] [--json] -- <command> [args...]
  mcpvet mcp
  mcpvet --version`);
  process.exit(2);
}

function exitCodeFor(r: VetReport): number {
  return r.verdict === "VETTED" ? 0 : 1;
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd) usage();
  const asJson = rest.includes("--json");
  const positional = rest.filter((a) => !a.startsWith("--"));
  try {
    if (cmd === "vet") {
      const report = vetPath(positional[0] ?? ".");
      await emit(asJson ? JSON.stringify(report, null, 2) : renderReport(report), exitCodeFor(report));
    } else if (cmd === "vet-package") {
      if (!positional[0]) usage();
      const report = await vetPackage(positional[0], fetch as never);
      await emit(asJson ? JSON.stringify(report, null, 2) : renderReport(report), exitCodeFor(report));
    } else if (cmd === "probe") {
      // Everything after -- is the server command line. The command is
      // EXECUTED (twice); that is the documented difference from vet.
      const sep = rest.indexOf("--");
      if (sep < 0) usage();
      const serverArgv = rest.slice(sep + 1);
      if (!serverArgv[0]) usage();
      const before = rest.slice(0, sep);
      let timeoutMs: number | undefined;
      const tIdx = before.indexOf("--timeout-ms");
      if (tIdx >= 0) {
        timeoutMs = Number(before[tIdx + 1]);
        if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) usage();
      }
      const report: LiveReport = await vetLive(
        { command: serverArgv[0], args: serverArgv.slice(1) },
        { timeoutMs },
      );
      await emit(
        asJson ? JSON.stringify(report, null, 2) : renderLiveReport(report),
        report.verdict === "VETTED" ? 0 : 1,
      );
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  }
}

void main();
