/**
 * Regenerate src/fingerprints.json by probing the fingerprinted test
 * fixture and hashing what it actually presents. This is the
 * reconstitution path for the seed entries (the same discipline as
 * dyva's "re-run the scorer to regenerate the fingerprint set"): the
 * hashes in the data file are never typed by hand, they are derived
 * from the fixture server's live answers.
 *
 * Run: npx tsx scripts/gen-seeds.ts
 *
 * The incident-validation fixtures under
 * ~/workspace/security-wave/incident-validation contain no MCP server
 * tool schemas (verified 2026-10-24: no inputSchema, no tools arrays,
 * no server code), so the seeds come from this repo's own fixtures and
 * are labeled as test seeds in their provenance.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { probeServer } from "../src/probe.js";
import { hashText, hashToolSet } from "../src/signals.js";
import type { FingerprintEntry, FingerprintFile } from "../src/fingerprints.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(repoRoot, "test", "fixtures", "live", "fingerprinted-server.mjs");

const outcome = await probeServer({ command: process.execPath, args: [fixture] }, 15000);
if (outcome.status !== "ok" || !outcome.observation) {
  throw new Error(`fingerprinted fixture probe failed: ${outcome.status} ${outcome.error ?? ""}`);
}
const obs = outcome.observation;
const hidden = obs.tools.find((t) => t.name === "hidden_tool");
if (!hidden || hidden.description === undefined) {
  throw new Error("fingerprinted fixture did not present hidden_tool with a description");
}

const provenance =
  "Seeded 2026-10-24 by scripts/gen-seeds.ts from a live probe of test/fixtures/live/fingerprinted-server.mjs, whose tools mirror the static mismatch-server test fixture (declared read_note plus undeclared hidden_tool). TEST SEED ONLY: this is not an observed real-world server.";

const entries: FingerprintEntry[] = [
  {
    id: "fixture-mismatch-toolset",
    label: "Tool set of the mismatch fixture server (declared read_note plus undeclared hidden_tool)",
    weight: 20,
    serverName: obs.serverName,
    serverVersion: obs.serverVersion,
    toolSetHash: hashToolSet(obs.tools),
    provenance,
  },
  {
    id: "fixture-hidden-tool-description",
    label: "Exact description text of the undeclared hidden_tool in the mismatch fixture",
    weight: 10,
    toolDescriptionHashes: [{ tool: "hidden_tool", sha256: hashText(hidden.description) }],
    provenance,
  },
];

const file: FingerprintFile = { version: 1, entries };
const out = join(repoRoot, "src", "fingerprints.json");
writeFileSync(out, `${JSON.stringify(file, null, 2)}\n`);
console.log(`wrote ${out} with ${entries.length} entries from ${obs.serverName} ${obs.serverVersion}`);
