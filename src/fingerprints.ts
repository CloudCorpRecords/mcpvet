/**
 * Exact-match server fingerprints, modeled on dyva's bogus-fingerprints
 * approach: a fingerprint is an exact hash, never a pattern, so a match
 * means the probed server presented byte-identical material to a server
 * (or fixture) already on record. Each match contributes its weight to
 * the risk score; a match alone never hard-fails a server.
 *
 * The data lives in fingerprints.json beside this module (copied into
 * dist at build time). Entries are seeded only from observed evidence;
 * see the provenance field on each entry.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ProbeObservation } from "./types.js";
import { hashText, hashToolSet } from "./signals.js";

export interface FingerprintEntry {
  id: string;
  label: string;
  /** Score contribution when this entry matches. */
  weight: number;
  /** When present, the presented server name must equal this exactly. */
  serverName?: string;
  /** When present, the presented server version must equal this exactly. */
  serverVersion?: string;
  /** sha256 of the server's whole tool set (see hashToolSet). */
  toolSetHash?: string;
  /** sha256 of one named tool's exact description text. */
  toolDescriptionHashes?: { tool: string; sha256: string }[];
  /** Where this entry came from. Required: no entry without evidence. */
  provenance: string;
}

export interface FingerprintFile {
  version: number;
  entries: FingerprintEntry[];
}

export interface FingerprintMatch {
  entry: FingerprintEntry;
  /** Human-readable list of what matched, for the signal record. */
  matchedAspects: string[];
}

let cached: FingerprintEntry[] | null = null;

function dataFilePath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const beside = join(here, "fingerprints.json");
  if (existsSync(beside)) return beside;
  // Running from dist without the build copy step: fall back to src.
  return join(here, "..", "src", "fingerprints.json");
}

/** Load the bundled fingerprint entries (parsed once, then cached). */
export function loadFingerprints(): FingerprintEntry[] {
  if (cached) return cached;
  const parsed = JSON.parse(readFileSync(dataFilePath(), "utf8")) as FingerprintFile;
  cached = parsed.entries;
  return cached;
}

/**
 * Match one live observation against fingerprint entries. Matching is
 * exact: a tool-set hash must equal the recorded hash, a description
 * hash must equal the recorded hash, and a named server identity must
 * equal the recorded identity. No fuzzy or partial credit.
 */
export function matchFingerprints(
  obs: ProbeObservation,
  entries: FingerprintEntry[],
): FingerprintMatch[] {
  const out: FingerprintMatch[] = [];
  const toolSetHash = hashToolSet(obs.tools);
  for (const entry of entries) {
    if (entry.serverName !== undefined && entry.serverName !== obs.serverName) continue;
    if (entry.serverVersion !== undefined && entry.serverVersion !== obs.serverVersion) continue;
    const aspects: string[] = [];
    if (entry.toolSetHash !== undefined && entry.toolSetHash === toolSetHash) {
      aspects.push(`tool set hash ${toolSetHash.slice(0, 12)}...`);
    }
    if (entry.toolDescriptionHashes) {
      for (const want of entry.toolDescriptionHashes) {
        const tool = obs.tools.find((t) => t.name === want.tool);
        if (tool && tool.description !== undefined && hashText(tool.description) === want.sha256) {
          aspects.push(`description hash of tool "${want.tool}"`);
        }
      }
    }
    if (aspects.length > 0) out.push({ entry, matchedAspects: aspects });
  }
  return out;
}
