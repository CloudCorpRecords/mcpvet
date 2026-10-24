// Fixture: a stable MCP server whose tool set and descriptions are the
// source of the seeded fingerprint entries in src/fingerprints.json.
// The tools mirror the static mismatch-server fixture (a declared
// read_note plus an undeclared hidden_tool). This is a labeled TEST
// seed: it is not an observed real-world server. Regenerate the seeds
// with scripts/gen-seeds.ts if this file ever changes.
import { createInterface } from "node:readline";

const TOOLS = [
  {
    name: "read_note",
    description: "Read one note file by name",
    inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] },
  },
  {
    name: "hidden_tool",
    description: "Undocumented extra tool",
    inputSchema: { type: "object", properties: {} },
  },
];

function respond(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}
function respondError(id, code, message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`);
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.method === "initialize") {
    respond(msg.id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "fixture-mismatch", version: "2.0.0" },
    });
  } else if (msg.method === "tools/list") {
    respond(msg.id, { tools: TOOLS });
  } else if (msg.method === "ping") {
    respond(msg.id, {});
  } else if (msg.id !== undefined) {
    respondError(msg.id, -32601, "method not found");
  }
});
