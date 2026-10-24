// Fixture: a minimal honest MCP server over stdio (raw JSON-RPC, no deps).
// Always presents the same identity and tool list. Used by live tests.
import { createInterface } from "node:readline";

const TOOLS = [
  {
    name: "ping_tool",
    description: "Ping the fixture server",
    inputSchema: { type: "object", properties: { echo: { type: "string" } } },
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
      serverInfo: { name: "fixture-honest", version: "1.0.0" },
    });
  } else if (msg.method === "tools/list") {
    respond(msg.id, { tools: TOOLS });
  } else if (msg.method === "ping") {
    respond(msg.id, {});
  } else if (msg.id !== undefined) {
    respondError(msg.id, -32601, "method not found");
  }
});
