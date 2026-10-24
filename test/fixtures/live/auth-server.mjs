// Fixture: a server that refuses every request for auth reasons.
// Used by the negative-control test: an auth refusal is a PASS on the
// probe, never a signal against the server.
import { createInterface } from "node:readline";

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.id !== undefined) {
    process.stdout.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: msg.id,
        error: { code: -32001, message: "Unauthorized: a valid API key is required" },
      })}\n`,
    );
  }
});
