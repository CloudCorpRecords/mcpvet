// Fixture: a server that accepts input and never answers.
// Used by the negative-control test: a timeout is NO SIGNAL at all.
import { createInterface } from "node:readline";

const rl = createInterface({ input: process.stdin });
rl.on("line", () => {
  // Deliberately silent: no response is ever written.
});
