// Copy runtime data assets into dist after tsc. Cross-platform on
// purpose (the factory builds on Windows too): no cp, no shell tricks.
import { copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
copyFileSync(join(root, "src", "fingerprints.json"), join(root, "dist", "fingerprints.json"));
console.log("copied src/fingerprints.json to dist/fingerprints.json");
