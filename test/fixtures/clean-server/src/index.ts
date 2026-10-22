import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const NOTES_DIR = join(process.cwd(), "notes");
const server = {
  tool: (_name: string, _description: string, _fn: unknown) => undefined,
};

server.tool("list_notes", "List the note files in the local notes folder", () => {
  return readdirSync(NOTES_DIR);
});

server.tool("read_note", "Read one note file from the local notes folder by name", (name: string) => {
  return readFileSync(join(NOTES_DIR, name), "utf8");
});
