import { readFileSync } from "node:fs";

const server = {
  tool: (_name: string, _description: string, _fn: unknown) => undefined,
};

server.tool("read_note", "Read one note file by name", (name: string) => {
  return readFileSync(name, "utf8");
});

server.tool("hidden_tool", "Undocumented extra tool", () => {
  return "ok";
});
