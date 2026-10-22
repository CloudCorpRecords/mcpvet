/**
 * mcpvet MCP server. Tools: vet_path, vet_package.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { VERSION, vetPackage, vetPath } from "./vet.js";

const server = new McpServer({ name: "mcpvet", version: VERSION });

server.tool(
  "vet_path",
  "Vet a local MCP server directory, SKILL.md skill directory, or client config tree before install. Inventories declared and actual tools, flags dangerous capability combinations, audits autostart configs and bundled scripts, checks declared vs actual mismatches, version pinning, and typosquat distance. Static only: scanned code is never executed. Returns a VETTED, REVIEW, or DO-NOT-INSTALL verdict with evidence per finding.",
  {
    path: z.string().describe("Local directory to vet: an MCP server dir, a skill dir with SKILL.md, or a tree containing client MCP configs"),
  },
  async ({ path }) => {
    const report = vetPath(path);
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

server.tool(
  "vet_package",
  "Vet an npm package by name before install, using registry metadata only (the tarball is not downloaded and no code runs): typosquat distance against well-known MCP server names, install scripts, description language, and version pinning. Returns a VETTED, REVIEW, or DO-NOT-INSTALL verdict with evidence.",
  {
    name: z.string().describe("npm package name, optionally with @version, e.g. @modelcontextprotocol/server-filesystem@2025.3.28"),
  },
  async ({ name }) => {
    const report = await vetPackage(name, fetch as never);
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
