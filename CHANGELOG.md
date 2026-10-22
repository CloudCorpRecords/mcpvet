# Changelog

## 0.1.0 (2026-10-22)

First release.

- Static vetting of local MCP server directories, SKILL.md skill directories, client config trees, and npm packages (registry metadata only, injectable fetch, tarball never downloaded, scanned code never executed).
- Declared vs actual tool inventory with resources and prompts; dangerous capability combination findings (filesystem plus network, env plus network, credential store plus egress, shell execution on the tool surface).
- Client config audit: autostart inventory, unpinned npx, curl pipe shell, shell wrappers, env harvesting, whole-environment passthrough.
- Install script audit with dropper grading; bundled script shapes for reverse shells, credential exfiltration, persistence, and droppers.
- Description and SKILL.md instruction and exfiltration language patterns (own copy, no runtime dependency on injectcheck).
- Declared vs actual mismatches, version pinning checks, and typosquat distance against a bundled well-known server list.
- Verdicts VETTED, REVIEW, DO-NOT-INSTALL with evidence per finding; deterministic report ordering.
- One bin: CLI (`mcpvet vet`, `mcpvet vet-package`, `mcpvet mcp`) plus a stdio MCP server with vet_path and vet_package tools. Flush-aware emit contract with spawned-CLI pipe regression tests from day one.
