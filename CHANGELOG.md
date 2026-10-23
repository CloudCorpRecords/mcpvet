# Changelog

## 0.1.1 (2026-10-22)

Emergency repair for a genuine detection gap found by incident validation.

- Fixed: a skill whose SKILL.md declares a download-and-execute prerequisite step (a remote download piped into a shell) verdicted VETTED with zero findings on 0.1.0. The capability inventory recorded the line as a network capability, but no finding rule fired: the script-shape rules only run on script files, and the description language rules grade prose commands at medium and require a run or execute verb on the line.
- New rule DOC-DOWNLOAD-EXEC (critical): download-and-execute shapes declared as text anywhere in the package (SKILL.md, READMEs, other docs, bundled scripts) now raise a critical finding and escalate the verdict to DO-NOT-INSTALL, graded like the same shape in autostart configs (CONFIG-CURL-PIPE) and install scripts (INSTALL-DROPPER). Pipe and chained forms require a remote reference between the downloader and the execution step, so a download with no execution step, and alternation lists inside pattern literals, do not draw the finding.
- Regression tests cover the shape in SKILL.md, the same shape in a plain README, and a download-only control.

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
