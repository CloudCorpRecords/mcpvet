# mcpvet

Vet MCP servers and agent skills before you install them.

In early 2026 the ClawHavoc wave put 1,184 malicious skills on a public skill marketplace from just 12 accounts: credential stealers and reverse shells dressed up as helpful agent skills, inheriting whatever permissions the agent itself had. Only a small minority of organizations audit the MCP servers they install, and almost none audit skill packs. The install click is the trust decision, and it usually happens with no evidence at all.

mcpvet is the pre-install check. Point it at a local MCP server directory, a SKILL.md skill directory, a client config tree, or an npm package name, and it returns a deterministic verdict with evidence for every finding: VETTED, REVIEW, or DO-NOT-INSTALL. The scan is static only. Scanned code is read as text and never executed, imported, or installed.

## Install

```
npx -y @reneturcios/mcpvet --version
npm install -g @reneturcios/mcpvet
docker run -i --rm ghcr.io/cloudcorprecords/mcpvet mcp
```

## Quick start

```
mcpvet vet ~/src/some-mcp-server
mcpvet vet ~/skills/some-skill --json
mcpvet vet-package @modelcontextprotocol/server-filesystem@2025.3.28
mcpvet mcp
```

CLI exit codes: 0 when the verdict is VETTED, 1 for REVIEW or DO-NOT-INSTALL, 2 for a usage or setup error, 141 when the reader closed the output pipe before the report was delivered.

## What it checks

| Check | What it catches |
| --- | --- |
| Tool inventory | Declared tools (server.json, package.json, tool manifests) against tools actually registered in source, plus resources and prompts |
| Capability combos | Filesystem read plus network egress, env access plus egress, credential store access plus egress, shell execution reachable from the tool surface |
| Config audit | Client configs (claude_desktop_config.json, .mcp.json, Cursor and VS Code mcp.json): autostart entries, npx -y on unpinned packages, curl pipe shell launchers, shell wrappers, wide env blocks sweeping in credential-shaped keys, whole-environment passthrough |
| Install scripts | preinstall, install, postinstall, and prepare scripts in package.json, with dropper shapes (remote download piped to a shell) graded critical |
| Manifest honesty | A package.json or server.json that is present but unparseable, unreadable, oversize and skipped, or not a regular file is reported as present but not audited, with a MANIFEST-UNPARSEABLE or MANIFEST-UNREADABLE finding, never as absent. A byte order mark prefix is stripped before parsing, so a BOM-prefixed manifest is audited normally |
| Bundled scripts | Reverse shell shapes (including a reverse shell composed from a socket connection, a spawned shell, and pipes joining them), one file that both reads a credential store and makes network requests, persistence touches (session hooks, scheduled tasks, autostart entries), download-and-execute droppers |
| Description language | Tool descriptions, package descriptions, and SKILL.md text carrying instruction or exfiltration language: override prior instructions, hide actions from the user, send credential material onward, run shell commands from prose |
| Documentation download-and-execute | A download-and-execute step declared as text anywhere in the package (SKILL.md prerequisites, READMEs, other docs, bundled scripts): a remote download piped or substituted into a shell or interpreter, or downloaded and run on the same line. Graded critical, like the same shape in autostart configs and install scripts. A download with no execution step does not draw this finding |
| Native binaries | Compiled native artifacts shipped in the package (.node, .dll, .so, .dylib files, or a prebuilds directory). Native code cannot be audited by static text scanning, so its presence is graded medium with a NATIVE-BINARY finding and the verdict floors at REVIEW: presence is not evidence of malice (many legitimate packages ship prebuilt addons), and it never escalates to DO-NOT-INSTALL on its own, but the binary should be reviewed, or the package built from source, before the server is trusted. The MALFEX imgdecode campaign hid its payload in exactly this shape: a native addon under prebuilds/ loaded at require time, with no install scripts at all |
| Mismatches | Declared tools missing from code, undeclared tools present in code, server.json and package.json disagreeing on name or version |
| Pinning | Missing version fields, moving tags such as latest or *, registry entries with no version, unpinned container references |
| Typosquat | Target and package names at edit distance 1 (or 2 for long names) from a bundled list of well-known MCP server names |

## Verdict rules

- DO-NOT-INSTALL: at least one critical finding. Reverse shells, credential stealers, install droppers, curl pipe shell autostarts, and download-and-execute steps declared in skill documentation land here.
- REVIEW: at least one high or medium finding and no criticals. Dangerous capability combos, undeclared tools, typosquats, env harvesting configs, and unpinned autostarts land here. A partial scan also lands here at minimum: when a manifest is present but could not be parsed or read, the scan did not see the whole target, so VETTED is unreachable in that state.
- VETTED: no critical, high, or medium findings. Info and low findings (such as the autostart inventory itself) are still reported as evidence.

A verdict is a scan result, never a safety claim. VETTED means these checks found nothing at or above medium severity in the files scanned; it does not certify a server safe.

Scope floor (v0.1.2): DO-NOT-INSTALL is a claim about an installable MCP bundle. If the target is not an MCP target (kind `unknown`, meaning no server, config, or skill as its primary subject, or a `mixed` monorepo root whose critical findings all come from outside every identified MCP bundle), the verdict floors at REVIEW with an explicit "not an MCP target" note telling you to scope vetting to the server or skill directory. Findings are still reported as evidence; a critical inside an identified bundle still verdicts DO-NOT-INSTALL.

## MCP

`mcpvet mcp` serves a stdio MCP server with two tools:

| Tool | What it does |
| --- | --- |
| vet_path | Vet a local MCP server directory, skill directory, or client config tree before install |
| vet_package | Vet an npm package by name using registry metadata only: the tarball is not downloaded and no code runs |

## Scope and limits

- Static analysis only, by design. mcpvet never executes, imports, or installs the target, and vet_package never downloads the tarball. Behavior that only appears at runtime is out of scope; vet the extracted directory for capability and inventory checks.
- Tool inventory is pattern-based: tools registered through shapes the scanner does not recognize (dynamic registration, generated code) can be missed, which is why a declared manifest with no matching registrations is itself a finding.
- The walk caps at 2,000 files and 512 KiB per file. Anything skipped is counted and reported in the report's caps block, never silently dropped. When the skipped file is package.json or server.json, the verdict is also floored at REVIEW, because the manifest itself went unaudited.
- The vet target must be a directory. A regular file, a FIFO, a device, or a nonexistent path is a usage error and exits 2, never a verdict.
- Compiled native code is opaque to this scanner by construction. A tree shipping native artifacts (.node, .dll, .so, .dylib, or a prebuilds directory) draws a NATIVE-BINARY finding at medium and verdicts at least REVIEW; the finding reports presence only and claims nothing about what the binary does.
- The typosquat list is a bundled snapshot of well-known MCP server names, not the live registry.
- Pattern literals are indistinguishable from payloads in a static text scan: the source of a security scanner (or a test fixture corpus) contains the very shapes it detects, so vetting detector tooling flags its own pattern strings (observed on the Security Wave factory repos themselves, where every such critical was hand-verified as a pattern literal or a planted fixture). Treat verdicts on scanner source as REVIEW-grade evidence, not as a compromise claim.

Part of the Security Wave: hookcheck (persistence hooks), actionpin (Actions pinning), injectcheck (prompt injection in agent-read content), tracewatch (observability and root cause), mcpvet (pre-install vetting).

MIT.
