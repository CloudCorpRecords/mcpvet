# Changelog

## 0.1.3 (2026-10-23)

Round 5 repair for three manifest and target handling gaps found by adversarial validation.

- Fixed: a package.json carrying a byte order mark prefix was treated as absent, so a postinstall curl pipe shell dropper verdicted VETTED with zero findings and a note claiming no package.json was found. JSON parsing now strips a leading byte order mark first, so a BOM-prefixed manifest is parsed and its install scripts are inventoried and graded like any other manifest. The same false absent treatment applied to any other unparseable manifest, such as one with a trailing comma.
- New rules MANIFEST-UNPARSEABLE and MANIFEST-UNREADABLE (both medium): a package.json or server.json that is present but unparseable, unreadable, oversize and skipped, or not a regular file now raises a finding naming the manifest and the reason, and the report note states that the manifest is present but could not be audited instead of claiming it was not found. The scan is partial in that state, so the verdict is floored at REVIEW and VETTED is unreachable until the manifest can be read.
- Fixed: vet on a non-directory target (a regular file, a FIFO, or /dev/null) returned VETTED at exit 0. It is now a usage error: the CLI reports that the target is not a directory on stderr and exits 2, matching the factory siblings, and a nonexistent target exits 2 as well.
- Fixed: a SKILL.md instruction to read a credential file (~/.aws/credentials, ~/.ssh/id_rsa) and send a summary onward verdicted VETTED with zero findings. Diagnosis: the file was scanned and the DESC-EXFIL pattern was present and identical in the published build and the source, but the pattern could never match a path shaped credential reference: its bounded spans forbade dot characters, and the credential paths it names are full of dots (~/.aws, ~/.ssh, .env, a collector URL), and its noun group opened with a word boundary that an alternative starting with ~ or . can never satisfy after a space or a slash. The spans now treat a dot followed by a non-space character as part of a path or host token and a dot followed by a space as the sentence boundary, and the noun group opens with a lookbehind. The fixture now flags DESC-EXFIL at high and verdicts REVIEW, with controls for a credential read with no send, a send with no credential read, and a cross-sentence shape.
- Fixed: a reverse shell composed from parts in an install-executed script (a socket connection, a spawned /bin/sh, and pipes joining them, with no /dev/tcp, nc -e, or dup2 text) graded REVIEW through SCRIPT-DROPPER alone. The composition now fires SCRIPT-REVERSE-SHELL at critical and verdicts DO-NOT-INSTALL, consistent with the literal reverse shell shapes and the critical download-and-execute shapes. A benign socket client with no shell pipe keeps its previous grade.
- Regression tests in test/round5.test.ts cover the BOM dropper, a BOM benign control, a download-only BOM control, the trailing comma floor, the oversize and unreadable and directory shaped skipped manifests, the non-directory exit codes, the credential read plus send instruction with its controls, and the socket plus shell pipe composition with its controls.

## 0.1.2 (2026-10-23)

Fix for a verdict-level false positive found by fresh-estate production validation (S4-1).

- Fixed: `vet` on a repo root that is not an MCP package returned DO-NOT-INSTALL driven by unrelated application code (an HTTP client's own credential/network code; a monorepo's CLI source and test files). The tool accepted the target, classified it `unknown` (or `mixed` at a monorepo root), and still issued its harshest verdict instead of declining to condemn a non-target.
- Scope floor: when the target has no MCP server, client config, or skill as its primary subject (kind `unknown`), or when a `mixed` monorepo root's critical findings all come from outside every identified MCP bundle, the verdict floors at REVIEW with an explicit "not an MCP target / scope to the server or skill directory" note. Findings are still reported as evidence; only the verdict is floored.
- Scoped vetting keeps its teeth: criticals inside an identified bundle still verdict DO-NOT-INSTALL (the ClawHavoc-shaped evil-skill fixture and a malicious skill nested in a mixed tree both still condemn).
- Regression tests: httpie-like plain-app fixture floors at REVIEW, mixed-monorepo fixture with out-of-bundle criticals floors at REVIEW, mixed-evil fixture still DO-NOT-INSTALL.

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
