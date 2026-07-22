---
name: skill-library
description: DAILY vs LIBRARY skill routing for the windows-inventory-lite project, produced by agent-sort. Points to the global ~/.claude/skills catalog instead of duplicating skill bodies.
---

# Skill Library — windows-inventory-lite

This project has no local skill copies. Every skill referenced below lives in the
global catalog at `C:\Users\101290\.claude\skills`. This file only records which
of those ~789 skills are worth loading every session for this specific repo
(DAILY) versus which stay reachable on demand through `ToolSearch`/`Skill`
(LIBRARY). See the full evidence table and reasoning in the agent-sort run that
produced this file.

## Stack this routing is based on

C# services on .NET Framework 3.5 (hand-rolled `TcpListener` HTTP server, no
ASP.NET, no NuGet), PowerShell 5.1-compatible install/deploy scripts, a vanilla
JS/HTML/CSS dashboard, Pester tests, GitHub Actions CI, WinRM-based remote
client deployment, and GPO packaging.

## DAILY

Load these every session in this repo:

- `security-review` — threat-model.md exists, WinRM credentials, Basic Auth,
  ingestion token, and a plaintext server-config.json are touched by most
  changes here.
- `api-design` — the server hand-rolls ~10 REST routes
  (`/api/v1/inventory`, `/api/v1/client-package/*`, ...) with no framework to
  lean on.
- `coding-standards` — mixed C#/PowerShell/JS codebase under the workspace's
  strict quality bar.
- `verification-loop` — CI builds the exe, runs `--version`, and runs Pester;
  changes should be verified the same way before considering them done.
- `stop-slop` — README.md/README_RU.md are actively maintained and the
  workspace CLAUDE.md makes this mandatory for docs.

## LIBRARY

Reachable via `ToolSearch`/`Skill` when a specific scenario comes up, not
loaded by default:

- **General engineering, off-stack or occasional**: `tdd-workflow`,
  `e2e-testing`, `documentation-lookup`, `deep-research`, `backend-patterns`,
  `dataviz`.
- **Frontend/JS frameworks** (dashboard is plain DOM, no framework):
  `frontend-patterns`, `frontend-slides`, `nextjs-turbopack`, `bun-runtime`,
  `mcp-server-patterns`.
- **Non-engineering domains** (no evidence in this repo):
  `mle-workflow`, `investor-materials`, `investor-outreach`, `content-engine`,
  `crosspost`, `article-writing`, `brand-voice`, `market-research`,
  `product-capability`, `x-api`, `fal-ai-media`, `video-editing`,
  `dmux-workflows`.
- **Security/DFIR/pentest catalog** (~700 skills; this repo builds a
  monitoring tool, it does not run incident response, forensics, or
  red-team engagements against itself): everything under
  `analyzing-*`, `detecting-*`, `hunting-*`, `performing-*`,
  `implementing-*`, `exploiting-*`, `conducting-*`, `auditing-*`,
  `building-*` in the cybersecurity set. Pull individually if a specific
  need comes up, e.g.:
  - Hardening the WinRM credential flow → `configuring-ldap-security-hardening`,
    `implementing-privileged-session-monitoring`.
  - TLS work if `--use-https` is ever implemented →
    `implementing-mtls-for-zero-trust-services`,
    `configuring-tls-1-3-for-secure-communications`.
  - Service-account misuse review → `detecting-service-account-abuse`.

## Notes

- No project-local `.claude/settings.json`, rules, or hooks exist for this
  repo, and none are needed — the offensive/defensive security skill set
  does not apply to building and maintaining this tool.
- Re-run agent-sort if the stack changes materially (e.g., a real ASP.NET
  migration, a JS framework added to the dashboard, or TLS gets implemented).
