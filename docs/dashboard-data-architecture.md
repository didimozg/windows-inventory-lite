# Dashboard Data Architecture Inventory

Reference snapshot of the current dashboard (as of server/dashboard 0.85.1), written to support the next navigation-redesign discussion. Covers every section: what data it shows, where that data actually comes from server-side, its real platform scope, and where it currently sits in the nav. Facts only — no redesign recommendations here; see the "Implications" section at the end for what these facts mean for the specific redesign options under discussion.

All file:line citations are against `server/dashboard/index.html`, `server/dashboard/app.js`, and `src/server/WindowsInventoryLiteServer.cs` (repo root `PowerShell/monitoring/windows-inventory-lite`).

## Current top-level nav (as of 0.85.1)

```
Dashboard
Fleet ▾          Clients, Software (Windows), Services (Linux), Hardware, Actions, Agent updates
Push & Schedule  (standalone top-level button)
Software ▾       Windows updates, Third-party software, History
Licenses
Settings         Server, Security, Credentials, Windows, Linux
Logging ▾        Ingestion, Installs, Debug
```

---

## 1. Dashboard tiles (`dashboardView`)

No dedicated endpoint — tiles are computed client-side from data already fetched for other views (`GET /api/v1/clients`, `GET /api/v1/linux/clients`, `GET /api/v1/licenses`). Render: `renderDashboardTiles()` (app.js:5365-5402).

| Tile | Platform scope |
|---|---|
| Client count, Stale count, USB storage count, OS/CPU/RAM/Storage charts | Merged Windows+Linux |
| Windows activated / Office activated | Windows-only (no Linux activation concept exists) |
| WU disabled count | Field is Windows-only; iterates merged list but Linux reports never carry the field |
| License count | Windows-only concept |

## 2. Fleet dropdown

### 2a. Clients (`clientsView`, `clientsTab`)

Merged Windows+Linux table, one row per machine, platform resolved client-side (`stampClientPlatform()`, app.js:5141) and stamped onto each report rather than inferred from its body (security rationale). Columns: Computer, Client version, OS, Office, Activation, Software/Services count, Description, Collected, Actions.

- Data: `GET /api/v1/clients` → `BuildClientIndex()` (server.cs:9284) + `GET /api/v1/linux/clients` → `BuildLinuxClientIndex()` (server.cs:5536).
- Office/Activation columns, bulk Delete, and license-key reveal: Windows-only, render `—` on Linux rows.
- Stale badge, USB badge, CPU/RAM/Storage: platform-agnostic shared fields.

### 2b. Hardware (`hardwareView`, `hardwareTab`)

Explicitly merged (code comment app.js:6072: "Replaces the former renderHardwarePage/renderLinuxHardwarePage pair"). Three stacked group-by tables: CPUs, Storage, RAM — grouped from the same two client-index endpoints as 2a, no dedicated hardware endpoint.

### 2c. Software (Windows) (`softwareView`, `softwareTab`)

**Windows-only.** Installed-software inventory, grouped from `client.software[]` on `GET /api/v1/clients` reports. No Linux equivalent anywhere in the app — Linux's nearest concept is 2d (systemd services), a structurally different kind of data (running services, not installed packages).

### 2d. Services (Linux) (`linuxServicesView`, `linuxServicesTab`)

**Linux-only.** systemd services list, grouped from `client.services[]` on `GET /api/v1/linux/clients` reports (name+version key, no publisher field — `ServiceInfo` has none). No Windows equivalent (no "running Windows services" inventory exists in this app).

### 2e. Actions (`installView`, `actionsTab`, aria-label "Remote client actions")

One single merged Windows+Linux form (not stacked/tabbed) — one Targets box, one Action dropdown routes internally to WinRM or SSH depending on the Detection-mode selector.

**The only two actions that exist are "Install client" and "Uninstall client"** (the inventory-client agent itself) — confirmed by grep: there is no restart action, no run-arbitrary-script action anywhere in the UI, server handler, or client. "Client actions" is a narrower concept than its name suggests.

- Data: `POST /api/v1/client-install` / `POST /api/v1/client-uninstall` → `StartClientAction()` (server.cs:5562) → creates an `InstallJob` (server.cs:9986), dispatched async, persisted as one JSON file per job under `_client-install-jobs/{id}.json`.

### 2f. Agent updates (`packageView`, `agentUpdatesTab`)

Two separate stacked blocks (Windows package / Linux package) — **not** the self-update toggle, **not** a push action. This page configures/regenerates the *initial deployment package* (GPO startup script + embedded config for Windows; an SSH-less install bundle for Linux) and shows build-artifact presence/version on the server.

**There are three independent "get the client to a new version" mechanisms in this project**, easy to conflate:
1. This page — package regeneration/download for *fresh installs*.
2. The "Enable client self-update" toggle, which actually lives under **Settings > Windows** / **Settings > Linux**, not here — it gates whether an already-installed, out-of-date client self-applies an update on its own next report.
3. The admin-driven WinRM/SSH push under Push & Schedule (section 3 below) — which reuses the *same* `InstallJob` machinery as 2e's Actions.

---

## 3. Push & Schedule (`updatesView`, standalone top-level button `softwarePushTab`)

Five stacked configuration blocks (not four — the HTML has one more than its name implies): WinRM credentials, SSH credentials, Windows schedule, Linux schedule, Linux client targeting (preferred subnet). Below them: one single merged Windows+Linux outdated-clients table with an "Update selected" button.

**Key fact: "Update selected" does not call a dedicated update endpoint.** It calls the exact same `POST /api/v1/client-install` as Fleet > Actions (`StartClientAction(..., "install")`, with `mode: force-windows`/`force-linux`), reusing the same `InstallJob` model, the same job-polling function (`pollInstallJob`), and feeding the same job-history view (Logging > Installs). Scheduled (timer-triggered) pushes go through the same path server-side (`StartScheduledClientUpdatePush`, server.cs:2030), no HTTP round-trip needed.

So **Fleet > Actions and Push & Schedule's push button are, underneath, the same action-dispatch mechanism** (System B below) — they differ only in how targets/mode get decided (manual form vs. pre-filtered outdated-client selection + schedule), not in what happens once dispatched.

## 4. Software dropdown

### 4a. Windows updates catalog (`windowsUpdatesMissingView` + `windowsUpdatesView`, 2 sub-tabs: Missing updates / Catalog)

**Windows-only.** A catalog entry: name, share file path, arguments, target mode (`static` host list, or `missingKb` — dynamically targets whoever's latest WSUS scan reports that KB missing), requires-reboot flag, enabled flag.

Missing-KB detection is a *separate* mechanism from the catalog: the server hosts Microsoft's offline scan file (`wsusscn2.cab`), each client downloads it, scans itself locally, and POSTs results — this writes directly onto that computer's own stored report (`wsusMissingUpdates` field), not into any catalog table. A `missingKb`-mode catalog entry's *targeting* is resolved against this scan data only at per-poll job-computation time — nothing about "who needs this KB" is persisted anywhere.

### 4b. Third-party software catalog (`thirdPartySoftwareView`)

**Windows-only.** Uses the **exact same generic storage handler** as the Windows-updates catalog (`CreateSoftwareCatalogEntry`/`UpdateSoftwareCatalogEntry`, same `SoftwareCatalogSpec` shape, same `missingKb`/`static` target-mode fields under the hood) — the UI form simply never exposes `targetMode`/`kbId` for this catalog type, but the data model doesn't distinguish them. Different subfolder on disk ("third-party-software" vs "windows-updates"), that's the only structural difference.

### 4c. History (now under Software > History, 2 sub-tabs: Installs / WSUS Downloads)

**Installs** (`softwareJobHistoryView`) — one row per install *attempt* (not per job — see System A/B split below): computer, catalogType, entry, status/exitCode, errorMessage, exitCodeMeaning (computed fresh on every read, never stored), diagnosticHint, eventLogEntries. Server model `SoftwareJobAttempt` (server.cs:9781), identified by a **client-generated** `AttemptId` GUID. Persisted append-only to a JSONL file; a "running" row and its later "success"/"failed" row are merged into one displayed line **purely client-side** (`mergeSoftwareJobAttempts`, app.js:4949) — the server storage itself stays two separate, unmodified rows forever.

**WSUS Downloads** (`wsusDownloadLogView`) — one row per cab/KB download attempt: time, source, item, result, details. Server model `WsusDownloadLogEntry` (server.cs:11090) — **has no identity/job-id field at all**. It's a flat log row the server writes synchronously as it performs the download itself; there's no "running" state to poll and no client involved. Persisted as a single JSON-array file, fully rewritten on every prune (unlike every other log in this app, which is JSONL/append-only).

---

## 5. Licenses (3 sub-tabs: Catalog / Sources / Keys)

All three are either admin-curated or Windows-only — none are derived from Linux reports:

- **Catalog** — platform-agnostic/manual. An admin-curated list (Name, Version, License, Comment, free-typed Computer names with no validation against either platform's real inventory).
- **Sources** — **Windows-only by construction**: a "source" is literally a Windows Registry hive/path/value definition. No Linux equivalent is possible without a different detection mechanism entirely.
- **Keys** — **Windows-only**: built from `state.clients` (never `getAllClients()`), reveal endpoint reads only from the Windows report store. Linux client reports carry no `licenses` field anywhere in the codebase.

## 6. Settings (5 tabs — unchanged by the nav redesign, documented in full in `docs/superpowers/specs/2026-10-05-settings-page-redesign-design.md`)

- **Server**: Inventory, Network, HTTPS, Outbound proxy, Ingestion Token, Log retention, Diagnostics, Connection status.
- **Security**: Admin password + Login lockout (reordered to the top per latest fix), Certificate (now second).
- **Credentials**: Windows Client update credentials (WinRM), Software repository, WSUS offline scan file, Linux Client update credentials (SSH), SSH key — these are the *global default* credentials; Push & Schedule's own WinRM/SSH blocks (section 3) and Fleet > Actions' "Global" option both reference these same saved accounts, rather than duplicating them.
- **Windows**: Active Directory, Install defaults (check intervals), Windows updates install window, Third-party software install window, Client self-update toggle.
- **Linux**: Linux client targeting, Install defaults, Client self-update toggle.

## 7. Logging dropdown (3 sub-tabs: Ingestion / Installs / Debug)

- **Ingestion** (`loggingView`) — rejected inventory-report requests (bad/missing token). Hostname and matched-client columns are computed fresh at serve time (best-effort heuristic), never stored.
- **Installs** (`installHistoryView`) — one row per client-action/push *job* (not attempt — see System B below). This is where **both** Fleet > Actions' and Push & Schedule's job history actually lives, even though those two entry points now sit in completely different places in the nav. Server model `InstallJob`, one JSON file per job under `_client-install-jobs/`, identified by a **server-generated** GUID.
- **Debug** (`debugLogView`) — plain-text server debug log, off by default, dual age+size cap. Separate file format from every other log in this app (plain text, not JSON/JSONL).

---

## Cross-cutting finding: there is no unified "Job" or "Task" model

Verified directly in the C# source (grep for `interface IJob`, `abstract class *Job`, `enum JobStatus`, or any shared base type — zero matches). The project has **two structurally independent systems** that happen to look similar in the UI:

### System A — catalog-driven software distribution (Windows updates, Third-party software)

- **Catalog** = the only persisted artifact. Describes *what can be installed* (`SoftwareCatalogSpec` shape).
- **Job** = never persisted. Computed fresh on every client poll by re-running the targeting logic against the live catalog. No job id, no status row exists server-side — a "job" exists only transiently inside one HTTP response.
- **Result/history** = `SoftwareJobAttempt`, client-generated `AttemptId`, appended to a fleet-wide JSONL log. Surfaced at Software > History > Installs.

### System B — direct client-install jobs (Fleet > Actions, Push & Schedule's push button and its scheduler)

- **No catalog concept** — targets/action/credentials are specified directly at dispatch time.
- **Job** = a real, persisted `InstallJob` object with a server-generated GUID, a status machine (queued/running/completed), and a Results array. One JSON file per job on disk. Individually pollable (`GET /api/v1/client-install/{id}`).
- **Result/history** = the same `InstallJob.Results`, surfaced at Logging > Installs.

**These two systems share zero code, zero data shape, and zero ID scheme.** The only place they touch is that a `missingKb`-mode catalog entry (System A) resolves its targeting against WSUS scan data written onto each client's own report — that's a one-way read, not a shared mechanism.

Three confusingly-similar-sounding tables are currently split across two different top-level nav locations for no structural reason — they're just as disconnected from each other as System A and B are:

| Table | Backing system | Current nav location |
|---|---|---|
| Software > History > Installs | System A (`SoftwareJobAttempt`, JSONL) | Software dropdown |
| Software > History > WSUS Downloads | Neither — no job/attempt id at all | Software dropdown |
| Logging > Installs | System B (`InstallJob`, one-file-per-job) | Logging (standalone button) |

---

## Implications for the redesign options under discussion

(Facts only, restated as direct answers to the two open questions — not a recommendation on which to pick.)

**"Inventory > Software (Win+Linux via platform filter)"** — already resolved in the last discussion: keep Software (Windows-only, installed-program inventory) and Services (Linux-only, systemd-service inventory) as separate destinations. They are genuinely different kinds of data (installed packages vs. running services), not two platform-halves of one table — merging them behind a filter would require inventing a new "service inventory" concept for Windows or a new "package inventory" concept for Linux, neither of which the client currently collects.

**"Operations > Tasks & Scripts" (Fleet > Actions + Push & Schedule) and "Logs > Task History" (Software History + Logging > Installs)** — two different weights of change are possible, and the real effort gap between them is now concrete:

- *Light (UI regrouping only)*: put Actions and Push & Schedule under one nav destination with sub-tabs, same for a combined History destination — this is exactly the pattern already used for Software > History's own two sub-tabs today. No server change. This is honest about the fact that System A and System B remain separate underneath; the UI would just stop hiding that two different job mechanisms happen to live next to each other.
- *Heavy (real unified "Task" model)*: would mean either (a) building a genuine shared abstraction that both `InstallJob` and `SoftwareJobAttempt` map onto (new server-side type, migration of two different storage formats — one-file-per-job JSON vs. append-only JSONL — onto one scheme, reconciling a server-generated vs. client-generated ID convention), or (b) a UI-only merge layer that reads both existing endpoints and fuses them into one displayed table without changing storage — cheaper than (a) but still real work (reconciling two different field sets — `InstallJob.Results[]` entries vs. `SoftwareJobAttempt` rows — into one row shape, handling that WSUS Downloads has no id/job concept at all to merge against).

Note one asymmetry worth deciding on explicitly either way: Push & Schedule's push button *already* dispatches through System B (the same `InstallJob` as Fleet > Actions), but its own *history* is split — the push's own job results land in Logging > Installs (System B), while any *software installs that resulted from it* land in Software > History > Installs (System A, via the client's separate job-result report once it actually runs the install). A user watching "what did Push & Schedule just do" today has to check two different history tables to get the full picture.
