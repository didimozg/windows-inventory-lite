# API Reference

This is a practical lookup document for the server's HTTP API, not an OpenAPI/Swagger spec. It covers the real, current route surface: 89 routes (73 exact-match paths, 16 with a parameterized path segment) - up by one in 1.0.2 for `GET /api/v1/client/software-download` (see its own entry below and `docs/threat-model.md`) - up by five in 0.95.0 for client enrollment (`POST /api/v1/client/enroll`, `GET`/`POST /api/v1/server/enrollment-token[/regenerate]`, `GET /api/v1/client-tokens`, `DELETE /api/v1/client-tokens/{computerName}` - see "Client enrollment" below and `docs/threat-model.md`) - down from 53 as of v0.42.0, which removed the four separate Linux install/uninstall job routes (`/api/v1/linux-client-install`, `/linux-client-uninstall`, and their GET list/detail equivalents) in favor of the unified `/api/v1/client-install`/`/client-uninstall` pair, up again with the two session endpoints, up again with the five license-key routes (the four-route `/api/v1/license-key-sources` catalog plus the `/api/v1/clients/{computerName}/license-keys` reveal endpoint), up again with v0.56.0's sixteen software-distribution routes documented below, up again with v0.66.0's four `DELETE`-verb "clear now" routes (one per Logging subtab, each sharing its path with an already-documented `GET` route), up by two more with the self-update download endpoints below (`/api/v1/client-package/update-download`, `/api/v1/linux-client-package/update-download`) - both existed in the server since v0.61.0 but were never added to this document, a gap found and closed during a 2026-09-16 full-project review - and up by three more in v0.81.0: the `GET /api/v1/client/software-jobs` poll was split into `GET /api/v1/client/windows-update-jobs`/`GET /api/v1/client/third-party-software-jobs` (net +1), and the earlier combined "check now" trigger was replaced by `POST /api/v1/clients/install-windows-updates-now`/`POST /api/v1/clients/install-third-party-software-now` (net +2, since the combined predecessor was never added to this document either). Recounted directly against the routing chain for this pass. It does not cover the static dashboard asset routes (`/`, `/app.js`, `/styles.css`, `/favicon.svg`, `/brand-mark.png`), which serve dashboard files rather than API data - note that these are not actually unauthenticated either; see "Session cookie" below for how a first-time visitor still reaches a login page despite that. Some other admin-triggered action routes under `/api/v1/windows-updates/` (`cab-status`, `missing-summary`, `download-schedule`, `download-log`, `cab-download-now`, `rescan-now`, and the per-KB `{id}/download-now`) are also missing from the tables below - a pre-existing gap, not introduced by this pass; flagged here rather than fixed, since closing it is unrelated to the windowsUpdate/thirdPartySoftware split this revision covers.

## Conventions

**Auth models.** Two separate models are in use, and a route uses exactly one of them:

- **Basic Auth** guards the dashboard/management surface: every route below except the eight ingestion-token endpoints (listed under "Ingestion token" below) and `POST /api/v1/server/login` (which checks credentials itself, before either the session-cookie or Basic Auth check would otherwise apply - see that endpoint below). It is checked once, centrally, by `IsWebRequestAuthorized` before the request reaches any handler. A missing or wrong `Authorization: Basic ...` header gets a `401` with body `Unauthorized` (plain text, not JSON) - deliberately without a `WWW-Authenticate: Basic` header, since that header is what makes a browser pop its native credential dialog and cache whatever is typed into it at the HTTP stack level, with no way to evict it later short of closing the browser (see "Session cookie" below for the supported alternative). If no admin username/password has been configured yet, this check instead falls back to restricting the route to the local machine (loopback) only. This gate also covers the static dashboard asset routes (`/`, `/index.html`, `/app.js`, `/styles.css`, `/favicon.svg`, `/brand-mark.png`) - they are not a separate, unauthenticated carve-out. A real browser's `GET` navigation to `/` or `/index.html` (an `Accept` header containing `text/html`) that fails this check gets an embedded login page instead of the plain-text `401` body, since there would otherwise be nothing for a human to see; every other unauthenticated case (any API route, any non-GET method, `app.js`'s own `fetch()` calls, which don't send an HTML-navigation `Accept` header) keeps the plain `401` body.
- **Session cookie.** A `wil_session` cookie is checked by `IsWebRequestAuthorized` before Basic Auth, on every route the bullet above covers - a valid session authorizes the request with no `Authorization` header at all. It is an alternative to Basic Auth, not an additional requirement on top of it: either one alone is sufficient. `POST /api/v1/server/login` establishes a session and returns the cookie; `POST /api/v1/server/logout` invalidates it. See those two endpoints below for the full behavior.
- **Ingestion token** guards the client-facing endpoints, via the `X-Inventory-Token` request header, checked inside each handler before Basic Auth would otherwise apply (these routes are dispatched before the Basic Auth check runs at all). A rejected token gets a `401` with plain-text body `Unauthorized`, not the JSON error shape below. Two groups, with different enforcement rules:
  - The three inventory-ingestion endpoints (`POST /api/v1/inventory`, `POST /api/v1/linux/inventory`, `POST /api/v1/linux/inventory/service-status`) honor the `RequireIngestionToken` server setting; when it is off, they accept any request unauthenticated.
  - The other six client-facing endpoints ignore `RequireIngestionToken` and always require a real, matching token, failing closed when no `Token` is configured at all: the four software-distribution client endpoints (`GET /api/v1/client/windows-update-jobs`, `GET /api/v1/client/third-party-software-jobs` - split by catalog type in v0.81.0, replacing the single `GET /api/v1/client/software-jobs` - `POST /api/v1/client/software-jobs/results`, `GET /api/v1/client/software-repository-connection`, all since v0.56.0), and the two self-update download endpoints (`GET /api/v1/client-package/update-download`, `GET /api/v1/linux-client-package/update-download`, since v0.61.0 - see "Client self-update" below). This is deliberate for all six: they return a plaintext share credential, the fleet's job assignments, or the raw client binary/executable itself, none of which the ingestion token's own "low-sensitivity, fake-inventory-only" trust model was designed to cover. See `docs/threat-model.md`.
  - `POST /api/v1/client/enroll` (since 0.95.0) also always requires a real, matching token via the same `X-Inventory-Token` header, but checked against a *different* configured value - `EnrollmentToken`, not `Token` - and accepted only on this one route. See "Client enrollment" below.

**Cross-site request checks (v0.48.0+, tightened v0.68.0).** Every `POST`/`PUT`/`DELETE` route, with no exemption of any kind, requires: if the request has an `Origin` or `Referer` header, it must match this server's own `Host`; and if the request has a body, `Content-Type` must be `application/json` (an optional `; charset=...` suffix is fine). Both checks are skipped entirely when the corresponding header is absent - direct API automation (like the `curl` examples below), and every genuine ingestion/client-facing request, sends neither `Origin` nor `Referer` and is unaffected. This check now runs first, unconditionally, before any route dispatch or other auth check - including the four device-ingestion routes (`/api/v1/inventory`, `/api/v1/linux/inventory`, `/api/v1/linux/inventory/service-status`, `/api/v1/client/software-jobs/results`), which used to sit ahead of it in the dispatch chain and so were entirely unprotected by it whenever `RequireIngestionToken` was off (fixed as part of the SEC-I2 hardening pass, v0.68.0 - see `docs/threat-model.md`). A violation gets a `400` with the usual `{"error": "..."}` shape. Every `curl` example below already sends `Content-Type: application/json` on any request with a body, so none of them need updating.

**Login lockout (v0.50.0+).** Every route that goes through Basic Auth is also subject to a per-source-IP failed-attempt lockout, checked before Basic Auth itself: once an IP has presented wrong Basic Auth credentials `LoginLockoutThreshold` times (default 10) within `LoginLockoutWindowMinutes` (default 15), every request from that IP - including one with the *correct* password - gets a `429 Too Many Requests` with a `Retry-After: <seconds>` header for `LoginLockoutDurationMinutes` (default 15). A request with no `Authorization` header at all (a browser's normal first request before it has cached credentials) never counts as a failed attempt. Configurable, and disable-able (`LoginLockoutThreshold: 0`), via Settings > Admin password > Login lockout or `POST /api/v1/server/settings`. Tracking is per source IP and in-memory only (reset by a server restart) - defense-in-depth on top of the documented network-level control (trusted management network), not a replacement for it.

**HSTS (v0.50.0+).** Off by default (`HstsEnabled: false`). When turned on via Settings > Server > HTTPS or `POST /api/v1/server/settings`, every response actually served over the HTTPS listener (never plain HTTP, regardless of this setting) additionally carries `Strict-Transport-Security: max-age=<HstsMaxAgeHours * 3600>`. `HstsMaxAgeHours` (default 24, range 1-8760) is admin-configured rather than the commonly-recommended one-year value, since a browser that has cached this policy can lock itself out of the dashboard for the full duration if HTTPS is later disabled (e.g. during a certificate emergency) - start with a short value and only enable once HTTPS is stable.

**Request/response envelope.** Request and response bodies are plain JSON objects, no envelope wrapper. Most POST/PUT bodies are read as a flat `{"key": value, ...}` object; most GET/success responses are a flat JSON object as well, with fields documented per endpoint below.

**Error shape.** Every error response documented here (except the two `401` cases above) is a single-field JSON object:

```json
{"error": "human-readable message"}
```

This project does not use a structured `{"error": {"code": ..., "message": ...}}` shape anywhere. A handful of `409` risk-confirmation errors add one extra field, `"risks"` (an array of strings), alongside `"error"` - noted individually where that applies.

## Overview

### Inventory ingestion (client to server)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/inventory` | Ingestion token | Accept a Windows client's inventory report. |
| POST | `/api/v1/linux/inventory` | Ingestion token | Accept a Linux client's inventory report. |
| POST | `/api/v1/linux/inventory/service-status` | Ingestion token | Merge a service active/inactive snapshot into an existing Linux report. |

### Client enrollment (client to server)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/client/enroll` | Enrollment token (always, never `RequireIngestionToken`) | Exchange the bootstrap `EnrollmentToken` for a real per-machine ingestion token, keyed by `computerName`. Re-enrolling an already-enrolled `computerName` rotates to a brand-new token, invalidating the previous one - it does NOT return the existing value unchanged (see the enrollment security note under "Client enrollment" in `docs/threat-model.md` for why). Since 1.0.2: when `AdSyncEnabled` is on, `computerName` must match a real AD computer object or the request is rejected (`401`) - fails open (allows) on an AD lookup error, only a definitive "not found" blocks it. No effect when AD sync is off. |

Auth here is deliberately a *different* credential from every other client-facing route: the `X-Inventory-Token` header must match the server's configured `EnrollmentToken`, not the shared `Token` - a wrong or missing value gets the same plain-text `401 Unauthorized` as every other ingestion-token failure, but is checked and logged (`client-enroll` tag) against `EnrollmentToken` specifically. See `docs/threat-model.md` for why this exists (GPO-distributed `Install-ClientGpo.cmd` no longer needs to embed the real shared token). Request body: `{"computerName": "..."}`. `400` `{"error": "computerName is required"}` if missing or too long. Response: `{"token": "<the machine's real per-machine ingestion token>"}` - used by the client exactly like `Token` from then on, for every other client-facing endpoint, with no further special handling.

```bash
curl -X POST https://server:8443/api/v1/client/enroll \
  -H "X-Inventory-Token: <enrollment token>" \
  -H "Content-Type: application/json" \
  -d '{"computerName": "PC-01"}'
```

### Software distribution (client to server)

Ingestion token always required on these four, regardless of `RequireIngestionToken` - see "Auth models" above.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/client/windows-update-jobs` | Ingestion token (always) | Return the enabled `windowsUpdate` catalog entries targeted at one computer name. |
| GET | `/api/v1/client/third-party-software-jobs` | Ingestion token (always) | Return the enabled `thirdPartySoftware` catalog entries targeted at one computer name. |
| POST | `/api/v1/client/software-jobs/results` | Ingestion token (always) | Report one cycle's install results into the attempt-history log. |
| GET | `/api/v1/client/software-download` | Ingestion token (always) | Stream one catalog entry's installer file directly - no share credential needed. |
| GET | `/api/v1/client/software-repository-connection` | Ingestion token (always) | Return the software share path and credentials the client needs to read installers. Deprecated as of 1.0.2 - see its own entry below. |

### Client self-update (client to server)

Ingestion token always required on both, regardless of `RequireIngestionToken` - see "Auth models" above. Both have existed since v0.61.0 but were undocumented until this pass.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/client-package/update-download?target=net35\|net40` | Ingestion token (always) | Download the raw Windows client executable for the requested build target, for self-update. |
| GET | `/api/v1/linux-client-package/update-download` | Ingestion token (always) | Download the raw Linux client binary, for self-update. |

### Software distribution (dashboard)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/software-repository/settings` | Basic Auth | Return the software share path, username, whether a password is stored, and the scan interval. |
| POST | `/api/v1/software-repository/settings` | Basic Auth | Set the software share path, credentials, and scan interval. |
| GET | `/api/v1/software-repository/scan-status` | Basic Auth | Return the last share-discovery scan's result and candidate lists. |
| POST | `/api/v1/software-repository/scan` | Basic Auth | Run a share-discovery scan now and return its result. |
| GET | `/api/v1/software-repository/attempt-history` | Basic Auth | Return the persisted per-client install attempt log. |
| DELETE | `/api/v1/software-repository/attempt-history` | Basic Auth | Clear the Software job attempt log immediately, independent of its 5000-entry/90-day cap. |
| GET | `/api/v1/windows-updates` | Basic Auth | List the Windows Updates catalog. |
| POST | `/api/v1/windows-updates` | Basic Auth | Add a Windows Updates catalog entry. |
| PUT | `/api/v1/windows-updates/{id}` | Basic Auth | Update a Windows Updates catalog entry. |
| DELETE | `/api/v1/windows-updates/{id}` | Basic Auth | Delete a Windows Updates catalog entry. |
| GET | `/api/v1/third-party-software` | Basic Auth | List the Third-Party Software catalog. |
| POST | `/api/v1/third-party-software` | Basic Auth | Add a Third-Party Software catalog entry. |
| PUT | `/api/v1/third-party-software/{id}` | Basic Auth | Update a Third-Party Software catalog entry. |
| DELETE | `/api/v1/third-party-software/{id}` | Basic Auth | Delete a Third-Party Software catalog entry. |

### Clients & inventory data

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/clients` | Basic Auth | Return the Windows client inventory index. |
| GET | `/api/v1/clients/{computerName}/license-keys` | Basic Auth | Return one Windows client's decrypted license keys. |
| PUT | `/api/v1/clients/{computerName}/description` | Basic Auth | Set a manual description override for one Windows client. |
| DELETE | `/api/v1/clients/{computerName}` | Basic Auth | Delete one Windows client's stored report. |
| POST | `/api/v1/clients/install-windows-updates-now` | Basic Auth | Flag one Windows client to check for and install pending Windows Update jobs on its next report - split by catalog type in v0.81.0, replacing the earlier combined "check now" action. |
| POST | `/api/v1/clients/install-third-party-software-now` | Basic Auth | Flag one Windows client to check for and install pending third-party-software jobs on its next report - split by catalog type in v0.81.0, replacing the earlier combined "check now" action. |
| GET | `/api/v1/linux/clients` | Basic Auth | Return the Linux client inventory index. |
| PUT | `/api/v1/linux/clients/{hostname}/description` | Basic Auth | Set a manual description override for one Linux client. |
| DELETE | `/api/v1/linux/clients/{hostname}` | Basic Auth | Delete one Linux client's stored report. |

### Client install/update (Windows + Linux)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/client-install` | Basic Auth | Queue a mode-aware (Auto/Force Windows/Force Linux) push-install job, WinRM and/or SSH, against one or more targets of either platform. |
| POST | `/api/v1/client-uninstall` | Basic Auth | Queue a mode-aware push-uninstall job. |
| GET | `/api/v1/client-install` | Basic Auth | List recent install/uninstall job summaries, both platforms. |
| DELETE | `/api/v1/client-install` | Basic Auth | Clear the Installs log immediately - every saved job file plus the in-memory job cache. |
| GET | `/api/v1/client-install/{jobId}` | Basic Auth | Return full detail for one install/uninstall job, including per-target protocol attempts. |
| POST | `/api/v1/linux-client-install/trust-host-key` | Basic Auth | Manually trust (pin) a Linux target's SSH host key. |

### Windows client updates

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/client-updates` | Basic Auth | List Windows clients running an outdated client version. |
| GET | `/api/v1/client-updates/credentials` | Basic Auth | Report whether WinRM update credentials are saved. |
| POST | `/api/v1/client-updates/credentials` | Basic Auth | Save WinRM update credentials. |
| GET | `/api/v1/client-updates/schedule` | Basic Auth | Return the scheduled push-update configuration. |
| POST | `/api/v1/client-updates/schedule` | Basic Auth | Configure the scheduled push-update timer. |

### Windows client package

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/client-package` | Basic Auth | Return the state of the generated GPO install package. |
| POST | `/api/v1/client-package/configure` | Basic Auth | Regenerate `Install-ClientGpo.cmd` with a server URL, token, and interval. |
| GET | `/api/v1/client-package/download` | Basic Auth | Download a zip of the GPO deployment package. |

### Linux client updates

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/linux-client-updates` | Basic Auth | List Linux clients running an outdated client version. |
| GET | `/api/v1/linux-client-updates/credentials` | Basic Auth | Report whether SSH update credentials or a key are saved. |
| POST | `/api/v1/linux-client-updates/credentials` | Basic Auth | Save the SSH username/password used for update pushes. |
| GET | `/api/v1/linux-client-updates/schedule` | Basic Auth | Return the scheduled Linux push-update configuration. |
| POST | `/api/v1/linux-client-updates/schedule` | Basic Auth | Configure the scheduled Linux push-update timer. |

### Linux client package & SSH key management

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/linux-client-package` | Basic Auth | Return the state of the generated Linux client package. |
| POST | `/api/v1/linux-client-package/configure` | Basic Auth | Regenerate the systemd units and `install.sh` with a server URL and token. |
| GET | `/api/v1/linux-client-package/download` | Basic Auth | Download a zip of the Linux client package. |
| GET | `/api/v1/server/linux-ssh-tools-status` | Basic Auth | Report whether `plink.exe`/`pscp.exe` are available on the server host. |
| POST | `/api/v1/server/linux-ssh-key` | Basic Auth | Upload the private SSH key used to push installs/updates to Linux clients. |
| DELETE | `/api/v1/server/linux-ssh-key` | Basic Auth | Delete the stored SSH private key. |

### Server settings & security

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/server/certificate` | Basic Auth | Return the configured HTTPS certificate's status. |
| POST | `/api/v1/server/certificate` | Basic Auth | Import a PFX certificate into the local machine store. |
| DELETE | `/api/v1/server/certificate` | Basic Auth | Remove the configured certificate and disable HTTPS. |
| GET | `/api/v1/server/certificate/history` | Basic Auth | List previously imported certificates. |
| DELETE | `/api/v1/server/certificate/history/{id}` | Basic Auth | Delete one certificate history entry. |
| GET | `/api/v1/server/settings` | Basic Auth | Return general server, AD, and HTTPS settings. |
| POST | `/api/v1/server/settings` | Basic Auth | Update general server, AD, and HTTPS settings. |
| GET | `/api/v1/server/admin-password` | Basic Auth | Report whether the dashboard admin account is configured. |
| POST | `/api/v1/server/admin-password` | Basic Auth | Set or rotate the dashboard admin username/password. |
| GET | `/api/v1/server/ingestion-token` | Basic Auth | Return the live ingestion token value. |
| POST | `/api/v1/server/ingestion-token/regenerate` | Basic Auth | Generate and save a new ingestion token. |
| GET | `/api/v1/server/ingestion-rejections` | Basic Auth | Return the log of rejected ingestion-token attempts (History & Logs > System Logs > Ingestion). |
| DELETE | `/api/v1/server/ingestion-rejections` | Basic Auth | Clear the ingestion-rejection log immediately, independent of its retention settings. |
| GET | `/api/v1/server/enrollment-token` | Basic Auth | Return the live enrollment (bootstrap) token value and whether one is configured. |
| POST | `/api/v1/server/enrollment-token/regenerate` | Basic Auth | Generate and save a new enrollment token. |
| GET | `/api/v1/client-tokens` | Basic Auth | List every per-machine token issued via enrollment (`computerName` and `issuedAtUtc` only - never the token value itself). |
| DELETE | `/api/v1/client-tokens/{computerName}` | Basic Auth | Revoke one machine's per-machine token immediately. `404` if none is on record for that name. |
| GET | `/api/v1/server/debug-log` | Basic Auth | Return the current content of the opt-in debug log (History & Logs > System Logs > Debug). |
| DELETE | `/api/v1/server/debug-log` | Basic Auth | Clear the debug log immediately, independent of its retention settings. |
| POST | `/api/v1/server/login` | None | Establish a server-side dashboard session with valid admin credentials; returns a `wil_session` cookie. |
| POST | `/api/v1/server/logout` | Basic Auth | Invalidate the current session and clear the `wil_session` cookie. |

### AD computer import

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/ad/computers` | Basic Auth | Search Active Directory for computer objects to import. |

### Licenses

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/licenses` | Basic Auth | List stored license records. |
| POST | `/api/v1/licenses` | Basic Auth | Create a license record. |
| PUT | `/api/v1/licenses/{id}` | Basic Auth | Update an existing license record. |
| DELETE | `/api/v1/licenses/{id}` | Basic Auth | Delete a license record. |

### License key sources

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/license-key-sources` | Basic Auth | List the admin-managed registry-location catalog used for automatic license key collection. |
| POST | `/api/v1/license-key-sources` | Basic Auth | Add a catalog entry. |
| PUT | `/api/v1/license-key-sources/{id}` | Basic Auth | Update an existing catalog entry. |
| DELETE | `/api/v1/license-key-sources/{id}` | Basic Auth | Delete a catalog entry. |

## Inventory ingestion

### POST /api/v1/inventory

Accepts a Windows client's full inventory report as the request body (an arbitrary JSON object; the only field the server reads directly is `computerName`, used to name the stored file) and overwrites `{DataPath}/{computerName}.json` with it, after merging in the current AD-sync fields (`adDescription`, `adSyncStatus`, `adSyncedAt`) so a client's own report never has to know about AD sync. Before the file is written, every `licenses[].key` present in the body is replaced with its DPAPI-encrypted form (`SecretProtector.Protect`) - the client submits it in plaintext, the stored copy never is; see `GET /api/v1/clients/{computerName}/license-keys` below for the only way to read it back decrypted.

- Auth: `X-Inventory-Token` header, checked against the configured token when `RequireIngestionToken` is on.
- Response on success: `{"status": "ok", "config": {...}, "forceImmediateWindowsUpdateCheck": bool, "forceImmediateThirdPartySoftwareCheck": bool, "licenseKeySources": [...]}`. `400 {"error": "invalid request body"}` if the body is not valid JSON.
  - `config.intervalHours`/`config.windowsUpdateCheckIntervalHours`/`config.thirdPartySoftwareCheckIntervalHours` - current fleet-wide defaults, always present regardless of token validity (not sensitive).
  - `forceImmediateWindowsUpdateCheck`/`forceImmediateThirdPartySoftwareCheck` - `true` once, for the one report that clears the matching per-computer flag an admin set via "Install now" (see the Agent Actions endpoints below) - the client acts on it immediately instead of waiting for its own poll interval. Always present, same low-sensitivity reasoning as the interval defaults above.
  - `licenseKeySources` - the current admin-managed license key source catalog (see `GET /api/v1/license-key-sources` below), trimmed to just `product`/`registryHive`/`registryPath`/`valueName` per entry (no `id`/`createdAt`/`updatedAt`). Present only when the supplied token is a real, exact match (not merely accepted because `RequireIngestionToken` is off, and not a previous-token-overlap match) - a caller with no valid token still gets its report accepted and the fields above, just not this catalog.
  - `config.ingestionToken` - the real current token in plaintext, present only on the one report where the client authenticated with the *previous* token during an overlap window (`PreviousToken`/`PreviousTokenExpiresUtc`, see Settings > Server > Ingestion Token), so the client learns and persists the rotated value. Never present otherwise.
  - `config.update` - present only when `EnableWindowsClientSelfUpdate` is on, the token is a real exact match, and a newer client build exists (`BuildWindowsClientUpdateInfo`): `versionNet35`/`sha256Net35`/`sigNet35` and/or `versionNet40`/`sha256Net40`/`sigNet40` (whichever target build is present in `ClientPackagePath`; `sigNet35`/`sigNet40` only when a matching `.sig` file exists next to it - see `docs/self-update-signing.md`), a legacy `version` field (best-effort, kept only so a pre-split client build still understands the field), and `httpsPort` - the port HTTPS is actually bound on right now, present only when the HTTPS listener is genuinely running (not just enabled in config), letting a client installed before a certificate existed opportunistically retry its download over HTTPS.

```bash
curl -X POST https://server:8443/api/v1/inventory \
  -H "X-Inventory-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"computerName":"WORKSTATION01", "...": "..."}'
```

### POST /api/v1/linux/inventory

Same behavior as `/api/v1/inventory`, for Linux clients: reads `hostname` from the body to name the stored file (`{LinuxDataPath}/{hostname}.json`), merges AD-sync fields, overwrites the file.

- Auth: identical to `/api/v1/inventory`.
- Response on success: `{"status": "ok", "config": {...}}` - simpler than the Windows endpoint's response, since the Linux client has no license-key catalog and no software-distribution force-check mechanism.
  - `config.intervalHours`/`config.statusIntervalMinutes` - current fleet-wide defaults for the Linux client's two collection timers, always present.
  - `config.ingestionToken` - same previous-token-overlap rotation case as `/api/v1/inventory`, present only then.
  - `config.update` - present only when `EnableLinuxClientSelfUpdate` is on, the token is a real exact match, and a newer `wil-linux-client` binary exists in `LinuxClientPackagePath`: `version`, `sha256`, and `sig` (only when a matching `.sig` file exists). One binary for all Linux targets, so no `versionNet35`/`versionNet40` split and no `httpsPort` field - the Linux self-update path does not have the opportunistic-HTTPS-retry behavior the Windows client's does.

```bash
curl -X POST https://server:8443/api/v1/linux/inventory \
  -H "X-Inventory-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web01", "...": "..."}'
```

### POST /api/v1/linux/inventory/service-status

Merges a lightweight service-status snapshot into an *existing* Linux inventory report, rather than replacing the report the way the two endpoints above do. This is the point of the endpoint: a status-check timer can run far more often than the full inventory collector without re-sending (or re-storing) the whole report each time.

Request body fields read: `hostname` (selects the target report file), `activeUnits` (an array of systemd unit names currently active), `collectedAt` (a timestamp string).

Merge behavior (`MergeServiceStatus`): for every entry in the existing report's `services` array whose `unit` field matches a name in `activeUnits`, sets that entry's `active` field to `true`; every other existing service entry gets `active: false`. It never adds, removes, or otherwise touches any other field on the report. It also sets a new top-level `servicesStatusCollectedAt` field to `collectedAt`. If no report exists yet for the hostname, or the existing file fails to parse, the request is silently accepted (`{"status": "ok"}`) and dropped - there is nothing to merge into.

- Auth: `X-Inventory-Token`, same as the other two ingestion endpoints.
- Response: `{"status": "ok"}` in all cases (including the silently-dropped ones above). `400 {"error": "invalid request body"}` on malformed JSON.

```bash
curl -X POST https://server:8443/api/v1/linux/inventory/service-status \
  -H "X-Inventory-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web01", "activeUnits":["nginx.service","sshd.service"], "collectedAt":"2026-08-04T12:00:00Z"}'
```

## Clients & inventory data

### GET /api/v1/clients

Returns the full Windows client inventory index in one response. Top-level fields: `schemaVersion`, `serverVersion`, `generatedAt`, `clientCount`, `staleHours`, `adDescriptionSyncEnabled`, `showUsbStorageIndicator` (dashboard-display toggle for the "Computers with USB storage" tile and per-client badge - a client's own `hasUsbStorage` field, inside `clients` below, is always present regardless of this setting), and `clients` - an array where each entry is a client's stored inventory report (the report body as last submitted to `POST /api/v1/inventory`, plus `sourceFile` and `sourceUpdatedAt` added by the server, the latter from the report file's last-write time; `lastIngestSourceIp` is a string, the source IP of the client's most recent successful report, used for ingestion-token-issue correlation; `tokenIssue` is one of `"missing"` or `"mismatched"` when a token problem is detected, absent from the object when there is none). Each entry's `licenses[].key`, if present, stays DPAPI-encrypted in this response - it is never decrypted for the bulk listing, only `product`/`source` are meaningful here. Use the reveal endpoint below to get one client's decrypted keys on demand.

### GET /api/v1/clients/{computerName}/license-keys

Looks up one client's stored report and returns its `licenses` array with every `key` decrypted (`SecretProtector.Unprotect`). The computer name is taken as everything between the `/api/v1/clients/` prefix and the `/license-keys` suffix (URL-decoded, trimmed), the same way the description/delete routes above extract it. Called only when the dashboard admin explicitly clicks "show" on one license entry - nothing is bulk-decrypted or pre-fetched.

- Response: `{"licenses": [{"product": "...", "source": "...", "key": "...", "isKms": false, "sharedWith": []}]}`. `isKms` is `true` when the key matches a known Microsoft volume-license (GVLK) key for that product (computed at ingest time, `IsKnownGvlk`). `sharedWith` lists every computer name whose own `product`+decrypted-key pair matches this one (built fresh on each client-listing load, `BuildSharedActivationKeyGroups`) - present only when at least one other machine shares the key; omitted (not an empty array) otherwise. `404 {"error": "client not found"}` if the client has no stored report (including an unreadable/corrupt report file) or the URL has no computer-name segment at all. A report with a missing or non-array `licenses` field is still a `200` with `licenses: []`, not a 404.

```bash
curl -X GET "https://server:8443/api/v1/clients/WORKSTATION01/license-keys" \
  -u admin:password
```

### DELETE /api/v1/clients/{computerName}/license-keys/{index}

Removes one entry from a client's stored `licenses` array by its position (`index`, 0-based, matching the order the array comes back in from the GET route above). Registered ahead of the broader `DELETE /api/v1/clients/{computerName}` route below so it isn't shadowed by it. Takes the same `reportFileLock` every other writer of that client's report file takes, so it can't race a concurrent inventory report for the same machine.

If the key is still detectable on that machine the next time it reports, the entry reappears - this endpoint only ever removes the currently-stored copy, it does not suppress future (re-)detection.

- Response: `{"status": "deleted"}`. `400 {"error": "invalid license key index"}` for a non-numeric or negative index segment. `404 {"error": "client not found"}` if the computer has no stored report, or `404 {"error": "license key not found"}` if the index is out of range for that client's current `licenses` array.

```bash
curl -X DELETE "https://server:8443/api/v1/clients/WORKSTATION01/license-keys/0" \
  -u admin:password
```

### PUT /api/v1/clients/{computerName}/description

Sets a manual description override for one client. The URL segment is URL-decoded and trimmed; the full route requires the `/description` suffix (`DELETE` on the same prefix does not - see below). Request body: `{"description": "..."}` (up to 1024 characters; a missing key is treated as an empty string, not an error).

Fails with `400 {"error": "Description is synced from AD - disable \"Sync Description from AD\" in Settings first."}` if `adDescriptionSyncEnabled` is on - this is enforced server-side, not just hidden in the UI. Otherwise sets the same `adDescription` field AD sync itself writes, without touching `adSyncStatus`/`adSyncedAt`, and rewrites the client's whole report file with that one field changed.

- Response: `{"status": "ok", "description": "..."}`. `404 {"error": "client not found"}` if the client has no stored report.

### DELETE /api/v1/clients/{computerName}

Deletes one client's stored report file. The computer name is taken as everything after the `/api/v1/clients/` prefix (URL-decoded, trimmed, then sanitized to a safe filename) - there is no suffix check the way the PUT route has one. Only the single report JSON file is removed; no other artifacts (install job history, etc.) are touched.

- Response: `{"status": "deleted"}`. `400 {"error": "computer name is required"}` if empty. `404 {"error": "client not found"}` if no matching file exists.

### GET /api/v1/linux/clients

Same shape as `GET /api/v1/clients` for Linux clients, with one difference: the Linux index has no `staleHours` field. Top-level fields: `schemaVersion`, `serverVersion`, `generatedAt`, `clientCount`, `adDescriptionSyncEnabled`, `clients`.

### PUT /api/v1/linux/clients/{hostname}/description and DELETE /api/v1/linux/clients/{hostname}

Linux equivalents of the two Windows endpoints above, operating on `LinuxDataPath` instead of `DataPath`. Same request/response shapes, same `/description` suffix requirement on PUT, same AD-sync guard, same 1024-character limit, same error shapes.

## Client install/update (Windows + Linux)

As of the Deploy > Actions unification (v0.42.0), one endpoint pair serves both platforms; the earlier separate `/api/v1/linux-client-install`/`/linux-client-uninstall`/`/linux-client-install` (GET list/detail) routes no longer exist. Anything that called them, or called the Windows routes without a `mode` field, needs updating - see the CHANGELOG's `[0.42.0]` entry. v0.43.0 added `winRmAuthMode`/new `sshAuthMode` values (`"global"`/`"manual"`) as the current way to pick a credential source - the older `useSavedCredentials`/`useAdCredentials`/`sshAuthMode: "ad"|"credentials"` fields still work unchanged for any existing caller. v0.44.0's Deploy > Updates unification switched the dashboard's own "Update selected" push (previously the last first-party user of the older fields) onto the same `winRmAuthMode`/`sshAuthMode` shape Deploy > Actions already used - the older fields are now kept purely for backward compatibility with anything that scripted the old payload shape directly.

### POST /api/v1/client-install and POST /api/v1/client-uninstall

Both routes share one handler, serving both platforms, distinguished only by which action it runs. A request must declare a **mode**, required: `"auto"` (TCP-probes WinRM port 5985 and SSH port 22 per target, tries WinRM first if both respond, falls back to SSH only if the WinRM attempt itself fails), `"force-windows"` (WinRM only, no probing), or `"force-linux"` (SSH only, no probing). Missing or invalid `mode` is `400 {"error": "mode must be 'auto', 'force-windows', or 'force-linux'"}`.

Request body fields:

- `targets` (free-text, newline/comma/space-separated hostnames/computer names or IPs, supports IP ranges) - required.
- `mode` - required, as above.
- `serverUrl` (required for install unless a saved Linux package configuration supplies a fallback - see below; not required for uninstall). Whenever a target actually dispatches over SSH, the server rewrites a `serverUrl` ending in `/api/v1/inventory` to end in `/api/v1/linux/inventory` instead (`ToLinuxServerUrl`) - the dashboard always sends the Windows-shaped URL (it has no way to know in advance which protocol Auto mode will pick per target), so a caller providing its own `serverUrl` should do the same and rely on this rewrite for SSH targets, rather than trying to guess the platform itself. A URL that doesn't end in that exact suffix passes through unchanged. `token` (blank falls back to the server's live ingestion token).
- WinRM fields, read whenever `mode` is `"auto"` or `"force-windows"`: `winRmAuthMode` (`"global"` or `"manual"`, optional - **as of v0.43.0**, the current/recommended way to select a credential source). `"global"` tries the saved WinRM update credentials first, then AD (service identity or a saved AD account) as a fallback, ignoring `username`/`password`; if nothing resolves, the install proceeds with no `-Credential` (the server's own service identity), not an error. `"manual"` uses `username`/`password` as given. If `winRmAuthMode` is omitted entirely, the endpoint falls back to the older `useSavedCredentials`/`useAdCredentials` boolean pair (still supported for backward compatibility - no first-party caller sends it since the Deploy > Updates unification, v0.44.0) with the same resolution semantics. `force` (reinstall over an existing install), `addToTrustedHosts`.
- SSH fields, read whenever `mode` is `"auto"` or `"force-linux"`: `sshAuthMode` - accepts `"global"`, `"manual"`, or `"key"` (current values, **as of v0.43.0**), plus the older `"ad"`/`"credentials"` (still supported for backward compatibility - same behavior as `"manual"` was for `"credentials"`; no first-party caller sends either since the Deploy > Updates unification, v0.44.0). `"global"` tries the saved Linux update credentials first, then AD as a fallback, ignoring `sshUsername`/`sshPassword` - unlike WinRM's `"global"`, this is a hard `400` if nothing resolves (there is no SSH equivalent of "run as no one"). `"manual"`/`"credentials"` use `sshUsername`/`sshPassword`, falling back to the saved account for whichever field is left blank. `"key"` mode uses the server's stored SSH private key and needs only `sshUsername` (also falls back to the saved username if blank). `installPath`/`intervalHours`/`statusIntervalMinutes` (default from Settings > Linux > Install defaults if omitted), and, for install only, `trustNewHostKeys` plus `acknowledgeHostKeyRisk` (both must be set together to let a first-contact SSH host key be auto-trusted instead of failing).
- `retentionDays` (optional, overrides the server's default job-log retention for this one job).

**Known characteristic:** Auto mode requires both credential sets (WinRM and SSH) to be resolvable before the job is queued, even if every target in the batch turns out to be one platform only. A deployment with no Linux credentials/SSH key saved (Settings > Linux) gets a validation error on Auto mode until that's configured, or Force Windows is used instead.

If `username`/`password` end up blank in a mode that reaches WinRM, that install runs without a WinRM `-Credential`, i.e. as whatever identity the server's own Windows service runs as - not rejected as an error.

The response comes back immediately with a job ID; the actual install/uninstall work happens asynchronously on a background thread pool, tracked by that job:

```json
{"jobId": "a1b2c3...", "status": "queued"}
```

`serverUrl` and other string inputs are validated against unsafe-character sets before being interpolated into the generated PowerShell (WinRM) or shell (SSH) invocation, and a validation failure comes back as `400 {"error": "..."}` describing which field failed. Target hostname-format validation (letters/digits/`.`/`-` only) applies for every mode except `force-windows` - Windows NetBIOS names can legally contain `_`, which that check would otherwise wrongly reject.

```bash
curl -X POST https://server:8443/api/v1/client-install \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"targets":"192.168.1.10-20", "mode":"force-windows", "serverUrl":"https://server:8443", "winRmAuthMode":"global"}'
```

```bash
curl -X POST https://server:8443/api/v1/client-uninstall \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"targets":"web01.example.com", "mode":"force-linux", "sshAuthMode":"key", "sshUsername":"deploy"}'
```

```bash
curl -X POST https://server:8443/api/v1/client-install \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"targets":"PC-01\nweb01.example.com", "mode":"auto", "serverUrl":"https://server:8443", "winRmAuthMode":"global", "sshAuthMode":"global"}'
```

### GET /api/v1/client-install

Lists install/uninstall job summaries across both platforms: `{"defaultRetentionDays": ..., "jobs": [...]}`. Each summary has `id`, `action`, `status`, `createdAt`, `startedAt`, `completedAt`, `mode`, `serverUrl`, `username` (falls back to the SSH username when the job had no WinRM username), `retentionDays`, `targetCount`, `resultCount`, `failedCount` - counts only, not the full per-target result list. As a side effect, every call also prunes job files older than their retention window from disk. A job saved before v0.42.0 has no `mode` field (reads as an empty string, shown as a legacy Windows job by the dashboard).

### DELETE /api/v1/client-install

Clears the Installs log immediately, independent of `retentionDays` - deletes every saved job file plus the in-memory job cache. Response: `{"status": "cleared", "clearedCount": N}`. Recorded to the debug log (category `Server`) when it happens.

### GET /api/v1/client-install/{jobId}

Returns one job's full detail, including the per-target `results` array. Each result carries the existing summary fields (`target`, `status`, `message`, `protocol` - which protocol the summary reflects, `output`/`error`) plus a new `attempts` array: one entry per protocol actually tried (`protocol`, `status`, `message`, `output`/`error`, timestamps, and for an `ssh` attempt only, `hostKeyTrust`/`hostKeyStatus`/`hostKeyFingerprint`). A force-mode job's `attempts` always has exactly one entry; an Auto-mode job that tried both protocols has two. Neither this endpoint nor the list endpoint above ever returns a `password`/`sshPassword`/`token`/SSH-key-path field. `404 {"error": "job not found"}` if the ID matches neither an in-memory job nor a persisted job file.

### POST /api/v1/linux-client-install/trust-host-key

Manually pins a Linux target's SSH host key (TOFU/known-hosts style), a prerequisite for non-key-auth installs against a host the server has never connected to before. Unaffected by the install/uninstall unification above - this route predates it and was deliberately left at its original path. Request body: `host` (required), `fingerprint` (required, must look like `SHA256:...`), `keyType` (default `ssh-ed25519`), `port` (default 22).

Stores the upserted record (`Host`, `Port`, `KeyType`, `Fingerprint`, `TrustedAtUtc`, `TrustMethod: "manual"`) and returns it directly as the response body. A subsequent install for that host pins the connection to this fingerprint; if the real key ever no longer matches, the result is classified `hostKeyStatus: "changed"` and is never auto-accepted, regardless of `trustNewHostKeys`.

```bash
curl -X POST https://server:8443/api/v1/linux-client-install/trust-host-key \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"host":"web01.example.com", "fingerprint":"SHA256:AbCdEf...", "keyType":"ssh-ed25519"}'
```

## Windows client updates

### GET /api/v1/client-updates

Lists Windows clients whose reported `clientVersion` does not match the current bundled client version. Fields: `net35Version`, `net40Version`, `lastScheduledJobId`, `packageAvailable`, `updates` (array of `{computerName, domain, clientVersion, collectedAt}`), `outdatedCount`. If no client package has been built yet, `packageAvailable` is `false` and `updates` is an empty array rather than treating every client as outdated.

### GET /api/v1/client-updates/credentials and POST /api/v1/client-updates/credentials

GET returns `{"configured": ..., "username": ..., "hasPassword": ...}` - never the password itself. POST reads `username`, `password` (blank/omitted keeps the existing stored password), `clear` (wipes both); response is the same shape as the GET. The password is stored DPAPI-encrypted at rest in `server-config.json`.

### GET /api/v1/client-updates/schedule and POST /api/v1/client-updates/schedule

GET returns `{"mode", "onceAtUtc", "intervalHours", "lastRunUtc", "hasSavedCredentials"}`. POST accepts `mode` (`"off"`, `"once"`, or `"interval"`), and either `onceAtUtc` or `intervalHours` (1-8760) depending on mode; applies the new schedule to the live timer immediately, no restart needed. `400 {"error": "mode must be 'off', 'once', or 'interval'"}` and similar messages on bad input.

## Windows client package

### GET /api/v1/client-package

Returns the state of the generated GPO install package: `packagePath`, `packagePresent`, `net35Present`/`net35Version`, `net40Present`/`net40Version`, `deployScriptPresent`, `cmdPresent`, `cmdServerUrl`, `cmdIntervalHours`, `cmdToken`, `cmdPackageSharePath`. `cmdToken` is the plaintext ingestion token read back out of the generated `Install-ClientGpo.cmd` file - intentional, since this page is where an admin reviews/copies that file's settings, but worth knowing this endpoint discloses the live token to anyone with Basic Auth access, same as `GET /api/v1/server/ingestion-token`.

### POST /api/v1/client-package/configure

Regenerates `Install-ClientGpo.cmd`. Request body: `serverUrl` (required), `token` (blank falls back to the server's live token), `packageSharePath` (blank uses the package folder itself), `intervalHours` (1-24, default 6). Response is the same shape as `GET /api/v1/client-package`. `400 {"error": "client package directory not found"}` if the package folder does not exist yet.

```bash
curl -X POST https://server:8443/api/v1/client-package/configure \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"serverUrl":"https://server:8443", "intervalHours":6}'
```

### GET /api/v1/client-package/download

Streams a ZIP built on the fly from whatever exists on disk: the client executables, `Deploy-ClientGpo.ps1`, and `Install-ClientGpo.cmd`. Requires `POST /api/v1/client-package/configure` to have run first - `400 {"error": "..."}` with guidance text if `Install-ClientGpo.cmd` or a client executable is missing. Response headers: `Content-Type: application/zip`, `Content-Disposition: attachment; filename="windows-inventory-lite-client.zip"`.

### GET /api/v1/client-package/update-download

**Not a dashboard-admin endpoint - called by the running Windows client itself**, to download its own self-update binary (v0.61.0+). Auth: ingestion token only (`X-Inventory-Token` header), always required regardless of `RequireIngestionToken` - a missing or wrong token gets a plain-text `401 Unauthorized`, and the attempt is recorded to the ingestion-rejection log under the `client-package-update-download` endpoint tag. Query string: `?target=net35` or `?target=net40` (required - anything else is `400 {"error": "target must be net35 or net40"}`), matching the two Windows build targets described under [The Windows Client Agent](./project-specification.md#the-windows-client-agent). `404` plain text `Client package not found for the requested target.` if that target's executable isn't present in `ClientPackagePath`. On success, streams the raw `.exe` bytes with `Content-Type: application/octet-stream` and `Content-Disposition: attachment; filename="WindowsInventoryLiteClient.exe"` - this is the same file `GET /api/v1/client-package` reports the version of, not a separate build. See "Client self-update" in `docs/threat-model.md` for what an attacker able to tamper with this response could achieve.

## Linux client updates

Install/uninstall job endpoints for Linux moved into the unified [Client install/update (Windows + Linux)](#post-apiv1client-install-and-post-apiv1client-uninstall) section above (v0.42.0). This section covers only the scheduled/manual update-push machinery, which the unification did not touch.

### GET /api/v1/linux-client-updates

Same purpose as the Windows equivalent: lists Linux clients on an outdated `clientVersion`. Fields: `currentVersion`, `lastScheduledJobId`, `packageAvailable`, `updates` (array of `{hostname, target, clientVersion, sourceUpdatedAt}` - `target` is the actual push address, which can differ from the self-reported `hostname`), `outdatedCount`.

### GET /api/v1/linux-client-updates/credentials and POST /api/v1/linux-client-updates/credentials

GET: `{"configured", "username", "hasPassword", "hasStoredKey", "keyUploadedAtUtc", "authPriority"}` - never the password or key contents. `authPriority` is `"key-first"` (default) or `"password-first"`, and decides which saved credential "Global" SSH auth mode tries first when both are configured. POST accepts `username`, `password` (blank keeps the existing one unless `clear` is set), `clear`, `authPriority` (optional, `"key-first"` or `"password-first"` - `400` if anything else is sent).

### GET /api/v1/linux-client-updates/schedule and POST /api/v1/linux-client-updates/schedule

Same shape and semantics as the Windows client-updates schedule endpoints, against separate `LinuxUpdateSchedule*` settings.

## Linux client package & SSH key management

### GET /api/v1/linux-client-package

Returns the generated Linux client package's state: `packagePath`, `packagePresent`, `binaryPresent`, `binaryVersion`, `serverUrl`, `token`, `intervalHours` (default 6), `statusIntervalMinutes` (default 30), `installPath` (default `/opt/windows-inventory-lite`). Like the Windows package status endpoint, `token` is returned in plaintext, read back from the saved package settings file.

### POST /api/v1/linux-client-package/configure

Regenerates the systemd unit files (`wil-linux-client.service`/`.timer`, `wil-linux-client-status.service`/`.timer`) and `install.sh`. Request body: `serverUrl` (required), `token` (falls back to the live server token), `installPath`, `intervalHours` (1-24), `statusIntervalMinutes` (1-1440). Response is the same shape as `GET /api/v1/linux-client-package`.

```bash
curl -X POST https://server:8443/api/v1/linux-client-package/configure \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"serverUrl":"https://server:8443", "intervalHours":6, "statusIntervalMinutes":30}'
```

### GET /api/v1/linux-client-package/download

Streams a ZIP of the Linux client bundle: the client binary, the four systemd unit files, and `install.sh`. Requires the binary and `install.sh` to already exist - `400 {"error": "..."}` with guidance text otherwise. `Content-Disposition: attachment; filename="windows-inventory-lite-linux-client.zip"`.

### GET /api/v1/linux-client-package/update-download

**Not a dashboard-admin endpoint - called by the running Linux client itself**, to download its own self-update binary (v0.61.0+). Auth: ingestion token only, always required regardless of `RequireIngestionToken` - a missing or wrong token gets a plain-text `401 Unauthorized`, recorded to the ingestion-rejection log under the `linux-client-package-update-download` endpoint tag. No `target` query parameter - the Linux client has one build, not two runtime targets, unlike the Windows equivalent above. `404` plain text `Client package not found.` if `wil-linux-client` isn't present in `LinuxClientPackagePath`. On success, streams the raw binary with `Content-Type: application/octet-stream` and `Content-Disposition: attachment; filename="wil-linux-client"`.

### GET /api/v1/server/linux-ssh-tools-status

Checks the *server host's own* local tooling, not anything about a client: whether `plink.exe` and `pscp.exe` (the PuTTY-suite binaries the server uses to SSH out to Linux clients, for both password- and key-based authentication) are present at either the installed-server location or the dev-tree location next to the running assembly. Response: `{"plinkFound": ..., "pscpFound": ...}`.

### POST /api/v1/server/linux-ssh-key

Uploads the private SSH key the server uses to connect to Linux clients for pushes. Request body: `keyBase64` (base64-encoded key file content, up to 1 MB). Rejects a `.pub` file (`400`, "This looks like a public key..."), rejects anything without a `-----BEGIN ... PRIVATE KEY-----` header, and flags (without rejecting) a passphrase-protected key, since batch-mode SSH cannot prompt for one.

The key is written to a restricted-ACL file under the server's data directory. The key contents are never returned in any response - success is `{"status": "ok", "risks": [...]}`, where `risks` only ever carries the passphrase warning above, never key material.

### DELETE /api/v1/server/linux-ssh-key

Deletes the stored SSH private key file, if present. `{"status": "deleted"}` whether or not a key existed to delete - not an error either way.

## Server settings & security

### GET /api/v1/server/certificate, POST /api/v1/server/certificate, DELETE /api/v1/server/certificate

GET/POST/DELETE all return the same shape: `useHttps`, `thumbprint`, `certificatePresent`, `subject`, `issuer`, `notBefore`, `notAfter`, `isExpired`, `risks`. The private key is never included.

POST imports a PFX: body is `pfxBase64` (1 byte to 1 MB after decoding) and `password`. It imports into `LocalMachine\My`, but only hot-swaps the live listener certificate if HTTPS is already on and the certificate has no flagged risks - a risky certificate is recorded but never silently put into use. Every successful import is also appended to the certificate history log.

DELETE removes the configured certificate from the store and, as a side effect, turns HTTPS off (there would be nothing left to serve it with) - `400 {"error": "no certificate is configured"}` if none is set.

```bash
curl -X POST https://server:8443/api/v1/server/certificate \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"pfxBase64":"<base64>", "password":"..."}'
```

### GET /api/v1/server/certificate/history and DELETE /api/v1/server/certificate/history/{id}

GET returns `{"history": [...]}`, most-recent-first, each entry `{id, thumbprint, subject, issuer, notBefore, notAfter, uploadedAt, risks}` - no key or password data. DELETE removes one entry by ID: `{"status": "deleted"}` on success, `404 {"error": "history entry not found"}` otherwise. Deleting a history entry never affects the certificate currently in use. History entries written before this endpoint existed have no `id` and cannot be targeted individually.

### GET /api/v1/server/settings

Returns the general settings block: everything from the certificate status shape above, plus `staleHours`, `showUsbStorageIndicator` (default `true` - hides the Dashboard's USB tile and the per-client badge when off, without affecting what the client reports), `port`, `enableHttp`, `httpsPort`, `hstsEnabled`, `hstsMaxAgeHours` (off by default - see "HSTS" under Conventions above), `adSyncEnabled`, `adDescriptionSyncEnabled`, `adSyncMode`, `adSyncIntervalHours`, `adDomain`, `adUseServiceIdentity`, `adUsername` (`null` when using the service identity), `adPasswordConfigured` (boolean only, never the password itself), `adComputerImportOUs`, `preferredLinuxSubnet` (empty string means no filtering), `linuxDefaultIntervalHours`, `linuxDefaultStatusIntervalMinutes`, `linuxDefaultInstallPath`, `loginLockoutThreshold`, `loginLockoutWindowMinutes`, `loginLockoutDurationMinutes` (see "Login lockout" under Conventions above), `sessionLifetimeHours`, `installLogRetentionDays`, `ingestionRejectionLogRetentionDays`, `ingestionRejectionLogMaxEntries`, `softwareJobAttemptLogRetentionDays`, `softwareJobAttemptLogMaxEntries`, `debugLogEnabled`, `debugLogPath`, `debugLogRetentionDays`, `debugLogMaxSizeMb`, `windowsUpdateCheckIntervalHours`/`thirdPartySoftwareCheckIntervalHours` (default `6` each - independent poll cadences for the two catalog types), `windowsUpdateInstallWindowEnabled`/`thirdPartySoftwareInstallWindowEnabled` (default `false` each), `windowsUpdateInstallWindowStartUtc`/`windowsUpdateInstallWindowEndUtc` and `thirdPartySoftwareInstallWindowStartUtc`/`thirdPartySoftwareInstallWindowEndUtc` (`HH:mm`, UTC - default `02:00`/`04:00` each; a range where start is later than end wraps past midnight, e.g. `22:00`-`06:00`), `windowsUpdateInstallWindowJitterMinutes`/`thirdPartySoftwareInstallWindowJitterMinutes` (default `30` each). Each install window only gates its own catalog type's jobs - because the Windows client polls each type on its own fixed period from service start (`windowsUpdateCheckIntervalHours`/`thirdPartySoftwareCheckIntervalHours` on the client), a window narrower than its matching interval can miss a machine's actual poll times entirely - size each window at least as wide as that catalog's configured check interval. `requireIngestionToken` and the dashboard admin username/password are deliberately not part of this response - see the ingestion-token and admin-password endpoints below.

### POST /api/v1/server/settings

Updates any subset of the fields above (each key is only applied if present in the body), plus write-only fields `useHttps`/`acknowledgeRisks`, `requireIngestionToken`/`acknowledgeIngestionTokenRisk`, and `adPassword` (blank/omitted keeps the existing one). Response on success is the same shape as `GET /api/v1/server/settings` (fresh state, not a bare status).

Two settings each require an explicit acknowledgment flag before a risky change is accepted, returned as `409` with both `error` and `risks`:

- Enabling `useHttps` while the configured certificate has flagged risks, without `acknowledgeRisks: true`.
- Turning off an already-enabled `requireIngestionToken`, without `acknowledgeIngestionTokenRisk: true` - since that removes authentication from both inventory-ingestion endpoints.

Other validation errors (`400 {"error": "..."}`) cover out-of-range numeric fields (`staleHours` 1-8760, `port`/`httpsPort` 1-65535, `installLogRetentionDays` 1-3650, `ingestionRejectionLogRetentionDays` 1-3650, `ingestionRejectionLogMaxEntries` 100-100000, `softwareJobAttemptLogRetentionDays` 1-3650, `softwareJobAttemptLogMaxEntries` 100-100000, `debugLogRetentionDays` 1-3650, `debugLogMaxSizeMb` 1-100, `adSyncIntervalHours` 1-8760, `linuxDefaultIntervalHours` 1-24, `linuxDefaultStatusIntervalMinutes` 1-1440, `loginLockoutThreshold` 0-1000, `loginLockoutWindowMinutes`/`loginLockoutDurationMinutes` 1-1440, `sessionLifetimeHours` 1-720, `hstsMaxAgeHours` 1-8760, `windowsUpdateCheckIntervalHours`/`thirdPartySoftwareCheckIntervalHours` 1-24, `windowsUpdateInstallWindowJitterMinutes`/`thirdPartySoftwareInstallWindowJitterMinutes` 0-1440), a malformed `preferredLinuxSubnet` (must be blank or a valid IPv4 CIDR, e.g. `192.168.1.0/24`), an empty or non-absolute `linuxDefaultInstallPath` (must start with `/`), `windowsUpdateInstallWindowStartUtc`/`windowsUpdateInstallWindowEndUtc` or `thirdPartySoftwareInstallWindowStartUtc`/`thirdPartySoftwareInstallWindowEndUtc` not in `HH:mm` format (each pair checked only when its own `...InstallWindowEnabled` is `true` - turning a window off is never blocked by stale or blank time fields left over from before), disabling HTTP while HTTPS is also off or not working (would make the dashboard unreachable), and HTTP/HTTPS ports colliding when both are enabled.

```bash
curl -X GET https://server:8443/api/v1/server/settings -u admin:password
```

```bash
curl -X POST https://server:8443/api/v1/server/settings \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"staleHours":48, "adSyncEnabled":true, "adSyncMode":"timer", "adSyncIntervalHours":6}'
```

### GET /api/v1/server/admin-password and POST /api/v1/server/admin-password

GET returns `{"configured": ..., "username": ...}` - never the password. POST doubles as first-time setup and password rotation: body is `newUsername`, `newPassword` (minimum 8 characters), and `currentPassword` (required only if an admin account is already configured, checked with a constant-time comparison). `401 {"error": "current password is incorrect"}` on a wrong current password. Response on success is the same shape as the GET.

### GET /api/v1/server/ingestion-token and POST /api/v1/server/ingestion-token/regenerate

GET returns `{"configured": ..., "token": ..., "requireIngestionToken": ...}` - unlike the admin password and certificate endpoints, this one returns the actual live token value in plaintext, by design: it exists so an operator can copy it into client configuration. Anyone with valid Basic Auth credentials can read it back.

POST generates a new 64-character random token, persists it, and only then swaps it into the live in-memory value (so a persist failure never leaves running clients failing against a token that was never actually saved). Response: `{"token": "<new token>"}`. Existing clients stop being able to submit inventory until reconfigured with the new token.

```bash
curl -X POST https://server:8443/api/v1/server/ingestion-token/regenerate -u admin:password
```

### GET /api/v1/server/enrollment-token and POST /api/v1/server/enrollment-token/regenerate

GET returns `{"configured": ..., "token": ...}` - the actual live value, same "visible to any authenticated admin session" posture as the ingestion token above (this is a bootstrap secret for `POST /api/v1/client/enroll` only, not a credential that itself grants inventory access). POST generates a new random value and persists it (encrypted at rest, same as `Token`); unlike regenerating the ingestion token, this has no effect on any already-enrolled client - each already has its own real per-machine token. It does invalidate any not-yet-used copy still sitting in an undeployed or stale GPO package, which must be rebuilt (`New-ClientGpoPackage.ps1 -EnrollmentToken`) before it can enroll anything.

```bash
curl -X POST https://server:8443/api/v1/server/enrollment-token/regenerate -u admin:password
```

### GET /api/v1/client-tokens and DELETE /api/v1/client-tokens/{computerName}

GET returns `{"tokens": [{"computerName": ..., "issuedAtUtc": ...}, ...]}` - every machine that has ever enrolled, newest and oldest side by side with no particular order guaranteed. The token value itself is never included; unlike the shared ingestion token, a per-machine token has no legitimate reason to ever be displayed back once issued. DELETE revokes one machine's token immediately - it stops authenticating on its very next request. `404 {"error": "no token found for that computer name"}` if nothing is on record for that name. The machine can re-enroll and receive a fresh token at any time, as long as `EnrollmentToken` is still configured; this is a point-in-time revoke, not a permanent per-machine ban.

```bash
curl -X DELETE "https://server:8443/api/v1/client-tokens/PC-01" -u admin:password
```

### GET /api/v1/server/ingestion-rejections

Returns the server's log of rejected ingestion-token attempts, most-recent-first: `{"entries": [...]}` where each entry has `timestampUtc`, `sourceIp`, `hostname` (a best-effort reverse-DNS lookup of `sourceIp` - can be `null`; an attacker controls what PTR record their own IP resolves to, if any, so never treat it as a verified identity), `endpoint` (which ingestion route), `reason` (`"missing"` or `"mismatched"`), and `matchedClient` (the known client's name if matched by source IP, else `null`). `ingestionRejectionLogRetentionDays` and `ingestionRejectionLogMaxEntries` are targets the log is kept close to, not an exact real-time bound: both are re-checked on every new rejection and again at server startup (not on a timer), and the count cap is enforced in batches for write efficiency, so entry count can transiently run over `ingestionRejectionLogMaxEntries` by a small margin, or entries can briefly outlive `ingestionRejectionLogRetentionDays`, between prune passes.

### DELETE /api/v1/server/ingestion-rejections

Clears the Ingestion Rejections log immediately, independent of `ingestionRejectionLogRetentionDays`/`ingestionRejectionLogMaxEntries`. Response: `{"status": "cleared", "clearedCount": N}`. Recorded to the debug log (category `Server`) when it happens.

### GET /api/v1/server/debug-log

Returns the current content of the optional debug log (`debugLogEnabled`/`debugLogPath` above): `{content, sizeBytes, path}`, where `content` is the raw file text (not parsed into lines), `sizeBytes` is the file's current size on disk, and `path` is the resolved file path (`DebugLogPath` if set, otherwise `DataPath\_logs\debug.log`). `content` is an empty string, not an error, before the debug log has ever been enabled or written - the same "nothing yet" convention the other logs on this page use. The file is automatically bounded by `debugLogRetentionDays` and `debugLogMaxSizeMb` (see `POST /api/v1/server/settings` above) the same way `ingestionRejectionLogRetentionDays`/`ingestionRejectionLogMaxEntries` bound the rejection log just above - oldest lines are dropped first, checked opportunistically on write rather than on a timer, so the file can transiently exceed the configured size by a small margin between prune passes.

```bash
curl -X GET https://server:8443/api/v1/server/debug-log -u admin:password
```

### DELETE /api/v1/server/debug-log

Deletes the debug log file immediately, regardless of `debugLogEnabled`'s current value. Response: `{"status": "cleared", "clearedCount": N}` where `N` is the number of lines the file had. Recorded to the debug log (category `Server`) AFTER the delete - if debug logging is currently on, this becomes the new file's first line, proving exactly when and that it was cleared.

### POST /api/v1/server/login

Establishes a server-side session with valid dashboard admin credentials. Request body: `{username, password}` (both required). Subject to the same cross-site request checks and `LoginLockoutThreshold` rate limiting as every other state-changing route (see "Cross-site request checks" and "Login lockout" under Conventions above) - unlike the three ingestion endpoints and `POST /api/v1/client/software-jobs/results`, this route is not exempt from either.

Success response: `200` with `Set-Cookie: wil_session=...` in response headers and `Cache-Control: no-store`. The cookie carries `HttpOnly` and `SameSite=Strict` flags. Over HTTPS, it also carries the `Secure` flag; over plain HTTP, the flag is omitted and the cookie travels in cleartext, the same as Basic Auth credentials already do. Response body: `{"status": "ok"}`.

Failure response: `401` with body `Unauthorized` (plain text, not JSON) - the same `SendUnauthorized` response every other unauthenticated request in this API gets, including the Basic Auth `401` case documented under Conventions above. Failed attempts are rate-limited per source IP using the same lockout mechanism as Basic Auth (see "Login lockout" under Conventions above). A malformed (non-JSON, or JSON that doesn't decode to an object) request body gets `400 {"error": "invalid request body"}` instead, the same shape used elsewhere in this API.

Loopback-only mode: Always returns `401` when both `WebUsername` and `WebPassword` are unconfigured, even with correct credentials - a session cookie would bypass the IP-based loopback restriction, so the endpoint does not issue one until credentials are configured.

```bash
curl -X POST https://server:8443/api/v1/server/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin", "password":"password"}'
```

### POST /api/v1/server/logout

Invalidates the server-side session and clears the session cookie. No request body required. Reachable the same way as every other management endpoint documented here - a valid session cookie or Basic Auth is required to reach the handler at all; unlike `/api/v1/server/login`, this route is dispatched after the `IsWebRequestAuthorized` check, with no unauthenticated carve-out.

Response: always `200` with body `{"status": "ok"}`. Logout is idempotent - logging out an already-missing or expired session is a no-op success, not an error. The response includes a cookie-clearing `Set-Cookie: wil_session=` header.

```bash
curl -X POST https://server:8443/api/v1/server/logout \
  -u admin:password \
  -H "Content-Type: application/json"
```

## AD computer import

### GET /api/v1/ad/computers

Searches Active Directory for computer objects under the configured Organizational Units (`adComputerImportOUs`), for import into the dashboard. `400 {"error": "Check \"Configure AD User\" in Settings > Windows > Active Directory first."}` if `adSyncEnabled` is off. On success: `{"computers": [...], "warnings": [...]}`. If every configured OU lookup fails, returns `500 {"error": "<joined warning text>"}` instead of an empty result, so a total AD outage is distinguishable from "no computers found."

## Licenses

### GET /api/v1/licenses

Returns `{"licenses": [...]}`, each record `{id, name, version, license, comment, computers, detectedComputers, createdAt, updatedAt}`. There is no `expiresAt` or `seats` field - license records here are a flat catalog of admin-entered product keys, not a license-enforcement structure.

`detectedComputers` (since 0.96.0) is purely computed, never persisted to `licenses.json` and never accepted on `POST`/`PUT` - the live set of machines currently reporting a client-side activation entry whose `product`/decrypted key match this record's own `name`/`license` (case-insensitive, trimmed - the same convention the dashboard's own "Add to licenses" matching already uses). Deliberately independent of `computers` (the static, admin-owned field set by `POST`/`PUT`/"Add to licenses"): nothing is ever written into `computers` just because a machine appears here, and a machine that stops reporting the key simply stops appearing in `detectedComputers` on the next request - no automatic add or prune of the stored field, by design.

### POST /api/v1/licenses

Creates a record. Request body: `name` (required), `version`, `license`, `comment` (all optional, default empty string), `computers` (optional array, trimmed and de-duplicated case-insensitively). `id` is always server-generated (`Guid.NewGuid`), never client-supplied. Response is the created record itself. `400 {"error": "name is required"}` if `name` is empty after trimming.

```bash
curl -X POST https://server:8443/api/v1/licenses \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"name":"Microsoft Office 2021", "version":"2021", "license":"XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", "computers":["WORKSTATION01"]}'
```

### PUT /api/v1/licenses/{id} and DELETE /api/v1/licenses/{id}

`{id}` is matched case-insensitively against stored records; it is not validated as a GUID, so any string that matches an existing `id` works. PUT accepts the same fields as POST (`name` required) and preserves the original `id`/`createdAt`; response is the updated record. DELETE removes the matching record; response is `{"status": "deleted"}`. Both return `404 {"error": "license not found"}` for an unknown ID.

All four license endpoints read and write one JSON array file (`licenses.json`) under a single lock, and every write re-applies a restricted file ACL - license keys are stored in plaintext JSON on disk, protected only by filesystem permissions.

## License key sources

Admin-managed catalog telling Windows clients which registry values to read for automatic third-party license key collection. Distinct from the `/api/v1/licenses` catalog above: entries here hold no secret material themselves (just a registry location to check), only `_license-key-sources/license-key-sources.json`, and unlike `licenses.json` do not get a restricted file ACL. The current catalog (trimmed to `product`/`registryHive`/`registryPath`/`valueName`) is also returned to every Windows client on its next `POST /api/v1/inventory` response - see that endpoint above.

### GET /api/v1/license-key-sources

Returns `{"licenseKeySources": [...]}`, each record `{id, product, registryHive, registryPath, valueName, createdAt, updatedAt}`.

### POST /api/v1/license-key-sources

Creates a catalog entry. Request body: `product`, `registryHive`, `registryPath`, `valueName` (all required). `registryHive` must be `HKEY_LOCAL_MACHINE` or `HKEY_CURRENT_USER`. `id` is always server-generated (`Guid.NewGuid`), never client-supplied. Response is the created record itself. `400 {"error": "product is required"}` / `{"error": "registryHive must be HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER"}` / `{"error": "registryPath is required"}` / `{"error": "valueName is required"}` for the respective missing/invalid field, checked in that order.

```bash
curl -X POST https://server:8443/api/v1/license-key-sources \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"product":"KriptoPro CSP", "registryHive":"HKEY_LOCAL_MACHINE", "registryPath":"SOFTWARE\\WOW6432Node\\Crypto Pro\\Cryptography\\CurrentVersion", "valueName":"WLProductID"}'
```

### PUT /api/v1/license-key-sources/{id} and DELETE /api/v1/license-key-sources/{id}

`{id}` is matched case-insensitively against stored records. PUT accepts the same fields as POST (all required) and preserves the original `id`/`createdAt`; response is the updated record. DELETE removes the matching record; response is `{"status": "deleted"}`. Both return `404 {"error": "license key source not found"}` for an unknown ID.

All four endpoints read and write one JSON array file (`_license-key-sources/license-key-sources.json`) under a single lock, same full-array-rewrite pattern as `licenses.json`.

## Software distribution

Added in v0.56.0. Two admin-managed catalogs (Windows Updates, Third-Party Software) name installer files on a UNC share; targeted Windows clients poll for their assignments, copy the file locally, run it, and report the result back. The server never connects outbound to a client for this feature - the opposite direction from Operations > Agent Actions > Actions. See `docs/threat-model.md` for the trust boundary (the share's own write-ACL) before enabling it.

### GET /api/v1/software-repository/settings

Returns `{path, username, hasPassword, scanIntervalMinutes}`. The password itself is never returned here - only `hasPassword`. `username` is `null` (not `""`) when unset.

### POST /api/v1/software-repository/settings

Sets the share location and credentials. Body fields, all optional: `path`, `username`, `password`, `scanIntervalMinutes`, `clear`. Every omitted field keeps its current value; an omitted or empty `password` also keeps the stored one, so the dashboard can save the form without re-typing it. `clear: true` wipes username and password (leaving `path` alone). `scanIntervalMinutes` must be 5-1440 - an out-of-range or unparseable value is silently ignored and the current value kept, not rejected. The stored password is DPAPI-encrypted at rest. Saving reconfigures the background scan timer immediately. Response is the same shape as the GET.

```bash
curl -X POST https://server:8443/api/v1/software-repository/settings \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"path":"\\\\fileserver\\software", "username":"CORP\\svc-software", "password":"...", "scanIntervalMinutes":60}'
```

### GET /api/v1/software-repository/scan-status

Returns the last scan's result without starting a new one: `{success, errorMessage, scannedAt, lastSuccessfulScanAt, windowsUpdateCandidates, thirdPartySoftwareCandidates}`. The two candidate arrays hold share-relative paths of files no catalog entry's `relativePath` references yet. A failed scan does not clear them - `success`/`errorMessage`/`scannedAt` describe the latest attempt while the candidate lists and `lastSuccessfulScanAt` carry forward from the last successful one. Both timestamps are `null` before the first scan.

### POST /api/v1/software-repository/scan

Runs a scan synchronously and returns the same shape as the status endpoint. Takes no body. Lists `<path>\windows-updates\` and `<path>\third-party-software\`.

### GET /api/v1/software-repository/attempt-history

Returns `{"attempts": [...]}`, each `{timestampUtc, computerName, catalogType, entryId, success, exitCode, errorMessage, diagnosticHint, installerFormat, exitCodeMeaning}`, oldest first. `catalogType` is `windowsUpdate` or `thirdPartySoftware`. `diagnosticHint` (nullable string, added in 0.82.0) is set when this attempt's failure matches the "stuck single-instance install lock" signature - either the immediately preceding completed attempt for the same computer+entry was killed by the 30-minute install timeout, or that preceding attempt already carried this same hint with a matching exit code (0.82.1+: the hint carries forward through a whole repeated-failure chain, not just the first attempt right after the kill, stopping the moment the exit code genuinely changes). `installerFormat` (nullable string) is the installer's packaging format reported by the client (the lowercased file extension of the catalog entry's relativePath, without the leading dot - e.g. `msi`, `msu`, `cab`, `exe`), persisted like any other field here. `exitCodeMeaning` (nullable string) is computed fresh on every read of this endpoint from a small built-in, format-keyed lookup table (deliberately not exhaustive) - it is NEVER persisted, so improving the table's wording later instantly applies to already-recorded history too. Capped at 5000 entries and 90 days, pruned on write.

### DELETE /api/v1/software-repository/attempt-history

Clears the Software job attempt log immediately, independent of its own 5000-entry/90-day cap. Response: `{"status": "cleared", "clearedCount": N}`. Recorded to the debug log (category `Server`) when it happens.

### GET /api/v1/windows-updates and GET /api/v1/third-party-software

Return `{"windowsUpdates": [...]}` / `{"thirdPartySoftware": [...]}`, each record `{id, name, relativePath, arguments, requiresReboot, enabled, targets, createdAt, updatedAt}`.

### POST /api/v1/windows-updates and POST /api/v1/third-party-software

Create a catalog entry. Body: `name` and `relativePath` are required; `arguments`, `targets` default to `""`, `requiresReboot` to `false`, `enabled` to `true` when omitted. `id`, `createdAt`, and `updatedAt` are always server-generated, never client-supplied. `relativePath` is share-relative (for example `windows-updates\kb5001716.msu`) - the client rejects a rooted path at run time. Response is the created record.

`targets` is the same plain delimited text `ExpandInstallTargets` parses for Operations > Agent Actions > Actions, but restricted here to computer names: any token that expands to something `IPAddress.TryParse` accepts is rejected with `400 {"error": "targets must be computer names - ..."}`, naming the offending value. A mixed list is rejected outright rather than partly accepted. The reason is directional - this feature matches a client's own self-reported computer name against the list, so an IP address could never match anything. Other validation: `400 {"error": "name is required"}` / `{"error": "relativePath is required"}` / `{"error": "invalid request body"}`.

```bash
curl -X POST https://server:8443/api/v1/windows-updates \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"name":"KB5001716", "relativePath":"windows-updates\\kb5001716.msu", "arguments":"/quiet /norestart", "requiresReboot":true, "enabled":true, "targets":"PC-01, PC-02"}'
```

### PUT and DELETE /api/v1/windows-updates/{id}, /api/v1/third-party-software/{id}

`{id}` is matched case-insensitively against stored records. PUT accepts the same fields and the same validation as POST, preserves `id`/`createdAt`, and sets `updatedAt` to now; response is the updated record. DELETE responds `{"status": "deleted"}`. Both return `404 {"error": "windows update entry not found"}` / `{"error": "third-party software entry not found"}` for an unknown ID.

The `updatedAt` bump on PUT is load-bearing, not bookkeeping: clients cache successful runs by `id` + `updatedAt`, so editing an entry in place is what makes machines that already ran the old version run the corrected one.

### GET /api/v1/client/windows-update-jobs, GET /api/v1/client/third-party-software-jobs

Client-facing. Split by catalog type in v0.81.0 - each endpoint replaces its half of the earlier combined `GET /api/v1/client/software-jobs` (removed outright, no compatibility shim) and is gated by that catalog's own `windowsUpdateInstallWindow*`/`thirdPartySoftwareInstallWindow*` setting independently (see `POST /api/v1/server/settings` above) - a job can be withheld from one catalog's response while the other catalog's jobs for the same computer are admitted, or vice versa.

Query parameter `computerName` is required on both (`400 {"error": "computerName is required"}` otherwise). Both return `{"jobs": [...]}`, each `{id, updatedAt, catalogType, relativePath, arguments, requiresReboot, contentSha256}`, filtered to entries of that endpoint's own catalog type that are `enabled` and whose expanded `targets` contain that computer name (case-insensitive). An unknown computer name returns an empty array, not a 404. `GET /api/v1/client/windows-update-jobs` additionally returns `wsusCabHash`, `wsusScanMaxAgeDays`, and `forceWsusRescan` (the WSUS-scan-freshness fields - unrelated to this split, `thirdPartySoftware` has no equivalent).

`contentSha256` (since 1.0.2) is the SHA256 of the entry's file, computed once at an admin-trusted boundary (catalog entry save, or the server's own WSUS re-download) - never recomputed per job poll. Empty string for an entry saved before this feature existed, or whose file wasn't reachable at save time; a client that sees an empty value skips verification for that one job rather than refusing it. See "Client self-update" below's sibling mechanism (self-update's own hash/signature check) for the same general pattern applied to a different content path.

### POST /api/v1/client/software-jobs/results

Client-facing. Body: `{computerName, results: [{id, catalogType, success, exitCode, errorMessage}, ...]}`. Each result is appended to the attempt-history log; `id` here is the plain catalog entry id. A missing or non-array `results` is accepted as a no-op. Response is `{"status": "ok"}`. Like the three inventory-ingestion endpoints, this route is dispatched before the auth/CSRF gate and is therefore exempt from the cross-site request and Content-Type checks (see Conventions above).

### GET /api/v1/client/software-download

Client-facing (since 1.0.2). Query parameters `catalogType` (`windowsUpdate` or `thirdPartySoftware`, case-insensitive) and `id` (the catalog entry's own id) - both required. Streams the entry's resolved file (`application/octet-stream`) using the server's own repository identity; the caller never needs or receives the share credential. `404` for an unrecognized/missing `catalogType`, `404` if no entry with that `id` exists in that catalog, `404 {"error": "catalog entry's file was not found on disk"}` if the entry exists but its file isn't currently reachable (a legitimately not-yet-uploaded file, not an error condition worth a 500), `500` for any other read failure (e.g. a misconfigured repository identity). This is the endpoint the Windows client uses to retrieve installer content as of this version - see "Client self-update" below for the same "download, then verify before trusting" shape applied to client binaries instead of job installers.

### GET /api/v1/client/software-repository-connection

Client-facing. Returns `{path, username, password}` with the share password **in plaintext** - the client needs it to read installers from the share. Empty strings, not `null`, when unset. This is the endpoint the "always requires a token" rule under "Auth models" exists for; read the corresponding `docs/threat-model.md` bullet, including the unresolved question about this credential crossing a plain-HTTP deployment, before deploying this feature.

**Deprecated as of 1.0.2 / Windows client 0.18.1**: a client at this version or later calls `GET /api/v1/client/software-download` instead and never calls this endpoint at all. Left in place, unchanged, only so a client that hasn't yet self-updated past this round keeps working during rollout - removing it entirely is a separate, later item once the whole fleet has moved on (see `docs/backlog.md`).
