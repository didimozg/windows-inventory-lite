# API Reference

This is a practical lookup document for the server's HTTP API, not an OpenAPI/Swagger spec. It covers the real, current route surface: 53 routes (44 exact-match paths, 9 with a parameterized path segment). It does not cover the static dashboard asset routes (`/`, `/app.js`, `/styles.css`, `/favicon.svg`), which serve dashboard files rather than API data.

## Conventions

**Auth models.** Two separate models are in use, and a route uses exactly one of them:

- **Basic Auth** guards the dashboard/management surface: every route below except the three inventory-ingestion endpoints. It is checked once, centrally, by `IsWebRequestAuthorized` before the request reaches any handler. A missing or wrong `Authorization: Basic ...` header gets a `401` with body `Unauthorized` (plain text, not JSON) and a `WWW-Authenticate: Basic` header. If no admin username/password has been configured yet, this check instead falls back to restricting the route to the local machine (loopback) only.
- **Ingestion token** guards the three inventory-ingestion endpoints only, via the `X-Inventory-Token` request header, checked inside each handler before Basic Auth would otherwise apply (these routes are dispatched before the Basic Auth check runs at all). Enforcement is controlled by the `RequireIngestionToken` server setting; when it is off, these three endpoints accept any request unauthenticated. A rejected token also gets a `401` with plain-text body `Unauthorized`, not the JSON error shape below.

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

### Clients & inventory data

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/clients` | Basic Auth | Return the Windows client inventory index. |
| PUT | `/api/v1/clients/{computerName}/description` | Basic Auth | Set a manual description override for one Windows client. |
| DELETE | `/api/v1/clients/{computerName}` | Basic Auth | Delete one Windows client's stored report. |
| GET | `/api/v1/linux/clients` | Basic Auth | Return the Linux client inventory index. |
| PUT | `/api/v1/linux/clients/{hostname}/description` | Basic Auth | Set a manual description override for one Linux client. |
| DELETE | `/api/v1/linux/clients/{hostname}` | Basic Auth | Delete one Linux client's stored report. |

### Windows client install/update

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/client-install` | Basic Auth | Queue a WinRM push-install job against one or more Windows targets. |
| POST | `/api/v1/client-uninstall` | Basic Auth | Queue a WinRM push-uninstall job. |
| GET | `/api/v1/client-install` | Basic Auth | List recent install/uninstall job summaries. |
| GET | `/api/v1/client-install/{jobId}` | Basic Auth | Return full detail for one install/uninstall job. |
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

### Linux client install/update

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/linux-client-install` | Basic Auth | Queue an SSH push-install job against one or more Linux targets. |
| POST | `/api/v1/linux-client-uninstall` | Basic Auth | Queue an SSH push-uninstall job. |
| POST | `/api/v1/linux-client-install/trust-host-key` | Basic Auth | Manually trust (pin) a Linux target's SSH host key. |
| GET | `/api/v1/linux-client-install` | Basic Auth | List recent Linux install/uninstall job summaries. |
| GET | `/api/v1/linux-client-install/{jobId}` | Basic Auth | Return full detail for one Linux install/uninstall job. |
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

## Inventory ingestion

### POST /api/v1/inventory

Accepts a Windows client's full inventory report as the request body (an arbitrary JSON object; the only field the server reads directly is `computerName`, used to name the stored file) and overwrites `{DataPath}/{computerName}.json` with it, after merging in the current AD-sync fields (`adDescription`, `adSyncStatus`, `adSyncedAt`) so a client's own report never has to know about AD sync.

- Auth: `X-Inventory-Token` header, checked against the configured token when `RequireIngestionToken` is on.
- Response: `{"status": "ok"}` on success. `400 {"error": "invalid request body"}` if the body is not valid JSON.

```bash
curl -X POST https://server:8443/api/v1/inventory \
  -H "X-Inventory-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"computerName":"WORKSTATION01", "...": "..."}'
```

### POST /api/v1/linux/inventory

Same behavior as `/api/v1/inventory`, for Linux clients: reads `hostname` from the body to name the stored file (`{LinuxDataPath}/{hostname}.json`), merges AD-sync fields, overwrites the file.

- Auth and response shape: identical to `/api/v1/inventory`.

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

Returns the full Windows client inventory index in one response. Top-level fields: `schemaVersion`, `serverVersion`, `generatedAt`, `clientCount`, `staleHours`, `adDescriptionSyncEnabled`, and `clients` - an array where each entry is a client's stored inventory report (the report body as last submitted to `POST /api/v1/inventory`, plus `sourceFile` and `sourceUpdatedAt` added by the server, the latter from the report file's last-write time).

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

## Windows client install/update

### POST /api/v1/client-install and POST /api/v1/client-uninstall

Both routes share one handler, distinguished only by which action it runs. Request body fields: `targets` (free-text, newline/comma/space-separated computer names, supports IP ranges), `serverUrl` (required for install, not for uninstall), `username`/`password` (optional; falls back to saved WinRM update credentials or an AD service identity, see `useSavedCredentials`/`useAdCredentials`), `force`, `addToTrustedHosts`, `retentionDays`.

The response comes back immediately with a job ID; the actual WinRM install/uninstall work happens asynchronously on a background thread pool, tracked by that job:

```json
{"jobId": "a1b2c3...", "status": "queued"}
```

If `username`/`password` end up blank, the install runs without a WinRM `-Credential`, i.e. as whatever identity the server's own Windows service runs as - not rejected as an error. `serverUrl` and other string inputs are validated against a small unsafe-character set before being interpolated into the generated PowerShell/cmd invocation, and a validation failure comes back as `400 {"error": "at least one target is required"}` or a similar message describing which field failed.

```bash
curl -X POST https://server:8443/api/v1/client-install \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"targets":"192.168.1.10-20", "serverUrl":"https://server:8443", "useSavedCredentials":true}'
```

```bash
curl -X POST https://server:8443/api/v1/client-uninstall \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"targets":"WORKSTATION01", "useSavedCredentials":true}'
```

### GET /api/v1/client-install

Lists install/uninstall job summaries: `{"defaultRetentionDays": ..., "jobs": [...]}`. Each summary has `id`, `action`, `status`, `createdAt`, `startedAt`, `completedAt`, `serverUrl`, `username`, `retentionDays`, `targetCount`, `resultCount`, `failedCount` - counts only, not the full per-target result list. As a side effect, every call also prunes job files older than their retention window from disk.

### GET /api/v1/client-install/{jobId}

Returns one job's full detail, including the per-target `results` array (with `target`, `status`, `output`, `error` per target). Neither this endpoint nor the list endpoint above ever returns a `password` field. `404 {"error": "job not found"}` if the ID matches neither an in-memory job nor a persisted job file.

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

## Linux client install/update

### POST /api/v1/linux-client-install and POST /api/v1/linux-client-uninstall

Shared handler, SSH-based equivalent of the Windows install/uninstall pair. Request body: `targets`, `authMode` (`"ad"`, `"credentials"`, or `"key"`, default `"credentials"`), `username`/`password` (for `credentials`/`key` modes; `key` mode uses the server's stored SSH private key file and needs only `username`), `serverUrl` (falls back to the saved package `serverUrl` for install if omitted), `token` (falls back to the live server token), `installPath` (default `/opt/windows-inventory-lite`), `intervalHours`, `statusIntervalMinutes`, and, for install only, `trustNewHostKeys` plus `acknowledgeHostKeyRisk` (both must be set together to let a first-contact SSH host key be auto-trusted instead of failing).

Same async job pattern as the Windows endpoints: immediate `{"jobId": "...", "status": "queued"}`, work runs in the background. A first install attempt against a never-seen host fails with a per-target result carrying `hostKeyStatus: "unknown"` and a `hostKeyFingerprint` - the dashboard is expected to feed that into `trust-host-key` (below) before retrying, unless `trustNewHostKeys`/`acknowledgeHostKeyRisk` were set on the original request.

```bash
curl -X POST https://server:8443/api/v1/linux-client-install \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"targets":"web01.example.com", "authMode":"credentials", "username":"deploy", "password":"...", "serverUrl":"https://server:8443"}'
```

```bash
curl -X POST https://server:8443/api/v1/linux-client-uninstall \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"targets":"web01.example.com", "authMode":"key", "username":"deploy"}'
```

### POST /api/v1/linux-client-install/trust-host-key

Manually pins a Linux target's SSH host key (TOFU/known-hosts style), a prerequisite for non-key-auth installs against a host the server has never connected to before. Request body: `host` (required), `fingerprint` (required, must look like `SHA256:...`), `keyType` (default `ssh-ed25519`), `port` (default 22).

Stores the upserted record (`Host`, `Port`, `KeyType`, `Fingerprint`, `TrustedAtUtc`, `TrustMethod: "manual"`) and returns it directly as the response body. A subsequent install for that host pins the connection to this fingerprint; if the real key ever no longer matches, the result is classified `hostKeyStatus: "changed"` and is never auto-accepted, regardless of `trustNewHostKeys`.

```bash
curl -X POST https://server:8443/api/v1/linux-client-install/trust-host-key \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"host":"web01.example.com", "fingerprint":"SHA256:AbCdEf...", "keyType":"ssh-ed25519"}'
```

### GET /api/v1/linux-client-install and GET /api/v1/linux-client-install/{jobId}

Same shape and behavior as the Windows job list/detail endpoints. List summary fields: `id`, `action`, `status`, `createdAt`, `startedAt`, `completedAt`, `authMode`, `username`, `retentionDays`, `targetCount`, `resultCount`, `failedCount`. Detail adds `targets`, `results`, `serverUrl`, `installPath`, `trustNewHostKeys`. `password` and the SSH key path are never included in either response. `404 {"error": "job not found"}` on an unknown ID.

### GET /api/v1/linux-client-updates

Same purpose as the Windows equivalent: lists Linux clients on an outdated `clientVersion`. Fields: `currentVersion`, `lastScheduledJobId`, `packageAvailable`, `updates` (array of `{hostname, target, clientVersion, sourceUpdatedAt}` - `target` is the actual push address, which can differ from the self-reported `hostname`), `outdatedCount`.

### GET /api/v1/linux-client-updates/credentials and POST /api/v1/linux-client-updates/credentials

GET: `{"configured", "username", "hasPassword", "hasStoredKey", "keyUploadedAtUtc"}` - never the password or key contents. POST accepts `username`, `password` (blank keeps the existing one unless `clear` is set), `clear`.

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

### GET /api/v1/server/linux-ssh-tools-status

Checks the *server host's own* local tooling, not anything about a client: whether `plink.exe` and `pscp.exe` (the PuTTY-suite binaries the server uses to SSH out to Linux clients) are present at either the installed-server location or the dev-tree location next to the running assembly. Response: `{"plinkFound": ..., "pscpFound": ...}`.

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

Returns the general settings block: everything from the certificate status shape above, plus `staleHours`, `port`, `enableHttp`, `httpsPort`, `adSyncEnabled`, `adDescriptionSyncEnabled`, `adSyncMode`, `adSyncIntervalHours`, `adDomain`, `adUseServiceIdentity`, `adUsername` (`null` when using the service identity), `adPasswordConfigured` (boolean only, never the password itself), `adComputerImportOUs`, `installLogRetentionDays`, `debugLogEnabled`, `debugLogPath`. `requireIngestionToken` and the dashboard admin username/password are deliberately not part of this response - see the ingestion-token and admin-password endpoints below.

### POST /api/v1/server/settings

Updates any subset of the fields above (each key is only applied if present in the body), plus write-only fields `useHttps`/`acknowledgeRisks`, `requireIngestionToken`/`acknowledgeIngestionTokenRisk`, and `adPassword` (blank/omitted keeps the existing one). Response on success is the same shape as `GET /api/v1/server/settings` (fresh state, not a bare status).

Two settings each require an explicit acknowledgment flag before a risky change is accepted, returned as `409` with both `error` and `risks`:

- Enabling `useHttps` while the configured certificate has flagged risks, without `acknowledgeRisks: true`.
- Turning off an already-enabled `requireIngestionToken`, without `acknowledgeIngestionTokenRisk: true` - since that removes authentication from both inventory-ingestion endpoints.

Other validation errors (`400 {"error": "..."}`) cover out-of-range numeric fields (`staleHours` 1-8760, `port`/`httpsPort` 1-65535, `installLogRetentionDays` 1-3650, `adSyncIntervalHours` 1-8760), disabling HTTP while HTTPS is also off or not working (would make the dashboard unreachable), and HTTP/HTTPS ports colliding when both are enabled.

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

## AD computer import

### GET /api/v1/ad/computers

Searches Active Directory for computer objects under the configured Organizational Units (`adComputerImportOUs`), for import into the dashboard. `400 {"error": "Check \"Configure AD User\" in Settings > General > Active Directory first."}` if `adSyncEnabled` is off. On success: `{"computers": [...], "warnings": [...]}`. If every configured OU lookup fails, returns `500 {"error": "<joined warning text>"}` instead of an empty result, so a total AD outage is distinguishable from "no computers found."

## Licenses

### GET /api/v1/licenses

Returns `{"licenses": [...]}`, each record `{id, name, version, license, comment, computers, createdAt, updatedAt}`. There is no `expiresAt` or `seats` field - license records here are a flat catalog of admin-entered product keys, not a license-enforcement structure.

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
