# AD Description sync — design

Status: draft, approved by owner, not yet planned or implemented.

## Purpose

Show each computer's Active Directory `description` attribute (the free-text note admins often keep in AD — location, owner, asset tag) next to its inventory record, so the dashboard doesn't require a separate AD lookup to answer "what is this machine, and where is it."

## Scope

- Read-only. The dashboard never writes back to AD.
- One AD attribute: `description`. Not a general-purpose AD attribute browser.
- Enrichment of the existing Clients table, not a standalone AD search tool. "Search by name" describes the lookup mechanism (LDAP filter on `cn`), not a user-facing search UI.
- Opt-in: disabled by default. Deployments without AD, or with a server that isn't domain-joined, are unaffected.

## Architecture

A new server-side component, `AdLookupService`, wraps `System.DirectoryServices.DirectorySearcher` — part of the base .NET Framework, no NuGet package, consistent with the project's no-external-dependency approach used everywhere else (HTTP server, WinRM, ZIP building).

Two sync modes, selectable in settings, sharing one sync function and one interval:

- **On inventory report** (default). When a client POSTs `/api/v1/inventory`, the server checks the cached AD fields already on that computer's saved report (if any). If missing or older than `AdSyncIntervalHours`, it performs the LDAP lookup and writes the result alongside the client's own data in the same file write. No new background thread; reuses the existing report cadence (`IntervalHours` on the client, typically every few hours).
- **Periodic timer**. A `System.Threading.Timer` (the first of its kind in this project — there's no existing periodic-job infrastructure) fires every `AdSyncIntervalHours`, walks every `*.json` in `DataPath`, and applies the same freshness check per computer. Needed for computers that still exist in AD but have stopped reporting inventory (otherwise their AD data would never refresh, only ever the value from their last report).

Either mode can be selected in Settings > General; the default is "on inventory report" since it needs no new background thread and self-paces to the fleet's own reporting rhythm.

## Data model

New fields on each computer's saved report (`DataPath\<computer>.json`), written by the **server**, never by the client:

```json
"adDescription": "Finance dept, room 214, asset #4521",
"adSyncedAt": "2026-07-15T09:00:00Z",
"adSyncStatus": "ok"
```

`adSyncStatus` is one of `"ok"`, `"not-found"` (no matching computer object in AD), or `"error"` (AD unreachable / timed out). A separate status field, not just an empty `adDescription`, because those are three different situations an admin needs to tell apart in the Clients table, and collapsing them into "blank" would hide that difference.

Since the client's own POST body doesn't include these fields, and `ReceiveInventory` writes the client's JSON to disk, the server must explicitly carry `adDescription`/`adSyncedAt`/`adSyncStatus` forward from the previous saved file into the new one whenever the sync-freshness check says "skip" — otherwise every client report would silently wipe the cached AD data.

## Settings

Extends the existing `GET/POST /api/v1/server/settings` endpoint and `server-config.json` (same file, same pattern as `StaleHours`/`HttpsPort`/etc.):

| Field | Type | Default |
| --- | --- | --- |
| `AdSyncEnabled` | bool | `false` |
| `AdSyncMode` | `"on-report"` \| `"timer"` | `"on-report"` |
| `AdSyncIntervalHours` | int | `24` |
| `AdDomain` | string | `""` (empty = auto-detect the server's own domain) |
| `AdUseServiceIdentity` | bool | `true` |
| `AdUsername` / `AdPassword` | string | used only when `AdUseServiceIdentity` is `false` |

`AdPassword` is stored in `server-config.json` in plaintext, the same precedent already accepted for `WebPassword` and `Token` — documented risk, mitigated by restricting the file's ACL (already done for the whole config file). Like other password fields in this app's settings API, it should be write-only: never echoed back by `GET /api/v1/server/settings`.

## UI

**Settings > General**, a new block "Active Directory" after the existing HTTPS block, same visual pattern (`settings-block`, checkboxes/fields, a hint paragraph):

- `Enable AD sync` (checkbox)
- `Sync mode` (select: "On inventory report" / "Periodic timer")
- `Sync interval (hours)`
- `Domain` (optional text field, hint: "leave blank to use the server's own domain")
- `Use service account identity` (checkbox); unchecking reveals `AD username` / `AD password` fields

**Clients table**: new "AD Description" column. Renders the description text normally; for `not-found`/`error` status, shows a muted placeholder ("Not found in AD" / "AD unreachable") instead of a value. CSV export gets the same column.

## Security

**LDAP injection.** The computer name used to build the LDAP filter (`(&(objectCategory=computer)(cn={name}))`) comes from the client's own report (`Environment.MachineName`) - the same class of semi-trusted, attacker-influenceable input this project has already hardened elsewhere this cycle (CSV formula injection, reserved Windows device names in file paths). Without escaping LDAP special characters (`\`, `*`, `(`, `)`, NUL per RFC 4515) before building the filter, a maliciously-named reporting host could distort the search filter. A dedicated escaping function is required, with a self-test - matching the existing pattern for `SanitizeFileName`/`NormalizeThumbprint`.

**Availability.** An unreachable or slow AD must not block inventory ingestion. The LDAP query runs with a bounded timeout (mirroring the existing 30-second socket timeout used elsewhere in the server); a failure is logged to the Event Log and recorded as `adSyncStatus: "error"`, but the client's report is saved regardless.

**Least privilege.** Reading the `description` attribute of computer objects is normally allowed to any authenticated domain user by default AD ACLs, so the service-identity path (the default) typically needs no special AD delegation beyond the service account already being domain-joined, which WinRM client actions already require.

## Testing

- Self-test for the LDAP filter-escaping function (all RFC 4515 special characters, plus a clean passthrough case) - same style as the existing `SanitizeFileName`/`NormalizeThumbprint` self-tests.
- Self-test for the freshness check (missing timestamp, stale timestamp, fresh timestamp → sync / sync / skip).
- Manual/live verification against a real AD, since this sandbox has no directory service to test against - same limitation already noted for TLS private-key operations earlier in this project's history.

## Open questions for the implementation plan

- Exact wording for the two placeholder states in the Clients table.
- Whether `AdSyncIntervalHours` needs its own min/max validation range (existing settings fields all validate bounds).
- Whether the timer mode needs a "sync now" manual trigger in the UI, or whether waiting for the next tick/report is acceptable.
