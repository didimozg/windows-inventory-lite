# AD-Editable Description Design

**Goal:** Let an administrator manually edit a client's Description directly in the dashboard, for deployments that don't run AD Description Sync at all, or that want a manual fallback/override when it's temporarily disabled - without losing the ability to keep using AD credentials elsewhere (Client actions, Client updates, AD Computer Import) while AD Description Sync itself is off.

**Architecture:** Split the current single `AdSyncEnabled` flag into two independent flags: `AdSyncEnabled` keeps meaning "AD identity (domain/credentials) is configured," and a new `AdDescriptionSyncEnabled` means "periodically write AD's Description into client records." The Clients table's Description column becomes an inline-editable `<input>` whenever `AdDescriptionSyncEnabled` is `false`, saved through a new per-client endpoint; it stays plain, read-only text (labeled "AD Description") whenever the flag is `true`. As a direct consequence of decoupling AD-identity-availability from Description-sync, `Client updates` gains the same "Use global AD settings" checkbox `Client actions` already has (v0.20.0), so every WinRM-credential-consuming feature in the dashboard offers the same choice consistently.

**Tech Stack:** C# (.NET Framework 3.5/4.0, hand-rolled server), vanilla JS dashboard - unchanged from the rest of the project.

## Global Constraints

- `AdSyncEnabled` is repurposed, not removed: it keeps its existing storage key, config-load behavior, and every existing consumer that only needs "AD identity is configured" (`TryResolveAdSyncCredentials`, `AdLookupService.SearchComputers` via `SendAdComputers`). Its UI label changes from "Enable AD sync" to "Configure AD identity."
- A new flag, `AdDescriptionSyncEnabled` (bool, `ServerOptions` + `server-config.json`), gates only the periodic AD → Description write path (`RunAdSyncSweep`, the `on-report` sync branch in the inventory-ingestion path, and `ComputeAdSyncFields`/`ApplyAdSyncFields`). UI label: "Sync Description from AD."
- **Migration:** on config load, if the `AdDescriptionSyncEnabled` key is absent from `server-config.json` (i.e. an existing install upgrading from a version that only had one flag), it defaults to whatever `AdSyncEnabled` resolved to from the same config file - so an existing deployment that already had AD Description Sync running keeps running it after the upgrade, with no behavior change until the admin explicitly changes the new setting.
- Manual Description editing is available (both in the UI and enforced server-side) if and only if `AdDescriptionSyncEnabled == false`. It is independent of `AdSyncEnabled` - an admin can have AD identity fully configured (and in active use by Client actions/Client updates/AD Computer Import) while Description sync itself is off and the field is manually editable.
- The manually-entered value is stored in the exact same `adDescription` report field AD Description Sync already writes - no new field, no separate "manual override" flag on the client record. If AD Description Sync is re-enabled later, the next sync cycle overwrites whatever was manually entered, exactly like it would overwrite any other previously-synced value. This is a deliberate simplicity choice, not an oversight.
- No new credential UI anywhere in this plan - `Client updates`' new "Use global AD settings" checkbox reuses the exact same `AdDomain`/`AdUseServiceIdentity`/`AdUsername`/`AdPassword` and the exact same `TryResolveAdSyncCredentials` function `Client actions` already uses.

## Data Model

| Field | Type | Meaning |
| --- | --- | --- |
| `AdDescriptionSyncEnabled` | bool | Gates the periodic AD → `adDescription` write path. Independent of `AdSyncEnabled` (AD identity availability). Migrates from `AdSyncEnabled`'s prior value on first load after upgrade. |

No new field on the client report record - `adDescription` (already existing) is written either by AD Description Sync (when `AdDescriptionSyncEnabled == true`) or by a manual edit through the new endpoint (when `false`). `adSyncStatus`/`adSyncedAt` remain AD-sync-only fields, untouched by manual edits.

## Server-Side Behavior

### AD flag split

- `ServerOptions.AdSyncEnabled` keeps its existing field, CLI flag (`--ad-sync-enabled`), and config-load logic unchanged - it now purely represents "AD identity is configured for use by any feature that needs AD credentials."
- New `ServerOptions.AdDescriptionSyncEnabled` (bool). Config load: read `AdDescriptionSyncEnabled` from `server-config.json`; if the key is missing, set it equal to the just-resolved `AdSyncEnabled` value (migration).
- `RunAdSyncSweep` (the timer-driven sync tick) and the `on-report` sync branch both gate on `AdDescriptionSyncEnabled` instead of `AdSyncEnabled`.
- `ComputeAdSyncFields` (the function that builds the `AdSyncFields` used by `ApplyAdSyncFields`) checks `AdDescriptionSyncEnabled` instead of `AdSyncEnabled` for its early-return no-op case.
- `TryResolveAdSyncCredentials`'s signature and internal logic are unchanged - it still takes an `adSyncEnabled` bool parameter, but every call site now passes `options.AdSyncEnabled` (AD identity), which is already what they pass today. No code change needed here beyond the label/meaning shift already covered by the flag split above.
- `GET`/`POST /api/v1/server/settings` gain `adDescriptionSyncEnabled` (bool) alongside the existing `adSyncEnabled`, following the exact same read/write pattern already used for every other AD setting in this payload.

### Manual Description editing

- New endpoint: `PUT /api/v1/clients/{computerName}/description`, body `{"description": "..."}`.
- Path parsing mirrors the existing `DeleteClient` handler exactly: substring after the `/api/v1/clients/` prefix, strip query string, `Uri.UnescapeDataString`, trim; `400` if empty.
- If `options.AdDescriptionSyncEnabled == true`: `400` with `{"error":"Description is synced from AD - disable \"Sync Description from AD\" in Settings first."}`. This is a server-side enforcement independent of the UI hiding the edit control - the UI is not the only guard.
- If the description text exceeds 1024 characters: `400` with `{"error":"description must be 1024 characters or fewer"}` (matches the practical LDAP `description` attribute limit, for consistency with AD-sourced values).
- Look up the client's report file the same way `DeleteClient` does (`SanitizeFileName(computerName) + ".json"` under `options.DataPath`); `404` with `{"error":"client not found"}` if it doesn't exist.
- Read the report JSON, set `inventory["adDescription"]` to the (possibly empty) submitted string, write it back under the same file lock `PatchClientReportVersionAfterInstall` already uses for targeted single-field report updates (no full re-ingest, no touching `adSyncStatus`/`adSyncedAt`).
- On success: `200` with `{"status":"ok","description":"..."}` (echoes the saved value back, so the client doesn't need a follow-up `GET` to confirm what was actually persisted).

### Client updates: "Use global AD settings"

- The push-start code path for `Client updates` gains the identical `useAdCredentials` handling `StartClientAction` already has: read `payload["useAdCredentials"]` (bool, default `false`), and when `true`, call `TryResolveAdSyncCredentials` after the existing `ResolveUpdateCredentials` call, using its result in place of whatever `ResolveUpdateCredentials` produced - mirroring `Client actions`' exact call order and precedence (typed override is impossible while the checkbox is checked, since the dashboard blanks/disables those fields client-side the same way it already does for `Client actions`).
- No new self-tests needed for `TryResolveAdSyncCredentials` itself (already covered by 5 existing tests) - this is a call-site change, verified via the same kind of end-to-end HTTP check already used to verify the Client actions version (save an explicit AD account, push with the checkbox on, confirm the job's stored `username` matches).

## UI

**Settings > General > Active Directory panel:**

- Existing "Enable AD sync" checkbox is relabeled "Configure AD identity," with updated hint text explaining it now governs AD credential availability for Client actions, Client updates, and AD Computer Import.
- New checkbox, "Sync Description from AD," placed directly below it, with hint text explaining that turning it off makes the Clients table's Description column manually editable and stops AD from overwriting it.

**Clients table:**

- Column header reads "AD Description" when `adDescriptionSyncEnabled` is `true` (current behavior, unchanged), or "Description" when `false`.
- When `false`: the cell renders an `<input>` (not plain text) pre-filled with the current `adDescription` value, left empty if unset (no placeholder text).
- `Enter` or losing focus (`blur`) triggers a save (`PUT /api/v1/clients/{computerName}/description`) only if the value actually changed since the last save/load - no request is sent for an unmodified field losing focus.
- `Escape` reverts the input to the last known-saved value and blurs it, without sending a request.
- A failed save (e.g. sync was re-enabled in another tab between render and save) shows a short inline error next to the field and reverts it to the last known server value.
- The 30-second live-poll refresh must not clobber an in-progress edit: while a given client's Description input has focus, `renderTable`'s re-render preserves that field's current (unsaved) text instead of overwriting it with the freshly-polled value - the same kind of state-preservation `state.expandedDetails` already provides for expanded detail cards, applied here via a new `state.editingDescriptionClientId`.

**Client updates tab, credentials form:**

- New "Use global AD settings" checkbox next to the existing `Saved account: X` hint, identical placement/behavior to `Client actions`': checking it disables the username/password inputs for the saved Client Update account; the dashboard sends `useAdCredentials: true` and omits/blanks username and password in the push request.

## Out of Scope (this iteration)

- Any distinction between "never synced" and "synced once, then sync was disabled" for a client's `adDescription` value - both look identical (just a string) once sync is off, and both become freely editable.
- A confirmation prompt or warning dialog when re-enabling "Sync Description from AD" that a manually-entered value is about to be overwritten - the Settings hint text covers this, no interactive confirmation is added.
- Any change to how `AdComputerImportOUs`/AD Computer Import resolves credentials - already independent of `AdSyncEnabled`'s Description-sync meaning (confirmed via code review: `SendAdComputers` never checks `AdSyncEnabled` at all), unaffected by this plan.
