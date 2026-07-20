# AD Computer Import Design

**Goal:** Let an administrator pull a list of computer names directly from Active Directory (scoped to one or more Organizational Units, or the whole domain) and use it to pre-fill the Targets field on the `Client actions` tab - instead of typing or pasting computer names by hand before a WinRM install/uninstall push.

**Architecture:** A one-shot "Load from AD" action, not a new persistent dashboard section. The admin configures which OU(s) to pull from once, in General settings, next to the existing AD Domain/account fields. A new read-only endpoint queries AD for every computer object under those OU(s) (or the whole domain if none are configured) using the server's already-configured AD credentials - the same `AdDomain`/`AdUseServiceIdentity`/`AdUsername`/`AdPassword` `AdLookupService` already uses - and returns a deduplicated, sorted list of computer names. Clicking "Load from AD" on `Client actions` calls this endpoint and replaces the Targets textarea's content with the result. No new credential UI, no new persistent list, no background sync.

**Tech Stack:** C# (.NET Framework 3.5/4.0, hand-rolled server, `System.DirectoryServices`), vanilla JS dashboard - unchanged from the rest of the project.

## Global Constraints

- No new AD credentials or domain field - reuses `options.AdDomain`, `options.AdUseServiceIdentity`, `options.AdUsername`, `options.AdPassword` exactly as `AdLookupService` does today.
- The OU list is a saved server setting (`AdComputerImportOUs`), not typed fresh on every use - persisted in `server-config.json` alongside the other AD settings, edited in the same General settings AD panel.
- The OU list is one Distinguished Name per line. It is parsed by splitting **only on newlines** (`\r`/`\n`) - a DN itself contains commas between its RDN components (`OU=Workstations,OU=Kaliningrad,DC=spb,DC=cccb,DC=ru`), so the existing comma/semicolon/space-splitting `ExpandInstallTargets` is not reused for this field. Each line is trimmed; blank lines are skipped.
- An empty OU list means "search the whole domain" (`LDAP://<AdDomain>`), not "search nothing."
- Every OU search is `SearchScope.Subtree` (the OU itself plus everything nested under it) - there is no separate "this OU only, not sub-OUs" option in this iteration.
- The result is **not** filtered by whether a computer has ever reported inventory - it is the raw AD computer list for the configured scope. The admin trims it by hand if a particular push (e.g. an uninstall) only makes sense for a subset.
- If one configured OU's DN does not resolve (typo, deleted OU, wrong domain), that OU is skipped and reported back as a warning string - the other configured OUs still return their results. Only a total AD failure (unreachable, bad credentials, no domain configured) fails the whole request.
- Clicking "Load from AD" **replaces** the Targets textarea's current content - it is a "load," not a "merge/append." The admin can still hand-edit the result afterward.
- `DirectorySearcher.PageSize` must be set explicitly (e.g. `1000`) on every search - left at its default (`0`), AD silently caps results at the domain controller's own page-size limit (often 1000) with no indication of truncation, which would be a silent, hard-to-diagnose data-loss bug for any OU/domain larger than that limit.

## Data Model

New field on `ServerOptions` / `server-config.json`, alongside the existing `AdDomain`/`AdUsername`/`AdPassword`:

| Field | Type | Meaning |
| --- | --- | --- |
| `AdComputerImportOUs` | string | Newline-separated list of OU Distinguished Names to search. Empty/unset means "whole domain." Not a secret - stored as plain text, same as `AdDomain`. |

## Server-Side Behavior

- New pure function `ParseAdComputerImportOUs(string raw)` - splits on `\r`/`\n` only, trims each line, drops empty lines, returns the list of DNs. Self-tested directly (no AD dependency), following the same pattern as `ExpandInstallTargets`'s own self-tests.
- New method `AdLookupService.SearchComputers(ArrayList organizationalUnits, ServerOptions options)`, added to `AdLookupService.cs` alongside `LookupComputerDescription` (same file, same credential-resolution pattern, same class) that, given the parsed OU list and `ServerOptions`:
  - If the OU list is empty: runs one search rooted at `LDAP://<AdDomain>` (resolving `AdDomain` the same way `AdLookupService` does when it's blank - `Domain.GetComputerDomain().Name`).
  - If the OU list is non-empty: runs one search per OU, rooted at `LDAP://<OU DN>`.
  - Each search: `DirectoryEntry` built with the same service-identity/explicit-account branching `AdLookupService` already uses, `DirectorySearcher` with `Filter = "(objectCategory=computer)"`, `PropertiesToLoad = { "cn" }`, `SearchScope = Subtree`, `PageSize` set explicitly, `ClientTimeout` matching `AdLookupService`'s existing 15-second bound.
  - A search that throws (bad DN, AD unreachable for just that OU) is caught per-OU: the OU's DN is added to a `warnings` list and the search moves on to the next OU. If every configured OU fails, or the single whole-domain search fails, the overall operation fails (see API below) - this is the only case that returns an error instead of a partial result.
  - Results across all successful searches are merged into one list, deduplicated case-insensitively, and sorted alphabetically. `ExpandInstallTargets` is not reused for this step - it operates on a single delimited string, not on lists of already-extracted names from multiple searches - a small dedicated merge/dedup/sort step is added instead, mirroring the same `Dictionary<string, bool> seen` case-insensitive pattern `ExpandInstallTargets` and `NormalizeComputerList` already use elsewhere in this file.
  - Each real search attempt (success or failure) gets one `DebugLogger.Log(options, "AD", ...)` line, following the exact convention `AdLookupService.LookupComputerDescription` already established for AD activity - so an admin troubleshooting a partial/empty result can see in the debug log which OUs were actually queried and what happened.

## API

- `GET /api/v1/ad/computers` - no request body, works entirely off the already-saved OU list and AD credentials. Response on success: `{"computers": ["PC-001", "PC-002", ...], "warnings": ["OU 'OU=Old,DC=...' was not found and was skipped."]}` (`warnings` is always present, empty array when there were none). Fails with `500` and a JSON `{"error": "..."}` body when AD itself could not be reached at all (every configured OU failed, or the single whole-domain search failed) - this project has no existing `4xx` code for "an external dependency failed, not the caller's fault" (`400` is reserved for invalid input), and `500` is what the one existing comparable case (`DeleteCertificate`'s local-store failure) already uses.
- `GET /api/v1/server/settings` / `POST /api/v1/server/settings` - extended with one more field, `adComputerImportOUs` (string, newline-separated DNs), read/written exactly like the existing `adDomain` field sits in the same payload today. No new endpoint pair for this - it lives with the rest of the AD settings that already round-trip through this pair.

## UI

**General settings, Active Directory panel** (the existing single-column 420px panel with Domain/service identity/AD account): one more field below the existing ones, a `<textarea>` labeled "Organizational Units (DN, one per line)" with placeholder text showing the DN format, saved by the panel's existing Save button alongside the other AD fields - no separate save action.

**Client actions tab**, next to the `Targets` textarea: a "Load from AD" button (same visual weight/class as the tab's other action buttons) and a small message area below it (reusing the existing `pkg-message` pattern used elsewhere in this dashboard for save/action feedback). Clicking it:

- Calls `GET /api/v1/ad/computers`.
- On success: replaces the Targets textarea's content with the returned `computers`, newline-joined; the message area shows `"Loaded N computer(s) from AD."`, appending any `warnings` on their own lines when present (e.g. `"OU '...' was not found and was skipped."`).
- On failure (network error, or a `500` from the endpoint): Targets is left untouched, the message area shows the error, styled the same way other error messages in this dashboard are (the existing `.error` modifier class).
- On a valid but empty result: Targets is left untouched (not cleared), message area shows `"No computers found for the configured scope."`.

## Out of Scope (this iteration)

- A per-OU "include sub-OUs" toggle - every search is always `Subtree`.
- Filtering the AD result against `LoadClientReports()` to show only computers that have never reported (the "coverage gap" use case discussed and explicitly deferred in favor of the simpler "always return everything" behavior).
- Any UI for browsing/picking OUs from a live AD tree - OUs are typed as DNs by hand.
- Using this same button/endpoint from the `Client updates` tab - that tab has no free-text target field (its targets come from already-known outdated clients), so there is nothing for this feature to populate there.
- Merge/append behavior for the Targets textarea - only replace.
- Any new credential storage or AD connection UI - entirely reuses the existing AD Domain/account settings.
