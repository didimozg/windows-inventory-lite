# AD-Editable Description Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the single `AdSyncEnabled` flag into "AD identity configured" and a new "Sync Description from AD" toggle, so an admin can manually edit a client's Description in the dashboard (when Description sync is off) without losing AD credentials for Client actions/Client updates/AD Computer Import - and give `Client updates` the same "Use global AD settings" checkbox `Client actions` already has.

**Architecture:** `AdSyncEnabled` (renamed in UI to "Configure AD identity") keeps meaning "domain/credentials are configured." A new `AdDescriptionSyncEnabled` flag ("Sync Description from AD" in UI) gates only the periodic AD→`adDescription` write path. The Clients table's Description column becomes an inline-editable `<input>` whenever `AdDescriptionSyncEnabled` is `false`, saved through a new `PUT /api/v1/clients/{computerName}/description` endpoint. `Client updates`' "Use global AD settings" checkbox needs no new server code - the push pipeline it already uses (`StartClientAction`) already resolves `useAdCredentials` the same way `Client actions` does.

**Tech Stack:** C# (.NET Framework 3.5/4.0, hand-rolled server), vanilla JS dashboard - unchanged from the rest of the project.

## Global Constraints

- `AdSyncEnabled`'s storage key, CLI flag (`--ad-sync-enabled`), and config-load logic are unchanged - only its UI label changes, from "Enable AD sync" to "Configure AD identity."
- New `AdDescriptionSyncEnabled` (bool, `ServerOptions` + `server-config.json`) gates `RunAdSyncSweep`, `ReconfigureAdSyncTimer`'s decision to even start the timer, and `ComputeAdSyncFields`'s early-return guard. UI label: "Sync Description from AD."
- Migration: if `AdDescriptionSyncEnabled` is absent from `server-config.json` (upgrade from a version with only one flag), it inherits whatever `AdSyncEnabled` resolved to from the same config - an existing AD Description Sync setup keeps running after the upgrade with no admin action needed.
- Manual Description editing is available (UI and server-enforced) if and only if `AdDescriptionSyncEnabled == false`. Independent of `AdSyncEnabled`.
- The manual edit writes the exact same `adDescription` report field AD Description Sync writes - no new client-record field. If sync is re-enabled later, the next cycle overwrites it, same as any other previously-synced value.
- `Client updates`' "Use global AD settings" checkbox reuses the exact same `TryResolveAdSyncCredentials` function and `AdDomain`/`AdUseServiceIdentity`/`AdUsername`/`AdPassword` fields `Client actions` already uses - no new credential storage.
- Description length limit: 1024 characters, enforced server-side on the new endpoint.

---

### Task 1: Split the AD sync flag (server)

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs:112-114` (new `ServerOptions` field)
- Modify: `src/server/WindowsInventoryLiteServer.cs:409-413` (config load + migration)
- Modify: `src/server/WindowsInventoryLiteServer.cs:685` (`ReconfigureAdSyncTimer`)
- Modify: `src/server/WindowsInventoryLiteServer.cs:712` (`RunAdSyncSweep`)
- Modify: `src/server/WindowsInventoryLiteServer.cs:1571` (`ComputeAdSyncFields`)
- Modify: `src/server/WindowsInventoryLiteServer.cs:3463-3486` (`SendServerSettings`)
- Modify: `src/server/WindowsInventoryLiteServer.cs:3672-3731` (`ConfigureServerSettings`)
- Modify: `src/server/WindowsInventoryLiteServer.cs` (self-test registration + new test bodies, near line 4696/5450)

**Interfaces:**
- Produces: `ServerOptions.AdDescriptionSyncEnabled` (bool field), `ServerOptions.ResolveAdDescriptionSyncEnabled(string configValueText, bool adSyncEnabledResolved)` (internal static bool, pure) - later tasks read `options.AdDescriptionSyncEnabled` to gate the new endpoint and to decide the Clients table's column label/editability.
- Consumes: nothing from other tasks - this is the foundation task.

- [ ] **Step 1: Write the failing self-test for the migration function**

Add these two test methods anywhere among the other `TestTryResolveAdSyncCredentials...` methods (e.g. directly after `TestTryResolveAdSyncCredentialsRejectsWhenSavedAccountIncomplete`, which ends around line 5461 with `return null; }`):

```csharp
        private static string TestResolveAdDescriptionSyncEnabledUsesExplicitConfigValue()
        {
            bool result = ServerOptions.ResolveAdDescriptionSyncEnabled("false", true);
            if (result != false)
            {
                return "expected an explicit 'false' config value to win over adSyncEnabledResolved=true, got " + result;
            }
            bool result2 = ServerOptions.ResolveAdDescriptionSyncEnabled("true", false);
            if (result2 != true)
            {
                return "expected an explicit 'true' config value to win over adSyncEnabledResolved=false, got " + result2;
            }
            return null;
        }

        private static string TestResolveAdDescriptionSyncEnabledMigratesFromAdSyncEnabledWhenUnset()
        {
            bool result = ServerOptions.ResolveAdDescriptionSyncEnabled(null, true);
            if (result != true)
            {
                return "expected a missing config value to inherit adSyncEnabledResolved=true, got " + result;
            }
            bool result2 = ServerOptions.ResolveAdDescriptionSyncEnabled(null, false);
            if (result2 != false)
            {
                return "expected a missing config value to inherit adSyncEnabledResolved=false, got " + result2;
            }
            return null;
        }
```

Register both in `RunSelfTests`, right before the `return allPassed;` line (currently line 4697):

```csharp
            allPassed &= SelfTestCheck(output, "ResolveAdDescriptionSyncEnabled uses the explicit config value when present", TestResolveAdDescriptionSyncEnabledUsesExplicitConfigValue);
            allPassed &= SelfTestCheck(output, "ResolveAdDescriptionSyncEnabled migrates from AdSyncEnabled when the config key is absent", TestResolveAdDescriptionSyncEnabledMigratesFromAdSyncEnabledWhenUnset);
```

- [ ] **Step 2: Run the build to confirm it fails (the function doesn't exist yet)**

Run: `pwsh -File src/Build-Server.ps1`
Expected: FAIL with `error CS0117: 'ServerOptions' does not contain a definition for 'ResolveAdDescriptionSyncEnabled'` (or similar CS0117/CS0103).

- [ ] **Step 3: Add the `AdDescriptionSyncEnabled` field and the migration function to `ServerOptions`**

In `ServerOptions`, right after `public bool AdSyncEnabled;` (line 112), before `public string AdSyncMode;`:

```csharp
        public bool AdSyncEnabled;
        // Independent of AdSyncEnabled (which now means "AD identity is
        // configured for use by Client actions/Client updates/AD Computer
        // Import"): this flag alone gates the periodic AD -> adDescription
        // write path (RunAdSyncSweep, ComputeAdSyncFields). Turning it off
        // makes the Clients table's Description column manually editable
        // without losing AD credentials elsewhere. See
        // docs/superpowers/specs/2026-07-21-ad-editable-description-design.md.
        public bool AdDescriptionSyncEnabled;
        public string AdSyncMode;
```

Add the migration function as a `private static` method on `ServerOptions`, right after `GetConfigString` (currently ends at line 532 with `}`), before the `}` that closes the `ServerOptions` class (line 533):

```csharp
        // Migration for upgrades from before AdDescriptionSyncEnabled
        // existed: if the config file has no explicit value for it yet,
        // the deployment keeps whatever behavior AdSyncEnabled (now "AD
        // identity is configured") already gave it, so an existing AD
        // Description Sync setup keeps running after the upgrade with no
        // admin action required. Pure - no I/O, self-tested directly.
        internal static bool ResolveAdDescriptionSyncEnabled(string configValueText, bool adSyncEnabledResolved)
        {
            if (!String.IsNullOrEmpty(configValueText))
            {
                return String.Equals(configValueText, "true", StringComparison.OrdinalIgnoreCase);
            }
            return adSyncEnabledResolved;
        }
```

- [ ] **Step 4: Run the self-test build and confirm the two new tests pass**

Run: `pwsh -File src/Build-Server.ps1` then `./build/WindowsInventoryLiteServer.exe --self-test`
Expected: both new tests print `PASS`, total count is 56 (54 existing + 2 new), 0 `FAIL`.

- [ ] **Step 5: Wire the migration into config load**

In the config-load block, right after the existing `AdSyncEnabled` block (lines 409-413), insert:

```csharp
                if (!options.AdSyncEnabled)
                {
                    string adSyncEnabledText = GetConfigString(config, "AdSyncEnabled");
                    options.AdSyncEnabled = String.Equals(adSyncEnabledText, "true", StringComparison.OrdinalIgnoreCase);
                }
                if (!options.AdDescriptionSyncEnabled)
                {
                    string adDescriptionSyncEnabledText = GetConfigString(config, "AdDescriptionSyncEnabled");
                    options.AdDescriptionSyncEnabled = ResolveAdDescriptionSyncEnabled(adDescriptionSyncEnabledText, options.AdSyncEnabled);
                }
                if (options.AdSyncMode == "on-report")
```

(Only the new middle block is added - the surrounding `AdSyncEnabled` and `AdSyncMode` blocks are shown for exact placement, do not duplicate them.)

- [ ] **Step 6: Re-gate the three Description-sync consumers**

In `ReconfigureAdSyncTimer` (line 685), change:
```csharp
                if (options.AdSyncEnabled && options.AdSyncMode == "timer")
```
to:
```csharp
                if (options.AdDescriptionSyncEnabled && options.AdSyncMode == "timer")
```

In `RunAdSyncSweep` (line 712), change:
```csharp
            if (!options.AdSyncEnabled || options.AdSyncMode != "timer")
```
to:
```csharp
            if (!options.AdDescriptionSyncEnabled || options.AdSyncMode != "timer")
```

In `ComputeAdSyncFields` (line 1571), change:
```csharp
            if (!options.AdSyncEnabled)
```
to:
```csharp
            if (!options.AdDescriptionSyncEnabled)
```

Every other use of `options.AdSyncEnabled` in the file (`TryResolveAdSyncCredentials` call sites, `AdLookupService.SearchComputers` via `SendAdComputers`) is unchanged - those correctly mean "AD identity is configured."

- [ ] **Step 7: Expose the new flag on `GET`/`POST /api/v1/server/settings`**

In `SendServerSettings` (around line 3470), right after `result["adSyncEnabled"] = options.AdSyncEnabled;`:

```csharp
            result["adSyncEnabled"] = options.AdSyncEnabled;
            result["adDescriptionSyncEnabled"] = options.AdDescriptionSyncEnabled;
            result["adSyncMode"] = options.AdSyncMode;
```

In `ConfigureServerSettings`, the `if` that decides whether the whole AD block runs (lines 3672-3674) gains one more `ContainsKey` check:

```csharp
            if (payload.ContainsKey("adSyncEnabled") || payload.ContainsKey("adDescriptionSyncEnabled") || payload.ContainsKey("adSyncMode") || payload.ContainsKey("adSyncIntervalHours")
                || payload.ContainsKey("adDomain") || payload.ContainsKey("adUseServiceIdentity") || payload.ContainsKey("adUsername") || payload.ContainsKey("adPassword")
                || payload.ContainsKey("adComputerImportOUs"))
            {
                bool adSyncEnabled = payload.ContainsKey("adSyncEnabled") ? Convert.ToBoolean(payload["adSyncEnabled"]) : options.AdSyncEnabled;
                bool adDescriptionSyncEnabled = payload.ContainsKey("adDescriptionSyncEnabled") ? Convert.ToBoolean(payload["adDescriptionSyncEnabled"]) : options.AdDescriptionSyncEnabled;
```

Right after `options.AdSyncEnabled = adSyncEnabled;` (line 3713):

```csharp
                options.AdSyncEnabled = adSyncEnabled;
                options.AdDescriptionSyncEnabled = adDescriptionSyncEnabled;
                options.AdSyncMode = adSyncMode;
```

Right after `updates["AdSyncEnabled"] = options.AdSyncEnabled ? "true" : "false";` (line 3723):

```csharp
                updates["AdSyncEnabled"] = options.AdSyncEnabled ? "true" : "false";
                updates["AdDescriptionSyncEnabled"] = options.AdDescriptionSyncEnabled ? "true" : "false";
                updates["AdSyncMode"] = options.AdSyncMode;
```

The existing validation at line 3707 (`if (adSyncEnabled && !adUseServiceIdentity && ...)`) is unchanged - it still validates AD identity completeness, which is still what `adSyncEnabled` means.

- [ ] **Step 8: Run the full self-test suite**

Run: `pwsh -File src/Build-Server.ps1` then `./build/WindowsInventoryLiteServer.exe --self-test`
Expected: 56 PASS, 0 FAIL.

- [ ] **Step 9: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Split AdSyncEnabled into AD-identity and AdDescriptionSyncEnabled flags"
```

---

### Task 2: Manual Description edit endpoint (server)

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs` (new route in the request dispatcher, near line 1214)
- Modify: `src/server/WindowsInventoryLiteServer.cs` (new `UpdateClientDescription` method, near `DeleteClient` at line 1635)

**Interfaces:**
- Consumes: `options.AdDescriptionSyncEnabled` (Task 1), `SanitizeFileName`, `reportFileLock`, `CreateJsonSerializer()` (all pre-existing).
- Produces: `PUT /api/v1/clients/{computerName}/description` - later UI tasks (Task 4) call this endpoint.

- [ ] **Step 1: Add the route**

In the request dispatcher, right after the existing `DELETE /api/v1/clients/` route (lines 1214-1217):

```csharp
                    else if (request.Method == "DELETE" && request.Path.StartsWith("/api/v1/clients/", StringComparison.OrdinalIgnoreCase))
                    {
                        DeleteClient(stream, request);
                    }
                    else if (request.Method == "PUT" && request.Path.StartsWith("/api/v1/clients/", StringComparison.OrdinalIgnoreCase))
                    {
                        UpdateClientDescription(stream, request);
                    }
```

- [ ] **Step 2: Add `UpdateClientDescription`, right after `DeleteClient` (ends at line 1662 with `}`)**

```csharp
        // Manual Description edit, only reachable while AD Description
        // Sync is off (AdDescriptionSyncEnabled == false) - enforced here,
        // not just by the dashboard hiding the edit control, since the UI
        // is not a security boundary. Writes the same adDescription field
        // AD Description Sync itself writes; adSyncStatus/adSyncedAt are
        // untouched. See
        // docs/superpowers/specs/2026-07-21-ad-editable-description-design.md.
        private void UpdateClientDescription(Stream stream, RequestContext request)
        {
            const string prefix = "/api/v1/clients/";
            const string suffix = "/description";
            string rawPath = request.Path;
            int queryStart = rawPath.IndexOf('?');
            if (queryStart >= 0)
            {
                rawPath = rawPath.Substring(0, queryStart);
            }
            if (!rawPath.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                SendText(stream, "{\"error\":\"not found\"}", "application/json; charset=utf-8", 404);
                return;
            }

            string rawComputerName = rawPath.Substring(prefix.Length, rawPath.Length - prefix.Length - suffix.Length);
            string computerName = Uri.UnescapeDataString(rawComputerName).Trim();
            if (String.IsNullOrEmpty(computerName))
            {
                SendText(stream, "{\"error\":\"computer name is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            if (options.AdDescriptionSyncEnabled)
            {
                SendText(stream, "{\"error\":\"Description is synced from AD - disable \\\"Sync Description from AD\\\" in Settings first.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> payload;
            try
            {
                payload = serializer.Deserialize<Dictionary<string, object>>(request.Body);
                if (payload == null)
                {
                    throw new ArgumentException("empty body");
                }
            }
            catch
            {
                SendText(stream, "{\"error\":\"invalid request body\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string description = payload.ContainsKey("description") ? Convert.ToString(payload["description"]) : "";
            if (description.Length > 1024)
            {
                SendText(stream, "{\"error\":\"description must be 1024 characters or fewer\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string path = Path.Combine(options.DataPath, SanitizeFileName(computerName) + ".json");
            lock (reportFileLock)
            {
                if (!File.Exists(path))
                {
                    SendText(stream, "{\"error\":\"client not found\"}", "application/json; charset=utf-8", 404);
                    return;
                }
                Dictionary<string, object> report;
                try
                {
                    report = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
                }
                catch
                {
                    SendText(stream, "{\"error\":\"client report could not be read\"}", "application/json; charset=utf-8", 500);
                    return;
                }
                if (report == null)
                {
                    SendText(stream, "{\"error\":\"client report could not be read\"}", "application/json; charset=utf-8", 500);
                    return;
                }
                report["adDescription"] = description;
                File.WriteAllText(path, serializer.Serialize(report), new UTF8Encoding(false));
            }

            Dictionary<string, object> response = new Dictionary<string, object>();
            response["status"] = "ok";
            response["description"] = description;
            SendJson(stream, serializer.Serialize(response));
        }
```

- [ ] **Step 3: Build**

Run: `pwsh -File src/Build-Server.ps1`
Expected: build succeeds with no errors.

- [ ] **Step 4: Run the self-test suite (no new self-tests in this task - verified via live HTTP below)**

Run: `./build/WindowsInventoryLiteServer.exe --self-test`
Expected: 56 PASS, 0 FAIL (unchanged from Task 1).

- [ ] **Step 5: Manual verification against a running console-mode instance**

Start a scratch instance (adjust the port/data dir):

```bash
./build/WindowsInventoryLiteServer.exe --console --port 18090 --data /tmp/wil-desc-test --content server/dashboard
```

Seed a client and confirm the endpoint's three guarded paths, using PowerShell's `Invoke-RestMethod` (avoids manual JSON escaping):

```powershell
# Seed a client
Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/inventory' -Method Post -ContentType 'application/json' -Body (@{ computerName = 'DESC-TEST-01' } | ConvertTo-Json)

# AdDescriptionSyncEnabled defaults to false (new flag, no migration source) -
# so this should succeed:
Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/clients/DESC-TEST-01/description' -Method Put -ContentType 'application/json' -Body (@{ description = 'Manually set' } | ConvertTo-Json)
# Expected: { status: ok, description: Manually set }

# Confirm it persisted:
(Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/clients').clients | Where-Object computerName -eq 'DESC-TEST-01' | Select-Object adDescription
# Expected: adDescription = Manually set

# Enable AD Description Sync, confirm the endpoint now rejects:
Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/server/settings' -Method Post -ContentType 'application/json' -Body (@{ adDescriptionSyncEnabled = $true } | ConvertTo-Json)
try {
  Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/clients/DESC-TEST-01/description' -Method Put -ContentType 'application/json' -Body (@{ description = 'Should be rejected' } | ConvertTo-Json)
} catch {
  $_.Exception.Response.StatusCode.value__  # Expected: 400
}

# Unknown computer:
try {
  Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/server/settings' -Method Post -ContentType 'application/json' -Body (@{ adDescriptionSyncEnabled = $false } | ConvertTo-Json)
  Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/clients/NO-SUCH-PC/description' -Method Put -ContentType 'application/json' -Body (@{ description = 'x' } | ConvertTo-Json)
} catch {
  $_.Exception.Response.StatusCode.value__  # Expected: 404
}
```

Stop the scratch instance afterward (`Get-Process WindowsInventoryLiteServer | Stop-Process`).

- [ ] **Step 6: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add PUT /api/v1/clients/{computerName}/description endpoint"
```

---

### Task 3: Settings UI - rename AD sync checkbox, add Description-sync toggle

**Files:**
- Modify: `server/dashboard/index.html:216-220` (AD panel checkboxes)
- Modify: `server/dashboard/app.js:1383` (`loadGeneralSettings`)
- Modify: `server/dashboard/app.js:1469` (`saveGeneralSettings`)

**Interfaces:**
- Consumes: `adSyncEnabled`/`adDescriptionSyncEnabled` from `GET /api/v1/server/settings` (Task 1).
- Produces: `#generalAdDescriptionSyncEnabled` checkbox id - Task 4 reads `state.adDescriptionSyncEnabled` (set here) to decide the Clients table's editability.

- [ ] **Step 1: Update the HTML**

In `server/dashboard/index.html`, replace lines 216-220:

```html
              <label class="check-label">
                <input id="generalAdSyncEnabled" type="checkbox">
                Enable AD sync
              </label>
```

with:

```html
              <label class="check-label">
                <input id="generalAdSyncEnabled" type="checkbox">
                Configure AD identity
              </label>
              <label class="check-label">
                <input id="generalAdDescriptionSyncEnabled" type="checkbox">
                Sync Description from AD
              </label>
```

Right after the closing `</div>` of `.ad-identity-panel` (line 256), before the existing `<p class="cert-hint">Shows each computer's...` paragraph (line 257), add a hint clarifying the split - replace line 257 entirely:

```html
            <p class="cert-hint">"Configure AD identity" makes the domain/credentials below available to Client actions, Client updates, and AD Computer Import. "Sync Description from AD" additionally writes each computer's Active Directory description into its inventory record, read-only in the Clients table while it's on. Turn it off to edit Description manually instead - re-enabling it later overwrites any manual edits on the next sync. Reading the description attribute is allowed to any authenticated domain user by default AD ACLs, so the service account identity usually needs no special AD delegation.</p>
```

- [ ] **Step 2: Load the new field**

In `app.js`'s `loadGeneralSettings` (line 1383), right after `byId('generalAdSyncEnabled').checked = !!data.adSyncEnabled;`:

```javascript
        byId('generalAdSyncEnabled').checked = !!data.adSyncEnabled;
        byId('generalAdDescriptionSyncEnabled').checked = !!data.adDescriptionSyncEnabled;
        state.adDescriptionSyncEnabled = !!data.adDescriptionSyncEnabled;
```

- [ ] **Step 3: Save the new field**

In `app.js`'s `saveGeneralSettings` (line 1469), right after `adSyncEnabled: byId('generalAdSyncEnabled').checked,`:

```javascript
        adSyncEnabled: byId('generalAdSyncEnabled').checked,
        adDescriptionSyncEnabled: byId('generalAdDescriptionSyncEnabled').checked,
```

Immediately after the `fetch(...)` call's success handling finishes updating `state` for other fields (find the block a few lines below the `.then(({ ok, status, data }) => {` that starts around line 1481 - after any existing `state.xxx = ...` assignment made on a successful save, e.g. alongside where `state.staleHours` gets updated on save if present; if no such state-sync block exists for other fields, add this as its own line right after the `showGeneralMessage('Saved.', false);` call inside the success path):

```javascript
        state.adDescriptionSyncEnabled = byId('generalAdDescriptionSyncEnabled').checked;
```

- [ ] **Step 4: Build and verify no self-tests are affected (this task is UI-only)**

Run: `pwsh -File src/Build-Server.ps1` then `./build/WindowsInventoryLiteServer.exe --self-test`
Expected: 56 PASS, 0 FAIL (unchanged).

- [ ] **Step 5: Verify live via Playwright against a scratch console-mode instance**

Start a scratch instance, open `#general`, confirm both checkboxes render with the new labels, toggle "Sync Description from AD" off, click Save, reload the page, confirm the checkbox is still unchecked (persisted) and `GET /api/v1/server/settings` returns `adDescriptionSyncEnabled: false`.

- [ ] **Step 6: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js
git commit -m "Rename AD sync checkbox, add Sync Description from AD toggle"
```

---

### Task 4: Inline-editable Description column (Clients table)

**Files:**
- Modify: `server/dashboard/index.html:583` (`<th>` id)
- Modify: `server/dashboard/app.js:129-143` (`formatAdDescription`)
- Modify: `server/dashboard/app.js:2069` area (`renderTable` - column header text, cell rendering, focus preservation)
- Modify: `server/dashboard/app.js` (new `saveClientDescription`, new event delegation for the input)
- Modify: `server/dashboard/styles.css` (new `.description-edit-input` rule)

**Interfaces:**
- Consumes: `state.adDescriptionSyncEnabled` (Task 3), `PUT /api/v1/clients/{computerName}/description` (Task 2), `escapeHtml`, `safeId`, `showSavedMessage` (all pre-existing).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Give the column header an id**

In `server/dashboard/index.html`, replace line 583:

```html
                  <th>AD Description</th>
```

with:

```html
                  <th id="descriptionColumnHeader">AD Description</th>
```

- [ ] **Step 2: Add CSS for the inline input**

In `server/dashboard/styles.css`, add this rule near the existing `textarea, input[type="text"], ...` block (after its closing `}`, currently around line 696):

```css
.description-edit-input {
  width: 100%;
  padding: 4px 6px;
  border: 1px solid var(--line);
  border-radius: 4px;
  font: inherit;
  font-size: 13px;
}
```

- [ ] **Step 3: Split `formatAdDescription` into read-only and editable renderers**

In `app.js`, replace the existing `formatAdDescription` function (lines 132-143):

```javascript
  function formatAdDescription(client) {
    if (client.adSyncStatus === 'not-found') {
      return '<small>Not found in AD</small>';
    }
    if (client.adSyncStatus === 'error') {
      return '<small>AD unreachable</small>';
    }
    if (client.adDescription) {
      return escapeHtml(client.adDescription);
    }
    return '';
  }
```

with:

```javascript
  function formatAdDescription(client) {
    if (client.adSyncStatus === 'not-found') {
      return '<small>Not found in AD</small>';
    }
    if (client.adSyncStatus === 'error') {
      return '<small>AD unreachable</small>';
    }
    if (client.adDescription) {
      return escapeHtml(client.adDescription);
    }
    return '';
  }

  // Editable Description cell, used instead of formatAdDescription's
  // read-only text whenever state.adDescriptionSyncEnabled is false.
  // adSyncStatus ('not-found'/'error') is deliberately ignored here - once
  // sync is off, those statuses are frozen leftovers from whenever sync
  // last ran and are no longer meaningful. data-last-saved-value lets
  // saveClientDescription (Step 6) detect a no-op blur/Enter and skip the
  // network request.
  function formatDescriptionEditor(client, clientId) {
    const value = escapeHtml(client.adDescription || '');
    return `<input type="text" class="description-edit-input" data-description-client="${clientId}" data-computer-name="${escapeHtml(client.computerName)}" data-last-saved-value="${value}" value="${value}" maxlength="1024">`;
  }
```

- [ ] **Step 4: Update `renderTable`'s column header and cell rendering**

In `app.js`, `renderTable` currently reads (lines 2069-2074):

```javascript
  function renderTable(clients) {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.clients;
    const filtered = applySort(clients.filter(client => clientMatches(client, query)), c => clientSortValue(c, sortKey), sortDir);
    const { items: pageItems, page, totalPages } = paginate(filtered, state.page.clients, state.pageSize.clients);
    state.page.clients = page;
```

Add one line right after `state.page.clients = page;`:

```javascript
    state.page.clients = page;
    byId('descriptionColumnHeader').textContent = state.adDescriptionSyncEnabled ? 'AD Description' : 'Description';
```

Then, inside the per-client row template, change line 2121 from:

```javascript
        <td>${formatAdDescription(client)}</td>
```

to:

```javascript
        <td>${state.adDescriptionSyncEnabled ? formatAdDescription(client) : formatDescriptionEditor(client, clientId)}</td>
```

(`clientId` is already computed a few lines above this in the same template, at line 2110: `const clientId = safeId(client.computerName || '');` - reuse it, do not recompute.)

- [ ] **Step 5: Preserve an in-progress edit across live-poll re-renders**

Replace `renderTable`'s opening line (line 2069):

```javascript
  function renderTable(clients) {
```

with:

```javascript
  function renderTable(clients) {
    const activeElement = document.activeElement;
    const editingClientId = activeElement && activeElement.matches('.description-edit-input') ? activeElement.dataset.descriptionClient : null;
    const editingValue = editingClientId ? activeElement.value : null;
    const editingSelectionStart = editingClientId ? activeElement.selectionStart : null;
```

Then replace the DOM-assignment line (currently line 2143):

```javascript
    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="10" class="empty">No matching inventory records.</td></tr>';
```

with:

```javascript
    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="10" class="empty">No matching inventory records.</td></tr>';
    if (editingClientId) {
      const restoredInput = document.querySelector(`.description-edit-input[data-description-client="${editingClientId}"]`);
      if (restoredInput) {
        restoredInput.value = editingValue;
        restoredInput.focus();
        restoredInput.setSelectionRange(editingSelectionStart, editingSelectionStart);
      }
    }
```

- [ ] **Step 6: Add the save function and wire Enter/blur/Escape via event delegation**

Add this function immediately after `showSavedMessage`'s closing `}` (currently line 859, right before `function loadClientUpdateCredentials() {`):

```javascript
  // Saves an inline Description edit. Only fires on an actual change
  // (skips a no-op save when a field loses focus unmodified). Reverts the
  // input to the last known-good value on failure, since a stale client-
  // side value (e.g. after AD Description Sync was re-enabled in another
  // tab between render and save) would otherwise silently diverge from
  // what the server actually has.
  function saveClientDescription(input) {
    const computerName = input.dataset.computerName;
    const newValue = input.value;
    if (newValue === input.dataset.lastSavedValue) return;

    input.disabled = true;
    fetch(`/api/v1/clients/${encodeURIComponent(computerName)}/description`, {
      method: 'PUT',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: newValue })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        input.dataset.lastSavedValue = data.description;
        const client = (state.clients || []).find(c => c.computerName === computerName);
        if (client) client.adDescription = data.description;
      })
      .catch(error => {
        input.value = input.dataset.lastSavedValue || '';
        window.alert(`Failed to save description: ${error.message}`);
      })
      .finally(() => {
        input.disabled = false;
      });
  }
```

Add the two delegated listeners right after `renderTable`'s closing `}` (currently line 2145, right before `function renderSoftwareTable(clients) {`):

```javascript
  document.addEventListener('keydown', event => {
    if (!event.target.matches('.description-edit-input')) return;
    if (event.key === 'Enter') {
      event.target.blur();
    } else if (event.key === 'Escape') {
      event.target.value = event.target.dataset.lastSavedValue || '';
      event.target.blur();
    }
  });

  document.addEventListener('blur', event => {
    if (!event.target.matches || !event.target.matches('.description-edit-input')) return;
    saveClientDescription(event.target);
  }, true);
```

(The `blur` listener uses capture (`true` as the third argument) because `blur` does not bubble - a plain bubbling listener on `document` would never see it.)

- [ ] **Step 7: Build and verify self-tests are unaffected (this task is UI-only)**

Run: `pwsh -File src/Build-Server.ps1` then `./build/WindowsInventoryLiteServer.exe --self-test`
Expected: 56 PASS, 0 FAIL (unchanged).

- [ ] **Step 8: Verify live via Playwright against a scratch console-mode instance**

- With `adDescriptionSyncEnabled: false` (the default for a fresh scratch instance): seed a client, open Clients, confirm the column header reads "Description" and the cell is an `<input>`. Type a new value, press Tab (triggers blur), confirm a `PUT` request fired and the value persisted after a page reload.
- Type a value, press Escape, confirm the field reverts without a network request (check via `page.route` interception or a network-idle assertion).
- Set `adDescriptionSyncEnabled: true` via `POST /api/v1/server/settings`, reload, confirm the column header reads "AD Description" and the cell is plain text again, not an input.
- With sync off again, start typing in the input, then trigger a live-poll re-render manually (call the app's own poll function from the console, or wait out one 30s cycle) - confirm the typed-but-unsaved text is still there afterward (not clobbered) and focus/cursor position are preserved.

- [ ] **Step 9: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js server/dashboard/styles.css
git commit -m "Add inline-editable Description column to the Clients table"
```

---

### Task 5: "Use global AD settings" checkbox for Client updates

**Files:**
- Modify: `server/dashboard/index.html:450-465` (credentials form)
- Modify: `server/dashboard/app.js:861-882` (`loadClientUpdateCredentials`)
- Modify: `server/dashboard/app.js:979-1026` (`startClientUpdateJob`)
- Modify: `server/dashboard/app.js` (new `updateUpdatesCredentialFieldsUi`, event listener registration)

**Interfaces:**
- Consumes: the server's existing `useAdCredentials` handling in `StartClientAction` (already shipped in v0.20.0, no server change needed - confirmed via code review that `POST /api/v1/client-install` is the same endpoint both `Client actions` and `Client updates` push through).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Add the checkbox to the HTML**

In `server/dashboard/index.html`, right after `<p id="updatesSavedAccountHint" class="cert-hint hidden"></p>` (line 450), before the `<div class="pkg-grid client-update-grid">` (line 451):

```html
            <p id="updatesSavedAccountHint" class="cert-hint hidden"></p>
            <label class="check-label">
              <input id="updatesUseAdCredentials" type="checkbox">
              Use global AD settings (Settings &gt; General &gt; Active Directory)
            </label>
            <div class="pkg-grid client-update-grid">
```

- [ ] **Step 2: Disable username/password fields while the checkbox is checked**

In `app.js`, add this function near `updateInstallCredentialFieldsUi` (right after its closing `}`, currently line 646):

```javascript
  // Mirrors updateInstallCredentialFieldsUi (Client actions) exactly: "Use
  // global AD settings" substitutes the typed/saved Client Update account
  // with the AD sync credentials already configured in Settings > General.
  function updateUpdatesCredentialFieldsUi() {
    const useAd = byId('updatesUseAdCredentials').checked;
    byId('updatesUsername').disabled = useAd;
    byId('updatesPassword').disabled = useAd;
  }
```

- [ ] **Step 3: Send `useAdCredentials` from `startClientUpdateJob`**

In `app.js`'s `startClientUpdateJob` (around line 992), replace:

```javascript
    const username = byId('updatesUsername').value.trim();
    const password = byId('updatesPassword').value;
```

with:

```javascript
    const useAdCredentials = byId('updatesUseAdCredentials').checked;
    const username = useAdCredentials ? '' : byId('updatesUsername').value.trim();
    const password = useAdCredentials ? '' : byId('updatesPassword').value;
```

A few lines below, in the same function's `fetch(...)` call body (currently `JSON.stringify({ targets: targets.join('\n'), serverUrl, username, password, force: false, addToTrustedHosts: false, useSavedCredentials: true })`), add `useAdCredentials`:

```javascript
      body: JSON.stringify({ targets: targets.join('\n'), serverUrl, username, password, force: false, addToTrustedHosts: false, useSavedCredentials: true, useAdCredentials })
```

- [ ] **Step 4: Wire the checkbox's change listener and initialize the UI state on load**

Near the existing `byId('installUseAdCredentials').addEventListener('change', updateInstallCredentialFieldsUi);` line (2500), add:

```javascript
  byId('updatesUseAdCredentials').addEventListener('change', updateUpdatesCredentialFieldsUi);
```

- [ ] **Step 5: Build and verify self-tests are unaffected (this task is UI-only, server already supports `useAdCredentials` on this endpoint)**

Run: `pwsh -File src/Build-Server.ps1` then `./build/WindowsInventoryLiteServer.exe --self-test`
Expected: 56 PASS, 0 FAIL (unchanged).

- [ ] **Step 6: Verify live via Playwright + direct HTTP against a scratch console-mode instance**

- Configure AD identity (domain + explicit account, `adUseServiceIdentity: false`) via `POST /api/v1/server/settings`.
- Open `Client updates`, check "Use global AD settings", confirm the username/password inputs become disabled.
- Seed an outdated client, select it, click "Update selected".
- Confirm via `GET /api/v1/client-install/<jobId>` that the resulting job's stored `username` matches the AD-configured account, not blank/service-identity - proving `useAdCredentials` genuinely reached `TryResolveAdSyncCredentials` through this tab.

- [ ] **Step 7: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js
git commit -m "Add Use global AD settings checkbox to Client updates"
```

---

### Task 6: Documentation and version bump

**Files:**
- Modify: `README.md`
- Modify: `README_RU.md`
- Modify: `CHANGELOG.md`
- Modify: `src/server/WindowsInventoryLiteServer.cs:23` (`ProductVersion`)

**Interfaces:**
- Consumes: the shipped behavior from Tasks 1-5.
- Produces: nothing (terminal task).

- [ ] **Step 1: Update README.md**

Find the existing section describing AD Description Sync (search for "AD Description" or "Active Directory" in `README.md`). Update it to describe the split: "Configure AD identity" governs credential availability for Client actions/Client updates/AD Computer Import; "Sync Description from AD" independently governs the periodic Description write; turning the latter off makes the Clients table's Description column inline-editable. Also add a sentence to the Client updates section noting the new "Use global AD settings" checkbox, matching how Client actions' equivalent checkbox is already documented there.

- [ ] **Step 2: Update README_RU.md**

Apply the same content changes as Step 1, adapted (not mechanically translated) for the Russian README, matching its existing tone and section structure.

- [ ] **Step 3: Add the CHANGELOG entry**

In `CHANGELOG.md`, add a new entry above the current top entry (`[0.20.2]`):

```markdown
## [0.21.0] - 2026-07-21

### Added

- The Clients table's Description column is now editable directly in the dashboard whenever AD Description Sync is off - previously it was always a read-only cache of AD's own value. `Settings > General > Active Directory` splits the old single "Enable AD sync" checkbox into "Configure AD identity" (domain/credentials, used by Client actions, Client updates, and AD Computer Import) and a new "Sync Description from AD" toggle (just the periodic Description write). Turning identity on but Description sync off keeps AD credentials usable everywhere else while making Description a manually-editable field (column header reads "Description" instead of "AD Description"). Existing deployments that already had AD sync enabled keep syncing Description after the upgrade with no action needed - the new toggle inherits the old flag's value automatically.
- `Client updates` gained the same "Use global AD settings" checkbox `Client actions` got in 0.20.0 - substitutes the AD identity credentials for the saved Client Update account on a push, with the same validation (AD identity must be configured, and a saved account or service identity must actually be usable).

### Changed

- `Client actions`' existing "Use global AD settings" checkbox now depends on "Configure AD identity" specifically rather than the old single AD-sync flag - no behavior change for existing users (the flag it depends on is the one that kept its meaning across the split).
```

- [ ] **Step 4: Bump the version**

In `src/server/WindowsInventoryLiteServer.cs:23`, change:

```csharp
        internal const string ProductVersion = "0.20.2";
```

to:

```csharp
        internal const string ProductVersion = "0.21.0";
```

- [ ] **Step 5: Rebuild and run the full verification suite**

Run: `pwsh -File src/Build-Server.ps1` then `./build/WindowsInventoryLiteServer.exe --self-test`
Expected: 56 PASS, 0 FAIL.

- [ ] **Step 6: Commit**

```bash
git add README.md README_RU.md CHANGELOG.md src/server/WindowsInventoryLiteServer.cs
git commit -m "Document AD-editable Description and Client updates AD credentials; bump to 0.21.0"
```

---

## Final Verification (after all tasks, before push)

- [ ] Full self-test suite: 56 PASS, 0 FAIL.
- [ ] Live Playwright pass covering: Description column toggling between read-only/editable as the new setting changes, inline edit save/cancel/error paths, the live-poll focus-preservation behavior, and the Client updates "Use global AD settings" checkbox disabling its fields.
- [ ] Push to `didimozg/windows-inventory-lite`'s `ad-integration` branch via the established `git subtree split --prefix=PowerShell/monitoring/windows-inventory-lite` workflow.
