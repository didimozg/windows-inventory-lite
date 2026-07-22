# AD Computer Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an administrator pull a list of computer names directly from Active Directory (scoped to one or more Organizational Units, or the whole domain) and use it to pre-fill the Targets field on the `Client actions` tab.

**Architecture:** A one-shot "Load from AD" action. The OU list is a saved setting (newline-separated DNs) edited in General settings' existing Active Directory panel, reusing the AD Domain/credentials already configured there. A new `GET /api/v1/ad/computers` endpoint queries AD (via a new `AdLookupService.SearchComputers` method) and returns a deduplicated, sorted computer-name list plus per-OU warnings. Clicking "Load from AD" on `Client actions` calls this endpoint and replaces the Targets textarea's content with the result.

**Tech Stack:** C# (.NET Framework, hand-rolled server, `System.DirectoryServices`), vanilla JS dashboard.

## Global Constraints

- No new AD credentials/domain field - reuses `options.AdDomain`, `options.AdUseServiceIdentity`, `options.AdUsername`, `options.AdPassword`.
- OU list (`AdComputerImportOUs`) is one DN per line, split **only on `\r`/`\n`** - never comma/semicolon/space (a DN itself contains commas).
- Empty OU list means "search the whole domain," not "search nothing."
- Every search is `SearchScope.Subtree`. No recursive-scope toggle in this iteration.
- The result is not filtered by inventory-report status - it is the raw AD computer list for the configured scope.
- A single failing OU is skipped and reported as a warning string; the rest still return results. Only a total failure (every configured OU failed, or the single whole-domain search failed) fails the whole request, with `500`.
- "Load from AD" **replaces** the Targets textarea's content - never merges/appends.
- `DirectorySearcher.PageSize` must be set explicitly on every search (e.g. `1000`) - AD silently truncates at the domain controller's own limit otherwise.
- No `Install-Server.ps1` CLI flag for the OU list - dashboard-only, same reasoning as `ClientUpdateUsername`/`ClientUpdatePassword`.
- Version bump: `0.17.4` -> `0.18.0` (MINOR - new feature, per this project's versioning convention).

---

### Task 1: OU-list parsing (pure function + self-tests)

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs` (add `ParseAdComputerImportOUs` near `ExpandInstallTargets`/`NormalizeComputerList`, and its self-tests near `TestExpandInstallTargetsDedup`)

**Interfaces:**
- Produces: `private static ArrayList ParseAdComputerImportOUs(string raw)` - returns one trimmed, non-empty DN string per input line, in input order, no dedup/sort (Task 2 handles dedup of the *computer names* returned by AD, not the OU list itself).

- [ ] **Step 1: Write the failing self-tests**

Find this registration line (search for `TestExpandInstallTargetsDedup` in the self-test registration list, right after the `ExpandInstallTargets` line):

```csharp
            allPassed &= SelfTestCheck(output, "ExpandInstallTargets de-duplicates and splits on separators", TestExpandInstallTargetsDedup);
```

Add two new lines immediately after it:

```csharp
            allPassed &= SelfTestCheck(output, "ExpandInstallTargets de-duplicates and splits on separators", TestExpandInstallTargetsDedup);
            allPassed &= SelfTestCheck(output, "ParseAdComputerImportOUs splits on newlines only, not commas", TestParseAdComputerImportOUsSplitsOnNewlinesOnly);
            allPassed &= SelfTestCheck(output, "ParseAdComputerImportOUs treats blank input as an empty OU list", TestParseAdComputerImportOUsEmptyMeansWholeDomain);
```

Find the `TestExpandInstallTargetsDedup` method body (search for `private static string TestExpandInstallTargetsDedup()`) and add the two new test methods immediately after its closing `}`:

```csharp
        private static string TestParseAdComputerImportOUsSplitsOnNewlinesOnly()
        {
            ArrayList result = ParseAdComputerImportOUs("OU=Workstations,OU=Kaliningrad,DC=spb,DC=cccb,DC=ru\r\n\r\nOU=Servers,DC=spb,DC=cccb,DC=ru\n  \nOU=Third,DC=x,DC=y  ");
            string[] expected = new string[] {
                "OU=Workstations,OU=Kaliningrad,DC=spb,DC=cccb,DC=ru",
                "OU=Servers,DC=spb,DC=cccb,DC=ru",
                "OU=Third,DC=x,DC=y"
            };
            return CompareStringLists(expected, result);
        }

        private static string TestParseAdComputerImportOUsEmptyMeansWholeDomain()
        {
            ArrayList result = ParseAdComputerImportOUs("   ");
            if (result.Count != 0)
            {
                return "expected a blank/whitespace-only input to produce zero OUs, got " + result.Count;
            }
            return null;
        }
```

- [ ] **Step 2: Run the build and self-test to confirm the new tests fail to compile (function not defined yet)**

Run (from the `windows-inventory-lite` directory):
```powershell
& .\src\Build-Server.ps1
```
Expected: FAIL - `error CS0103: The name 'ParseAdComputerImportOUs' does not exist in the current context` (or similar) at both new test methods.

- [ ] **Step 3: Implement `ParseAdComputerImportOUs`**

Find `ExpandInstallTargets` (search for `private static ArrayList ExpandInstallTargets(string input)`). Add the new function immediately before it:

```csharp
        // One OU Distinguished Name per line - not reused with
        // ExpandInstallTargets' comma/semicolon/space splitting below, since
        // a DN's own RDN components are themselves comma-separated
        // (e.g. "OU=Workstations,OU=Kaliningrad,DC=spb,DC=cccb,DC=ru") and
        // would be shredded by that splitter.
        private static ArrayList ParseAdComputerImportOUs(string raw)
        {
            ArrayList result = new ArrayList();
            if (String.IsNullOrEmpty(raw))
            {
                return result;
            }
            string[] lines = raw.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                string trimmed = line.Trim();
                if (trimmed.Length > 0)
                {
                    result.Add(trimmed);
                }
            }
            return result;
        }

```

- [ ] **Step 4: Rebuild and run self-test to verify all tests pass**

Run:
```powershell
Get-Process -Name WindowsInventoryLiteServer -ErrorAction SilentlyContinue | Stop-Process -Force
& .\src\Build-Server.ps1
& .\build\WindowsInventoryLiteServer.exe --self-test
```
Expected: build succeeds; self-test output includes:
```
PASS ParseAdComputerImportOUs splits on newlines only, not commas
PASS ParseAdComputerImportOUs treats blank input as an empty OU list
```
and the total PASS count increased by 2 with 0 FAIL.

- [ ] **Step 5: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add ParseAdComputerImportOUs for the AD computer import OU list"
```

---

### Task 2: `AdLookupService.SearchComputers` + `ServerOptions` field + config load

**Files:**
- Modify: `src/server/AdLookupService.cs` (add `AdComputerSearchResult`, `SearchComputers`, `SearchOneRoot`)
- Modify: `src/server/WindowsInventoryLiteServer.cs` (add `AdComputerImportOUs` field to `ServerOptions`, wire config load)

**Interfaces:**
- Consumes: `ParseAdComputerImportOUs` (Task 1) - not called from this task's own code, but its `ArrayList` return type is exactly what `SearchComputers` accepts as `organizationalUnits`.
- Produces:
  - `internal sealed class AdComputerSearchResult { public ArrayList Computers; public ArrayList Warnings; public bool AllAttemptsFailed; }`
  - `internal static AdComputerSearchResult AdLookupService.SearchComputers(ArrayList organizationalUnits, ServerOptions options)`
  - `public string ServerOptions.AdComputerImportOUs` - the raw, unparsed, newline-separated setting value.

- [ ] **Step 1: Add the `AdComputerImportOUs` field to `ServerOptions`**

Find this line in `src/server/WindowsInventoryLiteServer.cs` (in the `ServerOptions` class, right after `public string AdPassword;`):

```csharp
        public string AdDomain;
        public bool AdUseServiceIdentity;
        public string AdUsername;
        public string AdPassword;
```

Replace with:

```csharp
        public string AdDomain;
        public bool AdUseServiceIdentity;
        public string AdUsername;
        public string AdPassword;
        // Newline-separated list of OU Distinguished Names for the AD
        // Computer Import feature ("Load from AD" on Client actions) - see
        // docs/superpowers/specs/2026-07-20-ad-computer-import-design.md.
        // Empty means "search the whole domain." Not a secret - stored as
        // plain text, same as AdDomain. Dashboard-only, no Install-Server.ps1
        // CLI flag, same reasoning as ClientUpdateUsername below.
        public string AdComputerImportOUs;
```

- [ ] **Step 2: Wire config-file loading**

Find this block in `LoadConfigFile` (search for `options.AdPassword = SecretProtector.Unprotect(GetConfigString(config, "AdPassword"));`):

```csharp
                if (String.IsNullOrEmpty(options.AdPassword))
                {
                    // Decrypts a DPAPI-protected value (see SecretProtector.cs);
                    // a legacy/hand-edited plaintext value is used as-is.
                    options.AdPassword = SecretProtector.Unprotect(GetConfigString(config, "AdPassword"));
                }
```

Add immediately after it:

```csharp
                if (String.IsNullOrEmpty(options.AdComputerImportOUs))
                {
                    options.AdComputerImportOUs = GetConfigString(config, "AdComputerImportOUs");
                }
```

- [ ] **Step 3: Rebuild to confirm the field compiles and is wired**

Run:
```powershell
& .\src\Build-Server.ps1
```
Expected: builds cleanly (no new tests yet for this step - the field itself has no logic to unit test; `SendServerSettings`/`ConfigureServerSettings` round-trip it in Task 3, and `LoadConfigFile` is not independently unit-tested elsewhere in this project either, matching the existing `AdDomain`/`AdUsername` precedent).

- [ ] **Step 4: Add `using` directives to `AdLookupService.cs`**

`src/server/AdLookupService.cs` currently starts with:

```csharp
using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Text;
```

Replace with:

```csharp
using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Text;
```

(`ArrayList` needs `System.Collections`; the per-search `seen` dedup dictionary in Step 5 needs `System.Collections.Generic`.)

- [ ] **Step 5: Add `AdComputerSearchResult` and `SearchComputers`/`SearchOneRoot`**

Find the end of the `AdLookupService` class - the closing of `LookupComputerDescription` (search for the `return result;` immediately followed by `        }` and then `    }` and `}` that close the method, class, and namespace). The method ends like this:

```csharp
            DebugLogger.Log(options, "AD", message);
            }
            catch { }

            return result;
        }
    }
}
```

Insert the new class and methods immediately before the final `    }` (the one that closes `AdLookupService`), i.e. right after `LookupComputerDescription`'s closing `}` and before the class's own closing `}`:

```csharp
        }

        internal sealed class AdComputerSearchResult
        {
            public ArrayList Computers = new ArrayList();
            public ArrayList Warnings = new ArrayList();
            // True once every attempted search (the whole domain, or each
            // configured OU) has failed - the one case SendAdComputers
            // treats as a total failure (500) instead of a partial,
            // warning-carrying success (200).
            public bool AllAttemptsFailed;
        }

        internal static AdComputerSearchResult SearchComputers(ArrayList organizationalUnits, ServerOptions options)
        {
            AdComputerSearchResult result = new AdComputerSearchResult();
            Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            int attempted = 0;
            int failed = 0;

            if (organizationalUnits.Count == 0)
            {
                attempted++;
                if (!SearchOneRoot(null, options, seen, result.Computers, result.Warnings))
                {
                    failed++;
                }
            }
            else
            {
                foreach (string ou in organizationalUnits)
                {
                    attempted++;
                    if (!SearchOneRoot(ou, options, seen, result.Computers, result.Warnings))
                    {
                        failed++;
                    }
                }
            }

            result.Computers.Sort(StringComparer.OrdinalIgnoreCase);
            result.AllAttemptsFailed = failed == attempted;
            return result;
        }

        // Searches AD for computer objects under one root (an OU's DN, or
        // the whole domain when organizationalUnitDn is null) and adds any
        // found computer names into computers/seen (case-insensitive
        // dedup). Returns false (and appends one warning) if the search
        // itself failed - a bad/deleted OU DN, or AD being entirely
        // unreachable for the whole-domain case. Mirrors
        // LookupComputerDescription's own credential/domain-resolution and
        // debug-log conventions above.
        private static bool SearchOneRoot(string organizationalUnitDn, ServerOptions options, Dictionary<string, bool> seen, ArrayList computers, ArrayList warnings)
        {
            DirectoryEntry entry = null;
            DirectorySearcher searcher = null;
            string domain = null;
            string errorDetail = null;
            string status = "ok";
            int foundCount = 0;
            try
            {
                domain = !String.IsNullOrEmpty(options.AdDomain)
                    ? options.AdDomain
                    : Domain.GetComputerDomain().Name;
                string ldapPath = organizationalUnitDn != null
                    ? "LDAP://" + organizationalUnitDn
                    : "LDAP://" + domain;

                entry = options.AdUseServiceIdentity
                    ? new DirectoryEntry(ldapPath)
                    : new DirectoryEntry(ldapPath, options.AdUsername, options.AdPassword);

                searcher = new DirectorySearcher(entry);
                searcher.Filter = "(objectCategory=computer)";
                searcher.PropertiesToLoad.Add("cn");
                searcher.SearchScope = SearchScope.Subtree;
                searcher.PageSize = 1000;
                searcher.ClientTimeout = TimeSpan.FromSeconds(LdapTimeoutSeconds);

                using (SearchResultCollection foundResults = searcher.FindAll())
                {
                    foreach (SearchResult found in foundResults)
                    {
                        if (found.Properties["cn"].Count == 0)
                        {
                            continue;
                        }
                        string name = Convert.ToString(found.Properties["cn"][0]);
                        if (String.IsNullOrEmpty(name) || seen.ContainsKey(name))
                        {
                            continue;
                        }
                        seen[name] = true;
                        computers.Add(name);
                        foundCount++;
                    }
                }
            }
            catch (Exception ex)
            {
                status = "error";
                errorDetail = ex.Message;
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
                if (entry != null) entry.Dispose();
            }

            string rootDescription = organizationalUnitDn ?? "(whole domain)";
            try
            {
                string identity = options.AdUseServiceIdentity
                    ? "service identity"
                    : "explicit account '" + DebugLogger.SanitizeForLog(options.AdUsername) + "'";
                string message = "AD computer search for '" + DebugLogger.SanitizeForLog(rootDescription) + "' in domain '" + (domain ?? "(unresolved)")
                    + "' using " + identity + ": " + status + " (" + foundCount + " found)";
                if (errorDetail != null)
                {
                    message += " (" + DebugLogger.SanitizeForLog(errorDetail) + ")";
                }
                DebugLogger.Log(options, "AD", message);
            }
            catch { }

            if (status == "error")
            {
                string warning = organizationalUnitDn != null
                    ? "OU '" + organizationalUnitDn + "' could not be searched (" + errorDetail + ") - skipped."
                    : "The whole domain could not be searched (" + errorDetail + ").";
                warnings.Add(warning);
                return false;
            }
            return true;
        }
```

- [ ] **Step 6: Rebuild to confirm it compiles**

Run:
```powershell
Get-Process -Name WindowsInventoryLiteServer -ErrorAction SilentlyContinue | Stop-Process -Force
& .\src\Build-Server.ps1
& .\build\WindowsInventoryLiteServer.exe --self-test
```
Expected: builds cleanly; self-test still shows 0 FAIL (no new self-tests in this step - `SearchComputers`/`SearchOneRoot` need a real AD connection to exercise meaningfully, matching this project's existing precedent that `LookupComputerDescription` itself is not unit-tested either. Live verification happens in Task 9, on the user's real domain).

- [ ] **Step 7: Commit**

```bash
git add src/server/AdLookupService.cs src/server/WindowsInventoryLiteServer.cs
git commit -m "Add AdLookupService.SearchComputers and the AdComputerImportOUs setting"
```

---

### Task 3: API endpoint + settings GET/POST wiring + routing

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs` (add `SendAdComputers`, extend `SendServerSettings`/`ConfigureServerSettings`, add the route)

**Interfaces:**
- Consumes: `ParseAdComputerImportOUs` (Task 1), `AdLookupService.SearchComputers`/`AdComputerSearchResult` (Task 2), `options.AdComputerImportOUs` (Task 2).
- Produces: `GET /api/v1/ad/computers` -> `{"computers": [...], "warnings": [...]}` (200) or `{"error": "..."}` (500). `adComputerImportOUs` field on the existing `GET`/`POST /api/v1/server/settings` payloads.

- [ ] **Step 1: Add the route**

Find this block (search for `else if (request.Method == "POST" && request.Path == "/api/v1/server/settings")`):

```csharp
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/settings")
                    {
                        SendServerSettings(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/settings")
                    {
                        ConfigureServerSettings(stream, request);
                    }
```

Add immediately after it:

```csharp
                    else if (request.Method == "GET" && request.Path == "/api/v1/ad/computers")
                    {
                        SendAdComputers(stream);
                    }
```

- [ ] **Step 2: Add `SendAdComputers`**

Find `SendServerSettings` (search for `private void SendServerSettings(Stream stream)`). Add the new method immediately before it:

```csharp
        private void SendAdComputers(Stream stream)
        {
            ArrayList organizationalUnits = ParseAdComputerImportOUs(options.AdComputerImportOUs);
            AdComputerSearchResult result = AdLookupService.SearchComputers(organizationalUnits, options);

            if (result.AllAttemptsFailed)
            {
                string detail = result.Warnings.Count > 0
                    ? String.Join(" ", (string[])result.Warnings.ToArray(typeof(string)))
                    : "Active Directory could not be reached.";
                SendText(stream, "{\"error\":\"" + detail.Replace("\"", "'") + "\"}", "application/json; charset=utf-8", 500);
                return;
            }

            Dictionary<string, object> response = new Dictionary<string, object>();
            response["computers"] = result.Computers;
            response["warnings"] = result.Warnings;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(response));
        }

```

- [ ] **Step 3: Extend `SendServerSettings`**

Find:

```csharp
            result["adUsername"] = options.AdUseServiceIdentity ? null : options.AdUsername;
            result["debugLogEnabled"] = options.DebugLogEnabled;
```

Replace with:

```csharp
            result["adUsername"] = options.AdUseServiceIdentity ? null : options.AdUsername;
            result["adComputerImportOUs"] = options.AdComputerImportOUs;
            result["debugLogEnabled"] = options.DebugLogEnabled;
```

- [ ] **Step 4: Extend `ConfigureServerSettings`**

Find the gating condition:

```csharp
            if (payload.ContainsKey("adSyncEnabled") || payload.ContainsKey("adSyncMode") || payload.ContainsKey("adSyncIntervalHours")
                || payload.ContainsKey("adDomain") || payload.ContainsKey("adUseServiceIdentity") || payload.ContainsKey("adUsername") || payload.ContainsKey("adPassword"))
            {
```

Replace with:

```csharp
            if (payload.ContainsKey("adSyncEnabled") || payload.ContainsKey("adSyncMode") || payload.ContainsKey("adSyncIntervalHours")
                || payload.ContainsKey("adDomain") || payload.ContainsKey("adUseServiceIdentity") || payload.ContainsKey("adUsername") || payload.ContainsKey("adPassword")
                || payload.ContainsKey("adComputerImportOUs"))
            {
```

Find:

```csharp
                options.AdSyncEnabled = adSyncEnabled;
                options.AdSyncMode = adSyncMode;
                options.AdSyncIntervalHours = adSyncIntervalHours;
                options.AdDomain = adDomain;
                options.AdUseServiceIdentity = adUseServiceIdentity;
                options.AdUsername = adUsername;
                options.AdPassword = adPassword;
                ReconfigureAdSyncTimer();

                updates["AdSyncEnabled"] = options.AdSyncEnabled ? "true" : "false";
                updates["AdSyncMode"] = options.AdSyncMode;
                updates["AdSyncIntervalHours"] = options.AdSyncIntervalHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
                updates["AdDomain"] = options.AdDomain ?? "";
                updates["AdUseServiceIdentity"] = options.AdUseServiceIdentity ? "true" : "false";
                updates["AdUsername"] = options.AdUsername ?? "";
                updates["AdPassword"] = options.AdPassword ?? "";
            }
```

Replace with:

```csharp
                options.AdSyncEnabled = adSyncEnabled;
                options.AdSyncMode = adSyncMode;
                options.AdSyncIntervalHours = adSyncIntervalHours;
                options.AdDomain = adDomain;
                options.AdUseServiceIdentity = adUseServiceIdentity;
                options.AdUsername = adUsername;
                options.AdPassword = adPassword;
                options.AdComputerImportOUs = payload.ContainsKey("adComputerImportOUs") ? Convert.ToString(payload["adComputerImportOUs"]) : options.AdComputerImportOUs;
                ReconfigureAdSyncTimer();

                updates["AdSyncEnabled"] = options.AdSyncEnabled ? "true" : "false";
                updates["AdSyncMode"] = options.AdSyncMode;
                updates["AdSyncIntervalHours"] = options.AdSyncIntervalHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
                updates["AdDomain"] = options.AdDomain ?? "";
                updates["AdUseServiceIdentity"] = options.AdUseServiceIdentity ? "true" : "false";
                updates["AdUsername"] = options.AdUsername ?? "";
                updates["AdPassword"] = options.AdPassword ?? "";
                updates["AdComputerImportOUs"] = options.AdComputerImportOUs ?? "";
            }
```

(`adComputerImportOUs` is applied and persisted inside the same gated block as the other AD fields, rather than its own top-level `if (payload.ContainsKey("adComputerImportOUs"))` block, because `saveGeneralSettings` in the dashboard always sends every AD field together in one request - see Task 4.)

- [ ] **Step 5: Rebuild and self-test**

Run:
```powershell
Get-Process -Name WindowsInventoryLiteServer -ErrorAction SilentlyContinue | Stop-Process -Force
& .\src\Build-Server.ps1
& .\build\WindowsInventoryLiteServer.exe --self-test
```
Expected: builds cleanly, self-test still 0 FAIL (no new self-tests here - this is HTTP-handler wiring, and this project's existing precedent is to verify handlers like this via live functional HTTP checks, not self-test - do that verification now):

```powershell
$dataDir = Join-Path $env:TEMP ("wil-task3-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$p = Start-Process -FilePath .\build\WindowsInventoryLiteServer.exe -ArgumentList @('--console','--port','18097','--data',$dataDir,'--content','server\dashboard') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dataDir 'out.log') -RedirectStandardError (Join-Path $dataDir 'err.log')
Start-Sleep -Seconds 2
Invoke-RestMethod http://localhost:18097/api/v1/server/settings | Select-Object adComputerImportOUs
Invoke-RestMethod -Method Post -Uri http://localhost:18097/api/v1/server/settings -ContentType 'application/json' -Body '{"adComputerImportOUs":"OU=Test,DC=example,DC=com"}'
(Invoke-RestMethod http://localhost:18097/api/v1/server/settings).adComputerImportOUs
Invoke-RestMethod http://localhost:18097/api/v1/ad/computers
Stop-Process -Id $p.Id -Force
Remove-Item $dataDir -Recurse -Force
```
Expected: first settings GET shows `adComputerImportOUs` as `$null`/empty; the POST succeeds; the second GET shows `OU=Test,DC=example,DC=com`; `GET /api/v1/ad/computers` returns a `500` (this dev machine is not domain-joined and `OU=Test,DC=example,DC=com` does not exist) with a JSON `error` field describing the failure - confirming the endpoint round-trips the setting and reports a total failure correctly. A real success/partial-warning response needs the user's own domain (Task 9).

- [ ] **Step 6: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add GET /api/v1/ad/computers and wire adComputerImportOUs into server settings"
```

---

### Task 4: General settings UI - OU list field

**Files:**
- Modify: `server/dashboard/index.html` (add the OU textarea to the Active Directory panel)
- Modify: `server/dashboard/app.js` (load/save the new field)

**Interfaces:**
- Consumes: `adComputerImportOUs` field on `GET`/`POST /api/v1/server/settings` (Task 3).

- [ ] **Step 1: Add the textarea to the Active Directory panel**

Find in `server/dashboard/index.html`:

```html
              <label id="generalAdPasswordField" class="pkg-token-field hidden">
                AD password
                <input id="generalAdPassword" type="password" autocomplete="new-password" placeholder="leave blank to keep the current password">
              </label>
            </div>
```

Replace with:

```html
              <label id="generalAdPasswordField" class="pkg-token-field hidden">
                AD password
                <input id="generalAdPassword" type="password" autocomplete="new-password" placeholder="leave blank to keep the current password">
              </label>
              <label class="pkg-token-field">
                Organizational Units (DN, one per line)
                <textarea id="generalAdComputerImportOUs" rows="3" placeholder="OU=Workstations,OU=Kaliningrad,DC=spb,DC=cccb,DC=ru"></textarea>
              </label>
            </div>
```

- [ ] **Step 2: Load the field**

Find in `server/dashboard/app.js`:

```javascript
        byId('generalAdDomain').value = data.adDomain || '';
        byId('generalAdUseServiceIdentity').checked = data.adUseServiceIdentity !== false;
        byId('generalAdUsername').value = data.adUsername || '';
        byId('generalAdPassword').value = '';
```

Replace with:

```javascript
        byId('generalAdDomain').value = data.adDomain || '';
        byId('generalAdUseServiceIdentity').checked = data.adUseServiceIdentity !== false;
        byId('generalAdUsername').value = data.adUsername || '';
        byId('generalAdPassword').value = '';
        byId('generalAdComputerImportOUs').value = data.adComputerImportOUs || '';
```

- [ ] **Step 3: Save the field**

Find:

```javascript
        adDomain: byId('generalAdDomain').value.trim(),
        adUseServiceIdentity: byId('generalAdUseServiceIdentity').checked,
        adUsername: byId('generalAdUsername').value.trim(),
        adPassword: byId('generalAdPassword').value,
        debugLogEnabled: byId('generalDebugLogEnabled').checked
```

Replace with:

```javascript
        adDomain: byId('generalAdDomain').value.trim(),
        adUseServiceIdentity: byId('generalAdUseServiceIdentity').checked,
        adUsername: byId('generalAdUsername').value.trim(),
        adPassword: byId('generalAdPassword').value,
        adComputerImportOUs: byId('generalAdComputerImportOUs').value,
        debugLogEnabled: byId('generalDebugLogEnabled').checked
```

(Not `.trim()`-ed as a whole string - trimming would collapse the newlines between OU lines. `ParseAdComputerImportOUs`, Task 1, trims each individual line server-side.)

- [ ] **Step 4: Rebuild and verify visually**

Run:
```powershell
Get-Process -Name WindowsInventoryLiteServer -ErrorAction SilentlyContinue | Stop-Process -Force
& .\src\Build-Server.ps1
```
Start a local console-mode instance (scratch data dir, port 18097, `--content server\dashboard`) as in Task 3, open `http://localhost:18097/` with Playwright, navigate to Settings > General, confirm the new "Organizational Units (DN, one per line)" textarea appears in the Active Directory panel below "AD password", type a value, click Save, reload the page, confirm the value persisted. Stop the server and remove the scratch directory afterward.

- [ ] **Step 5: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js
git commit -m "Add Organizational Units field to the General settings AD panel"
```

---

### Task 5: Client actions UI - "Load from AD" button

**Files:**
- Modify: `server/dashboard/index.html` (restructure the Targets field, add the button + message area)
- Modify: `server/dashboard/app.js` (add `loadTargetsFromAd`, wire the button)

**Interfaces:**
- Consumes: `GET /api/v1/ad/computers` (Task 3), `showSavedMessage(el, msg, isError)` (already defined in `app.js`, added in the earlier backlog-fix batch - auto-hides success messages after 30s, leaves errors visible).

- [ ] **Step 1: Restructure the Targets field and add the button**

Find in `server/dashboard/index.html`:

```html
            <label class="install-targets-field">
              Targets
              <textarea id="installTargets" rows="4" placeholder="PC-001&#10;PC-002&#10;192.0.2.10&#10;192.0.2.20-192.0.2.30"></textarea>
            </label>
```

Replace with:

```html
            <div class="install-targets-field">
              <label>
                Targets
                <textarea id="installTargets" rows="4" placeholder="PC-001&#10;PC-002&#10;192.0.2.10&#10;192.0.2.20-192.0.2.30"></textarea>
              </label>
              <div class="pkg-buttons">
                <button id="installLoadAdButton" class="export-button" type="button">Load from AD</button>
              </div>
              <div id="installAdMessage" class="pkg-message hidden"></div>
            </div>
```

(Changed the outer element from `<label>` to `<div>` - a `<label>` should wrap only the one control it labels, the textarea; the button and message area are siblings inside the same `.install-targets-field` grid cell, not part of the Targets label. `.install-grid label { display: grid; ... }`'s CSS selector is a descendant selector, so it still applies to the inner `<label>` unchanged - only the outer wrapping element's tag changed, not its class or its grid placement.)

- [ ] **Step 2: Add `loadTargetsFromAd`**

Find `startClientActionJob` (search for `function startClientActionJob()`). Add the new function immediately before it:

```javascript
  function loadTargetsFromAd() {
    const messageElement = byId('installAdMessage');
    byId('installLoadAdButton').disabled = true;

    fetch('/api/v1/ad/computers', { cache: 'no-store' })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'AD search failed');

        const computers = data.computers || [];
        const warnings = data.warnings || [];
        if (computers.length === 0) {
          showSavedMessage(messageElement, 'No computers found for the configured scope.', false);
          return;
        }

        byId('installTargets').value = computers.join('\n');
        const lines = [`Loaded ${computers.length} computer(s) from AD.`, ...warnings];
        showSavedMessage(messageElement, lines.join('\n'), false);
      })
      .catch(error => {
        showSavedMessage(messageElement, `Failed to load from AD: ${error.message}`, true);
      })
      .finally(() => {
        byId('installLoadAdButton').disabled = false;
      });
  }

```

- [ ] **Step 3: Wire the button**

Find:

```javascript
  byId('installButton').addEventListener('click', startClientActionJob);
```

Replace with:

```javascript
  byId('installButton').addEventListener('click', startClientActionJob);
  byId('installLoadAdButton').addEventListener('click', loadTargetsFromAd);
```

- [ ] **Step 4: Rebuild and verify visually with a mocked response**

Run:
```powershell
Get-Process -Name WindowsInventoryLiteServer -ErrorAction SilentlyContinue | Stop-Process -Force
& .\src\Build-Server.ps1
```
Start a local console-mode instance as in Task 3. With Playwright, navigate to the dashboard, open Client actions, use `page.route('**/api/v1/ad/computers', ...)` to mock three responses in turn against the real running page:
1. `{"computers":["PC-001","PC-002"],"warnings":[]}` - click "Load from AD", confirm Targets now reads `PC-001\nPC-002` and the message shows "Loaded 2 computer(s) from AD."
2. `{"computers":[],"warnings":[]}` - click again, confirm Targets is unchanged from step 1's value (not cleared) and the message shows "No computers found for the configured scope."
3. `{"error":"Active Directory could not be reached."}` with HTTP status 500 - click again, confirm Targets is still unchanged and the message shows "Failed to load from AD: Active Directory could not be reached." styled with the `.error` class.

Stop the server and remove the scratch directory afterward.

- [ ] **Step 5: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js
git commit -m "Add Load from AD button to Client actions Targets field"
```

---

### Task 6: Frontend design consistency review

Dispatch a review using the `/frontend-design` skill's review perspective (not building anything new - auditing what Tasks 4-5 just added) against the two new UI surfaces:

1. The "Organizational Units (DN, one per line)" field in General settings' Active Directory panel (Task 4).
2. The "Load from AD" button and its message area on Client actions (Task 5).

Ask it to check specifically:
- Does the new textarea in the AD panel match the established 420px single-column `.ad-identity-panel` treatment, or does it look bolted-on?
- Does "Load from AD" (`.export-button`) read as the right visual weight next to the Targets field - not competing with the primary "Install client" button, not looking like a destructive/dangerous action?
- Does the message area under the button follow the same `.pkg-message`/`.error` conventions as every other save/action message in this dashboard, in both light and dark theme?
- Any spacing, alignment, or responsive (narrow-viewport) issues introduced by changing `.install-targets-field` from a `<label>` to a `<div>` wrapping an inner `<label>`.

- [ ] **Step 1: Take before/after screenshots and run the review**

With a local console-mode instance running (as in prior tasks) and Playwright available, capture screenshots of both new UI surfaces in light and dark theme, then produce a written consistency assessment against the points above, citing this dashboard's own existing CSS classes/patterns (not proposing a new visual language - see the project's established calibration for this kind of review: audits target consistency with the dashboard's own "instrument panel" aesthetic, never a redesign).

- [ ] **Step 2: Fix any findings**

Apply any Important/Critical findings directly (e.g. a missing `.pkg-buttons` wrapper, a spacing mismatch) - Minor/cosmetic findings that don't match this dashboard's own established conventions can be recorded and deferred, matching how prior design-consistency findings in this project were triaged.

- [ ] **Step 3: Commit any fixes**

```bash
git add server/dashboard/index.html server/dashboard/styles.css server/dashboard/app.js
git commit -m "Fix frontend design consistency findings for AD computer import UI"
```

(Skip this step entirely if the review found nothing to fix.)

---

### Task 7: Security review

Dispatch a security review (this project's established `/security-review` checklist) scoped to exactly what this plan added:

1. `src/server/AdLookupService.cs` - `SearchComputers`/`SearchOneRoot` (Task 2).
2. `src/server/WindowsInventoryLiteServer.cs` - `SendAdComputers`, the `AdComputerImportOUs` settings wiring, `ParseAdComputerImportOUs` (Tasks 1-3).
3. `server/dashboard/app.js` - `loadTargetsFromAd` (Task 5).

Points the review must specifically verify, not just generically check:

- **LDAP injection / path construction:** `SearchOneRoot` builds `"LDAP://" + organizationalUnitDn` directly from `options.AdComputerImportOUs` (admin-configured, saved only through the authenticated `/api/v1/server/settings` endpoint) with no `LdapFilterEscaper`-style escaping - unlike `LookupComputerDescription`, which escapes the client-reported `computerName` before embedding it in a *search filter* clause (`cn=...`). Confirm this distinction is actually sound: the OU DN here is used as a directory *path*, not interpolated into the `(objectCategory=computer)` filter string, and it is trusted admin config (same trust level as the already-unescaped `AdDomain`), not attacker-influenceable client-reported data. Flag it as a real gap only if either premise turns out to be wrong.
- **Information disclosure:** `SendAdComputers` returns raw `ex.Message` text (via `SearchOneRoot`'s `errorDetail`) in both the per-OU `warnings` array and the total-failure `error` body. Confirm this matches the project's existing convention (`AdLookupService.LookupComputerDescription` already logs raw `ex.Message` to the debug log, and other endpoints like the certificate-store failure at `DeleteCertificate` also return a fairly specific message) rather than being a new, broader disclosure - and confirm no credential material (`AdPassword`) could ever end up inside an `Exception.Message` from `DirectoryEntry`/`DirectorySearcher` construction.
- **Resource handling:** `SearchOneRoot` disposes `DirectorySearcher`/`DirectoryEntry` in a `finally` block and wraps `SearchResultCollection` in a `using` - confirm there is no leak on any exception path, including one thrown mid-enumeration of `foundResults`.
- **Authorization:** confirm `GET /api/v1/ad/computers` is reached only through the same `IsWebRequestAuthorized` gate every other management-API route already goes through (it should be, by virtue of sitting in the same `else if` chain - verify this wasn't accidentally placed outside it).
- **Denial of service:** an OU list with many entries means many sequential AD searches per request, each bounded by the existing 15-second `LdapTimeoutSeconds`. Confirm there's no unbounded-size input to `AdComputerImportOUs` that could make one request take pathologically long (it's admin-configured, not attacker-supplied, but note whether an accidental huge/malformed list is at least bounded by *something*, or explicitly flag it as accepted risk given the trust level).
- **Config field consistency:** confirm `AdComputerImportOUs` was correctly *not* added to any DPAPI-encryption path (`SecretProtector`) - it is not a secret, and encrypting it would be inconsistent with `AdDomain` while also being pointless overhead.

- [ ] **Step 1: Run the review and record findings**

- [ ] **Step 2: Fix Critical/Important findings**

Apply fixes directly for anything Critical or Important. Record any Minor findings inline as code comments or defer them explicitly with a one-line note in the final commit message - do not silently drop them.

- [ ] **Step 3: Rebuild, self-test, and commit any fixes**

```powershell
& .\src\Build-Server.ps1
& .\build\WindowsInventoryLiteServer.exe --self-test
```
Expected: 0 FAIL.

```bash
git add -A
git commit -m "Fix security review findings for AD computer import"
```

(Skip the commit entirely if the review found nothing to fix.)

---

### Task 8: Documentation and version bump

**Files:**
- Modify: `README.md`, `README_RU.md` (new subsection after "Active Directory Description Sync")
- Modify: `docs/threat-model.md` (note the new AD query path)
- Modify: `CHANGELOG.md` (new `0.18.0` entry)
- Modify: `src/server/WindowsInventoryLiteServer.cs` (version bump)

- [ ] **Step 1: Bump the version**

Find:

```csharp
        internal const string ProductVersion = "0.17.4";
```

Replace with:

```csharp
        internal const string ProductVersion = "0.18.0";
```

- [ ] **Step 2: Add the README.md section**

Find:

```markdown
If a computer's name has no matching AD computer object, the column shows "Not found in AD"; if AD itself was unreachable at sync time, it shows "AD unreachable" and the next report/sweep retries rather than waiting out the full sync interval.

## Diagnostics
```

Replace with:

```markdown
If a computer's name has no matching AD computer object, the column shows "Not found in AD"; if AD itself was unreachable at sync time, it shows "AD unreachable" and the next report/sweep retries rather than waiting out the full sync interval.

## AD Computer Import

On the `Client actions` tab, "Load from AD" pulls a list of computer names directly from Active Directory and fills the Targets field with it, replacing whatever was there - a faster starting point than typing names by hand before a WinRM install/uninstall push.

It searches whichever Organizational Units are configured in Settings > General's Active Directory panel ("Organizational Units (DN, one per line)" - one Distinguished Name per line, e.g. `OU=Workstations,OU=Kaliningrad,DC=spb,DC=cccb,DC=ru`), including everything nested under each one. Leave the list empty to search the whole domain instead. It uses the same AD Domain/credentials already configured for AD Description Sync above - there is nothing new to set up if that's already configured.

The result is the raw computer list for the configured scope - it is not filtered by whether a computer has ever reported inventory, so trim it by hand afterward if a particular push (e.g. an uninstall) only makes sense for a subset. If one configured OU can't be searched (a typo, a deleted OU), it's skipped and reported as a warning; the rest still load normally.

## Diagnostics
```

- [ ] **Step 3: Add the matching README_RU.md section**

Find in `README_RU.md`:

```markdown
Если имени компьютера не находится соответствующий объект в AD, колонка показывает «Not found in AD»; если AD была недоступна в момент синхронизации — «AD unreachable», а следующий отчёт или проход таймера повторит попытку, не дожидаясь окончания всего интервала синхронизации.

## Диагностика
```

Replace with:

```markdown
Если имени компьютера не находится соответствующий объект в AD, колонка показывает «Not found in AD»; если AD была недоступна в момент синхронизации — «AD unreachable», а следующий отчёт или проход таймера повторит попытку, не дожидаясь окончания всего интервала синхронизации.

## Импорт списка компьютеров из AD

На вкладке `Client actions` кнопка «Load from AD» подтягивает список компьютеров прямо из Active Directory и подставляет его в поле Targets, заменяя то, что там было - быстрее, чем вводить имена вручную перед WinRM-установкой или удалением.

Ищет по тем Organizational Units, что указаны в блоке «Active Directory» на странице Settings > General («Organizational Units (DN, one per line)» - один Distinguished Name на строку, например `OU=Workstations,OU=Kaliningrad,DC=spb,DC=cccb,DC=ru`), включая всё вложенное внутрь каждой из них. Если список пуст, поиск идёт по всему домену. Используются те же домен и учётные данные AD, что уже настроены для синхронизации Description выше - если она уже настроена, донастраивать нечего.

Результат - сырой список компьютеров для указанной области поиска, без фильтрации по тому, отчитывался ли компьютер когда-либо серверу - при необходимости список можно поправить вручную (например, для удаления клиента обычно нужны только те компьютеры, где он реально установлен). Если одна из указанных OU не находится (опечатка, удалённая OU), она пропускается с предупреждением, а остальные всё равно загружаются.

## Диагностика
```

- [ ] **Step 4: Add a threat-model.md note**

Find in `docs/threat-model.md`:

```markdown
- The computer name embedded in a client's inventory report, when AD sync is enabled: used to build an LDAP search filter (see AdLookupService.LookupComputerDescription), escaped per RFC 4515 before use.
```

Replace with:

```markdown
- The computer name embedded in a client's inventory report, when AD sync is enabled: used to build an LDAP search filter (see AdLookupService.LookupComputerDescription), escaped per RFC 4515 before use.
- The Organizational Unit list (`AdComputerImportOUs`) configured via `POST /api/v1/server/settings`, used to build LDAP directory paths (`LDAP://<OU DN>`) for AD Computer Import (see AdLookupService.SearchComputers) - admin-configured only, not derived from any client-reported or otherwise attacker-influenceable data, so it is not run through `LdapFilterEscaper`. That escaping targets search-filter clauses, not directory paths, and is applied to the one input in this list that IS attacker-influenceable: the client-reported computer name in the entry above.
```

If Task 7's security review reached a different conclusion than the text above (e.g. found the LDAP-path-vs-filter distinction does not hold, or found `AdComputerImportOUs` is reachable from a less-trusted path than assumed), update this note to match the review's actual finding instead of the text shown here.

- [ ] **Step 5: Add the CHANGELOG.md entry**

Find:

```markdown
## [0.17.4] - 2026-07-20
```

Replace with:

```markdown
## [0.18.0] - 2026-07-20

### Added

- `Client actions` has a "Load from AD" button next to Targets: pulls a computer list directly from Active Directory (scoped to one or more Organizational Units configured in Settings > General, or the whole domain if none are set) and replaces the Targets field with it. Reuses the existing AD Domain/credentials already configured for AD Description Sync - nothing new to set up if that's already in use. A single bad/unreachable OU is skipped with a warning rather than failing the whole load.

## [0.17.4] - 2026-07-20
```

- [ ] **Step 6: Rebuild and self-test one more time**

```powershell
Get-Process -Name WindowsInventoryLiteServer -ErrorAction SilentlyContinue | Stop-Process -Force
& .\src\Build-Server.ps1
& .\build\WindowsInventoryLiteServer.exe --self-test
```
Expected: 0 FAIL.

- [ ] **Step 7: Commit**

```bash
git add README.md README_RU.md docs/threat-model.md CHANGELOG.md src/server/WindowsInventoryLiteServer.cs
git commit -m "Document AD Computer Import; bump version to 0.18.0"
```

---

### Task 9: Final whole-branch verification

- [ ] **Step 1: Full rebuild, self-test, Pester**

```powershell
Get-Process -Name WindowsInventoryLiteServer -ErrorAction SilentlyContinue | Stop-Process -Force
& .\src\Build-Server.ps1
& .\build\WindowsInventoryLiteServer.exe --self-test
```
Run Pester via Windows PowerShell 5.1 specifically (`powershell.exe`, not `pwsh` - see this project's own established note on why `pwsh` produces a false failure here):
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Pester -Path '.\tests' -CI"
```
Expected: self-test 0 FAIL; Pester `Tests Passed` with `Failed: 0`.

- [ ] **Step 2: Live functional re-check of the whole flow**

Repeat Task 3 Step 5's HTTP round-trip check (settings GET/POST, `/api/v1/ad/computers` total-failure case) and Task 5 Step 4's Playwright mocked-response check (success/empty/error) one more time end-to-end against the final code, in one local console-mode instance, to confirm nothing from Tasks 6-8 broke either path. Clean up the scratch server/data directory afterward.

- [ ] **Step 3: Flag what still needs the user's real domain**

`AdLookupService.SearchComputers`/`SearchOneRoot`'s actual behavior against a real Active Directory (a real OU returning real computers, a real sub-OU being included via `Subtree`, a real deleted/mistyped OU producing a skip-with-warning alongside other OUs that succeed) has not been exercised against a real domain controller anywhere in this plan - this dev machine is not domain-joined, matching this project's standing constraint that live AD/WinRM verification happens on the user's own test stand, not the primary dev machine. State this plainly when reporting completion; do not claim the AD query itself is confirmed working beyond the total-failure-path check already done in Task 3.

- [ ] **Step 4: Push**

Follow this project's established `git subtree split` -> `git push` -> `git branch -D` workflow to push the branch's commits to `didimozg/windows-inventory-lite`'s `ad-integration` branch, with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>` on any commits made directly by an agent (per this project's explicit exception to the standing no-co-author rule).
