# AD Description Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show each computer's Active Directory `description` attribute next to its inventory record in the Clients table, read-only, kept fresh by a per-computer cache the server refreshes either when that computer's next inventory report arrives or on an independent timer.

**Architecture:** A new `AdLookupService` (wraps `System.DirectoryServices.DirectorySearcher`, no NuGet package) resolves a computer name to its AD `description`. The server calls it from `ReceiveInventory` (default) or from a `System.Threading.Timer` sweep (opt-in via a setting), and persists the result as three new fields on that computer's existing report file, carrying the previous values forward unchanged between the checks that don't need a fresh lookup. All of it is gated behind `AdSyncEnabled`, off by default, so deployments without AD are unaffected.

**Tech Stack:** C# / .NET Framework 3.5+, `System.DirectoryServices`, `System.DirectoryServices.ActiveDirectory`, the existing hand-rolled JSON (`JavaScriptSerializer`) and self-test conventions already used throughout `WindowsInventoryLiteServer.cs`. Dashboard side: vanilla JS/HTML/CSS, no build step.

## Global Constraints

- .NET Framework 3.5/4.0 target — no C# syntax newer than what `csc.exe` for those frameworks accepts (no `var`... actually `var` is fine in C# 3+; avoid string interpolation `$"..."`, use string concatenation or `String.Format`, matching the rest of the file).
- No NuGet packages, no new external dependencies.
- No secrets in the repository; `AdPassword` is stored in `server-config.json` in plaintext, the same accepted precedent as `WebPassword`/`Token` — this must be called out in `docs/threat-model.md`.
- Read-only against AD. Never write any attribute back.
- Every dashboard-configurable setting in this project has a matching `Install-Server.ps1` CLI flag and a `server-config.json` key (see `HttpsPort`/`EnableHttp`/`StaleHours` for the exact pattern) — the new AD settings follow the same shape.
- A failed or slow AD lookup must never fail or block `POST /api/v1/inventory` — it's best-effort enrichment, not a pipeline dependency.
- Version bump after this work lands, per the workspace versioning rule (this is a new feature — MINOR bump) and a CHANGELOG entry.

---

## File Structure

New files:
- `src/server/AdLookupService.cs` — `LdapFilterEscaper.Escape`, `AdLookupResult`, `AdLookupService.LookupComputerDescription`. Kept as its own file (a new, clearly-bounded subsystem) rather than folded into the already-large `WindowsInventoryLiteServer.cs`, but the same namespace and `partial` split is not used elsewhere in this project — instead it's a second top-level file compiled into the same `WindowsInventoryLiteServer.exe` by `Build-Server.ps1` (confirm in Task 1 that the build script picks up all `.cs` files in `src/server/`, not just the one named file).

Modified files:
- `src/server/WindowsInventoryLiteServer.cs` — `ServerOptions` fields/CLI parsing/`LoadConfigFile`, `InventoryServer` fields, `Start()`/`Stop()` timer lifecycle, `ReceiveInventory`, `SendServerSettings`, `ConfigureServerSettings`, self-tests.
- `src/Install-Server.ps1` — new params, config writes, validation.
- `server/dashboard/index.html` — new "Active Directory" settings block, new Clients table column.
- `server/dashboard/app.js` — load/save the new settings, render the new column, CSV export.
- `docs/threat-model.md`, `README.md`, `README_RU.md` — document the new feature and its risk.
- `CHANGELOG.md`, `src/server/WindowsInventoryLiteServer.cs` / `src/client/WindowsInventoryLiteClient.cs` `ProductVersion` — version bump.

---

### Task 1: LDAP filter escaping + AdLookupService

**Files:**
- Create: `src/server/AdLookupService.cs`
- Test: exercised via the server's built-in `--self-test` mode (`WindowsInventoryLiteServer.cs`'s `RunSelfTests`), not a separate test project — matches how `SanitizeFileName`/`NormalizeThumbprint` are already tested in this codebase.
- Modify: `src/server/WindowsInventoryLiteServer.cs:3097-3115` (`RunSelfTests`) to register the new checks.
- Modify: `src/server/WindowsInventoryLiteServer.cs` (end of the self-test methods region, after `TestTryParsePortFromPrefix`) to add the new test methods.

**Interfaces:**
- Produces: `LdapFilterEscaper.Escape(string value) -> string`, `AdLookupResult { public string Description; public string Status; }`, `AdLookupService.LookupComputerDescription(string computerName, ServerOptions options) -> AdLookupResult`. `ServerOptions` (from Task 2) is referenced but not required to compile this task in isolation — Task 1 can define its own local `AdOptions`-shaped read of the four fields it needs (`AdDomain`, `AdUseServiceIdentity`, `AdUsername`, `AdPassword`) once Task 2 lands; write Task 1 second, after Task 2, to avoid a forward reference. (Re-ordered below: implement Task 2's `ServerOptions` fields first, then Task 1's service. The task numbers stay as written for traceability to the design doc; execute Task 2 before Task 1's `AdLookupService` class body, but the escaping function and its self-tests have no dependency on `ServerOptions` and can be written first.)

- [ ] **Step 1: Write the failing self-test for LDAP filter escaping**

Add to `src/server/WindowsInventoryLiteServer.cs`, in the self-test methods region (after the existing `TestTryParsePortFromPrefix` method, before its closing class brace — find it via `grep -n "private static string TestTryParsePortFromPrefix" src/server/WindowsInventoryLiteServer.cs`):

```csharp
        private static string TestLdapFilterEscapeSpecialChars()
        {
            string escaped = LdapFilterEscaper.Escape("a*b(c)d\\e\0f");
            const string expected = "a\\2ab\\28c\\29d\\5ce\\00f";
            if (escaped != expected)
            {
                return "expected '" + expected + "' but got '" + escaped + "'";
            }
            return null;
        }

        private static string TestLdapFilterEscapeNormalName()
        {
            string escaped = LdapFilterEscaper.Escape("PC-WINADMIN-01");
            if (escaped != "PC-WINADMIN-01")
            {
                return "expected passthrough but got '" + escaped + "'";
            }
            return null;
        }
```

- [ ] **Step 2: Register the new checks in `RunSelfTests`**

Modify `src/server/WindowsInventoryLiteServer.cs:3114` (immediately after the `TryParsePortFromPrefix` line, before `return allPassed;`):

```csharp
            allPassed &= SelfTestCheck(output, "TryParsePortFromPrefix extracts the port from a ListenPrefix URL", TestTryParsePortFromPrefix);
            allPassed &= SelfTestCheck(output, "LdapFilterEscaper escapes RFC 4515 special characters", TestLdapFilterEscapeSpecialChars);
            allPassed &= SelfTestCheck(output, "LdapFilterEscaper leaves a normal computer name untouched", TestLdapFilterEscapeNormalName);
            return allPassed;
```

- [ ] **Step 3: Run self-tests to verify they fail to compile (the type doesn't exist yet)**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"`
Expected: build FAILS with `error CS0103: The name 'LdapFilterEscaper' does not exist in the current context` (or similar — the type is referenced but not defined).

- [ ] **Step 4: Create `src/server/AdLookupService.cs` with the escaping utility**

```csharp
using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Text;

namespace WindowsInventoryLite
{
    // RFC 4515 escaping for values embedded in an LDAP search filter. The
    // computer name that ends up here comes from a client's own inventory
    // report (Environment.MachineName on that machine) - the same class of
    // semi-trusted, attacker-influenceable input already hardened elsewhere
    // in this project (CSV formula injection, reserved Windows device names
    // in report file paths). Without this, a maliciously-named reporting
    // host could distort the search filter (e.g. close the cn= clause early
    // with an unescaped ")" and inject additional filter clauses).
    internal static class LdapFilterEscaper
    {
        internal static string Escape(string value)
        {
            if (value == null)
            {
                return String.Empty;
            }

            StringBuilder builder = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\':
                        builder.Append("\\5c");
                        break;
                    case '*':
                        builder.Append("\\2a");
                        break;
                    case '(':
                        builder.Append("\\28");
                        break;
                    case ')':
                        builder.Append("\\29");
                        break;
                    case '\0':
                        builder.Append("\\00");
                        break;
                    default:
                        builder.Append(c);
                        break;
                }
            }
            return builder.ToString();
        }
    }

    internal sealed class AdLookupResult
    {
        // Null when the computer object has no description attribute set,
        // or when Status is not "ok".
        public string Description;
        // One of "ok", "not-found" (no matching computer object in AD), or
        // "error" (AD unreachable, timed out, or query failed for any other
        // reason). Kept separate from a merely-empty Description because
        // the Clients table needs to tell these three situations apart.
        public string Status;
    }

    internal static class AdLookupService
    {
        // Bounds how long a single lookup can block the caller (either the
        // inventory-ingestion request thread, or the background sweep) -
        // mirrors the 30-second socket timeout already used for HTTP/HTTPS
        // connections elsewhere in this server.
        private const int LdapTimeoutSeconds = 15;

        internal static AdLookupResult LookupComputerDescription(string computerName, ServerOptions options)
        {
            AdLookupResult result = new AdLookupResult();
            DirectoryEntry entry = null;
            DirectorySearcher searcher = null;
            try
            {
                string domain = !String.IsNullOrEmpty(options.AdDomain)
                    ? options.AdDomain
                    : Domain.GetComputerDomain().Name;
                string ldapPath = "LDAP://" + domain;

                entry = options.AdUseServiceIdentity
                    ? new DirectoryEntry(ldapPath)
                    : new DirectoryEntry(ldapPath, options.AdUsername, options.AdPassword);

                searcher = new DirectorySearcher(entry);
                searcher.Filter = "(&(objectCategory=computer)(cn=" + LdapFilterEscaper.Escape(computerName) + "))";
                searcher.PropertiesToLoad.Add("description");
                searcher.ClientTimeout = TimeSpan.FromSeconds(LdapTimeoutSeconds);

                SearchResult found = searcher.FindOne();
                if (found == null)
                {
                    result.Status = "not-found";
                    return result;
                }

                if (found.Properties["description"].Count > 0)
                {
                    result.Description = Convert.ToString(found.Properties["description"][0]);
                }
                result.Status = "ok";
                return result;
            }
            catch (Exception ex)
            {
                try
                {
                    System.Diagnostics.EventLog.WriteEntry(
                        "WindowsInventoryLite",
                        "AD lookup failed for '" + computerName + "': " + ex.Message,
                        System.Diagnostics.EventLogEntryType.Warning);
                }
                catch { }
                result.Status = "error";
                return result;
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
                if (entry != null) entry.Dispose();
            }
        }
    }
}
```

- [ ] **Step 5: Confirm `Build-Server.ps1` compiles every `.cs` file under `src/server/`, not just the named entry file**

Run: `Get-Content .\src\Build-Server.ps1 | Select-String "csc|\.cs"`
Expected: the `csc.exe` invocation (or a `Get-ChildItem`/wildcard feeding it) includes `src\server\*.cs`, not a hardcoded single filename. If it hardcodes only `WindowsInventoryLiteServer.cs`, add `AdLookupService.cs` to that file list before continuing — do not silently skip this check, a build script that doesn't compile the new file will succeed locally with stale behavior and fail only at runtime with a missing-type error.

- [ ] **Step 6: Build and run self-tests to verify the new checks pass**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"` then `.\build\WindowsInventoryLiteServer.exe --self-test`
Expected: build succeeds; output includes `PASS LdapFilterEscaper escapes RFC 4515 special characters` and `PASS LdapFilterEscaper leaves a normal computer name untouched`, both self-tests count now included in the total (17, up from 15).

- [ ] **Step 7: Commit**

```bash
git add src/server/AdLookupService.cs src/server/WindowsInventoryLiteServer.cs
git commit -m "Add AdLookupService with RFC 4515 LDAP filter escaping"
```

---

### Task 2: ServerOptions fields, CLI parsing, config load

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs:78-107` (`ServerOptions` field declarations)
- Modify: `src/server/WindowsInventoryLiteServer.cs:108-121` (`Parse` defaults)
- Modify: `src/server/WindowsInventoryLiteServer.cs:222-226` (CLI arg parsing, after the existing `--disable-http` branch)
- Modify: `src/server/WindowsInventoryLiteServer.cs:300-308` (`LoadConfigFile`, after the existing `EnableHttp` block)

**Interfaces:**
- Consumes: nothing new.
- Produces: `ServerOptions.AdSyncEnabled` (bool), `AdSyncMode` (string, `"on-report"` or `"timer"`), `AdSyncIntervalHours` (int), `AdDomain` (string, nullable), `AdUseServiceIdentity` (bool), `AdUsername` (string, nullable), `AdPassword` (string, nullable). Tasks 1 (already written against these names), 3, 4, and 5 all read these fields directly off `options`.

- [ ] **Step 1: Add the new fields to `ServerOptions`**

Modify `src/server/WindowsInventoryLiteServer.cs`, immediately after line 106 (`public bool ShowVersion;`, the last field before `public static ServerOptions Parse`):

```csharp
        public bool ShowVersion;
        // AD sync is opt-in and off by default - deployments without AD, or
        // with a server that isn't domain-joined, are unaffected. See
        // AdLookupService.cs and InventoryServer.ApplyAdSync.
        public bool AdSyncEnabled;
        public string AdSyncMode;
        public int AdSyncIntervalHours;
        public string AdDomain;
        public bool AdUseServiceIdentity;
        public string AdUsername;
        public string AdPassword;
```

- [ ] **Step 2: Add defaults in `Parse()`**

Modify `src/server/WindowsInventoryLiteServer.cs:121` (immediately after `options.StaleHours = 48;`):

```csharp
            options.StaleHours = 48;
            options.AdSyncMode = "on-report";
            options.AdSyncIntervalHours = 24;
            options.AdUseServiceIdentity = true;
```

- [ ] **Step 3: Add CLI argument parsing**

Modify `src/server/WindowsInventoryLiteServer.cs`, immediately after the existing block:
```csharp
                else if (key == "--disable-http")
                {
                    options.EnableHttp = false;
                }
```
add:
```csharp
                else if (key == "--ad-sync-enabled")
                {
                    options.AdSyncEnabled = true;
                }
                else if (key == "--ad-sync-mode" && i + 1 < args.Length)
                {
                    string mode = args[++i].ToLowerInvariant();
                    if (mode == "on-report" || mode == "timer")
                    {
                        options.AdSyncMode = mode;
                    }
                }
                else if (key == "--ad-sync-interval-hours" && i + 1 < args.Length)
                {
                    int adHours;
                    if (Int32.TryParse(args[++i], out adHours) && adHours > 0)
                    {
                        options.AdSyncIntervalHours = adHours;
                    }
                }
                else if (key == "--ad-domain" && i + 1 < args.Length)
                {
                    options.AdDomain = args[++i];
                }
                else if (key == "--ad-username" && i + 1 < args.Length)
                {
                    options.AdUsername = args[++i];
                    options.AdUseServiceIdentity = false;
                }
                else if (key == "--ad-password" && i + 1 < args.Length)
                {
                    options.AdPassword = args[++i];
                }
```

- [ ] **Step 4: Add config-file loading**

Modify `src/server/WindowsInventoryLiteServer.cs`, immediately after the existing block:
```csharp
                if (options.EnableHttp)
                {
                    string enableHttpText = GetConfigString(config, "EnableHttp");
                    if (enableHttpText != null)
                    {
                        options.EnableHttp = String.Equals(enableHttpText, "true", StringComparison.OrdinalIgnoreCase);
                    }
                }
```
add (still inside the same `try` block, before its closing `catch`):
```csharp
                if (!options.AdSyncEnabled)
                {
                    string adSyncEnabledText = GetConfigString(config, "AdSyncEnabled");
                    options.AdSyncEnabled = String.Equals(adSyncEnabledText, "true", StringComparison.OrdinalIgnoreCase);
                }
                if (options.AdSyncMode == "on-report")
                {
                    string adSyncModeText = GetConfigString(config, "AdSyncMode");
                    if (adSyncModeText == "timer" || adSyncModeText == "on-report")
                    {
                        options.AdSyncMode = adSyncModeText;
                    }
                }
                if (options.AdSyncIntervalHours == 24)
                {
                    string adSyncIntervalText = GetConfigString(config, "AdSyncIntervalHours");
                    int adSyncIntervalFromConfig;
                    if (!String.IsNullOrEmpty(adSyncIntervalText) && Int32.TryParse(adSyncIntervalText, out adSyncIntervalFromConfig) && adSyncIntervalFromConfig > 0)
                    {
                        options.AdSyncIntervalHours = adSyncIntervalFromConfig;
                    }
                }
                if (String.IsNullOrEmpty(options.AdDomain))
                {
                    options.AdDomain = GetConfigString(config, "AdDomain");
                }
                if (options.AdUseServiceIdentity)
                {
                    string adUseServiceIdentityText = GetConfigString(config, "AdUseServiceIdentity");
                    if (adUseServiceIdentityText != null)
                    {
                        options.AdUseServiceIdentity = String.Equals(adUseServiceIdentityText, "true", StringComparison.OrdinalIgnoreCase);
                    }
                }
                if (String.IsNullOrEmpty(options.AdUsername))
                {
                    options.AdUsername = GetConfigString(config, "AdUsername");
                }
                if (String.IsNullOrEmpty(options.AdPassword))
                {
                    options.AdPassword = GetConfigString(config, "AdPassword");
                }
```

- [ ] **Step 5: Build to verify it compiles**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"`
Expected: build succeeds (no test yet exercises these fields directly — they're exercised end-to-end in Task 5's self-tests and Task 4's live checks).

- [ ] **Step 6: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add AD sync options: CLI flags and server-config.json fields"
```

---

### Task 3: Freshness check + ReceiveInventory integration

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs:808-833` (`ReceiveInventory`)
- Modify: `src/server/WindowsInventoryLiteServer.cs` (self-test region, add freshness-check tests)
- Modify: `src/server/WindowsInventoryLiteServer.cs:3097-3117` (`RunSelfTests`, register new checks)

**Interfaces:**
- Consumes: `AdLookupService.LookupComputerDescription` (Task 1), `ServerOptions.AdSyncEnabled`/`AdSyncIntervalHours` (Task 2).
- Produces: `InventoryServer.ShouldSyncAd(DateTime? lastSyncedUtc, int intervalHours) -> bool` (internal static, self-test-callable), `InventoryServer.ApplyAdSync(Dictionary<string, object> inventory, string computerName, Dictionary<string, object> previous)` (private instance method — needs `options`, hence not static). Task 4 (timer sweep) calls `ApplyAdSync` directly.

- [ ] **Step 1: Write the failing self-tests for the freshness check**

Add to the self-test methods region, after `TestLdapFilterEscapeNormalName` (from Task 1):

```csharp
        private static string TestShouldSyncAdNoPreviousTimestamp()
        {
            if (!InventoryServer.ShouldSyncAd(null, 24))
            {
                return "expected true when there is no previous sync timestamp";
            }
            return null;
        }

        private static string TestShouldSyncAdStaleTimestamp()
        {
            DateTime stale = DateTime.UtcNow.AddHours(-25);
            if (!InventoryServer.ShouldSyncAd(stale, 24))
            {
                return "expected true when the previous sync is older than the interval";
            }
            return null;
        }

        private static string TestShouldSyncAdFreshTimestamp()
        {
            DateTime fresh = DateTime.UtcNow.AddHours(-1);
            if (InventoryServer.ShouldSyncAd(fresh, 24))
            {
                return "expected false when the previous sync is within the interval";
            }
            return null;
        }
```

- [ ] **Step 2: Register the new checks in `RunSelfTests`**

Modify `src/server/WindowsInventoryLiteServer.cs`, after the two `LdapFilterEscaper` lines added in Task 1:

```csharp
            allPassed &= SelfTestCheck(output, "LdapFilterEscaper leaves a normal computer name untouched", TestLdapFilterEscapeNormalName);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns true with no previous timestamp", TestShouldSyncAdNoPreviousTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns true for a stale timestamp", TestShouldSyncAdStaleTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns false for a fresh timestamp", TestShouldSyncAdFreshTimestamp);
            return allPassed;
```

- [ ] **Step 3: Run self-tests to verify they fail to compile**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"`
Expected: build FAILS — `ShouldSyncAd` does not exist yet on `InventoryServer`.

- [ ] **Step 4: Implement `ShouldSyncAd` and `ApplyAdSync`, and wire them into `ReceiveInventory`**

Replace `src/server/WindowsInventoryLiteServer.cs:808-833` (the full current `ReceiveInventory` method) with:

```csharp
        private void ReceiveInventory(Stream stream, RequestContext request)
        {
            string token = request.Headers.ContainsKey("x-inventory-token") ? request.Headers["x-inventory-token"] : null;
            if (!String.IsNullOrEmpty(options.Token) && token != options.Token)
            {
                SendText(stream, "Unauthorized", "text/plain; charset=utf-8", 401);
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> inventory;
            try
            {
                inventory = serializer.Deserialize<Dictionary<string, object>>(request.Body);
            }
            catch
            {
                SendText(stream, "{\"error\":\"invalid request body\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string computerName = Convert.ToString(inventory.ContainsKey("computerName") ? inventory["computerName"] : "unknown");
            string path = Path.Combine(options.DataPath, SanitizeFileName(computerName) + ".json");

            Dictionary<string, object> previous = null;
            if (File.Exists(path))
            {
                try
                {
                    previous = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
                }
                catch
                {
                    previous = null;
                }
            }
            ApplyAdSync(inventory, computerName, previous);

            string json = serializer.Serialize(inventory);
            File.WriteAllText(path, json, new UTF8Encoding(false));
            SendJson(stream, "{\"status\":\"ok\"}");
        }

        // Returns true when an AD lookup is due: either there is no
        // previous sync timestamp at all, or it's older than the
        // configured interval. Static and parameter-driven (no dependency
        // on `options` or the clock beyond DateTime.UtcNow) so it's directly
        // self-testable without standing up a server instance.
        internal static bool ShouldSyncAd(DateTime? lastSyncedUtc, int intervalHours)
        {
            if (lastSyncedUtc == null)
            {
                return true;
            }
            return (DateTime.UtcNow - lastSyncedUtc.Value).TotalHours >= intervalHours;
        }

        // Carries the previous adDescription/adSyncedAt/adSyncStatus forward
        // onto `inventory` when they're still fresh, or performs a lookup
        // and stamps a new sync time when they're missing or stale. A
        // no-op when AD sync is disabled. `previous` may be the same object
        // reference as `inventory` (the timer sweep in Task 4 calls it this
        // way) - every read of `previous` happens before the corresponding
        // write to `inventory`, so that's safe.
        private void ApplyAdSync(Dictionary<string, object> inventory, string computerName, Dictionary<string, object> previous)
        {
            if (!options.AdSyncEnabled)
            {
                return;
            }

            DateTime? lastSyncedUtc = null;
            if (previous != null && previous.ContainsKey("adSyncedAt") && previous["adSyncedAt"] != null)
            {
                DateTime parsed;
                if (DateTime.TryParse(Convert.ToString(previous["adSyncedAt"]), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out parsed))
                {
                    lastSyncedUtc = parsed.ToUniversalTime();
                }
            }

            if (previous != null && !ShouldSyncAd(lastSyncedUtc, options.AdSyncIntervalHours))
            {
                inventory["adDescription"] = previous.ContainsKey("adDescription") ? previous["adDescription"] : null;
                inventory["adSyncedAt"] = previous.ContainsKey("adSyncedAt") ? previous["adSyncedAt"] : null;
                inventory["adSyncStatus"] = previous.ContainsKey("adSyncStatus") ? previous["adSyncStatus"] : null;
                return;
            }

            AdLookupResult result = AdLookupService.LookupComputerDescription(computerName, options);
            inventory["adDescription"] = result.Description;
            inventory["adSyncedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            inventory["adSyncStatus"] = result.Status;
        }
```

- [ ] **Step 5: Build and run self-tests to verify they pass**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"` then `.\build\WindowsInventoryLiteServer.exe --self-test`
Expected: build succeeds; `PASS ShouldSyncAd returns true with no previous timestamp`, `PASS ShouldSyncAd returns true for a stale timestamp`, `PASS ShouldSyncAd returns false for a fresh timestamp` all present (self-test count now 20).

- [ ] **Step 6: Live-verify `ReceiveInventory` still accepts reports with AD sync disabled (the default)**

Start an isolated server instance:

```bash
mkdir -p /tmp/wil-ad-test/data /tmp/wil-ad-test/config
"./build/WindowsInventoryLiteServer.exe" --console --prefix "http://localhost:18090/" --content "$(pwd)/server/dashboard" --data /tmp/wil-ad-test/data --config /tmp/wil-ad-test/config/server-config.json &
sleep 2
```

Then:

```bash
curl -s -X POST http://127.0.0.1:18090/api/v1/inventory -H "Content-Type: application/json" -d "{\"computerName\":\"TEST-PC-01\",\"os\":{}}"
cat /tmp/wil-ad-test/data/TEST-PC-01.json
```

Expected: `{"status":"ok"}` from the POST; the saved file contains `computerName`/`os` and does NOT contain `adDescription`/`adSyncedAt`/`adSyncStatus` (since `AdSyncEnabled` defaults to false and `ApplyAdSync` returns immediately).

Clean up:

```bash
kill %1 2>/dev/null
rm -rf /tmp/wil-ad-test
```

- [ ] **Step 7: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Wire AD sync freshness check into inventory ingestion"
```

---

### Task 4: Timer-mode background sweep

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs:345-365` (`InventoryServer` field declarations)
- Modify: `src/server/WindowsInventoryLiteServer.cs:367-414` (`Start()`)
- Modify: `src/server/WindowsInventoryLiteServer.cs:432-436` (`Stop()`)

**Interfaces:**
- Consumes: `ApplyAdSync` (Task 3), `ServerOptions.AdSyncEnabled`/`AdSyncMode`/`AdSyncIntervalHours` (Task 2).
- Produces: `InventoryServer.ReconfigureAdSyncTimer()` (private, also called from Task 5 when settings change at runtime).

- [ ] **Step 1: Add the timer field**

Modify `src/server/WindowsInventoryLiteServer.cs`, immediately after line 360 (`private volatile X509Certificate2 serverCertificate;`):

```csharp
        private volatile X509Certificate2 serverCertificate;
        private readonly object adSyncTimerLock = new object();
        private Timer adSyncTimer;
```

Add `using System.Threading;` near the top of the file if not already present (`Thread`/`ThreadPool` are already used in this file per `AcceptLoop`/`HandleClient`, so `System.Threading` should already be imported — verify with `grep -n "^using System.Threading" src/server/WindowsInventoryLiteServer.cs` and add it if missing).

- [ ] **Step 2: Start the timer (if configured) at service startup**

Modify `src/server/WindowsInventoryLiteServer.cs`, inside `Start()`, immediately after the existing HTTPS-slot block and before the `if (!httpSlot.Running && !httpsSlot.Running)` check:

```csharp
            if (options.UseHttps && serverCertificate != null)
            {
                string httpsError = ApplySlotState(httpsSlot, true, -1, options.HttpsPort, true);
                LogSlotStartupError("HTTPS", httpsError);
            }

            ReconfigureAdSyncTimer();

            if (!httpSlot.Running && !httpsSlot.Running)
```

- [ ] **Step 3: Add `ReconfigureAdSyncTimer` and the sweep callback**

Add as a new private method, after `Stop()` (find `public void Stop()` and its closing brace, insert immediately after):

```csharp
        // Starts, stops, or restarts the periodic sweep to match the current
        // options - called once at startup and again whenever AD settings
        // change through the dashboard (ConfigureServerSettings), so a mode
        // switch or interval change takes effect without a service restart,
        // consistent with how every other dashboard-driven setting in this
        // server behaves.
        private void ReconfigureAdSyncTimer()
        {
            lock (adSyncTimerLock)
            {
                if (adSyncTimer != null)
                {
                    adSyncTimer.Dispose();
                    adSyncTimer = null;
                }
                if (options.AdSyncEnabled && options.AdSyncMode == "timer")
                {
                    TimeSpan interval = TimeSpan.FromHours(Math.Max(1, options.AdSyncIntervalHours));
                    adSyncTimer = new Timer(RunAdSyncSweep, null, interval, interval);
                }
            }
        }

        // One tick of the "timer" sync mode: walks every saved report and
        // refreshes AD data for whichever ones are due, independent of
        // whether that computer has reported inventory recently - the "on
        // inventory report" mode (Task 3) only ever touches a computer's AD
        // fields when that computer itself POSTs a new report, so a machine
        // that's stopped reporting but still exists in AD would otherwise
        // never refresh.
        private void RunAdSyncSweep(object state)
        {
            if (!options.AdSyncEnabled || options.AdSyncMode != "timer")
            {
                return;
            }

            string[] files;
            try
            {
                files = Directory.GetFiles(options.DataPath, "*.json");
            }
            catch
            {
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            foreach (string file in files)
            {
                try
                {
                    Dictionary<string, object> inventory = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(file, Encoding.UTF8));
                    string computerName = Convert.ToString(inventory.ContainsKey("computerName") ? inventory["computerName"] : Path.GetFileNameWithoutExtension(file));
                    ApplyAdSync(inventory, computerName, inventory);
                    File.WriteAllText(file, serializer.Serialize(inventory), new UTF8Encoding(false));
                }
                catch
                {
                    // One unreadable/corrupt report must not stop the sweep
                    // over the rest of the fleet.
                }
            }
        }
```

- [ ] **Step 4: Dispose the timer on service stop**

Modify `src/server/WindowsInventoryLiteServer.cs`, `Stop()`:

```csharp
        public void Stop()
        {
            lock (adSyncTimerLock)
            {
                if (adSyncTimer != null)
                {
                    adSyncTimer.Dispose();
                    adSyncTimer = null;
                }
            }
            StopSlot(httpSlot);
            StopSlot(httpsSlot);
        }
```

- [ ] **Step 5: Build to verify it compiles**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"`
Expected: build succeeds.

- [ ] **Step 6: Live-verify the timer does not start when AD sync is disabled (the default)**

Run: `.\build\WindowsInventoryLiteServer.exe --self-test` (self-tests still pass — this step doesn't add new self-tests since a live `Timer` firing on a real schedule isn't practically unit-testable; verify by code inspection that `ReconfigureAdSyncTimer` is a no-op when `AdSyncEnabled` is false, which Task 2's default (`false`) guarantees).
Expected: 20/20 self-tests still pass, no regression.

- [ ] **Step 7: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add timer-mode background sweep for AD sync"
```

---

### Task 5: Settings API (`GET`/`POST /api/v1/server/settings`)

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs` (`SendServerSettings`)
- Modify: `src/server/WindowsInventoryLiteServer.cs` (`ConfigureServerSettings`)

**Interfaces:**
- Consumes: `ServerOptions.AdSyncEnabled`/`AdSyncMode`/`AdSyncIntervalHours`/`AdDomain`/`AdUseServiceIdentity`/`AdUsername`/`AdPassword` (Task 2), `ReconfigureAdSyncTimer` (Task 4).
- Produces: `GET /api/v1/server/settings` response gains `adSyncEnabled`, `adSyncMode`, `adSyncIntervalHours`, `adDomain`, `adUseServiceIdentity`, `adUsername` (never `adPassword`). `POST /api/v1/server/settings` accepts the same field names (plus `adPassword`) as optional payload keys — Task 7 (dashboard JS) sends exactly these names.

- [ ] **Step 1: Extend `SendServerSettings`**

Find `private void SendServerSettings(Stream stream)` and add before its `SendJson(stream, serializer.Serialize(result));` line:

```csharp
            result["adSyncEnabled"] = options.AdSyncEnabled;
            result["adSyncMode"] = options.AdSyncMode;
            result["adSyncIntervalHours"] = options.AdSyncIntervalHours;
            result["adDomain"] = options.AdDomain;
            result["adUseServiceIdentity"] = options.AdUseServiceIdentity;
            // Username is informational (shown in the UI when the explicit-
            // credentials option is selected); the password is never
            // returned by this endpoint, matching how WebPassword is never
            // echoed back either.
            result["adUsername"] = options.AdUseServiceIdentity ? null : options.AdUsername;
```

- [ ] **Step 2: Extend `ConfigureServerSettings`**

Find `private void ConfigureServerSettings(Stream stream, RequestContext request)` and add a new block immediately before its final `if (updates.Count > 0) { SaveServerConfigValues(updates); }`:

```csharp
            if (payload.ContainsKey("adSyncEnabled") || payload.ContainsKey("adSyncMode") || payload.ContainsKey("adSyncIntervalHours")
                || payload.ContainsKey("adDomain") || payload.ContainsKey("adUseServiceIdentity") || payload.ContainsKey("adUsername") || payload.ContainsKey("adPassword"))
            {
                bool adSyncEnabled = payload.ContainsKey("adSyncEnabled") ? Convert.ToBoolean(payload["adSyncEnabled"]) : options.AdSyncEnabled;

                string adSyncMode = payload.ContainsKey("adSyncMode") ? Convert.ToString(payload["adSyncMode"]) : options.AdSyncMode;
                if (adSyncMode != "on-report" && adSyncMode != "timer")
                {
                    SendText(stream, "{\"error\":\"adSyncMode must be 'on-report' or 'timer'\"}", "application/json; charset=utf-8", 400);
                    return;
                }

                int adSyncIntervalHours = options.AdSyncIntervalHours;
                if (payload.ContainsKey("adSyncIntervalHours"))
                {
                    if (!Int32.TryParse(Convert.ToString(payload["adSyncIntervalHours"]), out adSyncIntervalHours) || adSyncIntervalHours < 1 || adSyncIntervalHours > 8760)
                    {
                        SendText(stream, "{\"error\":\"adSyncIntervalHours must be between 1 and 8760\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                }

                string adDomain = payload.ContainsKey("adDomain") ? Convert.ToString(payload["adDomain"]) : options.AdDomain;
                bool adUseServiceIdentity = payload.ContainsKey("adUseServiceIdentity") ? Convert.ToBoolean(payload["adUseServiceIdentity"]) : options.AdUseServiceIdentity;
                string adUsername = payload.ContainsKey("adUsername") ? Convert.ToString(payload["adUsername"]) : options.AdUsername;
                // Blank/omitted password on save means "keep the existing
                // one" - the dashboard never pre-fills a password field with
                // the real stored value, so treating blank as "no change"
                // is the only way to edit other AD fields without being
                // forced to re-type the password every time.
                string adPassword = payload.ContainsKey("adPassword") && !String.IsNullOrEmpty(Convert.ToString(payload["adPassword"]))
                    ? Convert.ToString(payload["adPassword"])
                    : options.AdPassword;

                if (adSyncEnabled && !adUseServiceIdentity && (String.IsNullOrEmpty(adUsername) || String.IsNullOrEmpty(adPassword)))
                {
                    SendText(stream, "{\"error\":\"AD username and password are required when not using the service account identity.\"}", "application/json; charset=utf-8", 400);
                    return;
                }

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

- [ ] **Step 2: Build and run self-tests**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"` then `.\build\WindowsInventoryLiteServer.exe --self-test`
Expected: build succeeds, 20/20 self-tests pass (no new ones in this task — it's exercised live in the next step).

- [ ] **Step 3: Live-verify the settings endpoint**

Start a local server instance on an isolated port/data/config dir, then:

```bash
curl -s http://127.0.0.1:<port>/api/v1/server/settings
```
Expected: JSON includes `"adSyncEnabled":false,"adSyncMode":"on-report","adSyncIntervalHours":24,"adDomain":null,"adUseServiceIdentity":true,"adUsername":null`.

```bash
curl -s -X POST http://127.0.0.1:<port>/api/v1/server/settings -H "Content-Type: application/json" -d "{\"adSyncEnabled\":true,\"adSyncMode\":\"weekly\"}"
```
Expected: `400` with `{"error":"adSyncMode must be 'on-report' or 'timer'"}` (validates the enum).

```bash
curl -s -X POST http://127.0.0.1:<port>/api/v1/server/settings -H "Content-Type: application/json" -d "{\"adSyncEnabled\":true,\"adUseServiceIdentity\":false}"
```
Expected: `400` with the "AD username and password are required..." message (no username/password supplied).

```bash
curl -s -X POST http://127.0.0.1:<port>/api/v1/server/settings -H "Content-Type: application/json" -d "{\"adSyncEnabled\":true,\"adSyncMode\":\"on-report\",\"adSyncIntervalHours\":12}"
```
Expected: `200`, response reflects `adSyncEnabled:true, adSyncIntervalHours:12`; `<ConfigPath>` file on disk now contains `"AdSyncEnabled": "true", "AdSyncMode": "on-report", "AdSyncIntervalHours": "12"`.

- [ ] **Step 4: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Expose AD sync settings through the server settings API"
```

---

### Task 6: `Install-Server.ps1` CLI parameters

**Files:**
- Modify: `src/Install-Server.ps1` (param block, config-object construction, service command construction if applicable)

**Interfaces:**
- Consumes: nothing from earlier tasks (this is a parallel configuration surface, not code the server depends on).
- Produces: `-AdSyncEnabled`, `-AdSyncMode`, `-AdSyncIntervalHours`, `-AdDomain`, `-AdUsername`, `-AdPassword` install-time parameters; `server-config.json` keys matching Task 2's `GetConfigString` lookups exactly (`AdSyncEnabled`, `AdSyncMode`, `AdSyncIntervalHours`, `AdDomain`, `AdUseServiceIdentity`, `AdUsername`, `AdPassword`).

- [ ] **Step 1: Add the new parameters**

Find the `param(` block at the top of `src/Install-Server.ps1` (starts at line 8) and locate where `-HttpsPort`/`-DisableHttp` are declared (around lines 75-83). Add immediately after `-DisableHttp`:

```powershell
    [switch]$AdSyncEnabled,

    [ValidateSet('on-report', 'timer')]
    [string]$AdSyncMode = 'on-report',

    [ValidateRange(1, 8760)]
    [int]$AdSyncIntervalHours = 24,

    [string]$AdDomain,

    [string]$AdUsername,

    [string]$AdPassword,
```

- [ ] **Step 2: Reload from existing config when not explicitly passed, mirroring the `HttpsPort`/`DisableHttp` pattern**

Find where `$HttpsPort`/`$DisableHttp` are reloaded from `$existingConfig` (around line 404-417) and add immediately after that block:

```powershell
if (-not $PSBoundParameters.ContainsKey('AdSyncEnabled')) {
    $savedAdSyncEnabled = Get-ConfigValue -Config $existingConfig -Name 'AdSyncEnabled'
    if ($savedAdSyncEnabled -eq 'true') {
        $AdSyncEnabled = $true
    }
}
if (-not $PSBoundParameters.ContainsKey('AdSyncMode')) {
    $savedAdSyncMode = Get-ConfigValue -Config $existingConfig -Name 'AdSyncMode'
    if ($savedAdSyncMode -eq 'timer' -or $savedAdSyncMode -eq 'on-report') {
        $AdSyncMode = $savedAdSyncMode
    }
}
if (-not $PSBoundParameters.ContainsKey('AdSyncIntervalHours')) {
    $savedAdSyncIntervalHours = Get-ConfigValue -Config $existingConfig -Name 'AdSyncIntervalHours'
    if ($savedAdSyncIntervalHours) {
        $AdSyncIntervalHours = [int]$savedAdSyncIntervalHours
    }
}
if (-not $PSBoundParameters.ContainsKey('AdDomain')) {
    $savedAdDomain = Get-ConfigValue -Config $existingConfig -Name 'AdDomain'
    if ($savedAdDomain) {
        $AdDomain = $savedAdDomain
    }
}
if (-not $PSBoundParameters.ContainsKey('AdUsername')) {
    $savedAdUsername = Get-ConfigValue -Config $existingConfig -Name 'AdUsername'
    if ($savedAdUsername) {
        $AdUsername = $savedAdUsername
    }
}
# AdPassword is deliberately NOT reloaded from the saved config the way
# AdUsername is - re-running the installer without -AdPassword must not
# require re-supplying it if it's already saved, but the *existing* saved
# value is what server-config.json already has and $config.AdPassword
# below only overwrites it when a new one was actually passed this run.
$adUseServiceIdentity = [string]::IsNullOrEmpty($AdUsername)
if ($AdSyncEnabled -and -not $adUseServiceIdentity -and -not $AdPassword -and -not (Get-ConfigValue -Config $existingConfig -Name 'AdPassword')) {
    throw "-AdUsername was supplied without -AdPassword, and no AD password is already saved - provide -AdPassword."
}
```

- [ ] **Step 3: Write the new keys into `$config`**

Find where `$config.HttpsPort`/`$config.EnableHttp` are set (around line 578-579) and add immediately after:

```powershell
$config.AdSyncEnabled        = if ($AdSyncEnabled) { 'true' } else { 'false' }
$config.AdSyncMode           = $AdSyncMode
$config.AdSyncIntervalHours  = $AdSyncIntervalHours
$config.AdDomain             = $AdDomain
$config.AdUseServiceIdentity = if ($adUseServiceIdentity) { 'true' } else { 'false' }
$config.AdUsername           = $AdUsername
if ($AdPassword) {
    $config.AdPassword = $AdPassword
}
```

(The `if ($AdPassword)` guard means a re-run without `-AdPassword` doesn't overwrite an already-saved password with an empty string - `$config` starts from `$existingConfig`'s contents per the pre-existing "start from whatever is already on disk" pattern in this script, documented in the comment above `$config = @{}`, so simply not touching `$config.AdPassword` here leaves the previous value in place.)

- [ ] **Step 4: Syntax-check the script**

Run:
```powershell
powershell -NoProfile -Command "$tokens = $null; $errors = $null; [System.Management.Automation.Language.Parser]::ParseFile('src\Install-Server.ps1', [ref]$tokens, [ref]$errors) | Out-Null; $errors.Count"
```
Expected: `0`.

- [ ] **Step 5: Run the existing Pester suite**

Run: `powershell -NoProfile -Command "Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed"`
Expected: all tests pass, including `parses PowerShell scripts` (which parses `Install-Server.ps1` specifically).

- [ ] **Step 6: Commit**

```bash
git add src/Install-Server.ps1
git commit -m "Add AD sync install-time parameters to Install-Server.ps1"
```

---

### Task 7: Dashboard Settings UI

**Files:**
- Modify: `server/dashboard/index.html` (new "Active Directory" settings block inside `#generalView`)
- Modify: `server/dashboard/app.js` (`loadGeneralSettings`, `saveGeneralSettings`)

**Interfaces:**
- Consumes: `GET`/`POST /api/v1/server/settings` fields from Task 5.
- Produces: no new functions consumed by other tasks — this is a leaf UI task.

- [ ] **Step 1: Add the settings block to `index.html`**

Modify `server/dashboard/index.html`, inside `#generalView`, immediately after the existing HTTPS `settings-block` (`</div>\n            <p id="generalCertHint" class="cert-hint hidden"></p>\n          </div>`) and before the `<div class="pkg-buttons">` that holds the Save button:

```html
          <div class="settings-block">
            <h2 class="settings-block-title">Active Directory</h2>
            <div class="pkg-grid general-grid">
              <label class="check-label">
                <input id="generalAdSyncEnabled" type="checkbox">
                Enable AD sync
              </label>
              <label class="pkg-token-field">
                Sync mode
                <select id="generalAdSyncMode">
                  <option value="on-report">On inventory report</option>
                  <option value="timer">Periodic timer</option>
                </select>
              </label>
              <label class="pkg-token-field">
                Sync interval (hours)
                <input id="generalAdSyncIntervalHours" type="number" min="1" max="8760" value="24">
              </label>
              <label class="pkg-token-field">
                Domain
                <input id="generalAdDomain" type="text" placeholder="leave blank to use the server's own domain">
              </label>
              <label class="check-label">
                <input id="generalAdUseServiceIdentity" type="checkbox" checked>
                Use service account identity
              </label>
              <label id="generalAdUsernameField" class="pkg-token-field hidden">
                AD username
                <input id="generalAdUsername" type="text" autocomplete="off">
              </label>
              <label id="generalAdPasswordField" class="pkg-token-field hidden">
                AD password
                <input id="generalAdPassword" type="password" autocomplete="new-password" placeholder="leave blank to keep the current password">
              </label>
            </div>
            <p class="cert-hint">Shows each computer's Active Directory description next to its inventory record, read-only. Reading the description attribute is allowed to any authenticated domain user by default AD ACLs, so the service account identity usually needs no special AD delegation.</p>
          </div>
```

- [ ] **Step 2: Load the new fields in `app.js`**

Modify `server/dashboard/app.js`, inside `loadGeneralSettings`'s `.then(data => { ... })` callback, immediately after the existing `renderConnectionStatus(data);` line (and before the callback's closing brace):

```javascript
        byId('generalAdSyncEnabled').checked = !!data.adSyncEnabled;
        byId('generalAdSyncMode').value = data.adSyncMode || 'on-report';
        byId('generalAdSyncIntervalHours').value = data.adSyncIntervalHours || 24;
        byId('generalAdDomain').value = data.adDomain || '';
        byId('generalAdUseServiceIdentity').checked = data.adUseServiceIdentity !== false;
        byId('generalAdUsername').value = data.adUsername || '';
        byId('generalAdPassword').value = '';
        updateAdIdentityFields();
```

- [ ] **Step 3: Add the identity-field toggle and its event listener**

Add as a new function near `loadGeneralSettings` (e.g. immediately before it):

```javascript
  function updateAdIdentityFields() {
    const useServiceIdentity = byId('generalAdUseServiceIdentity').checked;
    byId('generalAdUsernameField').classList.toggle('hidden', useServiceIdentity);
    byId('generalAdPasswordField').classList.toggle('hidden', useServiceIdentity);
  }
```

Find where other General-page event listeners are registered near the bottom of the file (e.g. `byId('generalSaveButton').addEventListener(...)` — search for it) and add nearby:

```javascript
  byId('generalAdUseServiceIdentity').addEventListener('change', updateAdIdentityFields);
```

- [ ] **Step 4: Send the new fields on save**

Modify `server/dashboard/app.js`, `saveGeneralSettings`, its `fetch('/api/v1/server/settings', ...)` call. Change:

```javascript
      body: JSON.stringify({ staleHours, port, enableHttp, httpsPort, useHttps, acknowledgeRisks: !!acknowledgeRisks })
```
to:
```javascript
      body: JSON.stringify({
        staleHours, port, enableHttp, httpsPort, useHttps, acknowledgeRisks: !!acknowledgeRisks,
        adSyncEnabled: byId('generalAdSyncEnabled').checked,
        adSyncMode: byId('generalAdSyncMode').value,
        adSyncIntervalHours: Number.parseInt(byId('generalAdSyncIntervalHours').value, 10) || 24,
        adDomain: byId('generalAdDomain').value.trim(),
        adUseServiceIdentity: byId('generalAdUseServiceIdentity').checked,
        adUsername: byId('generalAdUsername').value.trim(),
        adPassword: byId('generalAdPassword').value
      })
```

And in the same function's success handler, immediately after the existing `renderConnectionStatus(data);` line, add:

```javascript
        byId('generalAdPassword').value = '';
```

(clears the password field after a successful save, so it doesn't sit filled with a value that will be silently ignored — matching the "blank means keep existing" server-side rule from Task 5 — on the next save if the admin doesn't intend to change it.)

- [ ] **Step 5: Verify no missing/duplicate ids**

Run:
```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('server/dashboard/index.html', 'utf8');
const js = fs.readFileSync('server/dashboard/app.js', 'utf8');
const htmlIds = new Set([...html.matchAll(/\bid=\"([^\"]+)\"/g)].map(m => m[1]));
const jsIds = new Set([...js.matchAll(/byId\('([^']+)'\)/g)].map(m => m[1]));
console.log('missing ids:', [...jsIds].filter(id => !htmlIds.has(id)));
const idList = [...html.matchAll(/\bid=\"([^\"]+)\"/g)].map(m => m[1]);
console.log('duplicate ids:', [...new Set(idList.filter((id, i) => idList.indexOf(id) !== i))]);
"
```
Expected: both arrays empty.

- [ ] **Step 6: `node --check` the JS**

Run: `node --check server/dashboard/app.js`
Expected: no output (syntax OK).

- [ ] **Step 7: Live-verify in a browser**

Start a local server instance pointing `--content` at `server/dashboard`, open `#general`, confirm: the "Active Directory" block renders below HTTPS; toggling "Use service account identity" off reveals the username/password fields and on hides them; entering values and clicking Save round-trips (reload the page, the saved values are still populated, except the password field which is always blank after load).

- [ ] **Step 8: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js
git commit -m "Add Active Directory settings block to General settings"
```

---

### Task 8: Clients table column + CSV export

**Files:**
- Modify: `server/dashboard/index.html` (Clients table header, `#inventoryBody` colspan)
- Modify: `server/dashboard/app.js` (`renderTable`, `exportClients`)
- Modify: `server/dashboard/styles.css` (placeholder text styling, if not already covered by an existing `.muted`-equivalent utility)

**Interfaces:**
- Consumes: `adDescription`/`adSyncStatus` fields on each client record (Task 3's server-side additions — already present in whatever `GET /api/v1/clients` returns, since that endpoint serializes the same per-computer JSON files verbatim; no server change needed for this task).
- Produces: nothing consumed elsewhere.

- [ ] **Step 1: Add the table header**

Modify `server/dashboard/index.html`, the Clients table `<thead>` (currently ending `...<th>Actions</th>`), insert a new column before `Actions`:

```html
                  <th data-sort-table="clients" data-sort-key="collectedAt" class="sortable">Collected</th>
                  <th>AD Description</th>
                  <th>Actions</th>
```

- [ ] **Step 2: Update the empty-state colspan**

Modify `server/dashboard/app.js`, `renderTable`'s last line:
```javascript
    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="9" class="empty">No matching inventory records.</td></tr>';
```
to:
```javascript
    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="10" class="empty">No matching inventory records.</td></tr>';
```

(The details-row's own `colspan="9"` inside the same function must also become `10` - see Step 3.)

- [ ] **Step 3: Render the column and add a formatting helper**

Add a new function near `activationBadge` (in the same area of `app.js`):

```javascript
  function formatAdDescription(client) {
    if (client.adSyncStatus === 'not-found') {
      return '<small class="muted-cell">Not found in AD</small>';
    }
    if (client.adSyncStatus === 'error') {
      return '<small class="muted-cell">AD unreachable</small>';
    }
    if (client.adDescription) {
      return escapeHtml(client.adDescription);
    }
    return '';
  }
```

Modify `renderTable`'s row template - the `<td>` currently holding `Collected` and the `<td>` holding the Delete button:

```javascript
        <td>${escapeHtml(formatDateTime(client.collectedAt || client.sourceUpdatedAt))}</td>
        <td>${formatAdDescription(client)}</td>
        <td><button class="danger-button-ghost" type="button" data-delete-client="${escapeHtml(client.computerName)}">Delete</button></td>
```

And update the details-row colspan in the same function:
```javascript
        <td colspan="10">
```

- [ ] **Step 4: Add the `.muted-cell` style, if `.status-row small`'s muted styling isn't already reusable as a generic utility**

Check first: `grep -n "\.muted-cell\|color: var(--muted)" server/dashboard/styles.css` — if a generic "muted inline text" utility class already exists, reuse its name in Step 3 instead of introducing `.muted-cell`. If none exists, add near the other small utility classes (e.g. near `.mono`):

```css
.muted-cell {
  color: var(--muted);
}
```

- [ ] **Step 5: Extend CSV export**

Modify `server/dashboard/app.js`, `exportClients`. Change the header row:
```javascript
    const rows = [['Computer', 'Domain', 'IP Addresses', 'Client Version', 'OS', 'OS Version', 'Build', 'Office', 'Office Version', 'Windows Activated', 'Office Activated', 'Software Count', 'Collected', 'Stale', 'CPU', 'RAM', 'Disks', 'USB Storage']].concat(
```
to:
```javascript
    const rows = [['Computer', 'Domain', 'IP Addresses', 'Client Version', 'OS', 'OS Version', 'Build', 'Office', 'Office Version', 'Windows Activated', 'Office Activated', 'Software Count', 'Collected', 'Stale', 'CPU', 'RAM', 'Disks', 'USB Storage', 'AD Description']].concat(
```

And the row-mapping return array, which currently ends `c.hasUsbStorage ? 'Yes' : 'No'`:
```javascript
          c.hasUsbStorage ? 'Yes' : 'No'
        ];
```
becomes:
```javascript
          c.hasUsbStorage ? 'Yes' : 'No',
          c.adSyncStatus === 'not-found' ? 'Not found in AD' : c.adSyncStatus === 'error' ? 'AD unreachable' : (c.adDescription || '')
        ];
```

(CSV export already goes through `sanitizeCsvCell` inside `downloadCsv` per the existing formula-injection fix from earlier in this project's history — no separate escaping needed here.)

- [ ] **Step 6: Verify ids and syntax**

Run the same id cross-check and `node --check` commands as Task 7, Steps 5-6.

- [ ] **Step 7: Live-verify**

With `AdSyncEnabled` still false (default), confirm the Clients table shows an empty "AD Description" cell for every row (no `adSyncStatus`/`adDescription` fields exist on any report yet) and CSV export includes the new column header with blank values. This exercises the "feature is present in the UI but inert when disabled" path without needing a real AD to test against.

- [ ] **Step 8: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js server/dashboard/styles.css
git commit -m "Add AD Description column to the Clients table and CSV export"
```

---

### Task 9: Documentation

**Files:**
- Modify: `docs/threat-model.md`
- Modify: `README.md`, `README_RU.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: nothing consumed by other tasks.

- [ ] **Step 1: Update `docs/threat-model.md`**

Add to **Assets**: `- Cached Active Directory computer descriptions (adDescription field on each report), and AD credentials when explicit AD credentials (rather than the service identity) are configured.`

Add to **Attacker-Controlled Inputs**: `- The computer name embedded in a client's inventory report, when AD sync is enabled: used to build an LDAP search filter (see AdLookupService.LookupComputerDescription), escaped per RFC 4515 before use.`

Add to **Required Invariants**: `- The LDAP filter built from a client-reported computer name must have its special characters escaped before use, to prevent LDAP injection from a maliciously-named reporting host.` and `- An unreachable or slow AD must not block or fail inventory report ingestion.`

Add to **Main Risks**: `- If explicit AD credentials are configured (rather than the service account identity), they are stored in server-config.json in plaintext - the same accepted risk as WebPassword/Token, mitigated the same way (ACL-restricted config file).` and `- AD sync is opt-in and off by default, so this entire risk surface does not apply to deployments that don't enable it.`

Add to **Controls**: `- Prefer the service account identity over explicit AD credentials when the service already runs under a domain account (which WinRM client actions already require) - it needs no additional secret in server-config.json.`

- [ ] **Step 2: Update `README.md`**

Add a new `## Active Directory Description Sync` section (placed after `## HTTPS Setup` and before `## Dashboard Usage`, matching the existing document's ordering of "how a feature works" before "how to use the dashboard"):

```markdown
## Active Directory Description Sync

Optional and off by default. When enabled, the server looks up each reporting computer's Active Directory `description` attribute and shows it as a column on the `Clients` view - read-only, the dashboard never writes back to AD.

Enable it on Settings > General, in the "Active Directory" block, or at install time:

```powershell
.\src\Install-Server.ps1 -AdSyncEnabled
```

Two sync modes:

- **On inventory report** (default): refreshes a computer's cached AD data when it next reports inventory, if the cached value is older than the configured sync interval (default 24 hours).
- **Periodic timer**: refreshes every known computer on a fixed schedule, independent of whether it has reported recently - useful for computers that still exist in AD but have stopped reporting.

By default the server authenticates to AD using its own Windows Service identity (the same domain account WinRM client actions already require - a `LocalSystem` service can't reach AD any more than it can reach WinRM targets). To use separate, explicit AD credentials instead, uncheck "Use service account identity" and supply a username and password - stored in `server-config.json` in plaintext, the same as `WebPassword`.

If a computer's name has no matching AD computer object, the column shows "Not found in AD"; if AD itself was unreachable at sync time, it shows "AD unreachable".
```

- [ ] **Step 3: Update `README_RU.md`**

Add the corresponding Russian section (adapted, not a literal translation, per this workspace's documentation rules) in the same position:

```markdown
## Синхронизация Description из Active Directory

Опциональная функция, по умолчанию выключена. При включении сервер подтягивает атрибут `description` из Active Directory для каждого отчитывающегося компьютера и показывает его отдельной колонкой на вкладке `Clients` — только для чтения, запись обратно в AD никогда не выполняется.

Включается на странице Settings > General, в блоке «Active Directory», либо при установке:

```powershell
.\src\Install-Server.ps1 -AdSyncEnabled
```

Два режима синхронизации:

- **On inventory report** (по умолчанию): обновляет закэшированные AD-данные компьютера при очередном приходе его инвентарь-отчёта, если кэш старше настроенного интервала (по умолчанию 24 часа).
- **Periodic timer**: обновляет все известные компьютеры по расписанию, независимо от того, отчитывались ли они недавно — полезно для компьютеров, которые всё ещё есть в AD, но перестали слать отчёты.

По умолчанию сервер обращается к AD от имени собственной учётной записи службы Windows (того же доменного аккаунта, что уже требуется для WinRM-действий — служба под `LocalSystem` не достучится до AD точно так же, как не достучится и до WinRM-целей). Чтобы использовать отдельные явные учётные данные, снимите галочку «Use service account identity» и укажите имя пользователя и пароль — они хранятся в `server-config.json` открытым текстом, как и `WebPassword`.

Если имени компьютера не находится соответствующий объект в AD, колонка показывает «Not found in AD»; если AD была недоступна в момент синхронизации — «AD unreachable».
```

- [ ] **Step 4: Commit**

```bash
git add docs/threat-model.md README.md README_RU.md
git commit -m "Document AD Description sync in README/README_RU/threat-model"
```

---

### Task 10: Version bump, CHANGELOG, final verification

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs` (`ProductVersion`)
- Modify: `src/client/WindowsInventoryLiteClient.cs` (`ProductVersion`)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Bump the version**

This is a new feature (broad addition, not a bug fix) — MINOR bump per the workspace versioning rule. Check the current version first:

```bash
grep -n "ProductVersion = " src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs
```

Update both to the next MINOR version (current-minor + 1, patch reset to 0) in both files.

- [ ] **Step 2: Add the CHANGELOG entry**

Add a new `## [<new-version>] - <today's date>` section at the top of `CHANGELOG.md` (after `## [Unreleased]`), with an `### Added` block summarizing: AD Description sync (opt-in, off by default), two sync modes, service-identity or explicit-credential auth, new Clients table column and CSV export column, LDAP filter escaping against injection from client-reported computer names.

- [ ] **Step 3: Full rebuild**

```powershell
.\src\Build-Server.ps1
.\src\Build-Client.ps1 -TargetFramework Net35 -OutputPath '.\build\WindowsInventoryLiteClient-net35.exe'
.\src\Build-Client.ps1 -TargetFramework Net40
```
Expected: all three builds succeed.

- [ ] **Step 4: Full self-test + Pester run**

```powershell
.\build\WindowsInventoryLiteServer.exe --self-test
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester -Path .\tests -Output Detailed
```
Expected: all self-tests pass (20/20 per this plan's additions), all Pester tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs CHANGELOG.md
git commit -m "Bump version for AD Description sync"
```

---

## Post-plan notes (not part of this plan's tasks)

- Live LDAP verification against a real AD is not possible in this sandbox (no directory service reachable) - the same limitation already noted for TLS private-key operations earlier in this project. Tasks 1/3/4/5 verify everything that's testable without one (escaping, freshness logic, settings API validation, the "disabled by default" inert path); the actual `AdLookupService.LookupComputerDescription` LDAP round-trip needs to be exercised against a real domain before this ships.
- This plan does not include a manual "sync now" button (the design spec listed it as an open question) - add it as a follow-up task if wanted after the base feature is verified against real AD.
