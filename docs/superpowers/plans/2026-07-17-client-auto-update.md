# Client Auto-Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an administrator see, from the dashboard, which deployed clients are running an outdated version relative to the client package on the server, and push an update to the eligible ones with one click.

**Architecture:** A new read-only detection endpoint compares each client's last-reported `clientVersion` against the client package files already on the server's disk (no new client protocol, no background timer). A new small credentials endpoint lets an administrator optionally store a DPAPI-encrypted WinRM account as a fallback to the service's own identity. Pushing an update reuses the existing `POST /api/v1/client-install` WinRM job pipeline unchanged. A new dashboard page (`Installation > Client updates`) ties these together: a table of outdated clients (with Windows 7/8/8.1 targets shown but disabled, since WinRM is unreliable against them), a credentials form, and an "Update selected" button.

**Tech Stack:** C# (.NET Framework 3.5/4.0, hand-rolled HTTP server, `JavaScriptSerializer`), vanilla JS dashboard (no build step, no framework), PowerShell 5.1 (no changes needed - the existing WinRM install pipeline is reused as-is).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-17-client-auto-update-design.md` - read it before starting if anything below is ambiguous.
- No new client protocol change. The client does not start reporting its target framework (net35 vs net40) as part of this plan.
- No new WinRM job type. Pushing an update calls the existing `POST /api/v1/client-install` endpoint with `action` implied `install` (that endpoint has no `action` field of its own - see Task 5) exactly as the `Client actions` tab already does.
- No Install-Server.ps1 CLI parameters for the new credentials (`ClientUpdateUsername`/`ClientUpdatePassword`). They are dashboard-only, saved via a new POST endpoint - this was an explicit decision during brainstorming, do not add install-time flags "for consistency" with AD credentials.
- A client is "up to date" if its reported `clientVersion` equals the on-disk `net35Version` OR `net40Version` of the client package (whichever is present) - never flagged outdated just because a package build is missing. A client is "outdated" if its `clientVersion` matches neither present package version, or if it never reported a version at all (empty/missing `clientVersion` counts as outdated, not skipped).
- A client is WinRM-**eligible** unless its reported `os.caption` contains "Windows 7" or "Windows 8" (which also covers "Windows 8.1") - blocklist, not allowlist. Windows Server and any other caption stays eligible by default.
- This project's versioning rule (CLAUDE.md): MINOR bump for a new feature. Current version is `0.15.1` - this ships as `0.16.0`.
- All Pester verification in this project MUST run via `powershell.exe` (Windows PowerShell 5.1), never `pwsh` - running Pester under `pwsh` produces a deterministic false failure in `Test-InstallServerRefreshOnly` (`System.Web.Extensions` cannot load its GAC assembly under .NET Core). See `project_wil_followup_roadmap.md` memory for the full root-cause writeup.
- Standing operational constraint: do not run `Install-*.ps1`/`Uninstall-*.ps1` for real on the dev machine (they perform real `sc.exe` service actions). Live verification of the new server endpoints and dashboard page uses the already-built `.exe` run directly in console mode on a scratch port (`--console --prefix http://+:<port>/ ...`, never installed as a service) plus Playwright against that local instance - this is safe and was already used successfully in this project's prior security-fix work.

---

### Task 1: Detection logic (pure functions + self-tests)

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs`

**Interfaces:**
- Produces: `private static bool IsWinRmEligibleOs(string osCaption)` and `private static bool IsClientVersionCurrent(string clientVersion, string net35Version, string net40Version)` - both pure, no I/O, used by Task 2's `SendClientUpdates`.

- [ ] **Step 1: Add the two pure functions**

Find this exact block (the `GetExeVersion` function, already present in the file):

```csharp
        private static string GetExeVersion(string path)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = path;
                psi.Arguments = "--version";
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.CreateNoWindow = true;
                using (Process process = Process.Start(psi))
                {
                    if (!process.WaitForExit(5000))
                    {
                        try { process.Kill(); } catch { }
                        return null;
                    }
                    string line = process.StandardOutput.ReadLine();
                    return line != null ? line.Trim() : null;
                }
            }
            catch
            {
                return null;
            }
        }
```

Insert this new block immediately after it (before `private static Dictionary<string, string> ParseCmdSettings`):

```csharp

        // Blocklist, not allowlist: WinRM is unreliable against Windows
        // 7/8/8.1 in this project's own test environment. "Windows 8" also
        // matches "Windows 8.1" as a substring, so one check covers both.
        // Windows Server and any other caption (including a blank/unknown
        // one) stays eligible by default - this only excludes known-bad
        // targets, it does not require enumerating every valid OS caption.
        private static bool IsWinRmEligibleOs(string osCaption)
        {
            if (String.IsNullOrEmpty(osCaption))
            {
                return true;
            }
            return osCaption.IndexOf("Windows 7", StringComparison.OrdinalIgnoreCase) < 0
                && osCaption.IndexOf("Windows 8", StringComparison.OrdinalIgnoreCase) < 0;
        }

        // The client does not report which framework (net35/net40) it was
        // built with, so a client is considered current if its reported
        // version matches EITHER package currently on disk - this never
        // flags a genuinely current client as outdated. A client with no
        // reported version (old report predating the clientVersion field)
        // is treated as outdated, not skipped, since it clearly isn't
        // running anything current. A missing package (null) never counts
        // as a match, so a client can't accidentally appear current just
        // because one of the two package builds was never produced.
        private static bool IsClientVersionCurrent(string clientVersion, string net35Version, string net40Version)
        {
            if (String.IsNullOrEmpty(clientVersion))
            {
                return false;
            }
            if (net35Version != null && String.Equals(clientVersion, net35Version, StringComparison.Ordinal))
            {
                return true;
            }
            if (net40Version != null && String.Equals(clientVersion, net40Version, StringComparison.Ordinal))
            {
                return true;
            }
            return false;
        }
```

- [ ] **Step 2: Add self-tests**

Find this exact block (near the end of the file, in the self-test section):

```csharp
        private static string TestParseCmdSettingsDefaultPackageRoot()
        {
```

Insert this new block immediately before it:

```csharp
        private static string TestIsWinRmEligibleOsBlocksKnownBadVersions()
        {
            string[] blocked = { "Microsoft Windows 7 Professional", "Microsoft Windows 7 Ultimate", "Microsoft Windows 8 Pro", "Microsoft Windows 8.1 Enterprise" };
            foreach (string caption in blocked)
            {
                if (IsWinRmEligibleOs(caption))
                {
                    return "expected '" + caption + "' to be ineligible for WinRM";
                }
            }
            return null;
        }

        private static string TestIsWinRmEligibleOsAllowsOthers()
        {
            string[] allowed = { "Microsoft Windows 10 Pro", "Microsoft Windows 11 Enterprise", "Microsoft Windows Server 2019 Datacenter", "", null };
            foreach (string caption in allowed)
            {
                if (!IsWinRmEligibleOs(caption))
                {
                    return "expected '" + (caption ?? "(null)") + "' to be eligible for WinRM";
                }
            }
            return null;
        }

        private static string TestIsClientVersionCurrentMatchesEitherPackage()
        {
            if (!IsClientVersionCurrent("0.15.1", "0.15.1", "0.16.0"))
            {
                return "expected a version matching net35Version to be current";
            }
            if (!IsClientVersionCurrent("0.16.0", "0.15.1", "0.16.0"))
            {
                return "expected a version matching net40Version to be current";
            }
            return null;
        }

        private static string TestIsClientVersionCurrentOutdatedWhenMatchesNeither()
        {
            if (IsClientVersionCurrent("0.14.0", "0.15.1", "0.16.0"))
            {
                return "expected a version matching neither package to be outdated";
            }
            return null;
        }

        private static string TestIsClientVersionCurrentTreatsEmptyAsOutdated()
        {
            if (IsClientVersionCurrent("", "0.15.1", "0.16.0"))
            {
                return "expected an empty clientVersion to be outdated";
            }
            if (IsClientVersionCurrent(null, "0.15.1", "0.16.0"))
            {
                return "expected a null clientVersion to be outdated";
            }
            return null;
        }

        private static string TestIsClientVersionCurrentIgnoresMissingPackage()
        {
            if (IsClientVersionCurrent("0.15.1", null, "0.16.0"))
            {
                return "expected a version that would have matched a missing net35 package to be outdated, not current";
            }
            if (!IsClientVersionCurrent("0.16.0", null, "0.16.0"))
            {
                return "expected a version matching the only present package (net40) to be current";
            }
            return null;
        }

        private static string TestParseCmdSettingsDefaultPackageRoot()
        {
```

- [ ] **Step 3: Register the new self-tests**

Find this exact line:

```csharp
            allPassed &= SelfTestCheck(output, "ParseCmdSettings round-trips GenerateCmdLines' default package root", TestParseCmdSettingsDefaultPackageRoot);
```

Insert these lines immediately before it:

```csharp
            allPassed &= SelfTestCheck(output, "IsWinRmEligibleOs blocks Windows 7/8/8.1", TestIsWinRmEligibleOsBlocksKnownBadVersions);
            allPassed &= SelfTestCheck(output, "IsWinRmEligibleOs allows Windows 10/11/Server and unknown captions", TestIsWinRmEligibleOsAllowsOthers);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent matches either package version", TestIsClientVersionCurrentMatchesEitherPackage);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent is outdated when it matches neither package", TestIsClientVersionCurrentOutdatedWhenMatchesNeither);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent treats an empty clientVersion as outdated", TestIsClientVersionCurrentTreatsEmptyAsOutdated);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent ignores a missing package instead of false-matching it", TestIsClientVersionCurrentIgnoresMissingPackage);
```

- [ ] **Step 4: Build and run self-tests**

```powershell
.\src\Build-Server.ps1
.\build\WindowsInventoryLiteServer.exe --self-test
```

Expected: all lines `PASS`, including the 6 new ones, exit code 0. Total self-test count goes from 31 to 37.

- [ ] **Step 5: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add Client Auto-Update detection logic (eligibility + version-currency checks)"
```

---

### Task 2: Detection endpoint

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs`

**Interfaces:**
- Consumes: `IsWinRmEligibleOs(string)`, `IsClientVersionCurrent(string, string, string)` from Task 1; `GetExeVersion(string)` (existing); `GetStringValue(Dictionary<string, object>, string)` (existing).
- Produces: `GET /api/v1/client-updates` → JSON `{"packageAvailable": bool, "net35Version": string|null, "net40Version": string|null, "updates": [{"computerName": string, "domain": string, "clientVersion": string, "collectedAt": string, "eligible": bool}], "eligibleCount": int, "blockedCount": int}`. Later tasks (4, 5) consume this exact shape from the dashboard.

- [ ] **Step 1: Extract a reusable client-loading helper**

`BuildClientIndex()` currently reads every per-computer JSON report and returns a serialized JSON string. `SendClientUpdates` (this task) needs the same reports as an in-memory list, not a JSON string. Extract the loading loop into its own method so both callers share it.

Find this exact block:

```csharp
        private string BuildClientIndex()
        {
            ArrayList clients = new ArrayList();
            JavaScriptSerializer serializer = CreateJsonSerializer();

            foreach (string file in Directory.GetFiles(options.DataPath, "*.json"))
            {
                try
                {
                    string raw = File.ReadAllText(file, Encoding.UTF8);
                    Dictionary<string, object> client = serializer.Deserialize<Dictionary<string, object>>(raw);
                    client["sourceFile"] = Path.GetFileName(file);
                    client["sourceUpdatedAt"] = File.GetLastWriteTimeUtc(file).ToString("yyyy-MM-ddTHH:mm:ssZ");
                    clients.Add(client);
                }
                catch
                {
                }
            }

            Dictionary<string, object> index = new Dictionary<string, object>();
            index["schemaVersion"] = "1.0";
            index["serverVersion"] = Program.ProductVersion;
            index["generatedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            index["clientCount"] = clients.Count;
            index["staleHours"] = options.StaleHours;
            index["clients"] = clients;
            return serializer.Serialize(index);
        }
```

Replace it with:

```csharp
        private ArrayList LoadClientReports()
        {
            ArrayList clients = new ArrayList();
            JavaScriptSerializer serializer = CreateJsonSerializer();

            foreach (string file in Directory.GetFiles(options.DataPath, "*.json"))
            {
                try
                {
                    string raw = File.ReadAllText(file, Encoding.UTF8);
                    Dictionary<string, object> client = serializer.Deserialize<Dictionary<string, object>>(raw);
                    client["sourceFile"] = Path.GetFileName(file);
                    client["sourceUpdatedAt"] = File.GetLastWriteTimeUtc(file).ToString("yyyy-MM-ddTHH:mm:ssZ");
                    clients.Add(client);
                }
                catch
                {
                }
            }

            return clients;
        }

        private string BuildClientIndex()
        {
            ArrayList clients = LoadClientReports();
            JavaScriptSerializer serializer = CreateJsonSerializer();

            Dictionary<string, object> index = new Dictionary<string, object>();
            index["schemaVersion"] = "1.0";
            index["serverVersion"] = Program.ProductVersion;
            index["generatedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            index["clientCount"] = clients.Count;
            index["staleHours"] = options.StaleHours;
            index["clients"] = clients;
            return serializer.Serialize(index);
        }
```

- [ ] **Step 2: Add `SendClientUpdates`**

Find this exact block (`SendClientPackageStatus`, already present):

```csharp
        private void SendClientPackageStatus(Stream stream)
        {
```

Insert this new method immediately before it:

```csharp
        private void SendClientUpdates(Stream stream)
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> result = new Dictionary<string, object>();

            string net35Version = null;
            string net40Version = null;
            if (Directory.Exists(options.ClientPackagePath))
            {
                string net35Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net35.exe");
                string net40Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net40.exe");
                net35Version = File.Exists(net35Path) ? GetExeVersion(net35Path) : null;
                net40Version = File.Exists(net40Path) ? GetExeVersion(net40Path) : null;
            }

            result["net35Version"] = net35Version;
            result["net40Version"] = net40Version;

            // No package built at all yet - there is nothing a push could
            // actually deploy, so classifying every client as "outdated"
            // here would be misleading rather than informative.
            if (net35Version == null && net40Version == null)
            {
                result["packageAvailable"] = false;
                result["updates"] = new ArrayList();
                result["eligibleCount"] = 0;
                result["blockedCount"] = 0;
                SendJson(stream, serializer.Serialize(result));
                return;
            }

            result["packageAvailable"] = true;
            ArrayList updates = new ArrayList();
            int eligibleCount = 0;
            int blockedCount = 0;

            foreach (Dictionary<string, object> client in LoadClientReports())
            {
                string clientVersion = GetStringValue(client, "clientVersion");
                if (IsClientVersionCurrent(clientVersion, net35Version, net40Version))
                {
                    continue;
                }

                Dictionary<string, object> os = client.ContainsKey("os") ? client["os"] as Dictionary<string, object> : null;
                string osCaption = GetStringValue(os, "caption");
                bool eligible = IsWinRmEligibleOs(osCaption);

                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["computerName"] = GetStringValue(client, "computerName");
                entry["domain"] = GetStringValue(client, "domain");
                entry["clientVersion"] = clientVersion;
                entry["osCaption"] = osCaption;
                entry["collectedAt"] = GetStringValue(client, "collectedAt");
                entry["eligible"] = eligible;
                updates.Add(entry);

                if (eligible)
                {
                    eligibleCount++;
                }
                else
                {
                    blockedCount++;
                }
            }

            result["updates"] = updates;
            result["eligibleCount"] = eligibleCount;
            result["blockedCount"] = blockedCount;
            SendJson(stream, serializer.Serialize(result));
        }

```

Note: `GetStringValue` already tolerates a `null` `source` argument (returns `""`), so passing `os` when a client has no `"os"` key at all is safe.

- [ ] **Step 3: Wire the route**

Find this exact block:

```csharp
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-package")
                    {
                        SendClientPackageStatus(stream);
                    }
```

Replace it with:

```csharp
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-updates")
                    {
                        SendClientUpdates(stream);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-package")
                    {
                        SendClientPackageStatus(stream);
                    }
```

- [ ] **Step 4: Build and run self-tests**

```powershell
.\src\Build-Server.ps1
.\build\WindowsInventoryLiteServer.exe --self-test
```

Expected: all 37 self-tests still `PASS`, exit code 0 (this step only adds new code paths, it doesn't touch anything the existing self-tests exercise, but confirms the file still compiles and nothing broke).

- [ ] **Step 5: Live-verify the endpoint**

Run the server in console mode on a scratch port against a temporary data directory with two synthetic client reports (one outdated+eligible, one outdated+blocked by OS), and a client package directory with a single fake versioned exe. Do this from an elevated-not-required PowerShell session (this only runs the already-built `.exe` directly, not any install script):

```powershell
$dataPath = Join-Path $env:TEMP 'wil-client-updates-test-data'
$packagePath = Join-Path $env:TEMP 'wil-client-updates-test-package'
New-Item -Path $dataPath -ItemType Directory -Force | Out-Null
New-Item -Path $packagePath -ItemType Directory -Force | Out-Null
'{"computerName":"PC-OLD-10","domain":"corp.local","clientVersion":"0.14.0","collectedAt":"2026-07-17T09:00:00Z","os":{"caption":"Microsoft Windows 10 Pro"}}' | Set-Content -LiteralPath (Join-Path $dataPath 'PC-OLD-10.json') -Encoding UTF8
'{"computerName":"PC-OLD-7","domain":"corp.local","clientVersion":"0.14.0","collectedAt":"2026-07-17T09:00:00Z","os":{"caption":"Microsoft Windows 7 Professional"}}' | Set-Content -LiteralPath (Join-Path $dataPath 'PC-OLD-7.json') -Encoding UTF8
'{"computerName":"PC-CURRENT","domain":"corp.local","clientVersion":"0.16.0","collectedAt":"2026-07-17T09:00:00Z","os":{"caption":"Microsoft Windows 11 Pro"}}' | Set-Content -LiteralPath (Join-Path $dataPath 'PC-CURRENT.json') -Encoding UTF8
Copy-Item -LiteralPath '.\build\WindowsInventoryLiteServer.exe' -Destination (Join-Path $packagePath 'WindowsInventoryLiteClient-net40.exe')
$proc = Start-Process -FilePath '.\build\WindowsInventoryLiteServer.exe' -ArgumentList '--console','--prefix','http://+:18097/','--data',$dataPath,'--content','.\server\dashboard','--client-package',$packagePath -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2
(Invoke-WebRequest -Uri 'http://127.0.0.1:18097/api/v1/client-updates' -UseBasicParsing).Content
Stop-Process -Id $proc.Id -Force
Remove-Item -LiteralPath $dataPath, $packagePath -Recurse -Force
```

Note: copying the server .exe itself into the package path as a stand-in is only to get a real, versioned PE file `GetExeVersion` can read (it shells out to `--version`, which the server exe also supports) - its actual reported version is `0.16.0` after this plan's Task 6 version bump; if this step runs before Task 6, expect whatever version `--self-test`/`--version` currently reports and adjust `PC-CURRENT`'s `clientVersion` in the fixture above to match, so the "current" fixture is genuinely exercised as current.

Expected JSON response: `packageAvailable: true`, `net40Version` matching the running server's own version, `net35Version: null`, `updates` containing exactly `PC-OLD-10` (`eligible: true`) and `PC-OLD-7` (`eligible: false`) - `PC-CURRENT` must NOT appear. `eligibleCount: 1`, `blockedCount: 1`.

- [ ] **Step 6: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add GET /api/v1/client-updates detection endpoint"
```

---

### Task 3: Credentials storage and status/save endpoints

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs`

**Interfaces:**
- Produces: `ServerOptions.ClientUpdateUsername`/`ClientUpdatePassword` fields; `GET /api/v1/client-updates/credentials` → `{"configured": bool, "username": string|null}`; `POST /api/v1/client-updates/credentials` accepting `{"username": string, "password": string}` (blank password on save = keep the existing one, matching the AD credentials save pattern). Task 5 (dashboard push action) consumes `options.ClientUpdateUsername`/`ClientUpdatePassword` as the credential fallback.

- [ ] **Step 1: Add the `ServerOptions` fields**

Find this exact block:

```csharp
        public bool DebugLogEnabled;
        public string DebugLogPath;

        public static ServerOptions Parse(string[] args)
```

Replace it with:

```csharp
        public bool DebugLogEnabled;
        public string DebugLogPath;
        // Optional, off by default - dashboard-configured only (no
        // Install-Server.ps1 CLI flag by design, see the plan's Global
        // Constraints). Used as a fallback WinRM credential for Client
        // Auto-Update pushes when the service's own identity can't reach a
        // target; see docs/superpowers/specs/2026-07-17-client-auto-update-design.md.
        public string ClientUpdateUsername;
        public string ClientUpdatePassword;

        public static ServerOptions Parse(string[] args)
```

- [ ] **Step 2: Load the fields from `server-config.json`**

Find this exact block:

```csharp
                if (String.IsNullOrEmpty(options.AdPassword))
                {
                    // Decrypts a DPAPI-protected value (see SecretProtector.cs);
                    // a legacy/hand-edited plaintext value is used as-is.
                    options.AdPassword = SecretProtector.Unprotect(GetConfigString(config, "AdPassword"));
                }
                if (!options.DebugLogEnabled)
```

Replace it with:

```csharp
                if (String.IsNullOrEmpty(options.AdPassword))
                {
                    // Decrypts a DPAPI-protected value (see SecretProtector.cs);
                    // a legacy/hand-edited plaintext value is used as-is.
                    options.AdPassword = SecretProtector.Unprotect(GetConfigString(config, "AdPassword"));
                }
                if (String.IsNullOrEmpty(options.ClientUpdateUsername))
                {
                    options.ClientUpdateUsername = GetConfigString(config, "ClientUpdateUsername");
                }
                if (String.IsNullOrEmpty(options.ClientUpdatePassword))
                {
                    options.ClientUpdatePassword = SecretProtector.Unprotect(GetConfigString(config, "ClientUpdatePassword"));
                }
                if (!options.DebugLogEnabled)
```

- [ ] **Step 3: Encrypt the password at rest**

Find this exact block:

```csharp
        private static readonly HashSet<string> EncryptedConfigKeys = new HashSet<string>(
            new[] { "AdPassword", "WebPassword", "Token" },
            StringComparer.Ordinal);
```

Replace it with:

```csharp
        private static readonly HashSet<string> EncryptedConfigKeys = new HashSet<string>(
            new[] { "AdPassword", "WebPassword", "Token", "ClientUpdatePassword" },
            StringComparer.Ordinal);
```

- [ ] **Step 4: Add the status and save handlers**

Find this exact block (`SendAdminPasswordStatus`, already present):

```csharp
        private void SendAdminPasswordStatus(Stream stream)
        {
            bool configured = !String.IsNullOrEmpty(options.WebUsername) && !String.IsNullOrEmpty(options.WebPassword);
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["configured"] = configured;
            result["username"] = configured ? options.WebUsername : null;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }
```

Insert this new pair of methods immediately after it:

```csharp

        private void SendClientUpdateCredentialsStatus(Stream stream)
        {
            bool configured = !String.IsNullOrEmpty(options.ClientUpdateUsername) && !String.IsNullOrEmpty(options.ClientUpdatePassword);
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["configured"] = configured;
            result["username"] = String.IsNullOrEmpty(options.ClientUpdateUsername) ? null : options.ClientUpdateUsername;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void ConfigureClientUpdateCredentials(Stream stream, RequestContext request)
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> payload;
            try
            {
                payload = serializer.Deserialize<Dictionary<string, object>>(request.Body);
            }
            catch
            {
                SendText(stream, "{\"error\":\"invalid request body\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string username = payload.ContainsKey("username") ? Convert.ToString(payload["username"]) : options.ClientUpdateUsername;
            // Blank/omitted password means "keep the existing one" - the
            // dashboard never pre-fills a password field with the real
            // stored value, matching the AD credentials save endpoint.
            string password = payload.ContainsKey("password") && !String.IsNullOrEmpty(Convert.ToString(payload["password"]))
                ? Convert.ToString(payload["password"])
                : options.ClientUpdatePassword;

            options.ClientUpdateUsername = username;
            options.ClientUpdatePassword = password;

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["ClientUpdateUsername"] = username ?? "";
            updates["ClientUpdatePassword"] = password ?? "";
            SaveServerConfigValues(updates);

            SendClientUpdateCredentialsStatus(stream);
        }
```

- [ ] **Step 5: Wire the routes**

Find this exact block:

```csharp
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-updates")
                    {
                        SendClientUpdates(stream);
                    }
```

Replace it with:

```csharp
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-updates")
                    {
                        SendClientUpdates(stream);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-updates/credentials")
                    {
                        SendClientUpdateCredentialsStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/client-updates/credentials")
                    {
                        ConfigureClientUpdateCredentials(stream, request);
                    }
```

- [ ] **Step 6: Build and run self-tests**

```powershell
.\src\Build-Server.ps1
.\build\WindowsInventoryLiteServer.exe --self-test
```

Expected: all 37 self-tests still `PASS`, exit code 0.

- [ ] **Step 7: Live-verify save + encryption + reload**

```powershell
$dataPath = Join-Path $env:TEMP 'wil-cred-test-data'
$configPath = Join-Path $env:TEMP 'wil-cred-test-config.json'
New-Item -Path $dataPath -ItemType Directory -Force | Out-Null
$proc = Start-Process -FilePath '.\build\WindowsInventoryLiteServer.exe' -ArgumentList '--console','--prefix','http://+:18096/','--data',$dataPath,'--content','.\server\dashboard','--config',$configPath -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2
Invoke-WebRequest -Uri 'http://127.0.0.1:18096/api/v1/client-updates/credentials' -Method Post -ContentType 'application/json' -Body '{"username":"CORP\\svc-update","password":"correct-horse-battery-staple"}' -UseBasicParsing | Out-Null
(Invoke-WebRequest -Uri 'http://127.0.0.1:18096/api/v1/client-updates/credentials' -UseBasicParsing).Content
Stop-Process -Id $proc.Id -Force
Start-Sleep -Seconds 1
Get-Content -LiteralPath $configPath | Select-String 'ClientUpdate'
Remove-Item -LiteralPath $dataPath, $configPath -Recurse -Force
```

Expected: the GET response shows `"configured":true,"username":"CORP\\svc-update"` (no password field at all). The raw config file's `ClientUpdatePassword` value starts with `dpapi:` (DPAPI-encrypted, never plaintext), while `ClientUpdateUsername` is plain `"CORP\\svc-update"` (not a secret, same treatment as `WebUsername`/`AdUsername`).

- [ ] **Step 8: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add Client Auto-Update credential storage (GET/POST /api/v1/client-updates/credentials)"
```

---

### Task 4: Dashboard UI - page scaffold, detection table, sidebar badge

**Files:**
- Modify: `server/dashboard/index.html`
- Modify: `server/dashboard/app.js`
- Modify: `server/dashboard/styles.css`

**Interfaces:**
- Consumes: `GET /api/v1/client-updates` (Task 2's exact response shape).
- Produces: `state.view === 'updates'`; `loadClientUpdates()` and `renderClientUpdates(data)` functions; a `#updatesTab`/`#updatesView` pair Task 5 extends with the credentials form and push button.

- [ ] **Step 1: Add the sidebar nav entry**

Find this exact block in `server/dashboard/index.html`:

```html
          <button id="packageTab" class="nav-item" type="button">
            <svg class="nav-icon" viewBox="0 0 20 20" aria-hidden="true"><rect x="2.5" y="4" width="15" height="3.5" rx="0.8"/><path d="M3.5 7.5 v8 h13 v-8"/><line x1="8" y1="10.5" x2="12" y2="10.5"/></svg>
            Client package
          </button>
        </div>
```

Replace it with:

```html
          <button id="packageTab" class="nav-item" type="button">
            <svg class="nav-icon" viewBox="0 0 20 20" aria-hidden="true"><rect x="2.5" y="4" width="15" height="3.5" rx="0.8"/><path d="M3.5 7.5 v8 h13 v-8"/><line x1="8" y1="10.5" x2="12" y2="10.5"/></svg>
            Client package
          </button>
          <button id="updatesTab" class="nav-item" type="button">
            <svg class="nav-icon" viewBox="0 0 20 20" aria-hidden="true"><path d="M10 3 a7 7 0 1 1 -6.3 4"/><path d="M3 3 v4 h4"/></svg>
            Client updates
            <span id="updatesBadge" class="nav-badge hidden">0</span>
          </button>
        </div>
```

- [ ] **Step 2: Add the view section**

Find this exact block:

```html
        <section id="installView" class="install-panel hidden" aria-label="Remote client actions">
```

Insert this new section immediately before it:

```html
        <section id="updatesView" class="install-panel hidden" aria-label="Client updates">
          <p id="updatesPackageStatus" class="pkg-status">Loading client update status...</p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Computer</th>
                  <th>Domain</th>
                  <th>Current version</th>
                  <th>Available version</th>
                  <th>Last collected</th>
                  <th><input id="updatesSelectAll" type="checkbox" title="Select all eligible"></th>
                </tr>
              </thead>
              <tbody id="updatesBody"></tbody>
            </table>
          </div>
        </section>

        <section id="installView" class="install-panel hidden" aria-label="Remote client actions">
```

- [ ] **Step 3: Add the sidebar badge CSS**

Find this exact block in `server/dashboard/styles.css`:

```css
.nav-item-root {
  margin: 4px 0 10px;
  padding-left: 10px;
  font-weight: 650;
}
```

Insert this new rule immediately after it:

```css

.nav-badge {
  margin-left: auto;
  background: var(--accent);
  color: var(--accent-text);
  font-size: 11px;
  font-weight: 650;
  line-height: 1;
  padding: 2px 7px;
  border-radius: 999px;
}
```

- [ ] **Step 4: Add the app.js state and view wiring**

Find this exact block in `server/dashboard/app.js`:

```javascript
    clients: [], view: getInitialView(), installJobId: null, installPollTimer: null, installJobs: [],
    packageStatus: null,
```

Replace it with:

```javascript
    clients: [], view: getInitialView(), installJobId: null, installPollTimer: null, installJobs: [],
    packageStatus: null,
    clientUpdates: null,
```

Find this exact block:

```javascript
    if (hash === 'client-package' || hash === 'package') return 'package';
```

Insert this line immediately after it:

```javascript
    if (hash === 'client-updates' || hash === 'updates') return 'updates';
```

Find this exact block:

```javascript
    const hash = view === 'install' ? 'client-actions' : view === 'package' ? 'client-package' : view === 'admin' ? 'admin-password' : view;
    if (window.location.hash.replace(/^#/, '') !== hash) {
      window.location.hash = hash;
      return;
    }
    render();
    if (view === 'install') loadInstallHistory();
    if (view === 'package') loadPackageStatus();
```

Replace it with:

```javascript
    const hash = view === 'install' ? 'client-actions' : view === 'package' ? 'client-package' : view === 'updates' ? 'client-updates' : view === 'admin' ? 'admin-password' : view;
    if (window.location.hash.replace(/^#/, '') !== hash) {
      window.location.hash = hash;
      return;
    }
    render();
    if (view === 'install') loadInstallHistory();
    if (view === 'package') loadPackageStatus();
    if (view === 'updates') loadClientUpdates();
```

Find this exact block:

```javascript
    byId('packageTab').classList.toggle('active', state.view === 'package');
```

Insert this line immediately after it:

```javascript
    byId('updatesTab').classList.toggle('active', state.view === 'updates');
```

Find this exact line:

```javascript
  byId('packageTab').addEventListener('click', () => setView('package'));
```

Insert this line immediately after it:

```javascript
  byId('updatesTab').addEventListener('click', () => setView('updates'));
```

Now find the section rendering logic - the code that shows/hides each `#...View` section based on `state.view` (it sits alongside the `nav-item` active-class toggles from a few steps above, in the same function). Find this exact block:

```javascript
    byId('packageView').classList.toggle('hidden', state.view !== 'package');
```

Insert this line immediately after it:

```javascript
    byId('updatesView').classList.toggle('hidden', state.view !== 'updates');
```

**Important - two non-identical occurrences ahead:** the `if (state.view === 'package') loadPackageStatus();` line (and its 4 neighboring `if` lines) appears TWICE in this file with DIFFERENT indentation each time - once inside the hash-change event listener (4-space indent) and once at the bottom of the file for the initial page load (2-space indent). Treat these as two separate edits, not one `replace_all` (a single old_string with one indentation level will only match one of the two). First occurrence, 4-space indent:

```javascript
    if (state.view === 'package') loadPackageStatus();
    if (state.view === 'general') loadGeneralSettings();
    if (state.view === 'certificate') { loadCertificateStatus(); loadCertificateHistory(); }
    if (state.view === 'licenses') loadLicenses();
    if (state.view === 'admin') loadAdminPasswordStatus();
```

Replace it with:

```javascript
    if (state.view === 'package') loadPackageStatus();
    if (state.view === 'updates') loadClientUpdates();
    if (state.view === 'general') loadGeneralSettings();
    if (state.view === 'certificate') { loadCertificateStatus(); loadCertificateHistory(); }
    if (state.view === 'licenses') loadLicenses();
    if (state.view === 'admin') loadAdminPasswordStatus();
```

Second occurrence, 2-space indent (near the bottom of the file, right after `updateThemeToggle();`):

```javascript
  if (state.view === 'package') loadPackageStatus();
  if (state.view === 'general') loadGeneralSettings();
  if (state.view === 'certificate') { loadCertificateStatus(); loadCertificateHistory(); }
  if (state.view === 'licenses') loadLicenses();
  if (state.view === 'admin') loadAdminPasswordStatus();
```

Replace it with:

```javascript
  if (state.view === 'package') loadPackageStatus();
  if (state.view === 'updates') loadClientUpdates();
  if (state.view === 'general') loadGeneralSettings();
  if (state.view === 'certificate') { loadCertificateStatus(); loadCertificateHistory(); }
  if (state.view === 'licenses') loadLicenses();
  if (state.view === 'admin') loadAdminPasswordStatus();
```

- [ ] **Step 5: Add the load/render functions**

Find this exact block (`loadPackageStatus`, already present):

```javascript
  function loadPackageStatus() {
```

Insert these new functions immediately before it:

```javascript
  function loadClientUpdates() {
    fetch('/api/v1/client-updates', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.clientUpdates = data;
        renderClientUpdates(data);
      })
      .catch(error => {
        byId('updatesPackageStatus').textContent = `Client update status unavailable: ${error.message}`;
      });
  }

  function formatAvailableVersion(data) {
    if (data.net35Version && data.net40Version && data.net35Version !== data.net40Version) {
      return `net35 v${escapeHtml(data.net35Version)} / net40 v${escapeHtml(data.net40Version)}`;
    }
    const version = data.net35Version || data.net40Version;
    return version ? `v${escapeHtml(version)}` : 'unknown';
  }

  function renderClientUpdates(data) {
    if (!data.packageAvailable) {
      byId('updatesPackageStatus').textContent = 'No client package is available yet - build or deploy one on the Client package tab first.';
      byId('updatesBody').innerHTML = '';
      updateUpdatesBadge(0);
      return;
    }

    const updates = data.updates || [];
    byId('updatesPackageStatus').textContent = `Current client package: ${formatAvailableVersion(data)}. ${data.eligibleCount} eligible for WinRM push, ${data.blockedCount} blocked by OS.`;

    if (updates.length === 0) {
      byId('updatesBody').innerHTML = '<tr><td colspan="6" class="empty">Every reporting client is up to date.</td></tr>';
      updateUpdatesBadge(0);
      return;
    }

    const rows = updates.map(update => {
      const checkbox = update.eligible
        ? `<input type="checkbox" class="updates-row-checkbox" data-computer-name="${escapeHtml(update.computerName)}">`
        : `<input type="checkbox" disabled title="WinRM is not supported on ${escapeHtml(update.osCaption || 'this OS')} - update via GPO or locally instead">`;
      return `<tr class="${update.eligible ? '' : 'muted-row'}">
        <td>${escapeHtml(update.computerName)}</td>
        <td>${escapeHtml(update.domain)}</td>
        <td>${escapeHtml(update.clientVersion || 'Unknown')}</td>
        <td>${formatAvailableVersion(data)}</td>
        <td>${escapeHtml(formatDateTime(update.collectedAt))}</td>
        <td>${checkbox}</td>
      </tr>`;
    });

    byId('updatesBody').innerHTML = rows.join('');
    updateUpdatesBadge(data.eligibleCount);
  }

  function updateUpdatesBadge(eligibleCount) {
    const badge = byId('updatesBadge');
    if (eligibleCount > 0) {
      badge.textContent = String(eligibleCount);
      badge.classList.remove('hidden');
    } else {
      badge.classList.add('hidden');
    }
  }

```

Note: `.muted-row` and `.empty` (used on the `<td colspan>` above) already exist as site-wide table conventions elsewhere in this file - no new CSS needed for them.

- [ ] **Step 6: Build and syntax-check**

```powershell
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester -Path .\tests\ScriptSyntax.Tests.ps1 -Output Detailed
```

Expected: PASS (this test file checks HTML/JS/CSS are well-formed alongside PowerShell syntax - confirm exactly what it covers by reading `tests/ScriptSyntax.Tests.ps1` if the result is unexpected).

- [ ] **Step 7: Live-verify the page renders**

Using the same synthetic-data pattern as Task 2 Step 5 (one eligible outdated client, one OS-blocked outdated client, one current client, and a client package with a single fake exe), start the server in console mode on a scratch port, then use Playwright to navigate to `http://localhost:<port>/#client-updates`, take a snapshot, and confirm:
- The sidebar shows a badge with the eligible count next to "Client updates".
- The table shows both outdated rows; the blocked row's checkbox is disabled with a title mentioning WinRM/OS; the eligible row's checkbox is enabled.
- The current client does not appear in the table at all.

Stop the server process and delete the scratch data/package directories afterward, exactly as in Task 2 Step 5.

- [ ] **Step 8: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js server/dashboard/styles.css
git commit -m "Add Client updates dashboard page: detection table and sidebar badge"
```

---

### Task 5: Dashboard UI - credentials form and push action

**Files:**
- Modify: `server/dashboard/index.html`
- Modify: `server/dashboard/app.js`
- Modify: `server/dashboard/styles.css`

**Interfaces:**
- Consumes: `GET`/`POST /api/v1/client-updates/credentials` (Task 3); `POST /api/v1/client-install` and `GET /api/v1/client-install/:id` (existing, unchanged); `state.clientUpdates` (Task 4).
- Produces: `saveClientUpdateCredentials()`, `startClientUpdateJob()`; generalizes `pollInstallJob`/`renderInstallJob` to accept a target element id (existing `Client actions` callers keep working unchanged by relying on the added parameter's default).

- [ ] **Step 1: Add the credentials form and push button markup**

Find this exact block in `server/dashboard/index.html` (the `updatesView` section added in Task 4):

```html
        <section id="updatesView" class="install-panel hidden" aria-label="Client updates">
          <p id="updatesPackageStatus" class="pkg-status">Loading client update status...</p>
          <div class="table-wrap">
```

Replace it with:

```html
        <section id="updatesView" class="install-panel hidden" aria-label="Client updates">
          <div class="settings-block">
            <h2 class="settings-block-title">WinRM credentials</h2>
            <p class="cert-hint">Leave both fields blank to use the server service's own identity (the same account WinRM client actions already require). Fill them in only if a separate account is needed to reach update targets.</p>
            <div class="pkg-grid client-update-grid">
              <label class="pkg-token-field">
                Client update username
                <input id="updatesUsername" type="text" autocomplete="username" placeholder="DOMAIN\svc-account">
              </label>
              <label class="pkg-token-field">
                Client update password
                <input id="updatesPassword" type="password" autocomplete="new-password" placeholder="leave blank to keep the current one">
              </label>
              <button id="updatesSaveCredentialsButton" class="primary-button" type="button">Save</button>
            </div>
            <div id="updatesCredentialsMessage" class="pkg-message hidden"></div>
          </div>
          <p id="updatesPackageStatus" class="pkg-status">Loading client update status...</p>
          <div class="table-wrap">
```

Find this exact block (the table's `<thead>` closing, still within `updatesView`):

```html
              </thead>
              <tbody id="updatesBody"></tbody>
            </table>
          </div>
        </section>
```

Replace it with:

```html
              </thead>
              <tbody id="updatesBody"></tbody>
            </table>
          </div>
          <button id="updatesPushButton" class="primary-button" type="button" disabled>Update selected</button>
          <div id="updatesStatus" class="install-status empty">No update job started.</div>
        </section>
```

- [ ] **Step 2: Add the credentials grid CSS**

Find this exact block in `server/dashboard/styles.css`:

```css
.general-grid {
  grid-template-columns: minmax(180px, 1fr) minmax(280px, 2fr) auto;
}
```

Insert this new rule immediately after it:

```css

.client-update-grid {
  grid-template-columns: minmax(200px, 1fr) minmax(200px, 1fr) auto;
}
```

- [ ] **Step 3: Generalize `pollInstallJob`/`renderInstallJob`**

Find this exact block in `server/dashboard/app.js`:

```javascript
  function renderInstallJob(job) {
    const results = job.results || [];
    const rows = results.map(result => `<tr>
      <td>${escapeHtml(result.target)}</td>
      <td>${escapeHtml(result.status)}</td>
      <td>${escapeHtml(result.message)}</td>
      <td><pre class="install-output">${escapeHtml((result.error || result.output || '').trim())}</pre></td>
    </tr>`).join('');

    byId('installStatus').classList.remove('empty');
    byId('installStatus').innerHTML = `<div class="job-header">
        <strong>Job ${escapeHtml(job.id)}</strong>
        <span>${escapeHtml(job.action || 'install')}</span>
        <span>${escapeHtml(job.status)}</span>
      </div>
      <div class="install-results">
        <table class="nested-table install-results-table">
          <thead><tr><th>Target</th><th>Status</th><th>Message</th><th>Output</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="4" class="empty">Waiting for results.</td></tr>'}</tbody>
        </table>
      </div>`;
  }
```

Replace it with:

```javascript
  function renderInstallJob(job, statusElementId = 'installStatus') {
    const results = job.results || [];
    const rows = results.map(result => `<tr>
      <td>${escapeHtml(result.target)}</td>
      <td>${escapeHtml(result.status)}</td>
      <td>${escapeHtml(result.message)}</td>
      <td><pre class="install-output">${escapeHtml((result.error || result.output || '').trim())}</pre></td>
    </tr>`).join('');

    const statusElement = byId(statusElementId);
    statusElement.classList.remove('empty');
    statusElement.innerHTML = `<div class="job-header">
        <strong>Job ${escapeHtml(job.id)}</strong>
        <span>${escapeHtml(job.action || 'install')}</span>
        <span>${escapeHtml(job.status)}</span>
      </div>
      <div class="install-results">
        <table class="nested-table install-results-table">
          <thead><tr><th>Target</th><th>Status</th><th>Message</th><th>Output</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="4" class="empty">Waiting for results.</td></tr>'}</tbody>
        </table>
      </div>`;
  }
```

Find this exact block:

```javascript
  function pollInstallJob(jobId) {
    fetch(`/api/v1/client-install/${encodeURIComponent(jobId)}`, { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(job => {
        renderInstallJob(job);
        if (job.status === 'completed' && state.installPollTimer) {
          window.clearInterval(state.installPollTimer);
          state.installPollTimer = null;
          loadInstallHistory();
        }
      })
      .catch(error => {
        byId('installStatus').textContent = `Install job status is not available: ${error.message}`;
      });
  }
```

Replace it with:

```javascript
  function pollInstallJob(jobId, statusElementId = 'installStatus', onComplete = loadInstallHistory) {
    fetch(`/api/v1/client-install/${encodeURIComponent(jobId)}`, { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(job => {
        renderInstallJob(job, statusElementId);
        if (job.status === 'completed' && state.installPollTimer) {
          window.clearInterval(state.installPollTimer);
          state.installPollTimer = null;
          onComplete();
        }
      })
      .catch(error => {
        byId(statusElementId).textContent = `Install job status is not available: ${error.message}`;
      });
  }
```

Every existing call site (`pollInstallJob(state.installJobId)` in `startClientActionJob`, and the one inside `renderInstallHistory`'s button click handler) keeps working unchanged: both extra parameters default to the `Client actions` tab's own element id and its existing history-reload behavior.

- [ ] **Step 4: Add the credentials save and push functions**

Find this exact block (right after the `updateUpdatesBadge` function added in Task 4):

```javascript
  function updateUpdatesBadge(eligibleCount) {
    const badge = byId('updatesBadge');
    if (eligibleCount > 0) {
      badge.textContent = String(eligibleCount);
      badge.classList.remove('hidden');
    } else {
      badge.classList.add('hidden');
    }
  }

```

Insert these new functions immediately after it:

```javascript
  function loadClientUpdateCredentials() {
    fetch('/api/v1/client-updates/credentials', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        if (data.username) byId('updatesUsername').value = data.username;
      })
      .catch(() => {});
  }

  function saveClientUpdateCredentials() {
    const username = byId('updatesUsername').value.trim();
    const password = byId('updatesPassword').value;
    const messageElement = byId('updatesCredentialsMessage');

    byId('updatesSaveCredentialsButton').disabled = true;
    fetch('/api/v1/client-updates/credentials', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(() => {
        byId('updatesPassword').value = '';
        messageElement.classList.remove('hidden', 'error');
        messageElement.textContent = 'Saved.';
      })
      .catch(error => {
        messageElement.classList.remove('hidden');
        messageElement.classList.add('error');
        messageElement.textContent = `Failed to save: ${error.message}`;
      })
      .finally(() => {
        byId('updatesSaveCredentialsButton').disabled = false;
      });
  }

  function updateUpdatesSelectionState() {
    const checkboxes = Array.from(document.querySelectorAll('.updates-row-checkbox'));
    const anyChecked = checkboxes.some(checkbox => checkbox.checked);
    byId('updatesPushButton').disabled = !anyChecked;
  }

  function startClientUpdateJob() {
    const targets = Array.from(document.querySelectorAll('.updates-row-checkbox:checked'))
      .map(checkbox => checkbox.dataset.computerName);
    if (targets.length === 0) return;

    const username = byId('updatesUsername').value.trim();
    const password = byId('updatesPassword').value;
    // #installServerUrl is populated once, unconditionally, on page load
    // (see the byId('installServerUrl').value = ... line near the bottom
    // of this file) - it always holds a real value by the time any tab is
    // used, so reusing it here needs no extra loading/fallback logic.
    const serverUrl = byId('installServerUrl').value.trim();

    byId('updatesPushButton').disabled = true;
    byId('updatesStatus').classList.add('empty');
    byId('updatesStatus').textContent = 'Starting update job...';

    fetch('/api/v1/client-install', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets: targets.join('\n'), serverUrl, username, password, force: false, addToTrustedHosts: false, retentionDays: 30 })
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.updateJobId = data.jobId;
        if (state.updatePollTimer) window.clearInterval(state.updatePollTimer);
        pollInstallJob(state.updateJobId, 'updatesStatus', () => loadClientUpdates());
        state.updatePollTimer = window.setInterval(() => pollInstallJob(state.updateJobId, 'updatesStatus', () => loadClientUpdates()), 3000);
      })
      .catch(error => {
        byId('updatesStatus').textContent = `Failed to start update job: ${error.message}`;
      })
      .finally(() => {
        byId('updatesPushButton').disabled = false;
      });
  }

```

Note: `serverUrl` reuses whatever the `Client actions` tab's own Server URL field already holds (`#installServerUrl`) as a convenience default, the same way the rest of the dashboard treats that field as the fleet's known reporting endpoint - it is required by the underlying `/api/v1/client-install` endpoint for an `install` action (see Task 2's Global Constraints note: there is no separate `action` field, this is exactly what `Client actions` already sends for "Install client"). If it's blank, the request fails with the same "serverUrl is required" error the `Client actions` tab already surfaces - no new error handling needed.

- [ ] **Step 5: Wire the new elements' event listeners and initial load**

Find this exact block:

```javascript
  byId('updatesTab').addEventListener('click', () => setView('updates'));
```

Replace it with:

```javascript
  byId('updatesTab').addEventListener('click', () => setView('updates'));
  byId('updatesSaveCredentialsButton').addEventListener('click', saveClientUpdateCredentials);
  byId('updatesPushButton').addEventListener('click', startClientUpdateJob);
  byId('updatesSelectAll').addEventListener('change', () => {
    const checked = byId('updatesSelectAll').checked;
    document.querySelectorAll('.updates-row-checkbox').forEach(checkbox => { checkbox.checked = checked; });
    updateUpdatesSelectionState();
  });
  document.addEventListener('change', event => {
    if (event.target.classList.contains('updates-row-checkbox')) {
      updateUpdatesSelectionState();
    }
  });
```

Leave the `if (view === 'updates') loadClientUpdates();` line inside `setView` (added in Task 4's Step 4) as-is - `setView` is not where credentials need loading, since it only fires on a tab click, and Task 5's Step 1 form is already visible by then regardless.

Task 4's Step 4 added `if (state.view === 'updates') loadClientUpdates();` in two places with different indentation (same non-identical-duplicate situation as earlier in this task) - both need `loadClientUpdateCredentials()` added alongside. First occurrence, 4-space indent (inside the hash-change listener, part of the 6-line block Task 4 created there):

```javascript
    if (state.view === 'updates') loadClientUpdates();
```

Replace it with:

```javascript
    if (state.view === 'updates') { loadClientUpdates(); loadClientUpdateCredentials(); }
```

Second occurrence, 2-space indent (near the bottom of the file, part of the 6-line block Task 4 created there for the initial page load):

```javascript
  if (state.view === 'updates') loadClientUpdates();
```

Replace it with:

```javascript
  if (state.view === 'updates') { loadClientUpdates(); loadClientUpdateCredentials(); }
```

- [ ] **Step 6: Build and syntax-check**

```powershell
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester -Path .\tests\ScriptSyntax.Tests.ps1 -Output Detailed
```

Expected: PASS.

- [ ] **Step 7: Live-verify the full flow**

Using the same synthetic-data pattern as Task 4 Step 7, start the server in console mode on a scratch port and use Playwright to:
1. Navigate to `#client-updates`, confirm the credentials block renders with both fields empty and the Save button present.
2. Type a username/password, click Save, confirm the success message appears and the password field clears (matching the AD/admin-password save UX elsewhere in this dashboard).
3. Reload the page, confirm the username field is pre-filled from `GET /api/v1/client-updates/credentials` but the password field is still empty (never echoed back).
4. Check the eligible row's checkbox, confirm "Update selected" becomes enabled; confirm the OS-blocked row's checkbox cannot be checked at all.
5. Confirm `Select all eligible` only checks the eligible row, not the disabled one.

Do NOT click "Update selected" during this verification - that would start a real WinRM job against a fake target name and hang/fail against nothing, which is an unnecessary side effect for a UI check. Confirming the button's enabled/disabled state and the request payload it would send (inspect via `mcp__playwright__browser_network_requests` after a dry click if truly needed, or just trust the code review of `startClientUpdateJob`'s payload construction) is sufficient.

Stop the server process and delete the scratch data/package directories afterward.

- [ ] **Step 8: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js server/dashboard/styles.css
git commit -m "Add Client updates credentials form and push action"
```

---

### Task 6: Documentation and version bump

**Files:**
- Modify: `README.md`
- Modify: `README_RU.md`
- Modify: `docs/threat-model.md`
- Modify: `CHANGELOG.md`
- Modify: `src/server/WindowsInventoryLiteServer.cs` (version constant)
- Modify: `src/client/WindowsInventoryLiteClient.cs` (version constant)

- [ ] **Step 1: Add a README.md section**

Find this exact block:

```markdown
## Dashboard Usage
```

Insert this new section immediately before it:

```markdown
## Client Auto-Update

The dashboard `Client updates` tab (under Installation) shows which reporting clients are running a version other than the client package currently on the server, and lets an administrator push an update to them over WinRM with one click - reusing the same install pipeline as `Client actions`.

WinRM is unreliable against Windows 7, 8, and 8.1 targets in some environments. Outdated clients on those OS versions are still listed (so nothing is silently hidden), but their row is disabled and cannot be selected for a push - update them via GPO or locally instead.

By default, an update push uses the server service's own identity, the same WinRM prerequisite `Client actions` already documents. If that identity cannot reach update targets, an optional dedicated WinRM account can be saved on the `Client updates` page itself (`Client update username` / `Client update password`) - the password is encrypted at rest the same way as `WebPassword`/`AdPassword`/`Token`. There is no `Install-Server.ps1` flag for these credentials; they are dashboard-only.

```

- [ ] **Step 2: Add a matching README_RU.md section**

Find this exact block:

```markdown
## Работа с web-интерфейсом
```

Insert this new section immediately before it:

```markdown
## Автообновление клиентов

Вкладка `Client updates` в web-интерфейсе (раздел Installation) показывает, какие отчитывающиеся клиенты работают на версии, отличной от текущего клиентского пакета на сервере, и позволяет обновить их по WinRM одной кнопкой — используя тот же механизм установки, что и `Client actions`.

WinRM в некоторых средах ненадёжен на Windows 7, 8 и 8.1. Устаревшие клиенты на этих версиях ОС всё равно показываются в списке (ничего не скрывается молча), но их строка недоступна для выбора — такие машины нужно обновлять через GPO или локально.

По умолчанию обновление использует identity самой серверной службы — тот же WinRM-прасint, что уже требуется для `Client actions`. Если этой identity недостаточно для доступа к целям, на странице `Client updates` можно сохранить отдельную учётную запись WinRM (`Client update username` / `Client update password`) — пароль шифруется так же, как `WebPassword`/`AdPassword`/`Token`. Параметра в `Install-Server.ps1` для этих учётных данных нет — они настраиваются только через web-интерфейс.

```

- [ ] **Step 3: Update docs/threat-model.md**

Find this exact block:

```markdown
- Cached Active Directory computer descriptions (adDescription field on each report), and AD credentials when explicit AD credentials (rather than the service identity) are configured.
```

Replace it with:

```markdown
- Cached Active Directory computer descriptions (adDescription field on each report), and AD credentials when explicit AD credentials (rather than the service identity) are configured.
- Client Auto-Update credentials (`ClientUpdateUsername`/`ClientUpdatePassword`), when a dedicated WinRM account is configured on the `Client updates` page instead of relying on the service identity.
```

Find this exact block:

```markdown
- POST body to `POST /api/v1/server/admin-password` (newUsername, currentPassword, newPassword) that sets up or rotates the dashboard's Basic Auth username and password. `currentPassword` is required only when Basic Auth is already configured.
```

Replace it with:

```markdown
- POST body to `POST /api/v1/server/admin-password` (newUsername, currentPassword, newPassword) that sets up or rotates the dashboard's Basic Auth username and password. `currentPassword` is required only when Basic Auth is already configured.
- POST body to `POST /api/v1/client-updates/credentials` (username, password) that saves the optional WinRM credential fallback used by Client Auto-Update pushes. No current-password check (unlike admin-password) - any authenticated dashboard user can already trigger a WinRM push via `Client actions` with arbitrary typed credentials, so this endpoint grants no capability the dashboard didn't already have.
```

Find this exact block:

```markdown
- Prefer the service account identity over explicit AD credentials when the service already runs under a domain account (which WinRM client actions already require) - it needs no additional secret in server-config.json.
```

Replace it with:

```markdown
- Prefer the service account identity over explicit AD credentials when the service already runs under a domain account (which WinRM client actions already require) - it needs no additional secret in server-config.json.
- The same identity-first preference applies to Client Auto-Update: only configure `ClientUpdateUsername`/`ClientUpdatePassword` on the `Client updates` page if the service identity genuinely cannot reach update targets.
```

- [ ] **Step 4: Add a CHANGELOG.md entry**

Find this exact block:

```markdown
## [Unreleased]

## [0.15.1] - 2026-07-17
```

Replace it with:

```markdown
## [Unreleased]

## [0.16.0] - 2026-07-17

### Added

- Dashboard `Client updates` tab (Installation section): shows which reporting clients are running a version other than the current client package, with a WinRM push to update selected clients. Windows 7/8/8.1 targets are listed but not selectable, since WinRM is unreliable against them. An optional dedicated WinRM credential can be saved as a fallback to the service's own identity, encrypted at rest the same way as other stored secrets.

## [0.15.1] - 2026-07-17
```

- [ ] **Step 5: Bump the version constants**

Find this exact line in `src/server/WindowsInventoryLiteServer.cs`:

```csharp
        internal const string ProductVersion = "0.15.1";
```

Replace it with:

```csharp
        internal const string ProductVersion = "0.16.0";
```

Find this exact line in `src/client/WindowsInventoryLiteClient.cs`:

```csharp
        internal const string ProductVersion = "0.15.1";
```

Replace it with:

```csharp
        internal const string ProductVersion = "0.16.0";
```

- [ ] **Step 6: Full combined verification**

```powershell
.\src\Build-Server.ps1
.\build\WindowsInventoryLiteServer.exe --self-test
.\build\WindowsInventoryLiteServer.exe --version
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester -Path .\tests -Output Detailed
```

Expected: 37/37 self-tests `PASS`; `--version` prints `0.16.0`; Pester suite green (18/18 plus whatever this plan's Task 5 syntax checks added - confirm the exact total by reading the Pester summary line, don't assume a specific number here since it depends on what earlier tasks' live-verification steps already confirmed).

Then repeat Task 5 Step 7's full Playwright flow one more time end-to-end against a build carrying the final version number, to confirm nothing regressed between tasks - this is the plan's only combined, cross-task live check; every earlier task's own live-verification step only covered that task in isolation.

- [ ] **Step 7: Commit**

```bash
git add README.md README_RU.md docs/threat-model.md CHANGELOG.md src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs
git commit -m "Document Client Auto-Update, bump version to 0.16.0"
```

---

## Self-Review Notes

**Spec coverage:** every section of the spec has a task - Detection (Tasks 1-2), Credential Storage (Task 3), UI (Tasks 4-5), Testing (folded into each task's own steps plus Task 6's combined pass), Version (Task 6). The spec's Non-Goals are all respected: no new WinRM job type, no client protocol change, no `Client package`/`net35VersionMismatch` changes, no Install-Server.ps1 flags for the new credentials.

**Placeholder scan:** no TBD/TODO; every code step contains complete, exact code; test steps show real synthetic fixtures and exact expected output, not "verify it works."

**Type/name consistency:** `IsWinRmEligibleOs`/`IsClientVersionCurrent` (Task 1) are the exact names `SendClientUpdates` (Task 2) calls. `ClientUpdateUsername`/`ClientUpdatePassword` (Task 3's `ServerOptions` fields) are the exact names Task 5's push action relies on via `options.ClientUpdateUsername`/`ClientUpdatePassword` being read inside the existing `RunClientInstallTarget` call path (unchanged - it already accepts `username`/`password` from the request body, which the dashboard now populates from the saved credentials same as it already does for typed-in `Client actions` credentials). `updatesTab`/`updatesView`/`updatesBody`/`updatesBadge`/`updatesUsername`/`updatesPassword`/`updatesPushButton`/`updatesStatus` (Task 4/5's DOM ids) are used consistently across both tasks' `index.html` and `app.js` changes.
