# Client Update Schedule Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an administrator schedule `Client updates` pushes (one-time at a specific date/time, or recurring every N hours) instead of always clicking "Update selected" by hand, targeting whichever clients are outdated at the moment the schedule fires.

**Architecture:** A single schedule configuration persisted in `server-config.json`, mirroring the existing AD sync `AdSyncMode`/`AdSyncIntervalHours` pattern. An in-process `System.Threading.Timer` inside the Windows Service polls every 60 seconds; when the schedule is due, the server computes the current outdated-client list (the same logic `GET /api/v1/client-updates` already uses) and starts a push job through the existing install-job pipeline (`RunClientActionJob`) - the same mechanism a manual "Update selected" click uses, just with a server-built target list and no user present for credentials.

**Tech Stack:** C# (.NET Framework 3.5/4.0, hand-rolled server, no NuGet), vanilla JS dashboard, no build step - unchanged from the rest of the project.

## Global Constraints

- Single schedule per server: `off` / `once` (specific UTC date-time) / `interval` (every N hours, 1-8760, same range as the AD sync interval field). Selecting one mode replaces whichever was active, same as the AD sync `Sync mode` dropdown - never two active at once.
- Schedule config persists across service restarts in `server-config.json`. None of the new fields are secrets - no DPAPI encryption needed for them.
- A scheduled run always targets the full outdated-client list computed fresh at trigger time (`LoadClientReports()` + `IsClientVersionCurrent()`) - never a frozen snapshot from when the schedule was configured.
- A scheduled run always uses `force = false`, `addToTrustedHosts = false` - matching the existing hardcoded values `startClientUpdateJob` already sends for manual Client-updates pushes.
- A scheduled run has no user to type credentials, so it always resolves through the existing `ResolveUpdateCredentials(ref username, ref password, useSavedCredentials: true, options.ClientUpdateUsername, options.ClientUpdatePassword)` path - saved account, falling through to the service's own identity if nothing is saved.
- Enabling a schedule without a saved WinRM account is allowed, not blocked - the dashboard shows a warning, never a hard error.
- `interval` mode's "last run" timestamp only advances on a schedule-triggered run, never on a manual push - a manual push shortly before a scheduled tick must not delay or skip that scheduled run.
- A missed `once` schedule (service was stopped through the scheduled moment) is silently reset to `off` on the next `Start()` - it never fires late and never notifies anyone.
- After a `once` schedule fires, the mode resets to `off` automatically.
- A scheduled run's resulting install job is a completely normal entry in the existing install-job history - no separate schedule-run history view, no email/external notification.
- Manual "Update selected" on the Client updates page is completely unaffected by whether a schedule is configured.
- No Windows Task Scheduler integration, no CLI flags on `Install-Server.ps1` for this feature (dashboard-configured only, matching how `ClientUpdateUsername`/`ClientUpdatePassword` are dashboard-only per their own existing comment in `WindowsInventoryLiteServer.cs`).

---

### Task 1: Schedule data model, config persistence, and the pure due-check function

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs`

**Interfaces:**
- Produces: `ServerOptions.ClientUpdateScheduleMode` (`string`, default `"off"`), `ServerOptions.ClientUpdateScheduleOnceAtUtc` (`string`, ISO `yyyy-MM-ddTHH:mm:ssZ` or `""`), `ServerOptions.ClientUpdateScheduleIntervalHours` (`int`, default `24`), `ServerOptions.ClientUpdateScheduleLastRunUtc` (`string`, ISO or `""`).
- Produces: `internal static bool InventoryServer.ShouldRunClientUpdateSchedule(DateTime nowUtc, string mode, DateTime? onceAtUtc, DateTime? lastRunUtc, int intervalHours)` - pure function, no I/O, used by Task 2's timer tick.

This task only adds the data model, config load, and the pure decision function with self-tests. No timer, no HTTP endpoint yet - those come in Tasks 2 and 3 and both depend on the fields and function this task produces.

- [ ] **Step 1: Add the four new fields to `ServerOptions`**

Open `src/server/WindowsInventoryLiteServer.cs` and find the `ClientUpdateUsername`/`ClientUpdatePassword` field declarations (currently around line 130):

```csharp
        // Optional, off by default - dashboard-configured only (no
        // Install-Server.ps1 CLI flag by design, see the plan's Global
        // Constraints). Used as a fallback WinRM credential for Client
        // Auto-Update pushes when the service's own identity can't reach a
        // target; see docs/superpowers/specs/2026-07-17-client-auto-update-design.md.
        public string ClientUpdateUsername;
        public string ClientUpdatePassword;
```

Add the four schedule fields immediately after `ClientUpdatePassword`:

```csharp
        public string ClientUpdateUsername;
        public string ClientUpdatePassword;
        // Off by default - dashboard-configured only, same reasoning as
        // ClientUpdateUsername/Password above. See
        // docs/superpowers/specs/2026-07-18-client-update-schedule-design.md.
        // Mode is "off", "once", or "interval" - never more than one active,
        // same as AdSyncMode above. OnceAtUtc/LastRunUtc are ISO
        // "yyyy-MM-ddTHH:mm:ssZ" strings (or "") rather than DateTime,
        // matching how every other timestamp in this class is stored.
        public string ClientUpdateScheduleMode;
        public string ClientUpdateScheduleOnceAtUtc;
        public int ClientUpdateScheduleIntervalHours;
        public string ClientUpdateScheduleLastRunUtc;
```

- [ ] **Step 2: Set defaults in `ServerOptions.Parse`**

Find the defaults block (currently around line 147, right after `options.AdSyncIntervalHours = 24;`):

```csharp
            options.AdSyncMode = "on-report";
            options.AdSyncIntervalHours = 24;
            options.AdUseServiceIdentity = true;
```

Add the schedule defaults right after `options.AdUseServiceIdentity = true;`:

```csharp
            options.AdSyncMode = "on-report";
            options.AdSyncIntervalHours = 24;
            options.AdUseServiceIdentity = true;
            options.ClientUpdateScheduleMode = "off";
            options.ClientUpdateScheduleOnceAtUtc = "";
            options.ClientUpdateScheduleIntervalHours = 24;
            options.ClientUpdateScheduleLastRunUtc = "";
```

- [ ] **Step 3: Load the fields from `server-config.json`**

Find where `ClientUpdateUsername`/`ClientUpdatePassword` are loaded from config (currently around line 422):

```csharp
                if (String.IsNullOrEmpty(options.ClientUpdateUsername))
                {
                    options.ClientUpdateUsername = GetConfigString(config, "ClientUpdateUsername");
                }
                if (String.IsNullOrEmpty(options.ClientUpdatePassword))
                {
                    options.ClientUpdatePassword = SecretProtector.Unprotect(GetConfigString(config, "ClientUpdatePassword"));
                }
```

Add the schedule field loads right after, following the exact same "only load from config if still at its CLI/hardcoded default" pattern used for `AdSyncMode`/`AdSyncIntervalHours` above it in the same function:

```csharp
                if (String.IsNullOrEmpty(options.ClientUpdateUsername))
                {
                    options.ClientUpdateUsername = GetConfigString(config, "ClientUpdateUsername");
                }
                if (String.IsNullOrEmpty(options.ClientUpdatePassword))
                {
                    options.ClientUpdatePassword = SecretProtector.Unprotect(GetConfigString(config, "ClientUpdatePassword"));
                }
                if (options.ClientUpdateScheduleMode == "off")
                {
                    string scheduleModeText = GetConfigString(config, "ClientUpdateScheduleMode");
                    if (scheduleModeText == "off" || scheduleModeText == "once" || scheduleModeText == "interval")
                    {
                        options.ClientUpdateScheduleMode = scheduleModeText;
                    }
                }
                if (String.IsNullOrEmpty(options.ClientUpdateScheduleOnceAtUtc))
                {
                    options.ClientUpdateScheduleOnceAtUtc = GetConfigString(config, "ClientUpdateScheduleOnceAtUtc") ?? "";
                }
                if (options.ClientUpdateScheduleIntervalHours == 24)
                {
                    string scheduleIntervalText = GetConfigString(config, "ClientUpdateScheduleIntervalHours");
                    int scheduleIntervalFromConfig;
                    if (!String.IsNullOrEmpty(scheduleIntervalText) && Int32.TryParse(scheduleIntervalText, out scheduleIntervalFromConfig) && scheduleIntervalFromConfig > 0 && scheduleIntervalFromConfig <= 8760)
                    {
                        options.ClientUpdateScheduleIntervalHours = scheduleIntervalFromConfig;
                    }
                }
                if (String.IsNullOrEmpty(options.ClientUpdateScheduleLastRunUtc))
                {
                    options.ClientUpdateScheduleLastRunUtc = GetConfigString(config, "ClientUpdateScheduleLastRunUtc") ?? "";
                }
```

- [ ] **Step 4: Write the failing self-tests for `ShouldRunClientUpdateSchedule`**

Find the `ShouldSyncAd` self-tests near the end of the file (currently around line 4312-4340: `TestShouldSyncAdNoPreviousTimestamp`, `TestShouldSyncAdStaleTimestamp`, `TestShouldSyncAdFreshTimestamp`). Add six new test methods right after `TestShouldSyncAdFreshTimestamp`'s closing brace:

```csharp
        private static string TestShouldRunClientUpdateScheduleOffMode()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            if (InventoryServer.ShouldRunClientUpdateSchedule(now, "off", now.AddHours(-1), now.AddHours(-1), 24))
            {
                return "expected mode 'off' to never be due, regardless of onceAtUtc/lastRunUtc values";
            }
            return null;
        }

        private static string TestShouldRunClientUpdateScheduleOnceNotYetDue()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            DateTime future = now.AddHours(1);
            if (InventoryServer.ShouldRunClientUpdateSchedule(now, "once", future, null, 24))
            {
                return "expected mode 'once' with a future onceAtUtc to not be due yet";
            }
            return null;
        }

        private static string TestShouldRunClientUpdateScheduleOnceDue()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            DateTime past = now.AddMinutes(-1);
            if (!InventoryServer.ShouldRunClientUpdateSchedule(now, "once", past, null, 24))
            {
                return "expected mode 'once' with a past onceAtUtc to be due";
            }
            return null;
        }

        private static string TestShouldRunClientUpdateScheduleOnceMissingTarget()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            if (InventoryServer.ShouldRunClientUpdateSchedule(now, "once", null, null, 24))
            {
                return "expected mode 'once' with no onceAtUtc value to never be due";
            }
            return null;
        }

        private static string TestShouldRunClientUpdateScheduleIntervalNoPreviousRun()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            if (!InventoryServer.ShouldRunClientUpdateSchedule(now, "interval", null, null, 24))
            {
                return "expected mode 'interval' with no previous run to be due immediately";
            }
            return null;
        }

        private static string TestShouldRunClientUpdateScheduleIntervalDueAndNotDue()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            DateTime stale = now.AddHours(-25);
            DateTime fresh = now.AddHours(-1);
            if (!InventoryServer.ShouldRunClientUpdateSchedule(now, "interval", null, stale, 24))
            {
                return "expected mode 'interval' to be due when lastRunUtc is older than intervalHours";
            }
            if (InventoryServer.ShouldRunClientUpdateSchedule(now, "interval", null, fresh, 24))
            {
                return "expected mode 'interval' to not be due when lastRunUtc is within intervalHours";
            }
            return null;
        }
```

- [ ] **Step 5: Register the six new self-tests**

Find the `ShouldSyncAd` self-test registrations in `RunSelfTests` (currently around line 3966-3968):

```csharp
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns true with no previous timestamp", TestShouldSyncAdNoPreviousTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns true for a stale timestamp", TestShouldSyncAdStaleTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns false for a fresh timestamp", TestShouldSyncAdFreshTimestamp);
```

Add the six new registrations right after:

```csharp
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns true with no previous timestamp", TestShouldSyncAdNoPreviousTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns true for a stale timestamp", TestShouldSyncAdStaleTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns false for a fresh timestamp", TestShouldSyncAdFreshTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule is never due in 'off' mode", TestShouldRunClientUpdateScheduleOffMode);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'once' is not due before the target time", TestShouldRunClientUpdateScheduleOnceNotYetDue);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'once' is due after the target time", TestShouldRunClientUpdateScheduleOnceDue);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'once' is never due with no target time set", TestShouldRunClientUpdateScheduleOnceMissingTarget);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'interval' is due immediately with no previous run", TestShouldRunClientUpdateScheduleIntervalNoPreviousRun);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'interval' respects the interval window", TestShouldRunClientUpdateScheduleIntervalDueAndNotDue);
```

- [ ] **Step 6: Build and run the self-test suite to confirm the new tests fail (method doesn't exist yet)**

Run:
```powershell
powershell.exe -NoProfile -Command "& 'src\Build-Server.ps1'"
```
Expected: `csc.exe failed with exit code 1` - `CS0117: 'InventoryServer' does not contain a definition for 'ShouldRunClientUpdateSchedule'` (or similar CS0103), confirming the test methods reference something that doesn't exist yet.

- [ ] **Step 7: Implement `ShouldRunClientUpdateSchedule`**

Find `ShouldSyncAd` (currently around line 1135):

```csharp
        internal static bool ShouldSyncAd(DateTime? lastSyncedUtc, int intervalHours)
```

Add the new method right after `ShouldSyncAd`'s closing brace:

```csharp
        // Pure decision function for the Client Update schedule timer (Task 2
        // calls this on every tick) - no I/O, so it's directly self-testable.
        // "once" fires exactly once when nowUtc reaches onceAtUtc; the caller
        // is responsible for resetting mode back to "off" afterward (this
        // function only answers "is it due right now", it doesn't mutate
        // anything). "interval" fires immediately if there's no previous run
        // recorded, then every intervalHours after the last scheduled run -
        // manual pushes never touch lastRunUtc, only a schedule-triggered run
        // does (see RunClientUpdateScheduleTick in Task 2).
        internal static bool ShouldRunClientUpdateSchedule(DateTime nowUtc, string mode, DateTime? onceAtUtc, DateTime? lastRunUtc, int intervalHours)
        {
            if (mode == "once")
            {
                return onceAtUtc.HasValue && nowUtc >= onceAtUtc.Value;
            }
            if (mode == "interval")
            {
                if (!lastRunUtc.HasValue)
                {
                    return true;
                }
                return nowUtc >= lastRunUtc.Value.AddHours(Math.Max(1, intervalHours));
            }
            return false;
        }
```

- [ ] **Step 8: Build and run the self-test suite to confirm all tests pass**

Run:
```powershell
powershell.exe -NoProfile -Command "& 'src\Build-Server.ps1'"
build\WindowsInventoryLiteServer.exe --self-test
```
Expected: build succeeds, and the self-test output includes six new `PASS ShouldRunClientUpdateSchedule ...` lines with zero `FAIL` lines anywhere in the output.

- [ ] **Step 9: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add Client Update schedule data model and due-check function"
```

---

### Task 2: Timer engine - reconfigure, tick, missed-schedule reset

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs`

**Interfaces:**
- Consumes: `ServerOptions.ClientUpdateScheduleMode/OnceAtUtc/IntervalHours/LastRunUtc` (Task 1), `InventoryServer.ShouldRunClientUpdateSchedule` (Task 1), `LoadClientReports()`, `IsClientVersionCurrent(string, string, string)`, `GetExeVersion(string)`, `ResolveUpdateCredentials(ref string, ref string, bool, string, string)`, `ParseCmdSettings(string)`, `RunClientActionJob(object)`, `SaveInstallJob(InstallJob)`, `SaveServerConfigValues(Dictionary<string,string>)` - all pre-existing in this file.
- Produces: `ReconfigureClientUpdateScheduleTimer()` - called by Task 3 after any schedule config change, and once at startup by this task's `Start()` wiring.

- [ ] **Step 1: Add the timer field and lock object**

Find the AD sync timer fields (currently around line 491-492):

```csharp
        private readonly object adSyncTimerLock = new object();
        private Timer adSyncTimer;
```

Add matching fields right after:

```csharp
        private readonly object adSyncTimerLock = new object();
        private Timer adSyncTimer;
        private readonly object clientUpdateScheduleTimerLock = new object();
        private Timer clientUpdateScheduleTimer;
```

- [ ] **Step 2: Wire startup and shutdown**

Find `Start()`'s call to `ReconfigureAdSyncTimer()` (currently around line 527):

```csharp
            ReconfigureAdSyncTimer();
```

Add the schedule wiring right after - `ResetMissedOnceSchedule()` (Step 5 below) must run before `ReconfigureClientUpdateScheduleTimer()` so a stale `once` schedule is cleared before the timer is armed:

```csharp
            ReconfigureAdSyncTimer();
            ResetMissedOnceSchedule();
            ReconfigureClientUpdateScheduleTimer();
```

Find `Stop()`'s disposal of `adSyncTimer` (currently around line 568-577):

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
```

Add disposal of the new timer right after the `adSyncTimerLock` block:

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
            lock (clientUpdateScheduleTimerLock)
            {
                if (clientUpdateScheduleTimer != null)
                {
                    clientUpdateScheduleTimer.Dispose();
                    clientUpdateScheduleTimer = null;
                }
            }
            StopSlot(httpSlot);
            StopSlot(httpsSlot);
```

- [ ] **Step 3: Implement `ReconfigureClientUpdateScheduleTimer`**

Find `ReconfigureAdSyncTimer`'s closing brace (currently around line 613). Add the new method right after:

```csharp
        // Polls every 60 seconds rather than mirroring ShouldSyncAd's
        // "interval IS the due time" Timer pattern - "once" mode needs to
        // fire close to an arbitrary target time (could be any minute of the
        // day), not just on hour boundaries, so a coarse once-per-interval
        // Timer can't represent it. A 60-second poll costs nothing (the tick
        // handler no-ops immediately when the schedule isn't due) and keeps
        // both "once" and "interval" modes on one simple mechanism instead of
        // two different Timer shapes. Called after every schedule config
        // change (Task 3's ConfigureClientUpdateSchedule) and once at
        // startup, so a mode switch takes effect without a service restart -
        // same pattern as ReconfigureAdSyncTimer above.
        private void ReconfigureClientUpdateScheduleTimer()
        {
            lock (clientUpdateScheduleTimerLock)
            {
                if (clientUpdateScheduleTimer != null)
                {
                    clientUpdateScheduleTimer.Dispose();
                    clientUpdateScheduleTimer = null;
                }
                if (options.ClientUpdateScheduleMode != "off")
                {
                    TimeSpan pollInterval = TimeSpan.FromSeconds(60);
                    clientUpdateScheduleTimer = new Timer(RunClientUpdateScheduleTick, null, TimeSpan.Zero, pollInterval);
                }
            }
        }
```

- [ ] **Step 4: Implement the tick handler and the push-starting helper**

Add these two methods right after `ReconfigureClientUpdateScheduleTimer`:

```csharp
        // One poll tick: checks whether the configured schedule is due and,
        // if so, starts a push against every currently-outdated client - then
        // updates and persists the schedule's own bookkeeping (mode/last-run)
        // so the next tick doesn't fire the same event again.
        private void RunClientUpdateScheduleTick(object state)
        {
            string mode = options.ClientUpdateScheduleMode;
            if (mode == "off")
            {
                return;
            }

            DateTime? onceAtUtc = ParseUtcOrNull(options.ClientUpdateScheduleOnceAtUtc);
            DateTime? lastRunUtc = ParseUtcOrNull(options.ClientUpdateScheduleLastRunUtc);
            if (!ShouldRunClientUpdateSchedule(DateTime.UtcNow, mode, onceAtUtc, lastRunUtc, options.ClientUpdateScheduleIntervalHours))
            {
                return;
            }

            StartScheduledClientUpdatePush();

            Dictionary<string, string> updates = new Dictionary<string, string>();
            if (mode == "once")
            {
                options.ClientUpdateScheduleMode = "off";
                options.ClientUpdateScheduleOnceAtUtc = "";
                updates["ClientUpdateScheduleMode"] = "off";
                updates["ClientUpdateScheduleOnceAtUtc"] = "";
                SaveServerConfigValues(updates);
                ReconfigureClientUpdateScheduleTimer();
            }
            else
            {
                options.ClientUpdateScheduleLastRunUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                updates["ClientUpdateScheduleLastRunUtc"] = options.ClientUpdateScheduleLastRunUtc;
                SaveServerConfigValues(updates);
            }
        }

        private static DateTime? ParseUtcOrNull(string value)
        {
            if (String.IsNullOrEmpty(value))
            {
                return null;
            }
            DateTime parsed;
            if (DateTime.TryParse(value, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out parsed))
            {
                return parsed.ToUniversalTime();
            }
            return null;
        }

        // Builds and starts an install job against every currently-outdated
        // client, exactly as if an admin had checked every row on the Client
        // updates page and clicked "Update selected" - reuses the same
        // outdated-detection logic as SendClientUpdates and the same
        // ResolveUpdateCredentials fallback chain a blank-fields manual push
        // uses. No-ops quietly (no job started) if there's no built client
        // package, no outdated clients, or no known server URL to hand the
        // client - there's no user present to show an error to, and this
        // feature deliberately has no separate notification mechanism (see
        // the design spec's Out of Scope section).
        private void StartScheduledClientUpdatePush()
        {
            string net35Version = null;
            string net40Version = null;
            if (Directory.Exists(options.ClientPackagePath))
            {
                string net35Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net35.exe");
                string net40Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net40.exe");
                net35Version = File.Exists(net35Path) ? GetExeVersion(net35Path) : null;
                net40Version = File.Exists(net40Path) ? GetExeVersion(net40Path) : null;
            }
            if (net35Version == null && net40Version == null)
            {
                return;
            }

            ArrayList targets = new ArrayList();
            foreach (Dictionary<string, object> client in LoadClientReports())
            {
                string clientVersion = GetStringValue(client, "clientVersion");
                if (IsClientVersionCurrent(clientVersion, net35Version, net40Version))
                {
                    continue;
                }
                string computerName = GetStringValue(client, "computerName");
                if (!String.IsNullOrEmpty(computerName))
                {
                    targets.Add(computerName);
                }
            }
            if (targets.Count == 0)
            {
                return;
            }

            // The same URL an already-deployed client is configured to
            // report to - there is no browser/admin present to type one, so
            // this is the one already-known-correct value to reuse (a
            // manual push's own pre-filled Server URL field is derived from
            // the browser's own address, which isn't available here either).
            string cmdPath = Path.Combine(options.ClientPackagePath, "Install-ClientGpo.cmd");
            Dictionary<string, string> cmdSettings = ParseCmdSettings(cmdPath);
            string serverUrl = cmdSettings.ContainsKey("serverUrl") ? cmdSettings["serverUrl"] : null;
            if (String.IsNullOrEmpty(serverUrl))
            {
                return;
            }

            string username = "";
            string password = "";
            ResolveUpdateCredentials(ref username, ref password, true, options.ClientUpdateUsername, options.ClientUpdatePassword);

            InstallJob job = new InstallJob();
            job.Id = Guid.NewGuid().ToString("N");
            job.Action = "install";
            job.Status = "queued";
            job.CreatedAtUtc = DateTime.UtcNow;
            job.Targets = targets;
            job.Results = new ArrayList();
            job.ServerUrl = serverUrl;
            job.Username = username;
            job.Password = password;
            job.Force = false;
            job.AddToTrustedHosts = false;
            job.RetentionDays = options.InstallLogRetentionDays;

            lock (installJobsLock)
            {
                installJobs[job.Id] = job;
                SaveInstallJob(job);
            }
            ThreadPool.QueueUserWorkItem(RunClientActionJob, job);
        }
```

- [ ] **Step 5: Implement the missed-schedule reset**

Add this method right after `StartScheduledClientUpdatePush`:

```csharp
        // Called once at startup, before the timer is armed - if the service
        // was stopped through a "once" schedule's target time, that moment
        // is gone and silently cleared rather than fired late (per the
        // design spec: a missed one-time push is not worth surprising an
        // admin with an unexpected WinRM push right as the service starts).
        private void ResetMissedOnceSchedule()
        {
            if (options.ClientUpdateScheduleMode != "once")
            {
                return;
            }
            DateTime? onceAtUtc = ParseUtcOrNull(options.ClientUpdateScheduleOnceAtUtc);
            if (!onceAtUtc.HasValue || DateTime.UtcNow < onceAtUtc.Value)
            {
                return;
            }

            options.ClientUpdateScheduleMode = "off";
            options.ClientUpdateScheduleOnceAtUtc = "";
            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["ClientUpdateScheduleMode"] = "off";
            updates["ClientUpdateScheduleOnceAtUtc"] = "";
            SaveServerConfigValues(updates);
        }
```

- [ ] **Step 6: Build and run the self-test suite**

Run:
```powershell
powershell.exe -NoProfile -Command "& 'src\Build-Server.ps1'"
build\WindowsInventoryLiteServer.exe --self-test
```
Expected: build succeeds (this task adds no new self-tests of its own - `ShouldRunClientUpdateSchedule` was already tested in Task 1; this step just confirms the new timer/tick code compiles cleanly and doesn't break anything), all existing self-tests still `PASS`, zero `FAIL` lines.

- [ ] **Step 7: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add Client Update schedule timer engine"
```

---

### Task 3: API endpoints

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs`

**Interfaces:**
- Consumes: `ServerOptions.ClientUpdateScheduleMode/OnceAtUtc/IntervalHours/LastRunUtc` (Task 1), `ReconfigureClientUpdateScheduleTimer()` (Task 2), `SaveServerConfigValues(Dictionary<string,string>)`, `CreateJsonSerializer()`, `SendJson(Stream, string)`, `SendText(Stream, string, string, int)` - all pre-existing.
- Produces: `GET /api/v1/client-updates/schedule` and `POST /api/v1/client-updates/schedule` routes, consumed by Task 4's dashboard JS.

- [ ] **Step 1: Add the two routes**

Find the existing Client updates credentials routes (currently around line 939-946):

```csharp
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-updates/credentials")
                    {
                        SendClientUpdateCredentialsStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/client-updates/credentials")
                    {
                        ConfigureClientUpdateCredentials(stream, request);
                    }
```

Add the schedule routes right after:

```csharp
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-updates/credentials")
                    {
                        SendClientUpdateCredentialsStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/client-updates/credentials")
                    {
                        ConfigureClientUpdateCredentials(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-updates/schedule")
                    {
                        SendClientUpdateScheduleStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/client-updates/schedule")
                    {
                        ConfigureClientUpdateSchedule(stream, request);
                    }
```

- [ ] **Step 2: Implement `SendClientUpdateScheduleStatus` and `ConfigureClientUpdateSchedule`**

Find `ConfigureClientUpdateCredentials`'s closing brace (the method added in the 0.16.x credential work - search for `private void ConfigureClientUpdateCredentials`). Add both new methods right after it:

```csharp
        private void SendClientUpdateScheduleStatus(Stream stream)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["mode"] = options.ClientUpdateScheduleMode;
            result["onceAtUtc"] = String.IsNullOrEmpty(options.ClientUpdateScheduleOnceAtUtc) ? null : options.ClientUpdateScheduleOnceAtUtc;
            result["intervalHours"] = options.ClientUpdateScheduleIntervalHours;
            result["lastRunUtc"] = String.IsNullOrEmpty(options.ClientUpdateScheduleLastRunUtc) ? null : options.ClientUpdateScheduleLastRunUtc;
            result["hasSavedCredentials"] = !String.IsNullOrEmpty(options.ClientUpdateUsername) && !String.IsNullOrEmpty(options.ClientUpdatePassword);
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void ConfigureClientUpdateSchedule(Stream stream, RequestContext request)
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

            string mode = payload.ContainsKey("mode") ? Convert.ToString(payload["mode"]) : "off";
            if (mode != "off" && mode != "once" && mode != "interval")
            {
                SendText(stream, "{\"error\":\"mode must be 'off', 'once', or 'interval'\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string onceAtUtc = "";
            if (mode == "once")
            {
                string onceAtRaw = payload.ContainsKey("onceAtUtc") ? Convert.ToString(payload["onceAtUtc"]) : "";
                DateTime parsedOnceAt;
                if (String.IsNullOrEmpty(onceAtRaw) || !DateTime.TryParse(onceAtRaw, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out parsedOnceAt))
                {
                    SendText(stream, "{\"error\":\"onceAtUtc is required and must be a valid date/time for mode 'once'\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                onceAtUtc = parsedOnceAt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
            }

            int intervalHours = options.ClientUpdateScheduleIntervalHours;
            if (mode == "interval")
            {
                if (!payload.ContainsKey("intervalHours") || !Int32.TryParse(Convert.ToString(payload["intervalHours"]), out intervalHours) || intervalHours < 1 || intervalHours > 8760)
                {
                    SendText(stream, "{\"error\":\"intervalHours must be between 1 and 8760 for mode 'interval'\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }

            options.ClientUpdateScheduleMode = mode;
            options.ClientUpdateScheduleOnceAtUtc = onceAtUtc;
            options.ClientUpdateScheduleIntervalHours = intervalHours;
            if (mode != "interval")
            {
                // Switching away from interval mode clears its "last run"
                // clock - re-enabling interval mode later starts counting
                // fresh instead of firing immediately off a stale timestamp
                // from a previous, unrelated stretch of interval mode.
                options.ClientUpdateScheduleLastRunUtc = "";
            }

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["ClientUpdateScheduleMode"] = options.ClientUpdateScheduleMode;
            updates["ClientUpdateScheduleOnceAtUtc"] = options.ClientUpdateScheduleOnceAtUtc ?? "";
            updates["ClientUpdateScheduleIntervalHours"] = options.ClientUpdateScheduleIntervalHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
            updates["ClientUpdateScheduleLastRunUtc"] = options.ClientUpdateScheduleLastRunUtc ?? "";
            SaveServerConfigValues(updates);

            ReconfigureClientUpdateScheduleTimer();

            SendClientUpdateScheduleStatus(stream);
        }
```

- [ ] **Step 3: Build and run the self-test suite**

Run:
```powershell
powershell.exe -NoProfile -Command "& 'src\Build-Server.ps1'"
build\WindowsInventoryLiteServer.exe --self-test
```
Expected: build succeeds, all self-tests `PASS`, zero `FAIL`.

- [ ] **Step 4: Manually verify both endpoints against a local console-mode instance**

Run the server in console mode on a scratch port with an isolated data directory (never a real service install):

```powershell
$dataPath = Join-Path $env:TEMP 'wil-schedule-verify'
New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
$exe = 'build\WindowsInventoryLiteServer.exe'
$content = 'server\dashboard'
$proc = Start-Process -FilePath $exe -ArgumentList @('--console','--port','18090','--data',$dataPath,'--content',$content) -PassThru -WindowStyle Hidden -RedirectStandardOutput "$dataPath\out.log" -RedirectStandardError "$dataPath\err.log"
Start-Sleep -Seconds 2
Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/client-updates/schedule' -Method Get | ConvertTo-Json
Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/client-updates/schedule' -Method Post -ContentType 'application/json' -Body '{"mode":"interval","intervalHours":6}' | ConvertTo-Json
Invoke-RestMethod -Uri 'http://localhost:18090/api/v1/client-updates/schedule' -Method Get | ConvertTo-Json
Stop-Process -Id $proc.Id -Force
```

Expected: first GET returns `mode: "off"`, `intervalHours: 24`. POST returns `mode: "interval"`, `intervalHours: 6`. Second GET confirms the change persisted in memory (`mode: "interval"`, `intervalHours: 6`).

- [ ] **Step 5: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Add Client Update schedule API endpoints"
```

---

### Task 4: Dashboard UI

**Files:**
- Modify: `server/dashboard/index.html`
- Modify: `server/dashboard/app.js`
- Modify: `server/dashboard/styles.css`

**Interfaces:**
- Consumes: `GET`/`POST /api/v1/client-updates/schedule` (Task 3).

- [ ] **Step 1: Add the Schedule settings block to `index.html`**

Find the WinRM credentials block on the Client updates page (search for `<h2 class="settings-block-title">WinRM credentials</h2>` inside `<section id="updatesView"`). Its containing `<div class="settings-block">` currently ends right before `<p id="updatesPackageStatus"`. Add a new `settings-block` for the schedule right after the WinRM credentials block's closing `</div>` and before `<p id="updatesPackageStatus" ...>`:

```html
          <div class="settings-block">
            <h2 class="settings-block-title">Schedule</h2>
            <p class="cert-hint">Automatically pushes to whichever clients are outdated when the schedule fires - the same targets "Update selected" would reach if every outdated row were checked. Uses the saved WinRM account above, or the server's own service identity if nothing is saved.</p>
            <p id="updatesScheduleCredentialWarning" class="cert-hint hidden">No saved WinRM account above - scheduled pushes will use the server's own service identity.</p>
            <div class="pkg-grid client-update-schedule-panel">
              <label class="pkg-token-field">
                Schedule
                <select id="updatesScheduleMode">
                  <option value="off">Off</option>
                  <option value="once">Run once</option>
                  <option value="interval">Every N hours</option>
                </select>
              </label>
              <label id="updatesScheduleOnceField" class="pkg-token-field hidden">
                Run at
                <input id="updatesScheduleOnceAt" type="datetime-local">
              </label>
              <label id="updatesScheduleIntervalField" class="pkg-token-field hidden">
                Every (hours)
                <input id="updatesScheduleIntervalHours" type="number" min="1" max="8760" value="24">
              </label>
              <button id="updatesScheduleSaveButton" class="primary-button" type="button">Save</button>
            </div>
            <div id="updatesScheduleMessage" class="pkg-message hidden"></div>
          </div>
```

- [ ] **Step 2: Add the panel width CSS rule to `styles.css`**

Find `.client-update-grid` (added for the WinRM credentials block):

```css
.client-update-grid {
  grid-template-columns: minmax(200px, 1fr) minmax(200px, 1fr) auto;
}
```

Add the schedule panel rule right after, matching `.ad-sync-panel`/`.ad-identity-panel`'s existing narrow-fixed-width treatment:

```css
.client-update-grid {
  grid-template-columns: minmax(200px, 1fr) minmax(200px, 1fr) auto;
}

/* Same narrow single-column treatment as .ad-sync-panel/.ad-identity-panel -
   the schedule's mode dropdown and its one conditional field read as a
   small deliberate group, not stretched across the page. */
.client-update-schedule-panel {
  grid-template-columns: 1fr;
  max-width: 420px;
}
```

- [ ] **Step 3: Add the JS - field visibility, load, save**

Find `updateAdSyncIntervalField` in `app.js` (added for the AD sync panel work):

```javascript
  function updateAdSyncIntervalField() {
    const isTimerMode = byId('generalAdSyncMode').value === 'timer';
    byId('generalAdSyncIntervalField').classList.toggle('hidden', !isTimerMode);
  }
```

Add the new functions right after `updateAdSyncIntervalField`'s closing brace:

```javascript
  function updateScheduleFieldVisibility() {
    const mode = byId('updatesScheduleMode').value;
    byId('updatesScheduleOnceField').classList.toggle('hidden', mode !== 'once');
    byId('updatesScheduleIntervalField').classList.toggle('hidden', mode !== 'interval');
  }

  // datetime-local inputs work in the browser's local time with no
  // timezone in the string - Date's own constructor/toISOString correctly
  // round-trip that local-time string against the server's UTC storage, so
  // no manual timezone math is needed here.
  function toDatetimeLocalValue(date) {
    const pad = n => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function loadClientUpdateSchedule() {
    fetch('/api/v1/client-updates/schedule', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('updatesScheduleMode').value = data.mode || 'off';
        byId('updatesScheduleOnceAt').value = data.onceAtUtc ? toDatetimeLocalValue(new Date(data.onceAtUtc)) : '';
        byId('updatesScheduleIntervalHours').value = data.intervalHours || 24;
        byId('updatesScheduleCredentialWarning').classList.toggle('hidden', !!data.hasSavedCredentials);
        updateScheduleFieldVisibility();
      })
      .catch(() => {});
  }

  function saveClientUpdateSchedule() {
    const mode = byId('updatesScheduleMode').value;
    const messageElement = byId('updatesScheduleMessage');
    const body = { mode };

    if (mode === 'once') {
      const localValue = byId('updatesScheduleOnceAt').value;
      if (!localValue) {
        messageElement.classList.remove('hidden');
        messageElement.classList.add('error');
        messageElement.textContent = 'Pick a date and time first.';
        return;
      }
      body.onceAtUtc = new Date(localValue).toISOString();
    } else if (mode === 'interval') {
      body.intervalHours = Number.parseInt(byId('updatesScheduleIntervalHours').value, 10) || 24;
    }

    byId('updatesScheduleSaveButton').disabled = true;
    fetch('/api/v1/client-updates/schedule', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(() => {
        messageElement.classList.remove('hidden', 'error');
        messageElement.textContent = 'Saved.';
        loadClientUpdateSchedule();
      })
      .catch(error => {
        messageElement.classList.remove('hidden');
        messageElement.classList.add('error');
        messageElement.textContent = `Failed to save: ${error.message}`;
      })
      .finally(() => {
        byId('updatesScheduleSaveButton').disabled = false;
      });
  }
```

- [ ] **Step 4: Wire the event listeners and the view-load calls**

Find the AD sync mode listener:

```javascript
  byId('generalAdSyncMode').addEventListener('change', updateAdSyncIntervalField);
```

Add the schedule listeners right after:

```javascript
  byId('generalAdSyncMode').addEventListener('change', updateAdSyncIntervalField);
  byId('updatesScheduleMode').addEventListener('change', updateScheduleFieldVisibility);
  byId('updatesScheduleSaveButton').addEventListener('click', saveClientUpdateSchedule);
```

Find the two existing `if (state.view === 'updates') { loadClientUpdates(); loadClientUpdateCredentials(); }` call sites (there are two - one in the initial page-load handler, one in the tab-click handler). Update both to also load the schedule:

```javascript
    if (state.view === 'updates') { loadClientUpdates(); loadClientUpdateCredentials(); loadClientUpdateSchedule(); }
```

- [ ] **Step 5: Manually verify with Playwright against a local console-mode instance**

Start a local instance the same way as Task 3 Step 4 (scratch port, isolated data dir, `--content server\dashboard`, never a real service install). Using Playwright:

1. Navigate to the dashboard, click into "Client updates".
2. Take a snapshot - confirm the "Schedule" block renders below "WinRM credentials", with the mode dropdown defaulting to "Off" and both conditional fields hidden.
3. Change the mode dropdown to "Run once" - confirm the "Run at" field appears and the "Every (hours)" field stays hidden.
4. Change the mode dropdown to "Every N hours" - confirm the "Every (hours)" field appears and "Run at" stays hidden.
5. Pick a date/time, save, reload the page, navigate back to Client updates - confirm the saved mode and value round-trip correctly.
6. Take a screenshot in both light and dark theme, confirming the panel matches the visual style of the AD sync/identity panels (420px width, same field spacing).

Stop the local instance when done.

- [ ] **Step 6: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js server/dashboard/styles.css
git commit -m "Add Client Update schedule dashboard UI"
```

---

### Task 5: Security review

This task is a dedicated review pass over Tasks 1-4's full diff before this ships - requested explicitly because this feature adds a new *unattended* trigger path for WinRM pushes (no user present, no browser-typed credentials, driven entirely by a server-side timer and persisted config) and touches stored-credential handling. This is exactly the kind of change `finishing-a-development-branch`'s standard "verify tests" step does not catch, since nothing here is functionally broken - the risk is in what the code is *allowed* to do unattended.

- [ ] **Step 1: Generate the review package**

From the repository root:
```bash
git log --oneline <task-1-base-commit>..HEAD
git diff <task-1-base-commit>..HEAD --stat
git diff <task-1-base-commit>..HEAD -U10 > /tmp/client-update-schedule-review.diff
```
(Substitute `<task-1-base-commit>` with the commit hash immediately before Task 1's first commit.)

- [ ] **Step 2: Review against this checklist**

Read the full diff and confirm each of the following, citing the specific line(s) that satisfy or violate it:

1. **Credential exposure**: `ClientUpdateUsername`/`ClientUpdatePassword` are never logged, never included in any HTTP response body (check `SendClientUpdateScheduleStatus` specifically - it must never echo the password), and are only read via the existing `ResolveUpdateCredentials` path.
2. **Unattended privilege scope**: `StartScheduledClientUpdatePush` only ever targets clients from `LoadClientReports()`/`IsClientVersionCurrent` (the server's own existing outdated-detection logic) - confirm there's no way a scheduled run's target list can be influenced by unauthenticated or externally-supplied input (it takes no parameters from any HTTP request).
3. **Config injection**: `ConfigureClientUpdateSchedule`'s `mode`/`onceAtUtc`/`intervalHours` payload fields are all validated (mode is an enum-checked string, onceAtUtc goes through `DateTime.TryParse` with `RoundtripKind`, intervalHours is bounds-checked `1-8760`) before being written to `ServerOptions` or `server-config.json` - confirm no field reaches `SaveServerConfigValues` unvalidated.
4. **Authorization**: confirm `/api/v1/client-updates/schedule` (both GET and POST) is reached through the same authentication/authorization gate as the neighboring `/api/v1/client-updates/credentials` routes (check the routing dispatcher's surrounding structure - this project gates the whole management API behind Basic Auth once configured, and loopback-only before that; confirm the new routes weren't accidentally placed outside that gate).
5. **Timer/thread safety**: `clientUpdateScheduleTimer` and `clientUpdateScheduleTimerLock` are used consistently (every read/write of the `Timer` reference itself is inside the lock; the tick handler itself does not need the lock since it only reads `options` fields and calls thread-safe methods like `SaveServerConfigValues`/`RunClientActionJob`, mirroring how `RunAdSyncSweep` is structured).
6. **Fail-safe defaults**: confirm a fresh install (no `server-config.json` entries for the new keys) resolves to `mode = "off"` (Task 1 Step 2's defaults) - the feature must be inert until explicitly configured, never auto-enabled.
7. **Denial-of-service via schedule**: confirm the minimum `intervalHours` is `1` (not `0` or negative) so a misconfigured interval can't create a tight loop of WinRM pushes: check the bounds validation in `ConfigureClientUpdateSchedule` (`intervalHours < 1`) and the `Math.Max(1, intervalHours)` guard in `ShouldRunClientUpdateSchedule`.

- [ ] **Step 3: Fix any findings, re-verify**

For each issue found in Step 2, fix it directly in the relevant task's file, then re-run:
```powershell
powershell.exe -NoProfile -Command "& 'src\Build-Server.ps1'"
build\WindowsInventoryLiteServer.exe --self-test
```
Expected: build succeeds, all self-tests `PASS`, zero `FAIL`. Repeat Step 2's checklist against the fixed diff.

- [ ] **Step 4: Commit any fixes**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Fix security review findings for Client Update schedule"
```
(Skip this step entirely if Step 2 found nothing to fix.)

---

### Task 6: Docs and version

**Files:**
- Modify: `README.md`
- Modify: `README_RU.md`
- Modify: `CHANGELOG.md`
- Modify: `src/server/WindowsInventoryLiteServer.cs` (version bump only)

- [ ] **Step 1: Document the feature in `README.md`**

Find the existing `Client updates` description (search for "The dashboard `Client updates` tab"). Add a new sentence right after the existing paragraph describing the manual push button:

```markdown
A "Schedule" section on the same page lets an administrator configure an automatic push instead of clicking "Update selected" by hand - either once at a specific date and time, or repeating every N hours. A scheduled push always targets whichever clients are outdated at the moment it fires, using the saved WinRM account (or the server's own service identity if none is saved) - there is no user present to type credentials for an unattended run.
```

- [ ] **Step 2: Document the feature in `README_RU.md`**

Find the matching Russian section for `Client updates` (the paragraph describing the manual push button) and add this paragraph right after it:

```markdown
В том же разделе появился блок «Schedule» — можно настроить автоматический пуш вместо ручного нажатия «Update selected»: либо разово в указанную дату и время, либо периодически, каждые N часов. Запланированный пуш всегда нацелен на клиентов, устаревших на момент срабатывания, и использует сохранённый WinRM-аккаунт (либо identity самой службы, если аккаунт не сохранён) — вводить креды вручную для автоматического запуска некому.
```

- [ ] **Step 3: Update `CHANGELOG.md`**

Add a new `### Added` entry under `## [Unreleased]` (or a new dated version header, matching whatever the current top-of-file convention is at execution time):

```markdown
### Added

- `Client updates` has a Schedule section: push automatically once at a chosen date/time, or every N hours, targeting whichever clients are outdated when the schedule fires. Configured entirely from the dashboard; persists across service restarts; uses the same saved-account/service-identity credential fallback as a manual push with blank fields.
```

- [ ] **Step 4: Bump the version**

Find `internal const string ProductVersion` in `src/server/WindowsInventoryLiteServer.cs` and bump it (MINOR bump - this is a new feature, per this project's versioning convention). Update the `CHANGELOG.md` entry's version header to match.

- [ ] **Step 5: Final build, self-test, and Pester run**

```powershell
powershell.exe -NoProfile -Command "& 'src\Build-Server.ps1'"
build\WindowsInventoryLiteServer.exe --self-test
powershell.exe -NoProfile -Command "Invoke-Pester -Path 'tests' -CI"
```
Expected: build succeeds, self-test suite fully `PASS` with zero `FAIL`, Pester run fully green (uses `powershell.exe`/Windows PowerShell 5.1, never `pwsh` - see this project's own established note about the `System.Web.Extensions` GAC-loading false failure under PowerShell 7).

- [ ] **Step 6: Commit**

```bash
git add README.md README_RU.md CHANGELOG.md src/server/WindowsInventoryLiteServer.cs
git commit -m "Document Client Update schedule; bump version"
```
