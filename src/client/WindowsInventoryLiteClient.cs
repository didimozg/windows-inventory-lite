using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace WindowsInventoryLite
{
    internal sealed class Program
    {
        private const string ServiceName = "WindowsInventoryLiteClient";
        internal const string ProductVersion = "0.18.0";

        private static int Main(string[] args)
        {
            ClientOptions options = ClientOptions.Parse(args);

            if (options.ShowVersion)
            {
                Console.WriteLine(ProductVersion);
                return 0;
            }

            if (options.RunSelfTest)
            {
                bool selfTestsPassed = InventoryCollector.RunSelfTests(Console.Out);
                return selfTestsPassed ? 0 : 1;
            }

            if (options.RunOnce)
            {
                InventoryCollector collector = new InventoryCollector(options);
                try
                {
                    collector.CollectAndSave();
                    DebugLogger.Log(options, "Server", "Collection cycle completed successfully.");
                }
                catch (Exception ex)
                {
                    // Unhandled otherwise (the console already shows it,
                    // unlike the service's timer callback which must
                    // swallow it) - also written to the debug log when
                    // enabled, for a manual --once diagnostic run whose
                    // console output isn't being watched live or is being
                    // run remotely.
                    DebugLogger.Log(options, "Error", ex.ToString());
                    throw;
                }
                return 0;
            }

            ServiceBase.Run(new InventoryService(options));
            return 0;
        }

        // internal rather than private so InventoryCollector (a separate
        // top-level class's self-tests) can construct SoftwareJobRunner
        // and call its RunOneJob directly - matching GetString's own
        // precedent for sharing logic across that same top-level-class
        // boundary, just in the other direction.
        internal sealed class InventoryService : ServiceBase
        {
            private readonly ClientOptions options;
            private Timer timer;
            private Timer windowsUpdateCheckTimer;
            private Timer thirdPartySoftwareCheckTimer;

            // Shared across both pipelines so the windowsUpdate and
            // thirdPartySoftware SoftwareJobRunner.CheckAndRun() bodies
            // never execute at the same time, even though their timers,
            // schedules, and reentrancy guards (windowsUpdateCheckRunning/
            // thirdPartySoftwareCheckRunning) are otherwise fully
            // independent. Without this, two CheckAndRun() calls could
            // overlap: each loads the shared success-cache file into its
            // own in-memory set and overwrites the whole file on save, so
            // whichever finishes first has its recorded successes silently
            // lost when the other one saves afterward - and two installers
            // (e.g. a Windows-update KB and a third-party MSI) could run
            // at the same time with no coordination, where previously only
            // one job ever ran at a time system-wide. A plain lock is used
            // deliberately even though it can block a Timer callback
            // thread for as long as the other pipeline's install is still
            // running (up to InstallProcessTimeoutMilliseconds = 30
            // minutes): these timers already tolerate arbitrarily-delayed
            // callbacks (see the reentrancy guards), so blocking here is
            // the correct, simple behavior rather than a bug. Uncontended
            // in the common case where only one pipeline is checking at a
            // time.
            private static readonly object softwareJobCheckAndRunLock = new object();

            public InventoryService(ClientOptions options)
            {
                this.options = options;
                ServiceName = Program.ServiceName;
                CanStop = true;
                AutoLog = true;
            }

            protected override void OnStart(string[] args)
            {
                // A throwaway InventoryCollector, used only to reach its
                // LoadLearnedState() - the shared learned-state cache file
                // is InventoryCollector's own concept, not this service's.
                Dictionary<string, object> learnedConfig = new InventoryCollector(options).LoadLearnedState();
                if (learnedConfig != null)
                {
                    if (learnedConfig.ContainsKey("intervalHours"))
                    {
                        int learnedInterval;
                        if (Int32.TryParse(Convert.ToString(learnedConfig["intervalHours"]), out learnedInterval) && learnedInterval >= 1 && learnedInterval <= 24)
                        {
                            options.IntervalHours = learnedInterval;
                        }
                    }
                    if (learnedConfig.ContainsKey("windowsUpdateCheckIntervalHours"))
                    {
                        int learnedWindowsUpdateInterval;
                        if (Int32.TryParse(Convert.ToString(learnedConfig["windowsUpdateCheckIntervalHours"]), out learnedWindowsUpdateInterval) && learnedWindowsUpdateInterval >= 1 && learnedWindowsUpdateInterval <= 24)
                        {
                            options.WindowsUpdateCheckIntervalHours = learnedWindowsUpdateInterval;
                        }
                    }
                    if (learnedConfig.ContainsKey("thirdPartySoftwareCheckIntervalHours"))
                    {
                        int learnedThirdPartySoftwareInterval;
                        if (Int32.TryParse(Convert.ToString(learnedConfig["thirdPartySoftwareCheckIntervalHours"]), out learnedThirdPartySoftwareInterval) && learnedThirdPartySoftwareInterval >= 1 && learnedThirdPartySoftwareInterval <= 24)
                        {
                            options.ThirdPartySoftwareCheckIntervalHours = learnedThirdPartySoftwareInterval;
                        }
                    }
                }
                timer = new Timer(Collect, null, TimeSpan.Zero, TimeSpan.FromHours(options.IntervalHours));
                // The thirdPartySoftware timer's initial due-time is offset
                // by an extra minute purely so the two independent pipelines'
                // first-ever ticks on service start don't race each other
                // needlessly.
                windowsUpdateCheckTimer = new Timer(CheckWindowsUpdateJobs, null, TimeSpan.FromMinutes(2), TimeSpan.FromHours(options.WindowsUpdateCheckIntervalHours));
                thirdPartySoftwareCheckTimer = new Timer(CheckThirdPartySoftwareJobs, null, TimeSpan.FromMinutes(3), TimeSpan.FromHours(options.ThirdPartySoftwareCheckIntervalHours));
            }

            protected override void OnStop()
            {
                if (timer != null)
                {
                    timer.Dispose();
                    timer = null;
                }
                if (windowsUpdateCheckTimer != null)
                {
                    windowsUpdateCheckTimer.Dispose();
                    windowsUpdateCheckTimer = null;
                }
                if (thirdPartySoftwareCheckTimer != null)
                {
                    thirdPartySoftwareCheckTimer.Dispose();
                    thirdPartySoftwareCheckTimer = null;
                }
                // Disposing the timers above only stops FUTURE ticks - an
                // already-running Collect()/CheckWindowsUpdateJobs()/
                // CheckThirdPartySoftwareJobs() callback
                // (the latter can legitimately be mid-install, up to
                // InstallProcessTimeoutMilliseconds = 30 minutes) keeps
                // running in the background after this method returns. If
                // the SCM's own stop timeout then kills the process, an
                // in-progress installer can be terminated mid-install. This
                // wait covers the common case (a normal collection cycle
                // finishing up) within a budget safely under the SCM's
                // default ~30-second stop timeout; it does not - and, short
                // of periodically calling RequestAdditionalTime to hold the
                // SCM off for the full up-to-30-minute installer window,
                // cannot - guarantee survival of a stop that lands in the
                // middle of an actual install.
                DateTime waitUntil = DateTime.UtcNow.AddSeconds(25);
                while ((Interlocked.CompareExchange(ref collectRunning, 0, 0) != 0 ||
                        Interlocked.CompareExchange(ref windowsUpdateCheckRunning, 0, 0) != 0 ||
                        Interlocked.CompareExchange(ref thirdPartySoftwareCheckRunning, 0, 0) != 0) &&
                       DateTime.UtcNow < waitUntil)
                {
                    Thread.Sleep(250);
                }
            }

            private int collectRunning;

            private void Collect(object state)
            {
                // Same reentrancy guard as windowsUpdateCheckRunning/thirdPartySoftwareCheckRunning below - a
                // System.Threading.Timer fires on schedule regardless of
                // whether the previous callback finished, and a slow/hung
                // WMI provider (no timeout is set on these queries) could
                // otherwise let two Collect() cycles overlap and race on
                // the same output file.
                if (Interlocked.CompareExchange(ref collectRunning, 1, 0) != 0)
                {
                    DebugLogger.Log(options, "Server", "Collection cycle skipped - a previous cycle is still running.");
                    return;
                }
                try
                {
                    // Snapshotted so a config change learned during
                    // CollectAndSave() (InventoryCollector.ApplyConfigFromServer
                    // mutates options in place, but cannot reach these Timer
                    // fields itself - see that method's own comment) can be
                    // detected here and rescheduled immediately, instead of
                    // waiting for this timer to next re-arm on its own.
                    int previousIntervalHours = options.IntervalHours;
                    int previousWindowsUpdateCheckIntervalHours = options.WindowsUpdateCheckIntervalHours;
                    int previousThirdPartySoftwareCheckIntervalHours = options.ThirdPartySoftwareCheckIntervalHours;
                    InventoryCollector collector = new InventoryCollector(options);
                    ForceImmediateCheckFlags forceImmediateCheckFlags = collector.CollectAndSave();
                    if (options.IntervalHours != previousIntervalHours && timer != null)
                    {
                        timer.Change(TimeSpan.FromHours(options.IntervalHours), TimeSpan.FromHours(options.IntervalHours));
                    }
                    if (options.WindowsUpdateCheckIntervalHours != previousWindowsUpdateCheckIntervalHours && windowsUpdateCheckTimer != null)
                    {
                        windowsUpdateCheckTimer.Change(TimeSpan.FromHours(options.WindowsUpdateCheckIntervalHours), TimeSpan.FromHours(options.WindowsUpdateCheckIntervalHours));
                    }
                    if (options.ThirdPartySoftwareCheckIntervalHours != previousThirdPartySoftwareCheckIntervalHours && thirdPartySoftwareCheckTimer != null)
                    {
                        thirdPartySoftwareCheckTimer.Change(TimeSpan.FromHours(options.ThirdPartySoftwareCheckIntervalHours), TimeSpan.FromHours(options.ThirdPartySoftwareCheckIntervalHours));
                    }
                    DebugLogger.Log(options, "Server", "Collection cycle completed successfully.");
                    if (forceImmediateCheckFlags.WindowsUpdate)
                    {
                        DebugLogger.Log(options, "Server", "Server requested an immediate Windows-update check - running it now instead of waiting for the next scheduled interval.");
                        CheckWindowsUpdateJobs(null);
                    }
                    if (forceImmediateCheckFlags.ThirdPartySoftware)
                    {
                        DebugLogger.Log(options, "Server", "Server requested an immediate third-party-software check - running it now instead of waiting for the next scheduled interval.");
                        CheckThirdPartySoftwareJobs(null);
                    }
                }
                catch (Exception ex)
                {
                    // Swallowed so one bad collection cycle (WMI hiccup, network
                    // blip, disk full) doesn't take down the whole service - the
                    // timer just tries again next interval. Logged so a
                    // persistently-failing agent is actually visible somewhere
                    // instead of silently reporting nothing forever. Written to
                    // both sinks independently (see AdLookupService.cs on the
                    // server side for why EventLog and the debug log must never
                    // share a try/catch): the Event Log write depends on this
                    // machine already having (or being able to auto-register)
                    // the "WindowsInventoryLiteClient" source, which the opt-in
                    // debug log does not depend on at all.
                    try
                    {
                        System.Diagnostics.EventLog.WriteEntry(Program.ServiceName, ex.ToString(), System.Diagnostics.EventLogEntryType.Warning);
                    }
                    catch { }
                    DebugLogger.Log(options, "Error", ex.ToString());
                }
                finally
                {
                    Interlocked.Exchange(ref collectRunning, 0);
                }
            }

            private int windowsUpdateCheckRunning;

            private void CheckWindowsUpdateJobs(object state)
            {
                if (Interlocked.CompareExchange(ref windowsUpdateCheckRunning, 1, 0) != 0)
                {
                    DebugLogger.Log(options, "Server", "Windows-update check cycle skipped - a previous cycle is still running.");
                    return;
                }
                try
                {
                    SoftwareJobRunner runner = new SoftwareJobRunner(options, true);
                    lock (softwareJobCheckAndRunLock)
                    {
                        runner.CheckAndRun();
                    }
                    DebugLogger.Log(options, "Server", "Windows-update check cycle completed.");
                }
                catch (Exception ex)
                {
                    try
                    {
                        System.Diagnostics.EventLog.WriteEntry(Program.ServiceName, ex.ToString(), System.Diagnostics.EventLogEntryType.Warning);
                    }
                    catch { }
                    DebugLogger.Log(options, "Error", ex.ToString());
                }
                finally
                {
                    Interlocked.Exchange(ref windowsUpdateCheckRunning, 0);
                }
            }

            private int thirdPartySoftwareCheckRunning;

            private void CheckThirdPartySoftwareJobs(object state)
            {
                if (Interlocked.CompareExchange(ref thirdPartySoftwareCheckRunning, 1, 0) != 0)
                {
                    DebugLogger.Log(options, "Server", "Third-party-software check cycle skipped - a previous cycle is still running.");
                    return;
                }
                try
                {
                    SoftwareJobRunner runner = new SoftwareJobRunner(options, false);
                    lock (softwareJobCheckAndRunLock)
                    {
                        runner.CheckAndRun();
                    }
                    DebugLogger.Log(options, "Server", "Third-party-software check cycle completed.");
                }
                catch (Exception ex)
                {
                    try
                    {
                        System.Diagnostics.EventLog.WriteEntry(Program.ServiceName, ex.ToString(), System.Diagnostics.EventLogEntryType.Warning);
                    }
                    catch { }
                    DebugLogger.Log(options, "Error", ex.ToString());
                }
                finally
                {
                    Interlocked.Exchange(ref thirdPartySoftwareCheckRunning, 0);
                }
            }

            // internal rather than private - see the comment on the
            // enclosing InventoryService class for why.
            internal sealed class SoftwareJobRunner
            {
                private readonly ClientOptions options;
                private readonly bool isWindowsUpdatePipeline;

                public SoftwareJobRunner(ClientOptions options, bool isWindowsUpdatePipeline)
                {
                    this.options = options;
                    this.isWindowsUpdatePipeline = isWindowsUpdatePipeline;
                }

                public void CheckAndRun()
                {
                    string jobsJson = FetchAssignedJobs();
                    if (String.IsNullOrEmpty(jobsJson))
                    {
                        return;
                    }

                    JavaScriptSerializer serializer = new JavaScriptSerializer();
                    Dictionary<string, object> jobsResponse = serializer.Deserialize<Dictionary<string, object>>(jobsJson);

                    // The server advertises its current WSUS cab hash, the
                    // configured max scan age, and whether an admin has
                    // requested an immediate rescan of this machine on this
                    // same poll response regardless of whether any software
                    // job is queued, so this check runs unconditionally here
                    // - before the jobs-empty early return below - rather
                    // than being folded into the job-processing path further
                    // down. WSUS scanning is a Windows-Update-only concept,
                    // so none of this runs for the thirdPartySoftware
                    // instance of this runner.
                    if (isWindowsUpdatePipeline)
                    {
                        string wsusCabHash = jobsResponse == null ? "" : (InventoryCollector.GetString(jobsResponse, "wsusCabHash") ?? "");
                        int wsusScanMaxAgeDays = jobsResponse != null && jobsResponse.ContainsKey("wsusScanMaxAgeDays") ? Convert.ToInt32(jobsResponse["wsusScanMaxAgeDays"]) : 7;
                        bool forceWsusRescan = jobsResponse != null && jobsResponse.ContainsKey("forceWsusRescan") && Convert.ToBoolean(jobsResponse["forceWsusRescan"]);
                        InventoryCollector wsusStateCollector = new InventoryCollector(options);
                        Dictionary<string, object> learnedWsusState = wsusStateCollector.LoadLearnedState();
                        string lastScannedWsusHash = learnedWsusState.ContainsKey("wsusScannedCabHash") ? Convert.ToString(learnedWsusState["wsusScannedCabHash"]) : "";
                        DateTime? lastScanAtUtc = null;
                        if (learnedWsusState.ContainsKey("wsusLastScanAtUtc"))
                        {
                            DateTime parsed;
                            if (DateTime.TryParse(Convert.ToString(learnedWsusState["wsusLastScanAtUtc"]), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out parsed))
                            {
                                lastScanAtUtc = parsed;
                            }
                        }
                        bool wsusScannedAndReported = InventoryCollector.MaybeRunWsusScanCore(
                            wsusCabHash,
                            lastScannedWsusHash,
                            lastScanAtUtc,
                            wsusScanMaxAgeDays,
                            forceWsusRescan,
                            WsusScanner.IsWuauservRunning,
                            WsusScanner.ScanForMissingUpdates,
                            (hash, destPath) => InventoryCollector.DownloadAndVerifyWsusCab(options.ServerUrl, options.Token, hash, destPath, InventoryCollector.HttpGetBytes),
                            (hash, available, missing) => InventoryCollector.PostWsusScanResults(options.ServerUrl, options.Token, Environment.MachineName, hash, available, missing, InventoryCollector.PostJson));
                        if (wsusScannedAndReported)
                        {
                            learnedWsusState["wsusScannedCabHash"] = wsusCabHash;
                            learnedWsusState["wsusLastScanAtUtc"] = DateTime.UtcNow.ToString("o");
                            wsusStateCollector.SaveLearnedState(learnedWsusState);
                        }
                    }

                    ArrayList jobs = jobsResponse != null && jobsResponse.ContainsKey("jobs") ? jobsResponse["jobs"] as ArrayList : null;
                    if (jobs == null || jobs.Count == 0)
                    {
                        return;
                    }

                    HashSet<string> alreadySucceeded = LoadSoftwareJobSuccessCache();

                    // Most cycles have no unfinished job - skip the result
                    // loop entirely rather than calling RunOneJob (and its
                    // ReportJobStart telemetry ping) for every already-
                    // succeeded entry only to have it filtered out below.
                    bool hasUnfinishedJob = false;
                    foreach (object item in jobs)
                    {
                        Dictionary<string, object> job = item as Dictionary<string, object>;
                        if (job == null)
                        {
                            continue;
                        }
                        if (!alreadySucceeded.Contains(BuildJobCacheKey(job)))
                        {
                            hasUnfinishedJob = true;
                            break;
                        }
                    }
                    if (!hasUnfinishedJob)
                    {
                        return;
                    }

                    ArrayList results = new ArrayList();
                    foreach (object item in jobs)
                    {
                        Dictionary<string, object> job = item as Dictionary<string, object>;
                        if (job == null)
                        {
                            continue;
                        }

                        string cacheKey = BuildJobCacheKey(job);
                        if (alreadySucceeded.Contains(cacheKey))
                        {
                            continue;
                        }

                        Dictionary<string, object> resultEntry = RunOneJob(job, InventoryCollector.DownloadToFileAndComputeSha256);
                        results.Add(resultEntry);

                        if (Convert.ToBoolean(resultEntry["success"]))
                        {
                            alreadySucceeded.Add(cacheKey);
                        }
                    }

                    if (results.Count > 0)
                    {
                        SaveSoftwareJobSuccessCache(alreadySucceeded);
                        PostResults(results);
                    }
                }

                // The success cache is keyed on the catalog entry's id AND
                // its server-side updatedAt, not the id alone. Editing an
                // entry (PUT /api/v1/windows-updates/<id> and the
                // third-party equivalent) mutates relativePath/arguments in
                // place and keeps the id, so an id-only key would make a
                // machine that already succeeded on the OLD version skip the
                // corrected one forever, with no error anywhere. The server
                // bumps updatedAt on every edit, so a composite key retries
                // exactly the edited entries and nothing else. Only used for
                // this local bookkeeping - the id reported back to the
                // server's attempt history stays the real catalog entry id.
                private static string BuildJobCacheKey(Dictionary<string, object> job)
                {
                    string id = InventoryCollector.GetString(job, "id");
                    string updatedAt = InventoryCollector.GetString(job, "updatedAt");
                    return id + "|" + (updatedAt ?? "");
                }

                private const int InstallProcessTimeoutMilliseconds = 30 * 60 * 1000;

                // Best-effort grace period after requesting a graceful close
                // (CloseMainWindow) and before falling back to a hard Kill().
                // Only matters for the minority of installers that actually
                // have a window - most /quiet-style installs never create
                // one, so CloseMainWindow() returns false immediately and
                // this constant is never waited on. See
                // docs/superpowers/specs/2026-09-30-stuck-install-lock-
                // diagnostics-design.md.
                private const int GracefulShutdownGraceMilliseconds = 15 * 1000;

                // internal rather than private - see the comment on the
                // SoftwareJobRunner class for why.
                //
                // downloadToFileAndComputeSha256(url, token, destPath) matches
                // InventoryCollector.DownloadToFileAndComputeSha256's own
                // signature exactly - production code passes
                // DownloadToFileAndComputeSha256 directly, self-tests inject a
                // fake that writes to destPath and returns the hash of what
                // it wrote, with no network I/O. Streaming straight to a
                // file (instead of returning the whole body as a byte[]) is
                // what lets this handle a multi-hundred-MB .msu/.cab without
                // holding the entire file in memory at once.
                internal Dictionary<string, object> RunOneJob(Dictionary<string, object> job, Func<string, string, string, string> downloadToFileAndComputeSha256)
                {
                    string id = InventoryCollector.GetString(job, "id");
                    string catalogType = InventoryCollector.GetString(job, "catalogType");
                    string relativePath = InventoryCollector.GetString(job, "relativePath");
                    string arguments = InventoryCollector.GetString(job, "arguments");
                    string attemptId = Guid.NewGuid().ToString("N");
                    DateTime localStartUtc = DateTime.UtcNow;
                    InventoryCollector.ReportJobStart(options.ServerUrl, options.Token, Environment.MachineName, catalogType, id, attemptId, InventoryCollector.PostJson);

                    Dictionary<string, object> resultEntry = new Dictionary<string, object>();
                    resultEntry["id"] = id;
                    resultEntry["catalogType"] = catalogType;
                    resultEntry["attemptId"] = attemptId;

                    string localCopyPath = null;
                    try
                    {
                        string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + Path.GetExtension(relativePath));
                        localCopyPath = tempPath;

                        string actualSha256;
                        try
                        {
                            string downloadUrl = InventoryCollector.ToSoftwareDownloadUrl(options.ServerUrl, catalogType, id);
                            actualSha256 = downloadToFileAndComputeSha256(downloadUrl, options.Token, tempPath);
                        }
                        catch (Exception ex)
                        {
                            try { File.Delete(tempPath); } catch { }
                            resultEntry["success"] = false;
                            resultEntry["exitCode"] = -1;
                            resultEntry["errorMessage"] = "failed to download installer: " + ex.Message;
                            return resultEntry;
                        }

                        // The server now computes contentSha256 at a trusted
                        // boundary (catalog entry save / WSUS re-download)
                        // and ships it with every job assignment. An older
                        // catalog entry saved before that change carries no
                        // hash at all - contentSha256 is empty - and the
                        // download proceeds unverified rather than being
                        // rejected outright for content the server itself
                        // never computed a hash for.
                        string expectedSha256 = InventoryCollector.GetString(job, "contentSha256");
                        if (!String.IsNullOrEmpty(expectedSha256))
                        {
                            if (!String.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
                            {
                                try { File.Delete(tempPath); } catch { }
                                resultEntry["success"] = false;
                                resultEntry["exitCode"] = -1;
                                resultEntry["errorMessage"] = "downloaded file content does not match the server's expected hash - refusing to run it";
                                return resultEntry;
                            }
                        }

                        // UseShellExecute=false means CreateProcess loads
                        // FileName as a PE image, so only a real executable can
                        // be launched directly. Every other packaging format
                        // needs its own host process: .msi -> msiexec.exe,
                        // .msu (a cabinet the Windows Update stack installs)
                        // -> wusa.exe, .cab -> dism.exe. Without this dispatch
                        // an .msu/.cab entry - the Windows Updates catalog's
                        // own designed content - fails with "not a valid
                        // application for this OS platform" on every attempt.
                        string extension = Path.GetExtension(relativePath);
                        resultEntry["installerFormat"] = String.IsNullOrEmpty(extension) ? null : extension.TrimStart('.').ToLowerInvariant();

                        // A compromised server could otherwise smuggle one of
                        // this installer's own package-selection switches
                        // (e.g. msiexec's "/i", dism's "/packagepath:") into
                        // the catalog entry's admin-configured arguments
                        // field, redirecting the install at a different file
                        // than the one relativePath already resolved and the
                        // software-repository confinement already validated.
                        string dangerousArgumentReason;
                        if (InventoryCollector.TryFindDangerousInstallerArgument(extension, arguments, out dangerousArgumentReason))
                        {
                            resultEntry["success"] = false;
                            resultEntry["exitCode"] = -1;
                            resultEntry["errorMessage"] = dangerousArgumentReason;
                            return resultEntry;
                        }

                        string installerFileName;
                        string installerArguments;
                        InventoryCollector.ResolveInstallerLaunch(extension, localCopyPath, arguments, out installerFileName, out installerArguments);
                        ProcessStartInfo psi = new ProcessStartInfo();
                        psi.FileName = installerFileName;
                        psi.Arguments = installerArguments;
                        psi.UseShellExecute = false;
                        psi.CreateNoWindow = true;
                        psi.WorkingDirectory = Path.GetTempPath();

                        using (Process process = Process.Start(psi))
                        {
                            bool exited = process.WaitForExit(InstallProcessTimeoutMilliseconds);
                            if (!exited)
                            {
                                // Most /quiet-style installs never create a
                                // window at all, so CloseMainWindow() returns
                                // false immediately here and this falls
                                // straight through to the existing Kill()
                                // behavior below - no behavior change for
                                // the common case. For the minority that DO
                                // have a real window (typically one hung
                                // waiting on input in a session no
                                // interactive user can ever see), this gives
                                // it a chance to exit and release its own
                                // single-instance lock, instead of
                                // guaranteeing that lock gets orphaned by a
                                // hard kill.
                                try
                                {
                                    if (process.CloseMainWindow())
                                    {
                                        exited = process.WaitForExit(GracefulShutdownGraceMilliseconds);
                                        if (exited)
                                        {
                                            DebugLogger.Log(options, "Job", "Installer for job '" + id + "' exited on its own after a graceful close request, avoiding a hard kill.");
                                        }
                                    }
                                }
                                catch { }

                                if (!exited)
                                {
                                    try { process.Kill(); } catch { }
                                    try { process.WaitForExit(5000); } catch { }
                                    resultEntry["success"] = false;
                                    resultEntry["exitCode"] = -1;
                                    resultEntry["errorMessage"] = "installer did not exit within " + (InstallProcessTimeoutMilliseconds / 60000) + " minutes and was terminated";
                                }
                            }

                            if (exited)
                            {
                                int exitCode = process.ExitCode;
                                resultEntry["success"] = exitCode == 0;
                                resultEntry["exitCode"] = exitCode;
                                resultEntry["errorMessage"] = exitCode == 0 ? null : ("installer exited with code " + exitCode);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        resultEntry["success"] = false;
                        resultEntry["exitCode"] = -1;
                        resultEntry["errorMessage"] = ex.Message;
                    }
                    finally
                    {
                        if (localCopyPath != null)
                        {
                            try { File.Delete(localCopyPath); } catch { }
                        }
                    }

                    resultEntry["eventLogEntries"] = TryCollectEventLogEntries(localStartUtc);
                    return resultEntry;
                }

                // Best-effort, real-OS-API diagnostic detail - not
                // unit-testable (a real System.Diagnostics.EventLog read
                // against this machine's actual Application/System logs),
                // the same accepted-limitation class as WsusScanner's WUA
                // COM calls elsewhere in this codebase. Any failure
                // (access denied, log unavailable) returns an empty list -
                // never throws, never blocks the caller's own result
                // reporting. Iterates each log's Entries collection from
                // the END backward (most recent first) rather than from
                // the start, so a large, long-lived Application/System log
                // does not need a full scan just to find a handful of
                // entries near "now".
                private static readonly string[] EventLogSourcesToCheck = new string[] { "MsiInstaller", "Microsoft-Windows-WindowsUpdateClient" };
                private const int MaxEventLogEntriesToCollect = 5;
                private const int MaxEventLogMessageLength = 500;

                private static List<Dictionary<string, object>> TryCollectEventLogEntries(DateTime localStartUtc)
                {
                    List<Dictionary<string, object>> found = new List<Dictionary<string, object>>();
                    DateTime windowStartUtc = localStartUtc.AddSeconds(-30);
                    DateTime windowEndUtc = DateTime.UtcNow.AddMinutes(2);

                    string[] logNames = new string[] { "Application", "System" };
                    foreach (string logName in logNames)
                    {
                        if (found.Count >= MaxEventLogEntriesToCollect)
                        {
                            break;
                        }
                        try
                        {
                            using (EventLog log = new EventLog(logName))
                            {
                                EventLogEntryCollection entries = log.Entries;
                                for (int i = entries.Count - 1; i >= 0 && found.Count < MaxEventLogEntriesToCollect; i--)
                                {
                                    EventLogEntry entry = entries[i];
                                    DateTime timeGeneratedUtc = entry.TimeGenerated.ToUniversalTime();
                                    if (timeGeneratedUtc < windowStartUtc)
                                    {
                                        // Entries are chronologically ordered -
                                        // once we're past the window's start,
                                        // nothing earlier in this log matters.
                                        break;
                                    }
                                    if (timeGeneratedUtc > windowEndUtc)
                                    {
                                        continue;
                                    }
                                    bool sourceMatches = false;
                                    foreach (string source in EventLogSourcesToCheck)
                                    {
                                        if (String.Equals(entry.Source, source, StringComparison.OrdinalIgnoreCase))
                                        {
                                            sourceMatches = true;
                                            break;
                                        }
                                    }
                                    if (!sourceMatches)
                                    {
                                        continue;
                                    }
                                    Dictionary<string, object> foundEntry = new Dictionary<string, object>();
                                    foundEntry["source"] = entry.Source;
                                    foundEntry["eventId"] = entry.InstanceId;
                                    foundEntry["timeCreatedUtc"] = timeGeneratedUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
                                    string message = entry.Message ?? "";
                                    foundEntry["message"] = message.Length > MaxEventLogMessageLength ? message.Substring(0, MaxEventLogMessageLength) : message;
                                    found.Add(foundEntry);
                                }
                            }
                        }
                        catch (Exception)
                        {
                            // Access denied, log unavailable, etc. - this
                            // one log's check is skipped, the other log
                            // (and the job's actual result) are unaffected.
                        }
                    }
                    return found;
                }

                private string FetchAssignedJobs()
                {
                    try
                    {
                        string url = isWindowsUpdatePipeline ? InventoryCollector.ToWindowsUpdateJobsUrl(options.ServerUrl) : InventoryCollector.ToThirdPartySoftwareJobsUrl(options.ServerUrl);
                        return InventoryCollector.HttpGet(url, options.Token);
                    }
                    catch
                    {
                        return null;
                    }
                }

                private void PostResults(ArrayList results)
                {
                    try
                    {
                        JavaScriptSerializer serializer = new JavaScriptSerializer();
                        Dictionary<string, object> body = new Dictionary<string, object>();
                        body["computerName"] = Environment.MachineName;
                        body["results"] = results;
                        InventoryCollector.PostJson(InventoryCollector.ToSoftwareJobResultsUrl(options.ServerUrl), serializer.Serialize(body), options.Token);
                    }
                    catch
                    {
                        // A failed results POST just means the next cycle's
                        // history is missing this batch - the success cache
                        // was already updated locally, so nothing gets
                        // silently re-run because of this specific failure.
                    }
                }

                private string GetSoftwareJobSuccessCachePath()
                {
                    string baseDir = options.OutputPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                        ? Path.GetDirectoryName(options.OutputPath)
                        : options.OutputPath;
                    return Path.Combine(baseDir, "software-job-success-cache.json");
                }

                private HashSet<string> LoadSoftwareJobSuccessCache()
                {
                    HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    string path = GetSoftwareJobSuccessCachePath();
                    if (!File.Exists(path))
                    {
                        return result;
                    }

                    try
                    {
                        JavaScriptSerializer serializer = new JavaScriptSerializer();
                        string json = File.ReadAllText(path, Encoding.UTF8);
                        ArrayList raw = serializer.Deserialize<ArrayList>(json);
                        if (raw != null)
                        {
                            foreach (object item in raw)
                            {
                                result.Add(Convert.ToString(item));
                            }
                        }
                    }
                    catch
                    {
                        return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    }
                    return result;
                }

                private void SaveSoftwareJobSuccessCache(HashSet<string> succeededIds)
                {
                    try
                    {
                        JavaScriptSerializer serializer = new JavaScriptSerializer();
                        ArrayList list = new ArrayList();
                        foreach (string id in succeededIds)
                        {
                            list.Add(id);
                        }
                        string json = serializer.Serialize(list);
                        string path = GetSoftwareJobSuccessCachePath();
                        string directory = Path.GetDirectoryName(path);
                        // Same GetDirectoryName-returns-"" gap as WriteText -
                        // caught by this method's own try/catch either way,
                        // but worth the same guard so the cache actually
                        // gets written under a relative OutputPath instead
                        // of silently failing every cycle.
                        if (!String.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                        {
                            Directory.CreateDirectory(directory);
                        }
                        File.WriteAllText(path, json, new UTF8Encoding(false));
                    }
                    catch
                    {
                        // Best-effort convenience cache - a write failure here
                        // must never fail the job-check cycle that already ran.
                    }
                }
            }
        }
    }

    // Plain-data return shape for ApplyInventoryAckResponse/CollectAndSave -
    // this client still targets .NET 3.5 (dual net35/net40 build), where
    // System.Tuple does not exist, so a small named class stands in for
    // what would otherwise be a two-element tuple.
    internal sealed class ForceImmediateCheckFlags
    {
        internal bool WindowsUpdate;
        internal bool ThirdPartySoftware;
    }

    internal sealed class ClientOptions
    {
        public string ServerSharePath;
        public string ServerUrl;
        public string Token;
        // A separate, narrowly-scoped bootstrap secret for POST
        // /api/v1/client/enroll ONLY - never sent to any other endpoint.
        // Set instead of Token on a GPO-deployed client that has no real
        // ingestion token yet; TryEnrollIfNeeded (InventoryCollector) uses
        // it to obtain a real per-machine Token on first contact, then
        // persists that token the same way a learned token already is
        // (ApplyLearnedIngestionToken), so this value is only ever
        // consulted while Token itself is still empty. See EnrollClient on
        // the server side and docs/threat-model.md for why this exists -
        // embedding the real shared Token in a SYSVOL-readable GPO .cmd is
        // the risk this closes.
        public string EnrollmentToken;
        public string OutputPath;
        public int IntervalHours;
        public int WindowsUpdateCheckIntervalHours;
        public int ThirdPartySoftwareCheckIntervalHours;
        public bool RunOnce;
        public bool SkipSoftware;
        public bool ShowVersion;
        public bool RunSelfTest;
        // Client-side, install-time security posture for self-update - NOT
        // server-pushed. A flag delivered inside the same HTTP response
        // this feature defends against forgery on would let the same
        // attacker simply omit/falsify it, defeating its own purpose. Both
        // default false so an existing self-update-enabled deployment is
        // never silently broken by upgrading to a client build that knows
        // about these flags - an admin opts in deliberately per install.
        //
        // RequireHttpsForSelfUpdate is re-evaluated dynamically on every
        // self-update check (ApplySelfUpdateFromServerCore), not just once
        // against this client's own static ServerUrl: if ServerUrl is http
        // but the server's ack just advertised an active httpsPort (added
        // after this client was deployed, a real and expected rollout
        // order - see BuildWindowsClientUpdateInfo's own comment), the
        // client opportunistically retries the download over https instead.
        // AllowHttpFallbackForSelfUpdate controls what happens when no such
        // https option is available (or the opportunistic attempt itself
        // fails, e.g. an invalid/self-signed cert - this client never
        // overrides .NET's default certificate validation, so that failure
        // is a real TLS rejection, not a formality): false keeps today's
        // strict "require" meaning (refuse rather than ever touch http);
        // true permits falling back to the plain ServerUrl, matching how
        // self-update already behaves with neither flag set, so a
        // certificate-less deployment (a real, common environment this
        // project runs in) keeps working exactly as before.
        public bool RequireHttpsForSelfUpdate;
        public bool AllowHttpFallbackForSelfUpdate;
        public bool RequireSignatureForSelfUpdate;
        // Off by default - a plain-text log file capturing each collection
        // cycle's outcome (success or the full exception on failure). See
        // DebugLogger below. Independent of the Windows Event Log write
        // right next to it, which depends on this machine already having
        // (or being able to auto-register) the "WindowsInventoryLiteClient"
        // event source.
        public bool DebugLogEnabled;
        public string DebugLogPath;

        public static ClientOptions Parse(string[] args)
        {
            ClientOptions options = new ClientOptions();
            options.IntervalHours = 6;
            options.WindowsUpdateCheckIntervalHours = 6;
            options.ThirdPartySoftwareCheckIntervalHours = 6;
            options.OutputPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WindowsInventoryLite");

            for (int i = 0; i < args.Length; i++)
            {
                string key = args[i].ToLowerInvariant();
                if (key == "--once")
                {
                    options.RunOnce = true;
                }
                else if (key == "--version")
                {
                    options.ShowVersion = true;
                }
                else if (key == "--self-test")
                {
                    options.RunSelfTest = true;
                }
                else if (key == "--skip-software")
                {
                    options.SkipSoftware = true;
                }
                else if (key == "--require-https-self-update")
                {
                    options.RequireHttpsForSelfUpdate = true;
                }
                else if (key == "--allow-http-self-update-fallback")
                {
                    options.AllowHttpFallbackForSelfUpdate = true;
                }
                else if (key == "--require-signed-self-update")
                {
                    options.RequireSignatureForSelfUpdate = true;
                }
                else if ((key == "--share" || key == "--server-share") && i + 1 < args.Length)
                {
                    options.ServerSharePath = args[++i];
                }
                else if (key == "--server-url" && i + 1 < args.Length)
                {
                    options.ServerUrl = args[++i];
                }
                else if (key == "--token" && i + 1 < args.Length)
                {
                    options.Token = args[++i];
                }
                else if (key == "--enrollment-token" && i + 1 < args.Length)
                {
                    options.EnrollmentToken = args[++i];
                }
                else if (key == "--output" && i + 1 < args.Length)
                {
                    options.OutputPath = args[++i];
                }
                else if (key == "--interval-hours" && i + 1 < args.Length)
                {
                    int parsed;
                    if (Int32.TryParse(args[++i], out parsed) && parsed >= 1 && parsed <= 24)
                    {
                        options.IntervalHours = parsed;
                    }
                }
                else if (key == "--software-check-interval-hours" && i + 1 < args.Length)
                {
                    // One install-time flag still seeds both independent
                    // pipelines' intervals - Install-Client.ps1 and the
                    // other deployment scripts only expose a single
                    // -SoftwareCheckIntervalHours parameter. The server can
                    // later adjust each pipeline's interval independently
                    // via ApplyConfigFromServer/learned state - both
                    // windowsUpdateCheckIntervalHours and
                    // thirdPartySoftwareCheckIntervalHours have their own
                    // live-push channel.
                    int parsedSoftwareInterval;
                    if (Int32.TryParse(args[++i], out parsedSoftwareInterval) && parsedSoftwareInterval >= 1 && parsedSoftwareInterval <= 24)
                    {
                        options.WindowsUpdateCheckIntervalHours = parsedSoftwareInterval;
                        options.ThirdPartySoftwareCheckIntervalHours = parsedSoftwareInterval;
                    }
                }
                else if (key == "--debug-log-enabled")
                {
                    options.DebugLogEnabled = true;
                }
                else if (key == "--debug-log-path" && i + 1 < args.Length)
                {
                    options.DebugLogPath = args[++i];
                }
            }

            // A service's WIL_INGESTION_TOKEN environment variable (set via the
            // HKLM\SYSTEM\...\Services\<name>\Environment registry value, which
            // the SCM injects at process start) takes priority over --token.
            // This mirrors the Linux client's ResolveIngestionToken (main.go) -
            // both keep the token off the process command line, which is
            // readable by any authenticated local user via `sc qc`/Win32_Service
            // on Windows or /proc/<pid>/cmdline on Linux. --token still works
            // for a standalone/manual run with no service environment.
            string environmentToken = Environment.GetEnvironmentVariable("WIL_INGESTION_TOKEN");
            if (!String.IsNullOrEmpty(environmentToken))
            {
                options.Token = environmentToken;
            }

            // Same off-the-command-line reasoning as WIL_INGESTION_TOKEN
            // above - a GPO-deployed EnrollmentToken is exactly as
            // SYSVOL/`sc qc`-exposed as the real token used to be if it sat
            // on the command line, so it goes through the identical
            // registry-Environment channel.
            string environmentEnrollmentToken = Environment.GetEnvironmentVariable("WIL_ENROLLMENT_TOKEN");
            if (!String.IsNullOrEmpty(environmentEnrollmentToken))
            {
                options.EnrollmentToken = environmentEnrollmentToken;
            }

            return options;
        }
    }

    // Optional, off-by-default plain-text log file - the client-side
    // counterpart to the server's DebugLogger.cs. Exists because the
    // Windows Event Log write next to every call site here depends on this
    // machine already having (or being able to auto-register) the
    // "WindowsInventoryLiteClient" event source, which is not guaranteed
    // and has no visible failure indication when it doesn't hold - a file
    // write has no such dependency. A no-op when disabled.
    internal static class DebugLogger
    {
        private static readonly object writeLock = new object();

        internal static void Log(ClientOptions options, string category, string message)
        {
            if (options == null || !options.DebugLogEnabled)
            {
                return;
            }

            string line = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") + " [" + category + "] " + message;

            try
            {
                lock (writeLock)
                {
                    string path = ResolvePath(options);
                    string directory = Path.GetDirectoryName(path);
                    if (!String.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }
                    File.AppendAllText(path, line + Environment.NewLine, new UTF8Encoding(false));
                }
            }
            catch
            {
                // A logging failure must never break the collection cycle
                // being logged.
            }
        }

        internal static string ResolvePath(ClientOptions options)
        {
            if (!String.IsNullOrEmpty(options.DebugLogPath))
            {
                return options.DebugLogPath;
            }
            // Nested 2-argument Path.Combine calls, not the 3/4-argument
            // overloads - those were added in .NET 4.0 and this client also
            // targets Net35 (mscorlib 2.0), which only has the 2-arg form.
            string baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WindowsInventoryLite");
            string logsDir = Path.Combine(baseDir, "_logs");
            return Path.Combine(logsDir, "debug-client.log");
        }
    }

    internal sealed class InventoryCollector
    {
        private readonly ClientOptions options;

        public InventoryCollector(ClientOptions options)
        {
            this.options = options;
        }

        public ForceImmediateCheckFlags CollectAndSave()
        {
            Dictionary<string, object> inventory = Collect();
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            string json = serializer.Serialize(inventory);
            string fileName = SanitizeFileName(Environment.MachineName) + ".json";
            string localPath = options.OutputPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                ? options.OutputPath
                : Path.Combine(options.OutputPath, fileName);

            WriteText(localPath, json);
            if (options.RunOnce)
            {
                Console.WriteLine("Local inventory file: " + localPath);
            }

            if (!String.IsNullOrEmpty(options.ServerSharePath))
            {
                string serverPath = Path.Combine(options.ServerSharePath, fileName);
                WriteText(serverPath, json);
                if (options.RunOnce)
                {
                    Console.WriteLine("Server share inventory file: " + serverPath);
                }
            }

            ForceImmediateCheckFlags forceImmediateCheckFlags = new ForceImmediateCheckFlags();
            if (!String.IsNullOrEmpty(options.ServerUrl))
            {
                TryEnrollIfNeeded();
                string responseBody;
                try
                {
                    responseBody = PostJson(options.ServerUrl, json, options.Token);
                }
                catch (InvalidOperationException ex)
                {
                    // A per-machine token stops working the moment it is
                    // revoked (Settings > Server > Enrollment Token) or
                    // rotated away by a later enrollment under the same
                    // computerName (EnrollClient on the server - re-enrolling
                    // an already-enrolled name now issues a brand-new token
                    // rather than returning the old one unchanged). Without
                    // this, a revoked/rotated-away client would 401 forever:
                    // TryEnrollIfNeeded only ever attempts enrollment while
                    // options.Token is still empty, and this client never
                    // clears a token just because it stopped working. Clear
                    // it here so the NEXT cycle's TryEnrollIfNeeded call
                    // re-enrolls automatically - this cycle's report still
                    // fails and propagates exactly as before (PostJson's own
                    // "Server returned HTTP 401" exception, unchanged),
                    // report acceptance is not retried inline.
                    if (ShouldClearTokenForReenrollment(options.EnrollmentToken, ex.Message))
                    {
                        options.Token = "";
                        DebugLogger.Log(options, "Server", "Inventory report rejected with 401 - clearing the learned token so the next cycle re-enrolls.");
                    }
                    throw;
                }
                forceImmediateCheckFlags = ApplyInventoryAckResponse(responseBody);
                if (options.RunOnce)
                {
                    Console.WriteLine("Inventory posted: " + options.ServerUrl);
                }
            }

            return forceImmediateCheckFlags;
        }

        private Dictionary<string, object> Collect()
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            Dictionary<string, object> computer = QueryFirst("SELECT Domain, Manufacturer, Model FROM Win32_ComputerSystem");
            Dictionary<string, object> bios = QueryFirst("SELECT SerialNumber FROM Win32_BIOS");

            result["schemaVersion"] = "1.0";
            result["clientVersion"] = Program.ProductVersion;
            result["collectedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            result["computerName"] = Environment.MachineName;
            result["domain"] = GetString(computer, "Domain");
            result["ipAddresses"] = GetIpAddresses();
            result["manufacturer"] = GetString(computer, "Manufacturer");
            result["model"] = GetString(computer, "Model");
            result["serialNumber"] = GetString(bios, "SerialNumber");
            Dictionary<string, object> os = GetOperatingSystem();
            result["os"] = os;
            // Computed once and reused for both fields - GetOfficeVersion's
            // own ClickToRun-fallback used to call GetInstalledSoftware()
            // again internally, unconditionally, so --skip-software never
            // actually skipped software enumeration on a non-ClickToRun
            // Office install (or no Office at all), and every normal cycle
            // walked the same two uninstall-registry hives twice.
            ArrayList installedSoftware = options.SkipSoftware ? new ArrayList() : GetInstalledSoftware();
            result["office"] = GetOfficeVersion(installedSoftware);
            result["activation"] = GetActivation();
            ArrayList licenseKeys = GetLicenseKeys();
            licenseKeys.AddRange(GetWindowsAndOfficeActivationKeys(GetString(os, "caption")));
            result["licenses"] = licenseKeys;
            result["software"] = installedSoftware;

            result["cpu"] = GetCpu();
            ArrayList ramModules = GetRamModules();
            result["ramModules"] = ramModules;
            result["ramTotalMb"] = SumRamMb(ramModules);
            ArrayList disks = GetDisks();
            result["disks"] = disks;
            result["hasUsbStorage"] = HasUsbDisk(disks);

            return result;
        }

        private Dictionary<string, object> GetCpu()
        {
            Dictionary<string, object> proc = QueryFirst("SELECT Name, NumberOfCores, MaxClockSpeed FROM Win32_Processor");
            Dictionary<string, object> result = new Dictionary<string, object>();
            string name = GetString(proc, "Name");
            result["name"] = name != null ? name.Trim() : null;
            result["cores"] = proc.ContainsKey("NumberOfCores") && proc["NumberOfCores"] != null
                ? (object)Convert.ToInt32(proc["NumberOfCores"])
                : null;
            result["clockMhz"] = proc.ContainsKey("MaxClockSpeed") && proc["MaxClockSpeed"] != null
                ? (object)Convert.ToInt32(proc["MaxClockSpeed"])
                : null;
            return result;
        }

        private ArrayList GetRamModules()
        {
            ArrayList modules = QueryList("SELECT Capacity, Manufacturer, Speed, DeviceLocator FROM Win32_PhysicalMemory");
            ArrayList result = new ArrayList();
            foreach (object obj in modules)
            {
                Dictionary<string, object> mod = obj as Dictionary<string, object>;
                if (mod == null) continue;

                Dictionary<string, object> item = new Dictionary<string, object>();
                long capacityBytes = mod.ContainsKey("Capacity") && mod["Capacity"] != null
                    ? Convert.ToInt64(mod["Capacity"])
                    : 0L;
                item["capacityMb"] = (int)(capacityBytes / 1048576L);
                string manufacturer = GetString(mod, "Manufacturer");
                item["manufacturer"] = !String.IsNullOrEmpty(manufacturer) ? manufacturer.Trim() : null;
                item["speedMhz"] = mod.ContainsKey("Speed") && mod["Speed"] != null
                    ? (object)Convert.ToInt32(mod["Speed"])
                    : null;
                item["slot"] = GetString(mod, "DeviceLocator");
                result.Add(item);
            }
            return result;
        }

        private static int SumRamMb(ArrayList modules)
        {
            int total = 0;
            foreach (object obj in modules)
            {
                Dictionary<string, object> mod = obj as Dictionary<string, object>;
                if (mod != null && mod.ContainsKey("capacityMb") && mod["capacityMb"] != null)
                {
                    total += Convert.ToInt32(mod["capacityMb"]);
                }
            }
            return total;
        }

        private ArrayList GetDisks()
        {
            // Try MSFT_PhysicalDisk (Win8+) for authoritative SSD/HDD classification.
            // MediaType: 3 = HDD, 4 = SSD. DeviceId matches the disk number in Win32_DiskDrive.DeviceID.
            Dictionary<string, int> msftMediaTypes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            try
            {
                ManagementScope scope = new ManagementScope(@"root\Microsoft\Windows\Storage");
                ObjectQuery msftQuery = new ObjectQuery("SELECT DeviceId, MediaType FROM MSFT_PhysicalDisk");
                EnumerationOptions enumOptions = new EnumerationOptions();
                enumOptions.Timeout = TimeSpan.FromSeconds(60);
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, msftQuery, enumOptions))
                {
                    foreach (ManagementObject item in searcher.Get())
                    {
                        using (item)
                        {
                            string deviceId = item["DeviceId"] != null ? Convert.ToString(item["DeviceId"]) : null;
                            int mediaType = item["MediaType"] != null ? Convert.ToInt32(item["MediaType"]) : 0;
                            if (!String.IsNullOrEmpty(deviceId))
                            {
                                msftMediaTypes[deviceId] = mediaType;
                            }
                        }
                    }
                }
            }
            catch { }

            ArrayList drives = QueryList("SELECT DeviceID, Model, Size, InterfaceType FROM Win32_DiskDrive");
            ArrayList result = new ArrayList();

            foreach (object obj in drives)
            {
                Dictionary<string, object> drive = obj as Dictionary<string, object>;
                if (drive == null) continue;

                Dictionary<string, object> item = new Dictionary<string, object>();
                string model = GetString(drive, "Model");
                item["model"] = !String.IsNullOrEmpty(model) ? model.Trim() : null;

                long sizeBytes = drive.ContainsKey("Size") && drive["Size"] != null
                    ? Convert.ToInt64(drive["Size"])
                    : 0L;
                item["sizeGb"] = (int)(sizeBytes / 1073741824L);

                string interfaceType = GetString(drive, "InterfaceType");
                bool isUsb = String.Equals(interfaceType, "USB", StringComparison.OrdinalIgnoreCase);
                item["usb"] = isUsb;

                string diskType;
                if (isUsb)
                {
                    diskType = "USB";
                }
                else
                {
                    // DeviceID format: \\.\PHYSICALDRIVE0 — extract the trailing number
                    string deviceId = GetString(drive, "DeviceID");
                    const string drivePrefix = @"\\.\PHYSICALDRIVE";
                    string diskNumStr = (!String.IsNullOrEmpty(deviceId) && deviceId.StartsWith(drivePrefix, StringComparison.OrdinalIgnoreCase))
                        ? deviceId.Substring(drivePrefix.Length)
                        : "";

                    int msftType = 0;
                    if (!String.IsNullOrEmpty(diskNumStr) && msftMediaTypes.ContainsKey(diskNumStr))
                    {
                        msftType = msftMediaTypes[diskNumStr];
                    }

                    if (msftType == 4)
                    {
                        diskType = "SSD";
                    }
                    else if (msftType == 3)
                    {
                        diskType = "HDD";
                    }
                    else
                    {
                        string modelLower = model != null ? model.ToLowerInvariant() : "";
                        diskType = (modelLower.Contains("ssd") || modelLower.Contains("solid state") ||
                                    modelLower.Contains("nvme") || modelLower.Contains("nand"))
                            ? "SSD"
                            : "HDD";
                    }
                }

                item["type"] = diskType;
                result.Add(item);
            }

            return result;
        }

        private static bool HasUsbDisk(ArrayList disks)
        {
            foreach (object obj in disks)
            {
                Dictionary<string, object> disk = obj as Dictionary<string, object>;
                if (disk != null && disk.ContainsKey("usb") && Convert.ToBoolean(disk["usb"]))
                {
                    return true;
                }
            }
            return false;
        }

        private ArrayList GetIpAddresses()
        {
            ArrayList result = new ArrayList();
            Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            ArrayList adapters = QueryList("SELECT IPAddress, IPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");

            foreach (Dictionary<string, object> adapter in adapters)
            {
                if (!adapter.ContainsKey("IPAddress") || adapter["IPAddress"] == null)
                {
                    continue;
                }

                IEnumerable addresses = adapter["IPAddress"] as IEnumerable;
                if (addresses == null || adapter["IPAddress"] is string)
                {
                    AddIpAddress(result, seen, Convert.ToString(adapter["IPAddress"]));
                    continue;
                }

                foreach (object address in addresses)
                {
                    AddIpAddress(result, seen, Convert.ToString(address));
                }
            }

            return result;
        }

        private static void AddIpAddress(ArrayList result, Dictionary<string, bool> seen, string value)
        {
            if (String.IsNullOrEmpty(value))
            {
                return;
            }

            IPAddress address;
            if (!IPAddress.TryParse(value, out address))
            {
                return;
            }

            if (IPAddress.IsLoopback(address))
            {
                return;
            }

            if (address.GetAddressBytes().Length != 4)
            {
                return;
            }

            string normalized = address.ToString();
            if (normalized.StartsWith("169.254.", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (seen.ContainsKey(normalized))
            {
                return;
            }

            seen[normalized] = true;
            result.Add(normalized);
        }

        private Dictionary<string, object> GetOperatingSystem()
        {
            Dictionary<string, object> os = QueryFirst("SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate FROM Win32_OperatingSystem");
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["caption"] = GetString(os, "Caption");
            result["version"] = GetString(os, "Version");
            result["buildNumber"] = GetString(os, "BuildNumber");
            result["architecture"] = GetString(os, "OSArchitecture");
            result["installDate"] = GetString(os, "InstallDate");
            return result;
        }

        private sealed class LicenseKeySource
        {
            public string Product;
            public string RegistryHive;
            public string RegistryPath;
            public string ValueName;
        }

        // This field is learned entirely from the server's own inventory-ack
        // response (ApplyInventoryAckResponse writes learned["licenseKeySources"]
        // from it directly, no validation at that point) and then used here
        // to read and report back an arbitrary registry value - with no
        // check at all, a compromised server (or a bug letting anything else
        // write into the learned-state file) could direct every client in
        // the fleet to read and exfiltrate any HKLM/HKCU value under cover
        // of ordinary inventory telemetry, not just real license keys.
        // Every legitimate use of this feature (the admin-configured
        // "License key sources" catalog - e.g. KriptoPro CSP's own
        // registration key, see this class's own comment above) reads a
        // vendor's own settings under the hive's SOFTWARE subtree; nothing
        // under SAM/SECURITY/SYSTEM/etc. is ever a real license key source.
        private static bool IsAllowedLicenseKeySourcePath(string registryPath)
        {
            return registryPath.StartsWith(@"SOFTWARE\", StringComparison.OrdinalIgnoreCase)
                || String.Equals(registryPath, "SOFTWARE", StringComparison.OrdinalIgnoreCase);
        }

        private List<LicenseKeySource> LoadLicenseKeySourcesCache()
        {
            List<LicenseKeySource> result = new List<LicenseKeySource>();
            Dictionary<string, object> learned = LoadLearnedState();
            object raw;
            if (!learned.TryGetValue("licenseKeySources", out raw))
            {
                return result;
            }
            ArrayList rawList = raw as ArrayList;
            if (rawList == null)
            {
                return result;
            }

            try
            {
                foreach (object item in rawList)
                {
                    Dictionary<string, object> record = item as Dictionary<string, object>;
                    if (record == null)
                    {
                        continue;
                    }

                    LicenseKeySource source = new LicenseKeySource();
                    source.Product = GetString(record, "product");
                    source.RegistryHive = GetString(record, "registryHive");
                    source.RegistryPath = GetString(record, "registryPath");
                    source.ValueName = GetString(record, "valueName");
                    if (!String.IsNullOrEmpty(source.RegistryPath) && !String.IsNullOrEmpty(source.ValueName) && IsAllowedLicenseKeySourcePath(source.RegistryPath))
                    {
                        result.Add(source);
                    }
                }
            }
            catch
            {
                return new List<LicenseKeySource>();
            }

            return result;
        }

        // Reads each cached source's exact registry value - no automatic
        // WOW6432Node fallback guessing, since the admin-entered path is
        // expected to already be the empirically-verified exact location
        // (e.g. KriptoPro CSP's own confirmed path already lives under
        // WOW6432Node; the admin enters that literal path, this code does
        // not need to search for it). A missing path/value is a normal
        // "not installed here" outcome, matching GetActivationState's own
        // tolerance for an absent WMI class.
        private ArrayList GetLicenseKeys()
        {
            ArrayList result = new ArrayList();
            foreach (LicenseKeySource source in LoadLicenseKeySourcesCache())
            {
                try
                {
                    RegistryKey root = String.Equals(source.RegistryHive, "HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase)
                        ? Registry.CurrentUser
                        : Registry.LocalMachine;

                    using (RegistryKey key = root.OpenSubKey(source.RegistryPath))
                    {
                        if (key == null)
                        {
                            continue;
                        }

                        object rawValue = key.GetValue(source.ValueName);
                        if (rawValue == null)
                        {
                            continue;
                        }

                        Dictionary<string, object> entry = new Dictionary<string, object>();
                        entry["product"] = source.Product;
                        entry["source"] = source.RegistryHive + "\\" + source.RegistryPath + "\\" + source.ValueName;
                        entry["key"] = Convert.ToString(rawValue);
                        result.Add(entry);
                    }
                }
                catch
                {
                    // A single bad entry (permissions, corrupt hive,
                    // unexpected value type) must not abort collection of
                    // the rest of the report.
                }
            }

            return result;
        }

        // Separate from GetActivation()/GetActivationState() deliberately -
        // those two have a narrow, already-tested job (the Clients table's
        // activated/not-activated checkmarks); this re-runs its own copy of
        // their WMI query rather than widening their return shape and
        // risking that existing behavior. One extra cheap WMI call per
        // report cycle.
        private ArrayList GetWindowsAndOfficeActivationKeys(string osCaption)
        {
            ArrayList result = new ArrayList();
            string query = "SELECT Name, ApplicationID, LicenseStatus, PartialProductKey FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL";
            ArrayList products = QueryList(query, "root\\cimv2");

            Dictionary<string, object> windowsProduct = null;
            Dictionary<string, object> officeProduct = null;
            foreach (object item in products)
            {
                Dictionary<string, object> product = item as Dictionary<string, object>;
                if (product == null) continue;
                string name = GetString(product, "Name");
                string applicationId = GetString(product, "ApplicationID");
                object licenseStatus = product.ContainsKey("LicenseStatus") ? product["LicenseStatus"] : null;
                bool activated = licenseStatus != null && Convert.ToInt32(licenseStatus) == 1;
                if (!activated) continue;

                bool isWindows = name != null && name.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0;
                bool isOffice = (applicationId != null && applicationId.Equals("0ff1ce15-a989-479d-af46-f275c6370663", StringComparison.OrdinalIgnoreCase)) ||
                                 (name != null && name.IndexOf("Office", StringComparison.OrdinalIgnoreCase) >= 0);

                if (isWindows && windowsProduct == null) windowsProduct = product;
                else if (isOffice && officeProduct == null) officeProduct = product;
            }

            if (windowsProduct != null)
            {
                // SoftwareLicensingProduct's own Name is a generic, edition-only
                // string ("Windows(R), Professional edition") with no OS major
                // version at all for client SKUs - Win32_OperatingSystem's
                // Caption (already collected into the report's own "os" field,
                // no extra query here) carries both the version number (7/8/10/
                // 11, or a Server release) and the edition in one string, so it
                // reads correctly where the licensing product name alone doesn't.
                string windowsName = !String.IsNullOrEmpty(osCaption) ? osCaption : GetString(windowsProduct, "Name");
                string fullKey = null;
                string source = null;

                try
                {
                    string oa3xKey = GetWindowsOa3xOriginalProductKey();
                    if (!String.IsNullOrEmpty(oa3xKey))
                    {
                        fullKey = oa3xKey;
                        source = "Windows activation (OEM firmware)";
                    }
                }
                catch
                {
                    // OA3xOriginalProductKey can throw on a machine with no
                    // OEM-embedded key at all (not every SKU has the WMI
                    // method/property) - absence is normal, not an error.
                }

                if (fullKey == null)
                {
                    try
                    {
                        byte[] digitalProductId = ReadRegistryBinary(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DigitalProductId");
                        string decoded = DecodeDigitalProductIdKey(digitalProductId);
                        if (!String.IsNullOrEmpty(decoded))
                        {
                            fullKey = decoded;
                            source = "Windows activation (registry)";
                        }
                    }
                    catch
                    {
                        // A missing/unreadable registry value is a normal
                        // outcome (permissions, non-standard install) - fall
                        // through to the partial-key fallback below.
                    }
                }

                if (fullKey != null)
                {
                    Dictionary<string, object> entry = new Dictionary<string, object>();
                    entry["product"] = windowsName;
                    entry["source"] = source;
                    entry["key"] = fullKey;
                    result.Add(entry);
                }
                else
                {
                    string partial = GetString(windowsProduct, "PartialProductKey");
                    if (!String.IsNullOrEmpty(partial))
                    {
                        Dictionary<string, object> entry = new Dictionary<string, object>();
                        entry["product"] = windowsName;
                        entry["source"] = "Windows activation (partial)";
                        entry["key"] = partial;
                        result.Add(entry);
                    }
                }
            }

            if (officeProduct != null)
            {
                string officeName = GetString(officeProduct, "Name");
                string partial = GetString(officeProduct, "PartialProductKey");
                string officeFullKey = null;
                string officeFullKeyProductName = null;

                // The registry scan only trusts a decoded key that ends with
                // this same product's own WMI-reported PartialProductKey -
                // no partial key means nothing to validate against, so the
                // scan is skipped rather than risking an unvalidated result.
                if (!String.IsNullOrEmpty(partial))
                {
                    try
                    {
                        officeFullKey = GetOfficeDigitalProductIdKey(partial, out officeFullKeyProductName);
                    }
                    catch
                    {
                        // A missing/unreadable Office registration hive is a
                        // normal outcome (Click-to-Run/retail install, which
                        // uses a different OSPP token-based licensing
                        // mechanism with no DigitalProductID value to find
                        // here at all) - fall through to the partial-key
                        // fallback below.
                    }
                }

                if (officeFullKey != null)
                {
                    Dictionary<string, object> entry = new Dictionary<string, object>();
                    entry["product"] = !String.IsNullOrEmpty(officeFullKeyProductName) ? officeFullKeyProductName : officeName;
                    entry["source"] = "Office activation (registry)";
                    entry["key"] = officeFullKey;
                    result.Add(entry);
                }
                else if (!String.IsNullOrEmpty(partial))
                {
                    Dictionary<string, object> entry = new Dictionary<string, object>();
                    entry["product"] = officeName;
                    entry["source"] = "Office activation (partial)";
                    entry["key"] = partial;
                    result.Add(entry);
                }
            }

            return result;
        }

        private static string GetWindowsOa3xOriginalProductKey()
        {
            ArrayList rows = QueryList("SELECT OA3xOriginalProductKey FROM SoftwareLicensingService", "root\\cimv2");
            if (rows.Count == 0) return null;
            Dictionary<string, object> row = (Dictionary<string, object>)rows[0];
            return GetString(row, "OA3xOriginalProductKey");
        }

        // A Volume License/MSI-activated Office install (KMS or MAK) registers
        // itself under HKLM\SOFTWARE\Microsoft\Office\<version>\Registration\
        // {GUID}, carrying its own DigitalProductID value using the same
        // base24 encoding Windows' own DigitalProductId uses - but NOT at
        // Windows' fixed byte offset (see DecodeOfficeDigitalProductIdKey's
        // own comment for why expectedLastFive is required and how the
        // offset is found). A Click-to-Run/retail install uses a different
        // (OSPP token-based) licensing mechanism with no DigitalProductID
        // value anywhere in this tree, so finding nothing is the normal
        // outcome there, not an error. Walks every version/subkey instead of
        // a hardcoded "Registration" path (matching the reference script
        // this is ported from) since the exact middle segment isn't
        // guaranteed stable across Office releases. Checked against both the
        // native and Wow6432Node roots the same way GetInstalledSoftware
        // already checks both for the Uninstall hive - a 32-bit Office
        // install's registration lives under Wow6432Node when seen from a
        // 64-bit view (and vice versa).
        private static string GetOfficeDigitalProductIdKey(string expectedLastFive, out string productName)
        {
            string found = GetOfficeDigitalProductIdKeyUnderRoot(@"SOFTWARE\Microsoft\Office", expectedLastFive, out productName);
            if (found != null)
            {
                return found;
            }
            return GetOfficeDigitalProductIdKeyUnderRoot(@"SOFTWARE\Wow6432Node\Microsoft\Office", expectedLastFive, out productName);
        }

        private static string GetOfficeDigitalProductIdKeyUnderRoot(string rootPath, string expectedLastFive, out string productName)
        {
            productName = null;
            using (RegistryKey officeKey = Registry.LocalMachine.OpenSubKey(rootPath))
            {
                if (officeKey == null)
                {
                    return null;
                }

                foreach (string versionName in officeKey.GetSubKeyNames())
                {
                    string versionPath = rootPath + "\\" + versionName;
                    using (RegistryKey versionKey = Registry.LocalMachine.OpenSubKey(versionPath))
                    {
                        if (versionKey == null)
                        {
                            continue;
                        }

                        foreach (string midName in versionKey.GetSubKeyNames())
                        {
                            string midPath = versionPath + "\\" + midName;
                            using (RegistryKey midKey = Registry.LocalMachine.OpenSubKey(midPath))
                            {
                                if (midKey == null)
                                {
                                    continue;
                                }

                                foreach (string leafName in midKey.GetSubKeyNames())
                                {
                                    // One subkey's own broken ACL/data must not
                                    // abort the rest of the walk - same
                                    // per-entry handling as ReadUninstallKey.
                                    try
                                    {
                                        string leafPath = midPath + "\\" + leafName;
                                        byte[] digitalProductId = ReadRegistryBinary(Registry.LocalMachine, leafPath, "DigitalProductID");
                                        if (digitalProductId == null)
                                        {
                                            continue;
                                        }
                                        string decoded = DecodeOfficeDigitalProductIdKey(digitalProductId, expectedLastFive);
                                        if (String.IsNullOrEmpty(decoded))
                                        {
                                            continue;
                                        }
                                        productName = ReadRegistryString(Registry.LocalMachine, leafPath, "ProductName");
                                        return decoded;
                                    }
                                    catch
                                    {
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }

        private static byte[] ReadRegistryBinary(RegistryKey root, string subKeyPath, string valueName)
        {
            using (RegistryKey key = root.OpenSubKey(subKeyPath))
            {
                if (key == null) return null;
                return key.GetValue(valueName, null) as byte[];
            }
        }

        private Dictionary<string, object> GetActivation()
        {
            // Queried once and evaluated against both matches below - the
            // Windows and Office activation checks used to each run this
            // same WMI query independently.
            string query = "SELECT Name, ApplicationID, LicenseStatus, PartialProductKey FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL";
            ArrayList products = QueryList(query, "root\\cimv2");

            Dictionary<string, object> result = new Dictionary<string, object>();
            result["windows"] = GetActivationState(true, products);
            result["office"] = GetActivationState(false, products);
            return result;
        }

        private Dictionary<string, object> GetActivationState(bool windows, ArrayList products)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();

            foreach (Dictionary<string, object> product in products)
            {
                // Name/ApplicationID come back null on a real machine whose
                // SoftwareLicensingProduct rows don't populate every column
                // (seen on some OEM/eval/Server Core licensing states) - a
                // bare .IndexOf/.Equals on either threw NullReferenceException
                // and lost this entire product's evaluation (and, since this
                // isn't wrapped by the caller, the whole report cycle).
                string name = GetString(product, "Name");
                string applicationId = GetString(product, "ApplicationID");
                bool match = windows
                    ? name != null && name.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0
                    : (applicationId != null && applicationId.Equals("0ff1ce15-a989-479d-af46-f275c6370663", StringComparison.OrdinalIgnoreCase)) ||
                      (name != null && name.IndexOf("Office", StringComparison.OrdinalIgnoreCase) >= 0);

                object licenseStatus = product.ContainsKey("LicenseStatus") ? product["LicenseStatus"] : null;
                if (match && Convert.ToInt32(licenseStatus) == 1)
                {
                    result["activated"] = true;
                    result["product"] = name;
                    return result;
                }
            }

            // Office 2010 predates Office's move into the unified
            // SoftwareLicensingProduct class above (Office 2013+/365 and the
            // OS itself all use it) - it registers its own activation state
            // in a separate class, OfficeSoftwareProtectionProduct, instead.
            // Confirmed live on a real Office 2010 VOLUME_KMSCLIENT host
            // (2026-08-26): that class lives directly in root\cimv2, the
            // SAME namespace as the query above - NOT in a dedicated
            // root\Microsoft\OfficeSoftwareProtectionPlatform namespace as
            // originally assumed (that namespace does not exist at all on a
            // real Office 2010 install; querying it always threw, silently
            // caught below, which is why this never worked). Only checked
            // for the Office branch: Windows OS activation has always lived
            // in SoftwareLicensingProduct, no equivalent gap there.
            if (!windows)
            {
                ArrayList officeLegacyProducts;
                try
                {
                    officeLegacyProducts = QueryList(
                        "SELECT ProductKeyID, LicenseStatus FROM OfficeSoftwareProtectionProduct WHERE PartialProductKey IS NOT NULL",
                        "root\\cimv2");
                }
                catch
                {
                    // OfficeSoftwareProtectionProduct doesn't exist as a class
                    // on hosts with no legacy Office Software Protection
                    // Platform installed (i.e. no Office 2010 or earlier ever
                    // present) - not an error, just no data.
                    officeLegacyProducts = new ArrayList();
                }

                foreach (Dictionary<string, object> product in officeLegacyProducts)
                {
                    object legacyLicenseStatus = product.ContainsKey("LicenseStatus") ? product["LicenseStatus"] : null;
                    if (Convert.ToInt32(legacyLicenseStatus) == 1)
                    {
                        result["activated"] = true;
                        result["product"] = "Microsoft Office 2010";
                        return result;
                    }
                }
            }

            result["activated"] = false;
            result["product"] = null;
            return result;
        }

        private Dictionary<string, object> GetOfficeVersion(ArrayList installedSoftware)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            string version = ReadRegistryString(Registry.LocalMachine, @"Software\Microsoft\Office\ClickToRun\Configuration", "VersionToReport");
            string products = ReadRegistryString(Registry.LocalMachine, @"Software\Microsoft\Office\ClickToRun\Configuration", "ProductReleaseIds");

            if (!String.IsNullOrEmpty(version) || !String.IsNullOrEmpty(products))
            {
                result["name"] = products;
                result["version"] = version;
                result["source"] = "ClickToRun";
                return result;
            }

            foreach (Dictionary<string, object> software in installedSoftware)
            {
                string name = GetString(software, "name");
                if (name.IndexOf("Microsoft Office", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    name.IndexOf("Microsoft 365 Apps", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    result["name"] = name;
                    result["version"] = GetString(software, "version");
                    result["source"] = "UninstallRegistry";
                    return result;
                }
            }

            result["name"] = null;
            result["version"] = null;
            result["source"] = null;
            return result;
        }

        private ArrayList GetInstalledSoftware()
        {
            ArrayList result = new ArrayList();
            Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            ReadUninstallKey(result, seen, Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Uninstall");
            ReadUninstallKey(result, seen, Registry.LocalMachine, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall");
            return result;
        }

        private static void ReadUninstallKey(ArrayList result, Dictionary<string, bool> seen, RegistryKey root, string subKeyPath)
        {
            using (RegistryKey uninstall = root.OpenSubKey(subKeyPath))
            {
                if (uninstall == null)
                {
                    return;
                }

                foreach (string subKeyName in uninstall.GetSubKeyNames())
                {
                    // One subkey's own ACL/data can be broken (an orphaned
                    // SID, a corrupted value) without the rest of the hive
                    // being affected - an unhandled exception here used to
                    // abort this whole method (and, since neither caller
                    // wraps it, the entire report cycle) over a single bad
                    // entry. Skip just that one entry instead.
                    try
                    {
                        using (RegistryKey item = uninstall.OpenSubKey(subKeyName))
                        {
                            if (item == null)
                            {
                                continue;
                            }

                            string displayName = Convert.ToString(item.GetValue("DisplayName", ""));
                            if (String.IsNullOrEmpty(displayName))
                            {
                                continue;
                            }

                            if (!IsVisibleSoftwareEntry(item))
                            {
                                continue;
                            }

                            string displayVersion = Convert.ToString(item.GetValue("DisplayVersion", ""));
                            string publisher = Convert.ToString(item.GetValue("Publisher", ""));
                            string installDate = FormatInstallDate(Convert.ToString(item.GetValue("InstallDate", "")));
                            string key = (displayName + "|" + displayVersion + "|" + publisher).ToLowerInvariant();
                            if (seen.ContainsKey(key))
                            {
                                continue;
                            }
                            seen[key] = true;

                            Dictionary<string, object> software = new Dictionary<string, object>();
                            software["name"] = displayName;
                            software["version"] = displayVersion;
                            software["publisher"] = publisher;
                            software["installDate"] = installDate;
                            result.Add(software);
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }

        // Uninstall registry InstallDate values are an 8-digit YYYYMMDD string
        // (e.g. "20251013"), not a normal date. Reformat to dd.MM.yyyy; leave
        // anything that does not match that shape untouched.
        private static string FormatInstallDate(string raw)
        {
            if (String.IsNullOrEmpty(raw) || raw.Length != 8)
            {
                return raw;
            }

            string year = raw.Substring(0, 4);
            string month = raw.Substring(4, 2);
            string day = raw.Substring(6, 2);

            int yearNum, monthNum, dayNum;
            if (!Int32.TryParse(year, out yearNum) || !Int32.TryParse(month, out monthNum) || !Int32.TryParse(day, out dayNum))
            {
                return raw;
            }
            if (monthNum < 1 || monthNum > 12 || dayNum < 1 || dayNum > 31)
            {
                return raw;
            }

            return day + "." + month + "." + year;
        }

        private static bool IsVisibleSoftwareEntry(RegistryKey item)
        {
            object systemComponent = item.GetValue("SystemComponent", 0);
            if (Convert.ToString(systemComponent) == "1")
            {
                return false;
            }

            string parentKeyName = Convert.ToString(item.GetValue("ParentKeyName", ""));
            if (!String.IsNullOrEmpty(parentKeyName))
            {
                return false;
            }

            string releaseType = Convert.ToString(item.GetValue("ReleaseType", ""));
            if (!String.IsNullOrEmpty(releaseType))
            {
                return false;
            }

            string uninstallString = Convert.ToString(item.GetValue("UninstallString", ""));
            string quietUninstallString = Convert.ToString(item.GetValue("QuietUninstallString", ""));
            if (String.IsNullOrEmpty(uninstallString) && String.IsNullOrEmpty(quietUninstallString))
            {
                return false;
            }

            return true;
        }

        private static string ReadRegistryString(RegistryKey root, string subKeyPath, string valueName)
        {
            using (RegistryKey key = root.OpenSubKey(subKeyPath))
            {
                if (key == null)
                {
                    return null;
                }

                return Convert.ToString(key.GetValue(valueName, null));
            }
        }

        // Decodes the classic DigitalProductId binary blob into the 25-
        // character Windows product key. Ported faithfully from the
        // real PowerShell reference implementation (base24 alphabet,
        // byte-array big-number division) rather than reimplemented from
        // description - see docs/superpowers/specs/2026-10-06-license-key-detection-design.md
        // for the original script this mirrors. Deliberately avoids
        // System.Numerics.BigInteger (not available under .NET 3.5, and
        // this client builds for net35 too) - uses the same byte-array
        // carry-propagation technique the original script uses, which
        // needs only byte/int arithmetic.
        // Returns null if digitalProductId is too short to contain the key
        // bytes (offset 52, 15 bytes - needs at least 67 bytes total), or
        // if the decoded result is the all-placeholder key ("BBBBB-BBBBB-
        // BBBBB-BBBBB-BBBBB") - the real signature of a MAK- or digital-
        // license-activated machine where no real key was ever entered.
        private static string DecodeDigitalProductIdKey(byte[] digitalProductId)
        {
            const int keyOffset = 52;
            const int keyByteCount = 15;
            if (digitalProductId == null || digitalProductId.Length < keyOffset + keyByteCount)
            {
                return null;
            }
            return DecodeDigitalProductIdKeyAtOffset(digitalProductId, keyOffset);
        }

        // Core decode, factored out of DecodeDigitalProductIdKey so the same
        // byte-arithmetic can run at an offset OTHER than Windows' fixed 52 -
        // see DecodeOfficeDigitalProductIdKey below for why that's needed.
        // Bounds are the caller's responsibility (DecodeDigitalProductIdKey
        // checks length before calling; the Office scan below only calls
        // this where a full 15-byte window exists).
        private static string DecodeDigitalProductIdKeyAtOffset(byte[] digitalProductId, int keyOffset)
        {
            const int keyByteCount = 15;

            // Copy the 15-byte slice - the decode loop mutates it in place
            // (storing each division's quotient back into the buffer), so
            // operating on a copy avoids corrupting the caller's array.
            byte[] buffer = new byte[keyByteCount];
            Array.Copy(digitalProductId, keyOffset, buffer, 0, keyByteCount);

            const string base24 = "BCDFGHJKMPQRTVWXY2346789";
            const int decodeStringLength = 24;
            const int decodeLength = 14;

            bool containsN = (buffer[decodeLength] / 8) % 2 == 1;
            buffer[decodeLength] = (byte)(buffer[decodeLength] & 0xF7);

            char[] decodedKey = new char[decodeStringLength + 1];
            for (int i = decodeStringLength; i >= 0; i--)
            {
                int digitMapIndex = 0;
                for (int j = decodeLength; j >= 0; j--)
                {
                    digitMapIndex = digitMapIndex * 256 ^ buffer[j];
                    buffer[j] = (byte)(digitMapIndex / base24.Length);
                    digitMapIndex = digitMapIndex % base24.Length;
                }
                decodedKey[i] = base24[digitMapIndex];
            }

            string decoded = new string(decodedKey);

            if (containsN)
            {
                int firstLetterIndex = base24.IndexOf(decoded[0]);
                if (firstLetterIndex < 0)
                {
                    return null;
                }
                decoded = decoded.Substring(1);
                decoded = decoded.Substring(0, firstLetterIndex) + "N" + decoded.Substring(firstLetterIndex);
            }

            // All-placeholder result: every character is base24[0] ('B') -
            // the real signature of a MAK/digital-license machine with no
            // real key material in these bytes. Not a real key - report
            // nothing, let the caller fall back to PartialProductKey.
            bool allPlaceholder = true;
            for (int k = 0; k < decoded.Length; k++)
            {
                if (decoded[k] != base24[0]) { allPlaceholder = false; break; }
            }
            if (allPlaceholder)
            {
                return null;
            }

            System.Text.StringBuilder withDashes = new System.Text.StringBuilder(decoded);
            for (int t = 20; t >= 5; t -= 5)
            {
                withDashes.Insert(t, '-');
            }
            return withDashes.ToString();
        }

        // Office's own DigitalProductID carries the identical base24-encoded
        // key material as Windows' - confirmed by decoding a real Volume
        // License/KMS-activated Office 2016 install's actual registry value
        // this session - but NOT at Windows' fixed offset 52: on that same
        // real machine the key only appeared at byte offset 808 of a 1272-
        // byte blob (nearly 8x Windows' ~164-byte one), found by brute-force
        // scanning every offset and comparing against the SAME machine's own
        // WMI-reported PartialProductKey. A single data point isn't enough
        // to trust a fixed offset for every Office build/edition/blob size,
        // so this scans every possible offset on EACH machine instead and
        // only accepts a decoded key that ends with that machine's own
        // already-verified PartialProductKey (expectedLastFive) - the result
        // is self-validating per machine, never a plausible-looking wrong
        // key, regardless of how Office's own blob layout varies. Returns
        // null (falls back to the partial key alone) when no offset
        // produces a match - the normal outcome for a Click-to-Run/retail
        // install, which has no DigitalProductID value at all.
        private static string DecodeOfficeDigitalProductIdKey(byte[] digitalProductId, string expectedLastFive)
        {
            const int keyByteCount = 15;
            if (digitalProductId == null || String.IsNullOrEmpty(expectedLastFive) || expectedLastFive.Length != 5)
            {
                return null;
            }

            for (int offset = 0; offset + keyByteCount <= digitalProductId.Length; offset++)
            {
                string decoded = DecodeDigitalProductIdKeyAtOffset(digitalProductId, offset);
                if (decoded != null && decoded.EndsWith(expectedLastFive, StringComparison.OrdinalIgnoreCase))
                {
                    return decoded;
                }
            }
            return null;
        }

        private static Dictionary<string, object> QueryFirst(string query)
        {
            ArrayList list = QueryList(query);
            return list.Count > 0 ? (Dictionary<string, object>)list[0] : new Dictionary<string, object>();
        }

        private static ArrayList QueryList(string query)
        {
            return QueryList(query, "root\\cimv2");
        }

        private static ArrayList QueryList(string query, string wmiNamespace)
        {
            ArrayList result = new ArrayList();
            try
            {
                ManagementScope scope = new ManagementScope(new ManagementPath(wmiNamespace));
                scope.Connect();
                // A bounded timeout (WMI's semisynchronous enumeration mode -
                // MoveNext throws ManagementException instead of blocking
                // forever) so a hung/misbehaving WMI provider can't wedge
                // this cycle indefinitely; caught by the try/catch below
                // like any other query failure.
                EnumerationOptions enumOptions = new EnumerationOptions();
                enumOptions.Timeout = TimeSpan.FromSeconds(60);
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query), enumOptions))
                {
                    // The searcher's own using disposes itself, but each
                    // ManagementObject it yields holds a separate COM RCW
                    // that isn't - undisposed, these accumulate for the
                    // life of this always-on service across every
                    // collection cycle until GC finalizers eventually
                    // catch up.
                    foreach (ManagementObject item in searcher.Get())
                    {
                        using (item)
                        {
                            Dictionary<string, object> row = new Dictionary<string, object>();
                            foreach (PropertyData property in item.Properties)
                            {
                                row[property.Name] = property.Value;
                            }
                            result.Add(row);
                        }
                    }
                }
            }
            catch
            {
            }

            return result;
        }

        // internal rather than private so SoftwareJobRunner (a separate
        // top-level class's nested type) can reuse it instead of duplicating it.
        internal static string GetString(Dictionary<string, object> data, string key)
        {
            if (!data.ContainsKey(key) || data[key] == null)
            {
                return null;
            }

            return Convert.ToString(data[key]);
        }

        // '.' is allowed but '/' and '\' are not, so the result can never
        // contain a path separator - mirrors the server's SanitizeFileName,
        // though here the input is always Environment.MachineName, not
        // network-supplied.
        private static string SanitizeFileName(string value)
        {
            StringBuilder builder = new StringBuilder();
            foreach (char c in value)
            {
                builder.Append(Char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' ? c : '_');
            }
            return builder.ToString();
        }

        private static void WriteText(string path, string value)
        {
            string directory = Path.GetDirectoryName(path);
            // GetDirectoryName returns "" (not null) for a bare filename
            // with no directory component (e.g. --output report.json) -
            // Directory.CreateDirectory("") throws ArgumentException, which
            // used to abort every single collection cycle permanently for
            // that configuration. Same guard DebugLogger.Log already uses.
            if (!String.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(path, value, new UTF8Encoding(false));
        }

        // The server's response to POST /api/v1/inventory can carry two
        // independent things worth persisting past this process's own
        // lifetime: the admin-managed license key source catalog
        // (top-level "licenseKeySources" - the client has no other
        // channel to pull it, see the license-key collection design doc)
        // and interval overrides (nested under "config", see
        // ApplyConfigFromServer). Both are merged into one shared
        // learned-state dictionary and written to disk together, at most
        // once per ack - see GetLearnedStateCachePath below for the
        // unified file both this method and GetLicenseKeys() read from. A
        // missing or corrupt cache file is a normal "nothing learned yet"
        // state, never an error - LoadLearnedState() returns an empty
        // dictionary rather than throwing or returning null.
        private ForceImmediateCheckFlags ApplyInventoryAckResponse(string responseBody)
        {
            if (String.IsNullOrEmpty(responseBody))
            {
                return new ForceImmediateCheckFlags();
            }

            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                Dictionary<string, object> response = serializer.Deserialize<Dictionary<string, object>>(responseBody);
                if (response == null)
                {
                    return new ForceImmediateCheckFlags();
                }
                Dictionary<string, object> learned = LoadLearnedState();
                bool learnedChanged = false;

                if (response.ContainsKey("licenseKeySources") && response["licenseKeySources"] is ArrayList)
                {
                    // Matches the old SaveLicenseKeySourcesCache's exact
                    // behavior: unconditional overwrite whenever the
                    // field is present, no comparison against the
                    // previously cached value.
                    learned["licenseKeySources"] = response["licenseKeySources"];
                    learnedChanged = true;
                }

                if (response.ContainsKey("config"))
                {
                    if (ApplyConfigFromServer(response["config"] as Dictionary<string, object>, learned))
                    {
                        learnedChanged = true;
                    }
                }

                if (learnedChanged)
                {
                    SaveLearnedState(learned);
                }

                ForceImmediateCheckFlags flags = new ForceImmediateCheckFlags();
                flags.WindowsUpdate = response.ContainsKey("forceImmediateWindowsUpdateCheck") && Convert.ToBoolean(response["forceImmediateWindowsUpdateCheck"]);
                flags.ThirdPartySoftware = response.ContainsKey("forceImmediateThirdPartySoftwareCheck") && Convert.ToBoolean(response["forceImmediateThirdPartySoftwareCheck"]);
                return flags;
            }
            catch
            {
                // A malformed/unparseable response must never fail a
                // report the server has already accepted.
                return new ForceImmediateCheckFlags();
            }
        }

        // Everything the server can push down to an already-running
        // client that needs to survive a process restart, keyed by the
        // same names the ack response itself uses (intervalHours,
        // windowsUpdateCheckIntervalHours, thirdPartySoftwareCheckIntervalHours,
        // licenseKeySources) - one JSON object, one file, read once and
        // written once per ack that actually changes something. The
        // ingestion token is the one
        // exception: it lives in the service's own registry Environment
        // value instead, since a restart's SCM-launched process needs to
        // see it as an environment variable before this code ever runs
        // again - see ApplyLearnedIngestionToken.
        private string GetLearnedStateCachePath()
        {
            string baseDir = options.OutputPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                ? Path.GetDirectoryName(options.OutputPath)
                : options.OutputPath;
            return Path.Combine(baseDir, "learned-config.json");
        }

        // Called once at startup, before the two Timer objects are
        // created, so a service restart mid-overlap or after an interval
        // change picks up the learned value instead of the original
        // command-line-parsed one. Returns an empty (never null)
        // dictionary if no learned state exists yet or it fails to parse
        // - a brand-new install has never contacted the server
        // successfully, so the command-line value is correctly the only
        // thing to fall back on.
        //
        // internal rather than private: InventoryService.OnStart() (a
        // different top-level-sibling class, not nested inside this one)
        // needs to call this before creating its own timer/
        // windowsUpdateCheckTimer/thirdPartySoftwareCheckTimer fields, the same cross-class reason PostJson
        // just above is internal instead of private.
        internal Dictionary<string, object> LoadLearnedState()
        {
            try
            {
                string path = GetLearnedStateCachePath();
                if (!File.Exists(path))
                {
                    return new Dictionary<string, object>();
                }
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                Dictionary<string, object> loaded = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
                return loaded ?? new Dictionary<string, object>();
            }
            catch
            {
                return new Dictionary<string, object>();
            }
        }

        // internal rather than private: SoftwareJobRunner.CheckAndRun() (a
        // separate top-level class's nested type, see GetString's own
        // comment above) needs to persist the last-scanned WSUS cab hash
        // through this same cache file, the same cross-class reason
        // LoadLearnedState just above is internal instead of private.
        internal void SaveLearnedState(Dictionary<string, object> learned)
        {
            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                WriteText(GetLearnedStateCachePath(), serializer.Serialize(learned));
            }
            catch
            {
                // Best-effort persistence, same reasoning as before - a
                // write failure here must never affect an inventory
                // report that has already succeeded.
            }
        }

        // Applies intervalHours/windowsUpdateCheckIntervalHours/
        // thirdPartySoftwareCheckIntervalHours/ingestionToken/update
        // learned from the inventory ack. Mutates options directly for
        // all five; additionally mutates the caller-owned `learned` dict
        // (persisted by the caller, ApplyInventoryAckResponse, once per
        // ack rather than once per field here) for the three interval
        // fields only - ingestionToken goes to the registry
        // (ApplyLearnedIngestionToken) and update triggers an immediate
        // action (ApplySelfUpdateFromServer), neither is cache-file
        // content. Does NOT reschedule the Timer objects itself, because
        // those are private fields of InventoryService (the outer,
        // service-hosting class in this same file), not of this
        // InventoryCollector - a fresh InventoryCollector is instantiated
        // by InventoryService for every single collection cycle and has
        // no reference back to the timers that scheduled it.
        // InventoryService.Collect() reschedules both timers itself
        // immediately after this method returns, by comparing options'
        // values before/after this call. Returns whether anything was
        // added to `learned` (the caller uses this to decide whether a
        // save is needed at all).
        private bool ApplyConfigFromServer(Dictionary<string, object> config, Dictionary<string, object> learned)
        {
            if (config == null)
            {
                return false;
            }

            bool changed = false;

            if (config.ContainsKey("intervalHours"))
            {
                int parsedInterval;
                if (Int32.TryParse(Convert.ToString(config["intervalHours"]), out parsedInterval) && parsedInterval >= 1 && parsedInterval <= 24 && parsedInterval != options.IntervalHours)
                {
                    options.IntervalHours = parsedInterval;
                    learned["intervalHours"] = parsedInterval;
                    changed = true;
                }
            }

            if (config.ContainsKey("windowsUpdateCheckIntervalHours"))
            {
                int parsedWindowsUpdateInterval;
                if (Int32.TryParse(Convert.ToString(config["windowsUpdateCheckIntervalHours"]), out parsedWindowsUpdateInterval) && parsedWindowsUpdateInterval >= 1 && parsedWindowsUpdateInterval <= 24 && parsedWindowsUpdateInterval != options.WindowsUpdateCheckIntervalHours)
                {
                    options.WindowsUpdateCheckIntervalHours = parsedWindowsUpdateInterval;
                    learned["windowsUpdateCheckIntervalHours"] = parsedWindowsUpdateInterval;
                    changed = true;
                }
            }

            if (config.ContainsKey("thirdPartySoftwareCheckIntervalHours"))
            {
                int parsedThirdPartySoftwareInterval;
                if (Int32.TryParse(Convert.ToString(config["thirdPartySoftwareCheckIntervalHours"]), out parsedThirdPartySoftwareInterval) && parsedThirdPartySoftwareInterval >= 1 && parsedThirdPartySoftwareInterval <= 24 && parsedThirdPartySoftwareInterval != options.ThirdPartySoftwareCheckIntervalHours)
                {
                    options.ThirdPartySoftwareCheckIntervalHours = parsedThirdPartySoftwareInterval;
                    learned["thirdPartySoftwareCheckIntervalHours"] = parsedThirdPartySoftwareInterval;
                    changed = true;
                }
            }

            if (config.ContainsKey("ingestionToken"))
            {
                string newToken = Convert.ToString(config["ingestionToken"]);
                if (!String.IsNullOrEmpty(newToken))
                {
                    ApplyLearnedIngestionToken(newToken);
                }
            }

            if (config.ContainsKey("update"))
            {
                Dictionary<string, object> update = config["update"] as Dictionary<string, object>;
                if (update != null)
                {
                    ApplySelfUpdateFromServer(update);
                }
            }

            return changed;
        }

        // Writes WIL_INGESTION_TOKEN into this service's own registry
        // Environment value (HKLM\SYSTEM\CurrentControlSet\Services\
        // <name>\Environment, REG_MULTI_SZ) - the same mechanism
        // Install-Client.ps1/Deploy-ClientGpo.ps1 already use at install
        // time (see their own Set-ServiceEnvironmentToken), just invoked
        // from the running client itself so a token learned mid-overlap
        // survives a later service restart instead of reverting to
        // whatever was written there at install time. Best-effort: a
        // registry-write failure (e.g. this instance is somehow not
        // running as LocalSystem/an account with rights to its own
        // service key) must not fail the report that already succeeded -
        // the in-process token (options.Token, set immediately below) still
        // works for the remainder of this process's lifetime either way.
        // Lets a GPO-deployed client - started with only a low-privilege
        // EnrollmentToken and no real Token yet - obtain its own
        // per-machine ingestion token from the server before the inventory
        // POST just below ever runs, instead of embedding the real shared
        // Token in a SYSVOL-readable GPO .cmd file (see EnrollClient on the
        // server side). A no-op once options.Token is set, whether that
        // was true from install or because an earlier cycle's enrollment
        // already succeeded and persisted it via ApplyLearnedIngestionToken
        // - so this never re-enrolls on every single cycle once it has
        // worked once. Best-effort: a failure here (server unreachable,
        // EnrollmentToken wrong or not configured) is logged and
        // swallowed - the PostJson call right after this returns gets its
        // own 401 in that case, exactly like today's behavior for a client
        // with no token at all, so a transient enrollment failure degrades
        // to "this cycle's report is rejected," not a crashed cycle.
        private void TryEnrollIfNeeded()
        {
            TryEnrollIfNeededCore(PostJson, ApplyLearnedIngestionToken);
        }

        // postJson AND applyLearnedToken are both injected so self-tests can
        // exercise the real decision/parsing logic above without a live
        // server and, just as important, without ever reaching the real
        // ApplyLearnedIngestionToken - that call writes to the real
        // HKLM\SYSTEM\...\Services\WindowsInventoryLiteClient registry key
        // (see ApplyIngestionTokenToRegistryCore's own comment on why tests
        // must never touch it, even when running elevated). Mirrors why
        // ApplySelfUpdateFromServerCore takes a download delegate.
        internal void TryEnrollIfNeededCore(Func<string, string, string, string> postJson, Action<string> applyLearnedToken)
        {
            if (!String.IsNullOrEmpty(options.Token) || String.IsNullOrEmpty(options.EnrollmentToken))
            {
                return;
            }

            try
            {
                string enrollUrl = ToEnrollUrl(options.ServerUrl);
                Dictionary<string, object> body = new Dictionary<string, object>();
                body["computerName"] = Environment.MachineName;
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                string responseBody = postJson(enrollUrl, serializer.Serialize(body), options.EnrollmentToken);
                Dictionary<string, object> response = serializer.Deserialize<Dictionary<string, object>>(responseBody);
                string issuedToken = response != null && response.ContainsKey("token") ? Convert.ToString(response["token"]) : null;
                if (!String.IsNullOrEmpty(issuedToken))
                {
                    applyLearnedToken(issuedToken);
                    DebugLogger.Log(options, "Server", "Enrolled with the server and obtained a per-machine ingestion token.");
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "Error", "Enrollment attempt failed: " + ex.Message);
            }
        }

        private void ApplyLearnedIngestionToken(string newToken)
        {
            options.Token = newToken;
            try
            {
                ApplyIngestionTokenToRegistryCore(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\WindowsInventoryLiteClient", newToken);
            }
            catch
            {
                // Best-effort - see method comment above.
            }
        }

        // Testable core of ApplyLearnedIngestionToken - baseKey/subKeyPath
        // are parameters so self-tests can point this at a scratch
        // HKEY_CURRENT_USER location instead of the real
        // HKEY_LOCAL_MACHINE service key, which a non-admin test process
        // cannot write to (and must never touch even when it can).
        internal static void ApplyIngestionTokenToRegistryCore(RegistryKey baseKey, string subKeyPath, string newToken)
        {
            using (RegistryKey serviceKey = baseKey.OpenSubKey(subKeyPath, true))
            {
                if (serviceKey == null)
                {
                    return;
                }
                List<string> lines = new List<string>();
                object existing = serviceKey.GetValue("Environment");
                string[] existingLines = existing as string[];
                if (existingLines != null)
                {
                    foreach (string line in existingLines)
                    {
                        if (!line.StartsWith("WIL_INGESTION_TOKEN=", StringComparison.OrdinalIgnoreCase))
                        {
                            lines.Add(line);
                        }
                    }
                }
                lines.Add("WIL_INGESTION_TOKEN=" + newToken);
                serviceKey.SetValue("Environment", lines.ToArray(), RegistryValueKind.MultiString);
                RestrictServiceRegistryKeyAcl(serviceKey);
            }
        }

        // Breaks ACL inheritance on the service's own registry key and
        // grants only Administrators+SYSTEM - see
        // Set-RestrictedServiceRegistryKeyAcl in Install-Client.ps1/
        // Deploy-ClientGpo.ps1 for the install-time equivalent and the
        // full reasoning (BUILTIN\Users inherits ReadKey by default,
        // verified live). Applied every time the token is rewritten here,
        // not just once at install, since nothing guarantees the key
        // wasn't recreated with default inheritance since the last run.
        internal static void RestrictServiceRegistryKeyAcl(RegistryKey serviceKey)
        {
            SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            RegistrySecurity acl = serviceKey.GetAccessControl();
            acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new RegistryAccessRule(adminSid, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new RegistryAccessRule(systemSid, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            serviceKey.SetAccessControl(acl);
        }

        // Fixed name, not a per-run GUID - see this feature's design spec
        // (docs/superpowers/specs/2026-09-10-client-self-update-design.md,
        // "AV posture"): a random scheduled-task name per invocation is
        // itself a heuristic red flag, while a fixed, documented name is
        // something an admin can whitelist once in their AV product.
        internal const string SelfUpdateTaskName = "WindowsInventoryLiteClient-SelfUpdate";

        // Placeholder until the project owner runs the one-time key
        // generation step (docs/self-update-signing.md) and pastes the
        // real Modulus/Exponent here. A placeholder key can never verify
        // any real signature - safe, since RequireSignatureForSelfUpdate
        // defaults to false and this constant is only consulted when an
        // admin has explicitly opted in via --require-signed-self-update.
        internal const string SelfUpdatePublicKeyModulusBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        internal const string SelfUpdatePublicKeyExponentBase64 = "AQAB";

        // Builds the plain cmd.exe script (not PowerShell - this client's
        // fleet includes real PowerShell 2.0 machines, and native cmd.exe
        // has no such floor) that a one-shot Scheduled Task runs to
        // perform the actual swap. Pure string construction - no side
        // effects - so it can be reasoned about/tested in isolation from
        // the process-spawning code that writes and registers it.
        //
        // logPath is where each major step gets logged (the same file
        // DebugLogger already writes to) - pass "NUL" (Windows' null
        // device) when debug logging is disabled, so the script's own
        // `>>` redirects are always valid syntax with no conditional
        // generation needed, and simply discard output when off.
        internal static string BuildSelfUpdateCmdScript(string currentExePath, string newExePath, string logPath)
        {
            string backupExePath = currentExePath + ".bak";
            string failedExePath = currentExePath + ".failed";
            string log = "\"" + logPath + "\"";
            StringBuilder script = new StringBuilder();
            script.AppendLine("@echo off");
            script.AppendLine("echo [self-update] starting >> " + log);
            script.AppendLine("sc stop WindowsInventoryLiteClient");
            script.AppendLine("set wilstopwaitcount=0");
            script.AppendLine(":waitstopped");
            script.AppendLine("sc query WindowsInventoryLiteClient | find \"STOPPED\" >nul");
            script.AppendLine("if not errorlevel 1 goto stopped");
            script.AppendLine("set /a wilstopwaitcount+=1");
            // Bounded, not the unbounded loop an earlier pass deliberately
            // shipped - a service that never reaches STOPPED (a genuinely
            // possible state per OnStop()'s own comment on an in-progress
            // install) must not spin this SYSTEM-level task forever with
            // no rollback ever reached. ~30s, matching the run-wait loop's
            // own bound below.
            script.AppendLine("if %wilstopwaitcount% GEQ 30 goto stop_timed_out");
            script.AppendLine("ping -n 2 127.0.0.1 >nul");
            script.AppendLine("goto waitstopped");
            script.AppendLine(":stop_timed_out");
            script.AppendLine("echo [self-update] service never reached STOPPED within timeout - aborting, nothing was touched >> " + log);
            script.AppendLine("goto cleanup");
            script.AppendLine(":stopped");
            script.AppendLine("echo [self-update] service stopped, swapping files >> " + log);
            script.AppendLine("move /y \"" + currentExePath + "\" \"" + backupExePath + "\"");
            // Both move /y calls are now errorlevel-checked - previously
            // neither was, so a failed backup (e.g. an AV real-time-scan
            // lock racing the just-stopped exe) silently proceeded to
            // overwrite the live exe anyway with no real backup to roll
            // back to if the new build then failed to start.
            script.AppendLine("if errorlevel 1 goto backup_failed");
            script.AppendLine("move /y \"" + newExePath + "\" \"" + currentExePath + "\"");
            script.AppendLine("if errorlevel 1 goto swap_failed");
            script.AppendLine("sc start WindowsInventoryLiteClient");
            script.AppendLine("set wilwaitcount=0");
            script.AppendLine(":waitrunning");
            script.AppendLine("sc query WindowsInventoryLiteClient | find \"RUNNING\" >nul");
            script.AppendLine("if not errorlevel 1 goto running");
            script.AppendLine("set /a wilwaitcount+=1");
            script.AppendLine("if %wilwaitcount% GEQ 30 goto rollback");
            script.AppendLine("ping -n 2 127.0.0.1 >nul");
            script.AppendLine("goto waitrunning");
            script.AppendLine(":running");
            script.AppendLine("echo [self-update] new version running, cleaning up >> " + log);
            script.AppendLine("del \"" + backupExePath + "\"");
            script.AppendLine("goto cleanup");
            script.AppendLine(":rollback");
            script.AppendLine("echo [self-update] new version failed to reach RUNNING within timeout, rolling back >> " + log);
            script.AppendLine("move /y \"" + currentExePath + "\" \"" + failedExePath + "\"");
            script.AppendLine("move /y \"" + backupExePath + "\" \"" + currentExePath + "\"");
            script.AppendLine("sc start WindowsInventoryLiteClient");
            script.AppendLine("goto cleanup");
            script.AppendLine(":backup_failed");
            // currentExePath was never actually moved (move /y failed, so
            // its source is untouched on this filesystem) - nothing to
            // restore, just get the still-original service running again.
            script.AppendLine("echo [self-update] failed to back up the current exe - aborting without touching it >> " + log);
            script.AppendLine("sc start WindowsInventoryLiteClient");
            script.AppendLine("goto cleanup");
            script.AppendLine(":swap_failed");
            // The backup DOES exist here (we only reach this label after
            // the backup move succeeded) - explicitly restore it rather
            // than assume currentExePath is still intact, since the
            // failure reason for this specific move is unknown.
            script.AppendLine("echo [self-update] failed to swap in the new exe after backup was created - restoring backup >> " + log);
            script.AppendLine("move /y \"" + backupExePath + "\" \"" + currentExePath + "\"");
            script.AppendLine("sc start WindowsInventoryLiteClient");
            script.AppendLine(":cleanup");
            script.AppendLine("schtasks /Delete /TN \"" + SelfUpdateTaskName + "\" /F");
            script.AppendLine("del \"%~f0\"");
            return script.ToString();
        }

        internal enum SelfUpdateOutcome
        {
            NoBuildForTarget,
            AlreadyCurrent,
            NotNewer,
            HttpsRequired,
            NoHashAdvertised,
            HashMismatch,
            SignatureRequired,
            SignatureMismatch,
            TaskCreateFailed,
            TaskRunFailed,
            Applied,
            Error
        }

        // Downloads the newer client build the server just advertised,
        // verifies its hash, and hands the actual swap-and-restart off to
        // a generated one-shot Scheduled Task - this running process
        // cannot safely overwrite its own locked executable. Best-effort
        // throughout: any failure here must never affect the inventory
        // report that already succeeded, and the server will keep
        // advertising the same "update" until this client's reported
        // version actually changes, so a failed attempt here is retried
        // automatically on the next cycle.
        //
        // Thin wrapper around ApplySelfUpdateFromServerCore below - all
        // decision logic and logging live in Core, which returns a
        // SelfUpdateOutcome so self-tests can assert on it directly. This
        // wrapper's own try/catch is defense in depth on top of Core's own
        // internal one, in case Core itself has a bug - this call path
        // must never throw back into Collect()'s already-accepted report.
        private void ApplySelfUpdateFromServer(Dictionary<string, object> update)
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                // Decoded in its own try/catch, separate from the outer one,
                // so a malformed pinned-key constant (e.g. a copy-paste
                // mistake when Task 5's real key is installed) degrades
                // ONLY the signature-verification feature - by passing null
                // keys through, which VerifyRsaSignature already fails
                // closed on - rather than aborting this entire self-update
                // attempt before the HTTPS/hash checks even run. A bad
                // constant must never be able to silently disable
                // self-update fleet-wide regardless of whether an admin
                // even uses --require-signed-self-update.
                byte[] publicKeyModulus = null;
                byte[] publicKeyExponent = null;
                try
                {
                    publicKeyModulus = Convert.FromBase64String(SelfUpdatePublicKeyModulusBase64);
                    publicKeyExponent = Convert.FromBase64String(SelfUpdatePublicKeyExponentBase64);
                }
                catch (FormatException keyEx)
                {
                    DebugLogger.Log(options, "SelfUpdate", "Pinned self-update public key constant is not valid base64 - signature verification will fail closed if required, but self-update itself will still proceed: " + keyEx.Message);
                }
                ApplySelfUpdateFromServerCore(update, exePath, Program.ProductVersion, options, HttpGetBytes, RunHelperProcess, publicKeyModulus, publicKeyExponent);
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "SelfUpdate", "Self-update attempt failed (report already accepted, will retry next cycle): " + ex);
            }
        }

        // Verifies an RSA/SHA256/PKCS#1v1.5 signature - the same scheme
        // Sign-ClientRelease.ps1 produces via RSACryptoServiceProvider.SignData.
        // Returns false (never throws) for any malformed input - a
        // verification helper failing closed on bad input is exactly the
        // behavior a signature check needs.
        private static bool VerifyRsaSignature(byte[] data, string signatureBase64, byte[] publicKeyModulus, byte[] publicKeyExponent)
        {
            if (String.IsNullOrEmpty(signatureBase64) || publicKeyModulus == null || publicKeyExponent == null)
            {
                return false;
            }
            try
            {
                byte[] signature = Convert.FromBase64String(signatureBase64);
                RSAParameters publicKeyParams = new RSAParameters();
                publicKeyParams.Modulus = publicKeyModulus;
                publicKeyParams.Exponent = publicKeyExponent;
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(publicKeyParams);
                    return rsa.VerifyData(data, "SHA256", signature);
                }
            }
            catch
            {
                return false;
            }
        }

        // Testable core of ApplySelfUpdateFromServer - exePath, currentVersion,
        // and options are explicit parameters (not derived internally via
        // Process.GetCurrentProcess()/Program.ProductVersion) specifically so
        // self-tests can supply fake values; the real wrapper above supplies
        // the real ones. download/runHelperProcess are injected the same way
        // (mirroring the Linux client's own downloadFunc/verifyFunc pattern)
        // since a real HTTP call and a real schtasks.exe spawn can't be faked
        // cheaply. File I/O is NOT injected - self-tests use real temporary
        // files/directories for the backup/swap/.cmd-write side, the same way
        // this project's server self-tests already do for file-based logic.
        //
        // Every DebugLogger.Log call below is unchanged from the original,
        // inline, single method this was extracted from - same text, same
        // position, same conditions. DebugLogger.Log is a safe no-op in a
        // test context (it early-returns whenever options.DebugLogEnabled is
        // false, the default for a freshly-constructed ClientOptions), so no
        // test needs to guard against it.
        internal static SelfUpdateOutcome ApplySelfUpdateFromServerCore(Dictionary<string, object> update, string exePath, string currentVersion, ClientOptions options, Func<string, string, byte[]> download, Func<string, string, bool> runHelperProcess, byte[] publicKeyModulus, byte[] publicKeyExponent)
        {
            string target = Environment.Version.Major >= 4 ? "net40" : "net35";
            string versionKey = target == "net40" ? "versionNet40" : "versionNet35";
            string hashKey = target == "net40" ? "sha256Net40" : "sha256Net35";
            if (!update.ContainsKey(versionKey) || !update.ContainsKey(hashKey))
            {
                // The server has no build for this client's own target
                // (e.g. only the other target's exe exists in
                // ClientPackagePath) - nothing to self-update to. Logged
                // (not silent) - otherwise this looks identical to the
                // original per-target hash bug from the outside: a client
                // that never updates with no visible reason why.
                DebugLogger.Log(options, "SelfUpdate", "Server has no build for this client's own target (" + target + ", keys " + versionKey + "/" + hashKey + ") - nothing to update to.");
                return SelfUpdateOutcome.NoBuildForTarget;
            }
            string newVersion = Convert.ToString(update[versionKey]);
            if (String.IsNullOrEmpty(newVersion) || String.Equals(newVersion, currentVersion, StringComparison.Ordinal))
            {
                return SelfUpdateOutcome.AlreadyCurrent;
            }
            if (!IsVersionNewer(newVersion, currentVersion))
            {
                // Only ever move forward. Nothing in this ack proves the
                // server's build is actually newer - a stale rebuild, a
                // bad manual ClientPackagePath copy, or a restored old
                // backup on the server would otherwise silently downgrade
                // every self-update-enabled client that reports in while
                // it's in that state, with no confirmation and no log
                // distinguishing "upgrade" from "downgrade." An
                // unparseable version string is treated the same as "not
                // newer" - never apply a build this client can't actually
                // compare.
                DebugLogger.Log(options, "SelfUpdate", "Server advertised version " + newVersion + " for target " + target + ", but it is not newer than this client's own " + currentVersion + " - ignoring (would be a downgrade, or the version string could not be compared).");
                return SelfUpdateOutcome.NotNewer;
            }
            // ServerUrl's own scheme is still checked first - if it's
            // already https, nothing below runs and downloadUrl is built
            // from it directly further down, exactly as before this change.
            string downloadUrl = ToClientPackageUpdateDownloadUrl(options.ServerUrl, target);
            bool usingOpportunisticHttps = false;
            if (options.RequireHttpsForSelfUpdate && !(options.ServerUrl ?? "").StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                if (update.ContainsKey("httpsPort"))
                {
                    int httpsPort;
                    if (Int32.TryParse(Convert.ToString(update["httpsPort"]), out httpsPort) && httpsPort > 0)
                    {
                        string httpsServerUrl = ToHttpsServerUrl(options.ServerUrl, httpsPort);
                        if (httpsServerUrl != null)
                        {
                            downloadUrl = ToClientPackageUpdateDownloadUrl(httpsServerUrl, target);
                            usingOpportunisticHttps = true;
                        }
                    }
                }

                if (!usingOpportunisticHttps && !options.AllowHttpFallbackForSelfUpdate)
                {
                    DebugLogger.Log(options, "SelfUpdate", "RequireHttpsForSelfUpdate is set, ServerUrl is not https, the server did not advertise an active httpsPort, and AllowHttpFallbackForSelfUpdate is not set - refusing to self-update over an unencrypted transport.");
                    return SelfUpdateOutcome.HttpsRequired;
                }
                // Either an https candidate was found (tried below, with a
                // fallback to plain ServerUrl on failure only if
                // AllowHttpFallbackForSelfUpdate allows it), or none was
                // available but AllowHttpFallbackForSelfUpdate explicitly
                // permits proceeding over the original ServerUrl anyway -
                // downloadUrl is already set to the right one of those.
            }
            string expectedSha256 = Convert.ToString(update[hashKey]);
            if (String.IsNullOrEmpty(expectedSha256))
            {
                return SelfUpdateOutcome.NoHashAdvertised;
            }

            DebugLogger.Log(options, "SelfUpdate", "Server advertised version " + newVersion + " for target " + target + " - attempting self-update.");

            try
            {
                string exeDirectory = Path.GetDirectoryName(exePath);
                string newExePath = Path.Combine(exeDirectory, "WindowsInventoryLiteClient.exe.new");

                byte[] downloadedBytes;
                try
                {
                    downloadedBytes = download(downloadUrl, options.Token);
                }
                catch (Exception ex)
                {
                    if (usingOpportunisticHttps && options.AllowHttpFallbackForSelfUpdate)
                    {
                        // The opportunistic https attempt failed - an
                        // invalid/self-signed cert (this client never
                        // overrides .NET's default certificate validation,
                        // so this is a real TLS rejection), the port not
                        // actually listening, etc. AllowHttpFallbackForSelfUpdate
                        // permits retrying over the original ServerUrl
                        // instead of giving up; without it, this exception
                        // propagates to the outer catch as a plain Error,
                        // matching "require" semantics (refuse rather than
                        // ever fall back to an unencrypted channel).
                        DebugLogger.Log(options, "SelfUpdate", "Opportunistic https self-update download failed (" + ex.Message + ") - falling back to the original ServerUrl since AllowHttpFallbackForSelfUpdate is set.");
                        downloadUrl = ToClientPackageUpdateDownloadUrl(options.ServerUrl, target);
                        downloadedBytes = download(downloadUrl, options.Token);
                    }
                    else
                    {
                        throw;
                    }
                }

                string actualSha256;
                using (SHA256 sha256 = SHA256.Create())
                {
                    actualSha256 = BitConverter.ToString(sha256.ComputeHash(downloadedBytes)).Replace("-", "").ToLowerInvariant();
                }
                if (!String.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    DebugLogger.Log(options, "SelfUpdate", "Downloaded build's hash did not match the advertised " + hashKey + " - aborting, will retry next cycle.");
                    return SelfUpdateOutcome.HashMismatch;
                }

                if (options.RequireSignatureForSelfUpdate)
                {
                    string sigKey = target == "net40" ? "sigNet40" : "sigNet35";
                    string signatureBase64 = update.ContainsKey(sigKey) ? Convert.ToString(update[sigKey]) : null;
                    if (String.IsNullOrEmpty(signatureBase64))
                    {
                        DebugLogger.Log(options, "SelfUpdate", "RequireSignatureForSelfUpdate is set but the server did not advertise a " + sigKey + " - refusing to self-update.");
                        return SelfUpdateOutcome.SignatureRequired;
                    }
                    if (!VerifyRsaSignature(downloadedBytes, signatureBase64, publicKeyModulus, publicKeyExponent))
                    {
                        DebugLogger.Log(options, "SelfUpdate", "RequireSignatureForSelfUpdate is set and the advertised " + sigKey + " did not verify against the pinned public key - refusing to self-update.");
                        return SelfUpdateOutcome.SignatureMismatch;
                    }
                }

                File.WriteAllBytes(newExePath, downloadedBytes);
                DebugLogger.Log(options, "SelfUpdate", "Downloaded and hash-verified version " + newVersion + " (" + target + ") - registering scheduled task to apply it.");

                // Fixed, deterministic path inside the ACL-restricted
                // install directory - not %TEMP% with a per-run GUID name,
                // which would have undercut this feature's own fixed-task-
                // name AV mitigation (an admin excluding the task name
                // would still have an unexcluded, ever-changing SYSTEM
                // script sitting in a world-writable-by-create directory).
                string logPath = options.DebugLogEnabled ? DebugLogger.ResolvePath(options) : "NUL";
                string cmdPath = Path.Combine(exeDirectory, "wil-self-update.cmd");
                File.WriteAllText(cmdPath, BuildSelfUpdateCmdScript(exePath, newExePath, logPath), Encoding.ASCII);

                // Previously logged success unconditionally regardless of
                // whether either schtasks.exe call actually succeeded - an
                // AV/EDR block on scheduled-task creation (a real risk
                // given this project's own Kaspersky false-positive
                // history) meant self-update silently never applied while
                // the diagnostic log built specifically to catch this kept
                // reporting success on every cycle.
                string createArgs = "/Create /TN \"" + SelfUpdateTaskName + "\" /TR \"cmd.exe /c \\\"" + cmdPath + "\\\"\" /SC ONCE /ST 23:59 /RU SYSTEM /F";
                bool created = runHelperProcess("schtasks.exe", createArgs);
                if (!created)
                {
                    DebugLogger.Log(options, "SelfUpdate", "Failed to create scheduled task '" + SelfUpdateTaskName + "' - self-update was not applied this cycle (possibly an AV/EDR block or a permissions issue). Will retry next cycle if the version still differs.");
                    return SelfUpdateOutcome.TaskCreateFailed;
                }
                bool ran = runHelperProcess("schtasks.exe", "/Run /TN \"" + SelfUpdateTaskName + "\"");
                if (!ran)
                {
                    DebugLogger.Log(options, "SelfUpdate", "Failed to run scheduled task '" + SelfUpdateTaskName + "' - self-update was not applied this cycle (possibly an AV/EDR block or a permissions issue). Will retry next cycle if the version still differs.");
                    return SelfUpdateOutcome.TaskRunFailed;
                }
                DebugLogger.Log(options, "SelfUpdate", "Scheduled task '" + SelfUpdateTaskName + "' created and started.");
                return SelfUpdateOutcome.Applied;
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "SelfUpdate", "Self-update attempt failed (report already accepted, will retry next cycle): " + ex);
                return SelfUpdateOutcome.Error;
            }
        }

        internal static string ToWsusCabDownloadUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/wsus-cab-download");
        }

        // download is injected the same way ApplySelfUpdateFromServerCore
        // injects it (production: HttpGetBytes) - lets the hash-mismatch
        // and file-write logic be self-tested without a real HTTP call.
        internal static bool DownloadAndVerifyWsusCab(string serverUrl, string token, string expectedHash, string destinationPath, Func<string, string, byte[]> download)
        {
            byte[] downloadedBytes = download(ToWsusCabDownloadUrl(serverUrl), token);

            string actualHash;
            using (SHA256 sha256 = SHA256.Create())
            {
                actualHash = BitConverter.ToString(sha256.ComputeHash(downloadedBytes)).Replace("-", "").ToLowerInvariant();
            }

            if (!String.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            File.WriteAllBytes(destinationPath, downloadedBytes);
            return true;
        }

        // Testable core of the WSUS scan trigger: every real I/O boundary
        // (wuauserv service check, WUA scan, cab download+verify, results
        // POST) is an injected delegate, so the decision sequencing - and
        // specifically the two "definitely do nothing" paths - can be
        // self-tested without any of them actually running. The real
        // wiring, in SoftwareJobRunner.CheckAndRun, passes the production
        // implementations.
        //
        // Returns true only when the scan ran and was reported
        // successfully; the caller then persists wsusCabHash as the new
        // last-scanned hash via LoadLearnedState/SaveLearnedState (kept
        // out of this function since both are InventoryCollector instance
        // methods, and this function stays static so its two no-op paths
        // stay trivially testable). On every other outcome - no rescan
        // needed, wuauserv down, download/verify failure, or a failed
        // report - this returns false and the caller leaves the stored
        // hash untouched: a wuauserv-down or report failure is retried
        // automatically on the next poll, with no separate retry/calendar
        // mechanism.
        internal static bool MaybeRunWsusScanCore(string wsusCabHash, string lastScannedHash, DateTime? lastScanAtUtc, int maxAgeDays, bool force, Func<bool> isWuauservRunning, Func<string, List<Dictionary<string, object>>> scanForMissingUpdates, Func<string, string, bool> downloadAndVerifyCab, Func<string, bool, List<Dictionary<string, object>>, bool> postResults)
        {
            if (!WsusScanner.ShouldRescan(wsusCabHash, lastScannedHash, lastScanAtUtc, maxAgeDays, force))
            {
                return false;
            }

            if (!isWuauservRunning())
            {
                postResults(wsusCabHash, false, new List<Dictionary<string, object>>());
                return false;
            }

            string cabPath = Path.Combine(Path.GetTempPath(), "wil-wsusscn2-" + Guid.NewGuid().ToString("N") + ".cab");
            try
            {
                if (!downloadAndVerifyCab(wsusCabHash, cabPath))
                {
                    return false;
                }

                List<Dictionary<string, object>> missingUpdates = scanForMissingUpdates(cabPath);
                return postResults(wsusCabHash, true, missingUpdates);
            }
            finally
            {
                try { File.Delete(cabPath); } catch { }
            }
        }

        internal static bool RunSelfTests(TextWriter output)
        {
            bool allPassed = true;
            allPassed &= SelfTestCheck(output, "IsVersionNewer returns true for a strictly greater version", TestIsVersionNewerReturnsTrueForStrictlyGreaterVersion);
            allPassed &= SelfTestCheck(output, "IsVersionNewer returns false for an equal version", TestIsVersionNewerReturnsFalseForEqualVersion);
            allPassed &= SelfTestCheck(output, "IsVersionNewer returns false for an older version", TestIsVersionNewerReturnsFalseForOlderVersion);
            allPassed &= SelfTestCheck(output, "IsVersionNewer returns false for an unparseable version", TestIsVersionNewerReturnsFalseForUnparseableVersion);
            allPassed &= SelfTestCheck(output, "IsVersionNewer handles differing segment counts", TestIsVersionNewerHandlesDifferingSegmentCounts);
            allPassed &= SelfTestCheck(output, "ApplyIngestionTokenToRegistryCore restricts the key's ACL to Administrators+SYSTEM", TestApplyIngestionTokenToRegistryCoreRestrictsAcl);
            allPassed &= SelfTestCheck(output, "BuildSelfUpdateCmdScript's label graph is closed (no dangling goto targets)", TestBuildSelfUpdateCmdScriptLabelGraphIsClosed);
            allPassed &= SelfTestCheck(output, "BuildSelfUpdateCmdScript checks both move commands for errorlevel", TestBuildSelfUpdateCmdScriptChecksBothMoveCommandsForErrorlevel);
            allPassed &= SelfTestCheck(output, "BuildSelfUpdateCmdScript's wait loops are bounded", TestBuildSelfUpdateCmdScriptHasBoundedWaitLoops);
            allPassed &= SelfTestCheck(output, "BuildSelfUpdateCmdScript's cleanup deletes the task and itself", TestBuildSelfUpdateCmdScriptCleansUpTaskAndItself);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns NoBuildForTarget for a pre-split ack", TestApplySelfUpdateFromServerCoreReturnsNoBuildForTargetOnPreSplitAck);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns NoBuildForTarget when only the version key is present", TestApplySelfUpdateFromServerCoreReturnsNoBuildForTargetWhenOnlyVersionKeyPresent);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns AlreadyCurrent when the version matches", TestApplySelfUpdateFromServerCoreReturnsAlreadyCurrentWhenVersionMatches);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns NotNewer when the advertised version is older", TestApplySelfUpdateFromServerCoreReturnsNotNewerWhenAdvertisedVersionIsOlder);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns NoHashAdvertised when the hash is empty", TestApplySelfUpdateFromServerCoreReturnsNoHashAdvertisedWhenHashIsEmpty);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns HashMismatch and leaves the file untouched", TestApplySelfUpdateFromServerCoreReturnsHashMismatchAndLeavesFileUntouched);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns TaskCreateFailed when schtasks /Create fails", TestApplySelfUpdateFromServerCoreReturnsTaskCreateFailedWhenSchtasksCreateFails);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns TaskRunFailed when schtasks /Run fails", TestApplySelfUpdateFromServerCoreReturnsTaskRunFailedWhenSchtasksRunFails);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns Applied and writes the expected files", TestApplySelfUpdateFromServerCoreReturnsAppliedAndWritesExpectedFiles);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns Error when download throws", TestApplySelfUpdateFromServerCoreReturnsErrorWhenDownloadThrows);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns HttpsRequired when RequireHttpsForSelfUpdate is true and ServerUrl is http", TestApplySelfUpdateFromServerCoreReturnsHttpsRequiredForHttpServerUrl);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore proceeds when RequireHttpsForSelfUpdate is true and ServerUrl is https", TestApplySelfUpdateFromServerCoreProceedsWhenHttpsSatisfied);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore falls back to http when no httpsPort is advertised and AllowHttpFallbackForSelfUpdate is set", TestApplySelfUpdateFromServerCoreFallsBackToHttpWhenNoHttpsPortAdvertised);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore still requires https when no httpsPort is advertised and AllowHttpFallbackForSelfUpdate is not set", TestApplySelfUpdateFromServerCoreStillRequiresHttpsWhenFallbackNotAllowedAndNoHttpsPortAdvertised);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore uses the advertised httpsPort opportunistically when ServerUrl is http", TestApplySelfUpdateFromServerCoreUsesOpportunisticHttpsWhenAdvertised);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore falls back to the original ServerUrl when the opportunistic https attempt fails and fallback is allowed", TestApplySelfUpdateFromServerCoreOpportunisticHttpsFailureFallsBackWhenAllowed);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore propagates a failed opportunistic https attempt as Error, never a silent http fallback, when fallback is not allowed", TestApplySelfUpdateFromServerCoreOpportunisticHttpsFailurePropagatesWhenFallbackNotAllowed);
            allPassed &= SelfTestCheck(output, "ToHttpsServerUrl swaps scheme and port, keeping host and path", TestToHttpsServerUrlSwapsSchemeAndPortKeepingHostAndPath);
            allPassed &= SelfTestCheck(output, "ToHttpsServerUrl returns null for a malformed serverUrl", TestToHttpsServerUrlReturnsNullForMalformedServerUrl);
            allPassed &= SelfTestCheck(output, "ToEnrollUrl swaps the /api/v1/inventory suffix for /api/v1/client/enroll", TestToEnrollUrlSwapsInventorySuffix);
            allPassed &= SelfTestCheck(output, "ToSoftwareDownloadUrl builds the expected catalogType/id query string", TestToSoftwareDownloadUrlBuildsExpectedQueryString);
            allPassed &= SelfTestCheck(output, "TryEnrollIfNeededCore never calls postJson once Token is already set", TestTryEnrollIfNeededCoreSkipsWhenTokenAlreadySet);
            allPassed &= SelfTestCheck(output, "TryEnrollIfNeededCore never calls postJson when no EnrollmentToken is configured", TestTryEnrollIfNeededCoreSkipsWhenNoEnrollmentTokenConfigured);
            allPassed &= SelfTestCheck(output, "TryEnrollIfNeededCore posts to the enroll URL with EnrollmentToken and applies the issued token to options.Token", TestTryEnrollIfNeededCoreAppliesIssuedTokenFromResponse);
            allPassed &= SelfTestCheck(output, "TryEnrollIfNeededCore swallows a failed enroll attempt instead of throwing, leaving Token empty", TestTryEnrollIfNeededCoreSwallowsPostJsonException);
            allPassed &= SelfTestCheck(output, "ShouldClearTokenForReenrollment clears on a 401 when EnrollmentToken is configured", TestShouldClearTokenForReenrollmentClearsOn401WhenEnrollmentTokenConfigured);
            allPassed &= SelfTestCheck(output, "ShouldClearTokenForReenrollment leaves Token alone when no EnrollmentToken is configured", TestShouldClearTokenForReenrollmentLeavesTokenAloneWhenNoEnrollmentTokenConfigured);
            allPassed &= SelfTestCheck(output, "ShouldClearTokenForReenrollment leaves Token alone for non-401 failures", TestShouldClearTokenForReenrollmentLeavesTokenAloneForNonAuthFailures);
            allPassed &= SelfTestCheck(output, "RunOneJob refuses to run the installer when downloaded content does not match the expected contentSha256", TestRunOneJobRefusesToRunWhenDownloadedContentDoesNotMatchExpectedHash);
            allPassed &= SelfTestCheck(output, "RunOneJob skips hash verification when the job carries no contentSha256", TestRunOneJobSkipsVerificationWhenJobHasNoContentSha256);
            allPassed &= SelfTestCheck(output, "StreamToFileAndComputeSha256 writes the full source stream to the destination file and returns its correct SHA256 hash", TestStreamToFileAndComputeSha256WritesFileAndComputesCorrectHash);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns SignatureRequired when RequireSignatureForSelfUpdate is true and no signature was advertised", TestApplySelfUpdateFromServerCoreReturnsSignatureRequiredWhenMissing);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns SignatureMismatch when the advertised signature does not verify", TestApplySelfUpdateFromServerCoreReturnsSignatureMismatchForBadSignature);
            allPassed &= SelfTestCheck(output, "ApplySelfUpdateFromServerCore returns Applied when a genuinely valid RSA signature is provided and required", TestApplySelfUpdateFromServerCoreAppliesWithValidSignature);
            allPassed &= SelfTestCheck(output, "The pinned self-update public key constants are valid base64", TestSelfUpdatePublicKeyConstantsAreValidBase64);
            allPassed &= SelfTestCheck(output, "LoadLearnedState returns an empty (not null) dictionary when no cache file exists", TestLoadLearnedStateReturnsEmptyDictWhenNoFileExists);
            allPassed &= SelfTestCheck(output, "SaveLearnedState/LoadLearnedState round-trip a dictionary with mixed value types", TestSaveLearnedStateRoundTripsMixedValueTypes);
            allPassed &= SelfTestCheck(output, "SaveLearnedState/LoadLearnedState round-trip the wsusLastScanAtUtc key", TestSaveLearnedStatePersistsWsusLastScanAtUtcKey);
            allPassed &= SelfTestCheck(output, "ApplyInventoryAckResponse does not lose a previously-learned field when a later ack only carries a different one", TestApplyInventoryAckResponsePreservesUnrelatedLearnedFields);
            allPassed &= SelfTestCheck(output, "ApplyInventoryAckResponse returns independent WindowsUpdate/ThirdPartySoftware flags for each ack shape", TestApplyInventoryAckResponseReturnsIndependentFlagsForEachType);
            allPassed &= SelfTestCheck(output, "ApplyConfigFromServer ignores an out-of-range interval and applies an in-range one", TestApplyConfigFromServerValidatesIntervalRange);
            allPassed &= SelfTestCheck(output, "LoadLicenseKeySourcesCache parses a source written via ApplyInventoryAckResponse", TestLoadLicenseKeySourcesCacheParsesEntryWrittenThroughAckResponse);
            allPassed &= SelfTestCheck(output, "LoadLicenseKeySourcesCache rejects a source whose registryPath is outside the SOFTWARE subtree (e.g. SAM, SECURITY)", TestLoadLicenseKeySourcesCacheRejectsSourceOutsideSoftwareSubtree);
            allPassed &= SelfTestCheck(output, "WsusScanner.ShouldRescan returns true when hashes differ or the client has never scanned, false when they match", TestWsusScannerShouldRescanCompares);
            allPassed &= SelfTestCheck(output, "DownloadAndVerifyWsusCab writes the file and returns true when the downloaded bytes' hash matches", TestDownloadAndVerifyWsusCabSucceedsOnHashMatch);
            allPassed &= SelfTestCheck(output, "DownloadAndVerifyWsusCab returns false and does not write the file when the downloaded bytes' hash does not match", TestDownloadAndVerifyWsusCabFailsOnHashMismatch);
            allPassed &= SelfTestCheck(output, "PostWsusScanResults returns true and posts the expected JSON fields when the injected postJson succeeds", TestPostWsusScanResultsReturnsTrueAndPostsExpectedFieldsOnSuccess);
            allPassed &= SelfTestCheck(output, "PostWsusScanResults returns false when the injected postJson throws", TestPostWsusScanResultsReturnsFalseWhenPostJsonThrows);
            allPassed &= SelfTestCheck(output, "ResolveInstallerLaunch dispatches .msi to msiexec.exe", TestResolveInstallerLaunchDispatchesMsiToMsiexec);
            allPassed &= SelfTestCheck(output, "ResolveInstallerLaunch dispatches .msu to wusa.exe", TestResolveInstallerLaunchDispatchesMsuToWusa);
            allPassed &= SelfTestCheck(output, "ResolveInstallerLaunch dispatches .cab to dism.exe", TestResolveInstallerLaunchDispatchesCabToDism);
            allPassed &= SelfTestCheck(output, "ResolveInstallerLaunch defaults to launching the downloaded file directly for any other extension", TestResolveInstallerLaunchDefaultsToDirectExecution);
            allPassed &= SelfTestCheck(output, "ResolveInstallerLaunch treats null arguments as empty", TestResolveInstallerLaunchHandlesNullArguments);
            allPassed &= SelfTestCheck(output, "TryFindDangerousInstallerArgument rejects msiexec's own package-selection switches", TestTryFindDangerousInstallerArgumentRejectsMsiPackageSelectionSwitches);
            allPassed &= SelfTestCheck(output, "TryFindDangerousInstallerArgument accepts legitimate msiexec arguments, including ones that share a prefix with a dangerous switch", TestTryFindDangerousInstallerArgumentAcceptsLegitimateMsiArguments);
            allPassed &= SelfTestCheck(output, "TryFindDangerousInstallerArgument rejects wusa's own package-selection switches", TestTryFindDangerousInstallerArgumentRejectsMsuPackageSelectionSwitches);
            allPassed &= SelfTestCheck(output, "TryFindDangerousInstallerArgument accepts legitimate wusa arguments", TestTryFindDangerousInstallerArgumentAcceptsLegitimateMsuArguments);
            allPassed &= SelfTestCheck(output, "TryFindDangerousInstallerArgument rejects dism's own package-selection switches", TestTryFindDangerousInstallerArgumentRejectsCabPackageSelectionSwitches);
            allPassed &= SelfTestCheck(output, "TryFindDangerousInstallerArgument accepts legitimate dism arguments", TestTryFindDangerousInstallerArgumentAcceptsLegitimateCabArguments);
            allPassed &= SelfTestCheck(output, "TryFindDangerousInstallerArgument never rejects anything for direct execution (no installer-selection switch convention to smuggle)", TestTryFindDangerousInstallerArgumentNeverRejectsDirectExecution);
            allPassed &= SelfTestCheck(output, "TryFindDangerousInstallerArgument never rejects null or empty arguments", TestTryFindDangerousInstallerArgumentHandlesNullOrEmpty);
            allPassed &= SelfTestCheck(output, "ReportJobStart posts computerName/catalogType/id/attemptId and returns true on success", TestReportJobStartPostsExpectedFieldsAndReturnsTrueOnSuccess);
            allPassed &= SelfTestCheck(output, "ReportJobStart returns false when the injected postJson throws", TestReportJobStartReturnsFalseWhenPostJsonThrows);
            allPassed &= SelfTestCheck(output, "MaybeRunWsusScanCore does nothing when wsusCabHash is empty or unchanged from the last scan", TestMaybeRunWsusScanCoreNoOpsWhenHashEmptyOrUnchanged);
            allPassed &= SelfTestCheck(output, "MaybeRunWsusScanCore runs when the hash is unchanged but the last scan is older than the configured max age", TestMaybeRunWsusScanCoreRunsWhenStaleByAgeEvenIfHashUnchanged);
            allPassed &= SelfTestCheck(output, "MaybeRunWsusScanCore runs when forced, regardless of hash or age", TestMaybeRunWsusScanCoreRunsWhenForcedEvenIfFreshAndHashUnchanged);
            allPassed &= SelfTestCheck(output, "DecodeDigitalProductIdKey round-trips a synthetic key through the test-only encoder", TestDecodeDigitalProductIdKeyRoundTrip);
            allPassed &= SelfTestCheck(output, "DecodeDigitalProductIdKey round-trips a synthetic N-key (N not at position 0) through the test-only encoder", TestDecodeDigitalProductIdKeyRoundTripWithN);
            allPassed &= SelfTestCheck(output, "DecodeDigitalProductIdKey returns null for an all-zero (placeholder) DigitalProductId", TestDecodeDigitalProductIdKeyDetectsPlaceholder);
            allPassed &= SelfTestCheck(output, "DecodeDigitalProductIdKey returns null for a too-short DigitalProductId buffer", TestDecodeDigitalProductIdKeyHandlesShortInput);
            allPassed &= SelfTestCheck(output, "DecodeOfficeDigitalProductIdKey finds a key at a non-Windows byte offset", TestDecodeOfficeDigitalProductIdKeyFindsNonWindowsOffset);
            allPassed &= SelfTestCheck(output, "DecodeOfficeDigitalProductIdKey rejects a decoded key whose suffix doesn't match the expected partial key", TestDecodeOfficeDigitalProductIdKeyRejectsMismatchedPartial);
            allPassed &= SelfTestCheck(output, "DecodeOfficeDigitalProductIdKey requires a valid 5-character expectedLastFive", TestDecodeOfficeDigitalProductIdKeyRequiresExpectedSuffix);
            return allPassed;
        }

        private static bool SelfTestCheck(TextWriter output, string name, Func<string> testCase)
        {
            string failure;
            try
            {
                failure = testCase();
            }
            catch (Exception ex)
            {
                failure = "threw " + ex.GetType().Name + ": " + ex.Message;
            }

            if (failure == null)
            {
                output.WriteLine("PASS " + name);
                return true;
            }

            output.WriteLine("FAIL " + name + " - " + failure);
            return false;
        }

        private static string TestIsVersionNewerReturnsTrueForStrictlyGreaterVersion()
        {
            if (!IsVersionNewer("1.2.10", "1.2.9"))
            {
                return "expected \"1.2.10\" to be newer than \"1.2.9\"";
            }
            return null;
        }

        private static string TestIsVersionNewerReturnsFalseForEqualVersion()
        {
            if (IsVersionNewer("1.2.9", "1.2.9"))
            {
                return "expected equal versions to not be considered newer";
            }
            return null;
        }

        private static string TestIsVersionNewerReturnsFalseForOlderVersion()
        {
            if (IsVersionNewer("1.2.8", "1.2.9"))
            {
                return "expected an older version to not be considered newer";
            }
            return null;
        }

        private static string TestIsVersionNewerReturnsFalseForUnparseableVersion()
        {
            if (IsVersionNewer("not-a-version", "1.2.9"))
            {
                return "expected an unparseable candidate version to never be treated as newer";
            }
            return null;
        }

        private static string TestIsVersionNewerHandlesDifferingSegmentCounts()
        {
            if (IsVersionNewer("1.2", "1.2.0"))
            {
                return "expected \"1.2\" and \"1.2.0\" to compare as equal (missing segments treated as 0), not newer";
            }
            if (!IsVersionNewer("1.2.1", "1.2"))
            {
                return "expected \"1.2.1\" to be newer than \"1.2\" (missing segment on the shorter side treated as 0)";
            }
            return null;
        }

        private static string TestApplyIngestionTokenToRegistryCoreRestrictsAcl()
        {
            // HKEY_CURRENT_USER is writable by the test process without
            // admin rights, unlike the real HKEY_LOCAL_MACHINE service key
            // this logic targets in production - a scratch subkey here is
            // the C# self-test equivalent of Pester's TestRegistry: drive.
            string subKeyPath = @"Software\WilSelfTest\" + Guid.NewGuid().ToString("N");
            try
            {
                using (RegistryKey scratchKey = Registry.CurrentUser.CreateSubKey(subKeyPath))
                {
                    if (scratchKey == null)
                    {
                        return "expected to create a scratch HKCU subkey for the test";
                    }
                }

                InventoryCollector.ApplyIngestionTokenToRegistryCore(Registry.CurrentUser, subKeyPath, "test-token-123");

                // Registry KEY_READ-class access (unlike NTFS, where
                // Get-Acl/GetAccessControl only needs READ_CONTROL -
                // implicitly granted to an object's owner) has no
                // owner-implicit bypass. So once ApplyIngestionTokenToRegistryCore
                // has locked this key to Administrators+SYSTEM only, an
                // Administrator can still open it for read, but a
                // non-admin identity - including this key's own creator -
                // can no longer even open it. Branch on the current
                // identity so this self-test is meaningful in both kinds
                // of environment instead of always failing on a non-admin box.
                bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
                if (isAdmin)
                {
                    using (RegistryKey scratchKey = Registry.CurrentUser.OpenSubKey(subKeyPath, false))
                    {
                        if (scratchKey == null)
                        {
                            return "expected the scratch subkey to still exist after ApplyIngestionTokenToRegistryCore";
                        }
                        string[] environment = scratchKey.GetValue("Environment") as string[];
                        if (environment == null || Array.IndexOf(environment, "WIL_INGESTION_TOKEN=test-token-123") < 0)
                        {
                            return "expected the Environment value to contain the new token";
                        }

                        RegistrySecurity acl = scratchKey.GetAccessControl();
                        SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                        SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                        bool sawAdmin = false;
                        bool sawSystem = false;
                        foreach (RegistryAccessRule rule in acl.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                        {
                            if (rule.IdentityReference.Equals(adminSid))
                            {
                                sawAdmin = true;
                            }
                            if (rule.IdentityReference.Equals(systemSid))
                            {
                                sawSystem = true;
                            }
                        }
                        if (!sawAdmin || !sawSystem)
                        {
                            return "expected the ACL to grant both Administrators and SYSTEM, got admin=" + sawAdmin + " system=" + sawSystem;
                        }
                    }
                }
                else
                {
                    // The identical OpenSubKey call would have succeeded
                    // before the fix, via this identity's own ownership of
                    // the key it just created - the denial itself is proof
                    // the restriction works.
                    try
                    {
                        using (RegistryKey scratchKey = Registry.CurrentUser.OpenSubKey(subKeyPath, false))
                        {
                            if (scratchKey != null)
                            {
                                return "expected OpenSubKey to be denied for a non-admin identity after the ACL was restricted, but it succeeded";
                            }
                        }
                    }
                    catch (System.Security.SecurityException)
                    {
                        // Expected: the restricted ACL denies this non-admin identity read access.
                    }
                }
            }
            finally
            {
                // Single-argument overload only: the two-argument
                // DeleteSubKeyTree(name, throwOnMissingSubKey) overload was
                // added in .NET 4.0 and does not exist in the .NET 2.0/3.5
                // mscorlib this project also builds against (confirmed via
                // a real Net35 build failure, CS1501). The one-argument
                // overload throws if the subkey is already gone, which the
                // surrounding catch already swallows - same best-effort
                // cleanup behavior either way.
                try { Registry.CurrentUser.DeleteSubKeyTree(subKeyPath); } catch { }
            }
            return null;
        }

        private static string TestBuildSelfUpdateCmdScriptLabelGraphIsClosed()
        {
            string script = BuildSelfUpdateCmdScript(@"C:\install\WindowsInventoryLiteClient.exe", @"C:\install\WindowsInventoryLiteClient.exe.new", "NUL");
            string[] lines = script.Split(new[] { "\r\n" }, StringSplitOptions.None);

            List<string> definedLabels = new List<string>();
            List<string> gotoTargets = new List<string>();
            foreach (string rawLine in lines)
            {
                string line = rawLine.Trim();
                if (line.StartsWith(":") && !line.StartsWith("::"))
                {
                    definedLabels.Add(line.Substring(1));
                }
                if (line.StartsWith("goto ", StringComparison.OrdinalIgnoreCase))
                {
                    gotoTargets.Add(line.Substring(5).Trim());
                }
            }

            if (definedLabels.Count == 0 || gotoTargets.Count == 0)
            {
                return "expected the generated script to contain both labels and goto statements - found none, this test's own parsing may be broken";
            }
            foreach (string target in gotoTargets)
            {
                if (!definedLabels.Contains(target))
                {
                    return "goto target \"" + target + "\" has no matching :label in the generated script";
                }
            }
            return null;
        }

        private static string TestBuildSelfUpdateCmdScriptChecksBothMoveCommandsForErrorlevel()
        {
            string currentExePath = @"C:\install\WindowsInventoryLiteClient.exe";
            string newExePath = @"C:\install\WindowsInventoryLiteClient.exe.new";
            string backupExePath = currentExePath + ".bak";
            string script = BuildSelfUpdateCmdScript(currentExePath, newExePath, "NUL");

            string expectedBackupSequence = "move /y \"" + currentExePath + "\" \"" + backupExePath + "\"\r\nif errorlevel 1 goto backup_failed";
            string expectedSwapSequence = "move /y \"" + newExePath + "\" \"" + currentExePath + "\"\r\nif errorlevel 1 goto swap_failed";

            if (!script.Contains(expectedBackupSequence))
            {
                return "expected the backup move to be immediately followed by \"if errorlevel 1 goto backup_failed\", got:\n" + script;
            }
            if (!script.Contains(expectedSwapSequence))
            {
                return "expected the swap move to be immediately followed by \"if errorlevel 1 goto swap_failed\", got:\n" + script;
            }
            return null;
        }

        private static string TestBuildSelfUpdateCmdScriptHasBoundedWaitLoops()
        {
            string script = BuildSelfUpdateCmdScript(@"C:\install\WindowsInventoryLiteClient.exe", @"C:\install\WindowsInventoryLiteClient.exe.new", "NUL");
            if (!script.Contains("if %wilstopwaitcount% GEQ 30 goto stop_timed_out"))
            {
                return "expected the stop-wait loop to have a bounded counter check, got:\n" + script;
            }
            if (!script.Contains("if %wilwaitcount% GEQ 30 goto rollback"))
            {
                return "expected the run-wait loop to have a bounded counter check, got:\n" + script;
            }
            return null;
        }

        private static string TestBuildSelfUpdateCmdScriptCleansUpTaskAndItself()
        {
            string script = BuildSelfUpdateCmdScript(@"C:\install\WindowsInventoryLiteClient.exe", @"C:\install\WindowsInventoryLiteClient.exe.new", "NUL");
            if (!script.Contains("schtasks /Delete /TN \"" + SelfUpdateTaskName + "\" /F"))
            {
                return "expected :cleanup to delete the scheduled task, got:\n" + script;
            }
            if (!script.Contains("del \"%~f0\""))
            {
                return "expected :cleanup to delete the script itself, got:\n" + script;
            }
            return null;
        }

        // Test-only fixture helper: builds an ack's "update" object with
        // BOTH targets' keys set to the same version/hash. Every Core test
        // below needs this rather than setting only one target's keys,
        // because the same compiled test binary runs as EITHER net35 or
        // net40 depending on which built exe self-tests are invoked
        // against (Environment.Version.Major inside Core picks the target
        // at runtime) - setting both keeps every test's outcome identical
        // regardless of which target is actually running it.
        //
        // The Core tests below pass "0.5.1" as currentVersion, not
        // Program.ProductVersion - deliberately: Core takes currentVersion
        // as an explicit parameter specifically so these tests never
        // depend on whatever the real product version happens to be. Do
        // not "fix" this to match Program.ProductVersion after a future
        // version bump - these fixtures compare two hardcoded version
        // strings against each other and stay correct regardless of what
        // ships.
        private static Dictionary<string, object> BuildSelfTestUpdateAck(string version, string sha256)
        {
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = version;
            update["sha256Net35"] = sha256;
            update["versionNet40"] = version;
            update["sha256Net40"] = sha256;
            return update;
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsNoBuildForTargetOnPreSplitAck()
        {
            // Regression-shaped test for the 2026-09-11 incident: a server
            // ack shaped like the pre-split wire format (a shared "version"
            // key, no versionNet35/versionNet40 for either target) must be
            // recognized as "nothing to update to," not silently ignored
            // or crash - regardless of which target this self-test binary
            // itself was compiled as.
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["version"] = "9.9.9";

            ClientOptions options = new ClientOptions();
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) => new byte[0], (fileName, arguments) => true, null, null);

            if (outcome != SelfUpdateOutcome.NoBuildForTarget)
            {
                return "expected NoBuildForTarget for a pre-split ack with no versionNetXX key for either target, got " + outcome;
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsNoBuildForTargetWhenOnlyVersionKeyPresent()
        {
            // Distinguishes the "||" in "!ContainsKey(versionKey) ||
            // !ContainsKey(hashKey)" from "&&" - the pre-split-ack test
            // above satisfies both sides of the check at once (neither key
            // present), so on its own it could not catch a regression that
            // flipped this to require BOTH keys missing. Here the version
            // key exists for both targets but neither hash key does, so
            // only the hashKey side of the check is what makes this return
            // NoBuildForTarget - correctly reachable regardless of which
            // target this self-test binary was compiled as.
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["versionNet40"] = "9.9.9";

            ClientOptions options = new ClientOptions();
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) => new byte[0], (fileName, arguments) => true, null, null);

            if (outcome != SelfUpdateOutcome.NoBuildForTarget)
            {
                return "expected NoBuildForTarget when the version key is present but the hash key is absent for both targets, got " + outcome;
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsAlreadyCurrentWhenVersionMatches()
        {
            Dictionary<string, object> update = BuildSelfTestUpdateAck("0.5.1", "aaaa");
            ClientOptions options = new ClientOptions();
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) => new byte[0], (fileName, arguments) => true, null, null);

            if (outcome != SelfUpdateOutcome.AlreadyCurrent)
            {
                return "expected AlreadyCurrent when the advertised version equals the current version, got " + outcome;
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsNotNewerWhenAdvertisedVersionIsOlder()
        {
            Dictionary<string, object> update = BuildSelfTestUpdateAck("0.5.0", "aaaa");
            ClientOptions options = new ClientOptions();
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) => new byte[0], (fileName, arguments) => true, null, null);

            if (outcome != SelfUpdateOutcome.NotNewer)
            {
                return "expected NotNewer when the advertised version is older than the current one, got " + outcome;
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsHttpsRequiredForHttpServerUrl()
        {
            // Both targets' keys are set (mirroring BuildSelfTestUpdateAck's
            // own rationale above) since this compiled self-test binary runs
            // as EITHER net35 or net40 depending on which built exe invokes
            // it - setting only one target's keys would make this test fail
            // with NoBuildForTarget whenever it runs under the other target.
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = "irrelevant-not-reached";
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = "irrelevant-not-reached";
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "http://server.example.local/api/v1/inventory";
            options.RequireHttpsForSelfUpdate = true;
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) => new byte[0], (fileName, arguments) => true, null, null);
            if (outcome != SelfUpdateOutcome.HttpsRequired)
            {
                return "expected HttpsRequired, got " + outcome;
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreProceedsWhenHttpsSatisfied()
        {
            string exePath = Path.Combine(Path.GetTempPath(), "wil-selftest-httpsok-" + Guid.NewGuid().ToString("N") + ".exe");
            byte[] newContent = Encoding.ASCII.GetBytes("new-build-content");
            string hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
            }
            // Both targets' keys are set - see the comment on
            // TestApplySelfUpdateFromServerCoreReturnsHttpsRequiredForHttpServerUrl
            // above for why.
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = hash;
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = hash;
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "https://server.example.local/api/v1/inventory";
            options.RequireHttpsForSelfUpdate = true;
            try
            {
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) => newContent, (fileName, arguments) => true, null, null);
                if (outcome != SelfUpdateOutcome.Applied)
                {
                    return "expected Applied when ServerUrl is https and RequireHttpsForSelfUpdate is true, got " + outcome;
                }
                return null;
            }
            finally
            {
                try { File.Delete(exePath + ".new"); } catch { }
                try { File.Delete(Path.Combine(Path.GetDirectoryName(exePath), "wil-self-update.cmd")); } catch { }
            }
        }

        // The exact scenario this whole mechanism exists for: a client
        // deployed before a certificate existed (ServerUrl is http,
        // RequireHttpsForSelfUpdate is on) still has no httpsPort advertised
        // - a certificate-less test rig is a real, common environment this
        // project runs in, not just a transitional state. With
        // AllowHttpFallbackForSelfUpdate set, self-update must keep working
        // over plain http exactly as it would with RequireHttpsForSelfUpdate
        // off entirely - no regression for this deployment shape.
        private static string TestApplySelfUpdateFromServerCoreFallsBackToHttpWhenNoHttpsPortAdvertised()
        {
            string exePath = Path.Combine(Path.GetTempPath(), "wil-selftest-nohttpsport-" + Guid.NewGuid().ToString("N") + ".exe");
            byte[] newContent = Encoding.ASCII.GetBytes("new-build-content");
            string hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
            }
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = hash;
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = hash;
            // Deliberately no "httpsPort" key - the server genuinely has no
            // HTTPS configured, matching a real certificate-less deployment.
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "http://server.example.local/api/v1/inventory";
            options.RequireHttpsForSelfUpdate = true;
            options.AllowHttpFallbackForSelfUpdate = true;
            List<string> requestedUrls = new List<string>();
            try
            {
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) =>
                {
                    requestedUrls.Add(url);
                    return newContent;
                }, (fileName, arguments) => true, null, null);
                if (outcome != SelfUpdateOutcome.Applied)
                {
                    return "expected Applied when no httpsPort is advertised but AllowHttpFallbackForSelfUpdate is set, got " + outcome;
                }
                if (requestedUrls.Count != 1 || !requestedUrls[0].StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                {
                    return "expected exactly one download attempt, over the original http ServerUrl, got: " + String.Join(", ", requestedUrls.ToArray());
                }
                return null;
            }
            finally
            {
                try { File.Delete(exePath + ".new"); } catch { }
                try { File.Delete(Path.Combine(Path.GetDirectoryName(exePath), "wil-self-update.cmd")); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreStillRequiresHttpsWhenFallbackNotAllowedAndNoHttpsPortAdvertised()
        {
            // Same "no httpsPort advertised" condition as the fallback test
            // above, but AllowHttpFallbackForSelfUpdate is NOT set (its
            // default) - must still refuse exactly like the original,
            // pre-opportunistic-https HttpsRequired behavior. Guards against
            // the new httpsPort logic accidentally loosening the strict case.
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = "irrelevant-not-reached";
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = "irrelevant-not-reached";
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "http://server.example.local/api/v1/inventory";
            options.RequireHttpsForSelfUpdate = true;
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) => new byte[0], (fileName, arguments) => true, null, null);
            if (outcome != SelfUpdateOutcome.HttpsRequired)
            {
                return "expected HttpsRequired when no httpsPort is advertised and AllowHttpFallbackForSelfUpdate is not set, got " + outcome;
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreUsesOpportunisticHttpsWhenAdvertised()
        {
            string exePath = Path.Combine(Path.GetTempPath(), "wil-selftest-opportunistichttps-" + Guid.NewGuid().ToString("N") + ".exe");
            byte[] newContent = Encoding.ASCII.GetBytes("new-build-content");
            string hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
            }
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = hash;
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = hash;
            update["httpsPort"] = 8443;
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "http://server.example.local/api/v1/inventory";
            options.RequireHttpsForSelfUpdate = true;
            // AllowHttpFallbackForSelfUpdate deliberately left false - an
            // advertised, successfully-used httpsPort must satisfy "require"
            // on its own, with no fallback needed.
            List<string> requestedUrls = new List<string>();
            try
            {
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) =>
                {
                    requestedUrls.Add(url);
                    return newContent;
                }, (fileName, arguments) => true, null, null);
                if (outcome != SelfUpdateOutcome.Applied)
                {
                    return "expected Applied when an httpsPort is advertised and the https download succeeds, got " + outcome;
                }
                if (requestedUrls.Count != 1 || !requestedUrls[0].StartsWith("https://server.example.local:8443/", StringComparison.OrdinalIgnoreCase))
                {
                    return "expected exactly one download attempt, over https on the advertised port 8443, got: " + String.Join(", ", requestedUrls.ToArray());
                }
                return null;
            }
            finally
            {
                try { File.Delete(exePath + ".new"); } catch { }
                try { File.Delete(Path.Combine(Path.GetDirectoryName(exePath), "wil-self-update.cmd")); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreOpportunisticHttpsFailureFallsBackWhenAllowed()
        {
            string exePath = Path.Combine(Path.GetTempPath(), "wil-selftest-httpsfailfallback-" + Guid.NewGuid().ToString("N") + ".exe");
            byte[] newContent = Encoding.ASCII.GetBytes("new-build-content");
            string hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
            }
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = hash;
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = hash;
            update["httpsPort"] = 8443;
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "http://server.example.local/api/v1/inventory";
            options.RequireHttpsForSelfUpdate = true;
            options.AllowHttpFallbackForSelfUpdate = true;
            List<string> requestedUrls = new List<string>();
            try
            {
                // Simulates a TLS failure (e.g. an invalid/self-signed
                // certificate) on the first (https) attempt only - the
                // second call, if one happens, is the http fallback.
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) =>
                {
                    requestedUrls.Add(url);
                    if (url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new System.Net.WebException("simulated TLS failure - invalid certificate");
                    }
                    return newContent;
                }, (fileName, arguments) => true, null, null);
                if (outcome != SelfUpdateOutcome.Applied)
                {
                    return "expected Applied after falling back to http once the https attempt failed, got " + outcome;
                }
                if (requestedUrls.Count != 2)
                {
                    return "expected exactly two download attempts (https then http), got: " + String.Join(", ", requestedUrls.ToArray());
                }
                if (!requestedUrls[0].StartsWith("https://", StringComparison.OrdinalIgnoreCase) || !requestedUrls[1].StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                {
                    return "expected the first attempt to be https and the second to be http, got: " + String.Join(", ", requestedUrls.ToArray());
                }
                return null;
            }
            finally
            {
                try { File.Delete(exePath + ".new"); } catch { }
                try { File.Delete(Path.Combine(Path.GetDirectoryName(exePath), "wil-self-update.cmd")); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreOpportunisticHttpsFailurePropagatesWhenFallbackNotAllowed()
        {
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = "aaaa";
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = "aaaa";
            update["httpsPort"] = 8443;
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "http://server.example.local/api/v1/inventory";
            options.RequireHttpsForSelfUpdate = true;
            // AllowHttpFallbackForSelfUpdate deliberately left false - a
            // failed https attempt must never silently fall back to http.
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) =>
            {
                throw new System.Net.WebException("simulated TLS failure - invalid certificate");
            }, (fileName, arguments) => true, null, null);
            if (outcome != SelfUpdateOutcome.Error)
            {
                return "expected Error (never a silent http fallback) when the https attempt fails and AllowHttpFallbackForSelfUpdate is not set, got " + outcome;
            }
            return null;
        }

        private static string TestToHttpsServerUrlSwapsSchemeAndPortKeepingHostAndPath()
        {
            string result = ToHttpsServerUrl("http://server.example.local:8080/api/v1/inventory", 8443);
            if (result != "https://server.example.local:8443/api/v1/inventory")
            {
                return "expected the scheme and port to be swapped with host and path unchanged, got: " + result;
            }
            return null;
        }

        private static string TestToHttpsServerUrlReturnsNullForMalformedServerUrl()
        {
            string result = ToHttpsServerUrl("not-a-url", 8443);
            if (result != null)
            {
                return "expected null for a malformed serverUrl, got: " + result;
            }
            return null;
        }

        private static string TestToEnrollUrlSwapsInventorySuffix()
        {
            string result = InventoryCollector.ToEnrollUrl("https://server.example.local/api/v1/inventory");
            if (result != "https://server.example.local/api/v1/client/enroll")
            {
                return "expected the /api/v1/inventory suffix to be swapped for /api/v1/client/enroll, got: " + result;
            }
            return null;
        }

        private static string TestToSoftwareDownloadUrlBuildsExpectedQueryString()
        {
            string url = InventoryCollector.ToSoftwareDownloadUrl("https://server.example.com/api/v1/inventory", "windowsUpdate", "entry-1");
            string expected = "https://server.example.com/api/v1/client/software-download?catalogType=windowsUpdate&id=entry-1";
            if (url != expected)
            {
                return "expected '" + expected + "', got: " + url;
            }
            return null;
        }

        private static string TestTryEnrollIfNeededCoreSkipsWhenTokenAlreadySet()
        {
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "https://server.example.local/api/v1/inventory";
            options.Token = "already-have-a-real-token";
            options.EnrollmentToken = "some-bootstrap-secret";
            InventoryCollector collector = new InventoryCollector(options);

            bool postJsonCalled = false;
            collector.TryEnrollIfNeededCore((url, json, token) => { postJsonCalled = true; return "{}"; }, token => { throw new InvalidOperationException("applyLearnedToken must never be called when postJson itself was never called"); });

            if (postJsonCalled)
            {
                return "expected TryEnrollIfNeededCore to never call postJson once Token is already set";
            }
            return null;
        }

        private static string TestTryEnrollIfNeededCoreSkipsWhenNoEnrollmentTokenConfigured()
        {
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "https://server.example.local/api/v1/inventory";
            options.Token = "";
            options.EnrollmentToken = "";
            InventoryCollector collector = new InventoryCollector(options);

            bool postJsonCalled = false;
            collector.TryEnrollIfNeededCore((url, json, token) => { postJsonCalled = true; return "{}"; }, token => { throw new InvalidOperationException("applyLearnedToken must never be called when postJson itself was never called"); });

            if (postJsonCalled)
            {
                return "expected TryEnrollIfNeededCore to never call postJson when no EnrollmentToken is configured";
            }
            return null;
        }

        private static string TestTryEnrollIfNeededCoreAppliesIssuedTokenFromResponse()
        {
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "https://server.example.local/api/v1/inventory";
            options.Token = "";
            options.EnrollmentToken = "correct-bootstrap-secret";
            InventoryCollector collector = new InventoryCollector(options);

            string capturedUrl = null;
            string capturedToken = null;
            string appliedToken = null;
            collector.TryEnrollIfNeededCore(
                (url, json, token) =>
                {
                    capturedUrl = url;
                    capturedToken = token;
                    return "{\"token\":\"freshly-issued-per-machine-token\"}";
                },
                token => { appliedToken = token; });

            if (capturedUrl != "https://server.example.local/api/v1/client/enroll")
            {
                return "expected postJson to be called against the enroll URL, got: " + capturedUrl;
            }
            if (capturedToken != "correct-bootstrap-secret")
            {
                return "expected postJson to be called with the EnrollmentToken as its auth token, got: " + capturedToken;
            }
            // Deliberately asserts on the injected delegate's captured
            // argument, not on options.Token/the real registry - calling the
            // real ApplyLearnedIngestionToken here would write to the actual
            // HKLM service key (see TryEnrollIfNeededCore's own comment).
            if (appliedToken != "freshly-issued-per-machine-token")
            {
                return "expected the issued token from the response to be passed to applyLearnedToken, got: " + appliedToken;
            }
            return null;
        }

        private static string TestTryEnrollIfNeededCoreSwallowsPostJsonException()
        {
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "https://server.example.local/api/v1/inventory";
            options.Token = "";
            options.EnrollmentToken = "correct-bootstrap-secret";
            InventoryCollector collector = new InventoryCollector(options);

            collector.TryEnrollIfNeededCore((url, json, token) => { throw new InvalidOperationException("Server returned HTTP 401"); }, token => { throw new InvalidOperationException("applyLearnedToken must never be called when postJson itself threw"); });

            if (!String.IsNullOrEmpty(options.Token))
            {
                return "expected options.Token to remain empty when the enroll attempt itself fails";
            }
            return null;
        }

        private static string TestShouldClearTokenForReenrollmentClearsOn401WhenEnrollmentTokenConfigured()
        {
            if (!InventoryCollector.ShouldClearTokenForReenrollment("correct-bootstrap-secret", "Server returned HTTP 401"))
            {
                return "expected true for a 401 failure with EnrollmentToken configured";
            }
            return null;
        }

        private static string TestShouldClearTokenForReenrollmentLeavesTokenAloneWhenNoEnrollmentTokenConfigured()
        {
            if (InventoryCollector.ShouldClearTokenForReenrollment("", "Server returned HTTP 401"))
            {
                return "expected false when no EnrollmentToken is configured - clearing Token here would strand the client with no credential at all, since it has nothing to re-enroll with";
            }
            return null;
        }

        private static string TestShouldClearTokenForReenrollmentLeavesTokenAloneForNonAuthFailures()
        {
            if (InventoryCollector.ShouldClearTokenForReenrollment("correct-bootstrap-secret", "Server returned HTTP 500"))
            {
                return "expected false for a non-401 failure - a transient server error must never throw away a token that may still be valid";
            }
            if (InventoryCollector.ShouldClearTokenForReenrollment("correct-bootstrap-secret", "Unable to connect to the remote server"))
            {
                return "expected false for a network-level failure with no HTTP status at all";
            }
            return null;
        }

        private static string TestRunOneJobRefusesToRunWhenDownloadedContentDoesNotMatchExpectedHash()
        {
            ClientOptions options = new ClientOptions();
            Program.InventoryService.SoftwareJobRunner runner = new Program.InventoryService.SoftwareJobRunner(options, true);

            Dictionary<string, object> job = new Dictionary<string, object>();
            job["id"] = "entry-1";
            job["catalogType"] = "windowsUpdate";
            job["relativePath"] = @"windows-updates\KB1111111.exe";
            job["arguments"] = "";
            job["requiresReboot"] = false;
            job["contentSha256"] = "0000000000000000000000000000000000000000000000000000000000000000000000000000"; // 64 hex chars, deliberately wrong

            Dictionary<string, object> result = runner.RunOneJob(job, (url, token, destPath) =>
            {
                byte[] tamperedContent = Encoding.UTF8.GetBytes("not what the server expects");
                File.WriteAllBytes(destPath, tamperedContent);
                using (SHA256 sha256 = SHA256.Create())
                {
                    return BitConverter.ToString(sha256.ComputeHash(tamperedContent)).Replace("-", "").ToLowerInvariant();
                }
            });

            if (Convert.ToBoolean(result["success"]))
            {
                return "expected the job to fail when downloaded content does not match contentSha256";
            }
            string errorMessage = Convert.ToString(result["errorMessage"]);
            if (errorMessage.IndexOf("does not match", StringComparison.OrdinalIgnoreCase) < 0)
            {
                return "expected a hash-mismatch errorMessage, got: " + errorMessage;
            }
            return null;
        }

        private static string TestRunOneJobSkipsVerificationWhenJobHasNoContentSha256()
        {
            ClientOptions options = new ClientOptions();
            Program.InventoryService.SoftwareJobRunner runner = new Program.InventoryService.SoftwareJobRunner(options, true);

            Dictionary<string, object> job = new Dictionary<string, object>();
            job["id"] = "entry-1";
            job["catalogType"] = "windowsUpdate";
            job["relativePath"] = @"windows-updates\KB1111111.exe";
            job["arguments"] = "/S";
            job["requiresReboot"] = false;
            job["contentSha256"] = "";

            Dictionary<string, object> result = runner.RunOneJob(job, (url, token, destPath) =>
            {
                byte[] anyContent = Encoding.UTF8.GetBytes("anything, not verified");
                File.WriteAllBytes(destPath, anyContent);
                using (SHA256 sha256 = SHA256.Create())
                {
                    return BitConverter.ToString(sha256.ComputeHash(anyContent)).Replace("-", "").ToLowerInvariant();
                }
            });

            // Must NOT fail for a hash reason when no contentSha256 is present -
            // it may still fail later (no real installer at the temp path, this
            // self-test never spawns a real process a priori) but the specific
            // hash-mismatch errorMessage from the test above must never appear
            // here, proving the graceful-degrade path is taken instead of a
            // false-positive rejection.
            string errorMessage = result.ContainsKey("errorMessage") ? Convert.ToString(result["errorMessage"]) : "";
            if (errorMessage.IndexOf("does not match", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "expected hash verification to be skipped when contentSha256 is empty, but got a hash-mismatch error";
            }
            return null;
        }

        // DownloadToFileAndComputeSha256 itself needs a real HTTP response
        // to drive, which this self-test suite has no server for - so this
        // exercises the streaming/hashing core it delegates to
        // (StreamToFileAndComputeSha256) directly against a MemoryStream,
        // proving the destination file ends up byte-for-byte identical to
        // the source and the returned hash matches an independently
        // computed one.
        private static string TestStreamToFileAndComputeSha256WritesFileAndComputesCorrectHash()
        {
            // Deliberately larger than one read-buffer's worth (81920 bytes)
            // so this actually exercises TransformBlock being called more
            // than once - the exact scenario a real 0.5-1.5 GB Windows
            // Update file hits and the one this whole streaming rewrite
            // exists to make safe. A single-chunk fixture would pass even
            // if hashing or write offsets were wrong across chunk
            // boundaries. Content varies by position (not all-zero/
            // repeating) so a boundary or offset bug can't hide behind a
            // byte value that happens to repeat.
            byte[] content = new byte[81920 * 2 + 37];
            for (int i = 0; i < content.Length; i++)
            {
                content[i] = (byte)(i % 256);
            }
            string expectedHash;
            using (SHA256 sha256 = SHA256.Create())
            {
                expectedHash = BitConverter.ToString(sha256.ComputeHash(content)).Replace("-", "").ToLowerInvariant();
            }

            string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                string actualHash;
                using (MemoryStream sourceStream = new MemoryStream(content))
                {
                    actualHash = InventoryCollector.StreamToFileAndComputeSha256(sourceStream, tempPath);
                }

                if (!String.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    return "expected hash " + expectedHash + " but got " + actualHash;
                }

                byte[] writtenContent = File.ReadAllBytes(tempPath);
                if (writtenContent.Length != content.Length)
                {
                    return "expected the destination file to contain " + content.Length + " bytes, found " + writtenContent.Length;
                }
                for (int i = 0; i < content.Length; i++)
                {
                    if (writtenContent[i] != content[i])
                    {
                        return "destination file content differs from the source stream at byte " + i;
                    }
                }
                return null;
            }
            finally
            {
                try { File.Delete(tempPath); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsSignatureRequiredWhenMissing()
        {
            // Both targets' keys are set - see the comment on
            // TestApplySelfUpdateFromServerCoreReturnsHttpsRequiredForHttpServerUrl
            // above for why. The signature check sits AFTER the hash-match
            // check (Core only reaches it once the downloaded bytes are
            // already proven to be what the server advertised) - so the hash
            // must genuinely match the injected download below (new
            // byte[0]), not an arbitrary placeholder, or the hash check
            // itself would return HashMismatch before the signature check is
            // ever reached. This is the well-known SHA-256 of an empty byte
            // array.
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "https://server.example.local/api/v1/inventory";
            options.RequireSignatureForSelfUpdate = true;
            RSACryptoServiceProvider testKey = new RSACryptoServiceProvider(2048);
            RSAParameters testPublic = testKey.ExportParameters(false);
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) => new byte[0], (fileName, arguments) => true, testPublic.Modulus, testPublic.Exponent);
            if (outcome != SelfUpdateOutcome.NoHashAdvertised && outcome != SelfUpdateOutcome.SignatureRequired)
            {
                return "expected NoHashAdvertised (hash check runs first) or SignatureRequired, got " + outcome;
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsSignatureMismatchForBadSignature()
        {
            string exePath = Path.Combine(Path.GetTempPath(), "wil-selftest-badsig-" + Guid.NewGuid().ToString("N") + ".exe");
            byte[] newContent = Encoding.ASCII.GetBytes("new-build-content-for-signature-test");
            string hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
            }
            // Both targets' keys are set - see the comment on
            // TestApplySelfUpdateFromServerCoreReturnsHttpsRequiredForHttpServerUrl
            // above for why.
            string badSignature = Convert.ToBase64String(Encoding.ASCII.GetBytes("not-a-real-signature"));
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = hash;
            update["sigNet35"] = badSignature;
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = hash;
            update["sigNet40"] = badSignature;
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "https://server.example.local/api/v1/inventory";
            options.RequireSignatureForSelfUpdate = true;
            RSACryptoServiceProvider testKey = new RSACryptoServiceProvider(2048);
            RSAParameters testPublic = testKey.ExportParameters(false);
            try
            {
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) => newContent, (fileName, arguments) => true, testPublic.Modulus, testPublic.Exponent);
                if (outcome != SelfUpdateOutcome.SignatureMismatch)
                {
                    return "expected SignatureMismatch, got " + outcome;
                }
                if (File.Exists(exePath + ".new"))
                {
                    return "expected the staged .new file to NOT be written when signature verification fails";
                }
                return null;
            }
            finally
            {
                try { File.Delete(exePath + ".new"); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreAppliesWithValidSignature()
        {
            string exePath = Path.Combine(Path.GetTempPath(), "wil-selftest-goodsig-" + Guid.NewGuid().ToString("N") + ".exe");
            byte[] newContent = Encoding.ASCII.GetBytes("new-build-content-with-a-real-valid-signature");
            string hash;
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
            }
            RSACryptoServiceProvider testKey = new RSACryptoServiceProvider(2048);
            byte[] signature = testKey.SignData(newContent, "SHA256");
            RSAParameters testPublic = testKey.ExportParameters(false);

            // Both targets' keys are set - see the comment on
            // TestApplySelfUpdateFromServerCoreReturnsHttpsRequiredForHttpServerUrl
            // above for why.
            string signatureBase64 = Convert.ToBase64String(signature);
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["sha256Net35"] = hash;
            update["sigNet35"] = signatureBase64;
            update["versionNet40"] = "9.9.9";
            update["sha256Net40"] = hash;
            update["sigNet40"] = signatureBase64;
            ClientOptions options = new ClientOptions();
            options.ServerUrl = "https://server.example.local/api/v1/inventory";
            options.RequireSignatureForSelfUpdate = true;
            try
            {
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) => newContent, (fileName, arguments) => true, testPublic.Modulus, testPublic.Exponent);
                if (outcome != SelfUpdateOutcome.Applied)
                {
                    return "expected Applied with a genuinely valid signature, got " + outcome;
                }
                return null;
            }
            finally
            {
                try { File.Delete(exePath + ".new"); } catch { }
                try { File.Delete(Path.Combine(Path.GetDirectoryName(exePath), "wil-self-update.cmd")); } catch { }
            }
        }

        // Guards against the exact regression a final review caught in this
        // feature: the pinned key constants are consumed by
        // Convert.FromBase64String at real-wrapper call time
        // (ApplySelfUpdateFromServer), never by ApplySelfUpdateFromServerCore
        // itself, so every other self-test in this file - which all call
        // Core directly - gave 0 FAIL even while the shipped Modulus
        // constant was, for one commit, invalid base64 that would have
        // thrown on every real self-update attempt regardless of either
        // flag. This test is the one place that actually exercises the
        // real constants' decodability.
        private static string TestSelfUpdatePublicKeyConstantsAreValidBase64()
        {
            byte[] modulus;
            byte[] exponent;
            try
            {
                modulus = Convert.FromBase64String(SelfUpdatePublicKeyModulusBase64);
                exponent = Convert.FromBase64String(SelfUpdatePublicKeyExponentBase64);
            }
            catch (FormatException ex)
            {
                return "expected both pinned public key constants to be valid base64, but decoding threw: " + ex.Message;
            }
            if (modulus.Length == 0)
            {
                return "expected a non-empty decoded modulus";
            }
            if (exponent.Length == 0)
            {
                return "expected a non-empty decoded exponent";
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsNoHashAdvertisedWhenHashIsEmpty()
        {
            Dictionary<string, object> update = new Dictionary<string, object>();
            update["versionNet35"] = "9.9.9";
            update["versionNet40"] = "9.9.9";
            update["sha256Net35"] = "";
            update["sha256Net40"] = "";
            ClientOptions options = new ClientOptions();
            SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, @"C:\fake\WindowsInventoryLiteClient.exe", "0.5.1", options, (url, token) => new byte[0], (fileName, arguments) => true, null, null);

            if (outcome != SelfUpdateOutcome.NoHashAdvertised)
            {
                return "expected NoHashAdvertised when the hash key is present but empty, got " + outcome;
            }
            return null;
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsHashMismatchAndLeavesFileUntouched()
        {
            string dir = Path.Combine(Path.GetTempPath(), "wil-selftest-selfupdatehashmismatch-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string exePath = Path.Combine(dir, "WindowsInventoryLiteClient.exe");
                byte[] originalContent = Encoding.ASCII.GetBytes("original-exe-content");
                File.WriteAllBytes(exePath, originalContent);

                Dictionary<string, object> update = BuildSelfTestUpdateAck("9.9.9", "0000000000000000000000000000000000000000000000000000000000000000");
                ClientOptions options = new ClientOptions();
                options.ServerUrl = "http://example.invalid/api/v1/inventory";
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) => Encoding.ASCII.GetBytes("downloaded-content-that-does-not-match-the-hash"), (fileName, arguments) => true, null, null);

                if (outcome != SelfUpdateOutcome.HashMismatch)
                {
                    return "expected HashMismatch when the downloaded bytes don't match the advertised hash, got " + outcome;
                }
                byte[] afterContent = File.ReadAllBytes(exePath);
                if (Encoding.ASCII.GetString(afterContent) != Encoding.ASCII.GetString(originalContent))
                {
                    return "expected the original exe to be untouched after a hash mismatch";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsTaskCreateFailedWhenSchtasksCreateFails()
        {
            string dir = Path.Combine(Path.GetTempPath(), "wil-selftest-selfupdatetaskcreatefail-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string exePath = Path.Combine(dir, "WindowsInventoryLiteClient.exe");
                File.WriteAllBytes(exePath, Encoding.ASCII.GetBytes("original-exe-content"));

                byte[] newContent = Encoding.ASCII.GetBytes("new-exe-content");
                string actualHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    actualHash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
                }

                Dictionary<string, object> update = BuildSelfTestUpdateAck("9.9.9", actualHash);
                ClientOptions options = new ClientOptions();
                options.ServerUrl = "http://example.invalid/api/v1/inventory";
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) => newContent, (fileName, arguments) => false, null, null);

                if (outcome != SelfUpdateOutcome.TaskCreateFailed)
                {
                    return "expected TaskCreateFailed when the injected schtasks call always returns false, got " + outcome;
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsTaskRunFailedWhenSchtasksRunFails()
        {
            string dir = Path.Combine(Path.GetTempPath(), "wil-selftest-selfupdatetaskrunfail-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string exePath = Path.Combine(dir, "WindowsInventoryLiteClient.exe");
                File.WriteAllBytes(exePath, Encoding.ASCII.GetBytes("original-exe-content"));

                byte[] newContent = Encoding.ASCII.GetBytes("new-exe-content");
                string actualHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    actualHash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
                }

                Dictionary<string, object> update = BuildSelfTestUpdateAck("9.9.9", actualHash);
                ClientOptions options = new ClientOptions();
                options.ServerUrl = "http://example.invalid/api/v1/inventory";
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) => newContent,
                    (fileName, arguments) => arguments.IndexOf("/Create", StringComparison.OrdinalIgnoreCase) >= 0, null, null);

                if (outcome != SelfUpdateOutcome.TaskRunFailed)
                {
                    return "expected TaskRunFailed when /Create succeeds but /Run does not, got " + outcome;
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsAppliedAndWritesExpectedFiles()
        {
            string dir = Path.Combine(Path.GetTempPath(), "wil-selftest-selfupdateapplied-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string exePath = Path.Combine(dir, "WindowsInventoryLiteClient.exe");
                File.WriteAllBytes(exePath, Encoding.ASCII.GetBytes("original-exe-content"));

                byte[] newContent = Encoding.ASCII.GetBytes("new-exe-content");
                string actualHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    actualHash = BitConverter.ToString(sha256.ComputeHash(newContent)).Replace("-", "").ToLowerInvariant();
                }

                Dictionary<string, object> update = BuildSelfTestUpdateAck("9.9.9", actualHash);
                ClientOptions options = new ClientOptions();
                options.ServerUrl = "http://example.invalid/api/v1/inventory";
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options, (url, token) => newContent, (fileName, arguments) => true, null, null);

                if (outcome != SelfUpdateOutcome.Applied)
                {
                    return "expected Applied when download, hash check, and both schtasks calls all succeed, got " + outcome;
                }

                string newExePath = exePath + ".new";
                if (!File.Exists(newExePath))
                {
                    return "expected " + newExePath + " to have been written";
                }
                byte[] writtenNewExe = File.ReadAllBytes(newExePath);
                if (Encoding.ASCII.GetString(writtenNewExe) != Encoding.ASCII.GetString(newContent))
                {
                    return "expected the written .new file to contain the downloaded bytes";
                }

                string cmdPath = Path.Combine(dir, "wil-self-update.cmd");
                if (!File.Exists(cmdPath))
                {
                    return "expected " + cmdPath + " to have been written";
                }
                string writtenCmd = File.ReadAllText(cmdPath, Encoding.ASCII);
                string expectedCmd = BuildSelfUpdateCmdScript(exePath, newExePath, "NUL");
                if (writtenCmd != expectedCmd)
                {
                    return "expected the written .cmd content to match BuildSelfUpdateCmdScript's own output exactly";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        private static string TestApplySelfUpdateFromServerCoreReturnsErrorWhenDownloadThrows()
        {
            string dir = Path.Combine(Path.GetTempPath(), "wil-selftest-selfupdateerror-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string exePath = Path.Combine(dir, "WindowsInventoryLiteClient.exe");
                byte[] originalContent = Encoding.ASCII.GetBytes("original-exe-content");
                File.WriteAllBytes(exePath, originalContent);

                Dictionary<string, object> update = BuildSelfTestUpdateAck("9.9.9", "aaaa");
                ClientOptions options = new ClientOptions();
                options.ServerUrl = "http://example.invalid/api/v1/inventory";
                SelfUpdateOutcome outcome = ApplySelfUpdateFromServerCore(update, exePath, "0.5.1", options,
                    (url, token) => { throw new InvalidOperationException("simulated download failure"); },
                    (fileName, arguments) => true, null, null);

                if (outcome != SelfUpdateOutcome.Error)
                {
                    return "expected Error when the injected download throws, got " + outcome;
                }
                byte[] afterContent = File.ReadAllBytes(exePath);
                if (Encoding.ASCII.GetString(afterContent) != Encoding.ASCII.GetString(originalContent))
                {
                    return "expected the original exe to be completely untouched when download throws before any file write";
                }
                if (File.Exists(exePath + ".new") || File.Exists(exePath + ".bak") || File.Exists(Path.Combine(dir, "wil-self-update.cmd")))
                {
                    return "expected no .new/.bak/.cmd file to exist when download throws before any file write";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        private static string TestLoadLearnedStateReturnsEmptyDictWhenNoFileExists()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "wil-selftest-learnedstate-empty-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(tempDir);
                ClientOptions options = new ClientOptions();
                options.OutputPath = tempDir;
                InventoryCollector collector = new InventoryCollector(options);

                Dictionary<string, object> result = collector.LoadLearnedState();
                if (result == null)
                {
                    return "expected a non-null empty dictionary when no cache file exists, got null";
                }
                if (result.Count != 0)
                {
                    return "expected an empty dictionary when no cache file exists, got " + result.Count + " entries";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static string TestSaveLearnedStateRoundTripsMixedValueTypes()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "wil-selftest-learnedstate-roundtrip-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(tempDir);
                ClientOptions options = new ClientOptions();
                options.OutputPath = tempDir;
                InventoryCollector collector = new InventoryCollector(options);

                Dictionary<string, object> toSave = new Dictionary<string, object>();
                toSave["intervalHours"] = 8;
                ArrayList sources = new ArrayList();
                Dictionary<string, object> oneSource = new Dictionary<string, object>();
                oneSource["product"] = "Test Product";
                oneSource["registryHive"] = "HKEY_LOCAL_MACHINE";
                oneSource["registryPath"] = @"SOFTWARE\Test";
                oneSource["valueName"] = "Key";
                sources.Add(oneSource);
                toSave["licenseKeySources"] = sources;

                collector.SaveLearnedState(toSave);
                Dictionary<string, object> loaded = collector.LoadLearnedState();

                if (!loaded.ContainsKey("intervalHours") || Convert.ToInt32(loaded["intervalHours"]) != 8)
                {
                    return "expected intervalHours=8 to round-trip, got: " + (loaded.ContainsKey("intervalHours") ? loaded["intervalHours"].ToString() : "(missing)");
                }
                if (!loaded.ContainsKey("licenseKeySources"))
                {
                    return "expected licenseKeySources to round-trip, key is missing";
                }
                ArrayList loadedSources = loaded["licenseKeySources"] as ArrayList;
                if (loadedSources == null || loadedSources.Count != 1)
                {
                    return "expected exactly one license key source to round-trip";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static string TestSaveLearnedStatePersistsWsusLastScanAtUtcKey()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "wil-selftest-learnedstate-wsuslastscan-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(tempDir);
                ClientOptions options = new ClientOptions();
                options.OutputPath = tempDir;
                InventoryCollector collector = new InventoryCollector(options);

                Dictionary<string, object> learned = new Dictionary<string, object>();
                learned["wsusScannedCabHash"] = "abc123";
                DateTime now = DateTime.UtcNow;
                learned["wsusLastScanAtUtc"] = now.ToString("o");
                collector.SaveLearnedState(learned);

                Dictionary<string, object> reloaded = collector.LoadLearnedState();
                if (!reloaded.ContainsKey("wsusLastScanAtUtc"))
                {
                    return "expected wsusLastScanAtUtc to round-trip through SaveLearnedState/LoadLearnedState";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static string TestApplyInventoryAckResponsePreservesUnrelatedLearnedFields()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "wil-selftest-learnedstate-preserve-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(tempDir);
                ClientOptions options = new ClientOptions();
                options.OutputPath = tempDir;
                options.IntervalHours = 6;
                InventoryCollector collector = new InventoryCollector(options);

                string ackWithLicenseKeysOnly = "{\"licenseKeySources\":[{\"product\":\"P\",\"registryHive\":\"HKEY_LOCAL_MACHINE\",\"registryPath\":\"SOFTWARE\\\\P\",\"valueName\":\"V\"}]}";
                collector.ApplyInventoryAckResponse(ackWithLicenseKeysOnly);

                string ackWithIntervalOnly = "{\"config\":{\"intervalHours\":9}}";
                collector.ApplyInventoryAckResponse(ackWithIntervalOnly);

                Dictionary<string, object> learned = collector.LoadLearnedState();
                if (!learned.ContainsKey("licenseKeySources"))
                {
                    return "expected licenseKeySources to survive a later ack that only touched intervalHours";
                }
                if (!learned.ContainsKey("intervalHours") || Convert.ToInt32(learned["intervalHours"]) != 9)
                {
                    return "expected intervalHours=9 to be applied by the second ack";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static string TestApplyInventoryAckResponseReturnsIndependentFlagsForEachType()
        {
            ClientOptions options = new ClientOptions();
            InventoryCollector collector = new InventoryCollector(options);

            ForceImmediateCheckFlags bothTrue = collector.ApplyInventoryAckResponse("{\"status\":\"ok\",\"forceImmediateWindowsUpdateCheck\":true,\"forceImmediateThirdPartySoftwareCheck\":true}");
            if (!bothTrue.WindowsUpdate || !bothTrue.ThirdPartySoftware)
            {
                return "expected both flags true when the ack sets both";
            }

            ForceImmediateCheckFlags onlyWindowsUpdate = collector.ApplyInventoryAckResponse("{\"status\":\"ok\",\"forceImmediateWindowsUpdateCheck\":true,\"forceImmediateThirdPartySoftwareCheck\":false}");
            if (!onlyWindowsUpdate.WindowsUpdate || onlyWindowsUpdate.ThirdPartySoftware)
            {
                return "expected only WindowsUpdate true when the ack sets only that one - flags must be independent";
            }

            ForceImmediateCheckFlags neither = collector.ApplyInventoryAckResponse("{\"status\":\"ok\"}");
            if (neither.WindowsUpdate || neither.ThirdPartySoftware)
            {
                return "expected both false when the ack has neither field";
            }

            ForceImmediateCheckFlags malformed = collector.ApplyInventoryAckResponse("not valid json");
            if (malformed.WindowsUpdate || malformed.ThirdPartySoftware)
            {
                return "expected both false for a malformed ack response (must never throw)";
            }
            return null;
        }

        private static string TestApplyConfigFromServerValidatesIntervalRange()
        {
            ClientOptions options = new ClientOptions();
            options.IntervalHours = 6;
            InventoryCollector collector = new InventoryCollector(options);
            Dictionary<string, object> learned = new Dictionary<string, object>();

            Dictionary<string, object> outOfRangeConfig = new Dictionary<string, object>();
            outOfRangeConfig["intervalHours"] = 0;
            bool changedOutOfRange = collector.ApplyConfigFromServer(outOfRangeConfig, learned);
            if (changedOutOfRange || learned.ContainsKey("intervalHours") || options.IntervalHours != 6)
            {
                return "expected an out-of-range intervalHours (0) to be ignored entirely";
            }

            Dictionary<string, object> inRangeConfig = new Dictionary<string, object>();
            inRangeConfig["intervalHours"] = 12;
            bool changedInRange = collector.ApplyConfigFromServer(inRangeConfig, learned);
            if (!changedInRange || !learned.ContainsKey("intervalHours") || options.IntervalHours != 12)
            {
                return "expected an in-range, different intervalHours (12) to be applied to both options and learned";
            }
            return null;
        }

        private static string TestLoadLicenseKeySourcesCacheParsesEntryWrittenThroughAckResponse()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "wil-selftest-learnedstate-licensekeys-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(tempDir);
                ClientOptions options = new ClientOptions();
                options.OutputPath = tempDir;
                InventoryCollector collector = new InventoryCollector(options);

                string ack = "{\"licenseKeySources\":[{\"product\":\"KriptoPro\",\"registryHive\":\"HKEY_LOCAL_MACHINE\",\"registryPath\":\"SOFTWARE\\\\WOW6432Node\\\\Test\",\"valueName\":\"SerialNumber\"}]}";
                collector.ApplyInventoryAckResponse(ack);

                List<LicenseKeySource> parsed = collector.LoadLicenseKeySourcesCache();
                if (parsed.Count != 1)
                {
                    return "expected exactly one parsed license key source, got " + parsed.Count;
                }
                if (parsed[0].Product != "KriptoPro" || parsed[0].ValueName != "SerialNumber")
                {
                    return "expected the parsed source's fields to match what was written, got Product='" + parsed[0].Product + "' ValueName='" + parsed[0].ValueName + "'";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        // Regression coverage for a real gap: licenseKeySources is learned
        // entirely from the server's inventory-ack response with no
        // validation - without IsAllowedLicenseKeySourcePath, a compromised
        // server could direct every client to read and report back any
        // HKLM/HKCU value (e.g. SAM, SECURITY) under cover of ordinary
        // inventory telemetry. Every legitimate source lives under the
        // SOFTWARE subtree; anything else must be dropped at load time.
        private static string TestLoadLicenseKeySourcesCacheRejectsSourceOutsideSoftwareSubtree()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "wil-selftest-learnedstate-licensekeys-reject-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(tempDir);
                ClientOptions options = new ClientOptions();
                options.OutputPath = tempDir;
                InventoryCollector collector = new InventoryCollector(options);

                string ack = "{\"licenseKeySources\":["
                    + "{\"product\":\"Malicious\",\"registryHive\":\"HKEY_LOCAL_MACHINE\",\"registryPath\":\"SAM\\\\SAM\\\\Domains\",\"valueName\":\"F\"},"
                    + "{\"product\":\"AlsoMalicious\",\"registryHive\":\"HKEY_LOCAL_MACHINE\",\"registryPath\":\"SECURITY\\\\Policy\\\\Secrets\",\"valueName\":\"X\"},"
                    + "{\"product\":\"KriptoPro\",\"registryHive\":\"HKEY_LOCAL_MACHINE\",\"registryPath\":\"SOFTWARE\\\\WOW6432Node\\\\Test\",\"valueName\":\"SerialNumber\"}"
                    + "]}";
                collector.ApplyInventoryAckResponse(ack);

                List<LicenseKeySource> parsed = collector.LoadLicenseKeySourcesCache();
                if (parsed.Count != 1)
                {
                    return "expected only the one SOFTWARE-subtree source to survive, got " + parsed.Count + " entries";
                }
                if (parsed[0].Product != "KriptoPro")
                {
                    return "expected the surviving source to be the legitimate SOFTWARE-subtree one, got Product='" + parsed[0].Product + "'";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static string TestWsusScannerShouldRescanCompares()
        {
            if (!WsusScanner.ShouldRescan("abc123", "", null, 7, false))
            {
                return "expected true when the client has never scanned (empty last-scanned hash)";
            }
            if (!WsusScanner.ShouldRescan("abc123", "def456", null, 7, false))
            {
                return "expected true when the hashes differ";
            }
            if (WsusScanner.ShouldRescan("abc123", "abc123", null, 7, false))
            {
                return "expected false when the hashes already match and no scan timestamp is on record (avoids an upgrade-day rescan storm)";
            }
            if (WsusScanner.ShouldRescan("", "abc123", null, 7, false))
            {
                return "expected false when the server has no cab configured (empty server hash), regardless of the client's own last-scanned hash";
            }
            if (WsusScanner.ShouldRescan("abc123", "abc123", DateTime.UtcNow.AddDays(-1), 7, false))
            {
                return "expected false when the hashes match and the last scan is well within the max age";
            }
            if (!WsusScanner.ShouldRescan("abc123", "abc123", DateTime.UtcNow.AddDays(-8), 7, false))
            {
                return "expected true when the hashes match but the last scan is older than the configured max age";
            }
            if (!WsusScanner.ShouldRescan("abc123", "xyz999", DateTime.UtcNow, 7, true))
            {
                return "expected true when force is set, regardless of hash or age";
            }
            if (WsusScanner.ShouldRescan("", "abc123", null, 7, true))
            {
                return "expected false even under force when the server has no cab configured at all - nothing to scan against";
            }
            return null;
        }

        private static string TestDownloadAndVerifyWsusCabSucceedsOnHashMatch()
        {
            string tempPath = Path.Combine(Path.GetTempPath(), "wil-selftest-cabverify-" + Guid.NewGuid().ToString("N") + ".cab");
            try
            {
                byte[] fakeContent = Encoding.UTF8.GetBytes("fake cab content");
                string expectedHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    expectedHash = BitConverter.ToString(sha256.ComputeHash(fakeContent)).Replace("-", "").ToLowerInvariant();
                }
                Func<string, string, byte[]> fakeDownload = (url, token) => fakeContent;

                bool result = DownloadAndVerifyWsusCab("https://server", "token", expectedHash, tempPath, fakeDownload);
                if (!result)
                {
                    return "expected DownloadAndVerifyWsusCab to return true when the hash matches";
                }
                if (!File.Exists(tempPath) || !Encoding.UTF8.GetString(File.ReadAllBytes(tempPath)).Equals("fake cab content"))
                {
                    return "expected the cab file to be written with the downloaded bytes";
                }
                return null;
            }
            finally
            {
                try { File.Delete(tempPath); } catch { }
            }
        }

        private static string TestDownloadAndVerifyWsusCabFailsOnHashMismatch()
        {
            string tempPath = Path.Combine(Path.GetTempPath(), "wil-selftest-cabverifybad-" + Guid.NewGuid().ToString("N") + ".cab");
            try
            {
                Func<string, string, byte[]> fakeDownload = (url, token) => Encoding.UTF8.GetBytes("wrong content");
                bool result = DownloadAndVerifyWsusCab("https://server", "token", "0000000000000000000000000000000000000000000000000000000000000000", tempPath, fakeDownload);
                if (result)
                {
                    return "expected DownloadAndVerifyWsusCab to return false when the hash does not match";
                }
                if (File.Exists(tempPath))
                {
                    return "expected the cab file NOT to be written when hash verification fails";
                }
                return null;
            }
            finally
            {
                try { File.Delete(tempPath); } catch { }
            }
        }

        private static string TestPostWsusScanResultsReturnsTrueAndPostsExpectedFieldsOnSuccess()
        {
            string capturedJson = null;
            Func<string, string, string, string> fakePostJson = (url, json, token) =>
            {
                capturedJson = json;
                return "{}";
            };

            List<Dictionary<string, object>> missingUpdates = new List<Dictionary<string, object>>();
            Dictionary<string, object> oneUpdate = new Dictionary<string, object>();
            oneUpdate["kb"] = "KB1234567";
            missingUpdates.Add(oneUpdate);

            bool result = PostWsusScanResults("https://server/api/v1/inventory", "token", "TEST-PC", "abc123", true, missingUpdates, fakePostJson);
            if (!result)
            {
                return "expected PostWsusScanResults to return true when the injected postJson succeeds";
            }
            if (capturedJson == null)
            {
                return "expected postJson to be called with a JSON body";
            }

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(capturedJson);
            if (!parsed.ContainsKey("computerName") || (string)parsed["computerName"] != "TEST-PC")
            {
                return "expected the posted JSON to contain computerName='TEST-PC', got: " + capturedJson;
            }
            if (!parsed.ContainsKey("cabHash") || (string)parsed["cabHash"] != "abc123")
            {
                return "expected the posted JSON to contain cabHash='abc123', got: " + capturedJson;
            }
            if (!parsed.ContainsKey("wuServiceAvailable") || !(bool)parsed["wuServiceAvailable"])
            {
                return "expected the posted JSON to contain wuServiceAvailable=true, got: " + capturedJson;
            }
            if (!parsed.ContainsKey("missingUpdates") || !(parsed["missingUpdates"] is ArrayList) || ((ArrayList)parsed["missingUpdates"]).Count != 1)
            {
                return "expected the posted JSON to contain a one-element missingUpdates array, got: " + capturedJson;
            }
            return null;
        }

        private static string TestPostWsusScanResultsReturnsFalseWhenPostJsonThrows()
        {
            Func<string, string, string, string> throwingPostJson = (url, json, token) =>
            {
                throw new InvalidOperationException("simulated HTTP failure");
            };

            bool result = PostWsusScanResults("https://server/api/v1/inventory", "token", "TEST-PC", "abc123", true, new List<Dictionary<string, object>>(), throwingPostJson);
            if (result)
            {
                return "expected PostWsusScanResults to return false when the injected postJson throws";
            }
            return null;
        }

        private static string TestResolveInstallerLaunchDispatchesMsiToMsiexec()
        {
            string fileName;
            string processArguments;
            ResolveInstallerLaunch(".msi", @"C:\temp\pkg.msi", "/qn", out fileName, out processArguments);
            if (fileName != "msiexec.exe")
            {
                return "expected .msi to dispatch to msiexec.exe, got: " + fileName;
            }
            if (processArguments != "/i \"C:\\temp\\pkg.msi\" /qn")
            {
                return "expected msiexec arguments to be '/i \"<path>\" <arguments>', got: " + processArguments;
            }
            return null;
        }

        private static string TestResolveInstallerLaunchDispatchesMsuToWusa()
        {
            string fileName;
            string processArguments;
            ResolveInstallerLaunch(".msu", @"C:\temp\KB1.msu", "/quiet", out fileName, out processArguments);
            if (fileName != "wusa.exe")
            {
                return "expected .msu to dispatch to wusa.exe, got: " + fileName;
            }
            if (processArguments != "\"C:\\temp\\KB1.msu\" /quiet")
            {
                return "expected wusa arguments to be '\"<path>\" <arguments>', got: " + processArguments;
            }
            return null;
        }

        private static string TestResolveInstallerLaunchDispatchesCabToDism()
        {
            string fileName;
            string processArguments;
            ResolveInstallerLaunch(".cab", @"C:\temp\pkg.cab", "", out fileName, out processArguments);
            if (fileName != "dism.exe")
            {
                return "expected .cab to dispatch to dism.exe, got: " + fileName;
            }
            if (processArguments != "/online /add-package /packagepath:\"C:\\temp\\pkg.cab\" ")
            {
                return "expected dism arguments to be '/online /add-package /packagepath:\"<path>\" <arguments>', got: " + processArguments;
            }
            return null;
        }

        private static string TestResolveInstallerLaunchDefaultsToDirectExecution()
        {
            string fileName;
            string processArguments;
            ResolveInstallerLaunch(".exe", @"C:\temp\setup.exe", "/S", out fileName, out processArguments);
            if (fileName != @"C:\temp\setup.exe")
            {
                return "expected any other extension to launch the downloaded file directly, got: " + fileName;
            }
            if (processArguments != "/S")
            {
                return "expected arguments to pass through unchanged for direct execution, got: " + processArguments;
            }
            return null;
        }

        private static string TestResolveInstallerLaunchHandlesNullArguments()
        {
            string fileName;
            string processArguments;
            ResolveInstallerLaunch(".msi", @"C:\temp\pkg.msi", null, out fileName, out processArguments);
            if (processArguments != "/i \"C:\\temp\\pkg.msi\" ")
            {
                return "expected a null arguments value to be treated as empty, got: " + processArguments;
            }
            return null;
        }

        private static string TestTryFindDangerousInstallerArgumentRejectsMsiPackageSelectionSwitches()
        {
            string[] dangerous = new string[] { "/i", "/a", "/x", "/j", "/p", "/uninstall", "/fpecms", "/f" };
            foreach (string value in dangerous)
            {
                string reason;
                if (!TryFindDangerousInstallerArgument(".msi", value, out reason))
                {
                    return "expected '" + value + "' to be rejected for a .msi installer";
                }
            }
            return null;
        }

        private static string TestTryFindDangerousInstallerArgumentAcceptsLegitimateMsiArguments()
        {
            // /passive and /forcerestart both start with the same two
            // characters as the repair switch ("/f...") or are otherwise
            // easy to mis-flag with a naive prefix check - this is the
            // regression test for that specific false-positive risk.
            string[] legitimate = new string[] { "/qn", "/quiet", "/passive", "/norestart", "/forcerestart", "/promptrestart", "/l*v C:\\log.txt", "TRANSFORMS=x.mst ALLUSERS=1" };
            foreach (string value in legitimate)
            {
                string reason;
                if (TryFindDangerousInstallerArgument(".msi", value, out reason))
                {
                    return "expected legitimate argument '" + value + "' to be accepted for a .msi installer, got reason: " + reason;
                }
            }
            return null;
        }

        private static string TestTryFindDangerousInstallerArgumentRejectsMsuPackageSelectionSwitches()
        {
            string[] dangerous = new string[] { "/uninstall", "/extract", "/extract:C:\\out" };
            foreach (string value in dangerous)
            {
                string reason;
                if (!TryFindDangerousInstallerArgument(".msu", value, out reason))
                {
                    return "expected '" + value + "' to be rejected for a .msu installer";
                }
            }
            return null;
        }

        private static string TestTryFindDangerousInstallerArgumentAcceptsLegitimateMsuArguments()
        {
            string[] legitimate = new string[] { "/quiet", "/norestart", "/forcerestart", "/promptrestart" };
            foreach (string value in legitimate)
            {
                string reason;
                if (TryFindDangerousInstallerArgument(".msu", value, out reason))
                {
                    return "expected legitimate argument '" + value + "' to be accepted for a .msu installer, got reason: " + reason;
                }
            }
            return null;
        }

        private static string TestTryFindDangerousInstallerArgumentRejectsCabPackageSelectionSwitches()
        {
            string[] dangerous = new string[] { "/packagepath:\\\\server\\share\\evil.cab", "/image:D:\\mount", "/add-package", "/remove-package" };
            foreach (string value in dangerous)
            {
                string reason;
                if (!TryFindDangerousInstallerArgument(".cab", value, out reason))
                {
                    return "expected '" + value + "' to be rejected for a .cab installer";
                }
            }
            return null;
        }

        private static string TestTryFindDangerousInstallerArgumentAcceptsLegitimateCabArguments()
        {
            string[] legitimate = new string[] { "/quiet", "/norestart", "/logpath:C:\\dism.log" };
            foreach (string value in legitimate)
            {
                string reason;
                if (TryFindDangerousInstallerArgument(".cab", value, out reason))
                {
                    return "expected legitimate argument '" + value + "' to be accepted for a .cab installer, got reason: " + reason;
                }
            }
            return null;
        }

        private static string TestTryFindDangerousInstallerArgumentNeverRejectsDirectExecution()
        {
            // Direct execution of the downloaded file has no "which
            // package/image" switch convention to smuggle - the file that
            // runs is always the one relativePath already resolved - so
            // nothing is rejected here, even values that look alarming for
            // the other installer types.
            string[] values = new string[] { "/i /packagepath:x /add-package", "/S", "" };
            foreach (string value in values)
            {
                string reason;
                if (TryFindDangerousInstallerArgument(".exe", value, out reason))
                {
                    return "expected direct execution (.exe) to never reject any argument, got reason for '" + value + "': " + reason;
                }
            }
            return null;
        }

        private static string TestTryFindDangerousInstallerArgumentHandlesNullOrEmpty()
        {
            string reason;
            if (TryFindDangerousInstallerArgument(".msi", null, out reason))
            {
                return "expected null arguments to never be rejected";
            }
            if (TryFindDangerousInstallerArgument(".msi", "", out reason))
            {
                return "expected empty arguments to never be rejected";
            }
            return null;
        }

        private static string TestReportJobStartPostsExpectedFieldsAndReturnsTrueOnSuccess()
        {
            string capturedUrl = null;
            string capturedJson = null;
            Func<string, string, string, string> fakePostJson = (url, json, token) =>
            {
                capturedUrl = url;
                capturedJson = json;
                return "{}";
            };

            bool result = InventoryCollector.ReportJobStart("https://server/api/v1/inventory", "token", "TEST-PC", "windowsUpdate", "wu-1", "attempt-abc", fakePostJson);
            if (!result)
            {
                return "expected ReportJobStart to return true when the injected postJson succeeds";
            }
            if (capturedUrl == null || capturedUrl.IndexOf("/api/v1/client/software-jobs/start", StringComparison.Ordinal) < 0)
            {
                return "expected the URL to target /api/v1/client/software-jobs/start, got: " + capturedUrl;
            }

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(capturedJson);
            if ((string)parsed["computerName"] != "TEST-PC" || (string)parsed["catalogType"] != "windowsUpdate" || (string)parsed["id"] != "wu-1" || (string)parsed["attemptId"] != "attempt-abc")
            {
                return "expected the posted JSON to contain computerName/catalogType/id/attemptId exactly as passed in, got: " + capturedJson;
            }
            return null;
        }

        private static string TestReportJobStartReturnsFalseWhenPostJsonThrows()
        {
            Func<string, string, string, string> throwingPostJson = (url, json, token) => { throw new Exception("network down"); };
            bool result = InventoryCollector.ReportJobStart("https://server/api/v1/inventory", "token", "TEST-PC", "windowsUpdate", "wu-1", "attempt-abc", throwingPostJson);
            if (result)
            {
                return "expected ReportJobStart to return false when the injected postJson throws";
            }
            return null;
        }

        // Only the two "definitely do nothing" no-op paths are testable
        // here without real I/O - see MaybeRunWsusScanCore's own comment.
        // Both fakes below assert they are never invoked; a call into
        // either would mean the no-op short-circuit failed.
        private static string TestMaybeRunWsusScanCoreNoOpsWhenHashEmptyOrUnchanged()
        {
            bool scanWasCalled = false;
            Func<string, List<Dictionary<string, object>>> fakeScan = cabPath => { scanWasCalled = true; return new List<Dictionary<string, object>>(); };
            Func<bool> fakeIsWuauservRunning = () => true;
            Func<string, string, bool> fakeDownloadAndVerifyCab = (hash, destPath) => true;
            Func<string, bool, List<Dictionary<string, object>>, bool> fakePostResults = (hash, available, missing) => true;

            bool ranWithEmptyHash = MaybeRunWsusScanCore("", "previous-hash", null, 7, false, fakeIsWuauservRunning, fakeScan, fakeDownloadAndVerifyCab, fakePostResults);
            if (scanWasCalled || ranWithEmptyHash)
            {
                return "expected no scan when wsusCabHash is empty (no cab configured)";
            }

            bool ranWithUnchangedHash = MaybeRunWsusScanCore("same-hash", "same-hash", null, 7, false, fakeIsWuauservRunning, fakeScan, fakeDownloadAndVerifyCab, fakePostResults);
            if (scanWasCalled || ranWithUnchangedHash)
            {
                return "expected no scan when wsusCabHash matches the last-scanned hash already";
            }
            return null;
        }

        private static string TestMaybeRunWsusScanCoreRunsWhenStaleByAgeEvenIfHashUnchanged()
        {
            bool scanRan = false;
            Func<bool> fakeIsWuauservRunning = () => true;
            Func<string, List<Dictionary<string, object>>> fakeScan = (cabPath) => { scanRan = true; return new List<Dictionary<string, object>>(); };
            Func<string, string, bool> fakeDownloadAndVerifyCab = (hash, destPath) => true;
            Func<string, bool, List<Dictionary<string, object>>, bool> fakePostResults = (hash, available, missing) => true;

            bool ran = InventoryCollector.MaybeRunWsusScanCore("same-hash", "same-hash", DateTime.UtcNow.AddDays(-8), 7, false, fakeIsWuauservRunning, fakeScan, fakeDownloadAndVerifyCab, fakePostResults);

            if (!ran || !scanRan)
            {
                return "expected a rescan to run when the hash is unchanged but the last scan exceeds the configured max age";
            }
            return null;
        }

        private static string TestMaybeRunWsusScanCoreRunsWhenForcedEvenIfFreshAndHashUnchanged()
        {
            bool scanRan = false;
            Func<bool> fakeIsWuauservRunning = () => true;
            Func<string, List<Dictionary<string, object>>> fakeScan = (cabPath) => { scanRan = true; return new List<Dictionary<string, object>>(); };
            Func<string, string, bool> fakeDownloadAndVerifyCab = (hash, destPath) => true;
            Func<string, bool, List<Dictionary<string, object>>, bool> fakePostResults = (hash, available, missing) => true;

            bool ran = InventoryCollector.MaybeRunWsusScanCore("same-hash", "same-hash", DateTime.UtcNow, 7, true, fakeIsWuauservRunning, fakeScan, fakeDownloadAndVerifyCab, fakePostResults);

            if (!ran || !scanRan)
            {
                return "expected a rescan to run when forced, even though the hash matches and the last scan is brand new";
            }
            return null;
        }

        // Test-only: the mathematical inverse of DecodeDigitalProductIdKey's
        // core loop - builds a 15-byte buffer from a target base24 digit
        // string via repeated multiply-by-24-and-add-digit with carry
        // propagation (the mirror of the decoder's repeated divide-by-24).
        // No BigInteger (same net35 constraint as the decoder itself) -
        // plain byte-array arithmetic, carry kept in an int (max possible
        // carry well under int range: 255*24+23).
        private static byte[] EncodeDigitalProductIdKeyForTest(string rawKeyNoDashes, bool containsN)
        {
            return EncodeDigitalProductIdKeyForTestAtOffset(rawKeyNoDashes, containsN, 52, 67);
        }

        // Same encoding as EncodeDigitalProductIdKeyForTest, but places the
        // 15 encoded bytes at an arbitrary offset in an arbitrary-sized
        // buffer - used to fabricate a synthetic "Office-shaped" blob (key
        // bytes NOT at Windows' offset 52) for DecodeOfficeDigitalProductIdKey's
        // own tests, without needing a second copy of the encode loop.
        private static byte[] EncodeDigitalProductIdKeyForTestAtOffset(string rawKeyNoDashes, bool containsN, int offset, int totalLength)
        {
            const string base24 = "BCDFGHJKMPQRTVWXY2346789";
            const int keyByteCount = 15;
            byte[] buffer = new byte[keyByteCount];

            string digits = rawKeyNoDashes;
            if (containsN)
            {
                // The decoder reconstructs the N position from the FIRST
                // character of the 24-digit (N-removed) decoded string, then
                // discards that leading character. To round-trip, the encoder
                // must supply that same leading digit - base24[nIndex] -
                // ahead of the remaining 24 non-N digits before running the
                // multiply-by-24 encoding loop below.
                int nIndex = digits.IndexOf('N');
                digits = digits.Remove(nIndex, 1);
                digits = base24[nIndex] + digits;
            }

            // Process most-significant digit first (index 0 of the 25-char
            // string), each step: buffer = buffer * 24 + digit, carry
            // propagated low-byte-first (index 0 = least significant byte,
            // matching the decoder's own j=0..14 convention).
            for (int d = 0; d < digits.Length; d++)
            {
                int digitValue = base24.IndexOf(digits[d]);
                int carry = digitValue;
                for (int j = 0; j <= 14; j++)
                {
                    int product = buffer[j] * 24 + carry;
                    buffer[j] = (byte)(product & 0xFF);
                    carry = product >> 8;
                }
            }

            if (containsN)
            {
                buffer[14] = (byte)(buffer[14] | 0x08);
            }

            byte[] full = new byte[totalLength];
            Array.Copy(buffer, 0, full, offset, keyByteCount);
            return full;
        }

        private static string TestDecodeDigitalProductIdKeyRoundTrip()
        {
            // A real key shape made only of base24 alphabet characters
            // (B,C,D,F,G,H,J,K,M,P,Q,R,T,V,W,X,Y,2,3,4,6,7,8,9 - no vowels,
            // no 0/1/5, matching Microsoft's own alphabet to avoid visual
            // ambiguity) - not a real license, a synthetic round-trip
            // fixture.
            string target = "BCDFG-HJKMP-QRTVW-XY234-6789B";
            string targetNoDashes = target.Replace("-", "");
            byte[] blob = EncodeDigitalProductIdKeyForTest(targetNoDashes, false);
            string decoded = DecodeDigitalProductIdKey(blob);
            if (decoded != target)
            {
                return "expected round-trip decode to reproduce the original key, got '" + decoded + "' expected '" + target + "'";
            }
            return null;
        }

        private static string TestDecodeDigitalProductIdKeyRoundTripWithN()
        {
            // Same alphabet-only key shape as the non-N round-trip test above,
            // but with 'N' spliced into the middle of the 25-char raw key
            // (index 5, not index 0) so this actually exercises the nIndex
            // splice/reinsert logic instead of passing by coincidence via the
            // N-at-position-0 special case.
            string target = "BCDFG-NHJKM-PQRTV-WXY23-46789";
            string targetNoDashes = target.Replace("-", "");
            byte[] blob = EncodeDigitalProductIdKeyForTest(targetNoDashes, true);
            string decoded = DecodeDigitalProductIdKey(blob);
            if (decoded != target)
            {
                return "expected N-key round-trip decode to reproduce the original key, got '" + decoded + "' expected '" + target + "'";
            }
            return null;
        }

        private static string TestDecodeDigitalProductIdKeyDetectsPlaceholder()
        {
            // A real MAK/digital-license machine has nothing meaningful in
            // these bytes - an all-zero 15-byte buffer decodes to all
            // base24[0] ('B'), which must be reported as "no key", not a
            // fake real-looking key.
            byte[] blob = new byte[67]; // all zero
            string decoded = DecodeDigitalProductIdKey(blob);
            if (decoded != null)
            {
                return "expected an all-zero DigitalProductId to decode to null (placeholder), got '" + decoded + "'";
            }
            return null;
        }

        private static string TestDecodeDigitalProductIdKeyHandlesShortInput()
        {
            byte[] tooShort = new byte[10];
            if (DecodeDigitalProductIdKey(tooShort) != null)
            {
                return "expected a too-short DigitalProductId buffer to decode to null, not throw or fabricate a key";
            }

            // Exact boundary: the minimum valid length is
            // keyOffset(52) + keyByteCount(15) = 67 bytes. A 66-byte buffer
            // (one byte short of that) must still decode to null, not throw.
            byte[] oneByteShort = new byte[66];
            if (DecodeDigitalProductIdKey(oneByteShort) != null)
            {
                return "expected a 66-byte (one byte short of the 67-byte minimum) DigitalProductId buffer to decode to null";
            }
            return null;
        }

        private static string TestDecodeOfficeDigitalProductIdKeyFindsNonWindowsOffset()
        {
            // Office's own DigitalProductID doesn't carry the key at
            // Windows' fixed offset 52 - a real Volume License Office 2016
            // install's blob (1272 bytes) had it at offset 808. This fixture
            // mirrors that shape: same alphabet-only key, embedded far from
            // offset 52 in a blob much larger than Windows' ~164 bytes.
            string target = "BCDFG-HJKMP-QRTVW-XY234-6789B";
            string targetNoDashes = target.Replace("-", "");
            byte[] blob = EncodeDigitalProductIdKeyForTestAtOffset(targetNoDashes, false, 808, 1272);
            string decoded = DecodeOfficeDigitalProductIdKey(blob, "6789B");
            if (decoded != target)
            {
                return "expected the scan to find the key at a non-Windows offset, got '" + decoded + "' expected '" + target + "'";
            }
            return null;
        }

        private static string TestDecodeOfficeDigitalProductIdKeyRejectsMismatchedPartial()
        {
            // The real safeguard this exists for: a wrong offset can decode
            // to a plausible-LOOKING key purely by chance (exactly what
            // happened trying offset 52 on a real Office 2016 blob this
            // session) - the scan must never surface such a result just
            // because it decoded to something key-shaped. Here the blob
            // genuinely contains a real key, but the caller's own
            // (deliberately wrong) expected suffix doesn't match it, so the
            // scan must report nothing rather than a false positive.
            string target = "BCDFG-HJKMP-QRTVW-XY234-6789B";
            byte[] blob = EncodeDigitalProductIdKeyForTestAtOffset(target.Replace("-", ""), false, 808, 1272);
            string decoded = DecodeOfficeDigitalProductIdKey(blob, "WRONG");
            if (decoded != null)
            {
                return "expected no match when the decoded key's suffix does not match expectedLastFive, got '" + decoded + "'";
            }
            return null;
        }

        private static string TestDecodeOfficeDigitalProductIdKeyRequiresExpectedSuffix()
        {
            byte[] blob = EncodeDigitalProductIdKeyForTestAtOffset("BCDFGHJKMPQRTVWXY2346789B", false, 808, 1272);
            if (DecodeOfficeDigitalProductIdKey(blob, null) != null || DecodeOfficeDigitalProductIdKey(blob, "") != null || DecodeOfficeDigitalProductIdKey(blob, "BAD") != null)
            {
                return "expected a null/empty/wrong-length expectedLastFive to skip the scan and return null";
            }
            return null;
        }

        // Returns true only if the process both exited within the timeout
        // AND returned a zero exit code - the caller previously ignored
        // both signals and always assumed success.
        private static bool RunHelperProcess(string fileName, string arguments)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo(fileName, arguments);
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            using (Process process = Process.Start(startInfo))
            {
                if (!process.WaitForExit(15000))
                {
                    try { process.Kill(); } catch { }
                    return false;
                }
                return process.ExitCode == 0;
            }
        }

        // Ordinal, numeric-segment version comparison ("1.2.10" > "1.2.9",
        // unlike a plain string compare) - this project's own versions are
        // always simple dotted-numeric (its own versioning convention),
        // so arbitrary semver pre-release/build-metadata suffixes are not
        // handled. Returns true only when candidateVersion is STRICTLY
        // greater than currentVersion; an equal or unparseable value
        // returns false - a client that can't prove a build is actually
        // newer must never apply it.
        internal static bool IsVersionNewer(string candidateVersion, string currentVersion)
        {
            int[] candidateParts = ParseVersionParts(candidateVersion);
            int[] currentParts = ParseVersionParts(currentVersion);
            if (candidateParts == null || currentParts == null)
            {
                return false;
            }
            int segmentCount = Math.Max(candidateParts.Length, currentParts.Length);
            for (int i = 0; i < segmentCount; i++)
            {
                int candidateSegment = i < candidateParts.Length ? candidateParts[i] : 0;
                int currentSegment = i < currentParts.Length ? currentParts[i] : 0;
                if (candidateSegment != currentSegment)
                {
                    return candidateSegment > currentSegment;
                }
            }
            return false;
        }

        private static int[] ParseVersionParts(string version)
        {
            if (String.IsNullOrEmpty(version))
            {
                return null;
            }
            string[] segments = version.Split('.');
            int[] parts = new int[segments.Length];
            for (int i = 0; i < segments.Length; i++)
            {
                int value;
                if (!Int32.TryParse(segments[i], out value))
                {
                    return null;
                }
                parts[i] = value;
            }
            return parts;
        }

        // internal rather than private so SoftwareJobRunner can post job
        // results through the same request shape the inventory report uses.
        internal static string PostJson(string url, string json, string token)
        {
            if (url.StartsWith("https:", StringComparison.OrdinalIgnoreCase))
            {
                // The server requires exactly TLS 1.2 (see
                // AuthenticateAsServer(..., SslProtocols.Tls12, ...) on the
                // server side) with no fallback. This client targets .NET
                // 3.5/4.0, whose SecurityProtocolType enum predates the
                // named Tls12 member (added in .NET 4.5) and whose default
                // enabled protocol set on older Windows/.NET installs may
                // not include TLS 1.2 at all - without this, the handshake
                // fails with no usable error, while plain HTTP keeps working
                // (masking the cause). 3072 = SecurityProtocolType.Tls12's
                // underlying value; the cast keeps this compiling under the
                // pre-4.5 target used for the Net35 client build. Assigned
                // (not OR'd in) so this never leaves an older OS/.NET's
                // legacy SSL3/TLS1.0/1.1 default enabled alongside it - every
                // HTTPS call this client makes is to this same server, which
                // only ever accepts TLS 1.2 anyway.
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            }

            byte[] body = Encoding.UTF8.GetBytes(json);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.ContentLength = body.Length;
            request.Timeout = 30000;

            if (!String.IsNullOrEmpty(token))
            {
                request.Headers["X-Inventory-Token"] = token;
            }

            using (Stream requestStream = request.GetRequestStream())
            {
                requestStream.Write(body, 0, body.Length);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if ((int)response.StatusCode < 200 || (int)response.StatusCode >= 300)
                {
                    throw new InvalidOperationException("Server returned HTTP " + (int)response.StatusCode);
                }

                using (Stream responseStream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(responseStream, Encoding.UTF8))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        // Same shape as PostJson (including the TLS 1.2 opt-in explained
        // there), minus the request body.
        internal static string HttpGet(string url, string token)
        {
            if (url.StartsWith("https:", StringComparison.OrdinalIgnoreCase))
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            }

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Timeout = 30000;

            if (!String.IsNullOrEmpty(token))
            {
                request.Headers["X-Inventory-Token"] = token;
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if ((int)response.StatusCode < 200 || (int)response.StatusCode >= 300)
                {
                    throw new InvalidOperationException("Server returned HTTP " + (int)response.StatusCode);
                }

                using (Stream responseStream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(responseStream, Encoding.UTF8))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        // Same shape as HttpGet, returning the raw response bytes instead
        // of decoding them as UTF-8 text - used for downloading the
        // client package itself, which is a binary .exe, not JSON/text.
        internal static byte[] HttpGetBytes(string url, string token)
        {
            if (url.StartsWith("https:", StringComparison.OrdinalIgnoreCase))
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            }

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Timeout = 60000;

            if (!String.IsNullOrEmpty(token))
            {
                request.Headers["X-Inventory-Token"] = token;
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if ((int)response.StatusCode < 200 || (int)response.StatusCode >= 300)
                {
                    throw new InvalidOperationException("Server returned HTTP " + (int)response.StatusCode);
                }

                using (Stream responseStream = response.GetResponseStream())
                using (MemoryStream buffer = new MemoryStream())
                {
                    // Stream.CopyTo was only added in .NET 4.0 - this
                    // client's Net35 build target predates it, so the copy
                    // loop is written out manually here instead.
                    byte[] readBuffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = responseStream.Read(readBuffer, 0, readBuffer.Length)) > 0)
                    {
                        buffer.Write(readBuffer, 0, bytesRead);
                    }
                    return buffer.ToArray();
                }
            }
        }

        // Copies sourceStream to destPath in fixed-size chunks and hashes
        // the same chunks incrementally (TransformBlock/TransformFinalBlock)
        // instead of buffering the whole thing in a byte[]/MemoryStream
        // first. Extracted out of DownloadToFileAndComputeSha256 below so it
        // can be exercised by a self-test with a plain MemoryStream - this
        // project has no built-in test HTTP server to drive the real
        // download path end to end.
        internal static string StreamToFileAndComputeSha256(Stream sourceStream, string destPath)
        {
            using (SHA256 sha256 = SHA256.Create())
            using (FileStream fileStream = new FileStream(destPath, FileMode.Create, FileAccess.Write))
            {
                byte[] readBuffer = new byte[81920];
                int bytesRead;
                while ((bytesRead = sourceStream.Read(readBuffer, 0, readBuffer.Length)) > 0)
                {
                    fileStream.Write(readBuffer, 0, bytesRead);
                    // Hash algorithms treat TransformBlock as a pass-through:
                    // it copies inputCount bytes from inputBuffer to
                    // outputBuffer unchanged while folding them into the
                    // running hash, so reusing readBuffer as both is safe.
                    sha256.TransformBlock(readBuffer, 0, bytesRead, readBuffer, 0);
                }
                sha256.TransformFinalBlock(new byte[0], 0, 0);
                return BitConverter.ToString(sha256.Hash).Replace("-", "").ToLowerInvariant();
            }
        }

        // Same request setup as HttpGetBytes (HTTPS/TLS, X-Inventory-Token
        // header, status-code check) but streams the response body straight
        // to destPath and returns its SHA256 hex hash, instead of returning
        // the whole body as a byte[]. A Windows Update .msu/.cab job
        // download can be 0.5-1.5 GB - routine content for this catalog, not
        // an edge case - so HttpGetBytes's whole-body-in-memory approach
        // (fine for the small self-update payload it exists for) would risk
        // OutOfMemoryException here, and anything near 2 GB would not fit in
        // a byte[]/MemoryStream at all. Timeout matches the server's own
        // DownloadBytesFromUrl/PerformWsusCabDownload choice for large-file
        // downloads (300000ms / 5 minutes), not HttpGetBytes's own 60000ms,
        // which is sized for the small self-update payload.
        internal static string DownloadToFileAndComputeSha256(string url, string token, string destPath)
        {
            if (url.StartsWith("https:", StringComparison.OrdinalIgnoreCase))
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            }

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Timeout = 300000;

            if (!String.IsNullOrEmpty(token))
            {
                request.Headers["X-Inventory-Token"] = token;
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if ((int)response.StatusCode < 200 || (int)response.StatusCode >= 300)
                {
                    throw new InvalidOperationException("Server returned HTTP " + (int)response.StatusCode);
                }

                using (Stream responseStream = response.GetResponseStream())
                {
                    return StreamToFileAndComputeSha256(responseStream, destPath);
                }
            }
        }

        // postJson is injected (production: the existing PostJson) so this
        // is testable without a real HTTP call. Mirrors
        // ApplySelfUpdateFromServerCore's own convention: the injected
        // delegate throws on failure (PostJson throws InvalidOperationException
        // on a non-2xx response), the caller catches and maps to a clean
        // bool instead of letting a real HTTP failure propagate out of the
        // poll cycle.
        internal static bool PostWsusScanResults(string serverUrl, string token, string computerName, string cabHash, bool wuServiceAvailable, List<Dictionary<string, object>> missingUpdates, Func<string, string, string, string> postJson)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> body = new Dictionary<string, object>();
            body["computerName"] = computerName;
            body["cabHash"] = cabHash;
            body["wuServiceAvailable"] = wuServiceAvailable;
            body["missingUpdates"] = missingUpdates;
            string json = serializer.Serialize(body);

            string url = ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/wsus-scan-results");
            try
            {
                postJson(url, json, token);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Pure mapping from a downloaded installer file's extension to the
        // process that should launch it - no I/O, no process creation.
        // Pulled out of RunOneJob so it's unit-testable without actually
        // launching msiexec/wusa/dism as a side effect of a self-test.
        // internal rather than private so SoftwareJobRunner (a separate
        // top-level class's nested type) can reuse it, matching GetString's
        // own precedent for sharing logic across that boundary.
        //
        // UseShellExecute=false means CreateProcess loads FileName as a PE
        // image, so only a real executable can be launched directly. Every
        // other packaging format needs its own host process: .msi ->
        // msiexec.exe, .msu (a cabinet the Windows Update stack installs) ->
        // wusa.exe, .cab -> dism.exe. Without this dispatch an .msu/.cab
        // entry - the Windows Updates catalog's own designed content - fails
        // with "not a valid application for this OS platform" on every
        // attempt.
        internal static void ResolveInstallerLaunch(string extension, string localCopyPath, string arguments, out string fileName, out string processArguments)
        {
            if (String.Equals(extension, ".msi", StringComparison.OrdinalIgnoreCase))
            {
                fileName = "msiexec.exe";
                processArguments = "/i \"" + localCopyPath + "\" " + (arguments ?? "");
            }
            else if (String.Equals(extension, ".msu", StringComparison.OrdinalIgnoreCase))
            {
                fileName = "wusa.exe";
                processArguments = "\"" + localCopyPath + "\" " + (arguments ?? "");
            }
            else if (String.Equals(extension, ".cab", StringComparison.OrdinalIgnoreCase))
            {
                fileName = "dism.exe";
                processArguments = "/online /add-package /packagepath:\"" + localCopyPath + "\" " + (arguments ?? "");
            }
            else
            {
                fileName = localCopyPath;
                processArguments = arguments ?? "";
            }
        }

        // Rejects a server-supplied installer `arguments` string that
        // contains one of THIS installer's own "which package/image to act
        // on" switches - a compromised server could otherwise smuggle an
        // extra /i, /packagepath:, etc. into an admin-configured catalog
        // entry's arguments field to redirect the install at a different
        // file than the one relativePath already resolved and the
        // software-repository confinement already validated. Scoped to each
        // installer's own documented switches (verified against their real
        // command-line syntax, not guessed) rather than a blanket character
        // filter - legitimate admin-configured content (PROPERTY=value
        // pairs, /quiet, /norestart, /log:path, values containing '=' or
        // spaces) is never touched. Direct execution of the downloaded file
        // itself (RunOneJob's "else" dispatch branch) has no such
        // switch convention to smuggle - the file that ever runs is always
        // the one relativePath already resolved - so nothing is rejected
        // for that case.
        internal static bool TryFindDangerousInstallerArgument(string extension, string arguments, out string reason)
        {
            reason = null;
            if (String.IsNullOrEmpty(arguments))
            {
                return false;
            }

            string[] tokens = arguments.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

            if (String.Equals(extension, ".msi", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string token in tokens)
                {
                    if (token.Equals("/i", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/a", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/x", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/j", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/p", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/uninstall", StringComparison.OrdinalIgnoreCase)
                        || IsMsiexecRepairSwitch(token))
                    {
                        reason = "arguments must not contain msiexec's own package-selection switch '" + token + "' - it could redirect the install at a different package than the one already resolved from relativePath";
                        return true;
                    }
                }
            }
            else if (String.Equals(extension, ".msu", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string token in tokens)
                {
                    if (token.Equals("/uninstall", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/extract", StringComparison.OrdinalIgnoreCase)
                        || token.StartsWith("/extract:", StringComparison.OrdinalIgnoreCase))
                    {
                        reason = "arguments must not contain wusa's own '" + token + "' switch - /uninstall targets a different package and /extract writes arbitrary files to an admin-chosen destination";
                        return true;
                    }
                }
            }
            else if (String.Equals(extension, ".cab", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string token in tokens)
                {
                    if (token.Equals("/add-package", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/remove-package", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/packagepath", StringComparison.OrdinalIgnoreCase)
                        || token.StartsWith("/packagepath:", StringComparison.OrdinalIgnoreCase)
                        || token.Equals("/image", StringComparison.OrdinalIgnoreCase)
                        || token.StartsWith("/image:", StringComparison.OrdinalIgnoreCase))
                    {
                        reason = "arguments must not contain dism's own '" + token + "' switch - dism accepts multiple /packagepath: values in one call, which could stage an extra, attacker-chosen package alongside the one already resolved from relativePath";
                        return true;
                    }
                }
            }

            return false;
        }

        // msiexec's repair switch is "/f" optionally glued directly to one or
        // more modifier letters (e.g. "/fpecms") with no separator -
        // distinguished here from an unrelated switch that merely starts
        // with the same two characters (e.g. "/forcerestart", a legitimate
        // restart-behavior switch) by requiring every remaining character to
        // be one of msiexec's documented repair modifiers.
        private static bool IsMsiexecRepairSwitch(string token)
        {
            if (!token.StartsWith("/f", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            for (int i = 2; i < token.Length; i++)
            {
                if ("poecdaumsv".IndexOf(Char.ToLowerInvariant(token[i])) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        internal static bool ReportJobStart(string serverUrl, string token, string computerName, string catalogType, string id, string attemptId, Func<string, string, string, string> postJson)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> body = new Dictionary<string, object>();
            body["computerName"] = computerName;
            body["catalogType"] = catalogType;
            body["id"] = id;
            body["attemptId"] = attemptId;
            string json = serializer.Serialize(body);

            string url = ToSoftwareJobStartUrl(serverUrl);
            try
            {
                postJson(url, json, token);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // options.ServerUrl is the full URL of the inventory ingestion
        // endpoint (the install wizard asks the admin for exactly
        // "https://server/api/v1/inventory"), so the sibling client endpoints
        // are reached by swapping that suffix. A ServerUrl that does not end
        // in the expected suffix is returned untouched: the resulting request
        // fails and the caller's catch treats it as "no work this cycle",
        // which is preferable to guessing at a base URL.
        private static string ToSoftwareRepositoryUrl(string inventoryUrl, string suffix)
        {
            const string InventorySuffix = "/api/v1/inventory";
            if (!String.IsNullOrEmpty(inventoryUrl) && inventoryUrl.EndsWith(InventorySuffix, StringComparison.OrdinalIgnoreCase))
            {
                return inventoryUrl.Substring(0, inventoryUrl.Length - InventorySuffix.Length) + suffix;
            }
            return inventoryUrl;
        }

        internal static string ToEnrollUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/enroll");
        }

        // Pure decision extracted out of CollectAndSave's own catch block so
        // it is directly testable without a live server or WMI collection -
        // mirrors why TryEnrollIfNeededCore/ApplySelfUpdateFromServerCore
        // are their own injectable/pure functions too. Only clears the
        // learned token when enrollment is even in use (no EnrollmentToken
        // configured means there is nothing to re-enroll with, so clearing
        // Token would just strand the client with no credential at all) and
        // the failure was specifically a 401 (matches PostJson's own
        // "Server returned HTTP " + statusCode exception text) - any other
        // failure (network blip, 500, etc.) must not throw away a token
        // that may well still be valid.
        internal static bool ShouldClearTokenForReenrollment(string enrollmentToken, string exceptionMessage)
        {
            return !String.IsNullOrEmpty(enrollmentToken)
                && !String.IsNullOrEmpty(exceptionMessage)
                && exceptionMessage.IndexOf("HTTP 401", StringComparison.Ordinal) >= 0;
        }

        internal static string ToWindowsUpdateJobsUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/windows-update-jobs?computerName=" + Uri.EscapeDataString(Environment.MachineName));
        }

        internal static string ToThirdPartySoftwareJobsUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/third-party-software-jobs?computerName=" + Uri.EscapeDataString(Environment.MachineName));
        }

        internal static string ToSoftwareDownloadUrl(string serverUrl, string catalogType, string id)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/software-download?catalogType=" + Uri.EscapeDataString(catalogType) + "&id=" + Uri.EscapeDataString(id));
        }

        internal static string ToClientPackageUpdateDownloadUrl(string serverUrl, string target)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client-package/update-download?target=" + Uri.EscapeDataString(target));
        }

        // Builds an https variant of serverUrl on a different port (the
        // server's own advertised httpsPort) - same host and path, scheme
        // and port swapped. Used only to opportunistically retry a
        // self-update download when ServerUrl itself is http; see
        // ClientOptions.RequireHttpsForSelfUpdate's own comment. Returns
        // null if serverUrl isn't a well-formed absolute URL - defensive
        // only, since a malformed ServerUrl would already have failed every
        // other call this client makes. Checked explicitly with
        // IsWellFormedUriString rather than relying on the UriBuilder
        // constructor to throw for bad input - it does not: UriBuilder is
        // lenient enough to accept a bare string like "not-a-url" as a
        // hostname and build a syntactically valid (but meaningless)
        // "https://not-a-url:.../" from it instead of failing, found live by
        // this function's own self-test.
        internal static string ToHttpsServerUrl(string serverUrl, int httpsPort)
        {
            if (!Uri.IsWellFormedUriString(serverUrl, UriKind.Absolute))
            {
                return null;
            }
            try
            {
                UriBuilder builder = new UriBuilder(serverUrl);
                builder.Scheme = "https";
                builder.Port = httpsPort;
                return builder.Uri.ToString();
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal static string ToSoftwareJobResultsUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/software-jobs/results");
        }

        internal static string ToSoftwareJobStartUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/software-jobs/start");
        }
    }
}
