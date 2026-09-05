using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
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
        internal const string ProductVersion = "0.3.0";

        private static int Main(string[] args)
        {
            ClientOptions options = ClientOptions.Parse(args);

            if (options.ShowVersion)
            {
                Console.WriteLine(ProductVersion);
                return 0;
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

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const int Logon32LogonNewCredentials = 9;
        private const int Logon32ProviderWinNt50 = 3;

        private static void SplitDomainUsername(string input, out string domain, out string username)
        {
            int separatorIndex = input.IndexOf('\\');
            if (separatorIndex < 0)
            {
                domain = ".";
                username = input;
            }
            else
            {
                domain = input.Substring(0, separatorIndex);
                username = input.Substring(separatorIndex + 1);
            }
        }

        // Deliberate duplicate of the server's helper of the same name: the
        // client and the server are separate executables with no shared
        // assembly, and this project's convention is per-file duplication
        // rather than a shared library.
        //
        // LOGON32_LOGON_NEW_CREDENTIALS does not validate the credentials
        // here - a wrong username or password still yields a "successful"
        // token, and the failure only surfaces when the impersonated code
        // actually touches the share. Callers must therefore treat share I/O
        // failures inside the action as the normal way bad credentials show up.
        private static void WithSoftwareRepositoryIdentity(string repositoryUsername, string repositoryPassword, Action action)
        {
            if (String.IsNullOrEmpty(repositoryUsername) || String.IsNullOrEmpty(repositoryPassword))
            {
                action();
                return;
            }

            string domain;
            string username;
            SplitDomainUsername(repositoryUsername, out domain, out username);

            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (!LogonUser(username, domain, repositoryPassword, Logon32LogonNewCredentials, Logon32ProviderWinNt50, out tokenHandle))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                using (WindowsIdentity identity = new WindowsIdentity(tokenHandle))
                {
                    WindowsImpersonationContext context = identity.Impersonate();
                    try
                    {
                        action();
                    }
                    finally
                    {
                        context.Undo();
                    }
                }
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    CloseHandle(tokenHandle);
                }
            }
        }

        private sealed class InventoryService : ServiceBase
        {
            private readonly ClientOptions options;
            private Timer timer;
            private Timer softwareCheckTimer;

            public InventoryService(ClientOptions options)
            {
                this.options = options;
                ServiceName = Program.ServiceName;
                CanStop = true;
                AutoLog = true;
            }

            protected override void OnStart(string[] args)
            {
                timer = new Timer(Collect, null, TimeSpan.Zero, TimeSpan.FromHours(options.IntervalHours));
                softwareCheckTimer = new Timer(CheckSoftwareJobs, null, TimeSpan.FromMinutes(2), TimeSpan.FromHours(options.SoftwareCheckIntervalHours));
            }

            protected override void OnStop()
            {
                if (timer != null)
                {
                    timer.Dispose();
                    timer = null;
                }
                if (softwareCheckTimer != null)
                {
                    softwareCheckTimer.Dispose();
                    softwareCheckTimer = null;
                }
            }

            private void Collect(object state)
            {
                try
                {
                    InventoryCollector collector = new InventoryCollector(options);
                    collector.CollectAndSave();
                    DebugLogger.Log(options, "Server", "Collection cycle completed successfully.");
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
            }

            private int softwareCheckRunning;

            private void CheckSoftwareJobs(object state)
            {
                if (Interlocked.CompareExchange(ref softwareCheckRunning, 1, 0) != 0)
                {
                    DebugLogger.Log(options, "Server", "Software job check cycle skipped - a previous cycle is still running.");
                    return;
                }
                try
                {
                    SoftwareJobRunner runner = new SoftwareJobRunner(options);
                    runner.CheckAndRun();
                    DebugLogger.Log(options, "Server", "Software job check cycle completed.");
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
                    Interlocked.Exchange(ref softwareCheckRunning, 0);
                }
            }

            private sealed class SoftwareJobRunner
            {
                private readonly ClientOptions options;

                public SoftwareJobRunner(ClientOptions options)
                {
                    this.options = options;
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
                    ArrayList jobs = jobsResponse != null && jobsResponse.ContainsKey("jobs") ? jobsResponse["jobs"] as ArrayList : null;
                    if (jobs == null || jobs.Count == 0)
                    {
                        return;
                    }

                    HashSet<string> alreadySucceeded = LoadSoftwareJobSuccessCache();

                    // Fetching the repository connection info returns the share
                    // password in plaintext (see SendSoftwareRepositoryConnectionInfo
                    // on the server). Most cycles have no unfinished job, so check
                    // the success cache BEFORE asking for the credential - this
                    // avoids sending it across the wire and doing a share logon on
                    // every tick when there is no actual work to do.
                    bool hasUnfinishedJob = false;
                    foreach (object item in jobs)
                    {
                        Dictionary<string, object> job = item as Dictionary<string, object>;
                        if (job == null)
                        {
                            continue;
                        }
                        if (!alreadySucceeded.Contains(InventoryCollector.GetString(job, "id")))
                        {
                            hasUnfinishedJob = true;
                            break;
                        }
                    }
                    if (!hasUnfinishedJob)
                    {
                        return;
                    }

                    string connectionJson = FetchSoftwareRepositoryConnection();
                    if (String.IsNullOrEmpty(connectionJson))
                    {
                        return;
                    }

                    Dictionary<string, object> connection = serializer.Deserialize<Dictionary<string, object>>(connectionJson);
                    if (connection == null)
                    {
                        return;
                    }
                    string repositoryPath = InventoryCollector.GetString(connection, "path");
                    string repositoryUsername = InventoryCollector.GetString(connection, "username");
                    string repositoryPassword = InventoryCollector.GetString(connection, "password");
                    if (String.IsNullOrEmpty(repositoryPath))
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

                        string id = InventoryCollector.GetString(job, "id");
                        if (alreadySucceeded.Contains(id))
                        {
                            continue;
                        }

                        Dictionary<string, object> resultEntry = RunOneJob(job, repositoryPath, repositoryUsername, repositoryPassword);
                        results.Add(resultEntry);

                        if (Convert.ToBoolean(resultEntry["success"]))
                        {
                            alreadySucceeded.Add(id);
                        }
                    }

                    if (results.Count > 0)
                    {
                        SaveSoftwareJobSuccessCache(alreadySucceeded);
                        PostResults(results);
                    }
                }

                // CRITICAL: Process.Start does NOT run under the calling
                // thread's impersonation token. CreateProcess loads the
                // target image using the PROCESS token (this service's own
                // running identity), not the calling thread's impersonation -
                // thread-level impersonation only affects file I/O and network
                // calls made directly on that thread, never a newly created
                // process. Launching straight from a UNC path INSIDE
                // WithSoftwareRepositoryIdentity would therefore fail in
                // exactly the case explicit share credentials exist to
                // handle - a service identity with no access to the share.
                //
                // The fix: copy the installer to a local temp path WHILE
                // impersonating (File.Copy DOES honor thread impersonation,
                // unlike process creation), then launch that LOCAL copy AFTER
                // impersonation has ended. The installer then runs under this
                // service's own normal identity - which is fine, since running
                // "as" the share account was never the goal, only READING from
                // the share as that account was.
                //
                // Known MVP limitation, not fixed here: an installer that
                // expects sibling files in its own directory (not a single
                // self-contained exe/msi) will not find them once copied alone
                // to a temp folder - the dashboard's "File path in share" field
                // hint documents this constraint rather than copying whole
                // directories, which would silently copy more than a given
                // entry asked for.
                private const int InstallProcessTimeoutMilliseconds = 30 * 60 * 1000;

                private Dictionary<string, object> RunOneJob(Dictionary<string, object> job, string repositoryPath, string repositoryUsername, string repositoryPassword)
                {
                    string id = InventoryCollector.GetString(job, "id");
                    string catalogType = InventoryCollector.GetString(job, "catalogType");
                    string relativePath = InventoryCollector.GetString(job, "relativePath");
                    string arguments = InventoryCollector.GetString(job, "arguments");

                    Dictionary<string, object> resultEntry = new Dictionary<string, object>();
                    resultEntry["id"] = id;
                    resultEntry["catalogType"] = catalogType;

                    string localCopyPath = null;
                    try
                    {
                        if (String.IsNullOrEmpty(relativePath) || Path.IsPathRooted(relativePath))
                        {
                            resultEntry["success"] = false;
                            resultEntry["exitCode"] = -1;
                            resultEntry["errorMessage"] = "relativePath must be a non-empty path relative to the software repository: " + relativePath;
                            return resultEntry;
                        }

                        string fullPath = Path.Combine(repositoryPath, relativePath);
                        string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + Path.GetExtension(relativePath));
                        localCopyPath = tempPath;

                        try
                        {
                            WithSoftwareRepositoryIdentity(repositoryUsername, repositoryPassword, () =>
                            {
                                File.Copy(fullPath, tempPath, true);
                            });
                        }
                        catch (FileNotFoundException)
                        {
                            resultEntry["success"] = false;
                            resultEntry["exitCode"] = -1;
                            resultEntry["errorMessage"] = "file not found: " + relativePath;
                            return resultEntry;
                        }
                        catch (DirectoryNotFoundException)
                        {
                            resultEntry["success"] = false;
                            resultEntry["exitCode"] = -1;
                            resultEntry["errorMessage"] = "file not found: " + relativePath;
                            return resultEntry;
                        }
                        catch (UnauthorizedAccessException ex)
                        {
                            resultEntry["success"] = false;
                            resultEntry["exitCode"] = -1;
                            resultEntry["errorMessage"] = "access denied reading from the software repository - check the configured share credentials: " + ex.Message;
                            return resultEntry;
                        }

                        bool isMsi = String.Equals(Path.GetExtension(relativePath), ".msi", StringComparison.OrdinalIgnoreCase);
                        ProcessStartInfo psi = new ProcessStartInfo();
                        if (isMsi)
                        {
                            psi.FileName = "msiexec.exe";
                            psi.Arguments = "/i \"" + localCopyPath + "\" " + (arguments ?? "");
                        }
                        else
                        {
                            psi.FileName = localCopyPath;
                            psi.Arguments = arguments ?? "";
                        }
                        psi.UseShellExecute = false;
                        psi.CreateNoWindow = true;
                        psi.WorkingDirectory = Path.GetTempPath();

                        using (Process process = Process.Start(psi))
                        {
                            if (!process.WaitForExit(InstallProcessTimeoutMilliseconds))
                            {
                                try { process.Kill(); } catch { }
                                try { process.WaitForExit(5000); } catch { }
                                resultEntry["success"] = false;
                                resultEntry["exitCode"] = -1;
                                resultEntry["errorMessage"] = "installer did not exit within " + (InstallProcessTimeoutMilliseconds / 60000) + " minutes and was terminated";
                                return resultEntry;
                            }

                            int exitCode = process.ExitCode;
                            resultEntry["success"] = exitCode == 0;
                            resultEntry["exitCode"] = exitCode;
                            resultEntry["errorMessage"] = exitCode == 0 ? null : ("installer exited with code " + exitCode);
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

                    return resultEntry;
                }

                private string FetchSoftwareRepositoryConnection()
                {
                    try
                    {
                        return InventoryCollector.HttpGet(InventoryCollector.ToConnectionInfoUrl(options.ServerUrl), options.Token);
                    }
                    catch
                    {
                        return null;
                    }
                }

                private string FetchAssignedJobs()
                {
                    try
                    {
                        return InventoryCollector.HttpGet(InventoryCollector.ToSoftwareJobsUrl(options.ServerUrl), options.Token);
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
                        if (!Directory.Exists(directory))
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

    internal sealed class ClientOptions
    {
        public string ServerSharePath;
        public string ServerUrl;
        public string Token;
        public string OutputPath;
        public int IntervalHours;
        public int SoftwareCheckIntervalHours;
        public bool RunOnce;
        public bool SkipSoftware;
        public bool ShowVersion;
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
            options.SoftwareCheckIntervalHours = 6;
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
                else if (key == "--skip-software")
                {
                    options.SkipSoftware = true;
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
                    int parsedSoftwareInterval;
                    if (Int32.TryParse(args[++i], out parsedSoftwareInterval) && parsedSoftwareInterval >= 1 && parsedSoftwareInterval <= 24)
                    {
                        options.SoftwareCheckIntervalHours = parsedSoftwareInterval;
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

        public void CollectAndSave()
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

            if (!String.IsNullOrEmpty(options.ServerUrl))
            {
                string responseBody = PostJson(options.ServerUrl, json, options.Token);
                ApplyLicenseKeySourcesResponse(responseBody);
                if (options.RunOnce)
                {
                    Console.WriteLine("Inventory posted: " + options.ServerUrl);
                }
            }
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
            result["os"] = GetOperatingSystem();
            result["office"] = GetOfficeVersion();
            result["activation"] = GetActivation();
            result["licenses"] = GetLicenseKeys();
            result["software"] = options.SkipSoftware ? new ArrayList() : GetInstalledSoftware();

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
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, msftQuery))
                {
                    foreach (ManagementObject item in searcher.Get())
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

        private List<LicenseKeySource> LoadLicenseKeySourcesCache()
        {
            List<LicenseKeySource> result = new List<LicenseKeySource>();
            string path = GetLicenseKeySourcesCachePath();
            if (!File.Exists(path))
            {
                return result;
            }

            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                string json = File.ReadAllText(path, Encoding.UTF8);
                ArrayList raw = serializer.Deserialize<ArrayList>(json);
                if (raw == null)
                {
                    return result;
                }

                foreach (object item in raw)
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
                    if (!String.IsNullOrEmpty(source.RegistryPath) && !String.IsNullOrEmpty(source.ValueName))
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

        private Dictionary<string, object> GetActivation()
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["windows"] = GetActivationState(true);
            result["office"] = GetActivationState(false);
            return result;
        }

        private Dictionary<string, object> GetActivationState(bool windows)
        {
            string query = "SELECT Name, ApplicationID, LicenseStatus, PartialProductKey FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL";
            ArrayList products = QueryList(query, "root\\cimv2");
            Dictionary<string, object> result = new Dictionary<string, object>();

            foreach (Dictionary<string, object> product in products)
            {
                string name = GetString(product, "Name");
                string applicationId = GetString(product, "ApplicationID");
                bool match = windows
                    ? name.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0
                    : applicationId.Equals("0ff1ce15-a989-479d-af46-f275c6370663", StringComparison.OrdinalIgnoreCase) ||
                      name.IndexOf("Office", StringComparison.OrdinalIgnoreCase) >= 0;

                if (match && Convert.ToInt32(product["LicenseStatus"]) == 1)
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
                    if (Convert.ToInt32(product["LicenseStatus"]) == 1)
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

        private Dictionary<string, object> GetOfficeVersion()
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

            foreach (Dictionary<string, object> software in GetInstalledSoftware())
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
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query)))
                {
                    foreach (ManagementObject item in searcher.Get())
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
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(path, value, new UTF8Encoding(false));
        }

        // The server's response to POST /api/v1/inventory carries the
        // current admin-managed license key source catalog. The client has
        // no other channel to pull server config (see the license-key
        // collection design doc), so this cache file - written after every
        // successful report, read at the START of the next collection cycle
        // - is how the catalog reaches this client. A missing or corrupt
        // cache file is a normal "nothing to look for yet" state, never an
        // error: GetLicenseKeys() (added in the next task) tolerates it by
        // returning an empty list.
        private string GetLicenseKeySourcesCachePath()
        {
            // options.OutputPath may be a directory or a literal .json file path
            // (see CollectAndSave's own localPath resolution above) - mirror that
            // same branch here so the cache never lands under a file-as-directory.
            string baseDir = options.OutputPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                ? Path.GetDirectoryName(options.OutputPath)
                : options.OutputPath;
            return Path.Combine(baseDir, "license-key-sources-cache.json");
        }

        private void SaveLicenseKeySourcesCache(object rawLicenseKeySources)
        {
            ArrayList sources = rawLicenseKeySources as ArrayList;
            if (sources == null)
            {
                return;
            }

            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                string json = serializer.Serialize(sources);
                WriteText(GetLicenseKeySourcesCachePath(), json);
            }
            catch
            {
                // Caching the list is a best-effort convenience for the
                // next collection cycle - a write failure here must never
                // affect the inventory report that has already succeeded.
            }
        }

        private void ApplyLicenseKeySourcesResponse(string responseBody)
        {
            if (String.IsNullOrEmpty(responseBody))
            {
                return;
            }

            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                Dictionary<string, object> response = serializer.Deserialize<Dictionary<string, object>>(responseBody);
                if (response != null && response.ContainsKey("licenseKeySources"))
                {
                    SaveLicenseKeySourcesCache(response["licenseKeySources"]);
                }
            }
            catch
            {
                // A malformed/unparseable response must never fail a
                // report the server has already accepted.
            }
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
                // pre-4.5 target used for the Net35 client build.
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
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
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
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

        internal static string ToConnectionInfoUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/software-repository-connection");
        }

        internal static string ToSoftwareJobsUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/software-jobs?computerName=" + Uri.EscapeDataString(Environment.MachineName));
        }

        internal static string ToSoftwareJobResultsUrl(string serverUrl)
        {
            return ToSoftwareRepositoryUrl(serverUrl, "/api/v1/client/software-jobs/results");
        }
    }
}
