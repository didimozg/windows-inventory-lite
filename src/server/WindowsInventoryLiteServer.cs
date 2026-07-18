using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace WindowsInventoryLite
{
    internal sealed class Program
    {
        private const string ServiceName = "WindowsInventoryLite";
        internal const string ProductVersion = "0.16.11";

        private static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--self-test")
            {
                bool passed = InventoryServer.RunSelfTests(Console.Out);
                return passed ? 0 : 1;
            }

            ServerOptions options = ServerOptions.Parse(args);

            if (options.ShowVersion)
            {
                Console.WriteLine(ProductVersion);
                return 0;
            }

            if (options.ConsoleMode)
            {
                InventoryServer server = new InventoryServer(options);
                server.Start();
                Console.WriteLine("Server URL: http://localhost:" + options.Port + "/");
                Console.WriteLine("Press Enter to stop.");
                Console.ReadLine();
                server.Stop();
                return 0;
            }

            ServiceBase.Run(new InventoryServerService(options));
            return 0;
        }

        private sealed class InventoryServerService : ServiceBase
        {
            private readonly InventoryServer server;

            public InventoryServerService(ServerOptions options)
            {
                ServiceName = Program.ServiceName;
                CanStop = true;
                AutoLog = true;
                server = new InventoryServer(options);
            }

            protected override void OnStart(string[] args)
            {
                server.Start();
            }

            protected override void OnStop()
            {
                server.Stop();
            }
        }
    }

    internal sealed class ServerOptions
    {
        // The plain HTTP listener's port. Independent of HttpsPort - HTTP and
        // HTTPS run as two separate listeners on two separate ports (see
        // InventoryServer's ListenerSlot design), not one port that switches
        // protocol based on a flag.
        public int Port;
        public bool EnableHttp;
        public int HttpsPort;
        public IPAddress Address;
        public string DataPath;
        public string ContentPath;
        public string ClientPackagePath;
        public string WinRmInstallerPath;
        public string WinRmUninstallerPath;
        public string Token;
        public string WebUsername;
        public string WebPassword;
        public int InstallLogRetentionDays;
        public string ConfigPath;
        // The certificate is resolved from the LocalMachine\My store by thumbprint
        // (see InventoryServer.FindCertificateByThumbprint). Install-Server.ps1 can
        // import a PFX at install time; the dashboard "Certificate" tab can import
        // and switch to a new PFX later without a service restart.
        public bool UseHttps;
        public string CertificateThumbprint;
        public int StaleHours;
        public bool ConsoleMode;
        public bool ShowVersion;
        // AD sync is opt-in and off by default - deployments without AD, or
        // with a server that isn't domain-joined, are unaffected. See
        // AdLookupService.cs and InventoryServer.ComputeAdSyncFields.
        public bool AdSyncEnabled;
        public string AdSyncMode;
        public int AdSyncIntervalHours;
        public string AdDomain;
        public bool AdUseServiceIdentity;
        public string AdUsername;
        public string AdPassword;
        // Off by default - a plain-text file capturing AD lookups,
        // inventory-report traffic, and unhandled server errors. See
        // DebugLogger.cs. Only meant for troubleshooting a specific
        // deployment; not rotated or size-capped.
        public bool DebugLogEnabled;
        public string DebugLogPath;
        // Optional, off by default - dashboard-configured only (no
        // Install-Server.ps1 CLI flag by design, see the plan's Global
        // Constraints). Used as a fallback WinRM credential for Client
        // Auto-Update pushes when the service's own identity can't reach a
        // target; see docs/superpowers/specs/2026-07-17-client-auto-update-design.md.
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

        public static ServerOptions Parse(string[] args)
        {
            ServerOptions options = new ServerOptions();
            options.Port = 8080;
            options.EnableHttp = true;
            options.HttpsPort = 8443;
            options.Address = IPAddress.Any;
            options.DataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server");
            options.ContentPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server-content");
            options.ClientPackagePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\client-package");
            options.WinRmInstallerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server-bin\Install-ClientWinRM.ps1");
            options.WinRmUninstallerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server-bin\Uninstall-ClientWinRM.ps1");
            options.InstallLogRetentionDays = 30;
            options.StaleHours = 48;
            options.AdSyncMode = "on-report";
            options.AdSyncIntervalHours = 24;
            options.AdUseServiceIdentity = true;
            options.ClientUpdateScheduleMode = "off";
            options.ClientUpdateScheduleOnceAtUtc = "";
            options.ClientUpdateScheduleIntervalHours = 24;
            options.ClientUpdateScheduleLastRunUtc = "";

            for (int i = 0; i < args.Length; i++)
            {
                string key = args[i].ToLowerInvariant();
                if (key == "--console")
                {
                    options.ConsoleMode = true;
                }
                else if (key == "--version")
                {
                    options.ShowVersion = true;
                }
                else if ((key == "--port" || key == "--listen-port") && i + 1 < args.Length)
                {
                    Int32.TryParse(args[++i], out options.Port);
                }
                else if (key == "--bind" && i + 1 < args.Length)
                {
                    IPAddress parsed;
                    if (IPAddress.TryParse(args[++i], out parsed))
                    {
                        options.Address = parsed;
                    }
                }
                else if (key == "--prefix" && i + 1 < args.Length)
                {
                    int parsedPort;
                    if (TryParsePortFromPrefix(args[++i], out parsedPort))
                    {
                        options.Port = parsedPort;
                    }
                }
                else if (key == "--data" && i + 1 < args.Length)
                {
                    options.DataPath = args[++i];
                }
                else if (key == "--content" && i + 1 < args.Length)
                {
                    options.ContentPath = args[++i];
                }
                else if (key == "--client-package" && i + 1 < args.Length)
                {
                    options.ClientPackagePath = args[++i];
                }
                else if (key == "--winrm-installer" && i + 1 < args.Length)
                {
                    options.WinRmInstallerPath = args[++i];
                }
                else if (key == "--winrm-uninstaller" && i + 1 < args.Length)
                {
                    options.WinRmUninstallerPath = args[++i];
                }
                else if (key == "--token" && i + 1 < args.Length)
                {
                    options.Token = args[++i];
                }
                else if (key == "--web-username" && i + 1 < args.Length)
                {
                    options.WebUsername = args[++i];
                }
                else if (key == "--web-password" && i + 1 < args.Length)
                {
                    options.WebPassword = args[++i];
                }
                else if (key == "--install-log-retention-days" && i + 1 < args.Length)
                {
                    int days;
                    if (Int32.TryParse(args[++i], out days) && days > 0)
                    {
                        options.InstallLogRetentionDays = days;
                    }
                }
                else if (key == "--config" && i + 1 < args.Length)
                {
                    options.ConfigPath = args[++i];
                }
                else if (key == "--use-https")
                {
                    options.UseHttps = true;
                }
                else if (key == "--certificate-thumbprint" && i + 1 < args.Length)
                {
                    options.CertificateThumbprint = args[++i];
                }
                else if (key == "--stale-hours" && i + 1 < args.Length)
                {
                    int staleHours;
                    if (Int32.TryParse(args[++i], out staleHours) && staleHours > 0)
                    {
                        options.StaleHours = staleHours;
                    }
                }
                else if (key == "--https-port" && i + 1 < args.Length)
                {
                    int httpsPort;
                    if (Int32.TryParse(args[++i], out httpsPort) && httpsPort > 0 && httpsPort <= 65535)
                    {
                        options.HttpsPort = httpsPort;
                    }
                }
                else if (key == "--disable-http")
                {
                    options.EnableHttp = false;
                }
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
                    if (Int32.TryParse(args[++i], out adHours) && adHours > 0 && adHours <= 8760)
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
                else if (key == "--debug-log-enabled")
                {
                    options.DebugLogEnabled = true;
                }
                else if (key == "--debug-log-path" && i + 1 < args.Length)
                {
                    options.DebugLogPath = args[++i];
                }
            }

            LoadConfigFile(options);
            return options;
        }

        private static void LoadConfigFile(ServerOptions options)
        {
            if (String.IsNullOrEmpty(options.ConfigPath) || !File.Exists(options.ConfigPath))
            {
                return;
            }

            try
            {
                string json = File.ReadAllText(options.ConfigPath, Encoding.UTF8);
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                Dictionary<string, object> config = serializer.Deserialize<Dictionary<string, object>>(json);
                if (String.IsNullOrEmpty(options.Token))
                {
                    options.Token = SecretProtector.Unprotect(GetConfigString(config, "Token"));
                }
                if (String.IsNullOrEmpty(options.WebUsername))
                {
                    options.WebUsername = GetConfigString(config, "WebUsername");
                }
                if (String.IsNullOrEmpty(options.WebPassword))
                {
                    options.WebPassword = SecretProtector.Unprotect(GetConfigString(config, "WebPassword"));
                }
                if (!options.UseHttps)
                {
                    string useHttps = GetConfigString(config, "UseHttps");
                    options.UseHttps = String.Equals(useHttps, "true", StringComparison.OrdinalIgnoreCase);
                }
                if (String.IsNullOrEmpty(options.CertificateThumbprint))
                {
                    options.CertificateThumbprint = GetConfigString(config, "CertificateThumbprint");
                }
                if (options.StaleHours == 48)
                {
                    string staleHoursText = GetConfigString(config, "StaleHours");
                    int staleHoursFromConfig;
                    if (!String.IsNullOrEmpty(staleHoursText) && Int32.TryParse(staleHoursText, out staleHoursFromConfig) && staleHoursFromConfig > 0)
                    {
                        options.StaleHours = staleHoursFromConfig;
                    }
                }
                // Deliberately NOT gated behind "no --prefix was passed" the way
                // every other field here is gated behind its own IsNullOrEmpty
                // check: Install-Server.ps1 no longer bakes --prefix into the
                // service's own start command at all (see its $serviceCommand
                // construction), specifically so a dashboard-driven port change
                // (see InventoryServer.ApplySlotState) survives a plain
                // service restart or reboot, not just a reinstall - matching
                // how WebUsername/UseHttps/etc. already behave. options.Port
                // still equalling the compiled-in default (8080) here means
                // nothing set it explicitly, so config is free to.
                if (options.Port == 8080)
                {
                    int portFromConfig;
                    if (TryParsePortFromPrefix(GetConfigString(config, "ListenPrefix"), out portFromConfig))
                    {
                        options.Port = portFromConfig;
                    }
                }
                if (options.HttpsPort == 8443)
                {
                    string httpsPortText = GetConfigString(config, "HttpsPort");
                    int httpsPortFromConfig;
                    if (!String.IsNullOrEmpty(httpsPortText) && Int32.TryParse(httpsPortText, out httpsPortFromConfig) && httpsPortFromConfig > 0 && httpsPortFromConfig <= 65535)
                    {
                        options.HttpsPort = httpsPortFromConfig;
                    }
                }
                if (options.EnableHttp)
                {
                    string enableHttpText = GetConfigString(config, "EnableHttp");
                    if (enableHttpText != null)
                    {
                        options.EnableHttp = String.Equals(enableHttpText, "true", StringComparison.OrdinalIgnoreCase);
                    }
                }
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
                    if (!String.IsNullOrEmpty(adSyncIntervalText) && Int32.TryParse(adSyncIntervalText, out adSyncIntervalFromConfig) && adSyncIntervalFromConfig > 0 && adSyncIntervalFromConfig <= 8760)
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
                if (!options.DebugLogEnabled)
                {
                    string debugLogEnabledText = GetConfigString(config, "DebugLogEnabled");
                    options.DebugLogEnabled = String.Equals(debugLogEnabledText, "true", StringComparison.OrdinalIgnoreCase);
                }
                if (String.IsNullOrEmpty(options.DebugLogPath))
                {
                    options.DebugLogPath = GetConfigString(config, "DebugLogPath");
                }
            }
            catch
            {
            }
        }

        // internal, not private: also called from InventoryServer's self-test suite.
        internal static bool TryParsePortFromPrefix(string prefix, out int port)
        {
            port = 0;
            if (String.IsNullOrEmpty(prefix))
            {
                return false;
            }

            string normalized = prefix.Replace("+", "localhost");
            Uri uri;
            if (Uri.TryCreate(normalized, UriKind.Absolute, out uri) && uri.Port > 0)
            {
                port = uri.Port;
                return true;
            }
            return false;
        }

        private static string GetConfigString(Dictionary<string, object> config, string key)
        {
            if (config == null || !config.ContainsKey(key) || config[key] == null)
            {
                return null;
            }
            string value = Convert.ToString(config[key]);
            return String.IsNullOrEmpty(value) ? null : value;
        }
    }

    internal sealed class InventoryServer
    {
        private readonly ServerOptions options;
        private readonly object installJobsLock = new object();
        private readonly Dictionary<string, InstallJob> installJobs = new Dictionary<string, InstallJob>();
        private readonly object licensesLock = new object();
        private readonly object certificateHistoryLock = new object();
        private readonly object listenerRestartLock = new object();
        // HTTP and HTTPS are two fully independent listeners on two
        // independent ports, each with its own accept thread - not one
        // listener that wraps connections in TLS or not depending on a flag.
        // That's what makes it possible to run both at once, run either one
        // alone, or run neither (see ApplySlotState / ConfigureServerSettings).
        private readonly ListenerSlot httpSlot = new ListenerSlot();
        private readonly ListenerSlot httpsSlot = new ListenerSlot();
        private volatile X509Certificate2 serverCertificate;
        private readonly object adSyncTimerLock = new object();
        private Timer adSyncTimer;
        private readonly object clientUpdateScheduleTimerLock = new object();
        private Timer clientUpdateScheduleTimer;
        private readonly object reportFileLock = new object();

        public InventoryServer(ServerOptions options)
        {
            this.options = options;
        }

        public void Start()
        {
            MigratePlaintextSecrets();
            LoadServerCertificate();

            if (!Directory.Exists(options.DataPath))
            {
                Directory.CreateDirectory(options.DataPath);
            }
            if (!Directory.Exists(GetInstallJobDirectory()))
            {
                Directory.CreateDirectory(GetInstallJobDirectory());
            }
            CleanupInstallJobLogs();

            if (options.EnableHttp)
            {
                string httpError = ApplySlotState(httpSlot, true, -1, options.Port, false);
                LogSlotStartupError("HTTP", httpError);
            }

            if (options.UseHttps && serverCertificate != null)
            {
                string httpsError = ApplySlotState(httpsSlot, true, -1, options.HttpsPort, true);
                LogSlotStartupError("HTTPS", httpsError);
            }

            ReconfigureAdSyncTimer();
            ResetMissedOnceSchedule();
            ReconfigureClientUpdateScheduleTimer();

            if (!httpSlot.Running && !httpsSlot.Running)
            {
                // Only reachable by hand-editing server-config.json (the
                // dashboard's own safety gate in ConfigureServerSettings
                // refuses to produce this state, and options.UseHttps with no
                // valid certificate already logs its own error above) - but
                // the server must still start cleanly rather than crash, since
                // this is exactly the broken state the documented recovery
                // procedure (re-edit the config, restart the service) needs
                // the service to be able to come back up into.
                try
                {
                    System.Diagnostics.EventLog.WriteEntry(
                        "WindowsInventoryLite",
                        "Neither HTTP nor HTTPS is listening (EnableHttp is false and HTTPS is not active). "
                            + "The dashboard is unreachable. Edit server-config.json, set \"EnableHttp\": \"true\", "
                            + "and restart the service to recover.",
                        System.Diagnostics.EventLogEntryType.Error);
                }
                catch { }
            }
        }

        private static void LogSlotStartupError(string label, string error)
        {
            if (error == null)
            {
                return;
            }
            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "WindowsInventoryLite",
                    label + " listener failed to start: " + error,
                    System.Diagnostics.EventLogEntryType.Error);
            }
            catch { }
        }

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
        }

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
                    // Due time is Zero, not `interval` - the first sweep
                    // runs almost immediately after enabling/reconfiguring
                    // timer mode, not after waiting out a full interval
                    // (which, at the 24h default, made timer mode look
                    // completely inert for the first day). Individual
                    // computers still only actually get re-looked-up when
                    // their own cached data is due, per ComputeAdSyncFields/
                    // ShouldSyncAd - this only controls how soon the sweep
                    // itself starts walking the fleet, not how often any
                    // one computer's AD data refreshes.
                    TimeSpan interval = TimeSpan.FromHours(Math.Max(1, options.AdSyncIntervalHours));
                    adSyncTimer = new Timer(RunAdSyncSweep, null, TimeSpan.Zero, interval);
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
                    // Read a snapshot and compute the AD fields (live lookup
                    // included) OUTSIDE reportFileLock - see ComputeAdSyncFields.
                    // The lock is only taken afterward, to re-read the file's
                    // CURRENT contents and merge just the AD fields onto them,
                    // so a client report that arrived for this same computer
                    // while the lookup was in flight is not clobbered by the
                    // stale snapshot read here.
                    Dictionary<string, object> snapshot = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(file, Encoding.UTF8));
                    string computerName = Convert.ToString(snapshot.ContainsKey("computerName") ? snapshot["computerName"] : Path.GetFileNameWithoutExtension(file));
                    AdSyncFields adFields = ComputeAdSyncFields(computerName, snapshot);

                    lock (reportFileLock)
                    {
                        Dictionary<string, object> current;
                        try
                        {
                            current = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(file, Encoding.UTF8));
                        }
                        catch
                        {
                            // A transient re-read failure right before
                            // writing means this thread cannot confirm the
                            // file is still what was snapshotted above -
                            // skip this file rather than risk overwriting a
                            // fresher write (e.g. a client report that
                            // landed for this same computer while the AD
                            // lookup was in flight) with the stale
                            // snapshot. The AD fields get reapplied on the
                            // next sweep tick.
                            continue;
                        }
                        ApplyAdSyncFields(current, adFields);
                        File.WriteAllText(file, serializer.Serialize(current), new UTF8Encoding(false));
                    }
                }
                catch
                {
                    // One unreadable/corrupt report must not stop the sweep
                    // over the rest of the fleet.
                }
            }
        }

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

        private sealed class ListenerSlot
        {
            public volatile TcpListener Listener;
            public volatile bool Running;
            public Thread Worker;
        }

        private sealed class AcceptState
        {
            public ListenerSlot Slot;
            public TcpListener BoundListener;
            public bool IsHttps;
        }

        private sealed class ClientState
        {
            public TcpClient Client;
            public bool IsHttps;
        }

        private static void StopSlot(ListenerSlot slot)
        {
            slot.Running = false;
            TcpListener listenerToStop = slot.Listener;
            Thread workerToJoin = slot.Worker;
            if (listenerToStop != null)
            {
                listenerToStop.Stop();
            }
            if (workerToJoin != null)
            {
                workerToJoin.Join(5000);
            }
        }

        // Brings a slot to the desired running/stopped state on the desired
        // port, changing as little as possible: turning a stopped slot off is
        // a no-op, and a running slot already on the requested port is left
        // alone (comparing against previousPort, not by inspecting the live
        // listener, since the caller always knows what it last asked for).
        // When a rebind IS needed, the new listener is bound and started
        // FIRST - if the port is unavailable (already in use, no permission),
        // Start() throws, the error is returned, and the slot is left exactly
        // as it was. Only once the new listener is confirmed listening does
        // the old one get stopped, so there is never a moment where the slot
        // has committed to a broken new port with no working listener at all.
        private string ApplySlotState(ListenerSlot slot, bool shouldRun, int previousPort, int newPort, bool isHttps)
        {
            lock (listenerRestartLock)
            {
                if (!shouldRun)
                {
                    if (slot.Running)
                    {
                        StopSlot(slot);
                    }
                    return null;
                }

                if (slot.Running && previousPort == newPort)
                {
                    return null;
                }

                TcpListener newListener = new TcpListener(options.Address, newPort);
                try
                {
                    newListener.Start();
                }
                catch (Exception ex)
                {
                    return "could not bind to port " + newPort + ": " + ex.Message;
                }

                if (slot.Running)
                {
                    StopSlot(slot);
                }

                slot.Listener = newListener;
                slot.Running = true;

                AcceptState state = new AcceptState();
                state.Slot = slot;
                state.BoundListener = newListener;
                state.IsHttps = isHttps;
                slot.Worker = new Thread(new ParameterizedThreadStart(AcceptLoop));
                slot.Worker.IsBackground = true;
                slot.Worker.Start(state);

                return null;
            }
        }

        private void LoadServerCertificate()
        {
            if (!options.UseHttps || String.IsNullOrEmpty(options.CertificateThumbprint))
            {
                serverCertificate = null;
                return;
            }

            X509Certificate2 certificate = FindCertificateByThumbprint(options.CertificateThumbprint);
            serverCertificate = certificate;

            if (certificate == null)
            {
                try
                {
                    System.Diagnostics.EventLog.WriteEntry(
                        "WindowsInventoryLite",
                        "UseHttps is set but no certificate with thumbprint " + options.CertificateThumbprint
                            + " was found in the LocalMachine\\My store. HTTPS connections will be refused "
                            + "until a valid certificate is configured (Install-Server.ps1 -CertificateThumbprint / "
                            + "-CertificatePfxPath, or the dashboard Certificate tab).",
                        System.Diagnostics.EventLogEntryType.Error);
                }
                catch { }
            }
        }

        private static X509Certificate2 FindCertificateByThumbprint(string thumbprint)
        {
            if (String.IsNullOrEmpty(thumbprint))
            {
                return null;
            }

            string normalized = NormalizeThumbprint(thumbprint);
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, false);
                return found.Count > 0 ? found[0] : null;
            }
            finally
            {
                store.Close();
            }
        }

        private static string NormalizeThumbprint(string thumbprint)
        {
            if (thumbprint == null)
            {
                return null;
            }
            return thumbprint.Replace(" ", "").Replace(":", "").Replace("-", "").ToUpperInvariant();
        }

        // Bound to a specific TcpListener/slot pairing passed as thread state
        // (never read from the shared slot field mid-loop) so a rebind
        // reassigning slot.Listener can't redirect this thread onto an
        // instance it didn't start on - see ApplySlotState.
        private void AcceptLoop(object state)
        {
            AcceptState acceptState = (AcceptState)state;
            ListenerSlot slot = acceptState.Slot;
            TcpListener boundListener = acceptState.BoundListener;
            bool isHttps = acceptState.IsHttps;

            while (slot.Running && ReferenceEquals(slot.Listener, boundListener))
            {
                try
                {
                    TcpClient client = boundListener.AcceptTcpClient();
                    ClientState clientState = new ClientState();
                    clientState.Client = client;
                    clientState.IsHttps = isHttps;
                    ThreadPool.QueueUserWorkItem(HandleClient, clientState);
                }
                catch
                {
                    if (slot.Running && ReferenceEquals(slot.Listener, boundListener))
                    {
                        Thread.Sleep(500);
                    }
                }
            }
        }

        private void HandleClient(object state)
        {
            ClientState clientState = (ClientState)state;
            using (TcpClient client = clientState.Client)
            using (NetworkStream networkStream = client.GetStream())
            {
                // Bounds how long a single connection can sit idle mid-read or
                // mid-write, including a stalled TLS handshake (a client that
                // opens the socket and never sends a ClientHello, or a private
                // key that cannot be used and blocks instead of failing fast).
                // Without this, enough such connections exhaust the ThreadPool.
                const int SocketTimeoutMs = 30000;
                client.ReceiveTimeout = SocketTimeoutMs;
                client.SendTimeout = SocketTimeoutMs;

                Stream stream = networkStream;
                SslStream sslStream = null;
                try
                {
                    if (clientState.IsHttps)
                    {
                        X509Certificate2 certificate = serverCertificate;
                        if (certificate == null)
                        {
                            return;
                        }
                        sslStream = new SslStream(networkStream, true);
                        AuthenticateServerStream(sslStream, certificate);
                        stream = sslStream;
                    }

                    RequestContext request = ReadRequest(stream);
                    IPEndPoint remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                    request.RemoteAddress = remoteEndPoint != null ? remoteEndPoint.Address : IPAddress.None;
                    if (request.Method == "POST" && request.Path == "/api/v1/inventory")
                    {
                        ReceiveInventory(stream, request);
                    }
                    else if (!IsWebRequestAuthorized(request))
                    {
                        SendUnauthorized(stream);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/clients")
                    {
                        SendJson(stream, BuildClientIndex());
                    }
                    else if (request.Method == "DELETE" && request.Path.StartsWith("/api/v1/clients/", StringComparison.OrdinalIgnoreCase))
                    {
                        DeleteClient(stream, request);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/client-install")
                    {
                        StartClientAction(stream, request, "install");
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/client-uninstall")
                    {
                        StartClientAction(stream, request, "uninstall");
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-install")
                    {
                        SendClientInstallJobs(stream);
                    }
                    else if (request.Method == "GET" && request.Path.StartsWith("/api/v1/client-install/", StringComparison.OrdinalIgnoreCase))
                    {
                        SendClientInstallJob(stream, request);
                    }
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
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-updates/schedule")
                    {
                        SendClientUpdateScheduleStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/client-updates/schedule")
                    {
                        ConfigureClientUpdateSchedule(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-package")
                    {
                        SendClientPackageStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/client-package/configure")
                    {
                        ConfigureClientPackage(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/client-package/download")
                    {
                        DownloadClientPackage(stream);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/certificate")
                    {
                        SendCertificateStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/certificate")
                    {
                        ConfigureCertificate(stream, request);
                    }
                    else if (request.Method == "DELETE" && request.Path == "/api/v1/server/certificate")
                    {
                        DeleteConfiguredCertificate(stream);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/certificate/history")
                    {
                        SendCertificateHistory(stream);
                    }
                    else if (request.Method == "DELETE" && request.Path.StartsWith("/api/v1/server/certificate/history/", StringComparison.OrdinalIgnoreCase))
                    {
                        DeleteCertificateHistoryEntry(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/settings")
                    {
                        SendServerSettings(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/settings")
                    {
                        ConfigureServerSettings(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/admin-password")
                    {
                        SendAdminPasswordStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/admin-password")
                    {
                        ChangeAdminPassword(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/licenses")
                    {
                        SendLicenses(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/licenses")
                    {
                        CreateLicense(stream, request);
                    }
                    else if (request.Method == "PUT" && request.Path.StartsWith("/api/v1/licenses/", StringComparison.OrdinalIgnoreCase))
                    {
                        UpdateLicense(stream, request);
                    }
                    else if (request.Method == "DELETE" && request.Path.StartsWith("/api/v1/licenses/", StringComparison.OrdinalIgnoreCase))
                    {
                        DeleteLicense(stream, request);
                    }
                    else if (request.Method == "GET" && (request.Path == "/" || request.Path == "/index.html"))
                    {
                        SendDashboardFile(stream, "index.html", DashboardHtml, "text/html; charset=utf-8");
                    }
                    else if (request.Method == "GET" && request.Path == "/app.js")
                    {
                        SendDashboardFile(stream, "app.js", DashboardJs, "application/javascript; charset=utf-8");
                    }
                    else if (request.Method == "GET" && request.Path == "/styles.css")
                    {
                        SendDashboardFile(stream, "styles.css", DashboardCss, "text/css; charset=utf-8");
                    }
                    else if (request.Method == "GET" && request.Path == "/favicon.svg")
                    {
                        SendDashboardFile(stream, "favicon.svg", FaviconSvg, "image/svg+xml");
                    }
                    else
                    {
                        SendText(stream, "Not found", "text/plain; charset=utf-8", 404);
                    }
                }
                catch (Exception ex)
                {
                    try
                    {
                        System.Diagnostics.EventLog.WriteEntry(
                            "WindowsInventoryLite",
                            ex.ToString(),
                            System.Diagnostics.EventLogEntryType.Error);
                    }
                    catch { }
                    DebugLogger.Log(options, "Error", ex.ToString());
                    try
                    {
                        SendText(stream, "Internal server error.", "text/plain; charset=utf-8", 500);
                    }
                    catch { }
                }
                finally
                {
                    if (sslStream != null)
                    {
                        sslStream.Dispose();
                    }
                }
            }
        }

        // SslProtocols.None is documented (.NET Framework 4.7+) to mean "let the
        // OS negotiate the best mutually supported protocol", but on this build's
        // .NET Framework it means "no protocols enabled" and AuthenticateAsServer
        // throws ArgumentException - confirmed against real certificates on a
        // live host. A second AuthenticateAsServer call on the same SslStream
        // after a failed first attempt hangs rather than cleanly retrying, so
        // this does not try None at all: it goes straight to an explicit
        // protocol that is known to work in this environment.
        private static void AuthenticateServerStream(SslStream sslStream, X509Certificate2 certificate)
        {
            sslStream.AuthenticateAsServer(certificate, false, SslProtocols.Tls12, false);
        }

        private void ReceiveInventory(Stream stream, RequestContext request)
        {
            string token = request.Headers.ContainsKey("x-inventory-token") ? request.Headers["x-inventory-token"] : null;
            if (!String.IsNullOrEmpty(options.Token) && !FixedTimeEquals(token, options.Token))
            {
                DebugLogger.Log(options, "Client", "Rejected inventory report: invalid or missing token");
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
                DebugLogger.Log(options, "Client", "Rejected inventory report: invalid request body");
                SendText(stream, "{\"error\":\"invalid request body\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string computerName = Convert.ToString(inventory.ContainsKey("computerName") ? inventory["computerName"] : "unknown");
            string path = Path.Combine(options.DataPath, SanitizeFileName(computerName) + ".json");

            // Read the previous report and compute the AD fields (which may
            // involve a live, possibly slow AD lookup) BEFORE taking
            // reportFileLock, so a slow/unreachable AD cannot serialize
            // ingestion for the rest of the fleet behind this one request.
            // This unlocked read is safe: a torn/partial read just fails to
            // deserialize (falls back to previous = null, same as a
            // brand-new computer), it cannot corrupt anything.
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
            AdSyncFields adFields = ComputeAdSyncFields(computerName, previous);

            lock (reportFileLock)
            {
                ApplyAdSyncFields(inventory, adFields);

                string json = serializer.Serialize(inventory);
                File.WriteAllText(path, json, new UTF8Encoding(false));
            }
            DebugLogger.Log(options, "Client", "Inventory report accepted from '" + DebugLogger.SanitizeForLog(computerName) + "'");
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

        // Returns true when a raw config value is still plaintext and
        // needs migrating to encrypted storage - i.e. it's non-empty and
        // does not already carry SecretProtector's "dpapi:" prefix. Pure
        // and parameter-driven so it's directly self-testable without a
        // live config file.
        internal static bool NeedsMigration(string rawValue)
        {
            return !String.IsNullOrEmpty(rawValue) && !rawValue.StartsWith("dpapi:", StringComparison.Ordinal);
        }

        // Detects any of the 3 encrypted secrets (see EncryptedConfigKeys)
        // still stored as plaintext in server-config.json and re-encrypts
        // them in a single batched rewrite. Runs once per service start,
        // as the very first action inside Start() - cheap (one small JSON
        // parse, at most 3 DPAPI calls) and must never throw, since a
        // migration failure must not prevent the server from starting.
        private void MigratePlaintextSecrets()
        {
            if (String.IsNullOrEmpty(options.ConfigPath) || !File.Exists(options.ConfigPath))
            {
                return;
            }

            Dictionary<string, object> config;
            try
            {
                config = CreateJsonSerializer().Deserialize<Dictionary<string, object>>(
                    File.ReadAllText(options.ConfigPath, Encoding.UTF8));
            }
            catch
            {
                return;
            }

            if (config == null)
            {
                return;
            }

            Dictionary<string, string> updates = new Dictionary<string, string>();
            foreach (string key in EncryptedConfigKeys)
            {
                string raw = config.ContainsKey(key) ? Convert.ToString(config[key]) : null;
                if (NeedsMigration(raw))
                {
                    updates[key] = raw;
                }
            }

            if (updates.Count > 0)
            {
                try
                {
                    SaveServerConfigValues(updates);
                    DebugLogger.Log(options, "Server", "Migrated " + updates.Count + " plaintext secret(s) in server-config.json to encrypted storage.");
                }
                catch
                {
                    // A migration failure must not prevent the server from
                    // starting - the affected secret(s) simply stay
                    // plaintext until the next successful attempt (every
                    // subsequent startup retries).
                }
            }
        }

        // Holds the AD fields a caller should merge into a report, computed
        // by ComputeAdSyncFields. Applicable is false when AD sync is
        // disabled, in which case the other fields are meaningless and
        // ApplyAdSyncFields is a no-op.
        private sealed class AdSyncFields
        {
            public bool Applicable;
            public object Description;
            public object Status;
            public object SyncedAt;
        }

        // Decides whether a computer's cached AD data is still fresh, and
        // performs a live AD lookup (AdLookupService, up to ~15s against a
        // slow or unreachable AD) when it isn't. Deliberately does not
        // touch reportFileLock or any other lock - a caller must never call
        // this while holding reportFileLock, since a slow/unreachable AD
        // would otherwise serialize every inventory report behind whichever
        // computer's lookup is in flight. Pure with respect to shared state
        // (only reads `previous` and `options`); the caller is responsible
        // for merging the result into a report via ApplyAdSyncFields.
        private AdSyncFields ComputeAdSyncFields(string computerName, Dictionary<string, object> previous)
        {
            AdSyncFields fields = new AdSyncFields();
            if (!options.AdSyncEnabled)
            {
                return fields;
            }
            fields.Applicable = true;

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
                fields.Description = previous.ContainsKey("adDescription") ? previous["adDescription"] : null;
                fields.SyncedAt = previous.ContainsKey("adSyncedAt") ? previous["adSyncedAt"] : null;
                fields.Status = previous.ContainsKey("adSyncStatus") ? previous["adSyncStatus"] : null;
                return fields;
            }

            AdLookupResult result = AdLookupService.LookupComputerDescription(computerName, options);
            fields.Description = result.Description;
            fields.Status = result.Status;
            if (result.Status != "error")
            {
                fields.SyncedAt = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            }
            else if (previous != null && previous.ContainsKey("adSyncedAt"))
            {
                // Do not advance the sync timestamp on a failed lookup - a
                // transient AD outage should be retried on the next
                // report/sweep tick, not stick at "AD unreachable" for the
                // full AdSyncIntervalHours window. Leaving the previous
                // (already-stale, which is why this attempt ran at all)
                // timestamp in place means the next ShouldSyncAd check
                // still sees it as due.
                fields.SyncedAt = previous["adSyncedAt"];
            }
            return fields;
        }

        // Merges a previously computed AdSyncFields onto `inventory`. Pure,
        // no I/O, no lock - safe to call from inside reportFileLock right
        // before writing, which is exactly how both call sites use it: the
        // (possibly slow) lookup already happened outside the lock via
        // ComputeAdSyncFields, and only this cheap merge happens inside it.
        private static void ApplyAdSyncFields(Dictionary<string, object> inventory, AdSyncFields fields)
        {
            if (!fields.Applicable)
            {
                return;
            }
            inventory["adDescription"] = fields.Description;
            inventory["adSyncStatus"] = fields.Status;
            if (fields.SyncedAt != null)
            {
                inventory["adSyncedAt"] = fields.SyncedAt;
            }
        }

        private void DeleteClient(Stream stream, RequestContext request)
        {
            const string prefix = "/api/v1/clients/";
            string rawComputerName = request.Path.Substring(prefix.Length);
            int queryStart = rawComputerName.IndexOf('?');
            if (queryStart >= 0)
            {
                rawComputerName = rawComputerName.Substring(0, queryStart);
            }

            string computerName = Uri.UnescapeDataString(rawComputerName).Trim();
            if (String.IsNullOrEmpty(computerName))
            {
                SendText(stream, "{\"error\":\"computer name is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string fileName = SanitizeFileName(computerName) + ".json";
            string path = Path.Combine(options.DataPath, fileName);
            if (!File.Exists(path))
            {
                SendText(stream, "{\"error\":\"client not found\"}", "application/json; charset=utf-8", 404);
                return;
            }

            File.Delete(path);
            SendJson(stream, "{\"status\":\"deleted\"}");
        }

        private void StartClientAction(Stream stream, RequestContext request, string action)
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> payload = serializer.Deserialize<Dictionary<string, object>>(request.Body);
            string targetText = Convert.ToString(payload.ContainsKey("targets") ? payload["targets"] : "");
            string serverUrl = Convert.ToString(payload.ContainsKey("serverUrl") ? payload["serverUrl"] : "");
            string username = Convert.ToString(payload.ContainsKey("username") ? payload["username"] : "");
            string password = Convert.ToString(payload.ContainsKey("password") ? payload["password"] : "");
            bool useSavedCredentials = payload.ContainsKey("useSavedCredentials") && Convert.ToBoolean(payload["useSavedCredentials"]);
            ResolveUpdateCredentials(ref username, ref password, useSavedCredentials, options.ClientUpdateUsername, options.ClientUpdatePassword);
            bool force = payload.ContainsKey("force") && Convert.ToBoolean(payload["force"]);
            bool addToTrustedHosts = payload.ContainsKey("addToTrustedHosts") && Convert.ToBoolean(payload["addToTrustedHosts"]);
            int retentionDays = options.InstallLogRetentionDays;
            if (payload.ContainsKey("retentionDays"))
            {
                Int32.TryParse(Convert.ToString(payload["retentionDays"]), out retentionDays);
            }
            retentionDays = NormalizeRetentionDays(retentionDays);
            ArrayList targets = ExpandInstallTargets(targetText);

            if (targets.Count == 0)
            {
                SendText(stream, "{\"error\":\"at least one target is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            if (action == "install" && String.IsNullOrEmpty(serverUrl))
            {
                SendText(stream, "{\"error\":\"serverUrl is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            if (!addToTrustedHosts && !String.IsNullOrEmpty(username) && !String.IsNullOrEmpty(password) && ContainsIpAddressTarget(targets))
            {
                addToTrustedHosts = true;
            }

            InstallJob job = new InstallJob();
            job.Id = Guid.NewGuid().ToString("N");
            job.Action = action;
            job.Status = "queued";
            job.CreatedAtUtc = DateTime.UtcNow;
            job.Targets = targets;
            job.Results = new ArrayList();
            job.ServerUrl = serverUrl;
            job.Username = username;
            job.Password = password;
            job.Force = force;
            job.AddToTrustedHosts = addToTrustedHosts;
            job.RetentionDays = retentionDays;

            lock (installJobsLock)
            {
                installJobs[job.Id] = job;
                SaveInstallJob(job);
            }

            ThreadPool.QueueUserWorkItem(RunClientActionJob, job);
            SendJson(stream, "{\"jobId\":\"" + job.Id + "\",\"status\":\"queued\"}");
        }

        private void SendClientInstallJobs(Stream stream)
        {
            CleanupInstallJobLogs();
            ArrayList jobs = new ArrayList();
            JavaScriptSerializer serializer = CreateJsonSerializer();

            foreach (string file in Directory.GetFiles(GetInstallJobDirectory(), "*.json"))
            {
                try
                {
                    Dictionary<string, object> job = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(file, Encoding.UTF8));
                    Dictionary<string, object> summary = new Dictionary<string, object>();
                    summary["id"] = GetStringValue(job, "id");
                    summary["action"] = GetStringValue(job, "action");
                    summary["status"] = GetStringValue(job, "status");
                    summary["createdAt"] = GetStringValue(job, "createdAt");
                    summary["startedAt"] = GetStringValue(job, "startedAt");
                    summary["completedAt"] = GetStringValue(job, "completedAt");
                    summary["serverUrl"] = GetStringValue(job, "serverUrl");
                    summary["username"] = GetStringValue(job, "username");
                    summary["retentionDays"] = GetIntValue(job, "retentionDays", options.InstallLogRetentionDays);

                    ArrayList targets = job.ContainsKey("targets") ? job["targets"] as ArrayList : null;
                    ArrayList results = job.ContainsKey("results") ? job["results"] as ArrayList : null;
                    summary["targetCount"] = targets == null ? 0 : targets.Count;
                    summary["resultCount"] = results == null ? 0 : results.Count;
                    summary["failedCount"] = CountInstallResults(results, "failed");
                    jobs.Add(summary);
                }
                catch
                {
                }
            }

            ArrayList sorted = SortJobsByCreatedAtDescending(jobs);
            Dictionary<string, object> response = new Dictionary<string, object>();
            response["defaultRetentionDays"] = options.InstallLogRetentionDays;
            response["jobs"] = sorted;
            SendJson(stream, serializer.Serialize(response));
        }

        private void SendClientInstallJob(Stream stream, RequestContext request)
        {
            const string prefix = "/api/v1/client-install/";
            string id = request.Path.Substring(prefix.Length);
            int queryStart = id.IndexOf('?');
            if (queryStart >= 0)
            {
                id = id.Substring(0, queryStart);
            }

            InstallJob job = null;
            lock (installJobsLock)
            {
                if (installJobs.ContainsKey(id))
                {
                    job = installJobs[id];
                }
            }

            if (job == null)
            {
                string persisted = ReadInstallJobJson(id);
                if (persisted == null)
                {
                    SendText(stream, "{\"error\":\"job not found\"}", "application/json; charset=utf-8", 404);
                    return;
                }

                SendJson(stream, persisted);
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(job.ToDictionary()));
        }

        private void RunClientActionJob(object state)
        {
            InstallJob job = (InstallJob)state;
            job.Status = "running";
            job.StartedAtUtc = DateTime.UtcNow;
            lock (installJobsLock)
            {
                SaveInstallJob(job);
            }

            foreach (string target in job.Targets)
            {
                Dictionary<string, object> result = job.Action == "uninstall"
                    ? RunClientUninstallTarget(target, job.Username, job.Password, job.AddToTrustedHosts)
                    : RunClientInstallTarget(target, job.ServerUrl, job.Username, job.Password, job.Force, job.AddToTrustedHosts);
                lock (installJobsLock)
                {
                    job.Results.Add(result);
                    SaveInstallJob(job);
                }
            }

            job.CompletedAtUtc = DateTime.UtcNow;
            job.Status = "completed";
            lock (installJobsLock)
            {
                SaveInstallJob(job);
            }
            CleanupInstallJobLogs();
        }

        // Credentials are never embedded in the command line (see
        // BuildCredentialReaderSnippet): they travel over the child
        // process's stdin pipe instead, which - unlike ProcessStartInfo.Arguments -
        // is not visible to anything inspecting this process's static state
        // (Task Manager's Command line column, Get-Process, WMI Win32_Process,
        // etc.). It's still an OS pipe local to this machine, not encrypted
        // transport, so it doesn't protect against something actively
        // attached as a debugger - but that already implies far deeper
        // compromise than reading a process list.
        private Dictionary<string, object> RunClientInstallTarget(string target, string serverUrl, string username, string password, bool force, bool addToTrustedHosts)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["target"] = target;
            result["startedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            if (!File.Exists(options.WinRmInstallerPath))
            {
                result["status"] = "failed";
                result["message"] = "WinRM installer script was not found: " + options.WinRmInstallerPath;
                return result;
            }

            if (!Directory.Exists(options.ClientPackagePath))
            {
                result["status"] = "failed";
                result["message"] = "Client package path was not found: " + options.ClientPackagePath;
                return result;
            }

            bool hasCredential = !String.IsNullOrEmpty(username) && !String.IsNullOrEmpty(password);
            string commandBody = "[Console]::OutputEncoding = [System.Text.Encoding]::Default; $OutputEncoding = [Console]::OutputEncoding; "
                + BuildCredentialReaderSnippet(hasCredential)
                + "& " + QuotePowerShellLiteral(options.WinRmInstallerPath) + " "
                + BuildPowerShellInstallArguments(target, serverUrl, hasCredential, force, addToTrustedHosts, options.ClientPackagePath);

            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "powershell.exe";
            startInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command " + QuoteArgument(commandBody);
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardInput = hasCredential;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.CreateNoWindow = true;

            try
            {
                using (Process process = Process.Start(startInfo))
                {
                    if (hasCredential)
                    {
                        process.StandardInput.WriteLine(username);
                        process.StandardInput.WriteLine(password);
                        process.StandardInput.Close();
                    }
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    result["exitCode"] = process.ExitCode;
                    result["output"] = output;
                    result["error"] = error;
                    result["status"] = process.ExitCode == 0 ? "completed" : "failed";
                    result["message"] = process.ExitCode == 0 ? "Client install command completed." : "Client install command failed.";
                }
            }
            catch (Exception ex)
            {
                result["status"] = "failed";
                result["message"] = ex.Message;
            }

            result["completedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            return result;
        }

        // Same stdin-based credential passing as RunClientInstallTarget above.
        private Dictionary<string, object> RunClientUninstallTarget(string target, string username, string password, bool addToTrustedHosts)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["target"] = target;
            result["startedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            if (!File.Exists(options.WinRmUninstallerPath))
            {
                result["status"] = "failed";
                result["message"] = "WinRM uninstaller script was not found: " + options.WinRmUninstallerPath;
                return result;
            }

            bool hasCredential = !String.IsNullOrEmpty(username) && !String.IsNullOrEmpty(password);
            string commandBody = "[Console]::OutputEncoding = [System.Text.Encoding]::Default; $OutputEncoding = [Console]::OutputEncoding; "
                + BuildCredentialReaderSnippet(hasCredential)
                + "& " + QuotePowerShellLiteral(options.WinRmUninstallerPath) + " "
                + BuildPowerShellUninstallArguments(target, hasCredential, addToTrustedHosts);

            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "powershell.exe";
            startInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command " + QuoteArgument(commandBody);
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardInput = hasCredential;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.CreateNoWindow = true;

            try
            {
                using (Process process = Process.Start(startInfo))
                {
                    if (hasCredential)
                    {
                        process.StandardInput.WriteLine(username);
                        process.StandardInput.WriteLine(password);
                        process.StandardInput.Close();
                    }
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    result["exitCode"] = process.ExitCode;
                    result["output"] = output;
                    result["error"] = error;
                    result["status"] = process.ExitCode == 0 ? "completed" : "failed";
                    result["message"] = process.ExitCode == 0 ? "Client uninstall command completed." : "Client uninstall command failed.";
                }
            }
            catch (Exception ex)
            {
                result["status"] = "failed";
                result["message"] = ex.Message;
            }

            result["completedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            return result;
        }

        private string GetInstallJobDirectory()
        {
            return Path.Combine(options.DataPath, "_client-install-jobs");
        }

        private string GetInstallJobPath(string id)
        {
            return Path.Combine(GetInstallJobDirectory(), SanitizeFileName(id) + ".json");
        }

        private void SaveInstallJob(InstallJob job)
        {
            if (!Directory.Exists(GetInstallJobDirectory()))
            {
                Directory.CreateDirectory(GetInstallJobDirectory());
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            File.WriteAllText(GetInstallJobPath(job.Id), serializer.Serialize(job.ToDictionary()), new UTF8Encoding(false));
        }

        private string ReadInstallJobJson(string id)
        {
            string safeId = SanitizeFileName(id);
            if (String.IsNullOrEmpty(safeId) || safeId != id)
            {
                return null;
            }

            string path = GetInstallJobPath(safeId);
            if (!File.Exists(path))
            {
                return null;
            }

            return File.ReadAllText(path, Encoding.UTF8);
        }

        private void CleanupInstallJobLogs()
        {
            string directory = GetInstallJobDirectory();
            if (!Directory.Exists(directory))
            {
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            foreach (string file in Directory.GetFiles(directory, "*.json"))
            {
                try
                {
                    Dictionary<string, object> job = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(file, Encoding.UTF8));
                    DateTime createdAt = ParseUtcDate(GetStringValue(job, "createdAt"), File.GetCreationTimeUtc(file));
                    int retentionDays = NormalizeRetentionDays(GetIntValue(job, "retentionDays", options.InstallLogRetentionDays));
                    if (createdAt.AddDays(retentionDays) < DateTime.UtcNow)
                    {
                        File.Delete(file);
                    }
                }
                catch
                {
                    if (File.GetLastWriteTimeUtc(file).AddDays(options.InstallLogRetentionDays) < DateTime.UtcNow)
                    {
                        File.Delete(file);
                    }
                }
            }
        }

        private static int NormalizeRetentionDays(int value)
        {
            if (value < 1)
            {
                return 30;
            }
            if (value > 3650)
            {
                return 3650;
            }
            return value;
        }

        private static int CountInstallResults(ArrayList results, string status)
        {
            if (results == null)
            {
                return 0;
            }

            int count = 0;
            foreach (object item in results)
            {
                Dictionary<string, object> result = item as Dictionary<string, object>;
                if (result != null && String.Equals(GetStringValue(result, "status"), status, StringComparison.OrdinalIgnoreCase))
                {
                    count++;
                }
            }
            return count;
        }

        private static ArrayList SortJobsByCreatedAtDescending(ArrayList jobs)
        {
            ArrayList sorted = new ArrayList(jobs);
            sorted.Sort(new InstallJobSummaryComparer());
            return sorted;
        }

        private static DateTime ParseUtcDate(string value, DateTime fallback)
        {
            DateTime parsed;
            if (DateTime.TryParse(value, out parsed))
            {
                return parsed.ToUniversalTime();
            }
            return fallback;
        }

        private static string GetStringValue(Dictionary<string, object> source, string key)
        {
            if (source == null || !source.ContainsKey(key) || source[key] == null)
            {
                return "";
            }
            return Convert.ToString(source[key]);
        }

        private static int GetIntValue(Dictionary<string, object> source, string key, int fallback)
        {
            if (source == null || !source.ContainsKey(key) || source[key] == null)
            {
                return fallback;
            }

            int value;
            if (Int32.TryParse(Convert.ToString(source[key]), out value))
            {
                return value;
            }
            return fallback;
        }

        private static ArrayList ExpandInstallTargets(string input)
        {
            ArrayList targets = new ArrayList();
            Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            string[] parts = input.Split(new char[] { '\r', '\n', ',', ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string raw in parts)
            {
                foreach (string target in ExpandInstallTarget(raw.Trim()))
                {
                    if (!seen.ContainsKey(target))
                    {
                        seen[target] = true;
                        targets.Add(target);
                    }
                }
            }

            return targets;
        }

        private static ArrayList ExpandInstallTarget(string value)
        {
            ArrayList result = new ArrayList();
            int dash = value.IndexOf('-');
            if (dash > 0)
            {
                string left = value.Substring(0, dash);
                string right = value.Substring(dash + 1);
                IPAddress leftAddress;
                IPAddress rightAddress;
                if (IPAddress.TryParse(left, out leftAddress))
                {
                    string[] leftParts = left.Split('.');
                    int start;
                    int end;
                    if (leftParts.Length == 4 && Int32.TryParse(leftParts[3], out start) && Int32.TryParse(right, out end) && end >= start && end <= 254)
                    {
                        string prefix = leftParts[0] + "." + leftParts[1] + "." + leftParts[2] + ".";
                        for (int i = start; i <= end; i++)
                        {
                            result.Add(prefix + i);
                        }
                        return result;
                    }
                }

                if (IPAddress.TryParse(left, out leftAddress) && IPAddress.TryParse(right, out rightAddress))
                {
                    byte[] lb = leftAddress.GetAddressBytes();
                    byte[] rb = rightAddress.GetAddressBytes();
                    if (lb.Length == 4 && rb.Length == 4 && lb[0] == rb[0] && lb[1] == rb[1] && lb[2] == rb[2] && rb[3] >= lb[3])
                    {
                        string prefix = lb[0] + "." + lb[1] + "." + lb[2] + ".";
                        for (int i = lb[3]; i <= rb[3]; i++)
                        {
                            result.Add(prefix + i);
                        }
                        return result;
                    }
                }
            }

            if (!String.IsNullOrEmpty(value))
            {
                result.Add(value);
            }
            return result;
        }

        private static string QuoteArgument(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static bool ContainsIpAddressTarget(ArrayList targets)
        {
            foreach (string target in targets)
            {
                IPAddress address;
                if (IPAddress.TryParse(target, out address))
                {
                    return true;
                }
            }

            return false;
        }

        private static string QuotePowerShellLiteral(string value)
        {
            return "'" + value.Replace("'", "''") + "'";
        }

        // Fixed, non-secret variable names embedded directly in the command
        // text - there is nothing user-supplied in this snippet, so there is
        // nothing to escape or inject through it. $__wilCredential is picked
        // up by name in BuildPowerShellInstallArguments/
        // BuildPowerShellUninstallArguments below when hasCredential is true.
        private static string BuildCredentialReaderSnippet(bool hasCredential)
        {
            if (!hasCredential)
            {
                return "";
            }
            return "$__wilUser = [Console]::In.ReadLine(); $__wilPass = [Console]::In.ReadLine(); "
                + "$__wilCredential = New-Object System.Management.Automation.PSCredential($__wilUser, (ConvertTo-SecureString -String $__wilPass -AsPlainText -Force)); ";
        }

        private static string BuildPowerShellInstallArguments(string target, string serverUrl, bool hasCredential, bool force, bool addToTrustedHosts, string packagePath)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("-ComputerName ").Append(QuotePowerShellLiteral(target));
            builder.Append(" -ServerUrl ").Append(QuotePowerShellLiteral(serverUrl));
            builder.Append(" -PackagePath ").Append(QuotePowerShellLiteral(packagePath));
            if (hasCredential)
            {
                builder.Append(" -Credential $__wilCredential");
            }
            if (force)
            {
                builder.Append(" -Force");
            }
            if (addToTrustedHosts)
            {
                builder.Append(" -AddToTrustedHosts");
            }
            return builder.ToString();
        }

        private static string BuildPowerShellUninstallArguments(string target, bool hasCredential, bool addToTrustedHosts)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("-ComputerName ").Append(QuotePowerShellLiteral(target));
            if (hasCredential)
            {
                builder.Append(" -Credential $__wilCredential");
            }
            if (addToTrustedHosts)
            {
                builder.Append(" -AddToTrustedHosts");
            }
            return builder.ToString();
        }

        private bool IsWebRequestAuthorized(RequestContext request)
        {
            if (String.IsNullOrEmpty(options.WebUsername) && String.IsNullOrEmpty(options.WebPassword))
            {
                // Every route reaching this check - dashboard, settings,
                // certificate import, WinRM client install/uninstall running
                // as the service account, initial admin-password setup -
                // would otherwise be reachable by anyone who can reach the
                // port while Basic Auth is unconfigured. Restrict to the
                // local machine until an administrator sets WebUsername/
                // WebPassword. POST /api/v1/inventory is unaffected: it is
                // dispatched before this check and gated by its own Token.
                return request.RemoteAddress != null && IPAddress.IsLoopback(request.RemoteAddress);
            }

            string authorization = request.Headers.ContainsKey("authorization") ? request.Headers["authorization"] : null;
            if (String.IsNullOrEmpty(authorization) || !authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            try
            {
                string encoded = authorization.Substring(6).Trim();
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                int separator = decoded.IndexOf(':');
                if (separator < 0)
                {
                    return false;
                }

                string username = decoded.Substring(0, separator);
                string password = decoded.Substring(separator + 1);
                // Two separate FixedTimeEquals calls combined with & (not &&):
                // && would still short-circuit after the username check fails,
                // making the password comparison's timing an observable signal
                // for "was the username right." Evaluating both unconditionally
                // closes that too.
                bool usernameMatches = FixedTimeEquals(username, options.WebUsername);
                bool passwordMatches = FixedTimeEquals(password, options.WebPassword);
                return usernameMatches & passwordMatches;
            }
            catch
            {
                return false;
            }
        }

        // Ordinary == (or String.Equals) fails fast at the first mismatched
        // character, which leaks how many leading characters of a guess were
        // correct via response timing - a textbook side-channel against
        // repeated login attempts (CWE-208). This walks the full length of
        // both inputs every time regardless of where they first differ, so
        // comparison time does not depend on how close the guess was.
        // .NET Framework has no built-in constant-time compare
        // (CryptographicOperations.FixedTimeEquals is .NET Core 2.1+ only).
        private static bool FixedTimeEquals(string a, string b)
        {
            byte[] aBytes = Encoding.UTF8.GetBytes(a ?? "");
            byte[] bBytes = Encoding.UTF8.GetBytes(b ?? "");
            int length = Math.Max(aBytes.Length, bBytes.Length);
            int diff = aBytes.Length ^ bBytes.Length;
            for (int i = 0; i < length; i++)
            {
                byte x = i < aBytes.Length ? aBytes[i] : (byte)0;
                byte y = i < bBytes.Length ? bBytes[i] : (byte)0;
                diff |= x ^ y;
            }
            return diff == 0;
        }

        private void SendDashboardFile(Stream stream, string fileName, string fallback, string contentType)
        {
            string path = Path.Combine(options.ContentPath, fileName);
            if (File.Exists(path))
            {
                SendText(stream, File.ReadAllText(path, Encoding.UTF8), contentType, 200);
                return;
            }

            SendText(stream, fallback, contentType, 200);
        }

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

        private static RequestContext ReadRequest(Stream stream)
        {
            const int MaxHeaderBytes = 65536;
            const int MaxBodyBytes = 16 * 1024 * 1024;

            MemoryStream buffer = new MemoryStream();
            byte[] temp = new byte[4096];
            int headerEnd = -1;
            int scanOffset = 0;

            while (headerEnd < 0)
            {
                if (buffer.Length >= MaxHeaderBytes)
                {
                    throw new InvalidOperationException("Request headers exceed the 64 KB size limit.");
                }

                int read = stream.Read(temp, 0, temp.Length);
                if (read <= 0)
                {
                    break;
                }

                buffer.Write(temp, 0, read);
                int bufLen = (int)buffer.Length;
                headerEnd = FindHeaderEnd(buffer.GetBuffer(), bufLen, scanOffset);
                scanOffset = Math.Max(0, bufLen - 3);
            }

            byte[] raw = buffer.ToArray();
            string headerText = Encoding.ASCII.GetString(raw, 0, headerEnd);
            string[] lines = headerText.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            string[] firstLine = lines[0].Split(' ');

            RequestContext request = new RequestContext();
            request.Method = firstLine.Length > 0 ? firstLine[0].ToUpperInvariant() : "";
            request.Path = firstLine.Length > 1 ? firstLine[1] : "/";
            request.Headers = new Dictionary<string, string>();

            for (int i = 1; i < lines.Length; i++)
            {
                int separator = lines[i].IndexOf(':');
                if (separator > 0)
                {
                    request.Headers[lines[i].Substring(0, separator).Trim().ToLowerInvariant()] = lines[i].Substring(separator + 1).Trim();
                }
            }

            int contentLength = 0;
            if (request.Headers.ContainsKey("content-length"))
            {
                int parsed;
                Int32.TryParse(request.Headers["content-length"], out parsed);
                contentLength = parsed;
            }

            if (contentLength > MaxBodyBytes)
            {
                throw new InvalidOperationException("Request body exceeds the 16 MB size limit.");
            }

            int bodyOffset = headerEnd + 4;
            MemoryStream body = new MemoryStream();
            if (raw.Length > bodyOffset)
            {
                body.Write(raw, bodyOffset, raw.Length - bodyOffset);
            }

            while (body.Length < contentLength)
            {
                int read = stream.Read(temp, 0, Math.Min(temp.Length, contentLength - (int)body.Length));
                if (read <= 0)
                {
                    break;
                }
                body.Write(temp, 0, read);
            }

            request.Body = Encoding.UTF8.GetString(body.ToArray());
            return request;
        }

        private static int FindHeaderEnd(byte[] data, int length, int startIndex)
        {
            for (int i = startIndex; i < length - 3; i++)
            {
                if (data[i] == 13 && data[i + 1] == 10 && data[i + 2] == 13 && data[i + 3] == 10)
                {
                    return i;
                }
            }
            return -1;
        }

        private static void SendJson(Stream stream, string json)
        {
            SendText(stream, json, "application/json; charset=utf-8", 200);
        }

        private static JavaScriptSerializer CreateJsonSerializer()
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = 16 * 1024 * 1024;
            return serializer;
        }

        private static void SendUnauthorized(Stream stream)
        {
            byte[] body = Encoding.UTF8.GetBytes("Unauthorized");
            string header = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Windows Inventory Lite\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(body, 0, body.Length);
        }

        // script-src has no 'unsafe-inline' - the dashboard's ~20 innerHTML
        // sinks are consistently escaped (see escapeHtml/escapeHtmlOrEmpty
        // in app.js), so this is a backstop against a future unescaped sink,
        // not the primary defense. style-src needs 'unsafe-inline' for the
        // one legitimate case (bar-chart width) that sets a real inline
        // style="..." attribute through innerHTML. The one sha256 source
        // allows index.html's inline theme-restore <script> (reads
        // localStorage before styles.css loads, so a saved dark preference
        // doesn't flash light first) - it was silently CSP-blocked without
        // this, breaking theme persistence across reloads. If that inline
        // script's content ever changes, this hash must be recomputed to
        // match (the browser's own CSP-violation console message reports
        // the exact hash it expected - the fastest way to get a fresh one).
        private const string ContentSecurityPolicy =
            "default-src 'self'; script-src 'self' 'sha256-rqltRpQDffCU3nbpQC/zdbFn0/Eb4PSGrbmQ8EbS3q4='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

        private static void SendText(Stream stream, string text, string contentType, int statusCode)
        {
            byte[] body = Encoding.UTF8.GetBytes(text);
            string status = statusCode == 200 ? "OK" : (statusCode == 400 ? "Bad Request" : (statusCode == 401 ? "Unauthorized" : (statusCode == 404 ? "Not Found" : "Error")));
            string header = "HTTP/1.1 " + statusCode + " " + status +
                "\r\nContent-Type: " + contentType +
                "\r\nContent-Length: " + body.Length +
                "\r\nX-Content-Type-Options: nosniff" +
                "\r\nX-Frame-Options: DENY" +
                "\r\nContent-Security-Policy: " + ContentSecurityPolicy +
                "\r\nConnection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(body, 0, body.Length);
        }

        // Windows reserves these as device names for any file whose name is
        // exactly one of them up to the first '.', regardless of extension -
        // "CON.json" is just as reserved as "CON" itself. Case-insensitive.
        private static readonly string[] ReservedDeviceNames =
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        // Allowing '.' looks risky at a glance (doesn't ".." mean parent
        // directory?), but it's safe here: '/' and '\' are not in the allowed
        // set, so the result can never contain a path separator, and every
        // caller appends ".json" to it - a value made entirely of dots can
        // never collide with "." or ".." as a whole path segment.
        //
        // A computer legitimately reporting itself as one of the reserved
        // device names above (see ReservedDeviceNames) would otherwise make
        // every write to its own report file fail, since every caller
        // appends an extension rather than using the sanitized value bare -
        // an underscore prefix breaks the match while keeping the name
        // recognizable.
        private static string SanitizeFileName(string value)
        {
            StringBuilder builder = new StringBuilder();
            foreach (char c in value)
            {
                builder.Append(Char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' ? c : '_');
            }
            string sanitized = builder.ToString();

            int dotIndex = sanitized.IndexOf('.');
            string baseName = dotIndex >= 0 ? sanitized.Substring(0, dotIndex) : sanitized;
            foreach (string reserved in ReservedDeviceNames)
            {
                if (String.Equals(baseName, reserved, StringComparison.OrdinalIgnoreCase))
                {
                    return "_" + sanitized;
                }
            }

            return sanitized;
        }

        private sealed class RequestContext
        {
            public string Method;
            public string Path;
            public Dictionary<string, string> Headers;
            public string Body;
            public IPAddress RemoteAddress;
        }

        private sealed class InstallJob
        {
            public string Id;
            public string Action;
            public string Status;
            public DateTime CreatedAtUtc;
            public DateTime StartedAtUtc;
            public DateTime CompletedAtUtc;
            public ArrayList Targets;
            public ArrayList Results;
            public string ServerUrl;
            public string Username;
            public string Password;
            public bool Force;
            public bool AddToTrustedHosts;
            public int RetentionDays;

            public Dictionary<string, object> ToDictionary()
            {
                Dictionary<string, object> result = new Dictionary<string, object>();
                result["id"] = Id;
                result["action"] = String.IsNullOrEmpty(Action) ? "install" : Action;
                result["status"] = Status;
                result["createdAt"] = CreatedAtUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
                result["startedAt"] = StartedAtUtc == DateTime.MinValue ? null : StartedAtUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
                result["completedAt"] = CompletedAtUtc == DateTime.MinValue ? null : CompletedAtUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
                result["targets"] = Targets;
                result["results"] = Results;
                result["serverUrl"] = ServerUrl;
                result["username"] = Username;
                result["force"] = Force;
                result["addToTrustedHosts"] = AddToTrustedHosts;
                result["retentionDays"] = RetentionDays;
                return result;
            }
        }

        private sealed class InstallJobSummaryComparer : IComparer
        {
            public int Compare(object x, object y)
            {
                Dictionary<string, object> left = x as Dictionary<string, object>;
                Dictionary<string, object> right = y as Dictionary<string, object>;
                DateTime leftDate = ParseUtcDate(GetStringValue(left, "createdAt"), DateTime.MinValue);
                DateTime rightDate = ParseUtcDate(GetStringValue(right, "createdAt"), DateTime.MinValue);
                return rightDate.CompareTo(leftDate);
            }
        }

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
                result["outdatedCount"] = 0;
                SendJson(stream, serializer.Serialize(result));
                return;
            }

            result["packageAvailable"] = true;
            ArrayList updates = new ArrayList();

            foreach (Dictionary<string, object> client in LoadClientReports())
            {
                string clientVersion = GetStringValue(client, "clientVersion");
                if (IsClientVersionCurrent(clientVersion, net35Version, net40Version))
                {
                    continue;
                }

                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["computerName"] = GetStringValue(client, "computerName");
                entry["domain"] = GetStringValue(client, "domain");
                entry["clientVersion"] = clientVersion;
                entry["collectedAt"] = GetStringValue(client, "collectedAt");
                updates.Add(entry);
            }

            result["updates"] = updates;
            result["outdatedCount"] = updates.Count;
            SendJson(stream, serializer.Serialize(result));
        }

        private void SendClientPackageStatus(Stream stream)
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["packagePath"] = options.ClientPackagePath;
            result["packagePresent"] = Directory.Exists(options.ClientPackagePath);

            if (Directory.Exists(options.ClientPackagePath))
            {
                string net35Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net35.exe");
                string net40Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net40.exe");
                string deployPath = Path.Combine(options.ClientPackagePath, "Deploy-ClientGpo.ps1");
                string cmdPath = Path.Combine(options.ClientPackagePath, "Install-ClientGpo.cmd");

                string net35Version = File.Exists(net35Path) ? GetExeVersion(net35Path) : null;
                string net40Version = File.Exists(net40Path) ? GetExeVersion(net40Path) : null;
                result["net35Present"] = File.Exists(net35Path);
                result["net35Version"] = net35Version;
                result["net40Present"] = File.Exists(net40Path);
                result["net40Version"] = net40Version;
                result["deployScriptPresent"] = File.Exists(deployPath);
                result["cmdPresent"] = File.Exists(cmdPath);

                Dictionary<string, string> cmdSettings = ParseCmdSettings(cmdPath);
                result["cmdServerUrl"] = cmdSettings.ContainsKey("serverUrl") ? (object)cmdSettings["serverUrl"] : null;
                result["cmdIntervalHours"] = cmdSettings.ContainsKey("intervalHours") ? (object)cmdSettings["intervalHours"] : (object)"6";
                result["cmdToken"] = cmdSettings.ContainsKey("token") ? (object)cmdSettings["token"] : null;
                result["cmdPackageSharePath"] = cmdSettings.ContainsKey("packageSharePath") ? (object)cmdSettings["packageSharePath"] : null;
            }
            else
            {
                result["net35Present"] = false;
                result["net35Version"] = null;
                result["net40Present"] = false;
                result["net40Version"] = null;
                result["deployScriptPresent"] = false;
                result["cmdPresent"] = false;
                result["cmdServerUrl"] = null;
                result["cmdIntervalHours"] = "6";
                result["cmdToken"] = null;
                result["cmdPackageSharePath"] = null;
            }

            SendJson(stream, serializer.Serialize(result));
        }

        private void ConfigureClientPackage(Stream stream, RequestContext request)
        {
            if (!Directory.Exists(options.ClientPackagePath))
            {
                SendText(stream, "{\"error\":\"client package directory not found\"}", "application/json; charset=utf-8", 400);
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> payload = serializer.Deserialize<Dictionary<string, object>>(request.Body);
            string serverUrl = Convert.ToString(payload.ContainsKey("serverUrl") ? payload["serverUrl"] : "");
            string token = Convert.ToString(payload.ContainsKey("token") ? payload["token"] : "");
            // Only when the GPO startup script and the package files (client
            // exes, Deploy-ClientGpo.ps1) are deployed to different
            // locations - e.g. the script runs from SYSVOL but the files
            // live on a separate share. Blank means "use the folder the
            // .cmd itself runs from" (%~dp0), which is correct whenever
            // both are copied to the same place.
            string packageSharePath = Convert.ToString(payload.ContainsKey("packageSharePath") ? payload["packageSharePath"] : "");
            int intervalHours = 6;
            if (payload.ContainsKey("intervalHours"))
            {
                int parsed;
                if (Int32.TryParse(Convert.ToString(payload["intervalHours"]), out parsed))
                    intervalHours = parsed;
            }
            if (intervalHours < 1) intervalHours = 1;
            if (intervalHours > 24) intervalHours = 24;

            if (String.IsNullOrEmpty(serverUrl))
            {
                SendText(stream, "{\"error\":\"serverUrl is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string[] cmdLines;
            try
            {
                cmdLines = GenerateCmdLines(serverUrl, token, intervalHours, packageSharePath);
            }
            catch (ArgumentException ex)
            {
                SendText(stream, "{\"error\":\"" + ex.Message.Replace("\"", "'") + "\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string cmdPath = Path.Combine(options.ClientPackagePath, "Install-ClientGpo.cmd");
            File.WriteAllLines(cmdPath, cmdLines, Encoding.ASCII);

            string deployInBin = Path.Combine(Path.GetDirectoryName(options.WinRmInstallerPath), "Deploy-ClientGpo.ps1");
            string deployInPackage = Path.Combine(options.ClientPackagePath, "Deploy-ClientGpo.ps1");
            if (File.Exists(deployInBin))
            {
                File.Copy(deployInBin, deployInPackage, true);
            }

            SendClientPackageStatus(stream);
        }

        private void DownloadClientPackage(Stream stream)
        {
            if (!Directory.Exists(options.ClientPackagePath))
            {
                SendText(stream, "Client package directory not found.", "text/plain; charset=utf-8", 404);
                return;
            }

            string cmdPath = Path.Combine(options.ClientPackagePath, "Install-ClientGpo.cmd");
            if (!File.Exists(cmdPath))
            {
                SendText(stream, "{\"error\":\"Configure the server URL on this page and save before downloading - Install-ClientGpo.cmd has not been generated yet.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string net35Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net35.exe");
            string net40Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net40.exe");
            if (!File.Exists(net35Path) && !File.Exists(net40Path))
            {
                SendText(stream, "{\"error\":\"No client executable found in the package - rebuild the server (which also builds both client targets) or run New-ClientGpoPackage.ps1.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string[] includeNames = {
                "WindowsInventoryLiteClient-net35.exe",
                "WindowsInventoryLiteClient-net40.exe",
                "Deploy-ClientGpo.ps1",
                "Install-ClientGpo.cmd"
            };

            List<string> names = new List<string>();
            List<byte[]> contents = new List<byte[]>();

            foreach (string name in includeNames)
            {
                string path = Path.Combine(options.ClientPackagePath, name);
                if (File.Exists(path))
                {
                    names.Add(name);
                    contents.Add(File.ReadAllBytes(path));
                }
            }

            if (names.Count == 0)
            {
                SendText(stream, "No files found in client package directory.", "text/plain; charset=utf-8", 404);
                return;
            }

            byte[] zipBytes = BuildZip(names, contents);
            SendBytes(stream, zipBytes, "application/zip", "windows-inventory-lite-client.zip");
        }

        private Dictionary<string, object> BuildCertificateStatusPayload()
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["useHttps"] = options.UseHttps;
            result["thumbprint"] = options.CertificateThumbprint;

            X509Certificate2 certificate = serverCertificate;
            if (certificate == null && !String.IsNullOrEmpty(options.CertificateThumbprint))
            {
                // Not actively serving HTTPS right now, but a certificate is
                // configured - look it up so the page can still show its details.
                certificate = FindCertificateByThumbprint(options.CertificateThumbprint);
            }

            result["certificatePresent"] = certificate != null;
            if (certificate != null)
            {
                result["subject"] = certificate.Subject;
                result["issuer"] = certificate.Issuer;
                result["notBefore"] = certificate.NotBefore.ToUniversalTime().ToString("o");
                result["notAfter"] = certificate.NotAfter.ToUniversalTime().ToString("o");
                result["isExpired"] = DateTime.UtcNow > certificate.NotAfter.ToUniversalTime();
                result["risks"] = EvaluateCertificateRisks(certificate);
            }
            else
            {
                result["subject"] = null;
                result["issuer"] = null;
                result["notBefore"] = null;
                result["notAfter"] = null;
                result["isExpired"] = null;
                result["risks"] = new ArrayList();
            }

            return result;
        }

        private void SendCertificateStatus(Stream stream)
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(BuildCertificateStatusPayload()));
        }

        // Basic sanity checks so an operator sees the risk before flipping HTTPS on,
        // not after the service refuses every connection. None of these are exotic:
        // they are the exact reasons a browser or SslStream.AuthenticateAsServer
        // will reject a certificate outright.
        private static List<string> EvaluateCertificateRisks(X509Certificate2 certificate)
        {
            List<string> risks = new List<string>();
            if (certificate == null)
            {
                risks.Add("No certificate is configured.");
                return risks;
            }

            DateTime nowUtc = DateTime.UtcNow;
            if (nowUtc > certificate.NotAfter.ToUniversalTime())
            {
                risks.Add("The certificate expired on " + certificate.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd") + ".");
            }
            if (nowUtc < certificate.NotBefore.ToUniversalTime())
            {
                risks.Add("The certificate is not valid until " + certificate.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd") + ".");
            }
            if (!certificate.HasPrivateKey)
            {
                risks.Add("The certificate has no private key available. The service cannot serve TLS with it.");
            }

            bool hasSubjectAlternativeName = false;
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension.Oid != null && extension.Oid.Value == "2.5.29.17")
                {
                    hasSubjectAlternativeName = true;
                    break;
                }
            }
            if (!hasSubjectAlternativeName)
            {
                risks.Add("The certificate has no Subject Alternative Name. Modern browsers reject certificates without a SAN outright, regardless of trust.");
            }

            try
            {
                int keySize = certificate.PublicKey.Key.KeySize;
                if (keySize > 0 && keySize < 2048)
                {
                    risks.Add("The certificate's key is only " + keySize + " bits; most browsers now require at least 2048.");
                }
            }
            catch
            {
            }

            return risks;
        }

        private sealed class CertificateUpload
        {
            public byte[] PfxBytes;
            public string Password;
            public string Error;
        }

        private static CertificateUpload ParseCertificateUpload(string requestBody)
        {
            CertificateUpload upload = new CertificateUpload();
            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> payload;
            try
            {
                payload = serializer.Deserialize<Dictionary<string, object>>(requestBody);
            }
            catch
            {
                upload.Error = "invalid request body";
                return upload;
            }

            string pfxBase64 = Convert.ToString(payload.ContainsKey("pfxBase64") ? payload["pfxBase64"] : "");
            upload.Password = Convert.ToString(payload.ContainsKey("password") ? payload["password"] : "");

            if (String.IsNullOrEmpty(pfxBase64))
            {
                upload.Error = "pfxBase64 is required";
                return upload;
            }

            try
            {
                upload.PfxBytes = Convert.FromBase64String(pfxBase64);
            }
            catch
            {
                upload.Error = "pfxBase64 is not valid base64";
                return upload;
            }

            const int MaxPfxBytes = 1024 * 1024;
            if (upload.PfxBytes.Length == 0 || upload.PfxBytes.Length > MaxPfxBytes)
            {
                upload.Error = "certificate file must be between 1 byte and 1 MB";
            }

            return upload;
        }

        // Imports the PFX into LocalMachine\My so the certificate (and its private
        // key) survive independently of this one request/response cycle.
        private static X509Certificate2 ImportCertificateIntoStore(byte[] pfxBytes, string password, out string error, out bool isServerError)
        {
            error = null;
            isServerError = false;

            X509Certificate2 imported;
            try
            {
                imported = new X509Certificate2(
                    pfxBytes,
                    password,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                try
                {
                    System.Diagnostics.EventLog.WriteEntry(
                        "WindowsInventoryLite",
                        "Certificate import failed: " + ex.Message,
                        System.Diagnostics.EventLogEntryType.Warning);
                }
                catch { }
                error = "could not read the certificate file. Check the password and file format.";
                return null;
            }

            if (!imported.HasPrivateKey)
            {
                error = "the certificate file has no private key";
                return null;
            }

            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(imported);
            }
            catch (Exception)
            {
                error = "could not import the certificate into the local machine store. Run the service with an account that has store-write rights.";
                isServerError = true;
                return null;
            }
            finally
            {
                store.Close();
            }

            return imported;
        }

        // Stores the uploaded certificate as the configured one and, if HTTPS is
        // already active AND the certificate has no known risks, hot-swaps the
        // serving certificate immediately. It does NOT turn HTTPS on by itself -
        // that is a separate decision made from Settings > General, so an operator
        // can stage a certificate without risking the current connection. A risky
        // certificate is never hot-swapped in: the live listener keeps serving
        // whatever it was already serving until the operator explicitly
        // acknowledges the risk from Settings > General, the same gate that
        // applies to turning HTTPS on for the first time.
        private void StoreUploadedCertificate(X509Certificate2 certificate, List<string> risks)
        {
            options.CertificateThumbprint = certificate.Thumbprint;
            if (options.UseHttps && risks.Count == 0)
            {
                serverCertificate = certificate;
            }

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["CertificateThumbprint"] = certificate.Thumbprint;
            SaveServerConfigValues(updates);

            AppendCertificateHistory(certificate, risks);

            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "WindowsInventoryLite",
                    "Certificate uploaded from the dashboard. Thumbprint: " + certificate.Thumbprint + ".",
                    System.Diagnostics.EventLogEntryType.Information);
            }
            catch { }
        }

        // Imports an uploaded PFX into LocalMachine\My. The upload itself travels
        // over whatever transport is currently active - if the server is still
        // plain HTTP, do the first upload from a trusted network or console
        // session, since the PFX password rides along with the request body in
        // that case.
        private void ConfigureCertificate(Stream stream, RequestContext request)
        {
            CertificateUpload upload = ParseCertificateUpload(request.Body);
            if (upload.Error != null)
            {
                SendText(stream, "{\"error\":\"" + upload.Error + "\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string importError;
            bool isServerError;
            X509Certificate2 imported = ImportCertificateIntoStore(upload.PfxBytes, upload.Password, out importError, out isServerError);
            if (imported == null)
            {
                SendText(stream, "{\"error\":\"" + importError + "\"}", "application/json; charset=utf-8", isServerError ? 500 : 400);
                return;
            }

            List<string> risks = EvaluateCertificateRisks(imported);
            StoreUploadedCertificate(imported, risks);

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> response = BuildCertificateStatusPayload();
            SendJson(stream, serializer.Serialize(response));
        }

        // Removes the currently configured certificate from LocalMachine\My and
        // clears it from server-config.json. If HTTPS was using this certificate,
        // HTTPS is turned off too - there would be nothing left to serve it with.
        private void DeleteConfiguredCertificate(Stream stream)
        {
            if (String.IsNullOrEmpty(options.CertificateThumbprint))
            {
                SendText(stream, "{\"error\":\"no certificate is configured\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string thumbprint = options.CertificateThumbprint;
            X509Certificate2 certificate = FindCertificateByThumbprint(thumbprint);
            if (certificate != null)
            {
                X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Remove(certificate);
                }
                catch (Exception)
                {
                    SendText(stream, "{\"error\":\"could not remove the certificate from the local machine store. Run the service with an account that has store-write rights.\"}", "application/json; charset=utf-8", 500);
                    return;
                }
                finally
                {
                    store.Close();
                }
            }

            options.CertificateThumbprint = null;
            options.UseHttps = false;
            serverCertificate = null;

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["CertificateThumbprint"] = "";
            updates["UseHttps"] = "false";
            SaveServerConfigValues(updates);

            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "WindowsInventoryLite",
                    "Certificate " + thumbprint + " deleted from the dashboard. HTTPS is now off.",
                    System.Diagnostics.EventLogEntryType.Information);
            }
            catch { }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(BuildCertificateStatusPayload()));
        }

        private string GetCertificateHistoryDirectory()
        {
            return Path.Combine(options.DataPath, "_certificates");
        }

        private string GetCertificateHistoryFilePath()
        {
            return Path.Combine(GetCertificateHistoryDirectory(), "certificate-history.json");
        }

        private List<Dictionary<string, object>> LoadCertificateHistory()
        {
            string path = GetCertificateHistoryFilePath();
            if (!File.Exists(path))
            {
                return new List<Dictionary<string, object>>();
            }

            List<Dictionary<string, object>> history = new List<Dictionary<string, object>>();
            try
            {
                JavaScriptSerializer serializer = CreateJsonSerializer();
                string json = File.ReadAllText(path, Encoding.UTF8);
                ArrayList raw = serializer.Deserialize<ArrayList>(json);
                if (raw != null)
                {
                    foreach (object item in raw)
                    {
                        Dictionary<string, object> record = item as Dictionary<string, object>;
                        if (record != null)
                        {
                            history.Add(record);
                        }
                    }
                }
            }
            catch
            {
            }
            return history;
        }

        private void SaveCertificateHistory(List<Dictionary<string, object>> history)
        {
            string directory = GetCertificateHistoryDirectory();
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            string json = serializer.Serialize(history);
            File.WriteAllText(GetCertificateHistoryFilePath(), json, new UTF8Encoding(false));
        }

        private void AppendCertificateHistory(X509Certificate2 certificate, List<string> risks)
        {
            lock (certificateHistoryLock)
            {
                List<Dictionary<string, object>> history = LoadCertificateHistory();
                Dictionary<string, object> record = new Dictionary<string, object>();
                record["id"] = Guid.NewGuid().ToString("N");
                record["thumbprint"] = certificate.Thumbprint;
                record["subject"] = certificate.Subject;
                record["issuer"] = certificate.Issuer;
                record["notBefore"] = certificate.NotBefore.ToUniversalTime().ToString("o");
                record["notAfter"] = certificate.NotAfter.ToUniversalTime().ToString("o");
                record["uploadedAt"] = DateTime.UtcNow.ToString("o");
                record["risks"] = risks;
                history.Add(record);
                SaveCertificateHistory(history);
            }
        }

        private void SendCertificateHistory(Stream stream)
        {
            List<Dictionary<string, object>> history;
            lock (certificateHistoryLock)
            {
                history = LoadCertificateHistory();
            }
            history.Reverse();

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> response = new Dictionary<string, object>();
            response["history"] = history;
            SendJson(stream, serializer.Serialize(response));
        }

        private static string ExtractCertificateHistoryId(string path)
        {
            const string prefix = "/api/v1/server/certificate/history/";
            string id = path.Substring(prefix.Length);
            int queryStart = id.IndexOf('?');
            if (queryStart >= 0)
            {
                id = id.Substring(0, queryStart);
            }
            return Uri.UnescapeDataString(id).Trim();
        }

        // Removes one entry from the certificate history log. This only ever
        // touches the log file - it does not affect the certificate itself or
        // whether it is currently configured/serving HTTPS. Entries written
        // before this endpoint existed have no "id" field and cannot be
        // targeted individually; they stay until the whole log is cleared some
        // other way.
        private void DeleteCertificateHistoryEntry(Stream stream, RequestContext request)
        {
            string id = ExtractCertificateHistoryId(request.Path);

            lock (certificateHistoryLock)
            {
                List<Dictionary<string, object>> history = LoadCertificateHistory();
                int indexToRemove = -1;
                for (int i = 0; i < history.Count; i++)
                {
                    if (String.Equals(GetStringValue(history[i], "id"), id, StringComparison.OrdinalIgnoreCase))
                    {
                        indexToRemove = i;
                        break;
                    }
                }

                if (indexToRemove < 0)
                {
                    SendText(stream, "{\"error\":\"history entry not found\"}", "application/json; charset=utf-8", 404);
                    return;
                }

                history.RemoveAt(indexToRemove);
                SaveCertificateHistory(history);
            }

            SendJson(stream, "{\"status\":\"deleted\"}");
        }

        private void SendServerSettings(Stream stream)
        {
            Dictionary<string, object> result = BuildCertificateStatusPayload();
            result["staleHours"] = options.StaleHours;
            result["port"] = options.Port;
            result["enableHttp"] = options.EnableHttp;
            result["httpsPort"] = options.HttpsPort;
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
            result["debugLogEnabled"] = options.DebugLogEnabled;
            result["debugLogPath"] = DebugLogger.ResolvePath(options);
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void ConfigureServerSettings(Stream stream, RequestContext request)
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

            Dictionary<string, string> updates = new Dictionary<string, string>();

            if (payload.ContainsKey("staleHours"))
            {
                int staleHours;
                if (!Int32.TryParse(Convert.ToString(payload["staleHours"]), out staleHours) || staleHours < 1 || staleHours > 8760)
                {
                    SendText(stream, "{\"error\":\"staleHours must be between 1 and 8760\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.StaleHours = staleHours;
                updates["StaleHours"] = staleHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            // HTTP and HTTPS are validated together, not field-by-field, because
            // the one rule that actually matters - "at least one of them must
            // end up reachable" - spans both. Nothing here is applied to the
            // live listeners until every check below has passed.
            bool desiredUseHttps = options.UseHttps;
            X509Certificate2 httpsCandidate = null;
            if (payload.ContainsKey("useHttps"))
            {
                desiredUseHttps = Convert.ToBoolean(payload["useHttps"]);
                if (desiredUseHttps)
                {
                    bool acknowledgeRisks = payload.ContainsKey("acknowledgeRisks") && Convert.ToBoolean(payload["acknowledgeRisks"]);

                    if (String.IsNullOrEmpty(options.CertificateThumbprint))
                    {
                        SendText(stream, "{\"error\":\"no certificate has been uploaded yet. Upload one on the Certificate page first.\"}", "application/json; charset=utf-8", 400);
                        return;
                    }

                    httpsCandidate = FindCertificateByThumbprint(options.CertificateThumbprint);
                    if (httpsCandidate == null)
                    {
                        SendText(stream, "{\"error\":\"the configured certificate was not found in LocalMachine\\\\My.\"}", "application/json; charset=utf-8", 400);
                        return;
                    }

                    List<string> risks = EvaluateCertificateRisks(httpsCandidate);
                    if (risks.Count > 0 && !acknowledgeRisks)
                    {
                        Dictionary<string, object> riskResponse = new Dictionary<string, object>();
                        riskResponse["error"] = "the certificate has risks that may prevent the service from serving HTTPS. Confirm to proceed anyway.";
                        riskResponse["risks"] = risks;
                        SendText(stream, serializer.Serialize(riskResponse), "application/json; charset=utf-8", 409);
                        return;
                    }
                }
            }

            bool desiredEnableHttp = options.EnableHttp;
            if (payload.ContainsKey("enableHttp"))
            {
                desiredEnableHttp = Convert.ToBoolean(payload["enableHttp"]);
            }

            // The one hard rule: refusing this combination here is what makes
            // "edit server-config.json and restart the service" the ONLY way
            // to end up with a fully unreachable dashboard, not something
            // reachable through the dashboard itself. See docs/threat-model.md
            // and the README's HTTP recovery section.
            if (!desiredEnableHttp && !desiredUseHttps)
            {
                SendText(stream, "{\"error\":\"cannot disable HTTP unless HTTPS is enabled and working - that would make the dashboard unreachable.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            int desiredHttpPort = options.Port;
            if (payload.ContainsKey("port"))
            {
                if (!Int32.TryParse(Convert.ToString(payload["port"]), out desiredHttpPort) || desiredHttpPort < 1 || desiredHttpPort > 65535)
                {
                    SendText(stream, "{\"error\":\"port must be between 1 and 65535\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }

            int desiredHttpsPort = options.HttpsPort;
            if (payload.ContainsKey("httpsPort"))
            {
                if (!Int32.TryParse(Convert.ToString(payload["httpsPort"]), out desiredHttpsPort) || desiredHttpsPort < 1 || desiredHttpsPort > 65535)
                {
                    SendText(stream, "{\"error\":\"httpsPort must be between 1 and 65535\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }

            if (desiredEnableHttp && desiredUseHttps && desiredHttpPort == desiredHttpsPort)
            {
                SendText(stream, "{\"error\":\"the HTTP and HTTPS ports must be different when both are enabled.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            // HTTPS is applied before HTTP, not just validated before HTTP -
            // deliberately, and in this order for a reason: the dashboard's
            // General Settings form always submits port/enableHttp/useHttps/
            // httpsPort together in one request, so "turn HTTPS on and turn
            // HTTP off" is a single call with both blocks active. ApplySlotState
            // never touches a slot's old listener when a new bind fails, so
            // whichever block runs SECOND is the one that's still safe to fail:
            // if HTTPS is applied first and its bind fails, we return before
            // ever touching the HTTP slot, so HTTP is untouched. Applying HTTP's
            // disable first would instead have already stopped a real, working
            // listener before finding out whether HTTPS could replace it -
            // exactly the fully-unreachable state the check above exists to
            // prevent, just reached through a failed bind instead of a bad
            // request.
            if (payload.ContainsKey("useHttps") || payload.ContainsKey("httpsPort"))
            {
                if (desiredUseHttps)
                {
                    if (httpsCandidate != null)
                    {
                        serverCertificate = httpsCandidate;
                    }
                    string httpsError = ApplySlotState(httpsSlot, true, options.HttpsPort, desiredHttpsPort, true);
                    if (httpsError != null)
                    {
                        SendText(stream, "{\"error\":\"HTTPS: " + httpsError + "\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                }
                else
                {
                    ApplySlotState(httpsSlot, false, options.HttpsPort, options.HttpsPort, true);
                    serverCertificate = null;
                }
                options.UseHttps = desiredUseHttps;
                options.HttpsPort = desiredHttpsPort;
                updates["UseHttps"] = options.UseHttps ? "true" : "false";
                updates["HttpsPort"] = options.HttpsPort.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("port") || payload.ContainsKey("enableHttp"))
            {
                string httpError = ApplySlotState(httpSlot, desiredEnableHttp, options.Port, desiredHttpPort, false);
                if (httpError != null)
                {
                    SendText(stream, "{\"error\":\"HTTP: " + httpError + "\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.Port = desiredHttpPort;
                options.EnableHttp = desiredEnableHttp;
                // ListenPrefix, not just a bare port number, because that's the
                // format Install-Server.ps1 both writes and re-reads from this
                // same config file on every install/reinstall - keeping the
                // same key means a future reinstall picks up this port instead
                // of reverting to whatever was baked in at install time.
                updates["ListenPrefix"] = "http://+:" + options.Port + "/";
                updates["EnableHttp"] = options.EnableHttp ? "true" : "false";
            }

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

            if (payload.ContainsKey("debugLogEnabled"))
            {
                // The log path is deliberately not settable from here - it
                // stays CLI/config-only, so this endpoint can't be used to
                // make the server write an arbitrary file path.
                options.DebugLogEnabled = Convert.ToBoolean(payload["debugLogEnabled"]);
                updates["DebugLogEnabled"] = options.DebugLogEnabled ? "true" : "false";
            }

            if (updates.Count > 0)
            {
                SaveServerConfigValues(updates);
            }

            SendServerSettings(stream);
        }

        private void SendAdminPasswordStatus(Stream stream)
        {
            bool configured = !String.IsNullOrEmpty(options.WebUsername) && !String.IsNullOrEmpty(options.WebPassword);
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["configured"] = configured;
            result["username"] = configured ? options.WebUsername : null;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

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

            bool clear = payload.ContainsKey("clear") && Convert.ToBoolean(payload["clear"]);
            string username;
            string password;
            if (clear)
            {
                username = "";
                password = "";
            }
            else
            {
                username = payload.ContainsKey("username") ? Convert.ToString(payload["username"]) : options.ClientUpdateUsername;
                // Blank/omitted password means "keep the existing one" - the
                // dashboard never pre-fills a password field with the real
                // stored value, matching the AD credentials save endpoint.
                password = payload.ContainsKey("password") && !String.IsNullOrEmpty(Convert.ToString(payload["password"]))
                    ? Convert.ToString(payload["password"])
                    : options.ClientUpdatePassword;
            }

            options.ClientUpdateUsername = username;
            options.ClientUpdatePassword = password;

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["ClientUpdateUsername"] = username ?? "";
            updates["ClientUpdatePassword"] = password ?? "";
            SaveServerConfigValues(updates);

            SendClientUpdateCredentialsStatus(stream);
        }

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

        // Doubles as first-time setup and password rotation. Bootstrapping without
        // a current-password check is reachable by anyone on the network while
        // Basic Auth is unconfigured, but at that point the whole dashboard is
        // already open (WinRM install/uninstall, client deletion, certificate
        // upload) - gating only this one endpoint would not meaningfully reduce
        // exposure. Once configured, changing the password always requires the
        // current one.
        private void ChangeAdminPassword(Stream stream, RequestContext request)
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

            bool alreadyConfigured = !String.IsNullOrEmpty(options.WebUsername) && !String.IsNullOrEmpty(options.WebPassword);
            string newUsername = Convert.ToString(payload.ContainsKey("newUsername") ? payload["newUsername"] : "").Trim();
            string newPassword = Convert.ToString(payload.ContainsKey("newPassword") ? payload["newPassword"] : "");

            if (alreadyConfigured)
            {
                string currentPassword = Convert.ToString(payload.ContainsKey("currentPassword") ? payload["currentPassword"] : "");
                if (!FixedTimeEquals(currentPassword, options.WebPassword))
                {
                    SendText(stream, "{\"error\":\"current password is incorrect\"}", "application/json; charset=utf-8", 401);
                    return;
                }
                if (String.IsNullOrEmpty(newUsername))
                {
                    newUsername = options.WebUsername;
                }
            }
            else if (String.IsNullOrEmpty(newUsername))
            {
                SendText(stream, "{\"error\":\"username is required for initial setup\"}", "application/json; charset=utf-8", 400);
                return;
            }

            if (newPassword.Length < 8)
            {
                SendText(stream, "{\"error\":\"new password must be at least 8 characters\"}", "application/json; charset=utf-8", 400);
                return;
            }

            options.WebUsername = newUsername;
            options.WebPassword = newPassword;

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["WebUsername"] = newUsername;
            updates["WebPassword"] = newPassword;
            SaveServerConfigValues(updates);

            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "WindowsInventoryLite",
                    alreadyConfigured
                        ? "Dashboard admin password changed from the Settings page."
                        : "Dashboard Basic Auth configured for the first time from the Settings page.",
                    System.Diagnostics.EventLogEntryType.Information);
            }
            catch { }

            SendJson(stream, "{\"status\":\"ok\"}");
        }

        // AdPassword, WebPassword, and Token are encrypted at rest (DPAPI,
        // see SecretProtector.cs) before being written to server-config.json
        // by SaveServerConfigValues below, and decrypted on load by
        // LoadConfigFile. CertificatePfxPassword is NOT in this set - it is
        // never persisted to server-config.json at all (it flows only into
        // a local SecureString used once for a PFX import, in both
        // ConfigureCertificate here and Install-Server.ps1's own import
        // step), so there is nothing to encrypt for it.
        private static readonly HashSet<string> EncryptedConfigKeys = new HashSet<string>(
            new[] { "AdPassword", "WebPassword", "Token", "ClientUpdatePassword" },
            StringComparer.Ordinal);

        private void SaveServerConfigValues(Dictionary<string, string> updates)
        {
            if (String.IsNullOrEmpty(options.ConfigPath))
            {
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> config;
            if (File.Exists(options.ConfigPath))
            {
                try
                {
                    string existing = File.ReadAllText(options.ConfigPath, Encoding.UTF8);
                    config = serializer.Deserialize<Dictionary<string, object>>(existing) ?? new Dictionary<string, object>();
                }
                catch
                {
                    config = new Dictionary<string, object>();
                }
            }
            else
            {
                config = new Dictionary<string, object>();
            }

            foreach (KeyValuePair<string, string> pair in updates)
            {
                config[pair.Key] = EncryptedConfigKeys.Contains(pair.Key) ? SecretProtector.Protect(pair.Value, options) : pair.Value;
            }

            string json = serializer.Serialize(config);
            File.WriteAllText(options.ConfigPath, json, new UTF8Encoding(false));
            ApplyRestrictedConfigAcl(options.ConfigPath);
        }

        // Mirrors Install-Server.ps1's Set-RestrictedFileAcl: restricts
        // server-config.json to Administrators + SYSTEM only. This file can
        // hold DPAPI-LocalMachine-protected secrets (AdPassword/WebPassword/
        // Token, see SecretProtector.cs) which ANY local process can decrypt
        // - the file's DACL is the only real confidentiality boundary for
        // them. Reapplied on every write, not just at install time, so the
        // file can never drift back to an inherited (broader) ACL if it is
        // ever deleted and recreated by the running service.
        private void ApplyRestrictedConfigAcl(string path)
        {
            try
            {
                SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                FileSecurity acl = File.GetAccessControl(path);
                acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));
                acl.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
                File.SetAccessControl(path, acl);
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "Config", "Could not restrict server-config.json permissions: " + DebugLogger.SanitizeForLog(ex.Message));
            }
        }

        // License inventory is an admin-entered catalog (name/version/license/comment),
        // separate from the per-client software lists collected from hosts. Stored as a
        // single JSON array under a subfolder so it never gets picked up by
        // BuildClientIndex, which scans DataPath's top-level *.json files as client reports.
        private string GetLicensesDirectory()
        {
            return Path.Combine(options.DataPath, "_licenses");
        }

        private string GetLicensesFilePath()
        {
            return Path.Combine(GetLicensesDirectory(), "licenses.json");
        }

        private List<Dictionary<string, object>> LoadLicenses()
        {
            string path = GetLicensesFilePath();
            if (!File.Exists(path))
            {
                return new List<Dictionary<string, object>>();
            }

            List<Dictionary<string, object>> licenses = new List<Dictionary<string, object>>();
            try
            {
                JavaScriptSerializer serializer = CreateJsonSerializer();
                string json = File.ReadAllText(path, Encoding.UTF8);
                ArrayList raw = serializer.Deserialize<ArrayList>(json);
                if (raw != null)
                {
                    foreach (object item in raw)
                    {
                        Dictionary<string, object> record = item as Dictionary<string, object>;
                        if (record != null)
                        {
                            licenses.Add(record);
                        }
                    }
                }
            }
            catch
            {
            }
            return licenses;
        }

        private void SaveLicenses(List<Dictionary<string, object>> licenses)
        {
            string directory = GetLicensesDirectory();
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            string json = serializer.Serialize(licenses);
            File.WriteAllText(GetLicensesFilePath(), json, new UTF8Encoding(false));
        }

        private static string ExtractLicenseId(string path)
        {
            const string prefix = "/api/v1/licenses/";
            string id = path.Substring(prefix.Length);
            int queryStart = id.IndexOf('?');
            if (queryStart >= 0)
            {
                id = id.Substring(0, queryStart);
            }
            return Uri.UnescapeDataString(id).Trim();
        }

        // Accepts the raw "computers" payload value (expected to be a JSON array
        // deserialized as ArrayList) and returns a trimmed, de-duplicated list.
        // De-duplication is case-insensitive but keeps the first-seen casing,
        // matching ExpandInstallTargets' behavior for the same kind of input.
        private static ArrayList NormalizeComputerList(object rawComputers)
        {
            ArrayList result = new ArrayList();
            ArrayList source = rawComputers as ArrayList;
            if (source == null)
            {
                return result;
            }

            Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (object item in source)
            {
                string computer = Convert.ToString(item).Trim();
                if (computer.Length == 0 || seen.ContainsKey(computer))
                {
                    continue;
                }
                seen[computer] = true;
                result.Add(computer);
            }
            return result;
        }

        private void SendLicenses(Stream stream)
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            List<Dictionary<string, object>> licenses;
            lock (licensesLock)
            {
                licenses = LoadLicenses();
            }

            Dictionary<string, object> response = new Dictionary<string, object>();
            response["licenses"] = licenses;
            SendJson(stream, serializer.Serialize(response));
        }

        private void CreateLicense(Stream stream, RequestContext request)
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

            string name = Convert.ToString(payload.ContainsKey("name") ? payload["name"] : "").Trim();
            if (String.IsNullOrEmpty(name))
            {
                SendText(stream, "{\"error\":\"name is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string nowUtc = DateTime.UtcNow.ToString("o");
            Dictionary<string, object> record = new Dictionary<string, object>();
            record["id"] = Guid.NewGuid().ToString("N");
            record["name"] = name;
            record["version"] = Convert.ToString(payload.ContainsKey("version") ? payload["version"] : "").Trim();
            record["license"] = Convert.ToString(payload.ContainsKey("license") ? payload["license"] : "").Trim();
            record["comment"] = Convert.ToString(payload.ContainsKey("comment") ? payload["comment"] : "").Trim();
            record["computers"] = NormalizeComputerList(payload.ContainsKey("computers") ? payload["computers"] : null);
            record["createdAt"] = nowUtc;
            record["updatedAt"] = nowUtc;

            lock (licensesLock)
            {
                List<Dictionary<string, object>> licenses = LoadLicenses();
                licenses.Add(record);
                SaveLicenses(licenses);
            }

            SendJson(stream, serializer.Serialize(record));
        }

        private void UpdateLicense(Stream stream, RequestContext request)
        {
            string id = ExtractLicenseId(request.Path);

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

            string name = Convert.ToString(payload.ContainsKey("name") ? payload["name"] : "").Trim();
            if (String.IsNullOrEmpty(name))
            {
                SendText(stream, "{\"error\":\"name is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            lock (licensesLock)
            {
                List<Dictionary<string, object>> licenses = LoadLicenses();
                Dictionary<string, object> record = null;
                for (int i = 0; i < licenses.Count; i++)
                {
                    if (String.Equals(GetStringValue(licenses[i], "id"), id, StringComparison.OrdinalIgnoreCase))
                    {
                        record = licenses[i];
                        break;
                    }
                }

                if (record == null)
                {
                    SendText(stream, "{\"error\":\"license not found\"}", "application/json; charset=utf-8", 404);
                    return;
                }

                record["name"] = name;
                record["version"] = Convert.ToString(payload.ContainsKey("version") ? payload["version"] : "").Trim();
                record["license"] = Convert.ToString(payload.ContainsKey("license") ? payload["license"] : "").Trim();
                record["comment"] = Convert.ToString(payload.ContainsKey("comment") ? payload["comment"] : "").Trim();
                record["computers"] = NormalizeComputerList(payload.ContainsKey("computers") ? payload["computers"] : null);
                record["updatedAt"] = DateTime.UtcNow.ToString("o");

                SaveLicenses(licenses);
                SendJson(stream, serializer.Serialize(record));
            }
        }

        private void DeleteLicense(Stream stream, RequestContext request)
        {
            string id = ExtractLicenseId(request.Path);

            lock (licensesLock)
            {
                List<Dictionary<string, object>> licenses = LoadLicenses();
                int indexToRemove = -1;
                for (int i = 0; i < licenses.Count; i++)
                {
                    if (String.Equals(GetStringValue(licenses[i], "id"), id, StringComparison.OrdinalIgnoreCase))
                    {
                        indexToRemove = i;
                        break;
                    }
                }

                if (indexToRemove < 0)
                {
                    SendText(stream, "{\"error\":\"license not found\"}", "application/json; charset=utf-8", 404);
                    return;
                }

                licenses.RemoveAt(indexToRemove);
                SaveLicenses(licenses);
            }

            SendJson(stream, "{\"status\":\"deleted\"}");
        }

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

        // Client updates sends useSavedCredentials=true (Client actions never
        // does - its own per-action fields have no persisted counterpart) to
        // signal that blank username/password should fall back to the saved
        // ClientUpdateUsername/ClientUpdatePassword instead of silently
        // running under the service's own identity. A typed per-push value
        // always wins over the saved one, matching this feature's original
        // design: per-push override, then the saved account, then the
        // service identity. Without this, the saved credentials were stored
        // correctly but never actually reached a push - the dashboard's
        // password field is cleared right after a successful Save (so the
        // password can't be echoed back), and the push read straight from
        // that same now-empty field, so it silently fell back to the
        // service identity on every push after the first Save.
        private static void ResolveUpdateCredentials(ref string username, ref string password, bool useSavedCredentials, string savedUsername, string savedPassword)
        {
            if (useSavedCredentials && String.IsNullOrEmpty(username) && String.IsNullOrEmpty(password))
            {
                username = savedUsername ?? "";
                password = savedPassword ?? "";
            }
        }

        private static Dictionary<string, string> ParseCmdSettings(string cmdPath)
        {
            Dictionary<string, string> settings = new Dictionary<string, string>();
            if (!File.Exists(cmdPath)) return settings;

            foreach (string line in File.ReadAllLines(cmdPath, Encoding.ASCII))
            {
                string t = line.Trim();
                if (t.StartsWith("set SERVER_URL=", StringComparison.OrdinalIgnoreCase))
                    settings["serverUrl"] = t.Substring(15).Replace("%%", "%");
                else if (t.StartsWith("set INTERVAL_HOURS=", StringComparison.OrdinalIgnoreCase))
                    settings["intervalHours"] = t.Substring(19).Trim();
                else if (t.StartsWith("set ARGS=%ARGS% -Token", StringComparison.OrdinalIgnoreCase))
                {
                    int idx = t.IndexOf("-Token \"");
                    if (idx >= 0)
                    {
                        int start = idx + 8;
                        int end = t.IndexOf('"', start);
                        if (end > start)
                            settings["token"] = t.Substring(start, end - start).Replace("%%", "%");
                    }
                }
                else if (t.StartsWith("set PACKAGE_ROOT=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = t.Substring(17).Replace("%%", "%");
                    // "%~dp0" (the script's own folder) is the default -
                    // only surface it as a configured value when it's
                    // something else, so the dashboard field shows blank
                    // (the "using the default" state) rather than the
                    // literal batch-file token.
                    if (!String.Equals(value, "%~dp0", StringComparison.OrdinalIgnoreCase))
                    {
                        settings["packageSharePath"] = value;
                    }
                }
            }

            return settings;
        }

        // Batch files treat &, |, <, >, ^ and an unbalanced " as live command
        // separators/redirection - serverUrl and packageSharePath land on a
        // SET line with no surrounding quotes at all, and token's quotes can
        // be broken out of with an embedded ". A value containing any of
        // these (or a line break, which injects a whole extra statement)
        // turns Install-ClientGpo.cmd into an attacker-controlled script that
        // a GPO computer startup script later runs as SYSTEM on every
        // deployed client. % is handled separately via doubling, not
        // rejected here, since it's expected in URLs/tokens.
        private static readonly char[] BatchUnsafeChars = { '"', '&', '|', '<', '>', '^', '\r', '\n' };

        private static void ValidateBatchSafe(string value, string fieldName)
        {
            if (!String.IsNullOrEmpty(value) && value.IndexOfAny(BatchUnsafeChars) >= 0)
            {
                throw new ArgumentException(fieldName + " contains a character that is not allowed here (\", &, |, <, >, ^, or a line break).");
            }
        }

        private static string[] GenerateCmdLines(string serverUrl, string token, int intervalHours, string packageSharePath)
        {
            ValidateBatchSafe(serverUrl, "serverUrl");
            ValidateBatchSafe(token, "token");
            ValidateBatchSafe(packageSharePath, "packageSharePath");

            string escapedUrl = serverUrl.Replace("%", "%%");
            string packageRoot = String.IsNullOrEmpty(packageSharePath)
                ? "%~dp0"
                : packageSharePath.Replace("%", "%%").TrimEnd('\\');
            List<string> lines = new List<string>();
            lines.Add("@echo off");
            lines.Add("setlocal");
            lines.Add("");
            lines.Add("set PACKAGE_ROOT=" + packageRoot);
            lines.Add("set SERVER_URL=" + escapedUrl);
            lines.Add("set INTERVAL_HOURS=" + intervalHours);
            lines.Add("set DEPLOY_SCRIPT=%PACKAGE_ROOT%\\Deploy-ClientGpo.ps1");
            lines.Add("set WAIT_SECONDS=90");
            lines.Add("");
            lines.Add("set ARGS=-ServerUrl \"%SERVER_URL%\" -IntervalHours %INTERVAL_HOURS%");
            if (!String.IsNullOrEmpty(token))
                lines.Add("set ARGS=%ARGS% -Token \"" + token.Replace("%", "%%") + "\"");
            lines.Add("");
            lines.Add(":WAIT_PACKAGE");
            lines.Add("if exist \"%DEPLOY_SCRIPT%\" goto RUN_DEPLOY");
            lines.Add("if \"%WAIT_SECONDS%\"==\"0\" exit /b 2");
            lines.Add("ping -n 2 127.0.0.1 >nul");
            lines.Add("set /a WAIT_SECONDS-=1");
            lines.Add("goto WAIT_PACKAGE");
            lines.Add("");
            lines.Add(":RUN_DEPLOY");
            lines.Add("powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%DEPLOY_SCRIPT%\" %ARGS%");
            lines.Add("");
            lines.Add("exit /b %ERRORLEVEL%");
            return lines.ToArray();
        }

        private static byte[] BuildZip(List<string> names, List<byte[]> contents)
        {
            MemoryStream ms = new MemoryStream();
            List<int> offsets = new List<int>();
            List<uint> crcs = new List<uint>();

            for (int i = 0; i < names.Count; i++)
            {
                offsets.Add((int)ms.Length);
                byte[] nameBytes = Encoding.UTF8.GetBytes(names[i]);
                byte[] data = contents[i];
                uint crc = Crc32Checksum(data);
                crcs.Add(crc);
                WriteZipInt32(ms, 0x04034b50);
                WriteZipInt16(ms, 20); WriteZipInt16(ms, 0); WriteZipInt16(ms, 0);
                WriteZipInt16(ms, 0); WriteZipInt16(ms, 0x4a21);
                WriteZipInt32(ms, (int)crc);
                WriteZipInt32(ms, data.Length); WriteZipInt32(ms, data.Length);
                WriteZipInt16(ms, nameBytes.Length); WriteZipInt16(ms, 0);
                ms.Write(nameBytes, 0, nameBytes.Length);
                ms.Write(data, 0, data.Length);
            }

            int centralStart = (int)ms.Length;
            for (int i = 0; i < names.Count; i++)
            {
                byte[] nameBytes = Encoding.UTF8.GetBytes(names[i]);
                byte[] data = contents[i];
                WriteZipInt32(ms, 0x02014b50);
                WriteZipInt16(ms, 20); WriteZipInt16(ms, 20); WriteZipInt16(ms, 0);
                WriteZipInt16(ms, 0); WriteZipInt16(ms, 0); WriteZipInt16(ms, 0x4a21);
                WriteZipInt32(ms, (int)crcs[i]);
                WriteZipInt32(ms, data.Length); WriteZipInt32(ms, data.Length);
                WriteZipInt16(ms, nameBytes.Length); WriteZipInt16(ms, 0); WriteZipInt16(ms, 0);
                WriteZipInt16(ms, 0); WriteZipInt16(ms, 0); WriteZipInt32(ms, 0);
                WriteZipInt32(ms, offsets[i]);
                ms.Write(nameBytes, 0, nameBytes.Length);
            }

            int centralSize = (int)ms.Length - centralStart;
            WriteZipInt32(ms, 0x06054b50);
            WriteZipInt16(ms, 0); WriteZipInt16(ms, 0);
            WriteZipInt16(ms, names.Count); WriteZipInt16(ms, names.Count);
            WriteZipInt32(ms, centralSize); WriteZipInt32(ms, centralStart);
            WriteZipInt16(ms, 0);
            return ms.ToArray();
        }

        private static uint Crc32Checksum(byte[] data)
        {
            uint crc = 0xFFFFFFFF;
            foreach (byte b in data)
            {
                crc ^= b;
                for (int j = 0; j < 8; j++)
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
            return crc ^ 0xFFFFFFFF;
        }

        private static void WriteZipInt16(MemoryStream ms, int value)
        {
            ms.Write(BitConverter.GetBytes((short)value), 0, 2);
        }

        private static void WriteZipInt32(MemoryStream ms, int value)
        {
            ms.Write(BitConverter.GetBytes(value), 0, 4);
        }

        private static void SendBytes(Stream stream, byte[] data, string contentType, string filename)
        {
            string header = "HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nContent-Disposition: attachment; filename=\"" + filename + "\"\r\nContent-Length: " + data.Length + "\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: " + ContentSecurityPolicy + "\r\nConnection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(data, 0, data.Length);
        }

        // Last-resort fallback, used only by SendDashboardFile when ContentPath
        // is missing the real file (e.g. a botched install that never copied
        // server\dashboard\* into place). Deliberately a minimal, old snapshot
        // of the dashboard (no tree nav, no Licenses/Settings/Dashboard pages) -
        // it exists so the server still answers with something useful instead
        // of a blank page, not to track feature parity with the real dashboard.
        // Do not "fix" it to match current features; fix the install/deploy
        // path that left ContentPath empty instead.
        private const string DashboardHtml = @"<!doctype html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1""><title>Windows Inventory Lite</title><link rel=""stylesheet"" href=""/styles.css""></head><body><header class=""topbar""><div><h1>Windows Inventory Lite</h1><p id=""generatedAt"">Waiting for inventory data.</p></div><input id=""searchInput"" type=""search"" placeholder=""Filter computers, OS, Office, software""></header><main><section class=""summary""><div><span id=""clientCount"">0</span><small>Clients</small></div><div><span id=""windowsActivated"">0</span><small>Windows activated</small></div><div><span id=""officeActivated"">0</span><small>Office activated</small></div><div><span id=""staleCount"">0</span><small>Stale &gt;48h</small></div></section><section class=""table-wrap""><table><thead><tr><th>Computer</th><th>OS</th><th>Office</th><th>Windows</th><th>Office activation</th><th>Software</th><th>Collected</th></tr></thead><tbody id=""inventoryBody""></tbody></table></section></main><script src=""/app.js""></script></body></html>";

        // Fallback for /app.js, same reasoning as DashboardHtml above.
        private const string DashboardJs = @"(function(){const staleHours=48;const state={clients:[]};function byId(id){return document.getElementById(id)}function text(v){return v===undefined||v===null||v===''?'Unknown':String(v)}function activated(v){return v?'Activated':'Not detected'}function isStale(c){const d=new Date(c.collectedAt||c.sourceUpdatedAt||0);return Number.isNaN(d.getTime())||((Date.now()-d.getTime())/36e5)>staleHours}function matches(c,q){if(!q)return true;const software=(c.software||[]).map(i=>`${i.name} ${i.version}`).join(' ');const h=[c.computerName,c.domain,c.os&&c.os.caption,c.os&&c.os.version,c.office&&c.office.name,c.office&&c.office.version,software].join(' ').toLowerCase();return h.indexOf(q.toLowerCase())!==-1}function summary(clients){byId('clientCount').textContent=clients.length;byId('windowsActivated').textContent=clients.filter(c=>c.activation&&c.activation.windows&&c.activation.windows.activated).length;byId('officeActivated').textContent=clients.filter(c=>c.activation&&c.activation.office&&c.activation.office.activated).length;byId('staleCount').textContent=clients.filter(isStale).length}function table(clients){const q=byId('searchInput').value.trim();const rows=clients.filter(c=>matches(c,q)).map(c=>{const os=c.os||{},office=c.office||{},a=c.activation||{},wa=a.windows||{},oa=a.office||{},count=(c.software||[]).length;return `<tr class=""${isStale(c)?'stale':''}""><td><strong>${text(c.computerName)}</strong><small>${text(c.domain)}</small></td><td>${text(os.caption)}<small>${text(os.version)} build ${text(os.buildNumber)}</small></td><td>${text(office.name)}<small>${text(office.version)}</small></td><td>${activated(wa.activated)}</td><td>${activated(oa.activated)}</td><td>${count}</td><td>${text(c.collectedAt)}</td></tr>`});byId('inventoryBody').innerHTML=rows.join('')||'<tr><td colspan=""7"" class=""empty"">No matching inventory records.</td></tr>'}function render(){summary(state.clients);table(state.clients)}fetch('/api/v1/clients',{cache:'no-store'}).then(r=>{if(!r.ok)throw new Error(`HTTP ${r.status}`);return r.json()}).then(d=>{state.clients=d.clients||[];byId('generatedAt').textContent=`Generated: ${text(d.generatedAt)}`;render()}).catch(e=>{byId('generatedAt').textContent=`Inventory index is not available: ${e.message}`;render()});byId('searchInput').addEventListener('input',render)}());";

        // Fallback for /styles.css, same reasoning as DashboardHtml above.
        private const string DashboardCss = @":root{--bg:#f5f7fa;--panel:#fff;--text:#17202a;--muted:#5f6b7a;--line:#d9e0e8;--accent:#126f8f;--warn:#fff1c2}*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text)}.topbar{display:flex;gap:24px;align-items:center;justify-content:space-between;padding:24px 32px;background:var(--panel);border-bottom:1px solid var(--line)}h1{margin:0 0 6px;font-size:24px;font-weight:650}p,small{color:var(--muted)}p{margin:0}input[type=search]{width:min(520px,45vw);min-width:280px;height:40px;padding:0 12px;border:1px solid var(--line);border-radius:6px;font:inherit}main{padding:24px 32px}.summary{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:12px;margin-bottom:18px}.summary div{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px}.summary span{display:block;margin-bottom:4px;color:var(--accent);font-size:28px;font-weight:700}.table-wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px}table{width:100%;border-collapse:collapse;min-width:980px}th,td{padding:12px 14px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:#edf2f6;font-size:12px;color:var(--muted);text-transform:uppercase}td small{display:block;margin-top:4px}tr.stale td{background:var(--warn)}.empty{padding:28px;text-align:center;color:var(--muted)}@media(max-width:820px){.topbar{align-items:stretch;flex-direction:column;padding:18px}input[type=search]{width:100%;min-width:0}main{padding:18px}.summary{grid-template-columns:repeat(2,minmax(0,1fr))}}";

        // Fallback for /favicon.svg. Kept in sync with server\dashboard\favicon.svg,
        // unlike the HTML/JS/CSS fallbacks above - it's small enough that there's
        // no tradeoff in keeping it current.
        private const string FaviconSvg = @"<svg xmlns=""http://www.w3.org/2000/svg"" viewBox=""0 0 32 32""><rect width=""32"" height=""32"" rx=""7"" fill=""#126f8f""/><rect x=""5.5"" y=""7"" width=""21"" height=""13.5"" rx=""2"" fill=""none"" stroke=""#ffffff"" stroke-width=""2.3""/><line x1=""12.5"" y1=""24.5"" x2=""19.5"" y2=""24.5"" stroke=""#ffffff"" stroke-width=""2.3"" stroke-linecap=""round""/><line x1=""16"" y1=""20.5"" x2=""16"" y2=""24.5"" stroke=""#ffffff"" stroke-width=""2.3"" stroke-linecap=""round""/><path d=""M9.8 13.3 L13.6 17 L22 9.4"" fill=""none"" stroke=""#ffffff"" stroke-width=""2.6"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>";

        // Self-checks for hand-rolled parsing/encoding logic that has no automated
        // coverage otherwise (no NuGet test framework is used in this project).
        // Invoked through `--self-test`; exercised by tests/SelfTest.Tests.ps1.
        internal static bool RunSelfTests(TextWriter output)
        {
            bool allPassed = true;
            allPassed &= SelfTestCheck(output, "FindHeaderEnd finds terminator in a single buffer", TestFindHeaderEndSingleBuffer);
            allPassed &= SelfTestCheck(output, "FindHeaderEnd finds terminator split across reads", TestFindHeaderEndSplitAcrossReads);
            allPassed &= SelfTestCheck(output, "FindHeaderEnd returns -1 when terminator is absent", TestFindHeaderEndNoMatch);
            allPassed &= SelfTestCheck(output, "ExpandInstallTarget expands a short IPv4 range", TestExpandInstallTargetShortRange);
            allPassed &= SelfTestCheck(output, "ExpandInstallTarget expands a full IPv4 range", TestExpandInstallTargetFullRange);
            allPassed &= SelfTestCheck(output, "ExpandInstallTarget passes through a single hostname", TestExpandInstallTargetHostname);
            allPassed &= SelfTestCheck(output, "ExpandInstallTargets de-duplicates and splits on separators", TestExpandInstallTargetsDedup);
            allPassed &= SelfTestCheck(output, "BuildZip produces a structurally valid archive", TestBuildZipStructure);
            allPassed &= SelfTestCheck(output, "NormalizeThumbprint strips separators and uppercases", TestNormalizeThumbprint);
            allPassed &= SelfTestCheck(output, "ExtractLicenseId strips the route prefix and query string", TestExtractLicenseIdWithQuery);
            allPassed &= SelfTestCheck(output, "ExtractLicenseId decodes URL-encoded ids", TestExtractLicenseIdDecodesEscaping);
            allPassed &= SelfTestCheck(output, "SanitizeFileName escapes a reserved Windows device name", TestSanitizeFileNameReservedDeviceName);
            allPassed &= SelfTestCheck(output, "SanitizeFileName leaves a normal computer name untouched", TestSanitizeFileNameNormalName);
            allPassed &= SelfTestCheck(output, "FixedTimeEquals matches identical strings and rejects everything else", TestFixedTimeEquals);
            allPassed &= SelfTestCheck(output, "IsWebRequestAuthorized restricts to loopback while Basic Auth is unconfigured", TestIsWebRequestAuthorizedRestrictsToLoopbackWhenUnconfigured);
            allPassed &= SelfTestCheck(output, "TryParsePortFromPrefix extracts the port from a ListenPrefix URL", TestTryParsePortFromPrefix);
            allPassed &= SelfTestCheck(output, "LdapFilterEscaper escapes RFC 4515 special characters", TestLdapFilterEscapeSpecialChars);
            allPassed &= SelfTestCheck(output, "LdapFilterEscaper leaves a normal computer name untouched", TestLdapFilterEscapeNormalName);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns true with no previous timestamp", TestShouldSyncAdNoPreviousTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns true for a stale timestamp", TestShouldSyncAdStaleTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldSyncAd returns false for a fresh timestamp", TestShouldSyncAdFreshTimestamp);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule is never due in 'off' mode", TestShouldRunClientUpdateScheduleOffMode);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'once' is not due before the target time", TestShouldRunClientUpdateScheduleOnceNotYetDue);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'once' is due after the target time", TestShouldRunClientUpdateScheduleOnceDue);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'once' is never due with no target time set", TestShouldRunClientUpdateScheduleOnceMissingTarget);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'interval' is due immediately with no previous run", TestShouldRunClientUpdateScheduleIntervalNoPreviousRun);
            allPassed &= SelfTestCheck(output, "ShouldRunClientUpdateSchedule 'interval' respects the interval window", TestShouldRunClientUpdateScheduleIntervalDueAndNotDue);
            allPassed &= SelfTestCheck(output, "DebugLogger.ResolvePath defaults under DataPath when unset", TestDebugLoggerResolvePathDefault);
            allPassed &= SelfTestCheck(output, "DebugLogger.ResolvePath honors an explicit DebugLogPath", TestDebugLoggerResolvePathOverride);
            allPassed &= SelfTestCheck(output, "DebugLogger.SanitizeForLog escapes embedded CR/LF", TestDebugLoggerSanitizeForLog);
            allPassed &= SelfTestCheck(output, "SecretProtector round-trips a value through Protect/Unprotect", TestSecretProtectorRoundTrip);
            allPassed &= SelfTestCheck(output, "SecretProtector.Unprotect passes through a legacy plaintext value", TestSecretProtectorLegacyPlaintext);
            allPassed &= SelfTestCheck(output, "NeedsMigration flags a plaintext value", TestNeedsMigrationPlaintextValue);
            allPassed &= SelfTestCheck(output, "NeedsMigration does not flag an already-encrypted or empty value", TestNeedsMigrationAlreadyEncryptedOrEmpty);
            allPassed &= SelfTestCheck(output, "GenerateCmdLines rejects serverUrl/token/packageSharePath containing batch-unsafe characters", TestGenerateCmdLinesRejectsUnsafeCharacters);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent matches either package version", TestIsClientVersionCurrentMatchesEitherPackage);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent is outdated when it matches neither package", TestIsClientVersionCurrentOutdatedWhenMatchesNeither);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent treats an empty clientVersion as outdated", TestIsClientVersionCurrentTreatsEmptyAsOutdated);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent ignores a missing package instead of false-matching it", TestIsClientVersionCurrentIgnoresMissingPackage);
            allPassed &= SelfTestCheck(output, "ResolveUpdateCredentials falls back to the saved account when blank", TestResolveUpdateCredentialsFallsBackToSavedWhenBlank);
            allPassed &= SelfTestCheck(output, "ResolveUpdateCredentials prefers a typed per-push override over the saved account", TestResolveUpdateCredentialsPrefersTypedOverride);
            allPassed &= SelfTestCheck(output, "ResolveUpdateCredentials is a no-op for Client actions (useSavedCredentials=false)", TestResolveUpdateCredentialsIgnoredWhenFlagIsFalse);
            allPassed &= SelfTestCheck(output, "ResolveUpdateCredentials falls through to the service identity when nothing is saved", TestResolveUpdateCredentialsFallsThroughWhenNothingSaved);
            allPassed &= SelfTestCheck(output, "ParseCmdSettings round-trips GenerateCmdLines' default package root", TestParseCmdSettingsDefaultPackageRoot);
            allPassed &= SelfTestCheck(output, "ParseCmdSettings round-trips GenerateCmdLines' custom package share path", TestParseCmdSettingsCustomPackageSharePath);
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

        private static string TestFindHeaderEndSingleBuffer()
        {
            byte[] data = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY");
            int headerEnd = FindHeaderEnd(data, data.Length, 0);
            int expected = "GET / HTTP/1.1\r\nHost: x".Length;
            if (headerEnd != expected)
            {
                return "expected header end at " + expected + " but got " + headerEnd;
            }
            return null;
        }

        private static string TestFindHeaderEndSplitAcrossReads()
        {
            byte[] firstRead = Encoding.ASCII.GetBytes("abc\r\n\r");
            int scanOffset = 0;
            int headerEnd = FindHeaderEnd(firstRead, firstRead.Length, scanOffset);
            if (headerEnd != -1)
            {
                return "expected no match before the terminator byte arrived, got " + headerEnd;
            }
            scanOffset = Math.Max(0, firstRead.Length - 3);

            byte[] secondRead = Encoding.ASCII.GetBytes("abc\r\n\r\n");
            headerEnd = FindHeaderEnd(secondRead, secondRead.Length, scanOffset);
            if (headerEnd != 3)
            {
                return "expected header end at 3 after the terminator completed, got " + headerEnd;
            }
            return null;
        }

        private static string TestFindHeaderEndNoMatch()
        {
            byte[] data = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\n");
            int headerEnd = FindHeaderEnd(data, data.Length, 0);
            if (headerEnd != -1)
            {
                return "expected -1 for an incomplete header block, got " + headerEnd;
            }
            return null;
        }

        private static string TestExpandInstallTargetShortRange()
        {
            ArrayList result = ExpandInstallTarget("192.0.2.5-10");
            string[] expected = new string[] { "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8", "192.0.2.9", "192.0.2.10" };
            return CompareStringLists(expected, result);
        }

        private static string TestExpandInstallTargetFullRange()
        {
            ArrayList result = ExpandInstallTarget("192.0.2.10-192.0.2.12");
            string[] expected = new string[] { "192.0.2.10", "192.0.2.11", "192.0.2.12" };
            return CompareStringLists(expected, result);
        }

        private static string TestExpandInstallTargetHostname()
        {
            ArrayList result = ExpandInstallTarget("workstation-01");
            string[] expected = new string[] { "workstation-01" };
            return CompareStringLists(expected, result);
        }

        private static string TestExpandInstallTargetsDedup()
        {
            ArrayList result = ExpandInstallTargets("host1, host1;host2\nhost1");
            string[] expected = new string[] { "host1", "host2" };
            return CompareStringLists(expected, result);
        }

        private static string CompareStringLists(string[] expected, ArrayList actual)
        {
            if (actual.Count != expected.Length)
            {
                return "expected " + expected.Length + " item(s) but got " + actual.Count + " (" + String.Join(",", (string[])actual.ToArray(typeof(string))) + ")";
            }
            for (int i = 0; i < expected.Length; i++)
            {
                if (!String.Equals((string)actual[i], expected[i], StringComparison.OrdinalIgnoreCase))
                {
                    return "expected item " + i + " to be '" + expected[i] + "' but got '" + actual[i] + "'";
                }
            }
            return null;
        }

        private static string TestBuildZipStructure()
        {
            List<string> names = new List<string>();
            List<byte[]> contents = new List<byte[]>();
            names.Add("Install-ClientGpo.cmd");
            contents.Add(Encoding.UTF8.GetBytes("echo hello"));
            names.Add("readme.txt");
            contents.Add(Encoding.UTF8.GetBytes(""));

            byte[] zip = BuildZip(names, contents);

            if (zip.Length < 4 || zip[0] != 0x50 || zip[1] != 0x4B || zip[2] != 0x03 || zip[3] != 0x04)
            {
                return "missing local file header signature at offset 0";
            }
            if (!ContainsSignature(zip, 0x01, 0x02))
            {
                return "missing central directory signature (PK\\x01\\x02)";
            }
            if (!ContainsSignature(zip, 0x05, 0x06))
            {
                return "missing end of central directory signature (PK\\x05\\x06)";
            }

            byte[] nameBytes = Encoding.UTF8.GetBytes(names[0]);
            bool nameFound = false;
            for (int i = 0; i <= zip.Length - nameBytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < nameBytes.Length; j++)
                {
                    if (zip[i + j] != nameBytes[j]) { match = false; break; }
                }
                if (match) { nameFound = true; break; }
            }
            if (!nameFound)
            {
                return "entry file name '" + names[0] + "' not found in archive bytes";
            }
            return null;
        }

        private static string TestNormalizeThumbprint()
        {
            string normalized = NormalizeThumbprint(" 89:b3-87 eb 01 88 ");
            if (normalized != "89B387EB0188")
            {
                return "expected '89B387EB0188' but got '" + normalized + "'";
            }
            return null;
        }

        private static string TestExtractLicenseIdWithQuery()
        {
            string id = ExtractLicenseId("/api/v1/licenses/abc123?foo=bar");
            if (id != "abc123")
            {
                return "expected 'abc123' but got '" + id + "'";
            }
            return null;
        }

        private static string TestExtractLicenseIdDecodesEscaping()
        {
            string id = ExtractLicenseId("/api/v1/licenses/abc%20123");
            if (id != "abc 123")
            {
                return "expected 'abc 123' but got '" + id + "'";
            }
            return null;
        }

        private static string TestSanitizeFileNameReservedDeviceName()
        {
            string[] cases = { "CON", "con", "NUL", "com1", "LPT9", "con.evil" };
            foreach (string input in cases)
            {
                string sanitized = SanitizeFileName(input);
                int dotIndex = sanitized.IndexOf('.');
                string baseName = dotIndex >= 0 ? sanitized.Substring(0, dotIndex) : sanitized;
                foreach (string reserved in ReservedDeviceNames)
                {
                    if (String.Equals(baseName, reserved, StringComparison.OrdinalIgnoreCase))
                    {
                        return "'" + input + "' sanitized to '" + sanitized + "', which is still a reserved device name";
                    }
                }
            }
            return null;
        }

        private static string TestSanitizeFileNameNormalName()
        {
            string sanitized = SanitizeFileName("PC-ACCOUNTING-01.example");
            if (sanitized != "PC-ACCOUNTING-01.example")
            {
                return "expected an ordinary name to pass through unchanged, got '" + sanitized + "'";
            }
            return null;
        }

        private static string TestFixedTimeEquals()
        {
            if (!FixedTimeEquals("correct horse", "correct horse"))
            {
                return "expected identical strings to match";
            }
            if (FixedTimeEquals("correct horse", "correct Horse"))
            {
                return "expected a case difference to not match";
            }
            if (FixedTimeEquals("short", "shorter"))
            {
                return "expected different-length strings to not match";
            }
            if (!FixedTimeEquals("", ""))
            {
                return "expected two empty strings to match";
            }
            if (FixedTimeEquals(null, "x"))
            {
                return "expected null vs non-empty to not match";
            }
            return null;
        }

        private static string TestIsWebRequestAuthorizedRestrictsToLoopbackWhenUnconfigured()
        {
            ServerOptions options = new ServerOptions();
            InventoryServer server = new InventoryServer(options);

            RequestContext loopbackRequest = new RequestContext();
            loopbackRequest.Headers = new Dictionary<string, string>();
            loopbackRequest.RemoteAddress = IPAddress.Loopback;
            if (!server.IsWebRequestAuthorized(loopbackRequest))
            {
                return "expected a loopback request to be authorized while Basic Auth is unconfigured";
            }

            RequestContext remoteRequest = new RequestContext();
            remoteRequest.Headers = new Dictionary<string, string>();
            remoteRequest.RemoteAddress = IPAddress.Parse("192.168.1.50");
            if (server.IsWebRequestAuthorized(remoteRequest))
            {
                return "expected a non-loopback request to be rejected while Basic Auth is unconfigured";
            }

            options.WebUsername = "admin";
            options.WebPassword = "secret";

            RequestContext remoteWithoutAuth = new RequestContext();
            remoteWithoutAuth.Headers = new Dictionary<string, string>();
            remoteWithoutAuth.RemoteAddress = IPAddress.Parse("192.168.1.50");
            if (server.IsWebRequestAuthorized(remoteWithoutAuth))
            {
                return "expected a non-loopback request with no Authorization header to be rejected once Basic Auth is configured";
            }

            RequestContext remoteWithAuth = new RequestContext();
            remoteWithAuth.Headers = new Dictionary<string, string>();
            remoteWithAuth.Headers["authorization"] = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:secret"));
            remoteWithAuth.RemoteAddress = IPAddress.Parse("192.168.1.50");
            if (!server.IsWebRequestAuthorized(remoteWithAuth))
            {
                return "expected a non-loopback request with correct Basic Auth credentials to be authorized once Basic Auth is configured";
            }

            return null;
        }

        private static string TestTryParsePortFromPrefix()
        {
            int port;
            if (!ServerOptions.TryParsePortFromPrefix("http://+:8080/", out port) || port != 8080)
            {
                return "expected 'http://+:8080/' to parse to port 8080, got " + port;
            }
            if (!ServerOptions.TryParsePortFromPrefix("http://localhost:9000/", out port) || port != 9000)
            {
                return "expected 'http://localhost:9000/' to parse to port 9000, got " + port;
            }
            if (ServerOptions.TryParsePortFromPrefix("", out port))
            {
                return "expected an empty prefix to fail to parse";
            }
            if (ServerOptions.TryParsePortFromPrefix(null, out port))
            {
                return "expected a null prefix to fail to parse";
            }
            return null;
        }

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

        private static string TestDebugLoggerResolvePathDefault()
        {
            ServerOptions options = new ServerOptions();
            options.DataPath = @"C:\test-data";
            string expected = Path.Combine(@"C:\test-data", "_logs", "debug.log");
            string actual = DebugLogger.ResolvePath(options);
            if (actual != expected)
            {
                return "expected '" + expected + "' but got '" + actual + "'";
            }
            return null;
        }

        private static string TestDebugLoggerResolvePathOverride()
        {
            ServerOptions options = new ServerOptions();
            options.DataPath = @"C:\test-data";
            options.DebugLogPath = @"D:\custom\debug.log";
            string actual = DebugLogger.ResolvePath(options);
            if (actual != @"D:\custom\debug.log")
            {
                return "expected the explicit DebugLogPath to be used, got '" + actual + "'";
            }
            return null;
        }

        private static string TestDebugLoggerSanitizeForLog()
        {
            string actual = DebugLogger.SanitizeForLog("EVIL\r\n2026-01-01T00:00:00Z [Error] forged line");
            if (actual.IndexOf('\r') >= 0 || actual.IndexOf('\n') >= 0)
            {
                return "expected embedded CR/LF to be escaped, got '" + actual + "'";
            }
            if (actual.IndexOf("\\r\\n") < 0)
            {
                return "expected the escaped '\\r\\n' sequence to be visible, got '" + actual + "'";
            }
            return null;
        }

        private static string TestSecretProtectorRoundTrip()
        {
            ServerOptions options = new ServerOptions();
            string original = "Sup3r$ecret AD password with spaces";
            string protectedValue = SecretProtector.Protect(original, options);
            if (protectedValue == original)
            {
                return "expected Protect to change the value (encrypt it), it returned the plaintext unchanged";
            }
            if (!protectedValue.StartsWith("dpapi:", StringComparison.Ordinal))
            {
                return "expected the protected value to carry the 'dpapi:' prefix, got '" + protectedValue + "'";
            }
            string roundTripped = SecretProtector.Unprotect(protectedValue);
            if (roundTripped != original)
            {
                return "expected Unprotect(Protect(x)) == x, got '" + roundTripped + "'";
            }
            // Protecting an already-protected value must be a no-op, not a
            // second encryption pass - otherwise a caller that accidentally
            // re-saves a stored value (rather than fresh plaintext) would
            // corrupt it, since Unprotect only ever decrypts once.
            string protectedTwice = SecretProtector.Protect(protectedValue, options);
            if (protectedTwice != protectedValue)
            {
                return "expected Protect to be a no-op on an already-'dpapi:'-prefixed value, got a different value";
            }
            return null;
        }

        private static string TestSecretProtectorLegacyPlaintext()
        {
            string legacy = "a-plaintext-value-with-no-prefix";
            string actual = SecretProtector.Unprotect(legacy);
            if (actual != legacy)
            {
                return "expected an unprefixed legacy value to pass through unchanged, got '" + actual + "'";
            }
            return null;
        }

        private static string TestNeedsMigrationPlaintextValue()
        {
            if (!NeedsMigration("a-plaintext-secret"))
            {
                return "expected a non-empty, unprefixed value to need migration";
            }
            return null;
        }

        private static string TestNeedsMigrationAlreadyEncryptedOrEmpty()
        {
            if (NeedsMigration("dpapi:AQAAANCMnd8BFdERjHoAwE"))
            {
                return "expected an already-'dpapi:'-prefixed value to not need migration";
            }
            if (NeedsMigration(null))
            {
                return "expected a null value to not need migration";
            }
            if (NeedsMigration(""))
            {
                return "expected an empty value to not need migration";
            }
            return null;
        }

        private static string TestGenerateCmdLinesRejectsUnsafeCharacters()
        {
            string[] unsafeValues = { "http://x \" & calc.exe & rem \"", "tok\"&calc.exe&rem\"", "\\\\share & calc.exe", "line1\nline2" };
            foreach (string unsafeValue in unsafeValues)
            {
                try
                {
                    GenerateCmdLines(unsafeValue, null, 6, null);
                    return "expected serverUrl '" + unsafeValue + "' to be rejected, but GenerateCmdLines accepted it";
                }
                catch (ArgumentException)
                {
                    // expected
                }
                try
                {
                    GenerateCmdLines("https://server/api/v1/inventory", unsafeValue, 6, null);
                    return "expected token '" + unsafeValue + "' to be rejected, but GenerateCmdLines accepted it";
                }
                catch (ArgumentException)
                {
                    // expected
                }
                try
                {
                    GenerateCmdLines("https://server/api/v1/inventory", null, 6, unsafeValue);
                    return "expected packageSharePath '" + unsafeValue + "' to be rejected, but GenerateCmdLines accepted it";
                }
                catch (ArgumentException)
                {
                    // expected
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

        private static string TestResolveUpdateCredentialsFallsBackToSavedWhenBlank()
        {
            string username = "";
            string password = "";
            ResolveUpdateCredentials(ref username, ref password, true, "CORP\\svc-update", "saved-secret");
            if (username != "CORP\\svc-update" || password != "saved-secret")
            {
                return "expected blank credentials with useSavedCredentials=true to resolve to the saved account, got username='" + username + "' password='" + password + "'";
            }
            return null;
        }

        private static string TestResolveUpdateCredentialsPrefersTypedOverride()
        {
            string username = "DOMAIN\\typed-admin";
            string password = "typed-secret";
            ResolveUpdateCredentials(ref username, ref password, true, "CORP\\svc-update", "saved-secret");
            if (username != "DOMAIN\\typed-admin" || password != "typed-secret")
            {
                return "expected a typed per-push override to win over the saved account even when useSavedCredentials=true, got username='" + username + "' password='" + password + "'";
            }
            return null;
        }

        private static string TestResolveUpdateCredentialsIgnoredWhenFlagIsFalse()
        {
            string username = "";
            string password = "";
            ResolveUpdateCredentials(ref username, ref password, false, "CORP\\svc-update", "saved-secret");
            if (username != "" || password != "")
            {
                return "expected Client actions (useSavedCredentials=false) to never fall back to the Client updates saved account, got username='" + username + "' password='" + password + "'";
            }
            return null;
        }

        private static string TestResolveUpdateCredentialsFallsThroughWhenNothingSaved()
        {
            string username = "";
            string password = "";
            ResolveUpdateCredentials(ref username, ref password, true, null, null);
            if (username != "" || password != "")
            {
                return "expected blank credentials with no saved account configured to stay blank (falls through to the service identity), got username='" + username + "' password='" + password + "'";
            }
            return null;
        }

        private static string TestParseCmdSettingsDefaultPackageRoot()
        {
            string path = Path.GetTempFileName();
            try
            {
                File.WriteAllLines(path, GenerateCmdLines("https://server/api/v1/inventory", null, 6, null), Encoding.ASCII);
                Dictionary<string, string> settings = ParseCmdSettings(path);
                if (settings.ContainsKey("packageSharePath"))
                {
                    return "expected no packageSharePath key for the default %~dp0 root, got '" + settings["packageSharePath"] + "'";
                }
                return null;
            }
            finally
            {
                File.Delete(path);
            }
        }

        private static string TestParseCmdSettingsCustomPackageSharePath()
        {
            string path = Path.GetTempFileName();
            try
            {
                string share = @"\\192.168.24.4\backup\gpo-client";
                File.WriteAllLines(path, GenerateCmdLines("https://server/api/v1/inventory", null, 6, share), Encoding.ASCII);
                Dictionary<string, string> settings = ParseCmdSettings(path);
                if (!settings.ContainsKey("packageSharePath") || settings["packageSharePath"] != share)
                {
                    string actual = settings.ContainsKey("packageSharePath") ? settings["packageSharePath"] : "(missing)";
                    return "expected packageSharePath '" + share + "', got '" + actual + "'";
                }
                return null;
            }
            finally
            {
                File.Delete(path);
            }
        }

        private static bool ContainsSignature(byte[] data, byte thirdByte, byte fourthByte)
        {
            for (int i = 0; i <= data.Length - 4; i++)
            {
                if (data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == thirdByte && data[i + 3] == fourthByte)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
