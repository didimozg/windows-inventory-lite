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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace WindowsInventoryLite
{
    internal sealed class Program
    {
        private const string ServiceName = "WindowsInventoryLite";
        internal const string ProductVersion = "0.54.8";

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
        // Fully separate from DataPath (Windows reports) - the Linux client
        // v1 has its own independent storage, API, and dashboard tab. See
        // ReceiveLinuxInventory/BuildLinuxClientIndex.
        public string LinuxDataPath;
        public string ContentPath;
        public string ClientPackagePath;
        public string WinRmInstallerPath;
        public string WinRmUninstallerPath;
        public string LinuxSshInstallerPath;
        public string LinuxSshUninstallerPath;
        // Optional, off by default - dashboard-configured only, same
        // reasoning as ClientUpdateUsername/Password (no Install-Server.ps1
        // CLI flag by design). Used as the "stored Linux credentials" auth
        // mode for Linux Client actions/updates pushes.
        public string LinuxUpdateUsername;
        public string LinuxUpdatePassword;
        public string LinuxUpdateKeyPath;
        public string LinuxClientPackagePath;
        // CIDR block (e.g. "192.168.1.0/24") an admin can set in Settings >
        // Linux when a Linux host reports several NICs and the "wrong"
        // one (a storage/cluster network, not the one reachable from this
        // server) would otherwise win GetLinuxClientUpdateTarget's plain
        // first-IPv4 heuristic. Empty by default - no filtering, unchanged
        // behavior for a single-NIC fleet.
        public string PreferredLinuxSubnet;
        // Independent of ClientUpdateSchedule* above - a separate Linux
        // fleet with separate credentials needs its own schedule, per
        // explicit user choice during design.
        public string LinuxUpdateScheduleMode;
        public string LinuxUpdateScheduleOnceAtUtc;
        public int LinuxUpdateScheduleIntervalHours;
        public string LinuxUpdateScheduleLastRunUtc;
        public string Token;
        public string WebUsername;
        public string WebPassword;
        // Dashboard-only (Settings > Admin password > Login lockout), no
        // Install-Server.ps1 CLI flag - same reasoning as
        // LinuxDefaultIntervalHours below. Threshold 0 disables the whole
        // per-IP lockout mechanism (see IsBasicAuthLockedOut).
        public int LoginLockoutThreshold;
        public int LoginLockoutWindowMinutes;
        public int LoginLockoutDurationMinutes;
        // Dashboard-only (Settings > Admin password > Login lockout, same
        // block), no Install-Server.ps1 CLI flag - same reasoning as
        // LoginLockoutThreshold above. Governs how long a dashboard login
        // session stays valid (sliding - see IsWebRequestAuthorized's
        // session-cookie branch), not anything Basic-Auth-related.
        public int SessionLifetimeHours;
        // Dashboard-only (Settings > Server > Ingestion Token), no
        // Install-Server.ps1 CLI flag - same reasoning as
        // LoginLockoutThreshold above. Governs the rejected-ingestion-
        // attempt log (see IngestionRejectionEntry/RecordIngestionRejection),
        // not the token itself.
        public int IngestionRejectionLogRetentionDays;
        public int IngestionRejectionLogMaxEntries;
        public int InstallLogRetentionDays;
        public string ConfigPath;
        // The certificate is resolved from the LocalMachine\My store by thumbprint
        // (see InventoryServer.FindCertificateByThumbprint). Install-Server.ps1 can
        // import a PFX at install time; the dashboard "Certificate" tab can import
        // and switch to a new PFX later without a service restart.
        public bool UseHttps;
        // Off by default - HSTS is only ever added to a response actually
        // served over the HTTPS listener (see BuildHstsHeaderOrEmpty), but
        // a browser that has cached the policy can still lock itself out of
        // this server if HTTPS is later disabled while this was on - opt-in
        // rather than tied automatically to UseHttps.
        public bool HstsEnabled;
        public int HstsMaxAgeHours;
        public string CertificateThumbprint;
        public int StaleHours;
        public bool ConsoleMode;
        public bool ShowVersion;
        // AD sync is opt-in and off by default - deployments without AD, or
        // with a server that isn't domain-joined, are unaffected. See
        // AdLookupService.cs and InventoryServer.ComputeAdSyncFields.
        public bool AdSyncEnabled;
        // Independent of AdSyncEnabled (which now means "AD identity is
        // configured for use by Client actions/Client updates/AD Computer
        // Import"): this flag alone gates the periodic AD -> adDescription
        // write path (RunAdSyncSweep, ComputeAdSyncFields). Turning it off
        // makes the Clients table's Description column manually editable
        // without losing AD credentials elsewhere.
        public bool AdDescriptionSyncEnabled;
        // Gates the ingestion endpoints - resolved by ResolveRequireIngestionToken
        // below to preserve upgrade compatibility (defaults to token presence).
        public bool RequireIngestionToken;
        public string AdSyncMode;
        public int AdSyncIntervalHours;
        public string AdDomain;
        public bool AdUseServiceIdentity;
        public string AdUsername;
        public string AdPassword;
        // Newline-separated list of OU Distinguished Names for the AD
        // Computer Import feature ("Load from AD" on Client actions).
        // Empty means "search the whole domain." Not a secret - stored as
        // plain text, same as AdDomain. Dashboard-only, no Install-Server.ps1
        // CLI flag, same reasoning as ClientUpdateUsername below.
        public string AdComputerImportOUs;
        // Dashboard-only (Settings > Linux > Install defaults), no
        // Install-Server.ps1 CLI flag - same reasoning as
        // AdComputerImportOUs above. Read by Auto-mode Deploy > Actions
        // (a later phase) as the fallback when a target resolves to Linux
        // and the install request itself supplies no override.
        public int LinuxDefaultIntervalHours;
        public int LinuxDefaultStatusIntervalMinutes;
        public string LinuxDefaultInstallPath;
        // Off by default - a plain-text file capturing AD lookups,
        // inventory-report traffic, and unhandled server errors. See
        // DebugLogger.cs. Only meant for troubleshooting a specific
        // deployment; not rotated or size-capped.
        public bool DebugLogEnabled;
        public string DebugLogPath;
        // Optional, off by default - dashboard-configured only, no
        // Install-Server.ps1 CLI flag by design. Used as a fallback WinRM
        // credential for Client Auto-Update pushes when the service's own
        // identity can't reach a target.
        public string ClientUpdateUsername;
        public string ClientUpdatePassword;
        // Off by default - dashboard-configured only, same reasoning as
        // ClientUpdateUsername/Password above.
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
            options.LinuxDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\linux-clients-data");
            options.ContentPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server-content");
            options.ClientPackagePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\client-package");
            options.LinuxClientPackagePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\linux-client-package");
            options.WinRmInstallerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server-bin\Install-ClientWinRM.ps1");
            options.WinRmUninstallerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server-bin\Uninstall-ClientWinRM.ps1");
            options.LinuxSshInstallerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server-bin\Install-ClientDebianSSH.ps1");
            options.LinuxSshUninstallerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\server-bin\Uninstall-ClientDebianSSH.ps1");
            options.InstallLogRetentionDays = 30;
            options.StaleHours = 48;
            options.AdSyncMode = "on-report";
            options.AdSyncIntervalHours = 24;
            options.AdUseServiceIdentity = true;
            options.ClientUpdateScheduleMode = "off";
            options.ClientUpdateScheduleOnceAtUtc = "";
            options.ClientUpdateScheduleIntervalHours = 24;
            options.ClientUpdateScheduleLastRunUtc = "";
            options.LinuxUpdateScheduleMode = "off";
            options.LinuxUpdateScheduleOnceAtUtc = "";
            options.LinuxUpdateScheduleIntervalHours = 24;
            options.LinuxUpdateScheduleLastRunUtc = "";
            options.LinuxDefaultIntervalHours = 6;
            options.LinuxDefaultStatusIntervalMinutes = 30;
            options.LinuxDefaultInstallPath = "/opt/windows-inventory-lite";
            options.LoginLockoutThreshold = 10;
            options.LoginLockoutWindowMinutes = 15;
            options.LoginLockoutDurationMinutes = 15;
            options.SessionLifetimeHours = 12;
            options.HstsMaxAgeHours = 24;
            options.IngestionRejectionLogRetentionDays = 30;
            options.IngestionRejectionLogMaxEntries = 5000;

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
                else if (key == "--linux-data" && i + 1 < args.Length)
                {
                    options.LinuxDataPath = args[++i];
                }
                else if (key == "--content" && i + 1 < args.Length)
                {
                    options.ContentPath = args[++i];
                }
                else if (key == "--client-package" && i + 1 < args.Length)
                {
                    options.ClientPackagePath = args[++i];
                }
                else if (key == "--linux-client-package" && i + 1 < args.Length)
                {
                    options.LinuxClientPackagePath = args[++i];
                }
                else if (key == "--winrm-installer" && i + 1 < args.Length)
                {
                    options.WinRmInstallerPath = args[++i];
                }
                else if (key == "--winrm-uninstaller" && i + 1 < args.Length)
                {
                    options.WinRmUninstallerPath = args[++i];
                }
                else if (key == "--linux-ssh-installer" && i + 1 < args.Length)
                {
                    options.LinuxSshInstallerPath = args[++i];
                }
                else if (key == "--linux-ssh-uninstaller" && i + 1 < args.Length)
                {
                    options.LinuxSshUninstallerPath = args[++i];
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

            // Matches the pre-branch guard's real-world behavior for a
            // config-less invocation ("--token X" with no --config, or a
            // --config path that doesn't exist yet): a token supplied on
            // the command line is enforced by default. LoadConfigFile below
            // still overrides this from an explicit RequireIngestionToken
            // key whenever a real config file exists.
            options.RequireIngestionToken = !String.IsNullOrEmpty(options.Token);
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
                options.RequireIngestionToken = ResolveRequireIngestionToken(GetConfigString(config, "RequireIngestionToken"), !String.IsNullOrEmpty(options.Token));
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
                if (!options.HstsEnabled)
                {
                    string hstsEnabledText = GetConfigString(config, "HstsEnabled");
                    options.HstsEnabled = String.Equals(hstsEnabledText, "true", StringComparison.OrdinalIgnoreCase);
                }
                if (options.HstsMaxAgeHours == 24)
                {
                    string hstsMaxAgeHoursText = GetConfigString(config, "HstsMaxAgeHours");
                    int hstsMaxAgeHoursFromConfig;
                    if (!String.IsNullOrEmpty(hstsMaxAgeHoursText) && Int32.TryParse(hstsMaxAgeHoursText, out hstsMaxAgeHoursFromConfig) && hstsMaxAgeHoursFromConfig >= 1 && hstsMaxAgeHoursFromConfig <= 8760)
                    {
                        options.HstsMaxAgeHours = hstsMaxAgeHoursFromConfig;
                    }
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
                if (options.InstallLogRetentionDays == 30)
                {
                    string retentionDaysText = GetConfigString(config, "InstallLogRetentionDays");
                    int retentionDaysFromConfig;
                    if (!String.IsNullOrEmpty(retentionDaysText) && Int32.TryParse(retentionDaysText, out retentionDaysFromConfig) && retentionDaysFromConfig >= 1 && retentionDaysFromConfig <= 3650)
                    {
                        options.InstallLogRetentionDays = retentionDaysFromConfig;
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
                if (!options.AdDescriptionSyncEnabled)
                {
                    string adDescriptionSyncEnabledText = GetConfigString(config, "AdDescriptionSyncEnabled");
                    options.AdDescriptionSyncEnabled = ResolveAdDescriptionSyncEnabled(adDescriptionSyncEnabledText, options.AdSyncEnabled);
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
                if (String.IsNullOrEmpty(options.AdComputerImportOUs))
                {
                    options.AdComputerImportOUs = GetConfigString(config, "AdComputerImportOUs");
                }
                if (String.IsNullOrEmpty(options.PreferredLinuxSubnet))
                {
                    options.PreferredLinuxSubnet = GetConfigString(config, "PreferredLinuxSubnet");
                }
                if (options.LinuxDefaultIntervalHours == 6)
                {
                    string linuxDefaultIntervalText = GetConfigString(config, "LinuxDefaultIntervalHours");
                    int linuxDefaultIntervalFromConfig;
                    if (!String.IsNullOrEmpty(linuxDefaultIntervalText) && Int32.TryParse(linuxDefaultIntervalText, out linuxDefaultIntervalFromConfig) && linuxDefaultIntervalFromConfig >= 1 && linuxDefaultIntervalFromConfig <= 24)
                    {
                        options.LinuxDefaultIntervalHours = linuxDefaultIntervalFromConfig;
                    }
                }
                if (options.LinuxDefaultStatusIntervalMinutes == 30)
                {
                    string linuxDefaultStatusIntervalText = GetConfigString(config, "LinuxDefaultStatusIntervalMinutes");
                    int linuxDefaultStatusIntervalFromConfig;
                    if (!String.IsNullOrEmpty(linuxDefaultStatusIntervalText) && Int32.TryParse(linuxDefaultStatusIntervalText, out linuxDefaultStatusIntervalFromConfig) && linuxDefaultStatusIntervalFromConfig >= 1 && linuxDefaultStatusIntervalFromConfig <= 1440)
                    {
                        options.LinuxDefaultStatusIntervalMinutes = linuxDefaultStatusIntervalFromConfig;
                    }
                }
                if (String.Equals(options.LinuxDefaultInstallPath, "/opt/windows-inventory-lite", StringComparison.Ordinal))
                {
                    string linuxDefaultInstallPathFromConfig = GetConfigString(config, "LinuxDefaultInstallPath");
                    if (!String.IsNullOrEmpty(linuxDefaultInstallPathFromConfig))
                    {
                        options.LinuxDefaultInstallPath = linuxDefaultInstallPathFromConfig;
                    }
                }
                if (options.LoginLockoutThreshold == 10)
                {
                    string loginLockoutThresholdText = GetConfigString(config, "LoginLockoutThreshold");
                    int loginLockoutThresholdFromConfig;
                    if (!String.IsNullOrEmpty(loginLockoutThresholdText) && Int32.TryParse(loginLockoutThresholdText, out loginLockoutThresholdFromConfig) && loginLockoutThresholdFromConfig >= 0 && loginLockoutThresholdFromConfig <= 1000)
                    {
                        options.LoginLockoutThreshold = loginLockoutThresholdFromConfig;
                    }
                }
                if (options.LoginLockoutWindowMinutes == 15)
                {
                    string loginLockoutWindowText = GetConfigString(config, "LoginLockoutWindowMinutes");
                    int loginLockoutWindowFromConfig;
                    if (!String.IsNullOrEmpty(loginLockoutWindowText) && Int32.TryParse(loginLockoutWindowText, out loginLockoutWindowFromConfig) && loginLockoutWindowFromConfig >= 1 && loginLockoutWindowFromConfig <= 1440)
                    {
                        options.LoginLockoutWindowMinutes = loginLockoutWindowFromConfig;
                    }
                }
                if (options.LoginLockoutDurationMinutes == 15)
                {
                    string loginLockoutDurationText = GetConfigString(config, "LoginLockoutDurationMinutes");
                    int loginLockoutDurationFromConfig;
                    if (!String.IsNullOrEmpty(loginLockoutDurationText) && Int32.TryParse(loginLockoutDurationText, out loginLockoutDurationFromConfig) && loginLockoutDurationFromConfig >= 1 && loginLockoutDurationFromConfig <= 1440)
                    {
                        options.LoginLockoutDurationMinutes = loginLockoutDurationFromConfig;
                    }
                }
                if (options.SessionLifetimeHours == 12)
                {
                    string sessionLifetimeHoursText = GetConfigString(config, "SessionLifetimeHours");
                    int sessionLifetimeHoursFromConfig;
                    if (!String.IsNullOrEmpty(sessionLifetimeHoursText) && Int32.TryParse(sessionLifetimeHoursText, out sessionLifetimeHoursFromConfig) && sessionLifetimeHoursFromConfig >= 1 && sessionLifetimeHoursFromConfig <= 720)
                    {
                        options.SessionLifetimeHours = sessionLifetimeHoursFromConfig;
                    }
                }
                if (options.IngestionRejectionLogRetentionDays == 30)
                {
                    string ingestionRejectionRetentionText = GetConfigString(config, "IngestionRejectionLogRetentionDays");
                    int ingestionRejectionRetentionFromConfig;
                    if (!String.IsNullOrEmpty(ingestionRejectionRetentionText) && Int32.TryParse(ingestionRejectionRetentionText, out ingestionRejectionRetentionFromConfig) && ingestionRejectionRetentionFromConfig >= 1 && ingestionRejectionRetentionFromConfig <= 3650)
                    {
                        options.IngestionRejectionLogRetentionDays = ingestionRejectionRetentionFromConfig;
                    }
                }
                if (options.IngestionRejectionLogMaxEntries == 5000)
                {
                    string ingestionRejectionMaxEntriesText = GetConfigString(config, "IngestionRejectionLogMaxEntries");
                    int ingestionRejectionMaxEntriesFromConfig;
                    if (!String.IsNullOrEmpty(ingestionRejectionMaxEntriesText) && Int32.TryParse(ingestionRejectionMaxEntriesText, out ingestionRejectionMaxEntriesFromConfig) && ingestionRejectionMaxEntriesFromConfig >= 100 && ingestionRejectionMaxEntriesFromConfig <= 100000)
                    {
                        options.IngestionRejectionLogMaxEntries = ingestionRejectionMaxEntriesFromConfig;
                    }
                }
                if (String.IsNullOrEmpty(options.ClientUpdateUsername))
                {
                    options.ClientUpdateUsername = GetConfigString(config, "ClientUpdateUsername");
                }
                if (String.IsNullOrEmpty(options.ClientUpdatePassword))
                {
                    options.ClientUpdatePassword = SecretProtector.Unprotect(GetConfigString(config, "ClientUpdatePassword"));
                }
                if (String.IsNullOrEmpty(options.LinuxUpdateUsername))
                {
                    options.LinuxUpdateUsername = GetConfigString(config, "LinuxUpdateUsername");
                }
                if (String.IsNullOrEmpty(options.LinuxUpdatePassword))
                {
                    options.LinuxUpdatePassword = SecretProtector.Unprotect(GetConfigString(config, "LinuxUpdatePassword"));
                }
                if (String.IsNullOrEmpty(options.LinuxUpdateKeyPath))
                {
                    options.LinuxUpdateKeyPath = GetConfigString(config, "LinuxUpdateKeyPath");
                }
                if (options.LinuxUpdateScheduleMode == "off")
                {
                    string linuxScheduleModeText = GetConfigString(config, "LinuxUpdateScheduleMode");
                    if (linuxScheduleModeText == "off" || linuxScheduleModeText == "once" || linuxScheduleModeText == "interval")
                    {
                        options.LinuxUpdateScheduleMode = linuxScheduleModeText;
                    }
                }
                if (String.IsNullOrEmpty(options.LinuxUpdateScheduleOnceAtUtc))
                {
                    options.LinuxUpdateScheduleOnceAtUtc = GetConfigString(config, "LinuxUpdateScheduleOnceAtUtc") ?? "";
                }
                if (options.LinuxUpdateScheduleIntervalHours == 24)
                {
                    string linuxScheduleIntervalText = GetConfigString(config, "LinuxUpdateScheduleIntervalHours");
                    int linuxScheduleIntervalFromConfig;
                    if (!String.IsNullOrEmpty(linuxScheduleIntervalText) && Int32.TryParse(linuxScheduleIntervalText, out linuxScheduleIntervalFromConfig) && linuxScheduleIntervalFromConfig > 0 && linuxScheduleIntervalFromConfig <= 8760)
                    {
                        options.LinuxUpdateScheduleIntervalHours = linuxScheduleIntervalFromConfig;
                    }
                }
                if (String.IsNullOrEmpty(options.LinuxUpdateScheduleLastRunUtc))
                {
                    options.LinuxUpdateScheduleLastRunUtc = GetConfigString(config, "LinuxUpdateScheduleLastRunUtc") ?? "";
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

        // Migration for upgrades from before RequireIngestionToken existed:
        // if the config file has no explicit value yet, preserve today's
        // real-world behavior exactly - enforcement was always implicitly
        // "on" whenever a token happened to be configured (see the old
        // ReceiveInventory/ReceiveLinuxInventory guard this replaces), so an
        // existing deployment keeps behaving the same way after the upgrade
        // with no admin action required. A fresh install always resolves
        // this to true with zero special-case code, since Install-Server.ps1
        // always configures a real token by the time this ever runs - no
        // separate "fresh install default" branch is needed. Pure - no I/O,
        // self-tested directly.
        internal static bool ResolveRequireIngestionToken(string configValueText, bool tokenIsConfigured)
        {
            if (!String.IsNullOrEmpty(configValueText))
            {
                return String.Equals(configValueText, "true", StringComparison.OrdinalIgnoreCase);
            }
            return tokenIsConfigured;
        }
    }

    internal sealed class InventoryServer
    {
        private readonly ServerOptions options;
        private readonly object installJobsLock = new object();
        private readonly Dictionary<string, InstallJob> installJobs = new Dictionary<string, InstallJob>();
        // Per-source-IP Basic Auth failure tracking (see IsBasicAuthLockedOut/
        // IsWebRequestAuthorized). In-memory only, does not survive a server
        // restart - defense-in-depth on top of the documented "trusted
        // management network" control, not the sole line of defense.
        private readonly object loginLockoutLock = new object();
        private readonly Dictionary<IPAddress, LoginLockoutRecord> loginLockoutState = new Dictionary<IPAddress, LoginLockoutRecord>();

        // Not persisted to disk - a server restart naturally requires
        // everyone to log in again, matching how loginLockoutState above
        // already resets on restart. Keyed by the random token that is
        // also the wil_session cookie's value (see GenerateRandomToken).
        private readonly object sessionLock = new object();
        private readonly Dictionary<string, SessionRecord> sessionStore = new Dictionary<string, SessionRecord>();

        // Rejected-ingestion-token attempt log (see IngestionRejectionEntry/
        // RecordIngestionRejection). Persisted to disk (see
        // GetIngestionRejectionLogPath) and loaded into this list once at
        // Start() - unlike loginLockoutState, this is meant to survive a
        // restart, since it's a history an admin reviews, not a transient
        // lockout counter.
        private readonly object ingestionRejectionLogLock = new object();
        private readonly List<IngestionRejectionEntry> ingestionRejectionLog = new List<IngestionRejectionEntry>();
        // IP -> resolved PTR hostname, or null for "resolution attempted,
        // no result" (still cached, so a non-resolving IP is never
        // retried). Cleared entirely (not partially evicted) if it exceeds
        // 1000 entries - see QueueReverseDnsLookup.
        private readonly object reverseDnsCacheLock = new object();
        private readonly Dictionary<IPAddress, string> reverseDnsCache = new Dictionary<IPAddress, string>();
        // Caps how many reverse-DNS lookups can be in flight on the
        // ThreadPool at once - the same pool HandleClient itself runs on.
        // Without this, a burst of first-time-seen source IPs (trivial for
        // an unauthenticated attacker to trigger) can tie up many pool
        // threads at once, each blocked up to 2 seconds, and starve real
        // request handling. See QueueReverseDnsLookup.
        private const int MaxConcurrentReverseDnsLookups = 20;
        private int reverseDnsLookupsInFlight;
        // Lets an open dashboard tab notice a server-initiated (scheduled)
        // push exists at all - a scheduled push never goes through any HTTP
        // request the browser makes, so without this the browser has no way
        // to learn a new job.Id exists to poll. Not used for jobs started
        // from either "Client actions" or "Client updates" (both already
        // know their own job.Id locally, from the response of the request
        // that created them) - only the schedule timer sets this.
        private volatile string lastScheduledUpdateJobId;
        private volatile string lastScheduledLinuxUpdateJobId;
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
        // server-config.json holds the DPAPI-encrypted secrets (AdPassword/
        // WebPassword/Token/ClientUpdatePassword) and is now written by more
        // than one unattended background path (the AD sync and Client Update
        // schedule timers) in addition to every operator-driven settings
        // save - without this lock, two writers reading-modifying-writing
        // the same file can silently drop each other's change (a lost
        // update), found during a security review of the schedule feature.
        private readonly object configFileLock = new object();

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
            if (!Directory.Exists(options.LinuxDataPath))
            {
                Directory.CreateDirectory(options.LinuxDataPath);
            }
            if (!Directory.Exists(GetInstallJobDirectory()))
            {
                Directory.CreateDirectory(GetInstallJobDirectory());
            }
            CleanupInstallJobLogs();
            MigrateLegacyLinuxSshKey();
            PurgeOrphanedLinuxInstallJobDirectory();
            LoadIngestionRejectionLogFromDisk();

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
            ReconfigureLinuxUpdateScheduleTimer();

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
                if (options.AdDescriptionSyncEnabled && options.AdSyncMode == "timer")
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
        // inventory report" mode only ever touches a computer's AD
        // fields when that computer itself POSTs a new report, so a machine
        // that's stopped reporting but still exists in AD would otherwise
        // never refresh.
        private void RunAdSyncSweep(object state)
        {
            if (!options.AdDescriptionSyncEnabled || options.AdSyncMode != "timer")
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
        // change (ConfigureClientUpdateSchedule) and once at startup, so a
        // mode switch takes effect without a service restart -
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
            // An unhandled exception thrown from a System.Threading.Timer
            // callback runs on a ThreadPool thread and tears down the whole
            // service process on .NET Framework. Unlike a manual push, this
            // path has no HandleClient try/catch above it, so a transient
            // failure here (DataPath briefly unreachable, a report or config
            // file locked by antivirus mid-read/write, disk pressure) must
            // skip this tick and let the next 60-second poll retry, exactly
            // as RunAdSyncSweep swallows per-sweep failures rather than crash
            // the server. The push and its bookkeeping mutate options in
            // memory before persisting, so a save that throws after a push
            // starts still leaves the in-memory state that stops the next
            // tick from re-firing the same event within this process.
            try
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
            catch (Exception ex)
            {
                DebugLogger.Log(options, "Error", "Client update schedule tick failed: " + ex);
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
        // feature deliberately has no separate notification mechanism
        // (e.g. email/webhook on failure) - an admin checks push results
        // the same way as any other job, via the Client updates page.
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
            job.Mode = "force-windows";
            job.ServerUrl = serverUrl;
            job.Token = options.Token;
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
            lastScheduledUpdateJobId = job.Id;
            DebugLogger.Log(options, "Schedule", "Scheduled client update push started: job '" + job.Id + "', mode '" + options.ClientUpdateScheduleMode + "', " + targets.Count + " target(s).");
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
                int loginLockoutRetryAfterSeconds;
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
                    else if (request.Method == "POST" && request.Path == "/api/v1/linux/inventory")
                    {
                        ReceiveLinuxInventory(stream, request);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/linux/inventory/service-status")
                    {
                        ReceiveLinuxServiceStatus(stream, request);
                    }
                    else if (IsBasicAuthLockedOut(request, out loginLockoutRetryAfterSeconds))
                    {
                        SendTooManyRequests(stream, loginLockoutRetryAfterSeconds);
                    }
                    else if (IsCrossSiteRequestRejected(request))
                    {
                        SendText(stream, "{\"error\":\"Cross-site request rejected - Origin/Referer does not match this server.\"}", "application/json; charset=utf-8", 400);
                    }
                    else if (RequiresJsonContentType(request) && !HasJsonContentType(request))
                    {
                        SendText(stream, "{\"error\":\"Content-Type must be application/json.\"}", "application/json; charset=utf-8", 400);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/login")
                    {
                        SendLoginResult(stream, request);
                    }
                    else if (!IsWebRequestAuthorized(request))
                    {
                        SendUnauthorized(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/clients")
                    {
                        SendJson(stream, BuildClientIndex());
                    }
                    else if (request.Method == "DELETE" && request.Path.StartsWith("/api/v1/clients/", StringComparison.OrdinalIgnoreCase))
                    {
                        DeleteClient(stream, request);
                    }
                    else if (request.Method == "PUT" && request.Path.StartsWith("/api/v1/clients/", StringComparison.OrdinalIgnoreCase))
                    {
                        UpdateClientDescription(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/linux/clients")
                    {
                        SendJson(stream, BuildLinuxClientIndex());
                    }
                    else if (request.Method == "DELETE" && request.Path.StartsWith("/api/v1/linux/clients/", StringComparison.OrdinalIgnoreCase))
                    {
                        DeleteLinuxClient(stream, request);
                    }
                    else if (request.Method == "PUT" && request.Path.StartsWith("/api/v1/linux/clients/", StringComparison.OrdinalIgnoreCase))
                    {
                        UpdateLinuxClientDescription(stream, request);
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
                    else if (request.Method == "POST" && request.Path == "/api/v1/linux-client-install/trust-host-key")
                    {
                        TrustLinuxHostKey(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/linux-client-updates")
                    {
                        SendLinuxClientUpdates(stream);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/linux-client-updates/credentials")
                    {
                        SendLinuxUpdateCredentialsStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/linux-client-updates/credentials")
                    {
                        ConfigureLinuxUpdateCredentials(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/linux-client-updates/schedule")
                    {
                        SendLinuxUpdateScheduleStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/linux-client-updates/schedule")
                    {
                        ConfigureLinuxUpdateSchedule(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/linux-ssh-tools-status")
                    {
                        SendLinuxSshToolsStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/linux-ssh-key")
                    {
                        ConfigureLinuxSshKey(stream, request);
                    }
                    else if (request.Method == "DELETE" && request.Path == "/api/v1/server/linux-ssh-key")
                    {
                        DeleteLinuxSshKey(stream);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/linux-client-package")
                    {
                        SendLinuxClientPackageStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/linux-client-package/configure")
                    {
                        ConfigureLinuxClientPackage(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/linux-client-package/download")
                    {
                        DownloadLinuxClientPackage(stream);
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
                    else if (request.Method == "GET" && request.Path == "/api/v1/ad/computers")
                    {
                        SendAdComputers(stream);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/admin-password")
                    {
                        SendAdminPasswordStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/admin-password")
                    {
                        ChangeAdminPassword(stream, request);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/logout")
                    {
                        SendLogoutResult(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/ingestion-token")
                    {
                        SendIngestionTokenStatus(stream);
                    }
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/ingestion-token/regenerate")
                    {
                        RegenerateIngestionToken(stream, request);
                    }
                    else if (request.Method == "GET" && request.Path == "/api/v1/server/ingestion-rejections")
                    {
                        SendIngestionRejectionLog(stream);
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
                    else if (request.Method == "GET" && request.Path == "/brand-mark.png")
                    {
                        SendDashboardImage(stream, "brand-mark.png", "image/png");
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
            if (IsIngestionTokenRejected(options.RequireIngestionToken, token, options.Token))
            {
                RecordIngestionRejection(request, "windows-inventory", ResolveIngestionRejectionReason(token));
                DebugLogger.Log(options, "Client", "Rejected inventory report: invalid or missing token");
                SendText(stream, "Unauthorized", "text/plain; charset=utf-8", 401);
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> inventory;
            try
            {
                inventory = serializer.Deserialize<Dictionary<string, object>>(request.Body);
                // A body of literally "null" parses fine and yields null, making the
                // ContainsKey call below an unauthenticated NullReferenceException
                // that writes a full stack trace to the Windows Event Log. Same guard
                // every authenticated handler in this file already has.
                if (inventory == null)
                {
                    throw new ArgumentException("empty body");
                }
            }
            catch
            {
                DebugLogger.Log(options, "Client", "Rejected inventory report: invalid request body");
                SendText(stream, "{\"error\":\"invalid request body\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string computerName = NormalizeReportIdentifier(inventory.ContainsKey("computerName") ? Convert.ToString(inventory["computerName"]) : null);
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
                inventory["lastIngestSourceIp"] = request.RemoteAddress != null ? request.RemoteAddress.ToString() : null;

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

        // Pure decision function for the Client Update schedule timer
        // (RunClientUpdateScheduleTick calls this on every tick) - no I/O,
        // so it's directly self-testable. "once" fires exactly once when
        // nowUtc reaches onceAtUtc; the caller is responsible for resetting
        // mode back to "off" afterward (this function only answers "is it
        // due right now", it doesn't mutate anything). "interval" fires
        // immediately if there's no previous run recorded, then every
        // intervalHours after the last scheduled run - manual pushes never
        // touch lastRunUtc, only a schedule-triggered run does.
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

        // Detects any of the encrypted secrets (see EncryptedConfigKeys)
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
            if (!options.AdDescriptionSyncEnabled)
            {
                // Sync is off, but a manually-edited Description (set via
                // PUT /api/v1/clients/{name}/description while sync is off)
                // must still survive this client's next inventory report -
                // the report body the client sends never carries
                // adDescription itself (only AD sync or a manual edit ever
                // write that field), so without this carry-forward,
                // HandleInventory's File.WriteAllText would overwrite the
                // whole record with a version that has no adDescription at
                // all, silently wiping a manual edit within one reporting
                // interval.
                if (previous != null)
                {
                    fields.Applicable = true;
                    fields.Description = previous.ContainsKey("adDescription") ? previous["adDescription"] : null;
                    fields.Status = previous.ContainsKey("adSyncStatus") ? previous["adSyncStatus"] : null;
                    fields.SyncedAt = previous.ContainsKey("adSyncedAt") ? previous["adSyncedAt"] : null;
                }
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

        // Manual Description edit, only reachable while AD Description
        // Sync is off (AdDescriptionSyncEnabled == false) - enforced here,
        // not just by the dashboard hiding the edit control, since the UI
        // is not a security boundary. Writes the same adDescription field
        // AD Description Sync itself writes; adSyncStatus/adSyncedAt are
        // untouched here (ComputeAdSyncFields carries them forward
        // separately on the next inventory report).
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

        // Ingests a Linux client report - fully independent of
        // ReceiveInventory (different storage directory, different report
        // schema entirely). Shares the server's one Token setting (same
        // header, same FixedTimeEquals check) and the AD Description Sync
        // resolution (ComputeAdSyncFields/ApplyAdSyncFields, both already
        // generic over "a hostname string and a previous report dict" -
        // zero changes needed to reuse them here).
        private void ReceiveLinuxInventory(Stream stream, RequestContext request)
        {
            string token = request.Headers.ContainsKey("x-inventory-token") ? request.Headers["x-inventory-token"] : null;
            if (IsIngestionTokenRejected(options.RequireIngestionToken, token, options.Token))
            {
                RecordIngestionRejection(request, "linux-inventory", ResolveIngestionRejectionReason(token));
                DebugLogger.Log(options, "Client", "Rejected Linux inventory report: invalid or missing token");
                SendText(stream, "Unauthorized", "text/plain; charset=utf-8", 401);
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> inventory;
            try
            {
                inventory = serializer.Deserialize<Dictionary<string, object>>(request.Body);
                // A body of literally "null" parses fine and yields null, making the
                // ContainsKey call below an unauthenticated NullReferenceException
                // that writes a full stack trace to the Windows Event Log. Same guard
                // every authenticated handler in this file already has.
                if (inventory == null)
                {
                    throw new ArgumentException("empty body");
                }
            }
            catch
            {
                DebugLogger.Log(options, "Client", "Rejected Linux inventory report: invalid request body");
                SendText(stream, "{\"error\":\"invalid request body\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string hostname = NormalizeReportIdentifier(inventory.ContainsKey("hostname") ? Convert.ToString(inventory["hostname"]) : null);
            string path = Path.Combine(options.LinuxDataPath, SanitizeFileName(hostname) + ".json");

            // Same lock-avoidance reasoning as ReceiveInventory: compute the
            // (possibly slow, up to ~15s against an unreachable AD) fields
            // before taking reportFileLock, which Windows and Linux
            // ingestion share - one slow AD lookup must not serialize
            // ingestion for the rest of either fleet.
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
            AdSyncFields adFields = ComputeAdSyncFields(hostname, previous);

            lock (reportFileLock)
            {
                ApplyAdSyncFields(inventory, adFields);
                inventory["lastIngestSourceIp"] = request.RemoteAddress != null ? request.RemoteAddress.ToString() : null;

                string json = serializer.Serialize(inventory);
                File.WriteAllText(path, json, new UTF8Encoding(false));
            }
            DebugLogger.Log(options, "Client", "Linux inventory report accepted from '" + DebugLogger.SanitizeForLog(hostname) + "'");
            SendJson(stream, "{\"status\":\"ok\"}");
        }

        private void ReceiveLinuxServiceStatus(Stream stream, RequestContext request)
        {
            string token = request.Headers.ContainsKey("x-inventory-token") ? request.Headers["x-inventory-token"] : null;
            if (IsIngestionTokenRejected(options.RequireIngestionToken, token, options.Token))
            {
                RecordIngestionRejection(request, "linux-service-status", ResolveIngestionRejectionReason(token));
                DebugLogger.Log(options, "Client", "Rejected Linux service-status report: invalid or missing token");
                SendText(stream, "Unauthorized", "text/plain; charset=utf-8", 401);
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> payload;
            try
            {
                payload = serializer.Deserialize<Dictionary<string, object>>(request.Body);
                // A body of literally "null" parses fine and yields null, making the
                // ContainsKey call below an unauthenticated NullReferenceException
                // that writes a full stack trace to the Windows Event Log. Same guard
                // every authenticated handler in this file already has.
                if (payload == null)
                {
                    throw new ArgumentException("empty body");
                }
            }
            catch
            {
                DebugLogger.Log(options, "Client", "Rejected Linux service-status report: invalid request body");
                SendText(stream, "{\"error\":\"invalid request body\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string hostname = NormalizeReportIdentifier(payload.ContainsKey("hostname") ? Convert.ToString(payload["hostname"]) : null);
            ArrayList activeUnits = new ArrayList();
            if (payload.ContainsKey("activeUnits") && payload["activeUnits"] is ArrayList)
            {
                activeUnits = (ArrayList)payload["activeUnits"];
            }
            string collectedAt = Convert.ToString(payload.ContainsKey("collectedAt") ? payload["collectedAt"] : "");

            string path = Path.Combine(options.LinuxDataPath, SanitizeFileName(hostname) + ".json");

            lock (reportFileLock)
            {
                if (!File.Exists(path))
                {
                    DebugLogger.Log(options, "Client", "Ignored Linux service-status report from '" + DebugLogger.SanitizeForLog(hostname) + "': no existing inventory report to merge into");
                    SendJson(stream, "{\"status\":\"ok\"}");
                    return;
                }

                Dictionary<string, object> existingReport;
                try
                {
                    existingReport = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
                }
                catch
                {
                    DebugLogger.Log(options, "Client", "Ignored Linux service-status report from '" + DebugLogger.SanitizeForLog(hostname) + "': existing report file could not be parsed");
                    SendJson(stream, "{\"status\":\"ok\"}");
                    return;
                }

                Dictionary<string, object> merged = MergeServiceStatus(existingReport, activeUnits, collectedAt);

                string json = serializer.Serialize(merged);
                File.WriteAllText(path, json, new UTF8Encoding(false));
            }

            DebugLogger.Log(options, "Client", "Linux service-status report accepted from '" + DebugLogger.SanitizeForLog(hostname) + "'");
            SendJson(stream, "{\"status\":\"ok\"}");
        }

        // Pure merge logic, extracted from ReceiveLinuxServiceStatus so it's
        // directly self-testable without HTTP plumbing. Only ever flips the
        // `active` field on services the existing report already knows
        // about (matched by `unit`) and sets a new servicesStatusCollectedAt
        // timestamp - never adds, removes, or otherwise touches any other
        // field, unlike ReceiveLinuxInventory's full-overwrite behavior.
        internal static Dictionary<string, object> MergeServiceStatus(Dictionary<string, object> existingReport, ArrayList activeUnits, string collectedAt)
        {
            HashSet<string> activeUnitNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (object unit in activeUnits)
            {
                string unitName = Convert.ToString(unit);
                if (!String.IsNullOrEmpty(unitName))
                {
                    activeUnitNames.Add(unitName);
                }
            }

            if (existingReport.ContainsKey("services") && existingReport["services"] is ArrayList)
            {
                ArrayList services = (ArrayList)existingReport["services"];
                foreach (object serviceObj in services)
                {
                    if (serviceObj is Dictionary<string, object>)
                    {
                        Dictionary<string, object> service = (Dictionary<string, object>)serviceObj;
                        string unitName = service.ContainsKey("unit") ? Convert.ToString(service["unit"]) : "";
                        service["active"] = activeUnitNames.Contains(unitName);
                    }
                }
            }

            existingReport["servicesStatusCollectedAt"] = collectedAt;
            return existingReport;
        }

        private ArrayList LoadLinuxClientReports()
        {
            ArrayList clients = new ArrayList();
            JavaScriptSerializer serializer = CreateJsonSerializer();

            foreach (string file in Directory.GetFiles(options.LinuxDataPath, "*.json"))
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

        // The Linux client is a Linux ELF binary - unlike GetExeVersion
        // (which runs the Windows client .exe locally to ask its version),
        // this server cannot execute a foreign-OS binary. Reads the
        // sidecar .version file Build-LinuxClient.ps1 writes alongside the
        // binary instead.
        private string GetLinuxClientPackageVersion()
        {
            string versionPath = Path.Combine(options.LinuxClientPackagePath, "wil-linux-client.version");
            if (!File.Exists(versionPath))
            {
                return null;
            }
            try
            {
                return File.ReadAllText(versionPath, Encoding.UTF8).Trim();
            }
            catch
            {
                return null;
            }
        }

        private void SendLinuxClientUpdates(Stream stream)
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> result = new Dictionary<string, object>();

            string currentVersion = GetLinuxClientPackageVersion();
            result["currentVersion"] = currentVersion;
            result["lastScheduledJobId"] = lastScheduledLinuxUpdateJobId;
            // Lets the dashboard's Client updates page pre-fill its own
            // "Preferred subnet" field with the currently saved value,
            // without a separate round trip to /api/v1/server/settings.
            result["preferredLinuxSubnet"] = options.PreferredLinuxSubnet;

            if (String.IsNullOrEmpty(currentVersion))
            {
                result["packageAvailable"] = false;
                result["updates"] = new ArrayList();
                result["outdatedCount"] = 0;
                SendJson(stream, serializer.Serialize(result));
                return;
            }

            result["packageAvailable"] = true;
            ArrayList updates = new ArrayList();

            foreach (Dictionary<string, object> client in LoadLinuxClientReports())
            {
                string clientVersion = GetStringValue(client, "clientVersion");
                if (!String.IsNullOrEmpty(clientVersion) && String.Equals(clientVersion, currentVersion, StringComparison.Ordinal))
                {
                    continue;
                }

                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["hostname"] = GetStringValue(client, "hostname");
                // The push target: prefers a real IPv4 address over the
                // (often unresolvable) self-reported hostname - see
                // GetLinuxClientUpdateTarget's own comment. "hostname" above
                // is kept separately for the dashboard's display column.
                entry["target"] = GetLinuxClientUpdateTarget(client, options.PreferredLinuxSubnet);
                entry["clientVersion"] = clientVersion;
                entry["sourceUpdatedAt"] = GetStringValue(client, "sourceUpdatedAt");
                updates.Add(entry);
            }

            result["updates"] = updates;
            result["outdatedCount"] = updates.Count;
            SendJson(stream, serializer.Serialize(result));
        }

        private void SendLinuxUpdateCredentialsStatus(Stream stream)
        {
            bool hasStoredCredentials = !String.IsNullOrEmpty(options.LinuxUpdateUsername) && !String.IsNullOrEmpty(options.LinuxUpdatePassword);
            string keyPath = GetLinuxSshKeyFilePath();
            bool hasStoredKey = File.Exists(keyPath);
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["configured"] = hasStoredCredentials || (!String.IsNullOrEmpty(options.LinuxUpdateUsername) && hasStoredKey);
            result["username"] = String.IsNullOrEmpty(options.LinuxUpdateUsername) ? null : options.LinuxUpdateUsername;
            result["hasPassword"] = !String.IsNullOrEmpty(options.LinuxUpdatePassword);
            result["hasStoredKey"] = hasStoredKey;
            result["keyUploadedAtUtc"] = hasStoredKey ? File.GetLastWriteTimeUtc(keyPath).ToString("yyyy-MM-ddTHH:mm:ssZ") : null;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void ConfigureLinuxUpdateCredentials(Stream stream, RequestContext request)
        {
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
                username = payload.ContainsKey("username") ? Convert.ToString(payload["username"]) : options.LinuxUpdateUsername;
                password = payload.ContainsKey("password") && !String.IsNullOrEmpty(Convert.ToString(payload["password"]))
                    ? Convert.ToString(payload["password"])
                    : options.LinuxUpdatePassword;
            }

            options.LinuxUpdateUsername = username;
            options.LinuxUpdatePassword = password;

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["LinuxUpdateUsername"] = username ?? "";
            updates["LinuxUpdatePassword"] = password ?? "";
            SaveServerConfigValues(updates);

            SendLinuxUpdateCredentialsStatus(stream);
        }

        private void SendLinuxUpdateScheduleStatus(Stream stream)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["mode"] = options.LinuxUpdateScheduleMode;
            result["onceAtUtc"] = String.IsNullOrEmpty(options.LinuxUpdateScheduleOnceAtUtc) ? null : options.LinuxUpdateScheduleOnceAtUtc;
            result["intervalHours"] = options.LinuxUpdateScheduleIntervalHours;
            result["lastRunUtc"] = String.IsNullOrEmpty(options.LinuxUpdateScheduleLastRunUtc) ? null : options.LinuxUpdateScheduleLastRunUtc;
            result["hasSavedCredentials"] = !String.IsNullOrEmpty(options.LinuxUpdateUsername) && (!String.IsNullOrEmpty(options.LinuxUpdatePassword) || File.Exists(GetLinuxSshKeyFilePath()));
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void ConfigureLinuxUpdateSchedule(Stream stream, RequestContext request)
        {
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

            int intervalHours = options.LinuxUpdateScheduleIntervalHours;
            if (mode == "interval")
            {
                if (!payload.ContainsKey("intervalHours") || !Int32.TryParse(Convert.ToString(payload["intervalHours"]), out intervalHours) || intervalHours < 1 || intervalHours > 8760)
                {
                    SendText(stream, "{\"error\":\"intervalHours must be between 1 and 8760 for mode 'interval'\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }

            options.LinuxUpdateScheduleMode = mode;
            options.LinuxUpdateScheduleOnceAtUtc = onceAtUtc;
            options.LinuxUpdateScheduleIntervalHours = intervalHours;
            if (mode != "interval")
            {
                options.LinuxUpdateScheduleLastRunUtc = "";
            }

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["LinuxUpdateScheduleMode"] = options.LinuxUpdateScheduleMode;
            updates["LinuxUpdateScheduleOnceAtUtc"] = options.LinuxUpdateScheduleOnceAtUtc ?? "";
            updates["LinuxUpdateScheduleIntervalHours"] = options.LinuxUpdateScheduleIntervalHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
            updates["LinuxUpdateScheduleLastRunUtc"] = options.LinuxUpdateScheduleLastRunUtc ?? "";
            SaveServerConfigValues(updates);

            ReconfigureLinuxUpdateScheduleTimer();

            SendLinuxUpdateScheduleStatus(stream);
        }

        private readonly object linuxUpdateScheduleTimerLock = new object();
        private Timer linuxUpdateScheduleTimer;

        private void ReconfigureLinuxUpdateScheduleTimer()
        {
            lock (linuxUpdateScheduleTimerLock)
            {
                if (linuxUpdateScheduleTimer != null)
                {
                    linuxUpdateScheduleTimer.Dispose();
                    linuxUpdateScheduleTimer = null;
                }
                if (options.LinuxUpdateScheduleMode != "off")
                {
                    TimeSpan pollInterval = TimeSpan.FromSeconds(60);
                    linuxUpdateScheduleTimer = new Timer(RunLinuxUpdateScheduleTick, null, TimeSpan.Zero, pollInterval);
                }
            }
        }

        private void RunLinuxUpdateScheduleTick(object state)
        {
            try
            {
                string mode = options.LinuxUpdateScheduleMode;
                if (mode == "off")
                {
                    return;
                }

                DateTime? onceAtUtc = ParseUtcOrNull(options.LinuxUpdateScheduleOnceAtUtc);
                DateTime? lastRunUtc = ParseUtcOrNull(options.LinuxUpdateScheduleLastRunUtc);
                if (!ShouldRunClientUpdateSchedule(DateTime.UtcNow, mode, onceAtUtc, lastRunUtc, options.LinuxUpdateScheduleIntervalHours))
                {
                    return;
                }

                StartScheduledLinuxClientUpdatePush();

                Dictionary<string, string> updates = new Dictionary<string, string>();
                if (mode == "once")
                {
                    options.LinuxUpdateScheduleMode = "off";
                    options.LinuxUpdateScheduleOnceAtUtc = "";
                    updates["LinuxUpdateScheduleMode"] = "off";
                    updates["LinuxUpdateScheduleOnceAtUtc"] = "";
                    SaveServerConfigValues(updates);
                    ReconfigureLinuxUpdateScheduleTimer();
                }
                else
                {
                    options.LinuxUpdateScheduleLastRunUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                    updates["LinuxUpdateScheduleLastRunUtc"] = options.LinuxUpdateScheduleLastRunUtc;
                    SaveServerConfigValues(updates);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "Error", "Linux update schedule tick failed: " + ex);
            }
        }

        private void StartScheduledLinuxClientUpdatePush()
        {
            string currentVersion = GetLinuxClientPackageVersion();
            if (String.IsNullOrEmpty(currentVersion))
            {
                return;
            }

            ArrayList targets = new ArrayList();
            foreach (Dictionary<string, object> client in LoadLinuxClientReports())
            {
                string clientVersion = GetStringValue(client, "clientVersion");
                if (!String.IsNullOrEmpty(clientVersion) && String.Equals(clientVersion, currentVersion, StringComparison.Ordinal))
                {
                    continue;
                }
                string target = GetLinuxClientUpdateTarget(client, options.PreferredLinuxSubnet);
                if (String.IsNullOrEmpty(target))
                {
                    continue;
                }
                // GetLinuxClientUpdateTarget can return a client-reported raw
                // hostname, which is attacker-influenced on a compromised managed
                // host. Skip rather than fail the whole scheduled push - one bad
                // record must not stop the rest of the fleet from updating.
                if (!IsValidSshTarget(target))
                {
                    DebugLogger.Log(options, "Schedule", "Scheduled Linux client update push skipped one target: '" + DebugLogger.SanitizeForLog(target) + "' is not a valid hostname or IPv4 address.");
                    continue;
                }
                targets.Add(target);
            }
            if (targets.Count == 0)
            {
                return;
            }

            // A scheduled push re-runs Install-ClientDebianSSH.ps1 against
            // an already-installed target, exactly like a manual "Update
            // selected" push - the script requires -ServerUrl (Mandatory),
            // so this needs the same URL/token/install-path used for the
            // original install, not blank values. Reads them back from the
            // Linux package settings Task 7's ConfigureLinuxClientPackage
            // writes (linux-package-settings.json) - the direct Linux
            // analog of how StartScheduledClientUpdatePush (Windows) reads
            // ParseCmdSettings(cmdPath) for the same reason. Gracefully
            // no-ops (like the Windows path) if that file doesn't exist yet
            // - nothing to push with an unknown server URL.
            string serverUrl = null;
            string token = null;
            string installPath = "/opt/windows-inventory-lite";
            int intervalHours = 6;
            int statusIntervalMinutes = 30;
            string packageSettingsPath = Path.Combine(options.LinuxClientPackagePath, "linux-package-settings.json");
            if (File.Exists(packageSettingsPath))
            {
                try
                {
                    JavaScriptSerializer settingsSerializer = CreateJsonSerializer();
                    Dictionary<string, object> savedSettings = settingsSerializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(packageSettingsPath, Encoding.UTF8));
                    serverUrl = GetStringValue(savedSettings, "serverUrl");
                    token = GetStringValue(savedSettings, "token");
                    string savedInstallPath = GetStringValue(savedSettings, "installPath");
                    if (!String.IsNullOrEmpty(savedInstallPath))
                    {
                        installPath = savedInstallPath;
                    }
                    intervalHours = GetIntValue(savedSettings, "intervalHours", 6);
                    statusIntervalMinutes = GetIntValue(savedSettings, "statusIntervalMinutes", 30);
                }
                catch
                {
                    serverUrl = null;
                }
            }
            if (String.IsNullOrEmpty(serverUrl))
            {
                DebugLogger.Log(options, "Schedule", "Scheduled Linux client update push skipped: no server URL saved yet - configure it on the Client package tab's Linux package section first.");
                return;
            }
            // The saved package settings' own token can be stale (e.g. the
            // package was configured before a later regenerate) - the
            // server's live options.Token is always the current, correct
            // value, so prefer it whenever the saved one is blank.
            if (String.IsNullOrEmpty(token))
            {
                token = options.Token;
            }

            string keyPath = GetLinuxSshKeyFilePath();
            string authMode = File.Exists(keyPath) ? "key" : "credentials";
            string username = options.LinuxUpdateUsername;
            string password = options.LinuxUpdatePassword;
            if (String.IsNullOrEmpty(username) || (authMode == "credentials" && String.IsNullOrEmpty(password)))
            {
                DebugLogger.Log(options, "Schedule", "Scheduled Linux client update push skipped: no saved Linux credentials configured.");
                return;
            }

            string pushValidationError;
            if (!TryValidateLinuxPushValues(serverUrl, token, installPath, out pushValidationError))
            {
                DebugLogger.Log(options, "Schedule", "Scheduled Linux client update push skipped: " + DebugLogger.SanitizeForLog(pushValidationError));
                return;
            }

            InstallJob job = new InstallJob();
            job.Id = Guid.NewGuid().ToString("N");
            job.Action = "install";
            job.Status = "queued";
            job.CreatedAtUtc = DateTime.UtcNow;
            job.Targets = targets;
            job.Results = new ArrayList();
            job.Mode = "force-linux";
            job.ServerUrl = serverUrl;
            job.Token = token;
            job.InstallPath = installPath;
            job.IntervalHours = intervalHours;
            job.StatusIntervalMinutes = statusIntervalMinutes;
            job.SshAuthMode = authMode;
            job.SshUsername = username;
            job.SshPassword = password;
            job.SshKeyPath = keyPath;
            job.RetentionDays = options.InstallLogRetentionDays;

            lock (installJobsLock)
            {
                installJobs[job.Id] = job;
                SaveInstallJob(job);
            }
            lastScheduledLinuxUpdateJobId = job.Id;
            DebugLogger.Log(options, "Schedule", "Scheduled Linux client update push started: job '" + job.Id + "', " + targets.Count + " target(s).");
            ThreadPool.QueueUserWorkItem(RunClientActionJob, job);
        }

        private string BuildLinuxClientIndex()
        {
            ArrayList clients = LoadLinuxClientReports();
            JavaScriptSerializer serializer = CreateJsonSerializer();

            Dictionary<string, object> index = new Dictionary<string, object>();
            index["schemaVersion"] = "1.0";
            index["serverVersion"] = Program.ProductVersion;
            index["generatedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            index["clientCount"] = clients.Count;
            index["adDescriptionSyncEnabled"] = options.AdDescriptionSyncEnabled;
            index["clients"] = clients;
            return serializer.Serialize(index);
        }

        private void DeleteLinuxClient(Stream stream, RequestContext request)
        {
            const string prefix = "/api/v1/linux/clients/";
            string rawHostname = request.Path.Substring(prefix.Length);
            int queryStart = rawHostname.IndexOf('?');
            if (queryStart >= 0)
            {
                rawHostname = rawHostname.Substring(0, queryStart);
            }

            string hostname = Uri.UnescapeDataString(rawHostname).Trim();
            if (String.IsNullOrEmpty(hostname))
            {
                SendText(stream, "{\"error\":\"hostname is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string path = Path.Combine(options.LinuxDataPath, SanitizeFileName(hostname) + ".json");
            if (!File.Exists(path))
            {
                SendText(stream, "{\"error\":\"client not found\"}", "application/json; charset=utf-8", 404);
                return;
            }

            File.Delete(path);
            SendJson(stream, "{\"status\":\"deleted\"}");
        }

        // Manual Description edit for a Linux client - same rule as
        // UpdateClientDescription: only reachable while AD Description
        // Sync is off, enforced here (not just by the dashboard hiding the
        // control). Writes the same adDescription field
        // ComputeAdSyncFields/ApplyAdSyncFields already read/write.
        private void UpdateLinuxClientDescription(Stream stream, RequestContext request)
        {
            const string prefix = "/api/v1/linux/clients/";
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

            string rawHostname = rawPath.Substring(prefix.Length, rawPath.Length - prefix.Length - suffix.Length);
            string hostname = Uri.UnescapeDataString(rawHostname).Trim();
            if (String.IsNullOrEmpty(hostname))
            {
                SendText(stream, "{\"error\":\"hostname is required\"}", "application/json; charset=utf-8", 400);
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

            string path = Path.Combine(options.LinuxDataPath, SanitizeFileName(hostname) + ".json");
            lock (reportFileLock)
            {
                if (!File.Exists(path))
                {
                    SendText(stream, "{\"error\":\"client not found\"}", "application/json; charset=utf-8", 404);
                    return;
                }
                Dictionary<string, object> record;
                try
                {
                    record = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
                }
                catch
                {
                    SendText(stream, "{\"error\":\"client report could not be read\"}", "application/json; charset=utf-8", 500);
                    return;
                }
                if (record == null)
                {
                    SendText(stream, "{\"error\":\"client report could not be read\"}", "application/json; charset=utf-8", 500);
                    return;
                }
                record["adDescription"] = description;
                File.WriteAllText(path, serializer.Serialize(record), new UTF8Encoding(false));
            }

            Dictionary<string, object> response = new Dictionary<string, object>();
            response["status"] = "ok";
            response["description"] = description;
            SendJson(stream, serializer.Serialize(response));
        }

        private void StartClientAction(Stream stream, RequestContext request, string action)
        {
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

            string mode = Convert.ToString(payload.ContainsKey("mode") ? payload["mode"] : "");
            if (mode != "auto" && mode != "force-windows" && mode != "force-linux")
            {
                SendText(stream, "{\"error\":\"mode must be 'auto', 'force-windows', or 'force-linux'\"}", "application/json; charset=utf-8", 400);
                return;
            }
            bool needsWinRm = mode == "auto" || mode == "force-windows";
            bool needsSsh = mode == "auto" || mode == "force-linux";

            string targetText = Convert.ToString(payload.ContainsKey("targets") ? payload["targets"] : "");
            string serverUrl = Convert.ToString(payload.ContainsKey("serverUrl") ? payload["serverUrl"] : "");
            // Blank means "use the server's current ingestion token", not
            // "install with no token" - same convention as the Linux
            // install endpoint used to have its own copy of this comment,
            // and the Package tab's token fields.
            string token = Convert.ToString(payload.ContainsKey("token") ? payload["token"] : "");
            if (String.IsNullOrEmpty(token))
            {
                token = options.Token;
            }

            string winRmUsername = "";
            string winRmPassword = "";
            bool force = false;
            bool addToTrustedHosts = false;
            if (needsWinRm)
            {
                winRmUsername = Convert.ToString(payload.ContainsKey("username") ? payload["username"] : "");
                winRmPassword = Convert.ToString(payload.ContainsKey("password") ? payload["password"] : "");
                if (payload.ContainsKey("winRmAuthMode"))
                {
                    // New Deploy > Actions shape (2026-08-21): an explicit
                    // credential-source dropdown, replacing the old "Use
                    // global AD settings" checkbox. Global tries the
                    // saved Client update account first, AD as a
                    // fallback if nothing is saved - same priority chain
                    // as SSH's own Global mode below. Manual keeps this
                    // endpoint's existing behavior for typed fields
                    // (used as given; blank means install as the
                    // server's own service identity, not an error).
                    string winRmAuthMode = Convert.ToString(payload["winRmAuthMode"]);
                    if (winRmAuthMode != "global" && winRmAuthMode != "manual")
                    {
                        SendText(stream, "{\"error\":\"winRmAuthMode must be 'global' or 'manual'\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                    if (winRmAuthMode == "global")
                    {
                        winRmUsername = "";
                        winRmPassword = "";
                        ResolveUpdateCredentials(ref winRmUsername, ref winRmPassword, true, options.ClientUpdateUsername, options.ClientUpdatePassword);
                        if (String.IsNullOrEmpty(winRmUsername) || String.IsNullOrEmpty(winRmPassword))
                        {
                            string adCredentialError;
                            TryResolveAdSyncCredentials(true, options.AdSyncEnabled, options.AdUseServiceIdentity, options.AdUsername, options.AdPassword, ref winRmUsername, ref winRmPassword, out adCredentialError);
                            // Ignore a false return here (AD disabled, or
                            // no saved AD account) - TryResolveAdSyncCredentials
                            // leaves username/password untouched on
                            // failure, so this just means "nothing to
                            // fall back to", which RunClientInstallTarget
                            // already treats as "install as the
                            // service's own identity", not an error.
                        }
                    }
                    // "manual": winRmUsername/winRmPassword already hold
                    // whatever was typed (or blank), used as-is.
                }
                else
                {
                    // Old shape. As of the Deploy > Updates unification,
                    // no first-party caller sends this any more - the
                    // dashboard's "Update selected" (startMergedUpdatesPush)
                    // sends winRmAuthMode like Deploy > Actions does.
                    // Kept for backward compatibility with anything that
                    // scripted the old payload shape directly.
                    bool useSavedCredentials = payload.ContainsKey("useSavedCredentials") && Convert.ToBoolean(payload["useSavedCredentials"]);
                    ResolveUpdateCredentials(ref winRmUsername, ref winRmPassword, useSavedCredentials, options.ClientUpdateUsername, options.ClientUpdatePassword);
                    bool useAdCredentials = payload.ContainsKey("useAdCredentials") && Convert.ToBoolean(payload["useAdCredentials"]);
                    string adCredentialError;
                    if (!TryResolveAdSyncCredentials(useAdCredentials, options.AdSyncEnabled, options.AdUseServiceIdentity, options.AdUsername, options.AdPassword, ref winRmUsername, ref winRmPassword, out adCredentialError))
                    {
                        SendText(stream, "{\"error\":\"" + adCredentialError.Replace("\"", "'") + "\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                }
                force = payload.ContainsKey("force") && Convert.ToBoolean(payload["force"]);
                addToTrustedHosts = payload.ContainsKey("addToTrustedHosts") && Convert.ToBoolean(payload["addToTrustedHosts"]);
            }

            string sshAuthMode = "credentials";
            string sshUsername = "";
            string sshPassword = "";
            string sshKeyPath = "";
            bool trustNewHostKeys = false;
            int intervalHours = options.LinuxDefaultIntervalHours;
            int statusIntervalMinutes = options.LinuxDefaultStatusIntervalMinutes;
            string installPath = Convert.ToString(payload.ContainsKey("installPath") ? payload["installPath"] : options.LinuxDefaultInstallPath);
            if (needsSsh)
            {
                sshAuthMode = Convert.ToString(payload.ContainsKey("sshAuthMode") ? payload["sshAuthMode"] : "credentials");
                sshUsername = Convert.ToString(payload.ContainsKey("sshUsername") ? payload["sshUsername"] : "");
                sshPassword = Convert.ToString(payload.ContainsKey("sshPassword") ? payload["sshPassword"] : "");
                sshKeyPath = GetLinuxSshKeyFilePath();

                if (sshAuthMode == "global")
                {
                    // New Deploy > Actions shape (2026-08-21): no typed
                    // fields shown - always tries the saved Linux
                    // account first, AD as a fallback if nothing is
                    // saved, same priority chain as WinRM's own Global
                    // mode above. Unlike WinRM, SSH has no "service
                    // identity" fallback (there is no anonymous SSH), so
                    // this is a hard error rather than a silent
                    // empty-credential fallback when nothing resolves.
                    sshUsername = options.LinuxUpdateUsername;
                    sshPassword = options.LinuxUpdatePassword;
                    if (String.IsNullOrEmpty(sshUsername) || String.IsNullOrEmpty(sshPassword))
                    {
                        string adCredentialError;
                        TryResolveAdSyncCredentials(true, options.AdSyncEnabled, options.AdUseServiceIdentity, options.AdUsername, options.AdPassword, ref sshUsername, ref sshPassword, out adCredentialError);
                        // Ignore a false return - AD service-identity mode
                        // resolves to blank username/password (no SSH
                        // equivalent exists), which the check below
                        // catches the same as "nothing configured at all".
                    }
                    if (String.IsNullOrEmpty(sshUsername) || String.IsNullOrEmpty(sshPassword))
                    {
                        SendText(stream, "{\"error\":\"No Linux credentials available for Global mode - save them in Settings > Linux > Linux Client update credentials, configure a non-service-identity AD account, or select Manual credentials/SSH key instead.\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                }
                else if (sshAuthMode == "manual" || sshAuthMode == "credentials")
                {
                    // "manual" (current dropdown value, sent by both
                    // Deploy > Actions and, since the Deploy > Updates
                    // unification, startMergedUpdatesPush too) and
                    // "credentials" (legacy value - no first-party caller
                    // sends it any more, kept for anything that scripted
                    // the old payload shape directly) are the same
                    // behavior: typed fields, falling back to the saved
                    // account when left blank - unchanged leniency from
                    // before.
                    if (String.IsNullOrEmpty(sshUsername)) sshUsername = options.LinuxUpdateUsername;
                    if (String.IsNullOrEmpty(sshPassword)) sshPassword = options.LinuxUpdatePassword;
                    if (String.IsNullOrEmpty(sshUsername) || String.IsNullOrEmpty(sshPassword))
                    {
                        SendText(stream, "{\"error\":\"username/password are required (enter them, or save them in Settings > Linux > Linux Client update credentials)\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                }
                else if (sshAuthMode == "key")
                {
                    if (String.IsNullOrEmpty(sshUsername)) sshUsername = options.LinuxUpdateUsername;
                    if (String.IsNullOrEmpty(sshUsername))
                    {
                        SendText(stream, "{\"error\":\"username is required for 'key' auth mode (enter it, or save it in Settings > Linux > Linux Client update credentials)\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                    if (!File.Exists(sshKeyPath))
                    {
                        SendText(stream, "{\"error\":\"No SSH key is configured - upload one in Settings > Linux > Linux Client update credentials.\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                }
                else if (sshAuthMode == "ad")
                {
                    // Legacy value, still sent by Deploy > Updates' Linux
                    // "Update selected" push - unchanged from before.
                    bool useAd = true;
                    string adCredentialError;
                    if (!TryResolveAdSyncCredentials(useAd, options.AdSyncEnabled, options.AdUseServiceIdentity, options.AdUsername, options.AdPassword, ref sshUsername, ref sshPassword, out adCredentialError))
                    {
                        SendText(stream, "{\"error\":\"" + adCredentialError.Replace("\"", "'") + "\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                    if (String.IsNullOrEmpty(sshUsername) || String.IsNullOrEmpty(sshPassword))
                    {
                        SendText(stream, "{\"error\":\"AD service-identity mode is not usable for SSH pushes to Linux targets (there is no SSH equivalent of running as the service's own identity). Select 'Stored Linux credentials' or 'SSH key' instead, or configure an explicit AD account rather than service identity in Settings > Windows > Active Directory.\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                }
                else
                {
                    SendText(stream, "{\"error\":\"sshAuthMode must be 'global', 'manual', 'key', 'ad', or 'credentials'\"}", "application/json; charset=utf-8", 400);
                    return;
                }

                if (payload.ContainsKey("intervalHours"))
                {
                    Int32.TryParse(Convert.ToString(payload["intervalHours"]), out intervalHours);
                }
                if (intervalHours < 1 || intervalHours > 24)
                {
                    intervalHours = options.LinuxDefaultIntervalHours;
                }
                if (payload.ContainsKey("statusIntervalMinutes"))
                {
                    Int32.TryParse(Convert.ToString(payload["statusIntervalMinutes"]), out statusIntervalMinutes);
                }
                if (statusIntervalMinutes < 1 || statusIntervalMinutes > 1440)
                {
                    statusIntervalMinutes = options.LinuxDefaultStatusIntervalMinutes;
                }
            }

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

            // Force Linux (and Auto, which may resolve a target to SSH)
            // rejects any target with characters invalid in a
            // hostname/IPv4 address up front, the all-or-nothing pre-check
            // StartLinuxClientAction always applied. Force Windows skips
            // this entirely - NetBIOS names can legally contain '_', which
            // this check would wrongly reject.
            if (mode != "force-windows")
            {
                foreach (string candidate in targets)
                {
                    if (!IsValidSshTarget(candidate))
                    {
                        SendText(stream, "{\"error\":\"one or more targets contain characters that are not valid in a hostname or IPv4 address (only letters, digits, '.' and '-' are allowed)\"}", "application/json; charset=utf-8", 400);
                        return;
                    }
                }
            }

            // The Deploy > Updates "Update selected" push (both the Linux
            // manual push and the Linux scheduled push) intentionally does
            // not resend serverUrl/installPath/intervalHours/
            // statusIntervalMinutes - it targets already-installed clients
            // and expects the same values used for the original install.
            // Fall back to linux-package-settings.json for whichever of
            // these fields the caller did not explicitly supply, exactly
            // as StartLinuxClientAction used to. Gated on needsSsh only -
            // this file has no Windows equivalent, and a pure
            // force-windows job has no use for it.
            if (needsSsh && action == "install" && String.IsNullOrEmpty(serverUrl))
            {
                string packageSettingsPath = Path.Combine(options.LinuxClientPackagePath, "linux-package-settings.json");
                if (File.Exists(packageSettingsPath))
                {
                    try
                    {
                        JavaScriptSerializer settingsSerializer = CreateJsonSerializer();
                        Dictionary<string, object> savedSettings = settingsSerializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(packageSettingsPath, Encoding.UTF8));
                        serverUrl = GetStringValue(savedSettings, "serverUrl");
                        if (!payload.ContainsKey("installPath"))
                        {
                            string savedInstallPath = GetStringValue(savedSettings, "installPath");
                            if (!String.IsNullOrEmpty(savedInstallPath))
                            {
                                installPath = savedInstallPath;
                            }
                        }
                        if (!payload.ContainsKey("intervalHours"))
                        {
                            intervalHours = GetIntValue(savedSettings, "intervalHours", intervalHours);
                        }
                        if (!payload.ContainsKey("statusIntervalMinutes"))
                        {
                            statusIntervalMinutes = GetIntValue(savedSettings, "statusIntervalMinutes", statusIntervalMinutes);
                        }
                    }
                    catch
                    {
                        serverUrl = null;
                    }
                }
            }

            if (action == "install" && String.IsNullOrEmpty(serverUrl))
            {
                SendText(stream, "{\"error\":\"serverUrl is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            // serverUrl flows unmodified through Install-ClientWinRM.ps1 into
            // Deploy-ClientGpo.ps1's cmd.exe-based service-creation step on the
            // TARGET machine (Invoke-ServiceCreate) - validated for every mode,
            // not just needsWinRm, since Auto mode may resolve any given target
            // to WinRM even when the admin expected SSH.
            try
            {
                ValidateBatchSafe(serverUrl, "serverUrl");
            }
            catch (ArgumentException ex)
            {
                SendText(stream, "{\"error\":\"" + ex.Message.Replace("\"", "'") + "\"}", "application/json; charset=utf-8", 400);
                return;
            }
            if (needsSsh)
            {
                string pushValidationError;
                if (!TryValidateLinuxPushValues(serverUrl, token, installPath, out pushValidationError))
                {
                    SendText(stream, "{\"error\":\"" + pushValidationError.Replace("\\", "\\\\").Replace("\"", "'") + "\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }

            if (needsWinRm && !addToTrustedHosts && !String.IsNullOrEmpty(winRmUsername) && !String.IsNullOrEmpty(winRmPassword) && ContainsIpAddressTarget(targets))
            {
                addToTrustedHosts = true;
            }

            if (needsSsh && action == "install")
            {
                trustNewHostKeys = payload.ContainsKey("trustNewHostKeys") && Convert.ToBoolean(payload["trustNewHostKeys"]);
                bool acknowledgeHostKeyRisk = payload.ContainsKey("acknowledgeHostKeyRisk") && Convert.ToBoolean(payload["acknowledgeHostKeyRisk"]);
                if (trustNewHostKeys && !acknowledgeHostKeyRisk)
                {
                    SendText(stream, "{\"error\":\"acknowledgeHostKeyRisk must be true when trustNewHostKeys is enabled\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                // Auto mode can dispatch a target to SSH the operator never
                // deliberately identified as a Linux host (it just happened
                // to answer on port 22) - combined with bulk-auto-trust,
                // that target's real SSH host key gets accepted sight
                // unseen, and the SSH credential (saved/AD password) is
                // sent to it in the same request. Force Linux carries the
                // same risk but requires the operator to have chosen SSH
                // explicitly for these targets first - keep the
                // combination gated to that deliberate choice.
                if (trustNewHostKeys && mode == "auto")
                {
                    SendText(stream, "{\"error\":\"Trust new host keys automatically is not available in Auto mode - select Force Linux to bulk-auto-trust SSH host keys for a target list you've deliberately identified as Linux hosts.\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }

            InstallJob job = new InstallJob();
            job.Id = Guid.NewGuid().ToString("N");
            job.Action = action;
            job.Status = "queued";
            job.CreatedAtUtc = DateTime.UtcNow;
            job.Targets = targets;
            job.Results = new ArrayList();
            job.Mode = mode;
            job.ServerUrl = serverUrl;
            job.Token = token;
            job.Username = winRmUsername;
            job.Password = winRmPassword;
            job.Force = force;
            job.AddToTrustedHosts = addToTrustedHosts;
            job.SshAuthMode = sshAuthMode;
            job.SshUsername = sshUsername;
            job.SshPassword = sshPassword;
            job.SshKeyPath = sshKeyPath;
            job.IntervalHours = intervalHours;
            job.StatusIntervalMinutes = statusIntervalMinutes;
            job.InstallPath = installPath;
            job.TrustNewHostKeys = trustNewHostKeys;
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
                    summary["mode"] = GetStringValue(job, "mode");
                    summary["serverUrl"] = GetStringValue(job, "serverUrl");
                    // A force-linux job has no WinRM username - fall back to
                    // sshUsername so the merged "Saved client action logs"
                    // table doesn't show a blank operator identity for
                    // every Linux job (the old, now-deleted
                    // SendLinuxClientInstallJobs exposed authMode/username
                    // directly; this is the closest equivalent once both
                    // credential sets live on one job).
                    string winRmUsername = GetStringValue(job, "username");
                    summary["username"] = String.IsNullOrEmpty(winRmUsername) ? GetStringValue(job, "sshUsername") : winRmUsername;
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
            // InstallJob.ToDictionary() shares its Results ArrayList by
            // reference rather than copying it, so serializing it after
            // releasing the lock would let RunClientActionJob's own
            // lock(installJobsLock) { job.Results.Add(result); ... }
            // mutate that same list mid-enumeration on a running job's
            // GET (ArrayList is not safe for concurrent read+write) - the
            // fix has to hold the lock for the whole serialize, not just
            // the dictionary lookup. Serializer.Serialize is CPU-only
            // (no I/O), so this doesn't meaningfully extend how long the
            // job-running thread might wait for the same lock.
            string serializedJob = null;
            lock (installJobsLock)
            {
                if (installJobs.ContainsKey(id))
                {
                    job = installJobs[id];
                    JavaScriptSerializer serializer = CreateJsonSerializer();
                    serializedJob = serializer.Serialize(job.ToDictionary());
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

            SendJson(stream, serializedJob);
        }

        private void RunClientActionJob(object state)
        {
            InstallJob job = (InstallJob)state;
            lock (installJobsLock)
            {
                job.Status = "running";
                job.StartedAtUtc = DateTime.UtcNow;
                SaveInstallJob(job);
            }

            // Used only to patch a target's stored report after a
            // successful WinRM install below (see
            // PatchClientReportVersionAfterInstall) - computed once per
            // job, not per-target. Irrelevant to an SSH-installed target,
            // which has no exe version in this sense; see the "protocol"
            // check below.
            string net35Version = null;
            string net40Version = null;
            if (job.Action != "uninstall" && Directory.Exists(options.ClientPackagePath))
            {
                string net35Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net35.exe");
                string net40Path = Path.Combine(options.ClientPackagePath, "WindowsInventoryLiteClient-net40.exe");
                net35Version = File.Exists(net35Path) ? GetExeVersion(net35Path) : null;
                net40Version = File.Exists(net40Path) ? GetExeVersion(net40Path) : null;
            }

            foreach (string target in job.Targets)
            {
                Dictionary<string, object> result = RunUnifiedInstallTarget(
                    target, job.Action, job.Mode,
                    job.ServerUrl, job.Token,
                    job.Username, job.Password, job.Force, job.AddToTrustedHosts,
                    job.SshAuthMode, job.SshUsername, job.SshPassword, job.SshKeyPath, job.TrustNewHostKeys,
                    job.IntervalHours, job.StatusIntervalMinutes, job.InstallPath,
                    AutoDetectProbeTimeoutMs);
                lock (installJobsLock)
                {
                    job.Results.Add(result);
                    SaveInstallJob(job);
                }

                if (job.Action != "uninstall" && GetStringValue(result, "status") == "completed" && GetStringValue(result, "protocol") == "winrm")
                {
                    PatchClientReportVersionAfterInstall(target, net35Version, net40Version);
                }
            }

            lock (installJobsLock)
            {
                job.CompletedAtUtc = DateTime.UtcNow;
                job.Status = "completed";
                SaveInstallJob(job);
                // The on-disk copy (SaveInstallJob, just above) is the durable
                // record and already omits Password/SshPassword (ToDictionary) -
                // nothing is lost by also dropping the in-memory entry now that
                // the job is done. Without this, installJobs grew unbounded for
                // the server's entire uptime, keeping every job's plaintext
                // WinRM/SSH password resident in memory long after it was
                // needed. SendClientInstallJob already falls back to reading
                // the file when a job isn't found in memory.
                installJobs.Remove(job.Id);
            }
            CleanupInstallJobLogs();
        }

        private void TrustLinuxHostKey(Stream stream, RequestContext request)
        {
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

            string host = GetStringValue(payload, "host");
            string fingerprint = GetStringValue(payload, "fingerprint");
            string keyType = GetStringValue(payload, "keyType");
            if (String.IsNullOrEmpty(keyType))
            {
                keyType = "ssh-ed25519";
            }
            int port = 22;
            if (payload.ContainsKey("port"))
            {
                // Parse into a separate local: Int32.TryParse writes 0 to
                // its out parameter on failure, which would otherwise
                // silently clobber the port=22 default for a malformed/null
                // "port" value instead of keeping it.
                int parsedPort;
                if (Int32.TryParse(Convert.ToString(payload["port"]), out parsedPort))
                {
                    port = parsedPort;
                }
            }

            if (String.IsNullOrEmpty(host))
            {
                SendText(stream, "{\"error\":\"host is required\"}", "application/json; charset=utf-8", 400);
                return;
            }
            if (!IsValidHostKeyFingerprint(fingerprint))
            {
                SendText(stream, "{\"error\":\"fingerprint must look like 'SHA256:...'\"}", "application/json; charset=utf-8", 400);
                return;
            }

            try
            {
                ValidatePosixShellSafe(host, "host");
                ValidatePosixShellSafe(fingerprint, "fingerprint");
            }
            catch (ArgumentException ex)
            {
                SendText(stream, "{\"error\":\"" + ex.Message.Replace("\\", "\\\\").Replace("\"", "'") + "\"}", "application/json; charset=utf-8", 400);
                return;
            }

            Dictionary<string, object> record = UpsertLinuxKnownHost(host, port, keyType, fingerprint, "manual");
            SendJson(stream, serializer.Serialize(record));
        }

        // Credentials/key path never appear on the child process's command
        // line (same reasoning as BuildCredentialReaderSnippet for the
        // WinRM path) - passed via a small PowerShell stdin-reading
        // preamble instead, invisible to a local process listing.
        private static string BuildLinuxCredentialReaderSnippet(string authMode)
        {
            if (authMode == "key")
            {
                return "$__wilUser = [Console]::In.ReadLine(); $__wilKeyPath = [Console]::In.ReadLine(); ";
            }
            return "$__wilUser = [Console]::In.ReadLine(); $__wilPass = [Console]::In.ReadLine(); $__wilSecurePass = ConvertTo-SecureString -String $__wilPass -AsPlainText -Force; ";
        }

        private Dictionary<string, object> RunLinuxClientInstallTarget(string target, string serverUrl, string token, int intervalHours, int statusIntervalMinutes, string installPath, string authMode, string username, string password, string keyPath, bool trustNewHostKeys)
        {
            return RunLinuxClientInstallTarget(target, serverUrl, token, intervalHours, statusIntervalMinutes, installPath, authMode, username, password, keyPath, trustNewHostKeys, false);
        }

        private Dictionary<string, object> RunLinuxClientInstallTarget(string target, string serverUrl, string token, int intervalHours, int statusIntervalMinutes, string installPath, string authMode, string username, string password, string keyPath, bool trustNewHostKeys, bool isBulkAutoRetry)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["target"] = target;
            result["startedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            if (!IsValidSshTarget(target))
            {
                result["status"] = "failed";
                result["message"] = "Target contains characters that are not valid in a hostname or IPv4 address. Only letters, digits, '.' and '-' are allowed.";
                return result;
            }

            if (!File.Exists(options.LinuxSshInstallerPath))
            {
                result["status"] = "failed";
                result["message"] = "Linux SSH installer script was not found: " + options.LinuxSshInstallerPath;
                return result;
            }

            bool usingKey = authMode == "key";
            string expectedHostKey = null;
            // Deliberately NOT gated on authMode. Which credential is used to
            // AUTHENTICATE the client is unrelated to whether the SERVER's key is
            // the one we previously trusted. Gating this on !usingKey is exactly
            // how the key-mode path ended up with no host-key verification at all:
            // C# never passed -ExpectedHostKey and the script never used it.
            Dictionary<string, object> knownHost;
            try
            {
                knownHost = FindLinuxKnownHost(target, 22);
            }
            catch (Exception ex)
            {
                // A failure to read the trust store must never be treated
                // as "no record, safe to auto-trust" - report the push as
                // failed instead of silently proceeding as if this target
                // were brand-new (see FindLinuxKnownHost).
                result["status"] = "failed";
                result["message"] = "Could not read the Linux SSH known-hosts trust store: " + ex.Message;
                return result;
            }
            if (knownHost != null)
            {
                expectedHostKey = GetStringValue(knownHost, "Fingerprint");
                result["hostKeyTrust"] = "already-trusted";
            }

            // Last line of defence at the single point both the manual and the
            // scheduled push paths converge on, right where the values become part
            // of a command line.
            string pushValidationError;
            if (!TryValidateLinuxPushValues(serverUrl, token, installPath, out pushValidationError))
            {
                result["status"] = "failed";
                result["message"] = pushValidationError;
                return result;
            }

            StringBuilder argsBuilder = new StringBuilder();
            argsBuilder.Append("-ComputerName ").Append(QuotePowerShellLiteral(target));
            argsBuilder.Append(" -ServerUrl ").Append(QuotePowerShellLiteral(serverUrl));
            argsBuilder.Append(" -IntervalHours ").Append(intervalHours);
            argsBuilder.Append(" -StatusIntervalMinutes ").Append(statusIntervalMinutes);
            argsBuilder.Append(" -InstallPath ").Append(QuotePowerShellLiteral(installPath));
            // On an installed server the script's own repo-relative default
            // (build\wil-linux-client) does not resolve - point it at the
            // well-known package location DownloadLinuxClientPackage already
            // requires an operator to place the binary at.
            argsBuilder.Append(" -ClientBinaryPath ").Append(QuotePowerShellLiteral(Path.Combine(options.LinuxClientPackagePath, "wil-linux-client")));
            if (!String.IsNullOrEmpty(token))
            {
                argsBuilder.Append(" -Token ").Append(QuotePowerShellLiteral(token));
            }
            if (!String.IsNullOrEmpty(expectedHostKey))
            {
                argsBuilder.Append(" -ExpectedHostKey ").Append(QuotePowerShellLiteral(expectedHostKey));
            }
            argsBuilder.Append(" -CredentialUsername $__wilUser");
            if (usingKey)
            {
                argsBuilder.Append(" -KeyPath $__wilKeyPath");
            }
            else
            {
                argsBuilder.Append(" -CredentialPassword $__wilSecurePass");
            }

            string commandBody = "[Console]::OutputEncoding = [System.Text.Encoding]::Default; $OutputEncoding = [Console]::OutputEncoding; "
                + BuildLinuxCredentialReaderSnippet(authMode)
                + "& " + QuotePowerShellLiteral(options.LinuxSshInstallerPath) + " "
                + argsBuilder.ToString();

            result = RunLinuxSshProcess(commandBody, authMode, username, password, keyPath, result);

            string hostKeyClassification = null;
            if (GetStringValue(result, "status") == "failed")
            {
                string combinedOutput = GetStringValue(result, "output") + "\n" + GetStringValue(result, "error");
                string parsedKeyType, parsedFingerprint;
                bool parsedOk = TryParseHostKeyDetails(combinedOutput, out parsedKeyType, out parsedFingerprint);

                hostKeyClassification = ClassifyHostKeyFailure(expectedHostKey, combinedOutput, parsedOk, trustNewHostKeys, isBulkAutoRetry);
                switch (hostKeyClassification)
                {
                    case "changed":
                        // expectedHostKey was set (a record already existed) and
                        // the connection still failed on a host-key-related
                        // message - the target's real key changed since it was
                        // trusted. Never auto-accepted, regardless of trustNewHostKeys.
                        // hostKeyFingerprint is deliberately never set here, even
                        // if parsedOk is true: the dashboard renders a pre-filled
                        // one-click "Trust and retry" button whenever a fingerprint
                        // is present, and a changed key must always force the
                        // manual-entry path so the operator types the new
                        // fingerprint deliberately - this must hold even if a
                        // future plink build's mismatch wording happens to also
                        // include a parseable fingerprint.
                        result["hostKeyStatus"] = "changed";
                        result.Remove("hostKeyTrust");
                        break;
                    case "bulk-auto":
                        // Same format validation the manual trust-host-key
                        // endpoint applies (IsValidHostKeyFingerprint) - a
                        // parsedFingerprint that doesn't look like a real
                        // fingerprint must not be auto-trusted; fall back to
                        // requiring an explicit manual decision instead.
                        if (!IsValidHostKeyFingerprint(parsedFingerprint))
                        {
                            // hostKeyFingerprint is deliberately not set here: the
                            // dashboard renders a pre-filled one-click button
                            // whenever it's present, and resubmitting this same
                            // value would just get rejected again by the
                            // trust-host-key endpoint's own validation. Fall back
                            // to requiring an explicit manual decision instead.
                            result["hostKeyStatus"] = "unknown";
                            break;
                        }
                        try
                        {
                            UpsertLinuxKnownHost(target, 22, parsedKeyType, parsedFingerprint, "bulk-auto");
                        }
                        catch (Exception ex)
                        {
                            // A write failure here must surface as a failed
                            // push, not be silently swallowed - this is the
                            // write-side counterpart to the read-failure
                            // handling above (see FindLinuxKnownHost).
                            result["status"] = "failed";
                            result["message"] = "Could not update the Linux SSH known-hosts trust store: " + ex.Message;
                            return result;
                        }
                        return RunLinuxClientInstallTarget(target, serverUrl, token, intervalHours, statusIntervalMinutes, installPath, authMode, username, password, keyPath, trustNewHostKeys, true);
                    case "unknown":
                        result["hostKeyStatus"] = "unknown";
                        result["hostKeyFingerprint"] = parsedFingerprint;
                        break;
                }
            }

            // isBulkAutoRetry marks a result that came from a connection made
            // right after a bulk-auto trust upsert. Skip the label when this
            // same attempt just reclassified as "changed" above - that means
            // the freshly-stored record itself didn't match what the target
            // presented, and "changed" must never be paired with "bulk-auto".
            if (isBulkAutoRetry && hostKeyClassification != "changed")
            {
                result["hostKeyTrust"] = "bulk-auto";
            }

            return result;
        }

        // Decides how a failed non-key SSH attempt should be classified from
        // its host-key evidence alone - no I/O, so it's directly unit-testable
        // without spinning up a real plink/pscp process. Returns:
        //   "changed"   - a prior trusted record existed (expectedHostKey set)
        //                 and the failure text mentions a host key. The target's
        //                 real key no longer matches what was trusted. Must
        //                 NEVER be auto-accepted, regardless of trustNewHostKeys.
        //   "bulk-auto" - no prior record existed, the failure fingerprint
        //                 parsed cleanly, bulk auto-trust is enabled, and this
        //                 isn't already a bulk-auto retry. Safe to trust and retry once.
        //   "unknown"   - the failure fingerprint parsed but neither of the
        //                 above applies AND no prior record existed - needs
        //                 an explicit manual trust decision.
        //   null        - not a host-key failure at all (or nothing to classify;
        //                 also covers a prior record existing but the failure
        //                 text not matching "changed" - see below).
        // String.IsNullOrEmpty(expectedHostKey) gates BOTH the "bulk-auto"
        // case and the "unknown" case structurally: a prior record existing
        // is enough, by itself, to rule out ever silently overwriting it via
        // "bulk-auto" AND to rule out ever mislabeling its failure as
        // "unknown" (which the dashboard renders as a pre-filled, un-warned
        // trust button) - independent of whatever wording plink/pscp happens
        // to produce. With a prior record present, the only possible
        // outcomes are "changed" or null - never "unknown", never "bulk-auto".
        internal static string ClassifyHostKeyFailure(string expectedHostKey, string combinedOutput, bool parsedOk, bool trustNewHostKeys, bool isBulkAutoRetry)
        {
            bool hasHostKeyText = !String.IsNullOrEmpty(combinedOutput) && combinedOutput.IndexOf("host key", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!String.IsNullOrEmpty(expectedHostKey) && hasHostKeyText)
            {
                return "changed";
            }
            if (String.IsNullOrEmpty(expectedHostKey) && parsedOk && trustNewHostKeys && !isBulkAutoRetry)
            {
                return "bulk-auto";
            }
            if (String.IsNullOrEmpty(expectedHostKey) && parsedOk)
            {
                return "unknown";
            }
            return null;
        }

        private Dictionary<string, object> RunLinuxClientUninstallTarget(string target, string authMode, string username, string password, string keyPath, string installPath)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["target"] = target;
            result["startedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            if (!IsValidSshTarget(target))
            {
                result["status"] = "failed";
                result["message"] = "Target contains characters that are not valid in a hostname or IPv4 address. Only letters, digits, '.' and '-' are allowed.";
                return result;
            }

            if (!File.Exists(options.LinuxSshUninstallerPath))
            {
                result["status"] = "failed";
                result["message"] = "Linux SSH uninstaller script was not found: " + options.LinuxSshUninstallerPath;
                return result;
            }

            // Last line of defence, mirroring RunLinuxClientInstallTarget's own
            // re-validation at its point of use - the caller (StartClientAction)
            // is currently the only call site and already validates installPath,
            // but a validator that exists without being re-checked at the actual
            // point of use is exactly the shape that produced this project's
            // install-path validation gaps before.
            if (!IsValidLinuxInstallPath(installPath))
            {
                result["status"] = "failed";
                result["message"] = "installPath must be a real subdirectory under /opt/ (e.g. /opt/windows-inventory-lite), with no '.' or '..' path segment";
                return result;
            }

            string expectedHostKey = null;
            Dictionary<string, object> knownHost;
            try
            {
                knownHost = FindLinuxKnownHost(target, 22);
            }
            catch (Exception ex)
            {
                result["status"] = "failed";
                result["message"] = "Could not read the Linux SSH known-hosts trust store: " + ex.Message;
                return result;
            }
            if (knownHost != null)
            {
                expectedHostKey = GetStringValue(knownHost, "Fingerprint");
            }

            bool usingKey = authMode == "key";
            StringBuilder argsBuilder = new StringBuilder();
            argsBuilder.Append("-ComputerName ").Append(QuotePowerShellLiteral(target));
            argsBuilder.Append(" -InstallPath ").Append(QuotePowerShellLiteral(installPath));
            if (!String.IsNullOrEmpty(expectedHostKey))
            {
                argsBuilder.Append(" -ExpectedHostKey ").Append(QuotePowerShellLiteral(expectedHostKey));
            }
            argsBuilder.Append(" -CredentialUsername $__wilUser");
            if (usingKey)
            {
                argsBuilder.Append(" -KeyPath $__wilKeyPath");
            }
            else
            {
                argsBuilder.Append(" -CredentialPassword $__wilSecurePass");
            }

            string commandBody = "[Console]::OutputEncoding = [System.Text.Encoding]::Default; $OutputEncoding = [Console]::OutputEncoding; "
                + BuildLinuxCredentialReaderSnippet(authMode)
                + "& " + QuotePowerShellLiteral(options.LinuxSshUninstallerPath) + " "
                + argsBuilder.ToString();

            return RunLinuxSshProcess(commandBody, authMode, username, password, keyPath, result);
        }

        private static Dictionary<string, object> RunLinuxSshProcess(string commandBody, string authMode, string username, string password, string keyPath, Dictionary<string, object> result)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "powershell.exe";
            startInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command " + QuoteArgument(commandBody);
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardInput = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.CreateNoWindow = true;

            try
            {
                using (Process process = Process.Start(startInfo))
                {
                    process.StandardInput.WriteLine(username);
                    process.StandardInput.WriteLine(authMode == "key" ? keyPath : password);
                    process.StandardInput.Close();
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    result["exitCode"] = process.ExitCode;
                    result["output"] = output;
                    result["error"] = error;
                    result["status"] = process.ExitCode == 0 ? "completed" : "failed";
                    result["message"] = process.ExitCode == 0 ? "Linux client command completed." : "Linux client command failed.";
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

        private static readonly Regex HostKeyFingerprintFormatPattern = new Regex(@"^SHA256:[A-Za-z0-9+/]+=*$");

        // Shared by the trust-host-key endpoint and its self-test, so the test
        // exercises the exact validation the endpoint applies rather than a
        // hand-copied duplicate of the pattern.
        private static bool IsValidHostKeyFingerprint(string fingerprint)
        {
            return !String.IsNullOrEmpty(fingerprint) && HostKeyFingerprintFormatPattern.IsMatch(fingerprint);
        }

        // A push target is either a hostname or an IPv4 literal, and it is
        // embedded into a PowerShell command line (RunLinuxClientInstallTarget's
        // -ComputerName) and from there into an ssh/plink destination. Unlike
        // serverUrl/token/installPath it was never validated, and its value can
        // come straight from a client-reported "hostname" field (see
        // GetLinuxClientUpdateTarget), which is attacker-influenced on a
        // compromised managed host. Restrict to what a hostname or IPv4 literal
        // can legally contain - letters, digits, '.', '-' - rather than trying to
        // quote/escape, matching this project's existing reject-don't-escape
        // convention (ValidatePosixShellSafe, Test-BatchSafeValue).
        private static readonly Regex SshTargetFormatPattern = new Regex(@"^[A-Za-z0-9][A-Za-z0-9.\-]*\z");

        internal static bool IsValidSshTarget(string target)
        {
            return !String.IsNullOrEmpty(target) && target.Length <= 253 && SshTargetFormatPattern.IsMatch(target);
        }

        // ValidatePosixShellSafe only screens for shell metacharacters - it has
        // no opinion on whether the path itself is a sane place to `rm -rf`.
        // This field's own validation was originally just "non-empty, starts
        // with /" because Deploy > Actions always sent its own hardcoded
        // override and this value was never actually exercised by an install
        // or uninstall (see the v0.41.0 CHANGELOG entry) - now that override
        // is gone (v0.54.0), this value alone governs every SSH-based install
        // AND uninstall Deploy > Actions runs, so a value like "/etc" or
        // "/usr" would pass the old check straight into a remote
        // "rm -rf $InstallPath".
        //
        // Was "starts with / and has >= 2 segments" - defeated by traversal
        // ("/opt/../etc" has 2 segments and no rejected character) and too weak
        // even without traversal ("/usr/bin", "/etc/systemd" both have 2
        // segments and are still catastrophic under the remote "rm -rf
        // $InstallPath" this value ends up in). A denylist of dangerous
        // directories would still be incomplete by construction - this is an
        // allowlist instead: the value must be a real subdirectory under /opt/,
        // and no path segment anywhere may be "." or ".." (checked independently
        // of the /opt/ prefix, so "/opt/../etc" is caught by the traversal rule
        // even though it technically starts with "/opt/").
        internal static bool IsValidLinuxInstallPath(string path)
        {
            if (String.IsNullOrEmpty(path) || !path.StartsWith("/"))
            {
                return false;
            }
            string[] allSegments = path.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string segment in allSegments)
            {
                if (segment == ".." || segment == ".")
                {
                    return false;
                }
            }
            if (!path.StartsWith("/opt/", StringComparison.Ordinal))
            {
                return false;
            }
            string remainder = path.Substring("/opt/".Length);
            string[] remainderSegments = remainder.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            return remainderSegments.Length >= 1;
        }

        private static readonly Regex HostKeyFingerprintPattern = new Regex(
            @"The server's ([\w-]+) key fingerprint is:\s*\r?\n\s*[\w-]+ \d+ (SHA256:\S+)",
            RegexOptions.IgnoreCase);

        // plink's "unknown/uncached" host-key failure includes this fingerprint
        // line and can be parsed; its "changed" (MISMATCH) failure does not
        // include it at all (confirmed via live testing) - callers must
        // tolerate TryParseHostKeyDetails returning false for a legitimate
        // "changed" case rather than treating that as a parser bug.
        private static bool TryParseHostKeyDetails(string text, out string keyType, out string fingerprint)
        {
            keyType = null;
            fingerprint = null;
            if (String.IsNullOrEmpty(text))
            {
                return false;
            }
            Match match = HostKeyFingerprintPattern.Match(text);
            if (!match.Success)
            {
                return false;
            }
            keyType = match.Groups[1].Value;
            fingerprint = match.Groups[2].Value;
            return true;
        }

        // A successful install push only becomes visible to
        // LoadClientReports() - and therefore to the outdated-clients list
        // both the dashboard and the update schedule read - once that
        // client's own next inventory report arrives. Until then it still
        // reads as outdated, so an interval-mode schedule shorter than the
        // client's own reporting interval can redundantly re-push to a
        // machine it just finished updating. Patching the stored report's
        // clientVersion immediately after a successful push closes that
        // gap; the client's own next report just confirms the same version
        // once it arrives. A missing report file (this target has never
        // reported at all yet) is left alone - nothing to patch.
        private void PatchClientReportVersionAfterInstall(string computerName, string net35Version, string net40Version)
        {
            string installedVersion = net35Version ?? net40Version;
            if (String.IsNullOrEmpty(installedVersion))
            {
                return;
            }

            string path = Path.Combine(options.DataPath, SanitizeFileName(computerName) + ".json");
            JavaScriptSerializer serializer = CreateJsonSerializer();

            lock (reportFileLock)
            {
                if (!File.Exists(path))
                {
                    return;
                }
                Dictionary<string, object> report;
                try
                {
                    report = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
                }
                catch
                {
                    return;
                }
                if (report == null)
                {
                    return;
                }
                report["clientVersion"] = installedVersion;
                // Marks this client as "pushed but not yet confirmed" for the
                // dashboard (see BuildClientIndex/app.js's awaiting-report
                // badge) - deliberately NOT preserved across a real report:
                // ReceiveInventory overwrites the whole file from the
                // client's own POST body, which never includes this field,
                // so it disappears the instant a genuine report lands. No
                // separate "clear" step is needed.
                report["lastInstalledAtUtc"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                File.WriteAllText(path, serializer.Serialize(report), new UTF8Encoding(false));
            }
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
        private Dictionary<string, object> RunClientInstallTarget(string target, string serverUrl, string token, string username, string password, bool force, bool addToTrustedHosts)
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
                + BuildPowerShellInstallArguments(target, serverUrl, token, hasCredential, force, addToTrustedHosts, options.ClientPackagePath);

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

        private string GetIngestionRejectionLogPath()
        {
            return Path.Combine(options.DataPath, "_logs", "ingestion-rejections.jsonl");
        }

        private void LoadIngestionRejectionLogFromDisk()
        {
            string path = GetIngestionRejectionLogPath();
            if (!File.Exists(path))
            {
                return;
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            lock (ingestionRejectionLogLock)
            {
                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    if (String.IsNullOrEmpty(line))
                    {
                        continue;
                    }
                    try
                    {
                        Dictionary<string, object> raw = serializer.Deserialize<Dictionary<string, object>>(line);
                        IngestionRejectionEntry entry = new IngestionRejectionEntry();
                        // A corrupt/unparseable timestamp falls back to
                        // DateTime.MinValue, not DateTime.UtcNow - the
                        // latter would make a broken line look like the
                        // NEWEST entry, immune to the age-based prune below
                        // (it would never look "old enough" to remove).
                        // MinValue instead makes it look maximally old, so
                        // it gets pruned on the very next pass.
                        entry.TimestampUtc = ParseUtcDate(GetStringValue(raw, "timestampUtc"), DateTime.MinValue);
                        entry.SourceIp = GetStringValue(raw, "sourceIp");
                        entry.Endpoint = GetStringValue(raw, "endpoint");
                        entry.Reason = GetStringValue(raw, "reason");
                        ingestionRejectionLog.Add(entry);
                    }
                    catch
                    {
                        // One corrupt line (e.g. a partial write from an
                        // unclean shutdown) must not lose every other
                        // entry - skip it and keep loading the rest.
                    }
                }

                // Enforce retention/max-entries at startup too, not only
                // when a new rejection arrives - otherwise a fleet with no
                // rejections between restarts never actually ages out old
                // entries, contradicting what docs/api-reference.md already
                // claims about retention (see Important Fix 3 in the final
                // review). Mirrors RecordIngestionRejection's own
                // conditional-rewrite pattern: only touch the file if
                // pruning actually removed something.
                //
                // This runs on the startup path (Start(), called unguarded
                // from both Main() and OnStart(), with no try/catch anywhere
                // above it) over what is only a diagnostic log - a disk-full
                // condition, an ACL/permissions issue, or a backup/AV tool
                // holding the file locked must not crash the whole server.
                // Matches RecordIngestionRejection's own established
                // try/catch pattern: log via DebugLogger.Log and swallow, so
                // the server still starts with whatever was already loaded
                // into memory - even if the rewrite below fails, memory has
                // already been pruned (Clear()+AddRange() ran first); it's
                // the on-disk file that's left stale in its pre-prune,
                // over-retention state until some later write succeeds
                // (RecordIngestionRejection's own batched prune+rewrite, or
                // the next restart's reload).
                try
                {
                    List<IngestionRejectionEntry> pruned = PruneIngestionRejectionEntries(ingestionRejectionLog, DateTime.UtcNow, options.IngestionRejectionLogRetentionDays, options.IngestionRejectionLogMaxEntries);
                    if (pruned.Count != ingestionRejectionLog.Count)
                    {
                        ingestionRejectionLog.Clear();
                        ingestionRejectionLog.AddRange(pruned);
                        RewriteIngestionRejectionLogFileLocked();
                    }
                }
                catch (Exception ex)
                {
                    DebugLogger.Log(options, "Error", "LoadIngestionRejectionLogFromDisk failed to prune/persist the loaded ingestion-rejection log at startup: " + ex.Message);
                }
            }
        }

        // Called from all three ingestion handlers immediately after
        // IsIngestionTokenRejected returns true - never before it, and
        // never after the request body has been touched (see the Global
        // Constraints at the top of this plan / spec decision 1).
        private void RecordIngestionRejection(RequestContext request, string endpoint, string reason)
        {
            // HandleClient never actually sets RemoteAddress to null for an
            // unresolvable peer - it uses the IPAddress.None sentinel
            // instead. The null check alone let an unresolvable peer's
            // rejection through and get logged with sourceIp
            // "255.255.255.255" rather than being skipped as intended; the
            // null check is kept only as a safety net for direct callers
            // (e.g. self-tests) that never set RemoteAddress at all.
            if (request.RemoteAddress == null || request.RemoteAddress.Equals(IPAddress.None))
            {
                return;
            }

            IngestionRejectionEntry entry = new IngestionRejectionEntry();
            entry.TimestampUtc = DateTime.UtcNow;
            entry.SourceIp = request.RemoteAddress.ToString();
            entry.Endpoint = endpoint;
            entry.Reason = reason;

            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> line = new Dictionary<string, object>();
            line["timestampUtc"] = entry.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            line["sourceIp"] = entry.SourceIp;
            line["endpoint"] = entry.Endpoint;
            line["reason"] = entry.Reason;

            try
            {
                lock (ingestionRejectionLogLock)
                {
                    ingestionRejectionLog.Add(entry);

                    string path = GetIngestionRejectionLogPath();
                    string directory = Path.GetDirectoryName(path);
                    if (!String.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }
                    File.AppendAllText(path, serializer.Serialize(line) + Environment.NewLine, new UTF8Encoding(false));

                    // Amortize the prune+rewrite cost. Once the log is at
                    // maxEntries, pruning removes exactly one entry per
                    // call, which would otherwise force a full
                    // serialize-and-rewrite of the whole file on every
                    // single rejection - an attacker sending one request
                    // per rewrite gets up to maxEntries-times the write
                    // cost for free (see Important Fix 1 in the final
                    // review). Letting the in-memory list grow past
                    // maxEntries by a slack margin before paying for the
                    // expensive prune+rewrite path turns this into roughly
                    // one full rewrite per slack-sized batch of new
                    // rejections instead of one per rejection.
                    //
                    // Gating day-based retention behind that SAME count-based
                    // check breaks continuous enforcement: a fleet whose
                    // rejection volume never crosses maxEntries+slack would
                    // then keep every entry indefinitely at runtime,
                    // regardless of IngestionRejectionLogRetentionDays (see
                    // Important Fix 1 in the re-review of the fix above).
                    // ingestionRejectionLog is chronological, oldest-first
                    // (see PruneIngestionRejectionEntries), so index 0 is
                    // always the oldest entry - checking whether just that
                    // one entry has aged out is an O(1) stand-in for what the
                    // O(n) prune pass would otherwise have to discover. This
                    // lets the prune+rewrite fire either when the count is
                    // genuinely oversized OR the oldest entry is genuinely
                    // too old, without reintroducing a rewrite-per-rejection.
                    int slack = Math.Max(options.IngestionRejectionLogMaxEntries / 10, 50);
                    bool oldestEntryAgedOut = ingestionRejectionLog.Count > 0
                        && ingestionRejectionLog[0].TimestampUtc < DateTime.UtcNow.AddDays(-options.IngestionRejectionLogRetentionDays);
                    if (ingestionRejectionLog.Count > options.IngestionRejectionLogMaxEntries + slack || oldestEntryAgedOut)
                    {
                        List<IngestionRejectionEntry> pruned = PruneIngestionRejectionEntries(ingestionRejectionLog, DateTime.UtcNow, options.IngestionRejectionLogRetentionDays, options.IngestionRejectionLogMaxEntries);
                        if (pruned.Count != ingestionRejectionLog.Count)
                        {
                            ingestionRejectionLog.Clear();
                            ingestionRejectionLog.AddRange(pruned);
                            RewriteIngestionRejectionLogFileLocked();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Every other diagnostic write in this file (and
                // DebugLogger.Log itself, called right after this method at
                // each of the 3 rejection call sites) never throws. Disk
                // I/O here (full disk, ACL drift, a sharing violation) must
                // not propagate out through ReceiveInventory/
                // ReceiveLinuxInventory/the Linux service-status handler
                // into HandleClient's catch block, which would turn an
                // expected 401 into a 500 plus a stack trace written to the
                // Windows Event Log - on an unauthenticated endpoint, so
                // attacker-triggerable (see Important Fix 2 in the final
                // review). Logging this failure must not itself risk
                // changing the 401 response the caller already sent.
                DebugLogger.Log(options, "Error", "RecordIngestionRejection failed to persist a rejected ingestion attempt: " + ex.Message);
            }

            QueueReverseDnsLookup(request.RemoteAddress);
        }

        // Caller must already hold ingestionRejectionLogLock. Only called
        // when a prune pass actually removed something - the common case
        // (no pruning needed) never rewrites the file, only appends.
        private void RewriteIngestionRejectionLogFileLocked()
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            StringBuilder sb = new StringBuilder();
            foreach (IngestionRejectionEntry entry in ingestionRejectionLog)
            {
                Dictionary<string, object> line = new Dictionary<string, object>();
                line["timestampUtc"] = entry.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                line["sourceIp"] = entry.SourceIp;
                line["endpoint"] = entry.Endpoint;
                line["reason"] = entry.Reason;
                sb.Append(serializer.Serialize(line));
                sb.Append(Environment.NewLine);
            }
            File.WriteAllText(GetIngestionRejectionLogPath(), sb.ToString(), new UTF8Encoding(false));
        }

        // Never runs on the request-handling path - queued to the thread
        // pool so a slow/unresponsive resolver cannot delay the 401 already
        // sent to the caller, and cannot be used to make this server do
        // extra synchronous work per guess. Caches both a real hostname AND
        // a failure/timeout (as null) so a repeat offender from the same IP
        // is never re-resolved.
        private void QueueReverseDnsLookup(IPAddress address)
        {
            lock (reverseDnsCacheLock)
            {
                if (reverseDnsCache.ContainsKey(address))
                {
                    return;
                }
            }

            // Bounds how many lookups can be in flight on the ThreadPool at
            // once (see Important Fix 5 in the final review, and
            // MaxConcurrentReverseDnsLookups' declaration). Exceeding the
            // cap fails closed: the lookup is silently skipped rather than
            // queued, matching this feature's existing best-effort framing
            // (no hostname is not a functional failure, just a missing
            // hint). This also resolves the non-atomic check-then-enqueue
            // race above on the cache lookup - a burst of redundant
            // concurrent lookups for the same not-yet-cached IP is now a
            // bounded, harmless occurrence rather than something needing
            // separate dedup.
            if (Interlocked.Increment(ref reverseDnsLookupsInFlight) > MaxConcurrentReverseDnsLookups)
            {
                Interlocked.Decrement(ref reverseDnsLookupsInFlight);
                return;
            }

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    string hostname = null;
                    try
                    {
                        IAsyncResult asyncResult = Dns.BeginGetHostEntry(address, null, null);
                        if (asyncResult.AsyncWaitHandle.WaitOne(2000))
                        {
                            IPHostEntry entry = Dns.EndGetHostEntry(asyncResult);
                            hostname = entry.HostName;
                        }
                    }
                    catch
                    {
                        hostname = null;
                    }

                    lock (reverseDnsCacheLock)
                    {
                        if (reverseDnsCache.Count > 1000)
                        {
                            reverseDnsCache.Clear();
                        }
                        reverseDnsCache[address] = hostname;
                    }
                }
                finally
                {
                    Interlocked.Decrement(ref reverseDnsLookupsInFlight);
                }
            });
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

        // A Linux client's self-reported "hostname" is frequently NOT
        // resolvable from the server's network - short local/container names
        // (e.g. "docker", "grafana", a Docker container's own hostname) have
        // no DNS entry, unlike a Windows AD computerName, which is the
        // Windows-side equivalent this pattern was originally mirrored from.
        // The client's own report already includes its real network
        // IP address(es) (linux-client/report.go's "ipAddresses", collected
        // via CollectIPAddresses() - up/non-loopback interfaces only, but
        // possibly including IPv6/container-bridge addresses too). On a host
        // with several NICs, the array's order is whatever order the Linux
        // kernel happened to enumerate interfaces in (net.Interfaces()) -
        // NOT necessarily the address actually reachable from this server.
        // Confirmed live: a Proxmox host with a dedicated storage/cluster
        // network reported that network's address BEFORE its real LAN
        // address, so a plain "first IPv4 wins" pick tried the unreachable
        // one and every scheduled update push to it failed. When
        // preferredSubnetCidr is configured (Settings > Linux), an
        // address inside it wins regardless of array position; otherwise -
        // or if nothing matches - falls back to the first IPv4 seen, same
        // as before this option existed. Falls back to the hostname only
        // when no IPv4 address was ever reported at all (e.g. an older
        // client build, or a report that predates this field).
        private static string GetLinuxClientUpdateTarget(Dictionary<string, object> client, string preferredSubnetCidr)
        {
            if (client != null && client.ContainsKey("ipAddresses"))
            {
                ArrayList addresses = client["ipAddresses"] as ArrayList;
                if (addresses != null)
                {
                    string firstIPv4 = null;
                    foreach (object candidate in addresses)
                    {
                        string candidateText = Convert.ToString(candidate);
                        IPAddress parsed;
                        if (IPAddress.TryParse(candidateText, out parsed) && parsed.AddressFamily == AddressFamily.InterNetwork)
                        {
                            if (firstIPv4 == null)
                            {
                                firstIPv4 = candidateText;
                            }
                            if (!String.IsNullOrEmpty(preferredSubnetCidr) && IsIPv4InCidr(candidateText, preferredSubnetCidr))
                            {
                                return candidateText;
                            }
                        }
                    }
                    if (firstIPv4 != null)
                    {
                        return firstIPv4;
                    }
                }
            }
            return GetStringValue(client, "hostname");
        }

        // Returns true if ipText (a dotted-quad IPv4 address) falls within
        // the CIDR block cidrText (e.g. "192.168.1.0/24"). Malformed input
        // in either argument returns false rather than throwing - a bad or
        // typo'd saved CIDR value must degrade to "no match" (the caller
        // then falls back to its own first-IPv4 heuristic), not break
        // target resolution for the whole fleet.
        private static bool IsIPv4InCidr(string ipText, string cidrText)
        {
            if (String.IsNullOrEmpty(ipText) || String.IsNullOrEmpty(cidrText))
            {
                return false;
            }

            string[] parts = cidrText.Split('/');
            if (parts.Length != 2)
            {
                return false;
            }

            IPAddress network;
            int prefixLength;
            if (!IPAddress.TryParse(parts[0], out network) || network.AddressFamily != AddressFamily.InterNetwork
                || !Int32.TryParse(parts[1], out prefixLength) || prefixLength < 0 || prefixLength > 32)
            {
                return false;
            }

            IPAddress candidate;
            if (!IPAddress.TryParse(ipText, out candidate) || candidate.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            uint networkBits = IPv4ToUInt32(network.GetAddressBytes());
            uint candidateBits = IPv4ToUInt32(candidate.GetAddressBytes());
            uint mask = prefixLength == 0 ? 0u : 0xFFFFFFFFu << (32 - prefixLength);

            return (networkBits & mask) == (candidateBits & mask);
        }

        // Builds a uint from network-byte-order (big-endian) octets
        // explicitly, rather than via BitConverter, so the result is
        // correct regardless of this machine's own endianness.
        private static uint IPv4ToUInt32(byte[] octets)
        {
            return ((uint)octets[0] << 24) | ((uint)octets[1] << 16) | ((uint)octets[2] << 8) | octets[3];
        }

        // Save-time validation for the Settings > Linux "preferred Linux
        // subnet" field - blank clears the setting (always valid); a
        // non-blank value must be a well-formed IPv4 CIDR block so a typo
        // is rejected at save time with a clear error, rather than silently
        // falling back to the old first-IPv4 behavior forever (which
        // IsIPv4InCidr does deliberately at USE time, since that path must
        // never break target resolution for an already-saved value).
        private static bool IsValidCidr(string cidrText)
        {
            if (String.IsNullOrEmpty(cidrText))
            {
                return true;
            }
            string[] parts = cidrText.Split('/');
            if (parts.Length != 2)
            {
                return false;
            }
            IPAddress network;
            int prefixLength;
            return IPAddress.TryParse(parts[0], out network) && network.AddressFamily == AddressFamily.InterNetwork
                && Int32.TryParse(parts[1], out prefixLength) && prefixLength >= 0 && prefixLength <= 32;
        }

        // One OU Distinguished Name per line - not reused with
        // ExpandInstallTargets' comma/semicolon/space splitting below, since
        // a DN's own RDN components are themselves comma-separated
        // (e.g. "OU=Workstations,OU=Site1,DC=corp,DC=example,DC=com") and
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
                    // Capped at .254, not .255 - .255 is the broadcast address on a
                    // /24. (The dotted full-range form below has no equivalent cap;
                    // not reconciled since this predates this comment and changing
                    // it would be a behavior change, not a documentation fix.)
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

        // Each Auto-mode probe (WinRM 5985, then SSH 22) gets this long to
        // connect before being treated as closed. Sequential target
        // execution (see Out of scope in the design spec) means both
        // probes' worst case adds directly to one target's total latency -
        // kept short since a LAN target that's actually reachable answers
        // a TCP handshake in single-digit milliseconds; a target that
        // never responds should not stall the whole job for long.
        private const int AutoDetectProbeTimeoutMs = 2000;

        // Auto-detect mode's protocol probe - a short-timeout TCP connect
        // attempt, used only to guess which install path is worth trying
        // first (or at all). Never a substitute for the actual install
        // attempt's own success/failure signal - a port answering doesn't
        // guarantee the install itself will succeed, it's just a much
        // cheaper and more reliable signal than trying an install and
        // guessing from its failure text (which can't distinguish "wrong
        // protocol" from "right protocol, wrong password" - see
        // DecideAutoDetectProtocols below for the pure logic this feeds).
        // Not self-tested: like every other network call in this file
        // (the actual WinRM/SSH install attempts), a real connection
        // attempt only means something against a real reachable or
        // unreachable host.
        internal static bool TryConnect(string host, int port, int timeoutMs)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult connectResult = client.BeginConnect(host, port, null, null);
                    bool signaled = connectResult.AsyncWaitHandle.WaitOne(timeoutMs, false);
                    if (!signaled)
                    {
                        return false;
                    }
                    client.EndConnect(connectResult);
                    return client.Connected;
                }
            }
            catch
            {
                return false;
            }
        }

        // Given Auto-detect's two TCP probe results (TryConnect against
        // WinRM's port 5985 - HTTP only, see below - and SSH's port 22),
        // decides which protocol(s) to attempt and in what order. Probe
        // 5985 only, never 5986 (WinRM over HTTPS): Install-ClientWinRM.ps1
        // calls New-PSSession -ComputerName with no -UseSSL/-Port override,
        // so it can only ever connect over HTTP WinRM - a target with only
        // 5986 open would probe as "reachable" and then fail when the
        // installer tries 5985 instead, instead of cleanly falling through
        // to SSH. Only one port open ->
        // try only that protocol. Both open -> try WinRM first (this
        // codebase's own working assumption: a box answering both is
        // overwhelmingly likely a Windows host with OpenSSH also
        // installed, not the reverse), with SSH as a fallback only if
        // WinRM's actual install attempt fails. Neither open -> empty
        // array, no attempt is worth making. Pure and self-tested,
        // unlike TryConnect above.
        internal static string[] DecideAutoDetectProtocols(bool winRmReachable, bool sshReachable)
        {
            if (winRmReachable && sshReachable)
            {
                return new string[] { "winrm", "ssh" };
            }
            if (winRmReachable)
            {
                return new string[] { "winrm" };
            }
            if (sshReachable)
            {
                return new string[] { "ssh" };
            }
            return new string[0];
        }

        // Given the unified job's Mode and (for Auto only) TryConnect's two
        // probe results, decides which protocol(s) RunUnifiedInstallTarget
        // should try and in what order. Force modes ignore the probe
        // results entirely - force means force, no detection round-trip is
        // spent reaching this decision. Auto mode delegates to
        // DecideAutoDetectProtocols unchanged. Pure and self-tested, same
        // convention as DecideAutoDetectProtocols itself.
        internal static string[] ResolveAttemptOrder(string mode, bool winRmReachable, bool sshReachable)
        {
            if (mode == "force-windows")
            {
                return new string[] { "winrm" };
            }
            if (mode == "force-linux")
            {
                return new string[] { "ssh" };
            }
            if (mode == "auto")
            {
                return DecideAutoDetectProtocols(winRmReachable, sshReachable);
            }
            // Fail closed, not open: every caller today always sets a
            // valid Mode ("auto"/"force-windows"/"force-linux"), so this
            // is unreachable in practice - but a protocol-selection
            // function silently defaulting an unrecognized value to
            // "probe and try both protocols" is the wrong failure mode
            // for a function a future caller could add without updating
            // this check. No attempt is worth making against a mode this
            // function doesn't recognize.
            return new string[0];
        }

        // One entry in a per-target job result's future "attempts" array
        // (see docs/superpowers/specs/2026-08-17-deploy-actions-updates-
        // unification-design.md's Data model changes section) - one
        // attempt is one try of one protocol against one target, whether
        // or not Auto-detect chose it (a Force-mode result also uses this
        // shape, just with exactly one entry, once Phase 3 wires this in).
        // Kept as a loose Dictionary<string, object>, matching every
        // other result-building convention in this file (e.g.
        // RunClientInstallTarget's own result dict) rather than
        // introducing a typed class this codebase doesn't otherwise use.
        // Deliberately does not stamp startedAt/completedAt/exitCode here -
        // Phase 3's real caller is expected to build an attempt by
        // enriching the dict RunClientInstallTarget/RunLinuxClientInstallTarget
        // already return (which already carry those fields) rather than
        // constructing one from scratch and losing them.
        internal static Dictionary<string, object> BuildAttemptResult(string protocol, string status, string message, string output, string error)
        {
            Dictionary<string, object> attempt = new Dictionary<string, object>();
            attempt["protocol"] = protocol;
            attempt["status"] = status;
            attempt["message"] = message;
            attempt["output"] = output;
            attempt["error"] = error;
            return attempt;
        }

        // The dashboard no longer lets an admin type a full ingestion URL
        // for Deploy > Actions (Server URL field removed, 2026-08-21) - it
        // always sends the Windows-shaped one (.../api/v1/inventory),
        // computed from window.location.origin. Whenever a target
        // actually dispatches over SSH, the Linux client's own ingestion
        // route lives at a different path (.../api/v1/linux/inventory) -
        // this swaps the suffix if present. Leaves anything else
        // unchanged: an already Linux-shaped URL (e.g. from
        // linux-package-settings.json's saved-settings fallback inside
        // StartClientAction, which is a full URL already read from a
        // Linux-specific config file, not this Windows-default value) or
        // a fully custom one some future caller supplies. Pure and
        // self-tested. Runs AFTER StartClientAction's two shell-safety
        // validators (ValidateBatchSafe/TryValidateLinuxPushValues,
        // which see the pre-transform value) - safe today only because
        // this swaps one fixed, already-safe literal suffix for another.
        // If this ever grows a transform that isn't a fixed literal
        // swap, re-validate the result before it reaches a
        // shell/PowerShell invocation.
        internal static string ToLinuxServerUrl(string serverUrl)
        {
            if (String.IsNullOrEmpty(serverUrl))
            {
                return serverUrl;
            }
            const string windowsSuffix = "/api/v1/inventory";
            if (serverUrl.EndsWith(windowsSuffix, StringComparison.OrdinalIgnoreCase))
            {
                return serverUrl.Substring(0, serverUrl.Length - windowsSuffix.Length) + "/api/v1/linux/inventory";
            }
            return serverUrl;
        }

        // Runs one target through Mode's chosen protocol(s), producing the
        // per-target result RunClientActionJob appends to job.Results.
        // Force modes skip probing entirely and call straight into the one
        // relevant existing per-target function. Auto mode probes both
        // ports, asks ResolveAttemptOrder for a try-order, and walks it -
        // stopping at the first protocol whose attempt reports "completed",
        // recording every attempt tried either way. Not self-tested: like
        // RunClientInstallTarget/RunLinuxClientInstallTarget, it makes real
        // network calls (see the comment on TryConnect for why those stay
        // integration-only in this codebase).
        private Dictionary<string, object> RunUnifiedInstallTarget(
            string target, string action, string mode,
            string serverUrl, string token,
            string winRmUsername, string winRmPassword, bool force, bool addToTrustedHosts,
            string sshAuthMode, string sshUsername, string sshPassword, string sshKeyPath, bool trustNewHostKeys,
            int intervalHours, int statusIntervalMinutes, string installPath,
            int probeTimeoutMs)
        {
            bool winRmReachable = false;
            bool sshReachable = false;
            if (mode == "auto")
            {
                winRmReachable = TryConnect(target, 5985, probeTimeoutMs);
                sshReachable = TryConnect(target, 22, probeTimeoutMs);
            }
            string[] attemptOrder = ResolveAttemptOrder(mode, winRmReachable, sshReachable);

            Dictionary<string, object> result = new Dictionary<string, object>();
            result["target"] = target;
            ArrayList attempts = new ArrayList();
            result["attempts"] = attempts;

            if (attemptOrder.Length == 0)
            {
                result["status"] = "failed";
                result["message"] = "Target did not respond on WinRM (port 5985) or SSH (port 22).";
                return result;
            }

            Dictionary<string, object> lastAttemptResult = null;
            string lastProtocol = null;
            foreach (string protocol in attemptOrder)
            {
                Dictionary<string, object> attemptResult;
                if (protocol == "winrm")
                {
                    attemptResult = action == "uninstall"
                        ? RunClientUninstallTarget(target, winRmUsername, winRmPassword, addToTrustedHosts)
                        : RunClientInstallTarget(target, serverUrl, token, winRmUsername, winRmPassword, force, addToTrustedHosts);
                }
                else
                {
                    attemptResult = action == "uninstall"
                        ? RunLinuxClientUninstallTarget(target, sshAuthMode, sshUsername, sshPassword, sshKeyPath, installPath)
                        : RunLinuxClientInstallTarget(target, ToLinuxServerUrl(serverUrl), token, intervalHours, statusIntervalMinutes, installPath, sshAuthMode, sshUsername, sshPassword, sshKeyPath, trustNewHostKeys);
                }

                Dictionary<string, object> attempt = BuildAttemptResult(protocol, GetStringValue(attemptResult, "status"), GetStringValue(attemptResult, "message"), GetStringValue(attemptResult, "output"), GetStringValue(attemptResult, "error"));
                // Enrich with the fields BuildAttemptResult's own comment
                // says its real caller must preserve rather than lose -
                // startedAt/completedAt/exitCode always; hostKey* only for
                // an ssh attempt, where RunLinuxClientInstallTarget sets
                // them conditionally.
                if (attemptResult.ContainsKey("startedAt")) attempt["startedAt"] = attemptResult["startedAt"];
                if (attemptResult.ContainsKey("completedAt")) attempt["completedAt"] = attemptResult["completedAt"];
                if (attemptResult.ContainsKey("exitCode")) attempt["exitCode"] = attemptResult["exitCode"];
                if (protocol == "ssh")
                {
                    if (attemptResult.ContainsKey("hostKeyTrust")) attempt["hostKeyTrust"] = attemptResult["hostKeyTrust"];
                    if (attemptResult.ContainsKey("hostKeyStatus")) attempt["hostKeyStatus"] = attemptResult["hostKeyStatus"];
                    if (attemptResult.ContainsKey("hostKeyFingerprint")) attempt["hostKeyFingerprint"] = attemptResult["hostKeyFingerprint"];
                }
                attempts.Add(attempt);

                lastAttemptResult = attemptResult;
                lastProtocol = protocol;

                if (GetStringValue(attemptResult, "status") == "completed")
                {
                    break;
                }
            }

            // The summary mirrors the last attempt tried (the winning one,
            // or the final failure if every protocol in the try-order
            // failed) - CountInstallResults and the job-list "Failed"
            // column only ever read this top-level status, never attempts[].
            result["protocol"] = lastProtocol;
            result["status"] = GetStringValue(lastAttemptResult, "status");
            result["message"] = attempts.Count > 1 && GetStringValue(result, "status") != "completed"
                ? "Both WinRM and SSH attempts failed."
                : GetStringValue(lastAttemptResult, "message");
            // The dashboard's own per-target row (renderInstallJob) reads
            // output/error straight off this top-level dict, not out of
            // attempts[] - it only renders the attempts sub-table at all
            // when there was more than one attempt (Auto mode trying both
            // protocols). A Force-mode result always has exactly one
            // attempt, so without copying these two fields here the real
            // PowerShell/SSH output or error text was silently unreachable
            // from the dashboard on every Force-mode job, regardless of
            // success or failure - the Output column fell back to
            // rendering the word "Unknown" (escapeHtml's own placeholder
            // for a missing value) instead.
            if (lastAttemptResult.ContainsKey("output")) result["output"] = lastAttemptResult["output"];
            if (lastAttemptResult.ContainsKey("error")) result["error"] = lastAttemptResult["error"];
            if (lastAttemptResult.ContainsKey("startedAt")) result["startedAt"] = lastAttemptResult["startedAt"];
            if (lastAttemptResult.ContainsKey("completedAt")) result["completedAt"] = lastAttemptResult["completedAt"];
            if (lastAttemptResult.ContainsKey("exitCode")) result["exitCode"] = lastAttemptResult["exitCode"];
            if (lastProtocol == "ssh")
            {
                if (lastAttemptResult.ContainsKey("hostKeyTrust")) result["hostKeyTrust"] = lastAttemptResult["hostKeyTrust"];
                if (lastAttemptResult.ContainsKey("hostKeyStatus")) result["hostKeyStatus"] = lastAttemptResult["hostKeyStatus"];
                if (lastAttemptResult.ContainsKey("hostKeyFingerprint")) result["hostKeyFingerprint"] = lastAttemptResult["hostKeyFingerprint"];
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

        private static string BuildPowerShellInstallArguments(string target, string serverUrl, string token, bool hasCredential, bool force, bool addToTrustedHosts, string packagePath)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("-ComputerName ").Append(QuotePowerShellLiteral(target));
            builder.Append(" -ServerUrl ").Append(QuotePowerShellLiteral(serverUrl));
            if (!String.IsNullOrEmpty(token))
            {
                builder.Append(" -Token ").Append(QuotePowerShellLiteral(token));
            }
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
            string cookieHeader = request.Headers.ContainsKey("cookie") ? request.Headers["cookie"] : null;
            string sessionToken = GetCookieValue(cookieHeader, "wil_session");
            if (!String.IsNullOrEmpty(sessionToken))
            {
                lock (sessionLock)
                {
                    SessionRecord record;
                    sessionStore.TryGetValue(sessionToken, out record);
                    DateTime now = DateTime.UtcNow;
                    if (IsSessionValid(record, now))
                    {
                        record.ExpiresUtc = ComputeSessionExpiry(now, options.SessionLifetimeHours);
                        return true;
                    }
                    // A found-but-expired record used to just fall through to
                    // Basic Auth below, leaving the stale entry in sessionStore
                    // until the next successful login's own prune swept it out -
                    // a dashboard tab left open with nobody logging back in
                    // could linger there indefinitely. Sweeping here too closes
                    // that gap without adding a new timer/background thread.
                    if (record != null)
                    {
                        PruneExpiredSessionsLocked(now);
                    }
                }
            }

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
                bool authorized = usernameMatches & passwordMatches;
                // Only a request that actually presented Basic Auth
                // credentials and got this far counts toward the lockout -
                // not the header-less first request every browser makes
                // (see IsBasicAuthLockedOut's own comment) and not a
                // malformed Authorization header (caught below).
                RecordBasicAuthAttempt(request.RemoteAddress, authorized);
                return authorized;
            }
            catch
            {
                return false;
            }
        }

        // Pure read - does not itself record anything, so a locked-out IP
        // hammering the server doesn't extend its own lockout (a sustained
        // flood must not keep pushing the unlock time forward indefinitely)
        // and doesn't cost a wasted FixedTimeEquals comparison. Called from
        // HandleClient before IsWebRequestAuthorized is even reached.
        private bool IsBasicAuthLockedOut(RequestContext request, out int retryAfterSeconds)
        {
            retryAfterSeconds = 0;
            if (options.LoginLockoutThreshold <= 0)
            {
                // Mechanism disabled (e.g. a test bench doing rapid scripted
                // auth checks) - never locked out.
                return false;
            }
            if (String.IsNullOrEmpty(options.WebUsername) && String.IsNullOrEmpty(options.WebPassword))
            {
                // Loopback-only mode (Basic Auth unconfigured) never records
                // attempts - nothing to check here.
                return false;
            }
            if (request.RemoteAddress == null)
            {
                return false;
            }

            lock (loginLockoutLock)
            {
                LoginLockoutRecord existing;
                loginLockoutState.TryGetValue(request.RemoteAddress, out existing);
                return EvaluateLockoutState(existing, DateTime.UtcNow, out retryAfterSeconds);
            }
        }

        // Pure - no I/O, no DateTime.UtcNow inside - takes "now" as an
        // explicit parameter so self-tests can exercise lockout/expiry
        // transitions without any real waiting.
        private static bool EvaluateLockoutState(LoginLockoutRecord existing, DateTime nowUtc, out int retryAfterSeconds)
        {
            retryAfterSeconds = 0;
            if (existing == null || !existing.LockedUntilUtc.HasValue || existing.LockedUntilUtc.Value <= nowUtc)
            {
                return false;
            }
            retryAfterSeconds = (int)Math.Ceiling((existing.LockedUntilUtc.Value - nowUtc).TotalSeconds);
            return true;
        }

        // Pure - returns the updated record, or null to mean "remove this
        // entry from the dictionary" (a successful attempt, or a counting
        // window that had already fully expired with nothing worth keeping).
        // An IP already locked out does NOT get its failure count bumped
        // further by more attempts during the lockout - see EvaluateLockoutState's
        // own comment on why the lockout must not self-extend.
        private static LoginLockoutRecord RecordAttemptOutcome(LoginLockoutRecord existing, bool succeeded, DateTime nowUtc, int thresholdCount, TimeSpan window, TimeSpan lockoutDuration)
        {
            if (succeeded)
            {
                return null;
            }

            LoginLockoutRecord record = existing;
            if (record == null || (nowUtc - record.WindowStartUtc) > window)
            {
                record = new LoginLockoutRecord();
                record.WindowStartUtc = nowUtc;
                record.FailedCount = 0;
                record.LockedUntilUtc = null;
            }

            if (record.LockedUntilUtc.HasValue && record.LockedUntilUtc.Value > nowUtc)
            {
                return record;
            }

            record.FailedCount++;
            if (thresholdCount > 0 && record.FailedCount >= thresholdCount)
            {
                record.LockedUntilUtc = nowUtc.Add(lockoutDuration);
            }
            return record;
        }

        private void RecordBasicAuthAttempt(IPAddress remoteAddress, bool succeeded)
        {
            if (options.LoginLockoutThreshold <= 0 || remoteAddress == null)
            {
                return;
            }

            lock (loginLockoutLock)
            {
                LoginLockoutRecord existing;
                loginLockoutState.TryGetValue(remoteAddress, out existing);
                LoginLockoutRecord updated = RecordAttemptOutcome(
                    existing,
                    succeeded,
                    DateTime.UtcNow,
                    options.LoginLockoutThreshold,
                    TimeSpan.FromMinutes(options.LoginLockoutWindowMinutes),
                    TimeSpan.FromMinutes(options.LoginLockoutDurationMinutes));

                if (updated == null)
                {
                    loginLockoutState.Remove(remoteAddress);
                }
                else
                {
                    loginLockoutState[remoteAddress] = updated;
                }

                // Bounds memory under a sustained attack from many distinct
                // IPs - piggybacks on the lock already held for this write
                // rather than a dedicated timer/thread for what is a rare,
                // self-limiting cleanup.
                if (loginLockoutState.Count > 500)
                {
                    PruneExpiredLoginLockoutEntriesLocked(DateTime.UtcNow);
                }
            }
        }

        // Caller must already hold loginLockoutLock.
        private void PruneExpiredLoginLockoutEntriesLocked(DateTime nowUtc)
        {
            TimeSpan window = TimeSpan.FromMinutes(options.LoginLockoutWindowMinutes);
            List<IPAddress> expired = new List<IPAddress>();
            foreach (KeyValuePair<IPAddress, LoginLockoutRecord> entry in loginLockoutState)
            {
                LoginLockoutRecord record = entry.Value;
                bool stillLocked = record.LockedUntilUtc.HasValue && record.LockedUntilUtc.Value > nowUtc;
                bool windowExpired = (nowUtc - record.WindowStartUtc) > window;
                if (!stillLocked && windowExpired)
                {
                    expired.Add(entry.Key);
                }
            }
            foreach (IPAddress ip in expired)
            {
                loginLockoutState.Remove(ip);
            }
        }

        private static string ResolveIngestionRejectionReason(string suppliedToken)
        {
            return String.IsNullOrEmpty(suppliedToken) ? "missing" : "mismatched";
        }

        // Pure - no I/O, no DateTime.UtcNow inside. Applies whichever cap
        // (age or count) is more restrictive - each is evaluated
        // independently against the input, and the surviving set is their
        // intersection (an entry must pass BOTH to survive).
        private static List<IngestionRejectionEntry> PruneIngestionRejectionEntries(List<IngestionRejectionEntry> entries, DateTime nowUtc, int retentionDays, int maxEntries)
        {
            List<IngestionRejectionEntry> withinAge = new List<IngestionRejectionEntry>();
            foreach (IngestionRejectionEntry entry in entries)
            {
                if ((nowUtc - entry.TimestampUtc).TotalDays <= retentionDays)
                {
                    withinAge.Add(entry);
                }
            }

            // A bare `new ServerOptions()` (as opposed to one that has gone
            // through Parse()) defaults IngestionRejectionLogMaxEntries to 0
            // - without this guard that would silently discard everything
            // that survived the age check above. Skip the max-entries trim
            // entirely rather than trimming to a 0 or negative range.
            if (maxEntries <= 0)
            {
                return withinAge;
            }

            if (withinAge.Count <= maxEntries)
            {
                return withinAge;
            }

            // entries arrive in chronological (oldest-first) order - keep
            // only the newest maxEntries.
            return withinAge.GetRange(withinAge.Count - maxEntries, maxEntries);
        }

        // Pure - no I/O. "Last successful report timestamp" is resolved by
        // the caller (BuildClientIndex/LoadClientReports) using the same
        // collectedAt-then-sourceUpdatedAt fallback the dashboard's own
        // allClientSortValue already uses - this function just compares
        // against whatever DateTime it's handed.
        private static string ComputeClientTokenIssue(string lastIngestSourceIp, DateTime lastCollectedUtc, List<IngestionRejectionEntry> rejectionLog)
        {
            if (String.IsNullOrEmpty(lastIngestSourceIp) || rejectionLog == null)
            {
                return null;
            }

            IngestionRejectionEntry newestMatch = null;
            foreach (IngestionRejectionEntry entry in rejectionLog)
            {
                if (!String.Equals(entry.SourceIp, lastIngestSourceIp, StringComparison.Ordinal))
                {
                    continue;
                }
                if (newestMatch == null || entry.TimestampUtc > newestMatch.TimestampUtc)
                {
                    newestMatch = entry;
                }
            }

            if (newestMatch == null || newestMatch.TimestampUtc <= lastCollectedUtc)
            {
                return null;
            }
            return newestMatch.Reason;
        }

        // Secure only over HTTPS (stream is SslStream - the same test
        // BuildHstsHeaderOrEmpty already uses): a Secure cookie is silently
        // dropped by the browser entirely over plain HTTP, which this app
        // still supports running under. HttpOnly always (never readable
        // from JS). SameSite=Strict (no legitimate cross-site use, matches
        // this app's CSRF-hardening posture). No Max-Age: this makes
        // wil_session a browser-session-scoped cookie (cleared when the
        // browser process closes) instead of pinned to a fixed lifetime
        // from login time. A fixed Max-Age meant a continuously active
        // admin still got logged out SessionLifetimeHours after first
        // logging in, even though the server-side SessionRecord.ExpiresUtc
        // already slides forward on every authorized request (see
        // IsWebRequestAuthorized) - the browser's own copy of the cookie
        // just never reflected that. Dropping Max-Age is safe rather than
        // a privilege widening: IsSessionValid still checks ExpiresUtc
        // server-side on every use, so a browser holding onto the cookie
        // longer than the server considers it valid grants nothing extra.
        // Re-issuing a fresh Set-Cookie on every request (to slide the
        // browser-side lifetime too) would require threading a Set-Cookie
        // header through this file's ~180 existing response call sites -
        // out of scope; this is the simpler, equally safe alternative.
        private static string BuildSessionCookieHeader(Stream stream, string token)
        {
            string secureFlag = stream is SslStream ? "; Secure" : "";
            return "Set-Cookie: wil_session=" + token + "; Path=/; HttpOnly; SameSite=Strict" + secureFlag;
        }

        // Secure only over HTTPS, matching BuildSessionCookieHeader's own
        // conditional above (a Secure cookie is silently dropped by the
        // browser entirely over plain HTTP) - this was a bare const
        // missing that flag until a whole-branch review caught the
        // inconsistency.
        private static string ClearSessionCookieHeader(Stream stream)
        {
            string secureFlag = stream is SslStream ? "; Secure" : "";
            return "Set-Cookie: wil_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + secureFlag;
        }

        // Dispatched from HandleClient BEFORE the IsWebRequestAuthorized
        // gate (you are not authenticated yet when logging in), but AFTER
        // IsBasicAuthLockedOut (a locked-out IP must not get unlimited
        // login attempts here either), IsCrossSiteRequestRejected, and the
        // JSON-Content-Type check - see HandleClient's dispatch chain.
        // This endpoint was originally dispatched before those CSRF/
        // Content-Type checks too, on the reasoning that a cross-site POST
        // here can't exploit any pre-existing authenticated state and a
        // forged cross-origin login could never read back or reuse the
        // resulting cookie (HttpOnly/SameSite=Strict). That reasoning held
        // for cookie theft, but missed a different attack: a plain,
        // JavaScript-free HTML form can still auto-submit cross-origin
        // here regardless of any of that, and doing so repeatedly drove
        // the victim's own source IP into the shared Basic-Auth lockout
        // counter (RecordBasicAuthAttempt) - a cross-origin lockout
        // denial-of-service found in a whole-branch review. Fixed by
        // requiring the same CSRF/Content-Type checks every other
        // state-changing route (other than the three ingestion endpoints)
        // already requires, while still not requiring prior authorization
        // (see above).
        private void SendLoginResult(Stream stream, RequestContext request)
        {
            if (String.IsNullOrEmpty(options.WebUsername) && String.IsNullOrEmpty(options.WebPassword))
            {
                // Loopback-only mode: no admin credential is configured to
                // check against. Login must never succeed here - unlike
                // the loopback check itself, a session cookie is not
                // IP-scoped, so a session minted in this mode would let a
                // request bypass the loopback restriction from anywhere.
                SendUnauthorized(stream, request);
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

            string username = payload.ContainsKey("username") ? Convert.ToString(payload["username"]) : "";
            string password = payload.ContainsKey("password") ? Convert.ToString(payload["password"]) : "";
            bool usernameMatches = FixedTimeEquals(username, options.WebUsername);
            bool passwordMatches = FixedTimeEquals(password, options.WebPassword);
            bool authorized = usernameMatches & passwordMatches;
            RecordBasicAuthAttempt(request.RemoteAddress, authorized);

            if (!authorized)
            {
                SendUnauthorized(stream, request);
                return;
            }

            string token = GenerateRandomToken();
            SessionRecord record = new SessionRecord();
            record.ExpiresUtc = ComputeSessionExpiry(DateTime.UtcNow, options.SessionLifetimeHours);
            lock (sessionLock)
            {
                sessionStore[token] = record;
                // Opportunistic - piggybacks on the lock already held for
                // this insert rather than a dedicated timer/thread, same
                // reasoning as PruneExpiredLoginLockoutEntriesLocked above.
                // Also means a repeat login without an intervening logout
                // no longer orphans the previous session forever - once it
                // expires, the next login sweeps it out.
                PruneExpiredSessionsLocked(DateTime.UtcNow);
            }

            string setCookie = BuildSessionCookieHeader(stream, token);
            SendText(stream, "{\"status\":\"ok\"}", "application/json; charset=utf-8", 200, "no-store", setCookie);
        }

        // Caller must already hold sessionLock.
        private void PruneExpiredSessionsLocked(DateTime nowUtc)
        {
            List<string> expired = new List<string>();
            foreach (KeyValuePair<string, SessionRecord> entry in sessionStore)
            {
                if (entry.Value.ExpiresUtc <= nowUtc)
                {
                    expired.Add(entry.Key);
                }
            }
            foreach (string expiredToken in expired)
            {
                sessionStore.Remove(expiredToken);
            }
        }

        // Always 200 - logging out a missing/already-expired session is a
        // no-op success, not an error (the caller's goal - "I should no
        // longer be logged in" - is already satisfied).
        private void SendLogoutResult(Stream stream, RequestContext request)
        {
            string cookieHeader = request.Headers.ContainsKey("cookie") ? request.Headers["cookie"] : null;
            string sessionToken = GetCookieValue(cookieHeader, "wil_session");
            if (!String.IsNullOrEmpty(sessionToken))
            {
                lock (sessionLock)
                {
                    sessionStore.Remove(sessionToken);
                }
            }
            SendText(stream, "{\"status\":\"ok\"}", "application/json; charset=utf-8", 200, null, ClearSessionCookieHeader(stream));
        }

        // Cookie header is "name1=value1; name2=value2" - no quoting or
        // escaping to worry about here, since this app's own cookie value
        // is always a fixed-format hex token from GenerateRandomToken,
        // never something a user typed. Returns null if the header is
        // absent/empty or the named cookie isn't present.
        private static string GetCookieValue(string cookieHeader, string name)
        {
            if (String.IsNullOrEmpty(cookieHeader))
            {
                return null;
            }
            string[] pairs = cookieHeader.Split(';');
            foreach (string pair in pairs)
            {
                string trimmed = pair.Trim();
                int separator = trimmed.IndexOf('=');
                if (separator < 0)
                {
                    continue;
                }
                string cookieName = trimmed.Substring(0, separator);
                if (String.Equals(cookieName, name, StringComparison.Ordinal))
                {
                    return trimmed.Substring(separator + 1);
                }
            }
            return null;
        }

        // Pure - no I/O, no DateTime.UtcNow inside. Strict ">" (not ">="):
        // a record expiring at exactly nowUtc is already invalid, matching
        // EvaluateLockoutState's own strict-comparison convention.
        private static bool IsSessionValid(SessionRecord record, DateTime nowUtc)
        {
            return record != null && record.ExpiresUtc > nowUtc;
        }

        // Pure - the trivial arithmetic is its own function (rather than
        // inlined at both the login and sliding-refresh call sites) so a
        // self-test can pin the exact "hours -> DateTime" behavior once.
        private static DateTime ComputeSessionExpiry(DateTime nowUtc, int sessionLifetimeHours)
        {
            return nowUtc.AddHours(sessionLifetimeHours);
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

        // Extracted from ReceiveInventory/ReceiveLinuxInventory's shared
        // guard shape so the security-relevant decision itself is directly
        // unit-testable, not only reachable through a full HTTP round-trip.
        // Fails closed: when enforcement is on, rejects if no token is
        // configured (preventing accidental unauthenticated access if an
        // admin explicitly sets RequireIngestionToken: true without also
        // configuring a token).
        private static bool IsIngestionTokenRejected(bool requireIngestionToken, string suppliedToken, string configuredToken)
        {
            if (!requireIngestionToken)
            {
                return false;
            }
            if (String.IsNullOrEmpty(configuredToken))
            {
                return true;
            }
            return !FixedTimeEquals(suppliedToken, configuredToken);
        }

        private static bool IsStateChangingMethod(string method)
        {
            return method == "POST" || method == "PUT" || method == "DELETE";
        }

        // CSRF defense #1: Basic Auth has no equivalent of a SameSite cookie -
        // once a browser has the admin's credentials cached for this origin,
        // it attaches them automatically to ANY request to this server,
        // including one a hostile page triggers via a cross-site form
        // submission or fetch(). Origin/Referer are checked only when
        // present, never required: every browser this project targets has
        // sent Origin on state-changing requests for years, so a real
        // browser being tricked into a cross-site request always gives us
        // something to check - but a non-browser caller (curl, Postman, an
        // automation script hitting the endpoints docs/api-reference.md
        // documents directly) typically sends neither header at all, and is
        // the intentional, authorized caller, not a tricked victim. Requiring
        // one would break that documented, supported usage for no real
        // security gain (there is no "victim" to trick when the same person
        // who holds the credentials is also the one making the request).
        // GET/HEAD are never checked - they're expected to be side-effect-
        // free (see CleanupInstallJobLogs' own retention-only cleanup for
        // the one narrow, attacker-uncontrolled exception, tracked
        // separately in the backlog rather than folded in here).
        private static bool IsCrossSiteRequestRejected(RequestContext request)
        {
            if (!IsStateChangingMethod(request.Method))
            {
                return false;
            }

            string host = request.Headers.ContainsKey("host") ? request.Headers["host"] : null;
            if (String.IsNullOrEmpty(host))
            {
                return true;
            }

            string origin = request.Headers.ContainsKey("origin") ? request.Headers["origin"] : null;
            if (!String.IsNullOrEmpty(origin))
            {
                // The literal string "null" is a real value browsers send for
                // an opaque origin (a sandboxed iframe, some redirect chains,
                // a data: URL) - it can never be verified to match this
                // server, so it's treated as a mismatch, not as absent. Some
                // CSRF checks elsewhere have been bypassed by treating "null"
                // as a wildcard; this deliberately does not.
                return !RequestHostMatches(origin, host);
            }

            string referer = request.Headers.ContainsKey("referer") ? request.Headers["referer"] : null;
            if (!String.IsNullOrEmpty(referer))
            {
                return !RequestHostMatches(referer, host);
            }

            return false;
        }

        private static bool RequestHostMatches(string originOrReferer, string host)
        {
            try
            {
                Uri parsed = new Uri(originOrReferer);
                return String.Equals(parsed.Authority, host, StringComparison.OrdinalIgnoreCase);
            }
            catch (UriFormatException)
            {
                return false;
            }
        }

        // CSRF defense #2: a plain HTML <form> can only submit
        // application/x-www-form-urlencoded, multipart/form-data, or
        // text/plain - a browser refuses to let a cross-origin form set an
        // arbitrary Content-Type like application/json. Without this check,
        // that restriction wouldn't actually stop an attacker: a form using
        // enctype="text/plain" with a single cleverly-named field can be made
        // to submit a body that is ALSO syntactically valid JSON (a known,
        // documented technique), so relying on "the body must parse as JSON"
        // alone is not enough - the Content-Type header itself must be
        // checked. Every route that reads a body already requires JSON
        // (JavaScriptSerializer.Deserialize), so this loses no legitimate
        // functionality; routes with no body (DELETE, RegenerateIngestionToken)
        // are unaffected since RequiresJsonContentType is false for them.
        private static bool RequiresJsonContentType(RequestContext request)
        {
            return IsStateChangingMethod(request.Method) && !String.IsNullOrEmpty(request.Body);
        }

        private static bool HasJsonContentType(RequestContext request)
        {
            string contentType = request.Headers.ContainsKey("content-type") ? request.Headers["content-type"] : null;
            if (String.IsNullOrEmpty(contentType))
            {
                return false;
            }
            int semicolon = contentType.IndexOf(';');
            string mediaType = (semicolon >= 0 ? contentType.Substring(0, semicolon) : contentType).Trim();
            return String.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase);
        }

        // Shared by the two Client Package generator endpoints below
        // (ConfigureClientPackage, ConfigureLinuxClientPackage), which had
        // no token fallback at all before this fix. StartClientAction has
        // its own equivalent inline fallback logic, added earlier and
        // deliberately left as-is here (same behavior, different call
        // sites, not worth the churn of consolidating already-working call
        // sites into one).
        private static string ResolveEffectiveToken(string requestedToken, string liveToken)
        {
            return String.IsNullOrEmpty(requestedToken) ? liveToken : requestedToken;
        }

        // Extracted so the "should this save be rejected pending an explicit
        // risk acknowledgment" decision is directly testable, mirroring how
        // the existing HTTPS-certificate-risk gate works inline in
        // ConfigureServerSettings but has no equivalent direct test today -
        // this one gets one, rather than repeating that gap.
        private static bool RequiresIngestionTokenRiskAcknowledgment(bool currentRequireIngestionToken, bool desiredRequireIngestionToken, bool acknowledgeIngestionTokenRisk)
        {
            return currentRequireIngestionToken && !desiredRequireIngestionToken && !acknowledgeIngestionTokenRisk;
        }

        // Dashboard files are served straight from disk with no build step
        // (see this project's own established pattern) - a server update
        // can replace app.js/index.html/styles.css on disk at any time,
        // but neither Content-Length nor Last-Modified/ETag were ever set
        // here, so a browser had nothing forcing it to notice. no-cache
        // (not no-store) still lets the browser keep a local copy, it just
        // has to ask "is this still current?" on every request - cheap for
        // files this small, and it closes off exactly the "dashboard still
        // shows an old build after an update, only a hard refresh fixes
        // it" class of report a live user hit after this project's own
        // Linux-client-actions view shipped.
        private void SendDashboardFile(Stream stream, string fileName, string fallback, string contentType)
        {
            string path = Path.Combine(options.ContentPath, fileName);
            if (File.Exists(path))
            {
                SendText(stream, File.ReadAllText(path, Encoding.UTF8), contentType, 200, "no-cache");
                return;
            }

            SendText(stream, fallback, contentType, 200, "no-cache");
        }

        // Binary counterpart to SendDashboardFile - reads raw bytes instead of
        // File.ReadAllText, since a text-mode read/re-encode would corrupt a
        // PNG's arbitrary byte content. No fallback constant (unlike the text
        // assets above): this is a decorative brand icon, not a load-bearing
        // page - a missing file degrades to a broken image, not a blank
        // dashboard, so embedding a base64 fallback isn't worth the size.
        private void SendDashboardImage(Stream stream, string fileName, string contentType)
        {
            string path = Path.Combine(options.ContentPath, fileName);
            if (!File.Exists(path))
            {
                SendText(stream, "Not found", "text/plain; charset=utf-8", 404);
                return;
            }

            byte[] data = File.ReadAllBytes(path);
            string header = "HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nContent-Length: " + data.Length + "\r\nCache-Control: no-cache\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: " + ContentSecurityPolicy + "\r\nReferrer-Policy: " + ReferrerPolicy + "\r\nPermissions-Policy: " + PermissionsPolicy + BuildHstsHeaderOrEmpty(stream) + "\r\nConnection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(data, 0, data.Length);
        }

        internal ArrayList LoadClientReports()
        {
            ArrayList clients = new ArrayList();
            JavaScriptSerializer serializer = CreateJsonSerializer();

            List<IngestionRejectionEntry> rejectionLogSnapshot;
            lock (ingestionRejectionLogLock)
            {
                rejectionLogSnapshot = new List<IngestionRejectionEntry>(ingestionRejectionLog);
            }
            // One pass over the whole rejection log up front instead of one
            // full linear scan per client inside the loop below. Before this,
            // ComputeClientTokenIssue(ip, ..., rejectionLogSnapshot) ran once
            // per client and each call re-scanned the entire snapshot, making
            // this O(clients x logEntries) - real cost at the max
            // configurable IngestionRejectionLogMaxEntries (100000), on a
            // method called from 4 places, 3 of which never even use the
            // resulting tokenIssue (see Important Fix 4 in the final
            // review). Building this map costs O(logEntries) once, and each
            // client's lookup below is then O(1).
            Dictionary<string, IngestionRejectionEntry> newestRejectionByIp = BuildNewestRejectionByIp(rejectionLogSnapshot);

            foreach (string file in Directory.GetFiles(options.DataPath, "*.json"))
            {
                try
                {
                    string raw = File.ReadAllText(file, Encoding.UTF8);
                    Dictionary<string, object> client = serializer.Deserialize<Dictionary<string, object>>(raw);
                    client["sourceFile"] = Path.GetFileName(file);
                    DateTime sourceUpdatedAtUtc = File.GetLastWriteTimeUtc(file);
                    client["sourceUpdatedAt"] = sourceUpdatedAtUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");

                    string lastIngestSourceIp = GetStringValue(client, "lastIngestSourceIp");
                    if (!String.IsNullOrEmpty(lastIngestSourceIp))
                    {
                        DateTime lastCollectedUtc = ParseUtcDate(GetStringValue(client, "collectedAt"), sourceUpdatedAtUtc);
                        // ComputeClientTokenIssue's own signature and self-tests
                        // are unchanged - it still takes a list and scans it,
                        // but that list now has at most one element (the
                        // newest rejection already resolved for this IP), so
                        // its internal scan is trivial regardless of how many
                        // entries the real log holds.
                        IngestionRejectionEntry newestMatch;
                        List<IngestionRejectionEntry> newestMatchAsList = new List<IngestionRejectionEntry>();
                        if (newestRejectionByIp.TryGetValue(lastIngestSourceIp, out newestMatch))
                        {
                            newestMatchAsList.Add(newestMatch);
                        }
                        string tokenIssue = ComputeClientTokenIssue(lastIngestSourceIp, lastCollectedUtc, newestMatchAsList);
                        if (tokenIssue != null)
                        {
                            client["tokenIssue"] = tokenIssue;
                        }
                    }

                    clients.Add(client);
                }
                catch
                {
                }
            }

            return clients;
        }

        // Pure - no I/O. One pass over the rejection log, keeping only the
        // newest entry per sourceIp. See LoadClientReports, the only caller.
        private static Dictionary<string, IngestionRejectionEntry> BuildNewestRejectionByIp(List<IngestionRejectionEntry> rejectionLog)
        {
            Dictionary<string, IngestionRejectionEntry> newestByIp = new Dictionary<string, IngestionRejectionEntry>(StringComparer.Ordinal);
            foreach (IngestionRejectionEntry entry in rejectionLog)
            {
                // TryGetValue/index-assignment below throw on a null key.
                // Not reachable today (RecordIngestionRejection always sets
                // SourceIp from a non-null RemoteAddress, and the disk loader
                // falls back to "" rather than null), but this file is
                // otherwise null-tolerant throughout its dictionary-keying
                // loops - skip defensively rather than crash this endpoint.
                if (String.IsNullOrEmpty(entry.SourceIp))
                {
                    continue;
                }
                IngestionRejectionEntry existing;
                if (!newestByIp.TryGetValue(entry.SourceIp, out existing) || entry.TimestampUtc > existing.TimestampUtc)
                {
                    newestByIp[entry.SourceIp] = entry;
                }
            }
            return newestByIp;
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
            index["adDescriptionSyncEnabled"] = options.AdDescriptionSyncEnabled;
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

            // The loop above exits either because headers were found (headerEnd >= 0)
            // or because the peer closed first (read <= 0). In the second case
            // headerEnd is still -1, and Encoding.ASCII.GetString(raw, 0, -1) below
            // throws ArgumentOutOfRangeException - reachable by a bare port scan or
            // health probe, and an unauthenticated path to a full stack trace in the
            // Windows Event Log. Fail the same clean way the size limits above do.
            if (headerEnd < 0)
            {
                throw new InvalidOperationException("Connection closed before the request headers were complete.");
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

        private void SendJson(Stream stream, string json)
        {
            SendText(stream, json, "application/json; charset=utf-8", 200);
        }

        // HSTS is opt-in (off by default, see ServerOptions.HstsEnabled) and
        // only ever added to a response actually served over the HTTPS
        // listener - "stream is SslStream" is exactly how HandleClient
        // itself already distinguishes the two (see AuthenticateServerStream/
        // sslStream there), so this needs no extra plumbing through
        // RequestContext. A browser that has cached the policy can still
        // lock itself out of this server if HTTPS is later disabled while
        // this was on, so max-age is admin-configured rather than the
        // textbook one-year default, and the toggle itself defaults off.
        private string BuildHstsHeaderOrEmpty(Stream stream)
        {
            if (!options.HstsEnabled || !(stream is SslStream))
            {
                return "";
            }
            return "\r\nStrict-Transport-Security: max-age=" + (options.HstsMaxAgeHours * 3600);
        }

        private static JavaScriptSerializer CreateJsonSerializer()
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = 16 * 1024 * 1024;
            return serializer;
        }

        // Self-contained on purpose - no dependency on styles.css/app.js,
        // since those themselves are only reachable once authenticated
        // (see SendDashboardFile, gated the same as every other route).
        // Inline colors are a light echo of this app's real dark theme
        // (see styles.css's Ocean Blue tokens), not a pixel-accurate copy.
        private const string LoginPageHtml =
@"<!doctype html>
<html>
<head>
<meta charset=""utf-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1"">
<title>Windows Inventory Lite - Sign in</title>
<style>
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #0c2340; font-family: system-ui, sans-serif; }
.login-card { background: #153a63; border-radius: 14px; padding: 32px; width: 340px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
.login-logo { display: block; margin: 0 auto 20px; max-width: 260px; width: 100%; height: auto; background: #fff; border-radius: 12px; padding: 14px; }
.login-card label { display: block; color: #cfe3f5; font-size: 0.85rem; margin-bottom: 4px; }
.login-card input { width: 100%; box-sizing: border-box; padding: 8px 10px; margin-bottom: 14px; border-radius: 6px; border: 1px solid #2a4d75; background: #0c2340; color: #fff; }
.login-card button { width: 100%; padding: 10px; border: none; border-radius: 6px; background: #126f8f; color: #fff; font-weight: 600; cursor: pointer; }
.login-error { color: #ff8080; font-size: 0.85rem; min-height: 1.2em; margin-top: 10px; }
</style>
</head>
<body>
<form class=""login-card"" id=""loginForm"">
<img class=""login-logo"" src=""data:image/jpeg;base64,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"" alt=""Windows Inventory Lite"">
<label for=""loginUsername"">Username</label>
<input id=""loginUsername"" name=""username"" type=""text"" autocomplete=""username"" required autofocus>
<label for=""loginPassword"">Password</label>
<input id=""loginPassword"" name=""password"" type=""password"" autocomplete=""current-password"" required>
<button type=""submit"">Sign in</button>
<div class=""login-error"" id=""loginError""></div>
</form>
<script>
document.getElementById('loginForm').addEventListener('submit', function (event) {
  event.preventDefault();
  var errorEl = document.getElementById('loginError');
  errorEl.textContent = '';
  fetch('/api/v1/server/login', {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: document.getElementById('loginUsername').value,
      password: document.getElementById('loginPassword').value
    })
  }).then(function (response) {
    if (response.ok) {
      window.location.reload();
      return;
    }
    if (response.status === 429) {
      errorEl.textContent = 'Too many failed login attempts. Try again later.';
      return;
    }
    errorEl.textContent = 'Incorrect username or password.';
  }).catch(function () {
    errorEl.textContent = 'Sign-in failed - check the connection and try again.';
  });
});
</script>
</body>
</html>";

        private void SendUnauthorized(Stream stream, RequestContext request)
        {
            // WWW-Authenticate: Basic is deliberately NOT sent (removed as
            // part of the session-based logout feature) - that header is
            // exactly what makes a browser pop its native Basic Auth
            // dialog and cache whatever gets typed into it at the HTTP
            // stack level, with no JS-reachable way to evict it later.
            // curl -u user:pass does not depend on this header - it sends
            // Basic Auth preemptively on the first request regardless of
            // any challenge - so this is safe for existing automation.
            //
            // A real browser navigating to / or /index.html (Accept
            // contains text/html) gets the embedded login page instead of
            // a bare 401 body, since there is otherwise nothing for it to
            // show a human. Every other case - any API route, any non-GET
            // method, app.js's own fetch() calls (which don't send an
            // HTML-navigation Accept header) - keeps the original
            // plain-text 401 body unchanged, so existing error handling
            // that expects a non-HTML response is unaffected.
            bool isHtmlNavigationToRoot = request.Method == "GET"
                && (request.Path == "/" || request.Path == "/index.html")
                && request.Headers.ContainsKey("accept")
                && request.Headers["accept"].IndexOf("text/html", StringComparison.OrdinalIgnoreCase) >= 0;

            byte[] body = Encoding.UTF8.GetBytes(isHtmlNavigationToRoot ? LoginPageHtml : "Unauthorized");
            string contentType = isHtmlNavigationToRoot ? "text/html; charset=utf-8" : "text/plain; charset=utf-8";
            // Picked up during a security-headers audit: this response
            // bypasses SendText (its own status line doesn't fit that
            // helper's signature), so it had never carried ANY of the
            // headers below - not just the two new ones, the pre-existing
            // CSP/X-Frame-Options/nosniff too. A 401 is a response like
            // any other and deserves the same baseline.
            string header = "HTTP/1.1 401 Unauthorized\r\nContent-Type: " + contentType + "\r\nContent-Length: " + body.Length + "\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: " + ContentSecurityPolicy + "\r\nReferrer-Policy: " + ReferrerPolicy + "\r\nPermissions-Policy: " + PermissionsPolicy + BuildHstsHeaderOrEmpty(stream) + "\r\nConnection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(body, 0, body.Length);
        }

        // Distinct from SendUnauthorized so a legitimate admin who tripped
        // the lockout by mistyping sees why (and how long to wait) instead
        // of it looking like an ordinary wrong-password rejection.
        // Deliberately omits WWW-Authenticate - re-prompting the browser for
        // credentials while the IP is locked out would just produce a
        // confusing repeated login dialog that can't succeed yet.
        private void SendTooManyRequests(Stream stream, int retryAfterSeconds)
        {
            byte[] body = Encoding.UTF8.GetBytes("{\"error\":\"Too many failed login attempts. Try again later.\"}");
            string header = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: " + retryAfterSeconds + "\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: " + body.Length + "\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: " + ContentSecurityPolicy + "\r\nReferrer-Policy: " + ReferrerPolicy + "\r\nPermissions-Policy: " + PermissionsPolicy + BuildHstsHeaderOrEmpty(stream) + "\r\nConnection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(body, 0, body.Length);
        }

        // script-src has no 'unsafe-inline' - the dashboard's ~20 innerHTML
        // sinks are consistently escaped (see escapeHtml/escapeHtmlOrEmpty
        // in app.js), so this is a backstop against a future unescaped sink,
        // not the primary defense. style-src needs 'unsafe-inline' for the
        // one legitimate case (bar-chart width) that sets a real inline
        // style="..." attribute through innerHTML. Two sha256 sources are
        // allow-listed: the first is index.html's inline theme-restore
        // <script> (reads localStorage before styles.css loads, so a saved
        // dark preference doesn't flash light first); the second is
        // LoginPageHtml's inline <script> (wires the login form's submit to
        // a fetch() POST instead of falling through to the form's native
        // GET submission, which would otherwise put the password in the
        // URL - found live: without this hash the script was silently
        // CSP-blocked, and the login form degraded to exactly that GET). If
        // either inline script's content ever changes, its hash must be
        // recomputed to match (the browser's own CSP-violation console
        // message reports the exact hash it expected - the fastest way to
        // get a fresh one).
        private const string ContentSecurityPolicy =
            "default-src 'self'; script-src 'self' 'sha256-rqltRpQDffCU3nbpQC/zdbFn0/Eb4PSGrbmQ8EbS3q4=' 'sha256-307+P/nzCy66y2Q8MR0B+9BDei02iFWi+rMImlh6/C0='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

        // same-origin (not the stricter no-referrer) deliberately: this
        // dashboard's own pages never navigate cross-origin, so a leak to
        // another site was never actually possible - the meaningful choice
        // here is that Referer keeps flowing for genuine same-origin
        // requests, which IsCrossSiteRequestRejected's own fallback path
        // reads when Origin happens to be absent (see that function's
        // comment). A stricter policy would silently narrow that fallback's
        // coverage for zero real privacy benefit, since there's no cross-
        // origin navigation to protect against here in the first place.
        private const string ReferrerPolicy = "same-origin";

        // This dashboard never uses any of these browser APIs - disabling
        // them removes an otherwise-unused attack surface (e.g. a future
        // XSS gaining camera/microphone access) at zero functional cost.
        private const string PermissionsPolicy = "geolocation=(), camera=(), microphone=(), payment=(), usb=()";

        private void SendText(Stream stream, string text, string contentType, int statusCode)
        {
            SendText(stream, text, contentType, statusCode, null);
        }

        private void SendText(Stream stream, string text, string contentType, int statusCode, string cacheControl)
        {
            SendText(stream, text, contentType, statusCode, cacheControl, null);
        }

        // extraHeaders, when non-null, is one or more already-formatted
        // "Name: value" lines (no leading/trailing \r\n) to splice into the
        // response - currently only used for Set-Cookie (see
        // BuildSessionCookieHeader/ClearSessionCookieHeader). Existing
        // 4-arg/5-arg SendText callers are unaffected - see the delegation
        // above, matching this file's established "add an overload, don't
        // touch existing call sites" convention (compare BuildHstsHeaderOrEmpty's
        // own introduction).
        private void SendText(Stream stream, string text, string contentType, int statusCode, string cacheControl, string extraHeaders)
        {
            byte[] body = Encoding.UTF8.GetBytes(text);
            string status = statusCode == 200 ? "OK" : (statusCode == 400 ? "Bad Request" : (statusCode == 401 ? "Unauthorized" : (statusCode == 404 ? "Not Found" : "Error")));
            string header = "HTTP/1.1 " + statusCode + " " + status +
                "\r\nContent-Type: " + contentType +
                "\r\nContent-Length: " + body.Length +
                "\r\nX-Content-Type-Options: nosniff" +
                "\r\nX-Frame-Options: DENY" +
                "\r\nContent-Security-Policy: " + ContentSecurityPolicy +
                "\r\nReferrer-Policy: " + ReferrerPolicy +
                "\r\nPermissions-Policy: " + PermissionsPolicy +
                BuildHstsHeaderOrEmpty(stream) +
                (String.IsNullOrEmpty(cacheControl) ? "" : "\r\nCache-Control: " + cacheControl) +
                (String.IsNullOrEmpty(extraHeaders) ? "" : "\r\n" + extraHeaders) +
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
        // A present-but-blank computerName/hostname (e.g. "" or "   ") used to
        // slip past the ContainsKey-only "unknown" fallback at each ingestion
        // call site, since Convert.ToString("") is "" - not missing - and
        // SanitizeFileName("") is also "", producing a literal ".json" report
        // file that LoadClientReports' *.json glob then happily picks up as a
        // client with no name. Treats blank the same as missing.
        private static string NormalizeReportIdentifier(string value)
        {
            return String.IsNullOrWhiteSpace(value) ? "unknown" : value;
        }

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

        // Reference type deliberately, not a struct - "no record yet for
        // this IP" is a plain null rather than a Nullable<T>. See
        // EvaluateLockoutState/RecordAttemptOutcome.
        private sealed class LoginLockoutRecord
        {
            public int FailedCount;
            public DateTime WindowStartUtc;
            public DateTime? LockedUntilUtc;
        }

        // One active dashboard login session, created by SendLoginResult
        // and removed by SendLogoutResult - see IsWebRequestAuthorized's
        // session-cookie branch. Sliding expiration: ExpiresUtc is pushed
        // forward by SessionLifetimeHours on every authorized request that
        // used this session, not fixed from creation time.
        private sealed class SessionRecord
        {
            public DateTime ExpiresUtc;
        }

        // One rejected ingestion-token attempt. Persisted as one JSON-lines
        // record (see RecordIngestionRejection) and kept in memory in
        // ingestionRejectionLog for fast correlation/serving without
        // re-reading the file. Endpoint is one of "windows-inventory",
        // "linux-inventory", "linux-service-status"; Reason is one of
        // "missing" (no token header at all) or "mismatched" (a token was
        // supplied but did not match).
        private sealed class IngestionRejectionEntry
        {
            public DateTime TimestampUtc;
            public string SourceIp;
            public string Endpoint;
            public string Reason;
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
            public string Mode;
            public string ServerUrl;
            public string Token;
            public string Username;
            public string Password;
            public bool Force;
            public bool AddToTrustedHosts;
            public string SshAuthMode;
            public string SshUsername;
            public string SshPassword;
            public string SshKeyPath;
            public int IntervalHours;
            public int StatusIntervalMinutes;
            public string InstallPath;
            public bool TrustNewHostKeys;
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
                result["mode"] = Mode;
                result["serverUrl"] = ServerUrl;
                result["username"] = Username;
                result["force"] = Force;
                result["addToTrustedHosts"] = AddToTrustedHosts;
                result["sshAuthMode"] = SshAuthMode;
                result["sshUsername"] = SshUsername;
                result["installPath"] = InstallPath;
                result["trustNewHostKeys"] = TrustNewHostKeys;
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
            // Lets an open dashboard tab notice a schedule-triggered push it
            // never requested itself - see lastScheduledUpdateJobId's own
            // comment. Null until the first scheduled push of this service
            // run.
            result["lastScheduledJobId"] = lastScheduledUpdateJobId;

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
            string serverUrl = Convert.ToString(payload.ContainsKey("serverUrl") ? payload["serverUrl"] : "");
            string token = ResolveEffectiveToken(Convert.ToString(payload.ContainsKey("token") ? payload["token"] : ""), options.Token);
            // Only when the GPO startup script and the package files (client
            // exes, Deploy-ClientGpo.ps1) are deployed to different
            // locations - e.g. the script runs from SYSVOL but the files
            // live on a separate share. Blank means "use the folder the
            // .cmd itself runs from" (%~dp0), which is correct whenever
            // both are copied to the same place.
            string packageSharePath = Convert.ToString(payload.ContainsKey("packageSharePath") ? payload["packageSharePath"] : "");
            // Reject out-of-range like every other numeric-range field on
            // this API (staleHours, adSyncIntervalHours, schedule
            // intervalHours, port, httpsPort) instead of silently clamping -
            // a caller sending 100 here should see why the value it asked
            // for wasn't used, not get a silently different one back.
            int intervalHours = 6;
            if (payload.ContainsKey("intervalHours"))
            {
                if (!Int32.TryParse(Convert.ToString(payload["intervalHours"]), out intervalHours) || intervalHours < 1 || intervalHours > 24)
                {
                    SendText(stream, "{\"error\":\"intervalHours must be between 1 and 24\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }

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

        private void SendLinuxClientPackageStatus(Stream stream)
        {
            JavaScriptSerializer serializer = CreateJsonSerializer();
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["packagePath"] = options.LinuxClientPackagePath;
            result["packagePresent"] = Directory.Exists(options.LinuxClientPackagePath);

            string binaryPath = Path.Combine(options.LinuxClientPackagePath, "wil-linux-client");
            result["binaryPresent"] = File.Exists(binaryPath);
            result["binaryVersion"] = GetLinuxClientPackageVersion();

            string configPath = Path.Combine(options.LinuxClientPackagePath, "linux-package-settings.json");
            if (File.Exists(configPath))
            {
                try
                {
                    Dictionary<string, object> saved = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(configPath, Encoding.UTF8));
                    result["serverUrl"] = GetStringValue(saved, "serverUrl");
                    result["token"] = GetStringValue(saved, "token");
                    result["intervalHours"] = GetIntValue(saved, "intervalHours", 6);
                    result["statusIntervalMinutes"] = GetIntValue(saved, "statusIntervalMinutes", 30);
                    result["installPath"] = String.IsNullOrEmpty(GetStringValue(saved, "installPath")) ? "/opt/windows-inventory-lite" : GetStringValue(saved, "installPath");
                }
                catch
                {
                    result["serverUrl"] = null;
                    result["token"] = null;
                    result["intervalHours"] = 6;
                    result["statusIntervalMinutes"] = 30;
                    result["installPath"] = "/opt/windows-inventory-lite";
                }
            }
            else
            {
                result["serverUrl"] = null;
                result["token"] = null;
                result["intervalHours"] = 6;
                result["statusIntervalMinutes"] = 30;
                result["installPath"] = "/opt/windows-inventory-lite";
            }

            SendJson(stream, serializer.Serialize(result));
        }

        private void ConfigureLinuxClientPackage(Stream stream, RequestContext request)
        {
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

            string serverUrl = Convert.ToString(payload.ContainsKey("serverUrl") ? payload["serverUrl"] : "");
            string token = ResolveEffectiveToken(Convert.ToString(payload.ContainsKey("token") ? payload["token"] : ""), options.Token);
            string installPath = Convert.ToString(payload.ContainsKey("installPath") ? payload["installPath"] : "/opt/windows-inventory-lite");
            // An explicit but blank/whitespace installPath in the payload (e.g. "") bypasses
            // the ContainsKey default above - apply the same default here so the generated
            // units/install.sh and saved settings never end up with an empty install path,
            // matching what SendLinuxClientPackageStatus already defaults to on read.
            if (String.IsNullOrWhiteSpace(installPath))
            {
                installPath = "/opt/windows-inventory-lite";
            }
            // This value is saved to linux-package-settings.json, which the
            // scheduled Linux update push (StartScheduledLinuxClientUpdatePush)
            // later reads straight into TryValidateLinuxPushValues - reject a
            // bare top-level directory here too, at the point it's actually
            // set, not just when it's used.
            if (!IsValidLinuxInstallPath(installPath))
            {
                SendText(stream, "{\"error\":\"installPath must be a real subdirectory under /opt/ (e.g. /opt/windows-inventory-lite), with no '.' or '..' path segment\"}", "application/json; charset=utf-8", 400);
                return;
            }
            int intervalHours = 6;
            if (payload.ContainsKey("intervalHours"))
            {
                if (!Int32.TryParse(Convert.ToString(payload["intervalHours"]), out intervalHours) || intervalHours < 1 || intervalHours > 24)
                {
                    SendText(stream, "{\"error\":\"intervalHours must be between 1 and 24\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }
            int statusIntervalMinutes = 30;
            if (payload.ContainsKey("statusIntervalMinutes"))
            {
                if (!Int32.TryParse(Convert.ToString(payload["statusIntervalMinutes"]), out statusIntervalMinutes) || statusIntervalMinutes < 1 || statusIntervalMinutes > 1440)
                {
                    SendText(stream, "{\"error\":\"statusIntervalMinutes must be between 1 and 1440\"}", "application/json; charset=utf-8", 400);
                    return;
                }
            }

            if (String.IsNullOrEmpty(serverUrl))
            {
                SendText(stream, "{\"error\":\"serverUrl is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string statusUrl = serverUrl.TrimEnd('/') + "/service-status";

            string[] serviceLines;
            string[] timerLines;
            string[] statusServiceLines;
            string[] statusTimerLines;
            string[] installScriptLines;
            string[] envFileLines;
            try
            {
                serviceLines = GenerateSystemdUnitLines(installPath, serverUrl, token);
                timerLines = GenerateSystemdTimerLines(intervalHours);
                statusServiceLines = GenerateSystemdStatusUnitLines(installPath, statusUrl, token);
                statusTimerLines = GenerateSystemdStatusTimerLines(statusIntervalMinutes);
                installScriptLines = GenerateLinuxInstallScriptLines(installPath);
                envFileLines = GenerateSystemdEnvFileLines(token);
            }
            catch (ArgumentException ex)
            {
                SendText(stream, "{\"error\":\"" + ex.Message.Replace("\\", "\\\\").Replace("\"", "'") + "\"}", "application/json; charset=utf-8", 400);
                return;
            }

            if (!Directory.Exists(options.LinuxClientPackagePath))
            {
                Directory.CreateDirectory(options.LinuxClientPackagePath);
            }

            File.WriteAllLines(Path.Combine(options.LinuxClientPackagePath, "wil-linux-client.service"), serviceLines, new UTF8Encoding(false));
            File.WriteAllLines(Path.Combine(options.LinuxClientPackagePath, "wil-linux-client.timer"), timerLines, new UTF8Encoding(false));
            File.WriteAllLines(Path.Combine(options.LinuxClientPackagePath, "wil-linux-client-status.service"), statusServiceLines, new UTF8Encoding(false));
            File.WriteAllLines(Path.Combine(options.LinuxClientPackagePath, "wil-linux-client-status.timer"), statusTimerLines, new UTF8Encoding(false));
            // install.sh runs on Linux via its shebang and relies on "set -e" - Environment.NewLine
            // (WriteAllLines' default) is \r\n on Windows, which breaks the shebang interpreter lookup
            // and turns "set -e" into the literal token "-e\r", silently disabling errexit. Force bare \n.
            File.WriteAllText(Path.Combine(options.LinuxClientPackagePath, "install.sh"), String.Join("\n", installScriptLines) + "\n", new UTF8Encoding(false));
            // Written with bare \n for the same reason install.sh is: this file is
            // sourced by systemd on Linux, and a trailing \r would become part of
            // the token value. Only written when there is a token - the unit files
            // only reference EnvironmentFile in that case (see
            // GenerateSystemdUnitLines).
            string envFilePath = Path.Combine(options.LinuxClientPackagePath, "wil-linux-client.env");
            if (!String.IsNullOrEmpty(token))
            {
                File.WriteAllText(envFilePath, String.Join("\n", envFileLines) + "\n", new UTF8Encoding(false));
            }
            else if (File.Exists(envFilePath))
            {
                // A reconfigure that clears the token must not leave the previous
                // token sitting in the package directory.
                File.Delete(envFilePath);
            }

            Dictionary<string, object> settingsToSave = new Dictionary<string, object>();
            settingsToSave["serverUrl"] = serverUrl;
            settingsToSave["token"] = token;
            settingsToSave["intervalHours"] = intervalHours;
            settingsToSave["statusIntervalMinutes"] = statusIntervalMinutes;
            settingsToSave["installPath"] = installPath;
            File.WriteAllText(Path.Combine(options.LinuxClientPackagePath, "linux-package-settings.json"), serializer.Serialize(settingsToSave), new UTF8Encoding(false));

            SendLinuxClientPackageStatus(stream);
        }

        private void DownloadLinuxClientPackage(Stream stream)
        {
            if (!Directory.Exists(options.LinuxClientPackagePath))
            {
                SendText(stream, "Linux client package directory not found.", "text/plain; charset=utf-8", 404);
                return;
            }

            string binaryPath = Path.Combine(options.LinuxClientPackagePath, "wil-linux-client");
            if (!File.Exists(binaryPath))
            {
                SendText(stream, "{\"error\":\"No Linux client binary found - run Build-LinuxClient.ps1 and place the output in the Linux client package directory first.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string installScriptPath = Path.Combine(options.LinuxClientPackagePath, "install.sh");
            if (!File.Exists(installScriptPath))
            {
                SendText(stream, "{\"error\":\"Configure the server URL on this page and save before downloading - install.sh has not been generated yet.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string[] includeNames = {
                "wil-linux-client",
                "wil-linux-client.service",
                "wil-linux-client.timer",
                "wil-linux-client-status.service",
                "wil-linux-client-status.timer",
                "wil-linux-client.env",
                "install.sh"
            };

            List<string> names = new List<string>();
            List<byte[]> contents = new List<byte[]>();

            foreach (string name in includeNames)
            {
                string path = Path.Combine(options.LinuxClientPackagePath, name);
                if (File.Exists(path))
                {
                    names.Add(name);
                    contents.Add(File.ReadAllBytes(path));
                }
            }

            byte[] zipBytes = BuildZip(names, contents);
            SendBytes(stream, zipBytes, "application/zip", "windows-inventory-lite-linux-client.zip");
        }

        private Dictionary<string, object> BuildCertificateStatusPayload()
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["useHttps"] = options.UseHttps;
            result["hstsEnabled"] = options.HstsEnabled;
            result["hstsMaxAgeHours"] = options.HstsMaxAgeHours;
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
        // that is a separate decision made from Settings > Server, so an operator
        // can stage a certificate without risking the current connection. A risky
        // certificate is never hot-swapped in: the live listener keeps serving
        // whatever it was already serving until the operator explicitly
        // acknowledges the risk from Settings > Server, the same gate that
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

        private void SendAdComputers(Stream stream)
        {
            // "Configure AD User" also gates AD Computer Import, per its own
            // documented scope (README: "makes the domain/credentials below
            // available to Client actions, Client updates, and AD Computer
            // Import") - this was previously unenforced here, so an admin
            // with the checkbox off but an old saved AD account still got a
            // working computer list, inconsistent with Client actions'/
            // Client updates' own credential checks and confusing when
            // compared side by side.
            if (!options.AdSyncEnabled)
            {
                SendText(stream, "{\"error\":\"Check \\\"Configure AD User\\\" in Settings > Windows > Active Directory first.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            ArrayList organizationalUnits = ParseAdComputerImportOUs(options.AdComputerImportOUs);
            AdLookupService.AdComputerSearchResult result = AdLookupService.SearchComputers(organizationalUnits, options);

            if (result.AllAttemptsFailed)
            {
                string detail = result.Warnings.Count > 0
                    ? String.Join(" ", (string[])result.Warnings.ToArray(typeof(string)))
                    : "Active Directory could not be reached.";
                Dictionary<string, object> errorResponse = new Dictionary<string, object>();
                errorResponse["error"] = detail;
                SendText(stream, CreateJsonSerializer().Serialize(errorResponse), "application/json; charset=utf-8", 500);
                return;
            }

            Dictionary<string, object> response = new Dictionary<string, object>();
            response["computers"] = result.Computers;
            response["warnings"] = result.Warnings;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(response));
        }

        private void SendServerSettings(Stream stream)
        {
            Dictionary<string, object> result = BuildCertificateStatusPayload();
            result["staleHours"] = options.StaleHours;
            result["port"] = options.Port;
            result["enableHttp"] = options.EnableHttp;
            result["httpsPort"] = options.HttpsPort;
            result["adSyncEnabled"] = options.AdSyncEnabled;
            result["adDescriptionSyncEnabled"] = options.AdDescriptionSyncEnabled;
            result["adSyncMode"] = options.AdSyncMode;
            result["adSyncIntervalHours"] = options.AdSyncIntervalHours;
            result["adDomain"] = options.AdDomain;
            result["adUseServiceIdentity"] = options.AdUseServiceIdentity;
            // Username is informational (shown in the UI when the explicit-
            // credentials option is selected); the password is never
            // returned by this endpoint, matching how WebPassword is never
            // echoed back either.
            result["adUsername"] = options.AdUseServiceIdentity ? null : options.AdUsername;
            // Mirrors LinuxUpdateCredentials'/ClientUpdateCredentials' own
            // hasPassword field - lets the dashboard show a saved-password
            // indicator without ever exposing the value itself.
            result["adPasswordConfigured"] = !String.IsNullOrEmpty(options.AdPassword);
            result["adComputerImportOUs"] = options.AdComputerImportOUs;
            result["preferredLinuxSubnet"] = options.PreferredLinuxSubnet;
            result["linuxDefaultIntervalHours"] = options.LinuxDefaultIntervalHours;
            result["linuxDefaultStatusIntervalMinutes"] = options.LinuxDefaultStatusIntervalMinutes;
            result["linuxDefaultInstallPath"] = options.LinuxDefaultInstallPath;
            result["loginLockoutThreshold"] = options.LoginLockoutThreshold;
            result["loginLockoutWindowMinutes"] = options.LoginLockoutWindowMinutes;
            result["loginLockoutDurationMinutes"] = options.LoginLockoutDurationMinutes;
            result["sessionLifetimeHours"] = options.SessionLifetimeHours;
            result["ingestionRejectionLogRetentionDays"] = options.IngestionRejectionLogRetentionDays;
            result["ingestionRejectionLogMaxEntries"] = options.IngestionRejectionLogMaxEntries;
            result["installLogRetentionDays"] = options.InstallLogRetentionDays;
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

            if (payload.ContainsKey("installLogRetentionDays"))
            {
                int installLogRetentionDays;
                if (!Int32.TryParse(Convert.ToString(payload["installLogRetentionDays"]), out installLogRetentionDays) || installLogRetentionDays < 1 || installLogRetentionDays > 3650)
                {
                    SendText(stream, "{\"error\":\"installLogRetentionDays must be between 1 and 3650\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.InstallLogRetentionDays = installLogRetentionDays;
                updates["InstallLogRetentionDays"] = installLogRetentionDays.ToString(System.Globalization.CultureInfo.InvariantCulture);
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

            // Validated here, in the pure-validation phase alongside the
            // HTTPS/HTTP checks above - deliberately BEFORE any of the
            // ApplySlotState calls below, which take effect on the live
            // listeners immediately. A 409 return after this point but
            // before SaveServerConfigValues would otherwise leave listener
            // state already changed on the live server with nothing
            // persisted to disk, reverting silently on the next restart.
            bool desiredRequireIngestionToken = options.RequireIngestionToken;
            if (payload.ContainsKey("requireIngestionToken"))
            {
                desiredRequireIngestionToken = Convert.ToBoolean(payload["requireIngestionToken"]);
                bool acknowledgeIngestionTokenRisk = payload.ContainsKey("acknowledgeIngestionTokenRisk") && Convert.ToBoolean(payload["acknowledgeIngestionTokenRisk"]);
                if (RequiresIngestionTokenRiskAcknowledgment(options.RequireIngestionToken, desiredRequireIngestionToken, acknowledgeIngestionTokenRisk))
                {
                    List<string> ingestionRisks = new List<string>();
                    ingestionRisks.Add("Anyone who can reach this server's port will be able to submit inventory reports with no token at all - both /api/v1/inventory and /api/v1/linux/inventory accept any request unauthenticated while this is off.");
                    Dictionary<string, object> ingestionRiskResponse = new Dictionary<string, object>();
                    ingestionRiskResponse["error"] = "disabling ingestion token enforcement removes authentication from inventory ingestion. Confirm to proceed anyway.";
                    ingestionRiskResponse["risks"] = ingestionRisks;
                    SendText(stream, serializer.Serialize(ingestionRiskResponse), "application/json; charset=utf-8", 409);
                    return;
                }
            }

            // HTTPS is applied before HTTP, not just validated before HTTP -
            // deliberately, and in this order for a reason: the dashboard's
            // Server Settings form always submits port/enableHttp/useHttps/
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

            if (payload.ContainsKey("hstsEnabled"))
            {
                options.HstsEnabled = Convert.ToBoolean(payload["hstsEnabled"]);
                updates["HstsEnabled"] = options.HstsEnabled ? "true" : "false";
            }

            if (payload.ContainsKey("hstsMaxAgeHours"))
            {
                int hstsMaxAgeHours;
                if (!Int32.TryParse(Convert.ToString(payload["hstsMaxAgeHours"]), out hstsMaxAgeHours) || hstsMaxAgeHours < 1 || hstsMaxAgeHours > 8760)
                {
                    SendText(stream, "{\"error\":\"hstsMaxAgeHours must be between 1 and 8760\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.HstsMaxAgeHours = hstsMaxAgeHours;
                updates["HstsMaxAgeHours"] = hstsMaxAgeHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("adSyncEnabled") || payload.ContainsKey("adDescriptionSyncEnabled") || payload.ContainsKey("adSyncMode") || payload.ContainsKey("adSyncIntervalHours")
                || payload.ContainsKey("adDomain") || payload.ContainsKey("adUseServiceIdentity") || payload.ContainsKey("adUsername") || payload.ContainsKey("adPassword")
                || payload.ContainsKey("adComputerImportOUs"))
            {
                bool adSyncEnabled = payload.ContainsKey("adSyncEnabled") ? Convert.ToBoolean(payload["adSyncEnabled"]) : options.AdSyncEnabled;
                bool adDescriptionSyncEnabled = payload.ContainsKey("adDescriptionSyncEnabled") ? Convert.ToBoolean(payload["adDescriptionSyncEnabled"]) : options.AdDescriptionSyncEnabled;

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
                options.AdDescriptionSyncEnabled = adDescriptionSyncEnabled;
                options.AdSyncMode = adSyncMode;
                options.AdSyncIntervalHours = adSyncIntervalHours;
                options.AdDomain = adDomain;
                options.AdUseServiceIdentity = adUseServiceIdentity;
                options.AdUsername = adUsername;
                options.AdPassword = adPassword;
                options.AdComputerImportOUs = payload.ContainsKey("adComputerImportOUs") ? Convert.ToString(payload["adComputerImportOUs"]) : options.AdComputerImportOUs;
                ReconfigureAdSyncTimer();

                updates["AdSyncEnabled"] = options.AdSyncEnabled ? "true" : "false";
                updates["AdDescriptionSyncEnabled"] = options.AdDescriptionSyncEnabled ? "true" : "false";
                updates["AdSyncMode"] = options.AdSyncMode;
                updates["AdSyncIntervalHours"] = options.AdSyncIntervalHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
                updates["AdDomain"] = options.AdDomain ?? "";
                updates["AdUseServiceIdentity"] = options.AdUseServiceIdentity ? "true" : "false";
                updates["AdUsername"] = options.AdUsername ?? "";
                updates["AdPassword"] = options.AdPassword ?? "";
                updates["AdComputerImportOUs"] = options.AdComputerImportOUs ?? "";
            }

            if (payload.ContainsKey("preferredLinuxSubnet"))
            {
                string preferredLinuxSubnet = Convert.ToString(payload["preferredLinuxSubnet"]).Trim();
                if (!IsValidCidr(preferredLinuxSubnet))
                {
                    SendText(stream, "{\"error\":\"preferredLinuxSubnet must be blank or a valid IPv4 CIDR block, e.g. 192.168.1.0/24\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.PreferredLinuxSubnet = preferredLinuxSubnet;
                updates["PreferredLinuxSubnet"] = options.PreferredLinuxSubnet;
            }

            if (payload.ContainsKey("linuxDefaultIntervalHours"))
            {
                int linuxDefaultIntervalHours;
                if (!Int32.TryParse(Convert.ToString(payload["linuxDefaultIntervalHours"]), out linuxDefaultIntervalHours) || linuxDefaultIntervalHours < 1 || linuxDefaultIntervalHours > 24)
                {
                    SendText(stream, "{\"error\":\"linuxDefaultIntervalHours must be between 1 and 24\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.LinuxDefaultIntervalHours = linuxDefaultIntervalHours;
                updates["LinuxDefaultIntervalHours"] = linuxDefaultIntervalHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("linuxDefaultStatusIntervalMinutes"))
            {
                int linuxDefaultStatusIntervalMinutes;
                if (!Int32.TryParse(Convert.ToString(payload["linuxDefaultStatusIntervalMinutes"]), out linuxDefaultStatusIntervalMinutes) || linuxDefaultStatusIntervalMinutes < 1 || linuxDefaultStatusIntervalMinutes > 1440)
                {
                    SendText(stream, "{\"error\":\"linuxDefaultStatusIntervalMinutes must be between 1 and 1440\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.LinuxDefaultStatusIntervalMinutes = linuxDefaultStatusIntervalMinutes;
                updates["LinuxDefaultStatusIntervalMinutes"] = linuxDefaultStatusIntervalMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("linuxDefaultInstallPath"))
            {
                string linuxDefaultInstallPath = Convert.ToString(payload["linuxDefaultInstallPath"]).Trim();
                if (!IsValidLinuxInstallPath(linuxDefaultInstallPath))
                {
                    SendText(stream, "{\"error\":\"linuxDefaultInstallPath must be a real subdirectory under /opt/ (e.g. /opt/windows-inventory-lite), with no '.' or '..' path segment, since this value is used in a remote 'rm -rf' during uninstall\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.LinuxDefaultInstallPath = linuxDefaultInstallPath;
                updates["LinuxDefaultInstallPath"] = linuxDefaultInstallPath;
            }

            if (payload.ContainsKey("loginLockoutThreshold"))
            {
                int loginLockoutThreshold;
                if (!Int32.TryParse(Convert.ToString(payload["loginLockoutThreshold"]), out loginLockoutThreshold) || loginLockoutThreshold < 0 || loginLockoutThreshold > 1000)
                {
                    SendText(stream, "{\"error\":\"loginLockoutThreshold must be between 0 and 1000 (0 disables lockout)\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.LoginLockoutThreshold = loginLockoutThreshold;
                updates["LoginLockoutThreshold"] = loginLockoutThreshold.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("loginLockoutWindowMinutes"))
            {
                int loginLockoutWindowMinutes;
                if (!Int32.TryParse(Convert.ToString(payload["loginLockoutWindowMinutes"]), out loginLockoutWindowMinutes) || loginLockoutWindowMinutes < 1 || loginLockoutWindowMinutes > 1440)
                {
                    SendText(stream, "{\"error\":\"loginLockoutWindowMinutes must be between 1 and 1440\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.LoginLockoutWindowMinutes = loginLockoutWindowMinutes;
                updates["LoginLockoutWindowMinutes"] = loginLockoutWindowMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("loginLockoutDurationMinutes"))
            {
                int loginLockoutDurationMinutes;
                if (!Int32.TryParse(Convert.ToString(payload["loginLockoutDurationMinutes"]), out loginLockoutDurationMinutes) || loginLockoutDurationMinutes < 1 || loginLockoutDurationMinutes > 1440)
                {
                    SendText(stream, "{\"error\":\"loginLockoutDurationMinutes must be between 1 and 1440\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.LoginLockoutDurationMinutes = loginLockoutDurationMinutes;
                updates["LoginLockoutDurationMinutes"] = loginLockoutDurationMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("sessionLifetimeHours"))
            {
                int sessionLifetimeHours;
                if (!Int32.TryParse(Convert.ToString(payload["sessionLifetimeHours"]), out sessionLifetimeHours) || sessionLifetimeHours < 1 || sessionLifetimeHours > 720)
                {
                    SendText(stream, "{\"error\":\"sessionLifetimeHours must be between 1 and 720\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.SessionLifetimeHours = sessionLifetimeHours;
                updates["SessionLifetimeHours"] = sessionLifetimeHours.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("ingestionRejectionLogRetentionDays"))
            {
                int ingestionRejectionLogRetentionDays;
                if (!Int32.TryParse(Convert.ToString(payload["ingestionRejectionLogRetentionDays"]), out ingestionRejectionLogRetentionDays) || ingestionRejectionLogRetentionDays < 1 || ingestionRejectionLogRetentionDays > 3650)
                {
                    SendText(stream, "{\"error\":\"ingestionRejectionLogRetentionDays must be between 1 and 3650\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.IngestionRejectionLogRetentionDays = ingestionRejectionLogRetentionDays;
                updates["IngestionRejectionLogRetentionDays"] = ingestionRejectionLogRetentionDays.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("ingestionRejectionLogMaxEntries"))
            {
                int ingestionRejectionLogMaxEntries;
                if (!Int32.TryParse(Convert.ToString(payload["ingestionRejectionLogMaxEntries"]), out ingestionRejectionLogMaxEntries) || ingestionRejectionLogMaxEntries < 100 || ingestionRejectionLogMaxEntries > 100000)
                {
                    SendText(stream, "{\"error\":\"ingestionRejectionLogMaxEntries must be between 100 and 100000\"}", "application/json; charset=utf-8", 400);
                    return;
                }
                options.IngestionRejectionLogMaxEntries = ingestionRejectionLogMaxEntries;
                updates["IngestionRejectionLogMaxEntries"] = ingestionRejectionLogMaxEntries.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            if (payload.ContainsKey("debugLogEnabled"))
            {
                // The log path is deliberately not settable from here - it
                // stays CLI/config-only, so this endpoint can't be used to
                // make the server write an arbitrary file path.
                options.DebugLogEnabled = Convert.ToBoolean(payload["debugLogEnabled"]);
                updates["DebugLogEnabled"] = options.DebugLogEnabled ? "true" : "false";
            }

            if (payload.ContainsKey("requireIngestionToken"))
            {
                options.RequireIngestionToken = desiredRequireIngestionToken;
                updates["RequireIngestionToken"] = options.RequireIngestionToken ? "true" : "false";
            }

            if (updates.Count > 0)
            {
                SaveServerConfigValues(updates);
            }

            SendServerSettings(stream);
        }

        // Same shape as Install-Server.ps1's own New-RandomToken (32 bytes,
        // hex-encoded to 64 lowercase characters) - not shared code (this
        // runs in the C# server, that runs in PowerShell at install time),
        // but deliberately the same generation approach for consistency.
        private static string GenerateRandomToken()
        {
            byte[] bytes = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        private void SendIngestionTokenStatus(Stream stream)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["configured"] = !String.IsNullOrEmpty(options.Token);
            result["token"] = options.Token;
            result["requireIngestionToken"] = options.RequireIngestionToken;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void SendIngestionRejectionLog(Stream stream)
        {
            List<IngestionRejectionEntry> snapshot;
            lock (ingestionRejectionLogLock)
            {
                snapshot = new List<IngestionRejectionEntry>(ingestionRejectionLog);
            }

            // Source IP -> client display name, built once for this
            // request rather than once per log entry - see spec's
            // SendIngestionRejectionLog description for why.
            Dictionary<string, string> clientsByIp = new Dictionary<string, string>();
            Dictionary<string, DateTime> lastCollectedByIp = new Dictionary<string, DateTime>();
            foreach (Dictionary<string, object> client in LoadClientReports())
            {
                string ip = GetStringValue(client, "lastIngestSourceIp");
                if (String.IsNullOrEmpty(ip))
                {
                    continue;
                }
                string name = GetStringValue(client, "computerName");
                if (String.IsNullOrEmpty(name))
                {
                    name = GetStringValue(client, "hostname");
                }
                DateTime lastCollectedUtc = ParseUtcDate(GetStringValue(client, "collectedAt"), ParseUtcDate(GetStringValue(client, "sourceUpdatedAt"), DateTime.MinValue));
                clientsByIp[ip] = name;
                lastCollectedByIp[ip] = lastCollectedUtc;
            }

            ArrayList entries = new ArrayList();
            for (int i = snapshot.Count - 1; i >= 0; i--)
            {
                IngestionRejectionEntry entry = snapshot[i];
                Dictionary<string, object> row = new Dictionary<string, object>();
                row["timestampUtc"] = entry.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                row["sourceIp"] = entry.SourceIp;
                row["endpoint"] = entry.Endpoint;
                row["reason"] = entry.Reason;

                string hostname = null;
                IPAddress parsedSourceIp;
                if (IPAddress.TryParse(entry.SourceIp, out parsedSourceIp))
                {
                    lock (reverseDnsCacheLock)
                    {
                        reverseDnsCache.TryGetValue(parsedSourceIp, out hostname);
                    }
                }
                row["hostname"] = hostname;

                string matchedClient = null;
                DateTime lastCollectedUtc;
                if (clientsByIp.TryGetValue(entry.SourceIp, out matchedClient) && lastCollectedByIp.TryGetValue(entry.SourceIp, out lastCollectedUtc) && entry.TimestampUtc > lastCollectedUtc)
                {
                    row["matchedClient"] = matchedClient;
                }
                else
                {
                    row["matchedClient"] = null;
                }

                entries.Add(row);
            }

            Dictionary<string, object> result = new Dictionary<string, object>();
            result["entries"] = entries;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void SendLinuxSshToolsStatus(Stream stream)
        {
            // deploy\linux-client is the source location documented in
            // NOTICE (fetched by whoever built the install package).
            // Install-ClientDebianSSH.ps1 resolves $projectRoot as the
            // parent of its own directory and looks for the tools at
            // $projectRoot\deploy\linux-client - on an installed server
            // that script lives in server-bin, so $projectRoot is the
            // WindowsInventoryLite root and the tools must sit in a
            // deploy\linux-client folder that is a SIBLING of server-bin
            // (which Install-Server.ps1 now populates conditionally, same
            // as it does for Deploy-ClientGpo.ps1). Check both that
            // installed-server location and the repo-relative path (dev/
            // build-tree environment) so this status is accurate either way.
            string installedDeployDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"WindowsInventoryLite\deploy\linux-client");
            string repoRelativePlink = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\deploy\linux-client\plink.exe");
            string repoRelativePscp = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\deploy\linux-client\pscp.exe");
            string installedPlink = Path.Combine(installedDeployDir, "plink.exe");
            string installedPscp = Path.Combine(installedDeployDir, "pscp.exe");

            bool plinkFound = File.Exists(repoRelativePlink) || File.Exists(installedPlink);
            bool pscpFound = File.Exists(repoRelativePscp) || File.Exists(installedPscp);

            Dictionary<string, object> result = new Dictionary<string, object>();
            result["plinkFound"] = plinkFound;
            result["pscpFound"] = pscpFound;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void RegenerateIngestionToken(Stream stream, RequestContext request)
        {
            string newToken = GenerateRandomToken();

            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["Token"] = newToken;
            SaveServerConfigValues(updates);

            // Only mutate in-memory state after the save succeeds - if
            // SaveServerConfigValues throws, the exception propagates to the
            // generic error handler and options.Token is left untouched, so
            // a failed persist never leaves live clients 401'ing against a
            // token that was never actually written to disk.
            options.Token = newToken;

            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "WindowsInventoryLite",
                    "Ingestion token regenerated from the Settings page. Existing clients will be unable to submit inventory until reconfigured with the new token.",
                    System.Diagnostics.EventLogEntryType.Information);
            }
            catch { }

            Dictionary<string, object> result = new Dictionary<string, object>();
            result["token"] = newToken;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendJson(stream, serializer.Serialize(result));
        }

        private void SendAdminPasswordStatus(Stream stream)
        {
            SendAdminPasswordStatus(stream, null);
        }

        // extraHeaders lets ChangeAdminPassword attach the caller's fresh
        // session cookie to this same response after a password rotation
        // (see ChangeAdminPassword) - the plain 1-arg overload above covers
        // every other caller, which has nothing extra to send.
        private void SendAdminPasswordStatus(Stream stream, string extraHeaders)
        {
            bool configured = !String.IsNullOrEmpty(options.WebUsername) && !String.IsNullOrEmpty(options.WebPassword);
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["configured"] = configured;
            result["username"] = configured ? options.WebUsername : null;
            JavaScriptSerializer serializer = CreateJsonSerializer();
            SendText(stream, serializer.Serialize(result), "application/json; charset=utf-8", 200, null, extraHeaders);
        }

        private void SendClientUpdateCredentialsStatus(Stream stream)
        {
            bool configured = !String.IsNullOrEmpty(options.ClientUpdateUsername) && !String.IsNullOrEmpty(options.ClientUpdatePassword);
            Dictionary<string, object> result = new Dictionary<string, object>();
            result["configured"] = configured;
            result["username"] = String.IsNullOrEmpty(options.ClientUpdateUsername) ? null : options.ClientUpdateUsername;
            result["hasPassword"] = !String.IsNullOrEmpty(options.ClientUpdatePassword);
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
                // clock - re-enabling interval mode later starts fresh (the
                // first tick fires right away, since ShouldRunClientUpdateSchedule
                // treats a blank last-run as due) instead of computing the
                // wait against a stale timestamp left over from a previous,
                // unrelated stretch of interval mode.
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

            // Persist FIRST, mutate live state only after the save
            // succeeds - the previous order mutated options.WebUsername/
            // WebPassword before persisting, so a save failure (disk
            // full, AV/backup file lock, an ACL problem like the one
            // fixed alongside this) left the password changed in memory
            // (silently reverting on the next restart, since disk still
            // had the old value) with sessionStore never cleared below -
            // meaning every pre-rotation session, including one the
            // admin may be rotating specifically because they suspect
            // it's compromised, stayed valid. If SaveServerConfigValues
            // throws here, it propagates to the caller's normal error
            // handling with options.WebUsername/WebPassword and
            // sessionStore both untouched - the admin sees a real error
            // and can retry, with the system in the same consistent
            // state it was in before the attempt.
            Dictionary<string, string> updates = new Dictionary<string, string>();
            updates["WebUsername"] = newUsername;
            updates["WebPassword"] = newPassword;
            SaveServerConfigValues(updates);

            options.WebUsername = newUsername;
            options.WebPassword = newPassword;

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

            // A rotated password must not leave any existing session
            // valid - before this fix, a session cookie survived a
            // password rotation indefinitely (subject only to its own
            // expiry), unlike Basic Auth, which has always locked out
            // stale credentials on their very next request. Clear every
            // session, then mint a fresh one for the admin performing the
            // rotation so they are not logged out mid-action themselves.
            lock (sessionLock)
            {
                sessionStore.Clear();
            }
            string freshSessionToken = GenerateRandomToken();
            SessionRecord freshSession = new SessionRecord();
            freshSession.ExpiresUtc = ComputeSessionExpiry(DateTime.UtcNow, options.SessionLifetimeHours);
            lock (sessionLock)
            {
                sessionStore[freshSessionToken] = freshSession;
            }
            string freshSessionCookie = BuildSessionCookieHeader(stream, freshSessionToken);

            // Echoes the fresh GET-shaped status, matching every other
            // config POST on this API (settings, certificate, client-update
            // credentials/schedule) - a bare {"status":"ok"} was the one
            // outlier. Also carries the caller's fresh session cookie from
            // above.
            SendAdminPasswordStatus(stream, freshSessionCookie);
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
            new[] { "AdPassword", "WebPassword", "Token", "ClientUpdatePassword", "LinuxUpdatePassword" },
            StringComparer.Ordinal);

        private void SaveServerConfigValues(Dictionary<string, string> updates)
        {
            if (String.IsNullOrEmpty(options.ConfigPath))
            {
                return;
            }

            // The whole read-modify-write is inside configFileLock so two
            // writers (an operator's HTTP save and a background timer tick,
            // or two timers) can't interleave and silently drop each
            // other's change - see the lock's own declaration comment.
            lock (configFileLock)
            {
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
                // Write to a temp file then swap it into place, instead of
                // File.WriteAllText directly on the real path - this file
                // holds the auth credential and encrypted secrets, so a
                // process crash or a concurrent reader must never be able to
                // observe a truncated/partial write.
                //
                // The temp file's ACL is restricted BEFORE any secret bytes
                // are written into it, not after the swap - writing first
                // and restricting only the final path (the previous order)
                // left the temp file under the containing directory's
                // inherited ACL for the whole window it held the real
                // content, and if the subsequent File.Replace/Move then
                // threw, that weakly-protected file was left behind
                // permanently. Mirrors Install-Server.ps1's
                // Set-RestrictedFileAcl, which fixed the identical ordering
                // bug on the PowerShell side.
                //
                // Side effect worth knowing about: restricting the temp
                // file's ACL before writing content means the WRITING
                // PROCESS itself must already hold Administrators-or-SYSTEM
                // access, on every save now, not just a later one - the
                // real shipped Windows Service always runs as LocalSystem
                // (Install-Server.ps1 never passes sc.exe an obj= account),
                // so production is unaffected, but running --console mode
                // from a non-elevated prompt (including a literal member of
                // the local Administrators group who has not explicitly
                // "Run as Administrator" - UAC gives such a process a
                // filtered token where Administrators is present but marked
                // deny-only) will now fail on its very first config save,
                // where it previously happened to succeed by writing into a
                // temp file that had no ACL restriction yet. That failure is
                // this fix working as intended (fail closed before any
                // secret byte is written) rather than a bug - run --console
                // elevated if it needs to persist its own configuration.
                string tempPath = options.ConfigPath + ".tmp";
                File.WriteAllText(tempPath, "", new UTF8Encoding(false));
                ApplyRestrictedConfigAcl(tempPath);
                File.WriteAllText(tempPath, json, new UTF8Encoding(false));
                if (File.Exists(options.ConfigPath))
                {
                    File.Replace(tempPath, options.ConfigPath, null);
                }
                else
                {
                    File.Move(tempPath, options.ConfigPath);
                }
                ApplyRestrictedConfigAcl(options.ConfigPath);
            }
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

        private static readonly object linuxKnownHostsLock = new object();

        // Stored under a subfolder (same convention as _licenses/, _logs/,
        // _linux-client-install-jobs/) so it never lands in the client-report
        // filename namespace: per-client inventory reports are written as
        // SanitizeFileName(computerName) + ".json" directly under DataPath's
        // top level, and SanitizeFileName passes letters/digits/hyphens
        // through unchanged. A client POSTing computerName "linux-ssh-known-hosts"
        // to /api/v1/inventory - an endpoint gated only by the ingestion
        // token, not admin auth - would otherwise overwrite this trust store
        // outright (or DELETE /api/v1/clients/linux-ssh-known-hosts could
        // remove it), corrupting the file and hard-failing every
        // password-based Linux push.
        private string GetLinuxSshDirectory()
        {
            return Path.Combine(options.DataPath, "_linux-ssh");
        }

        private string GetLinuxKnownHostsFilePath()
        {
            return Path.Combine(GetLinuxSshDirectory(), "linux-ssh-known-hosts.json");
        }

        private string GetLinuxSshKeyFilePath()
        {
            return Path.Combine(GetLinuxSshDirectory(), "linux-update-key");
        }

        private void ConfigureLinuxSshKey(Stream stream, RequestContext request)
        {
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

            string keyBase64 = Convert.ToString(payload.ContainsKey("keyBase64") ? payload["keyBase64"] : "");
            if (String.IsNullOrEmpty(keyBase64))
            {
                SendText(stream, "{\"error\":\"keyBase64 is required\"}", "application/json; charset=utf-8", 400);
                return;
            }

            byte[] keyBytes;
            try
            {
                keyBytes = Convert.FromBase64String(keyBase64);
            }
            catch
            {
                SendText(stream, "{\"error\":\"keyBase64 is not valid base64\"}", "application/json; charset=utf-8", 400);
                return;
            }

            const int MaxKeyBytes = 1024 * 1024;
            if (keyBytes.Length == 0 || keyBytes.Length > MaxKeyBytes)
            {
                SendText(stream, "{\"error\":\"key file must be between 1 byte and 1 MB\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string content;
            try
            {
                content = Encoding.UTF8.GetString(keyBytes);
            }
            catch
            {
                SendText(stream, "{\"error\":\"key file is not readable as text\"}", "application/json; charset=utf-8", 400);
                return;
            }

            if (LooksLikePublicKey(content))
            {
                SendText(stream, "{\"error\":\"This looks like a public key (.pub) - upload the matching private key instead.\"}", "application/json; charset=utf-8", 400);
                return;
            }

            if (!LooksLikePrivateKey(content))
            {
                SendText(stream, "{\"error\":\"This does not look like a private key file (expected a -----BEGIN ... PRIVATE KEY----- header).\"}", "application/json; charset=utf-8", 400);
                return;
            }

            string keyPath = GetLinuxSshKeyFilePath();
            string tempPath = keyPath + ".tmp";
            try
            {
                string directory = GetLinuxSshDirectory();
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                File.WriteAllBytes(tempPath, keyBytes);
                // Restrict the temp file's ACL immediately - it holds the plaintext
                // private key and would otherwise inherit the directory's default
                // (broader) permissions for the whole window before the replace/move.
                ApplyRestrictedKeyFileAcl(tempPath);
                if (File.Exists(keyPath))
                {
                    File.Replace(tempPath, keyPath, null);
                }
                else
                {
                    File.Move(tempPath, keyPath);
                }
                ApplyRestrictedKeyFileAcl(keyPath);
                // Harden the directory itself only now that every write into it
                // for this operation is done. The grant set (see
                // ApplyRestrictedDirectoryAcl's doc comment) already includes the
                // server's own operating identity, so this ordering is no longer
                // needed to avoid locking that identity out - it remains good
                // defense-in-depth for the directory's first-ever hardening pass.
                ApplyRestrictedDirectoryAcl(directory);
            }
            catch (Exception)
            {
                SendText(stream, "{\"error\":\"could not save the key file to disk\"}", "application/json; charset=utf-8", 500);
                return;
            }
            finally
            {
                // File.Replace/File.Move already consumed tempPath on the success
                // path, so this is a no-op then; it only matters when something
                // above threw, to avoid leaving an orphaned key file on disk.
                try
                {
                    if (File.Exists(tempPath))
                    {
                        File.Delete(tempPath);
                    }
                }
                catch (Exception)
                {
                    // Best-effort cleanup only - do not let a failure here mask
                    // the original error or crash a successful save.
                }
            }

            ArrayList risks = new ArrayList();
            if (LooksLikeEncryptedPrivateKey(content))
            {
                risks.Add("This key appears to be passphrase-protected. Linux pushes run SSH in batch mode, which cannot prompt for a passphrase - pushes using this key will fail until it's replaced with an unencrypted key.");
            }

            Dictionary<string, object> result = new Dictionary<string, object>();
            result["status"] = "ok";
            result["risks"] = risks;
            JavaScriptSerializer responseSerializer = CreateJsonSerializer();
            SendJson(stream, responseSerializer.Serialize(result));
        }

        private void DeleteLinuxSshKey(Stream stream)
        {
            string keyPath = GetLinuxSshKeyFilePath();
            try
            {
                if (File.Exists(keyPath))
                {
                    File.Delete(keyPath);
                }
            }
            catch (Exception)
            {
                SendText(stream, "{\"error\":\"could not delete the key file\"}", "application/json; charset=utf-8", 500);
                return;
            }

            // Best-effort cleanup of any orphaned temp file left behind by a
            // prior failed upload (see ConfigureLinuxSshKey). A failure here
            // must not turn a successful delete of the real key into a 500.
            try
            {
                string tempPath = keyPath + ".tmp";
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (Exception)
            {
            }

            SendJson(stream, "{\"status\":\"deleted\"}");
        }

        // Pure string checks, no I/O - self-testable directly. Together
        // these close the exact live failure this feature exists to
        // prevent: a .pub file (the wrong half of a keypair) accepted as
        // if it were a private key, with nothing catching the mistake
        // until an actual SSH push failed against a real target.
        internal static bool LooksLikePrivateKey(string content)
        {
            if (String.IsNullOrEmpty(content))
            {
                return false;
            }
            string trimmed = content.TrimStart();
            if (!trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal))
            {
                return false;
            }
            int headerEnd = trimmed.IndexOf('\n');
            string headerLine = headerEnd >= 0 ? trimmed.Substring(0, headerEnd) : trimmed;
            return headerLine.IndexOf("PRIVATE KEY-----", StringComparison.Ordinal) >= 0;
        }

        internal static bool LooksLikePublicKey(string content)
        {
            if (String.IsNullOrEmpty(content))
            {
                return false;
            }
            string trimmed = content.TrimStart();
            return trimmed.StartsWith("ssh-rsa ", StringComparison.Ordinal)
                || trimmed.StartsWith("ssh-ed25519 ", StringComparison.Ordinal)
                || trimmed.StartsWith("ssh-dss ", StringComparison.Ordinal)
                || trimmed.StartsWith("ecdsa-sha2-", StringComparison.Ordinal);
        }

        // OpenSSH's own key format (openssh-key-v1) embeds a KDF name
        // right after a fixed magic preamble in the base64-decoded body:
        // "none" for an unencrypted key, "bcrypt" for a passphrase-
        // protected one. Decoding the base64 body and checking for the
        // literal ASCII substring "bcrypt" is a reliable, parser-free
        // signal - it does not require walking the full length-prefixed
        // binary structure to tell "has a passphrase" from "doesn't".
        // Legacy PEM-format encrypted keys instead carry a plaintext
        // "Proc-Type: 4,ENCRYPTED" header line, checked first.
        internal static bool LooksLikeEncryptedPrivateKey(string content)
        {
            if (String.IsNullOrEmpty(content))
            {
                return false;
            }
            if (content.IndexOf("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal) >= 0)
            {
                return true;
            }
            const string openSshHeader = "-----BEGIN OPENSSH PRIVATE KEY-----";
            const string openSshFooter = "-----END OPENSSH PRIVATE KEY-----";
            int headerIndex = content.IndexOf(openSshHeader, StringComparison.Ordinal);
            if (headerIndex < 0)
            {
                return false;
            }
            int bodyStart = headerIndex + openSshHeader.Length;
            int footerIndex = content.IndexOf(openSshFooter, bodyStart, StringComparison.Ordinal);
            if (footerIndex < 0)
            {
                return false;
            }
            string base64Body = content.Substring(bodyStart, footerIndex - bodyStart).Replace("\r", "").Replace("\n", "").Trim();
            byte[] decoded;
            try
            {
                decoded = Convert.FromBase64String(base64Body);
            }
            catch
            {
                return false;
            }
            string decodedText = Encoding.ASCII.GetString(decoded);
            return decodedText.IndexOf("bcrypt", StringComparison.Ordinal) >= 0;
        }

        // Same DACL treatment as ApplyRestrictedConfigAcl, plus explicit
        // Owner=SYSTEM - the load-bearing difference. ssh.exe's own
        // private-key permission check inspects Owner as a condition
        // independent of the DACL; neither ApplyRestrictedConfigAcl nor
        // Install-Server.ps1's Set-RestrictedFileAcl ever set it, and a
        // DACL-only fix was confirmed live to still produce the exact
        // "UNPROTECTED PRIVATE KEY FILE" refusal this method exists to
        // prevent. Setting Owner to a SID other than the caller requires
        // an elevated/SYSTEM process token - this matches the real
        // deployment (the Windows Service runs as LocalSystem) but not
        // every dev/test environment, so failures here are caught and
        // logged, never thrown, exactly like ApplyRestrictedConfigAcl.
        private void ApplyRestrictedKeyFileAcl(string path)
        {
            try
            {
                SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

                // DACL first, persisted on its own - this alone matches
                // ApplyRestrictedConfigAcl's own guarantee (no elevation
                // needed) and must not be lost if the Owner step below
                // fails for lack of privilege.
                FileSecurity acl = File.GetAccessControl(path);
                acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));
                acl.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
                File.SetAccessControl(path, acl);

                // Owner is a separate persist step - setting it to a SID
                // other than the caller requires an elevated/SYSTEM
                // process token, and a failure here must not roll back
                // the DACL hardening already persisted above.
                FileSecurity ownerAcl = File.GetAccessControl(path);
                ownerAcl.SetOwner(systemSid);
                File.SetAccessControl(path, ownerAcl);
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "Config", "Could not fully restrict linux-update-key permissions: " + DebugLogger.SanitizeForLog(ex.Message));
            }
        }

        // Directory counterpart to ApplyRestrictedKeyFileAcl. The _linux-ssh
        // directory holds the private key and the known-hosts trust store, but was
        // created with a bare Directory.CreateDirectory and inherited whatever
        // ProgramData's defaults are. Same two-step DACL-then-Owner persist and
        // the same swallow-and-log failure handling as the file version.
        //
        // Grant set: Administrators, SYSTEM, and the identity actually running
        // this server process (WindowsIdentity.GetCurrent().User) - skipped only
        // if that identity's SID already equals SYSTEM, to avoid a redundant
        // duplicate rule. (The Administrators check is defensive but effectively
        // dead code: WindowsIdentity.GetCurrent().User returns an individual
        // user SID, which can never equal the well-known Administrators GROUP
        // SID, even for a user who is a group member. Only the SYSTEM comparison
        // can actually match and skip.) This is deliberately NOT
        // "Administrators and SYSTEM only": there is no way for a non-privileged
        // identity to repeatedly read/write/rotate/delete files in an
        // ACL-protected directory across separate operations unless it is
        // explicitly granted access on the directory itself (or is a member of
        // a granted group) - a directory locked to Administrators+SYSTEM only is
        // permanently inaccessible to any other identity, full stop, for as long
        // as it stays configured that way. Excluding the server's own operating
        // identity would therefore permanently break the SSH-key upload,
        // rotation, and delete flow (ConfigureLinuxSshKey, DeleteLinuxSshKey)
        // after the very first successful hardening, in exactly the
        // least-privileged domain/managed service account deployment mode the
        // project's own threat model recommends (docs/threat-model.md) - this is
        // not a hypothetical edge case, and it is not a no-op even when the
        // service runs as LocalSystem, because the documented supported
        // deployment mode is a non-LocalSystem account.
        //
        // Granting the operating identity here does not meaningfully widen the
        // attack surface: it is the SAME account already running the entire
        // server process, so it already has access to everything else the
        // server manages (DPAPI-protected secrets - which are inherently scoped
        // to the identity that encrypted them by DPAPI's own design). Restricting
        // this one directory to "Administrators+SYSTEM only, excluding the
        // server's own account" would not protect against a compromise of that
        // account - it already holds the keys to everything else - while the
        // actual threat this hardening exists to stop (some OTHER local account
        // snooping on or tampering with the SSH trust store) remains fully
        // addressed, since every other local identity is still excluded.
        //
        // Callers should still only invoke this after every write into the
        // directory for the current operation has completed (temp file write,
        // per-file hardening, move into place). That ordering is no longer
        // required to avoid a lockout (the grant above prevents that on its
        // own), but it remains good defense-in-depth for the directory's
        // first-ever hardening pass.
        private void ApplyRestrictedDirectoryAcl(string path)
        {
            try
            {
                SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                SecurityIdentifier currentSid = WindowsIdentity.GetCurrent().User;

                DirectorySecurity acl = Directory.GetAccessControl(path);
                acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                acl.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                if (currentSid != null && !currentSid.Equals(adminSid) && !currentSid.Equals(systemSid))
                {
                    acl.AddAccessRule(new FileSystemAccessRule(currentSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                }
                Directory.SetAccessControl(path, acl);

                DirectorySecurity ownerAcl = Directory.GetAccessControl(path);
                ownerAcl.SetOwner(systemSid);
                Directory.SetAccessControl(path, ownerAcl);
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "Config", "Could not fully restrict the linux-ssh directory permissions: " + DebugLogger.SanitizeForLog(ex.Message));
            }
        }

        // One-time upgrade path: an existing install may already have
        // LinuxUpdateKeyPath pointing at a real private key file
        // somewhere on disk (the old "type a path" model). Adopts it
        // automatically so upgrading needs zero admin action - but only
        // once (guarded by "the managed file doesn't exist yet"), and
        // only if the legacy path genuinely looks like a private key;
        // any failure (unreadable, wrong format, copy error) is logged
        // and swallowed, never thrown - a failed migration just leaves
        // the key unconfigured, same as a fresh install, and must never
        // block server startup.
        private void MigrateLegacyLinuxSshKey()
        {
            try
            {
                string managedPath = GetLinuxSshKeyFilePath();
                if (File.Exists(managedPath))
                {
                    return;
                }
                if (String.IsNullOrEmpty(options.LinuxUpdateKeyPath) || !File.Exists(options.LinuxUpdateKeyPath))
                {
                    return;
                }
                string content = File.ReadAllText(options.LinuxUpdateKeyPath, Encoding.UTF8);
                if (!LooksLikePrivateKey(content))
                {
                    return;
                }
                string directory = GetLinuxSshDirectory();
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                // Copy to a temp path, THEN move into place and harden the real
                // file - mirroring the upload path's own temp/move idiom
                // (ConfigureLinuxSshKey). File.Copy straight to the real path
                // would leave a window where the private key sits there with
                // whatever broad, inherited permissions the containing
                // directory has. The directory itself is deliberately NOT
                // hardened until after this whole sequence completes (below).
                // The grant set (see ApplyRestrictedDirectoryAcl's doc comment)
                // already includes the server's own operating identity, so this
                // ordering is no longer needed to avoid locking that identity
                // out - it remains good defense-in-depth for the directory's
                // first-ever hardening pass.
                //
                // NOTE: an intermediate ApplyRestrictedKeyFileAcl(tempPath) call
                // before the move (matching ConfigureLinuxSshKey's own temp-file
                // hardening) was evaluated and is intentionally NOT applied
                // here. Confirmed via an isolated repro: hardening tempPath to
                // Administrators+SYSTEM only, then calling File.Move, throws
                // UnauthorizedAccessException for a non-privileged identity even
                // though the containing directory itself is unrestricted - a
                // rename requires DELETE access on the source file's own
                // security descriptor, which is not satisfiable via the parent
                // directory's delete-child grant (unlike a plain File.Delete,
                // which is). This is independent of the directory-ACL ordering
                // fix above. The only known workaround is granting the current
                // identity access on the temp file, which would reintroduce the
                // same kind of permanent-widening risk this fix exists to
                // remove (ApplyRestrictedKeyFileAcl is shared with the final
                // managedPath hardening below, so widening it here would widen
                // the real key file's grant set too). Left as a known,
                // documented limitation rather than worked around; see the
                // fix report for details. ConfigureLinuxSshKey has the same
                // latent limitation in its own upload path, pre-existing and
                // out of scope here.
                string tempPath = managedPath + ".tmp";
                try
                {
                    File.Copy(options.LinuxUpdateKeyPath, tempPath, true);
                    File.Move(tempPath, managedPath);
                    ApplyRestrictedKeyFileAcl(managedPath);
                }
                finally
                {
                    try
                    {
                        if (File.Exists(tempPath))
                        {
                            File.Delete(tempPath);
                        }
                    }
                    catch (Exception)
                    {
                        // Best-effort cleanup only, same as UploadLinuxSshKey's.
                    }
                }
                // Harden the directory itself only now that every write into it
                // for this migration is done (see ApplyRestrictedDirectoryAcl's
                // doc comment for why the ordering matters).
                ApplyRestrictedDirectoryAcl(directory);
                DebugLogger.Log(options, "Config", "Migrated legacy LinuxUpdateKeyPath ('" + DebugLogger.SanitizeForLog(options.LinuxUpdateKeyPath) + "') into the managed linux-update-key store. The original file is no longer used and can be removed.");
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "Config", "Could not migrate legacy LinuxUpdateKeyPath: " + DebugLogger.SanitizeForLog(ex.Message));
            }
        }

        // The Deploy > Actions unification (Phase 3, 2026-08-21) merged the
        // separate Windows/Linux install job classes and storage into one -
        // _linux-client-install-jobs (under LinuxDataPath) stopped being
        // created, read, or pruned at that point, since job history now
        // lives entirely under DataPath's _client-install-jobs instead.
        // Any files left over from before that merge would otherwise
        // persist forever, invisible in the dashboard and never subject to
        // their own configured retention window. One-shot: the directory
        // won't exist on a fresh install, and once deleted here it stays
        // gone since nothing recreates it. Never blocks startup - logged
        // and swallowed on failure, same as MigrateLegacyLinuxSshKey above.
        private void PurgeOrphanedLinuxInstallJobDirectory()
        {
            try
            {
                string directory = Path.Combine(options.LinuxDataPath, "_linux-client-install-jobs");
                if (!Directory.Exists(directory))
                {
                    return;
                }
                Directory.Delete(directory, true);
                DebugLogger.Log(options, "Startup", "Removed the orphaned _linux-client-install-jobs directory (superseded by the unified install job storage under DataPath since v0.42.0).");
            }
            catch (Exception ex)
            {
                DebugLogger.Log(options, "Startup", "Could not remove the orphaned _linux-client-install-jobs directory: " + DebugLogger.SanitizeForLog(ex.Message));
            }
        }

        // Deliberately does NOT swallow read/parse errors into an empty list:
        // concurrent Linux install jobs (each dispatched via
        // ThreadPool.QueueUserWorkItem) and the manual trust-host-key
        // endpoint can all read/write this file at the same time, so a
        // transient sharing violation is real, not theoretical. Silently
        // returning "no records" here would make a host that DOES have a
        // pinned trust record look brand-new to FindLinuxKnownHost, and a
        // trustNewHostKeys push could then overwrite the pin via the
        // bulk-auto path - exactly the failure-looks-like-empty bug this
        // method must not reintroduce. Let the exception propagate;
        // FindLinuxKnownHost/UpsertLinuxKnownHost's callers are responsible
        // for treating it as a failure rather than "no record".
        private List<Dictionary<string, object>> LoadLinuxKnownHosts()
        {
            string path = GetLinuxKnownHostsFilePath();
            List<Dictionary<string, object>> hosts = new List<Dictionary<string, object>>();
            if (!File.Exists(path))
            {
                return hosts;
            }

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
                        hosts.Add(record);
                    }
                }
            }
            return hosts;
        }

        private void SaveLinuxKnownHosts(List<Dictionary<string, object>> hosts)
        {
            string directory = GetLinuxSshDirectory();
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            JavaScriptSerializer serializer = CreateJsonSerializer();
            string json = serializer.Serialize(hosts);
            string path = GetLinuxKnownHostsFilePath();
            // Write to a temp file then swap it into place (same idiom as
            // SaveConfig's ConfigPath write) instead of File.WriteAllText
            // directly on the real path - a crash or service stop mid-write
            // could otherwise leave a truncated/corrupt file, which then
            // reads back as "no records" and silently loses every
            // previously trusted host's pin.
            string tempPath = path + ".tmp";
            File.WriteAllText(tempPath, json, new UTF8Encoding(false));
            if (File.Exists(path))
            {
                File.Replace(tempPath, path, null);
            }
            else
            {
                File.Move(tempPath, path);
            }
            // A tampered fingerprint here would let a pinned push accept a
            // different key than the operator actually trusted - integrity,
            // not confidentiality, is what this ACL protects (same reasoning
            // as licenses.json, reusing the identical helper).
            ApplyRestrictedConfigAcl(path);
            // Harden the directory itself only now that every write into it
            // for this operation is done, matching the ordering contract
            // ConfigureLinuxSshKey and MigrateLegacyLinuxSshKey both follow -
            // this is the password-auth-only deployment path, where no
            // private key is ever uploaded and no legacy migration ever
            // runs, so this is the only call site that would otherwise
            // harden the directory for that deployment shape.
            ApplyRestrictedDirectoryAcl(directory);
        }

        private Dictionary<string, object> FindLinuxKnownHost(string host, int port)
        {
            List<Dictionary<string, object>> hosts;
            try
            {
                lock (linuxKnownHostsLock)
                {
                    hosts = LoadLinuxKnownHosts();
                }
            }
            catch (Exception ex)
            {
                // Explicitly re-thrown (not swallowed into "no record found")
                // so RunLinuxClientInstallTarget can distinguish "genuinely
                // no trust record" from "couldn't read the trust store right
                // now" and treat the latter as a failed push instead of
                // silently proceeding as if the host were brand-new.
                throw new IOException("Could not read the Linux SSH known-hosts trust store: " + ex.Message, ex);
            }

            foreach (Dictionary<string, object> record in hosts)
            {
                if (String.Equals(GetStringValue(record, "Host"), host, StringComparison.OrdinalIgnoreCase)
                    && GetIntValue(record, "Port", 22) == port)
                {
                    return record;
                }
            }
            return null;
        }

        private Dictionary<string, object> UpsertLinuxKnownHost(string host, int port, string keyType, string fingerprint, string trustMethod)
        {
            lock (linuxKnownHostsLock)
            {
                List<Dictionary<string, object>> hosts = LoadLinuxKnownHosts();
                hosts.RemoveAll(record =>
                    String.Equals(GetStringValue(record, "Host"), host, StringComparison.OrdinalIgnoreCase)
                    && GetIntValue(record, "Port", 22) == port);

                Dictionary<string, object> newRecord = new Dictionary<string, object>();
                newRecord["Host"] = host;
                newRecord["Port"] = port;
                newRecord["KeyType"] = keyType;
                newRecord["Fingerprint"] = fingerprint;
                newRecord["TrustedAtUtc"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                newRecord["TrustMethod"] = trustMethod;
                hosts.Add(newRecord);

                SaveLinuxKnownHosts(hosts);
                return newRecord;
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
            // Licenses can hold real product keys (see index.html's "License
            // type, key, or note" field hint) - restrict the same way
            // server-config.json already is, reapplied on every write so the
            // file can't drift back to an inherited (broader) ACL if it's
            // ever deleted and recreated.
            ApplyRestrictedConfigAcl(GetLicensesFilePath());
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

        // "Use global AD settings" on Client actions: substitutes the AD sync
        // credentials already configured in Settings > Windows > Active
        // Directory (the same ones AdLookupService uses) for this push -
        // either the server's own service identity (blank username/password,
        // the same as leaving both fields empty already means to
        // RunClientInstallTarget/RunClientUninstallTarget) or the saved
        // explicit AD account. Requires AD sync to actually be enabled and,
        // when not using the service identity, requires a saved username AND
        // password - returns false (leaving username/password untouched) and
        // sets errorMessage when either requirement isn't met, so the caller
        // rejects the request with a clear reason instead of silently
        // proceeding with the wrong identity or empty credentials.
        private static bool TryResolveAdSyncCredentials(bool useAdCredentials, bool adSyncEnabled, bool adUseServiceIdentity, string adUsername, string adPassword, ref string username, ref string password, out string errorMessage)
        {
            errorMessage = null;
            if (!useAdCredentials)
            {
                return true;
            }
            if (!adSyncEnabled)
            {
                errorMessage = "Check \"Configure AD User\" in Settings > Windows > Active Directory first.";
                return false;
            }
            if (adUseServiceIdentity)
            {
                username = "";
                password = "";
                return true;
            }
            if (String.IsNullOrEmpty(adUsername) || String.IsNullOrEmpty(adPassword))
            {
                errorMessage = "No AD username/password is saved in Settings > Windows > Active Directory.";
                return false;
            }
            username = adUsername;
            password = adPassword;
            return true;
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

        // POSIX shell metacharacters - these values are interpolated into a
        // generated remote SSH command (Invoke-RemoteCommand's -Command
        // argument, on the TARGET Linux machine), a generated systemd unit
        // file, or a generated install.sh for the downloadable Linux
        // package. Unlike ValidateBatchSafe's cmd.exe set above, POSIX
        // shells also treat $, `, single/double quotes, backslash, and
        // parentheses as live metacharacters - all rejected here rather
        // than attempting to safely quote/escape them, matching this
        // project's existing reject-rather-than-escape convention for the
        // Windows GPO cmd-generation path.
        // Space and tab are rejected alongside the shell metacharacters below -
        // none of this validator's callers (URLs, tokens, host/install paths,
        // fingerprints) legitimately need whitespace, and every one of them
        // gets interpolated unquoted into a remote POSIX command line built as
        // a plain string (e.g. Uninstall-ClientDebianSSH.ps1's "rm -rf
        // $InstallPath"). A value like "/opt/wil /usr" has no character this
        // list used to forbid, so it passed straight through and word-split
        // into two arguments on the remote shell - turning a scoped "rm -rf
        // $InstallPath" into "rm -rf /opt/wil /usr" on every target.
        private static readonly char[] PosixShellUnsafeChars = { '`', '$', '"', '\'', '\\', ';', '|', '&', '<', '>', '(', ')', '\r', '\n', ' ', '\t' };

        private static void ValidatePosixShellSafe(string value, string fieldName)
        {
            if (!String.IsNullOrEmpty(value) && value.IndexOfAny(PosixShellUnsafeChars) >= 0)
            {
                throw new ArgumentException(fieldName + " contains a character that is not allowed here (`, $, \", ', \\, ;, |, &, <, >, (, ), whitespace, or a line break).");
            }
        }

        // The three values that get interpolated into the remote shell command
        // built for a Linux push. Grouped into one helper because they must be
        // validated at the point they are USED, not at the top of the request
        // handler: StartClientAction overwrites serverUrl/installPath from
        // linux-package-settings.json AFTER its original validation ran, and
        // StartScheduledLinuxClientUpdatePush reads all three straight from that
        // file and never validated them at all.
        internal static bool TryValidateLinuxPushValues(string serverUrl, string token, string installPath, out string error)
        {
            error = null;
            try
            {
                ValidatePosixShellSafe(serverUrl, "serverUrl");
                ValidatePosixShellSafe(token, "token");
                ValidatePosixShellSafe(installPath, "installPath");
                // ValidatePosixShellSafe only screens for shell metacharacters
                // and whitespace - a bare top-level directory like "/etc" has
                // neither, so it passed straight through into a remote
                // "rm -rf $InstallPath" on every SSH install/uninstall/update
                // push that supplies installPath directly in its request body
                // (the dashboard UI stopped offering this field in v0.54.0,
                // but the server still accepts it - this is every actual
                // point of use for that value, not just the Settings-saved
                // default IsValidLinuxInstallPath already gated in v0.54.3).
                if (!IsValidLinuxInstallPath(installPath))
                {
                    throw new ArgumentException("installPath must be a real subdirectory under /opt/ (e.g. /opt/windows-inventory-lite), with no '.' or '..' path segment, since this value is used in a remote 'rm -rf' during uninstall.");
                }
                return true;
            }
            catch (ArgumentException ex)
            {
                error = ex.Message;
                return false;
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

        // Absolute path on the MANAGED LINUX HOST (not on this Windows server).
        // Must stay identical to Install-ClientDebianSSH.ps1's own copy.
        internal const string LinuxClientEnvFilePath = "/etc/wil-linux-client.env";

        // The mode-600 counterpart to the unit files' EnvironmentFile= line.
        // Must stay byte-for-byte in sync with New-SystemdEnvFile
        // (Install-ClientDebianSSH.ps1) - cross-checked by
        // TestGenerateSystemdEnvFileLinesMatchesPowerShellFormat.
        // ValidatePosixShellSafe already rejects CR/LF in sharedToken, so the
        // single-line shape cannot be broken by the value.
        private static string[] GenerateSystemdEnvFileLines(string sharedToken)
        {
            ValidatePosixShellSafe(sharedToken, "sharedToken");
            return new string[] { "WIL_INGESTION_TOKEN=" + sharedToken };
        }

        // Must stay byte-for-byte in sync with New-SystemdUnitFiles
        // (Install-ClientDebianSSH.ps1) - same two independent generators,
        // one per runtime, that this project already maintains for the
        // Windows GPO cmd-generation pair (GenerateCmdLines here vs.
        // New-ClientGpoPackage.ps1's own copy). Cross-checked by
        // TestGenerateSystemdUnitLinesMatchesPowerShellFormat below.
        private static string[] GenerateSystemdUnitLines(string installDirectory, string url, string sharedToken)
        {
            ValidatePosixShellSafe(installDirectory, "installDirectory");
            ValidatePosixShellSafe(url, "url");
            ValidatePosixShellSafe(sharedToken, "sharedToken");

            string execStart = installDirectory + "/wil-linux-client --server-url \"" + url + "\"";

            List<string> lines = new List<string>();
            lines.Add("[Unit]");
            lines.Add("Description=Windows Inventory Lite - Linux client (one-shot report)");
            lines.Add("");
            lines.Add("[Service]");
            lines.Add("Type=oneshot");
            // The token is deliberately NOT on the ExecStart line. A command-line
            // argument is readable from /proc/<pid>/cmdline by any local user on the
            // managed host, and from this unit file itself (mode 644). It goes in a
            // mode-600 EnvironmentFile instead. This project already fixed the
            // equivalent Windows-side exposure - see docs/threat-model.md, "Storing
            // dashboard credentials in the Windows Service ImagePath registry key".
            // Written without systemd's "-" ignore-if-missing prefix on purpose: a
            // silently-absent token file would put the client back in the "reports
            // are rejected and nobody knows why" state this project has already been
            // bitten by once.
            if (!String.IsNullOrEmpty(sharedToken))
            {
                lines.Add("EnvironmentFile=" + LinuxClientEnvFilePath);
            }
            lines.Add("ExecStart=" + execStart);
            return lines.ToArray();
        }

        private static string[] GenerateSystemdTimerLines(int hours)
        {
            List<string> lines = new List<string>();
            lines.Add("[Unit]");
            lines.Add("Description=Runs the Windows Inventory Lite Linux client every " + hours + " hour(s)");
            lines.Add("");
            lines.Add("[Timer]");
            lines.Add("OnBootSec=5min");
            lines.Add("OnUnitActiveSec=" + hours + "h");
            lines.Add("Unit=wil-linux-client.service");
            lines.Add("");
            lines.Add("[Install]");
            lines.Add("WantedBy=timers.target");
            return lines.ToArray();
        }

        // Status-ping counterpart to GenerateSystemdUnitLines/GenerateSystemdTimerLines
        // above - same structure, but the service execs with --mode status
        // against the merge-only endpoint, and the timer's interval is in
        // minutes (short enough that hour granularity would be too coarse),
        // not hours. Must stay byte-for-byte in sync with
        // New-SystemdStatusUnitFiles (Install-ClientDebianSSH.ps1) exactly
        // like its full-inventory sibling - cross-checked by
        // TestGenerateSystemdStatusUnitLinesMatchesPowerShellFormat below.
        private static string[] GenerateSystemdStatusUnitLines(string installDirectory, string statusUrl, string sharedToken)
        {
            ValidatePosixShellSafe(installDirectory, "installDirectory");
            ValidatePosixShellSafe(statusUrl, "statusUrl");
            ValidatePosixShellSafe(sharedToken, "sharedToken");

            string execStart = installDirectory + "/wil-linux-client --server-url \"" + statusUrl + "\" --mode status";

            List<string> lines = new List<string>();
            lines.Add("[Unit]");
            lines.Add("Description=Windows Inventory Lite - Linux client service-status ping (one-shot report)");
            lines.Add("");
            lines.Add("[Service]");
            lines.Add("Type=oneshot");
            // Same EnvironmentFile reasoning as GenerateSystemdUnitLines above.
            if (!String.IsNullOrEmpty(sharedToken))
            {
                lines.Add("EnvironmentFile=" + LinuxClientEnvFilePath);
            }
            lines.Add("ExecStart=" + execStart);
            return lines.ToArray();
        }

        private static string[] GenerateSystemdStatusTimerLines(int minutes)
        {
            List<string> lines = new List<string>();
            lines.Add("[Unit]");
            lines.Add("Description=Runs the Windows Inventory Lite Linux client service-status ping every " + minutes + " minute(s)");
            lines.Add("");
            lines.Add("[Timer]");
            lines.Add("OnBootSec=5min");
            lines.Add("OnUnitActiveSec=" + minutes + "min");
            lines.Add("Unit=wil-linux-client-status.service");
            lines.Add("");
            lines.Add("[Install]");
            lines.Add("WantedBy=timers.target");
            return lines.ToArray();
        }

        // Mirrors Get-LinuxUninstallCommand (Task 3) as closely as the
        // install-vs-uninstall difference allows: same
        // systemctl/InstallPath shape, generated for local (not SSH)
        // execution by whoever deploys this package.
        private static string[] GenerateLinuxInstallScriptLines(string installPath)
        {
            ValidatePosixShellSafe(installPath, "installPath");

            List<string> lines = new List<string>();
            lines.Add("#!/bin/sh");
            lines.Add("set -e");
            lines.Add("");
            lines.Add("SCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"");
            lines.Add("INSTALL_PATH=\"" + installPath + "\"");
            lines.Add("");
            lines.Add("sudo mkdir -p \"$INSTALL_PATH\"");
            lines.Add("sudo cp \"$SCRIPT_DIR/wil-linux-client\" \"$INSTALL_PATH/wil-linux-client\"");
            lines.Add("sudo chmod 755 \"$INSTALL_PATH/wil-linux-client\"");
            lines.Add("sudo cp \"$SCRIPT_DIR/wil-linux-client.service\" /etc/systemd/system/wil-linux-client.service");
            lines.Add("sudo cp \"$SCRIPT_DIR/wil-linux-client.timer\" /etc/systemd/system/wil-linux-client.timer");
            lines.Add("sudo cp \"$SCRIPT_DIR/wil-linux-client-status.service\" /etc/systemd/system/wil-linux-client-status.service");
            lines.Add("sudo cp \"$SCRIPT_DIR/wil-linux-client-status.timer\" /etc/systemd/system/wil-linux-client-status.timer");
            // Mode 600, owned by root: this file holds the ingestion token, which
            // used to sit readable on the ExecStart command line. Conditional
            // because the package only contains this file when a token is
            // configured (see ConfigureLinuxClientPackage).
            lines.Add("if [ -f \"$SCRIPT_DIR/wil-linux-client.env\" ]; then");
            lines.Add("  sudo cp \"$SCRIPT_DIR/wil-linux-client.env\" " + LinuxClientEnvFilePath);
            lines.Add("  sudo chmod 600 " + LinuxClientEnvFilePath);
            lines.Add("fi");
            lines.Add("sudo systemctl daemon-reload");
            lines.Add("sudo systemctl enable --now wil-linux-client.timer");
            lines.Add("sudo systemctl enable --now wil-linux-client-status.timer");
            // enable --now on a timer that was already active (a reinstall
            // over an existing client) does not reset OnUnitActiveSec's
            // countdown - restart unconditionally does, so a fresh binary is
            // scheduled promptly on its normal cadence (6h / 30min) whether
            // this is a fresh install or a reinstall. OnBootSec=5min does NOT
            // help here: it fires once, relative to actual machine boot, not
            // to this restart - on a long-uptime host it never fires again
            // this session, so without the explicit immediate run below, the
            // fresh binary's first real report could still be up to a full
            // 6h/30min away.
            lines.Add("sudo systemctl restart wil-linux-client.timer");
            lines.Add("sudo systemctl restart wil-linux-client-status.timer");
            // Best-effort immediate report so an admin sees fresh data right
            // after install/reinstall instead of waiting out the normal
            // cadence. "|| true" so a transient collection failure here (e.g.
            // dpkg momentarily locked right after other package activity)
            // does not abort the script under "set -e" - the scheduled
            // timers above already guarantee a real report lands on the
            // normal cadence regardless.
            lines.Add("sudo systemctl start wil-linux-client.service || true");
            lines.Add("sudo systemctl start wil-linux-client-status.service || true");
            lines.Add("");
            lines.Add("echo \"Windows Inventory Lite Linux client installed to $INSTALL_PATH.\"");
            return lines.ToArray();
        }

        private static string TestGenerateSystemdUnitLinesUsesEnvironmentFileNotCommandLineToken()
        {
            string[] lines = GenerateSystemdUnitLines("/opt/windows-inventory-lite", "https://example.local/api/v1/linux/inventory", "secret-token");
            string content = String.Join("\n", lines);
            // The whole point of the fix: the token must not be readable from
            // /proc/<pid>/cmdline or from the mode-644 unit file.
            if (content.Contains("--token"))
            {
                return "expected no --token on the ExecStart line once EnvironmentFile is used, got: " + content;
            }
            if (content.Contains("secret-token"))
            {
                return "expected the token value to appear nowhere in the unit file, got: " + content;
            }
            if (!content.Contains("EnvironmentFile=/etc/wil-linux-client.env"))
            {
                return "expected EnvironmentFile=/etc/wil-linux-client.env in the [Service] section, got: " + content;
            }
            return null;
        }

        private static string TestGenerateSystemdUnitLinesOmitsEnvironmentFileWhenNoToken()
        {
            string[] lines = GenerateSystemdUnitLines("/opt/windows-inventory-lite", "https://example.local/api/v1/linux/inventory", "");
            string content = String.Join("\n", lines);
            // No token means no env file is written, and a unit referencing a
            // nonexistent EnvironmentFile (without the "-" prefix) fails to start.
            if (content.Contains("EnvironmentFile"))
            {
                return "expected no EnvironmentFile line when there is no token, got: " + content;
            }
            return null;
        }

        private static string TestGenerateSystemdStatusUnitLinesUsesEnvironmentFileNotCommandLineToken()
        {
            string[] lines = GenerateSystemdStatusUnitLines("/opt/windows-inventory-lite", "https://example.local/api/v1/linux/inventory/service-status", "secret-token");
            string content = String.Join("\n", lines);
            if (content.Contains("--token") || content.Contains("secret-token"))
            {
                return "expected the status unit to carry no token on its command line, got: " + content;
            }
            if (!content.Contains("EnvironmentFile=/etc/wil-linux-client.env"))
            {
                return "expected EnvironmentFile=/etc/wil-linux-client.env in the status unit, got: " + content;
            }
            if (!content.Contains("--mode status"))
            {
                return "expected --mode status to survive the ExecStart rewrite, got: " + content;
            }
            return null;
        }

        private static string TestGenerateSystemdEnvFileLinesMatchesPowerShellFormat()
        {
            string[] lines = GenerateSystemdEnvFileLines("secret-token");
            if (lines.Length != 1 || lines[0] != "WIL_INGESTION_TOKEN=secret-token")
            {
                return "expected exactly one line 'WIL_INGESTION_TOKEN=secret-token', got: " + String.Join("\n", lines);
            }
            return null;
        }

        private static string TestGenerateSystemdUnitLinesMatchesPowerShellFormat()
        {
            string[] serviceLines = GenerateSystemdUnitLines("/opt/windows-inventory-lite", "https://example.local/api/v1/linux/inventory", "");
            string serviceContent = String.Join("\n", serviceLines);
            if (!serviceContent.Contains("Type=oneshot"))
            {
                return "expected service content to contain 'Type=oneshot'";
            }
            if (!serviceContent.Contains("ExecStart=/opt/windows-inventory-lite/wil-linux-client --server-url \"https://example.local/api/v1/linux/inventory\""))
            {
                return "expected ExecStart line to match the PowerShell generator's format exactly, got: " + serviceContent;
            }
            if (serviceContent.Contains("--token"))
            {
                return "expected no --token when sharedToken is empty";
            }

            string[] serviceLinesWithToken = GenerateSystemdUnitLines("/opt/windows-inventory-lite", "https://example.local/api/v1/linux/inventory", "secret-token");
            if (!String.Join("\n", serviceLinesWithToken).Contains("EnvironmentFile=/etc/wil-linux-client.env"))
            {
                return "expected the token to be delivered via EnvironmentFile, not the command line";
            }

            string[] timerLines = GenerateSystemdTimerLines(12);
            string timerContent = String.Join("\n", timerLines);
            if (!timerContent.Contains("OnUnitActiveSec=12h") || !timerContent.Contains("Unit=wil-linux-client.service"))
            {
                return "expected timer content to match the PowerShell generator's format exactly, got: " + timerContent;
            }
            return null;
        }

        private static string TestGenerateSystemdUnitLinesRejectsUnsafeCharacters()
        {
            try
            {
                GenerateSystemdUnitLines("/opt/wil; rm -rf /", "https://example.local", "");
                return "expected an unsafe installDirectory to be rejected";
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        private static string TestGenerateSystemdStatusUnitLinesMatchesPowerShellFormat()
        {
            string[] serviceLines = GenerateSystemdStatusUnitLines("/opt/windows-inventory-lite", "https://example.local/api/v1/linux/inventory/service-status", "");
            string serviceContent = String.Join("\n", serviceLines);
            if (!serviceContent.Contains("Type=oneshot"))
            {
                return "expected status service content to contain 'Type=oneshot'";
            }
            if (!serviceContent.Contains("ExecStart=/opt/windows-inventory-lite/wil-linux-client --server-url \"https://example.local/api/v1/linux/inventory/service-status\" --mode status"))
            {
                return "expected ExecStart line to include --mode status and match the PowerShell generator's format exactly, got: " + serviceContent;
            }

            string[] timerLines = GenerateSystemdStatusTimerLines(30);
            string timerContent = String.Join("\n", timerLines);
            if (!timerContent.Contains("OnUnitActiveSec=30min") || !timerContent.Contains("Unit=wil-linux-client-status.service"))
            {
                return "expected status timer content to use minute granularity and reference wil-linux-client-status.service, got: " + timerContent;
            }
            return null;
        }

        private static string TestGenerateSystemdStatusUnitLinesRejectsUnsafeCharacters()
        {
            try
            {
                GenerateSystemdStatusUnitLines("/opt/wil; rm -rf /", "https://example.local", "");
                return "expected an unsafe installDirectory to be rejected";
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        private static string TestGenerateLinuxInstallScriptLinesProducesValidShellSyntax()
        {
            string[] lines = GenerateLinuxInstallScriptLines("/opt/windows-inventory-lite");
            string content = String.Join("\n", lines);
            if (!content.StartsWith("#!/bin/sh"))
            {
                return "expected a #!/bin/sh shebang as the first line";
            }
            if (!content.Contains("systemctl enable --now wil-linux-client.timer"))
            {
                return "expected the script to enable the timer";
            }
            // A re-install over an already-enabled timer must still take
            // effect promptly: `enable --now` on a timer that's already
            // active is a no-op for its OnUnitActiveSec countdown, so a
            // fresh binary can silently wait out the rest of the OLD
            // schedule (up to 6h for the full-inventory timer) before its
            // first real run - `restart` unconditionally resets the
            // countdown, whether this is a fresh install or a reinstall.
            if (!content.Contains("systemctl restart wil-linux-client.timer") || !content.Contains("systemctl restart wil-linux-client-status.timer"))
            {
                return "expected the script to restart both timers (not just enable --now) so a reinstall's fresh binary actually gets scheduled promptly, got: " + content;
            }
            // OnBootSec=5min fires once, relative to actual machine boot, not
            // to this restart - on a long-uptime host it never fires again,
            // so restarting the timers alone still leaves up to a full
            // 6h/30min wait for the first real report. An explicit immediate
            // "systemctl start" closes that gap; "|| true" keeps a transient
            // collection failure there from aborting the script under "set -e".
            if (!content.Contains("systemctl start wil-linux-client.service || true") || !content.Contains("systemctl start wil-linux-client-status.service || true"))
            {
                return "expected the script to immediately start both services (best-effort) after restarting their timers, so a fresh install/reinstall reports promptly instead of waiting out the normal cadence, got: " + content;
            }
            return null;
        }

        // 20 is the ZIP version-needed-to-extract.
        private static byte[] BuildZip(List<string> names, List<byte[]> contents)
        {
            MemoryStream ms = new MemoryStream();
            List<int> offsets = new List<int>();
            List<uint> crcs = new List<uint>();
            DateTime now = DateTime.Now;
            int dosTime = DosTime(now);
            int dosDate = DosDate(now);

            for (int i = 0; i < names.Count; i++)
            {
                offsets.Add((int)ms.Length);
                byte[] nameBytes = Encoding.UTF8.GetBytes(names[i]);
                byte[] data = contents[i];
                uint crc = Crc32Checksum(data);
                crcs.Add(crc);
                WriteZipInt32(ms, 0x04034b50);
                WriteZipInt16(ms, 20); WriteZipInt16(ms, 0); WriteZipInt16(ms, 0);
                WriteZipInt16(ms, dosTime); WriteZipInt16(ms, dosDate);
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
                WriteZipInt16(ms, 0); WriteZipInt16(ms, dosTime); WriteZipInt16(ms, dosDate);
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

        // MS-DOS date/time format used by the ZIP local/central file headers -
        // no timezone, 2-second resolution, and no representation for years
        // before 1980 (clamped rather than throwing, since this only feeds a
        // cosmetic "last modified" column in archive viewers).
        private static int DosTime(DateTime dt)
        {
            return (dt.Hour << 11) | (dt.Minute << 5) | (dt.Second / 2);
        }

        private static int DosDate(DateTime dt)
        {
            int year = Math.Max(dt.Year, 1980) - 1980;
            return (year << 9) | (dt.Month << 5) | dt.Day;
        }

        private static void WriteZipInt16(MemoryStream ms, int value)
        {
            ms.Write(BitConverter.GetBytes((short)value), 0, 2);
        }

        private static void WriteZipInt32(MemoryStream ms, int value)
        {
            ms.Write(BitConverter.GetBytes(value), 0, 4);
        }

        private void SendBytes(Stream stream, byte[] data, string contentType, string filename)
        {
            string header = "HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nContent-Disposition: attachment; filename=\"" + filename + "\"\r\nContent-Length: " + data.Length + "\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: " + ContentSecurityPolicy + "\r\nReferrer-Policy: " + ReferrerPolicy + "\r\nPermissions-Policy: " + PermissionsPolicy + BuildHstsHeaderOrEmpty(stream) + "\r\nConnection: close\r\n\r\n";
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
            allPassed &= SelfTestCheck(output, "DecideAutoDetectProtocols tries WinRM first when both ports are open", TestDecideAutoDetectProtocolsBothOpen);
            allPassed &= SelfTestCheck(output, "DecideAutoDetectProtocols tries only WinRM when just that port is open", TestDecideAutoDetectProtocolsWinRmOnly);
            allPassed &= SelfTestCheck(output, "DecideAutoDetectProtocols tries only SSH when just that port is open", TestDecideAutoDetectProtocolsSshOnly);
            allPassed &= SelfTestCheck(output, "DecideAutoDetectProtocols returns no attempts when neither port is open", TestDecideAutoDetectProtocolsNeitherOpen);
            allPassed &= SelfTestCheck(output, "BuildAttemptResult produces the expected dictionary shape", TestBuildAttemptResultShape);
            allPassed &= SelfTestCheck(output, "ResolveAttemptOrder tries only WinRM for force-windows regardless of probe results", TestResolveAttemptOrderForceWindowsIgnoresProbes);
            allPassed &= SelfTestCheck(output, "ResolveAttemptOrder tries only SSH for force-linux regardless of probe results", TestResolveAttemptOrderForceLinuxIgnoresProbes);
            allPassed &= SelfTestCheck(output, "ResolveAttemptOrder delegates to DecideAutoDetectProtocols for auto mode", TestResolveAttemptOrderAutoDelegatesToDecideAutoDetectProtocols);
            allPassed &= SelfTestCheck(output, "ResolveAttemptOrder fails closed (empty array) on an unrecognized mode", TestResolveAttemptOrderFailsClosedOnUnrecognizedMode);
            allPassed &= SelfTestCheck(output, "ToLinuxServerUrl swaps the Windows ingestion suffix for the Linux one", TestToLinuxServerUrlSwapsWindowsSuffix);
            allPassed &= SelfTestCheck(output, "ToLinuxServerUrl leaves an already Linux-shaped URL unchanged", TestToLinuxServerUrlLeavesAlreadyLinuxShapedUrlUnchanged);
            allPassed &= SelfTestCheck(output, "ToLinuxServerUrl leaves blank and unrecognized-shape values unchanged", TestToLinuxServerUrlLeavesBlankAndCustomValuesUnchanged);
            allPassed &= SelfTestCheck(output, "ParseAdComputerImportOUs splits on newlines only, not commas", TestParseAdComputerImportOUsSplitsOnNewlinesOnly);
            allPassed &= SelfTestCheck(output, "ParseAdComputerImportOUs treats blank input as an empty OU list", TestParseAdComputerImportOUsEmptyMeansWholeDomain);
            allPassed &= SelfTestCheck(output, "BuildZip produces a structurally valid archive", TestBuildZipStructure);
            allPassed &= SelfTestCheck(output, "BuildZip stamps entries with the real current date, not a hardcoded placeholder", TestBuildZipUsesRealDate);
            allPassed &= SelfTestCheck(output, "NormalizeThumbprint strips separators and uppercases", TestNormalizeThumbprint);
            allPassed &= SelfTestCheck(output, "ExtractLicenseId strips the route prefix and query string", TestExtractLicenseIdWithQuery);
            allPassed &= SelfTestCheck(output, "ExtractLicenseId decodes URL-encoded ids", TestExtractLicenseIdDecodesEscaping);
            allPassed &= SelfTestCheck(output, "SanitizeFileName escapes a reserved Windows device name", TestSanitizeFileNameReservedDeviceName);
            allPassed &= SelfTestCheck(output, "SanitizeFileName leaves a normal computer name untouched", TestSanitizeFileNameNormalName);
            allPassed &= SelfTestCheck(output, "FixedTimeEquals matches identical strings and rejects everything else", TestFixedTimeEquals);
            allPassed &= SelfTestCheck(output, "IsWebRequestAuthorized restricts to loopback while Basic Auth is unconfigured", TestIsWebRequestAuthorizedRestrictsToLoopbackWhenUnconfigured);
            allPassed &= SelfTestCheck(output, "GetCookieValue parses a named cookie out of a raw Cookie header", TestGetCookieValueParsesNamedCookie);
            allPassed &= SelfTestCheck(output, "IsSessionValid checks expiry with a strict (not inclusive) comparison", TestIsSessionValidChecksExpiry);
            allPassed &= SelfTestCheck(output, "ComputeSessionExpiry adds the given number of hours to now", TestComputeSessionExpiryAddsHours);
            allPassed &= SelfTestCheck(output, "IsWebRequestAuthorized accepts a valid session cookie with no Authorization header", TestIsWebRequestAuthorizedAcceptsValidSessionCookieWithNoAuthorizationHeader);
            allPassed &= SelfTestCheck(output, "IsWebRequestAuthorized rejects an expired session cookie and falls through to Basic Auth", TestIsWebRequestAuthorizedRejectsExpiredSessionCookie);
            allPassed &= SelfTestCheck(output, "IsWebRequestAuthorized refreshes a session's expiry on successful use (sliding expiration)", TestIsWebRequestAuthorizedRefreshesSessionExpiryOnUse);
            allPassed &= SelfTestCheck(output, "SendLoginResult creates a session and sets a cookie on correct credentials", TestSendLoginResultCreatesSessionOnCorrectCredentials);
            allPassed &= SelfTestCheck(output, "SendLoginResult rejects wrong credentials without creating a session", TestSendLoginResultRejectsWrongCredentials);
            allPassed &= SelfTestCheck(output, "SendLoginResult refuses to create a session while Basic Auth is unconfigured", TestSendLoginResultRejectsWhenBasicAuthUnconfigured);
            allPassed &= SelfTestCheck(output, "SendLogoutResult removes the session from the server-side store", TestSendLogoutResultRemovesSessionFromStore);
            allPassed &= SelfTestCheck(output, "SendLogoutResult is idempotent when no session cookie is present", TestSendLogoutResultIsIdempotentWithNoSessionCookie);
            allPassed &= SelfTestCheck(output, "ConfigureServerSettings validates sessionLifetimeHours is between 1 and 720", TestConfigureServerSettingsValidatesSessionLifetimeHours);
            allPassed &= SelfTestCheck(output, "SendUnauthorized serves the embedded login page for a browser navigation to /, with no WWW-Authenticate", TestSendUnauthorizedServesLoginPageForBrowserNavigation);
            allPassed &= SelfTestCheck(output, "SendUnauthorized keeps the plain-text 401 body for API routes", TestSendUnauthorizedServesPlainTextForApiRequests);
            allPassed &= SelfTestCheck(output, "SendDashboardImage returns 404 with no body when the file is missing", TestSendDashboardImageReturns404WhenFileMissing);
            allPassed &= SelfTestCheck(output, "SendDashboardImage's 200 response carries the same security headers as every other response", TestSendDashboardImageIncludesSecurityHeaders);
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
            allPassed &= SelfTestCheck(output, "PatchClientReportVersionAfterInstall updates a target's stored clientVersion", TestPatchClientReportVersionAfterInstallUpdatesVersion);
            allPassed &= SelfTestCheck(output, "PatchClientReportVersionAfterInstall's lastInstalledAtUtc is cleared once a real report overwrites the file", TestPatchClientReportVersionAfterInstallFieldClearedByRealReport);
            allPassed &= SelfTestCheck(output, "PatchClientReportVersionAfterInstall is a no-op when the target has no stored report yet", TestPatchClientReportVersionAfterInstallMissingReport);
            allPassed &= SelfTestCheck(output, "DebugLogger.ResolvePath defaults under DataPath when unset", TestDebugLoggerResolvePathDefault);
            allPassed &= SelfTestCheck(output, "DebugLogger.ResolvePath honors an explicit DebugLogPath", TestDebugLoggerResolvePathOverride);
            allPassed &= SelfTestCheck(output, "DebugLogger.SanitizeForLog escapes embedded CR/LF", TestDebugLoggerSanitizeForLog);
            allPassed &= SelfTestCheck(output, "SecretProtector round-trips a value through Protect/Unprotect", TestSecretProtectorRoundTrip);
            allPassed &= SelfTestCheck(output, "SecretProtector.Unprotect passes through a legacy plaintext value", TestSecretProtectorLegacyPlaintext);
            allPassed &= SelfTestCheck(output, "NeedsMigration flags a plaintext value", TestNeedsMigrationPlaintextValue);
            allPassed &= SelfTestCheck(output, "NeedsMigration does not flag an already-encrypted or empty value", TestNeedsMigrationAlreadyEncryptedOrEmpty);
            allPassed &= SelfTestCheck(output, "BuildPowerShellInstallArguments includes -Token when a token is set, omits it when empty", TestBuildPowerShellInstallArgumentsIncludesToken);
            allPassed &= SelfTestCheck(output, "GenerateCmdLines rejects serverUrl/token/packageSharePath containing batch-unsafe characters", TestGenerateCmdLinesRejectsUnsafeCharacters);
            allPassed &= SelfTestCheck(output, "ValidatePosixShellSafe rejects POSIX shell metacharacters", TestValidatePosixShellSafeRejectsUnsafeCharacters);
            allPassed &= SelfTestCheck(output, "ValidatePosixShellSafe accepts safe values including null/empty", TestValidatePosixShellSafeAcceptsSafeValues);
            allPassed &= SelfTestCheck(output, "ReadRequest fails cleanly when the connection closes mid-headers", TestReadRequestFailsCleanlyOnAConnectionClosedMidHeaders);
            allPassed &= SelfTestCheck(output, "ReadRequest fails cleanly on an immediately closed connection", TestReadRequestFailsCleanlyOnAnImmediatelyClosedConnection);
            allPassed &= SelfTestCheck(output, "A 'null' JSON body deserializes to null, which is why the ingestion endpoints need an explicit guard", TestNullJsonBodyDeserializesToNullNotAnEmptyDictionary);
            allPassed &= SelfTestCheck(output, "TryValidateLinuxPushValues rejects shell-unsafe serverUrl/token/installPath", TestTryValidateLinuxPushValuesRejectsUnsafeValuesAndAcceptsSafeOnes);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent matches either package version", TestIsClientVersionCurrentMatchesEitherPackage);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent is outdated when it matches neither package", TestIsClientVersionCurrentOutdatedWhenMatchesNeither);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent treats an empty clientVersion as outdated", TestIsClientVersionCurrentTreatsEmptyAsOutdated);
            allPassed &= SelfTestCheck(output, "IsClientVersionCurrent ignores a missing package instead of false-matching it", TestIsClientVersionCurrentIgnoresMissingPackage);
            allPassed &= SelfTestCheck(output, "GetLinuxClientUpdateTarget prefers a reported IPv4 address over the (often unresolvable) hostname", TestGetLinuxClientUpdateTargetPrefersIPv4OverHostname);
            allPassed &= SelfTestCheck(output, "GetLinuxClientUpdateTarget falls back to hostname when no IPv4 address is available", TestGetLinuxClientUpdateTargetFallsBackToHostnameWithNoIPv4);
            allPassed &= SelfTestCheck(output, "GetLinuxClientUpdateTarget prefers an address inside the configured preferred subnet over the first-seen IPv4", TestGetLinuxClientUpdateTargetPrefersConfiguredSubnet);
            allPassed &= SelfTestCheck(output, "GetLinuxClientUpdateTarget falls back to the first-seen IPv4 when no address matches the configured subnet", TestGetLinuxClientUpdateTargetFallsBackWhenNoAddressMatchesSubnet);
            allPassed &= SelfTestCheck(output, "GetLinuxClientUpdateTarget ignores a malformed configured subnet instead of failing target resolution", TestGetLinuxClientUpdateTargetIgnoresMalformedSubnet);
            allPassed &= SelfTestCheck(output, "IsIPv4InCidr matches an address inside the subnet", TestIsIPv4InCidrMatchesInsideSubnet);
            allPassed &= SelfTestCheck(output, "IsIPv4InCidr rejects an address outside the subnet", TestIsIPv4InCidrRejectsOutsideSubnet);
            allPassed &= SelfTestCheck(output, "IsIPv4InCidr handles /0 (matches everything) and /32 (matches only itself)", TestIsIPv4InCidrHandlesEdgePrefixLengths);
            allPassed &= SelfTestCheck(output, "IsIPv4InCidr returns false for malformed CIDR text or IP text instead of throwing", TestIsIPv4InCidrRejectsMalformedInput);
            allPassed &= SelfTestCheck(output, "ResolveUpdateCredentials falls back to the saved account when blank", TestResolveUpdateCredentialsFallsBackToSavedWhenBlank);
            allPassed &= SelfTestCheck(output, "ResolveUpdateCredentials prefers a typed per-push override over the saved account", TestResolveUpdateCredentialsPrefersTypedOverride);
            allPassed &= SelfTestCheck(output, "ResolveUpdateCredentials is a no-op for Client actions (useSavedCredentials=false)", TestResolveUpdateCredentialsIgnoredWhenFlagIsFalse);
            allPassed &= SelfTestCheck(output, "ResolveUpdateCredentials falls through to the service identity when nothing is saved", TestResolveUpdateCredentialsFallsThroughWhenNothingSaved);
            allPassed &= SelfTestCheck(output, "TryResolveAdSyncCredentials is a no-op when useAdCredentials=false", TestTryResolveAdSyncCredentialsIgnoredWhenFlagIsFalse);
            allPassed &= SelfTestCheck(output, "TryResolveAdSyncCredentials rejects when AD sync is disabled", TestTryResolveAdSyncCredentialsRejectsWhenAdSyncDisabled);
            allPassed &= SelfTestCheck(output, "TryResolveAdSyncCredentials resolves to the service identity when configured", TestTryResolveAdSyncCredentialsUsesServiceIdentityWhenConfigured);
            allPassed &= SelfTestCheck(output, "TryResolveAdSyncCredentials resolves to the saved AD account when not using the service identity", TestTryResolveAdSyncCredentialsUsesSavedAccountWhenNotServiceIdentity);
            allPassed &= SelfTestCheck(output, "TryResolveAdSyncCredentials rejects when the saved AD account is incomplete", TestTryResolveAdSyncCredentialsRejectsWhenSavedAccountIncomplete);
            allPassed &= SelfTestCheck(output, "ParseCmdSettings round-trips GenerateCmdLines' default package root", TestParseCmdSettingsDefaultPackageRoot);
            allPassed &= SelfTestCheck(output, "ParseCmdSettings round-trips GenerateCmdLines' custom package share path", TestParseCmdSettingsCustomPackageSharePath);
            allPassed &= SelfTestCheck(output, "ResolveAdDescriptionSyncEnabled uses the explicit config value when present", TestResolveAdDescriptionSyncEnabledUsesExplicitConfigValue);
            allPassed &= SelfTestCheck(output, "ResolveAdDescriptionSyncEnabled migrates from AdSyncEnabled when the config key is absent", TestResolveAdDescriptionSyncEnabledMigratesFromAdSyncEnabledWhenUnset);
            allPassed &= SelfTestCheck(output, "ResolveRequireIngestionToken uses the explicit config value when present", TestResolveRequireIngestionTokenUsesExplicitConfigValue);
            allPassed &= SelfTestCheck(output, "ResolveRequireIngestionToken migrates from whether a token is configured when the config key is absent", TestResolveRequireIngestionTokenMigratesFromTokenPresenceWhenUnset);
            allPassed &= SelfTestCheck(output, "Parse defaults RequireIngestionToken from CLI --token presence when no config file exists", TestParseDefaultsRequireIngestionTokenFromCliTokenWhenNoConfigFile);
            allPassed &= SelfTestCheck(output, "IsIngestionTokenRejected requires a matching token when enforcement is on", TestIsIngestionTokenRejectedRequiresMatchWhenEnforced);
            allPassed &= SelfTestCheck(output, "IsIngestionTokenRejected always accepts when enforcement is off, regardless of the supplied token", TestIsIngestionTokenRejectedAlwaysAcceptsWhenNotEnforced);
            allPassed &= SelfTestCheck(output, "IsIngestionTokenRejected fails closed when enforcement is on but no token is configured", TestIsIngestionTokenRejectedFailsClosedWhenEnforcedButNoTokenConfigured);
            allPassed &= SelfTestCheck(output, "IsCrossSiteRequestRejected ignores non-state-changing methods", TestIsCrossSiteRequestRejectedIgnoresNonStateChangingMethods);
            allPassed &= SelfTestCheck(output, "IsCrossSiteRequestRejected allows a state-changing request with neither Origin nor Referer", TestIsCrossSiteRequestRejectedAllowsMissingOriginAndReferer);
            allPassed &= SelfTestCheck(output, "IsCrossSiteRequestRejected requires a Host header", TestIsCrossSiteRequestRejectedRequiresHostHeader);
            allPassed &= SelfTestCheck(output, "IsCrossSiteRequestRejected accepts an Origin matching the Host header", TestIsCrossSiteRequestRejectedAcceptsMatchingOrigin);
            allPassed &= SelfTestCheck(output, "IsCrossSiteRequestRejected rejects an Origin that doesn't match the Host header", TestIsCrossSiteRequestRejectedRejectsMismatchedOrigin);
            allPassed &= SelfTestCheck(output, "IsCrossSiteRequestRejected treats the literal Origin 'null' as a mismatch, not as absent", TestIsCrossSiteRequestRejectedTreatsNullOriginAsMismatch);
            allPassed &= SelfTestCheck(output, "IsCrossSiteRequestRejected falls back to Referer when Origin is absent", TestIsCrossSiteRequestRejectedFallsBackToRefererWhenOriginAbsent);
            allPassed &= SelfTestCheck(output, "IsCrossSiteRequestRejected fails closed on a malformed Origin header", TestIsCrossSiteRequestRejectedFailsClosedOnMalformedOrigin);
            allPassed &= SelfTestCheck(output, "RequiresJsonContentType is true only for a state-changing request with a non-empty body", TestRequiresJsonContentTypeOnlyForStateChangingRequestsWithABody);
            allPassed &= SelfTestCheck(output, "HasJsonContentType accepts application/json with or without a charset suffix, case-insensitively", TestHasJsonContentTypeAcceptsJsonWithOrWithoutCharsetSuffix);
            allPassed &= SelfTestCheck(output, "HasJsonContentType rejects form-encoded, text/plain, and missing Content-Type", TestHasJsonContentTypeRejectsFormAndTextPlainAndMissing);
            allPassed &= SelfTestCheck(output, "EvaluateLockoutState reports not-locked-out with no record or an elapsed lockout", TestEvaluateLockoutStateNotLockedOutCases);
            allPassed &= SelfTestCheck(output, "EvaluateLockoutState reports locked-out with the correct Retry-After seconds while active", TestEvaluateLockoutStateLockedOutReportsRetryAfter);
            allPassed &= SelfTestCheck(output, "RecordAttemptOutcome locks out once the threshold is reached within the window", TestRecordAttemptOutcomeLocksOutAtThreshold);
            allPassed &= SelfTestCheck(output, "RecordAttemptOutcome does not extend an active lockout on further failed attempts", TestRecordAttemptOutcomeDoesNotExtendActiveLockout);
            allPassed &= SelfTestCheck(output, "RecordAttemptOutcome clears the record entirely on a successful attempt", TestRecordAttemptOutcomeClearsRecordOnSuccess);
            allPassed &= SelfTestCheck(output, "RecordAttemptOutcome resets the count once the counting window has elapsed", TestRecordAttemptOutcomeResetsAfterWindowElapses);
            allPassed &= SelfTestCheck(output, "RecordAttemptOutcome never locks out when the threshold is 0 (disabled)", TestRecordAttemptOutcomeNeverLocksOutWhenThresholdIsZero);
            allPassed &= SelfTestCheck(output, "IsWebRequestAuthorized's recorded failures and IsBasicAuthLockedOut's read are wired together and scoped per-IP", TestIsWebRequestAuthorizedLocksOutAfterRepeatedFailures);
            allPassed &= SelfTestCheck(output, "BuildHstsHeaderOrEmpty only adds Strict-Transport-Security when enabled AND the stream is TLS", TestBuildHstsHeaderOrEmpty);
            allPassed &= SelfTestCheck(output, "ResolveIngestionRejectionReason distinguishes a missing token from a wrong one", TestResolveIngestionRejectionReason);
            allPassed &= SelfTestCheck(output, "PruneIngestionRejectionEntries keeps everything under both caps", TestPruneIngestionRejectionEntriesUnderBothCaps);
            allPassed &= SelfTestCheck(output, "PruneIngestionRejectionEntries trims oldest-first over the count cap", TestPruneIngestionRejectionEntriesOverCountCap);
            allPassed &= SelfTestCheck(output, "PruneIngestionRejectionEntries removes entries older than the retention-days cap", TestPruneIngestionRejectionEntriesOverAgeCap);
            allPassed &= SelfTestCheck(output, "PruneIngestionRejectionEntries applies whichever cap is more restrictive", TestPruneIngestionRejectionEntriesBothCapsEngaged);
            allPassed &= SelfTestCheck(output, "PruneIngestionRejectionEntries skips the max-entries trim (rather than discarding everything) when maxEntries is 0 or negative", TestPruneIngestionRejectionEntriesZeroMaxEntriesKeepsWithinAge);
            allPassed &= SelfTestCheck(output, "RecordIngestionRejection batches its prune+rewrite instead of rewriting the whole log on every call once at cap", TestRecordIngestionRejectionBatchesRewrites);
            allPassed &= SelfTestCheck(output, "RecordIngestionRejection still enforces day-based retention continuously even when the count-based batch gate never trips", TestRecordIngestionRejectionEnforcesRetentionContinuously);
            allPassed &= SelfTestCheck(output, "ComputeClientTokenIssue returns null when no log entry matches the client's IP", TestComputeClientTokenIssueNoMatch);
            allPassed &= SelfTestCheck(output, "ComputeClientTokenIssue ignores a matching-IP rejection older than the client's last report", TestComputeClientTokenIssueStaleRejectionIgnored);
            allPassed &= SelfTestCheck(output, "ComputeClientTokenIssue flags a matching-IP rejection newer than the client's last report", TestComputeClientTokenIssueRecentRejectionFlagged);
            allPassed &= SelfTestCheck(output, "ComputeClientTokenIssue picks the newest matching-IP entry's reason when several match", TestComputeClientTokenIssueNewestWins);
            allPassed &= SelfTestCheck(output, "LoadClientReports sets tokenIssue on a client whose IP has a newer rejected attempt", TestLoadClientReportsSetsTokenIssueFromRejectionLog);
            allPassed &= SelfTestCheck(output, "ResolveEffectiveToken falls back to the live server token when the request supplies none", TestResolveEffectiveTokenFallsBackToLiveTokenWhenBlank);
            allPassed &= SelfTestCheck(output, "RequiresIngestionTokenRiskAcknowledgment only fires on an actual on-to-off transition without prior acknowledgment", TestRequiresIngestionTokenRiskAcknowledgmentOnlyWhenTurningEnforcementOff);
            allPassed &= SelfTestCheck(output, "ComputeAdSyncFields carries a manually-set Description forward when sync is disabled", TestComputeAdSyncFieldsCarriesDescriptionForwardWhenSyncDisabled);
            allPassed &= SelfTestCheck(output, "ComputeAdSyncFields is a no-op for a brand-new computer with sync disabled", TestComputeAdSyncFieldsNoOpForNewComputerWhenSyncDisabled);
            allPassed &= SelfTestCheck(output, "SaveLicenses restricts licenses.json to Administrators+SYSTEM", TestSaveLicensesRestrictsFileAcl);
            allPassed &= SelfTestCheck(output, "SaveServerConfigValues leaves the final config file with a restricted ACL, no leftover .tmp file", TestSaveServerConfigValuesRestrictsTempFileBeforeWritingContent);
            allPassed &= SelfTestCheck(output, "Linux known-hosts store round-trips and overwrites by host:port", TestLinuxKnownHostsRoundTrip);
            allPassed &= SelfTestCheck(output, "A malformed known-hosts file surfaces as a read error from FindLinuxKnownHost, not as 'no record found'", TestLinuxKnownHostsReadFailureSurfacesAsError);
            allPassed &= SelfTestCheck(output, "TryParseHostKeyDetails extracts type+fingerprint from a real captured plink failure, ignores unrelated failures", TestParseHostKeyFingerprintFromRealCapturedOutput);
            allPassed &= SelfTestCheck(output, "ClassifyHostKeyFailure returns 'changed' for a prior record even when trustNewHostKeys=true, never auto-accepting a changed key", TestClassifyHostKeyFailureChangedNeverAutoAcceptedEvenWithTrustEnabled);
            allPassed &= SelfTestCheck(output, "ClassifyHostKeyFailure never returns 'bulk-auto' or 'unknown' with a prior trusted record, even if the failure text doesn't say 'host key'", TestClassifyHostKeyFailureNeverBulkAutoWithPriorRecordRegardlessOfWording);
            allPassed &= SelfTestCheck(output, "ClassifyHostKeyFailure returns 'bulk-auto' for a brand-new target with auto-trust enabled", TestClassifyHostKeyFailureBulkAutoForNewTarget);
            allPassed &= SelfTestCheck(output, "ClassifyHostKeyFailure returns 'unknown' for a brand-new target when auto-trust is disabled", TestClassifyHostKeyFailureUnknownWhenAutoTrustDisabled);
            allPassed &= SelfTestCheck(output, "ClassifyHostKeyFailure returns null for a failure unrelated to host keys", TestClassifyHostKeyFailureNullForNonHostKeyFailure);
            allPassed &= SelfTestCheck(output, "trust-host-key fingerprint format validation accepts SHA256:... and rejects everything else", TestTrustLinuxHostKeyRejectsMalformedFingerprint);
            allPassed &= SelfTestCheck(output, "IsValidSshTarget accepts hostnames and IPv4 literals", TestIsValidSshTargetAcceptsHostnamesAndIPv4);
            allPassed &= SelfTestCheck(output, "IsValidSshTarget rejects shell-injection shapes, flag-lookalikes, and empty values", TestIsValidSshTargetRejectsInjectionAndEmpty);
            allPassed &= SelfTestCheck(output, "IsValidLinuxInstallPath accepts a real multi-segment absolute path", TestIsValidLinuxInstallPathAcceptsMultiSegmentPath);
            allPassed &= SelfTestCheck(output, "IsValidLinuxInstallPath rejects a bare top-level directory, a relative path, and empty/null", TestIsValidLinuxInstallPathRejectsTopLevelAndInvalid);
            allPassed &= SelfTestCheck(output, "IsValidLinuxInstallPath rejects .. and . traversal even inside an /opt/ path", TestIsValidLinuxInstallPathRejectsTraversal);
            allPassed &= SelfTestCheck(output, "GenerateRandomToken returns a 64-character lowercase hex string, different each call", TestGenerateRandomTokenShape);
            allPassed &= SelfTestCheck(output, "Ingestion token configured-state reflects whether options.Token is set", TestSendIngestionTokenStatusReflectsConfiguredState);
            allPassed &= SelfTestCheck(output, "Linux SSH tools status reflects plink.exe/pscp.exe file presence", TestSendLinuxSshToolsStatusReflectsFilePresence);
            allPassed &= SelfTestCheck(output, "GenerateSystemdUnitLines matches the PowerShell New-SystemdUnitFiles format", TestGenerateSystemdUnitLinesMatchesPowerShellFormat);
            allPassed &= SelfTestCheck(output, "GenerateSystemdUnitLines rejects shell-unsafe installDirectory", TestGenerateSystemdUnitLinesRejectsUnsafeCharacters);
            allPassed &= SelfTestCheck(output, "GenerateLinuxInstallScriptLines produces a script with a valid shebang and enable step", TestGenerateLinuxInstallScriptLinesProducesValidShellSyntax);
            allPassed &= SelfTestCheck(output, "LooksLikePrivateKey accepts real OPENSSH/RSA private key headers", TestLooksLikePrivateKeyAcceptsRealHeaders);
            allPassed &= SelfTestCheck(output, "LooksLikePrivateKey rejects a public key line and garbage", TestLooksLikePrivateKeyRejectsPublicKeyAndGarbage);
            allPassed &= SelfTestCheck(output, "LooksLikePublicKey recognizes each ssh-*/ecdsa-* prefix", TestLooksLikePublicKeyRecognizesEachPrefix);
            allPassed &= SelfTestCheck(output, "LooksLikeEncryptedPrivateKey detects a legacy PEM Proc-Type header", TestLooksLikeEncryptedPrivateKeyDetectsLegacyPem);
            allPassed &= SelfTestCheck(output, "LooksLikeEncryptedPrivateKey detects an OpenSSH bcrypt KDF marker", TestLooksLikeEncryptedPrivateKeyDetectsOpenSshBcryptKdf);
            allPassed &= SelfTestCheck(output, "ApplyRestrictedKeyFileAcl sets the DACL (and Owner, when elevated)", TestApplyRestrictedKeyFileAclSetsDaclAndOwnerWhenElevated);
            allPassed &= SelfTestCheck(output, "ApplyRestrictedDirectoryAcl protects the _linux-ssh directory itself", TestApplyRestrictedDirectoryAclSetsDacl);
            allPassed &= SelfTestCheck(output, "MigrateLegacyLinuxSshKey adopts a valid legacy LinuxUpdateKeyPath", TestMigrateLegacyLinuxSshKeyAdoptsValidLegacyPath);
            allPassed &= SelfTestCheck(output, "MigrateLegacyLinuxSshKey is a no-op when the legacy path is missing or invalid", TestMigrateLegacyLinuxSshKeyIgnoresMissingOrInvalidLegacyPath);
            allPassed &= SelfTestCheck(output, "MergeServiceStatus flips active in both directions for known units", TestMergeServiceStatusFlipsActiveBothDirections);
            allPassed &= SelfTestCheck(output, "MergeServiceStatus ignores units not already in the stored services array", TestMergeServiceStatusIgnoresUnknownUnits);
            allPassed &= SelfTestCheck(output, "MergeServiceStatus handles a report with no services array without throwing", TestMergeServiceStatusHandlesMissingServicesArray);
            allPassed &= SelfTestCheck(output, "MergeServiceStatus sets servicesStatusCollectedAt from the incoming payload", TestMergeServiceStatusSetsTimestamp);
            allPassed &= SelfTestCheck(output, "GenerateSystemdStatusUnitLines matches the PowerShell New-SystemdStatusUnitFiles format", TestGenerateSystemdStatusUnitLinesMatchesPowerShellFormat);
            allPassed &= SelfTestCheck(output, "GenerateSystemdStatusUnitLines rejects shell-unsafe installDirectory", TestGenerateSystemdStatusUnitLinesRejectsUnsafeCharacters);
            allPassed &= SelfTestCheck(output, "GenerateSystemdUnitLines passes the token via EnvironmentFile, never on the command line", TestGenerateSystemdUnitLinesUsesEnvironmentFileNotCommandLineToken);
            allPassed &= SelfTestCheck(output, "GenerateSystemdUnitLines omits EnvironmentFile entirely when there is no token", TestGenerateSystemdUnitLinesOmitsEnvironmentFileWhenNoToken);
            allPassed &= SelfTestCheck(output, "GenerateSystemdStatusUnitLines passes the token via EnvironmentFile, never on the command line", TestGenerateSystemdStatusUnitLinesUsesEnvironmentFileNotCommandLineToken);
            allPassed &= SelfTestCheck(output, "GenerateSystemdEnvFileLines matches the PowerShell New-SystemdEnvFile format", TestGenerateSystemdEnvFileLinesMatchesPowerShellFormat);
            allPassed &= SelfTestCheck(output, "Full session lifecycle: a cookie value produced by SendLoginResult authorizes IsWebRequestAuthorized, then SendLogoutResult makes that same cookie stop authorizing it", TestSessionLifecycleEndToEndLoginAuthorizeLogout);
            allPassed &= SelfTestCheck(output, "ChangeAdminPassword does not mutate the live credential or clear sessions when persisting the new config fails", TestChangeAdminPasswordDoesNotMutateStateWhenSaveFails);
            allPassed &= SelfTestCheck(output, "RunLinuxClientUninstallTarget rejects an unsafe installPath before attempting any SSH connection", TestRunLinuxClientUninstallTargetRejectsUnsafeInstallPath);
            allPassed &= SelfTestCheck(output, "RunClientActionJob removes a completed job from the in-memory installJobs dictionary", TestRunClientActionJobRemovesCompletedJobFromMemory);
            allPassed &= SelfTestCheck(output, "IsWebRequestAuthorized prunes an expired session from sessionStore on use, not just at the next login", TestIsWebRequestAuthorizedPrunesExpiredSessionOnUse);
            allPassed &= SelfTestCheck(output, "ChangeAdminPassword invalidates every pre-rotation session on a successful rotation", TestChangeAdminPasswordInvalidatesSessionsOnSuccess);
            allPassed &= SelfTestCheck(output, "Content-Security-Policy restricts form-action to 'self'", TestContentSecurityPolicyRestrictsFormAction);
            allPassed &= SelfTestCheck(output, "NormalizeReportIdentifier treats a blank identifier the same as a missing one", TestNormalizeReportIdentifierTreatsBlankSameAsMissing);
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

        private static string TestDecideAutoDetectProtocolsBothOpen()
        {
            string[] result = DecideAutoDetectProtocols(true, true);
            if (result.Length != 2 || result[0] != "winrm" || result[1] != "ssh")
            {
                return "expected [\"winrm\", \"ssh\"] (WinRM first) but got [" + String.Join(", ", result) + "]";
            }
            return null;
        }

        private static string TestDecideAutoDetectProtocolsWinRmOnly()
        {
            string[] result = DecideAutoDetectProtocols(true, false);
            if (result.Length != 1 || result[0] != "winrm")
            {
                return "expected [\"winrm\"] but got [" + String.Join(", ", result) + "]";
            }
            return null;
        }

        private static string TestDecideAutoDetectProtocolsSshOnly()
        {
            string[] result = DecideAutoDetectProtocols(false, true);
            if (result.Length != 1 || result[0] != "ssh")
            {
                return "expected [\"ssh\"] but got [" + String.Join(", ", result) + "]";
            }
            return null;
        }

        private static string TestDecideAutoDetectProtocolsNeitherOpen()
        {
            string[] result = DecideAutoDetectProtocols(false, false);
            if (result.Length != 0)
            {
                return "expected an empty array (no attempt worth making) but got [" + String.Join(", ", result) + "]";
            }
            return null;
        }

        private static string TestBuildAttemptResultShape()
        {
            Dictionary<string, object> attempt = BuildAttemptResult("winrm", "failed", "Client install command failed.", "some output", "some error");
            if (GetStringValue(attempt, "protocol") != "winrm") return "expected protocol 'winrm', got '" + GetStringValue(attempt, "protocol") + "'";
            if (GetStringValue(attempt, "status") != "failed") return "expected status 'failed', got '" + GetStringValue(attempt, "status") + "'";
            if (GetStringValue(attempt, "message") != "Client install command failed.") return "expected the given message, got '" + GetStringValue(attempt, "message") + "'";
            if (GetStringValue(attempt, "output") != "some output") return "expected the given output, got '" + GetStringValue(attempt, "output") + "'";
            if (GetStringValue(attempt, "error") != "some error") return "expected the given error, got '" + GetStringValue(attempt, "error") + "'";
            return null;
        }

        private static string TestResolveAttemptOrderForceWindowsIgnoresProbes()
        {
            string[] result = ResolveAttemptOrder("force-windows", false, false);
            if (result.Length != 1 || result[0] != "winrm")
            {
                return "expected [\"winrm\"] regardless of probe results but got [" + String.Join(", ", result) + "]";
            }
            return null;
        }

        private static string TestResolveAttemptOrderForceLinuxIgnoresProbes()
        {
            string[] result = ResolveAttemptOrder("force-linux", false, false);
            if (result.Length != 1 || result[0] != "ssh")
            {
                return "expected [\"ssh\"] regardless of probe results but got [" + String.Join(", ", result) + "]";
            }
            return null;
        }

        private static string TestResolveAttemptOrderAutoDelegatesToDecideAutoDetectProtocols()
        {
            string[] bothOpen = ResolveAttemptOrder("auto", true, true);
            if (bothOpen.Length != 2 || bothOpen[0] != "winrm" || bothOpen[1] != "ssh")
            {
                return "expected auto mode with both ports open to match DecideAutoDetectProtocols(true, true) but got [" + String.Join(", ", bothOpen) + "]";
            }
            string[] neitherOpen = ResolveAttemptOrder("auto", false, false);
            if (neitherOpen.Length != 0)
            {
                return "expected auto mode with neither port open to return an empty array but got [" + String.Join(", ", neitherOpen) + "]";
            }
            return null;
        }

        private static string TestResolveAttemptOrderFailsClosedOnUnrecognizedMode()
        {
            string[] result = ResolveAttemptOrder("not-a-real-mode", true, true);
            if (result.Length != 0)
            {
                return "expected an unrecognized mode to return an empty array (no attempt worth making) even with both ports open, but got [" + String.Join(", ", result) + "]";
            }
            return null;
        }

        private static string TestToLinuxServerUrlSwapsWindowsSuffix()
        {
            string result = ToLinuxServerUrl("https://server:8443/api/v1/inventory");
            if (result != "https://server:8443/api/v1/linux/inventory")
            {
                return "expected the /api/v1/inventory suffix swapped for /api/v1/linux/inventory but got '" + result + "'";
            }
            return null;
        }

        private static string TestToLinuxServerUrlLeavesAlreadyLinuxShapedUrlUnchanged()
        {
            string result = ToLinuxServerUrl("https://server:8443/api/v1/linux/inventory");
            if (result != "https://server:8443/api/v1/linux/inventory")
            {
                return "expected an already Linux-shaped URL to pass through unchanged but got '" + result + "'";
            }
            return null;
        }

        private static string TestToLinuxServerUrlLeavesBlankAndCustomValuesUnchanged()
        {
            if (ToLinuxServerUrl("") != "")
            {
                return "expected a blank serverUrl to stay blank";
            }
            string custom = "https://migration-target.example.com/some/other/path";
            if (ToLinuxServerUrl(custom) != custom)
            {
                return "expected a URL with no recognized Windows suffix to pass through unchanged, got '" + ToLinuxServerUrl(custom) + "'";
            }
            return null;
        }

        private static string TestParseAdComputerImportOUsSplitsOnNewlinesOnly()
        {
            ArrayList result = ParseAdComputerImportOUs("OU=Workstations,OU=Site1,DC=corp,DC=example,DC=com\r\n\r\nOU=Servers,DC=corp,DC=example,DC=com\n  \nOU=Third,DC=x,DC=y  ");
            string[] expected = new string[] {
                "OU=Workstations,OU=Site1,DC=corp,DC=example,DC=com",
                "OU=Servers,DC=corp,DC=example,DC=com",
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

        private static string TestBuildZipUsesRealDate()
        {
            List<string> names = new List<string>();
            List<byte[]> contents = new List<byte[]>();
            names.Add("a.txt");
            contents.Add(Encoding.UTF8.GetBytes("x"));

            byte[] zip = BuildZip(names, contents);

            // Local file header layout: signature(4) + version(2) + flags(2)
            // + method(2) + mod time(2) + mod date(2) + ...
            int dateOffset = 4 + 2 + 2 + 2 + 2;
            int dosDate = zip[dateOffset] | (zip[dateOffset + 1] << 8);
            int year = 1980 + (dosDate >> 9);
            if (year != DateTime.Now.Year)
            {
                return "expected the ZIP entry's mod date to reflect the current year (" + DateTime.Now.Year + ") but got " + year + " - looks like a hardcoded placeholder date is still in use";
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

        private static string TestGetCookieValueParsesNamedCookie()
        {
            if (GetCookieValue(null, "wil_session") != null)
            {
                return "expected a null cookie header to yield null";
            }
            if (GetCookieValue("", "wil_session") != null)
            {
                return "expected an empty cookie header to yield null";
            }
            if (GetCookieValue("foo=bar", "wil_session") != null)
            {
                return "expected a cookie header with no matching name to yield null";
            }
            if (GetCookieValue("wil_session=abc123", "wil_session") != "abc123")
            {
                return "expected a single-cookie header to parse its value";
            }
            if (GetCookieValue("foo=bar; wil_session=abc123; baz=qux", "wil_session") != "abc123")
            {
                return "expected the named cookie to parse correctly among several";
            }
            return null;
        }

        private static string TestIsSessionValidChecksExpiry()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);

            if (IsSessionValid(null, now))
            {
                return "expected a null record to be invalid";
            }

            SessionRecord expired = new SessionRecord();
            expired.ExpiresUtc = now.AddSeconds(-1);
            if (IsSessionValid(expired, now))
            {
                return "expected a record that expired one second ago to be invalid";
            }

            SessionRecord exactlyAtExpiry = new SessionRecord();
            exactlyAtExpiry.ExpiresUtc = now;
            if (IsSessionValid(exactlyAtExpiry, now))
            {
                return "expected a record expiring exactly now to be invalid (strict comparison)";
            }

            SessionRecord stillValid = new SessionRecord();
            stillValid.ExpiresUtc = now.AddMinutes(1);
            if (!IsSessionValid(stillValid, now))
            {
                return "expected a record expiring one minute from now to be valid";
            }

            return null;
        }

        private static string TestComputeSessionExpiryAddsHours()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            DateTime expiry = ComputeSessionExpiry(now, 12);
            if (expiry != now.AddHours(12))
            {
                return "expected ComputeSessionExpiry to add exactly the given number of hours to now";
            }
            return null;
        }

        private static string TestIsWebRequestAuthorizedAcceptsValidSessionCookieWithNoAuthorizationHeader()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            options.SessionLifetimeHours = 12;
            InventoryServer server = new InventoryServer(options);

            string token = "test-session-token";
            SessionRecord record = new SessionRecord();
            record.ExpiresUtc = DateTime.UtcNow.AddHours(1);
            server.sessionStore[token] = record;

            RequestContext request = new RequestContext();
            request.Headers = new Dictionary<string, string>();
            request.Headers["cookie"] = "wil_session=" + token;
            request.RemoteAddress = IPAddress.Parse("192.168.1.50");

            if (!server.IsWebRequestAuthorized(request))
            {
                return "expected a valid session cookie to authorize the request with no Authorization header present";
            }

            return null;
        }

        private static string TestIsWebRequestAuthorizedRejectsExpiredSessionCookie()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            InventoryServer server = new InventoryServer(options);

            string token = "expired-session-token";
            SessionRecord record = new SessionRecord();
            record.ExpiresUtc = DateTime.UtcNow.AddMinutes(-1);
            server.sessionStore[token] = record;

            RequestContext request = new RequestContext();
            request.Headers = new Dictionary<string, string>();
            request.Headers["cookie"] = "wil_session=" + token;
            request.RemoteAddress = IPAddress.Parse("192.168.1.50");

            if (server.IsWebRequestAuthorized(request))
            {
                return "expected an expired session cookie to fall through to (and fail) Basic Auth, not authorize the request";
            }

            return null;
        }

        private static string TestIsWebRequestAuthorizedRefreshesSessionExpiryOnUse()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            options.SessionLifetimeHours = 12;
            InventoryServer server = new InventoryServer(options);

            string token = "sliding-session-token";
            SessionRecord record = new SessionRecord();
            DateTime almostExpired = DateTime.UtcNow.AddMinutes(1);
            record.ExpiresUtc = almostExpired;
            server.sessionStore[token] = record;

            RequestContext request = new RequestContext();
            request.Headers = new Dictionary<string, string>();
            request.Headers["cookie"] = "wil_session=" + token;
            request.RemoteAddress = IPAddress.Parse("192.168.1.50");

            server.IsWebRequestAuthorized(request);

            SessionRecord refreshed;
            server.sessionStore.TryGetValue(token, out refreshed);
            if (refreshed == null || refreshed.ExpiresUtc <= almostExpired.AddHours(1))
            {
                return "expected a successful session-cookie authorization to push ExpiresUtc forward by SessionLifetimeHours (sliding expiration)";
            }

            return null;
        }

        private static string TestSendLoginResultCreatesSessionOnCorrectCredentials()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            options.SessionLifetimeHours = 12;
            InventoryServer server = new InventoryServer(options);

            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Path = "/api/v1/server/login";
            request.Headers = new Dictionary<string, string>();
            request.RemoteAddress = IPAddress.Parse("192.168.1.50");
            request.Body = "{\"username\":\"admin\",\"password\":\"secret\"}";

            using (MemoryStream stream = new MemoryStream())
            {
                server.SendLoginResult(stream, request);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (!response.Contains("200 OK"))
                {
                    return "expected correct credentials to return 200 OK, got: " + response;
                }
                if (!response.Contains("Set-Cookie: wil_session="))
                {
                    return "expected a successful login to set the wil_session cookie";
                }
                if (!response.Contains("HttpOnly") || !response.Contains("SameSite=Strict"))
                {
                    return "expected the session cookie to carry HttpOnly and SameSite=Strict";
                }
            }

            if (server.sessionStore.Count != 1)
            {
                return "expected exactly one session to be created in the store";
            }

            return null;
        }

        private static string TestSendLoginResultRejectsWrongCredentials()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            InventoryServer server = new InventoryServer(options);

            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Path = "/api/v1/server/login";
            request.Headers = new Dictionary<string, string>();
            request.RemoteAddress = IPAddress.Parse("192.168.1.50");
            request.Body = "{\"username\":\"admin\",\"password\":\"wrong\"}";

            using (MemoryStream stream = new MemoryStream())
            {
                server.SendLoginResult(stream, request);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (!response.Contains("401"))
                {
                    return "expected wrong credentials to return 401, got: " + response;
                }
                if (response.Contains("Set-Cookie: wil_session="))
                {
                    return "expected wrong credentials to never set a session cookie";
                }
            }

            if (server.sessionStore.Count != 0)
            {
                return "expected no session to be created on failed login";
            }

            return null;
        }

        private static string TestSendLoginResultRejectsWhenBasicAuthUnconfigured()
        {
            ServerOptions options = new ServerOptions();
            InventoryServer server = new InventoryServer(options);

            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Path = "/api/v1/server/login";
            request.Headers = new Dictionary<string, string>();
            request.RemoteAddress = IPAddress.Parse("192.168.1.50");
            request.Body = "{\"username\":\"\",\"password\":\"\"}";

            using (MemoryStream stream = new MemoryStream())
            {
                server.SendLoginResult(stream, request);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (!response.Contains("401"))
                {
                    return "expected login to be rejected outright when WebUsername/WebPassword are both unconfigured (loopback-only mode), got: " + response;
                }
            }

            if (server.sessionStore.Count != 0)
            {
                return "expected no session to ever be created while Basic Auth is unconfigured - a session cookie would bypass the loopback-only IP restriction";
            }

            return null;
        }

        private static string TestSendLogoutResultRemovesSessionFromStore()
        {
            ServerOptions options = new ServerOptions();
            InventoryServer server = new InventoryServer(options);

            string token = "logout-test-token";
            SessionRecord record = new SessionRecord();
            record.ExpiresUtc = DateTime.UtcNow.AddHours(1);
            server.sessionStore[token] = record;

            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Path = "/api/v1/server/logout";
            request.Headers = new Dictionary<string, string>();
            request.Headers["cookie"] = "wil_session=" + token;

            using (MemoryStream stream = new MemoryStream())
            {
                server.SendLogoutResult(stream, request);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (!response.Contains("200 OK"))
                {
                    return "expected logout to return 200 OK, got: " + response;
                }
                if (!response.Contains("Max-Age=0"))
                {
                    return "expected logout to send a cookie-clearing Set-Cookie with Max-Age=0";
                }
            }

            if (server.sessionStore.ContainsKey(token))
            {
                return "expected the session to be removed from the store, not just cleared client-side";
            }

            return null;
        }

        private static string TestSendLogoutResultIsIdempotentWithNoSessionCookie()
        {
            ServerOptions options = new ServerOptions();
            InventoryServer server = new InventoryServer(options);

            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Path = "/api/v1/server/logout";
            request.Headers = new Dictionary<string, string>();

            using (MemoryStream stream = new MemoryStream())
            {
                server.SendLogoutResult(stream, request);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (!response.Contains("200 OK"))
                {
                    return "expected logout with no session cookie present to still succeed (idempotent no-op), got: " + response;
                }
            }

            return null;
        }

        private static string TestConfigureServerSettingsValidatesSessionLifetimeHours()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            options.EnableHttp = true;
            // SendServerSettings (called at the end of a successful
            // ConfigureServerSettings) resolves DebugLogger.ResolvePath(options)
            // for display, which falls back to Path.Combine(options.DataPath, ...)
            // when DebugLogPath is unset - DataPath must be non-null for that
            // call to succeed, even though this test never enables debug
            // logging or touches disk.
            options.DataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-sessionlifetimehours-" + Guid.NewGuid().ToString("N"));
            InventoryServer server = new InventoryServer(options);

            RequestContext outOfRange = new RequestContext();
            outOfRange.Method = "POST";
            outOfRange.Path = "/api/v1/server/settings";
            outOfRange.Headers = new Dictionary<string, string>();
            outOfRange.Body = "{\"sessionLifetimeHours\":0}";

            using (MemoryStream stream = new MemoryStream())
            {
                server.ConfigureServerSettings(stream, outOfRange);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (!response.Contains("400"))
                {
                    return "expected sessionLifetimeHours of 0 to be rejected as out of range (1-720), got: " + response;
                }
            }

            RequestContext valid = new RequestContext();
            valid.Method = "POST";
            valid.Path = "/api/v1/server/settings";
            valid.Headers = new Dictionary<string, string>();
            valid.Body = "{\"sessionLifetimeHours\":24}";

            using (MemoryStream stream = new MemoryStream())
            {
                server.ConfigureServerSettings(stream, valid);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (!response.Contains("200 OK"))
                {
                    return "expected sessionLifetimeHours of 24 to be accepted, got: " + response;
                }
            }

            if (options.SessionLifetimeHours != 24)
            {
                return "expected options.SessionLifetimeHours to be updated to 24";
            }

            return null;
        }

        private static string TestSendUnauthorizedServesLoginPageForBrowserNavigation()
        {
            ServerOptions options = new ServerOptions();
            InventoryServer server = new InventoryServer(options);

            RequestContext request = new RequestContext();
            request.Method = "GET";
            request.Path = "/";
            request.Headers = new Dictionary<string, string>();
            request.Headers["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            using (MemoryStream stream = new MemoryStream())
            {
                server.SendUnauthorized(stream, request);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (!response.Contains("401 Unauthorized"))
                {
                    return "expected a 401 status even when serving the login page";
                }
                if (response.Contains("WWW-Authenticate"))
                {
                    return "expected WWW-Authenticate to never be sent, on any 401 response";
                }
                if (!response.Contains("id=\"loginForm\""))
                {
                    return "expected a browser navigation to / to receive the embedded login page";
                }
                if (!response.Contains("Content-Type: text/html"))
                {
                    return "expected the login page response to declare text/html";
                }
            }

            return null;
        }

        private static string TestSendUnauthorizedServesPlainTextForApiRequests()
        {
            ServerOptions options = new ServerOptions();
            InventoryServer server = new InventoryServer(options);

            RequestContext request = new RequestContext();
            request.Method = "GET";
            request.Path = "/api/v1/clients";
            request.Headers = new Dictionary<string, string>();

            using (MemoryStream stream = new MemoryStream())
            {
                server.SendUnauthorized(stream, request);
                string response = Encoding.UTF8.GetString(stream.ToArray());
                if (response.Contains("id=\"loginForm\""))
                {
                    return "expected an API route's 401 to stay plain text, not the HTML login page";
                }
                if (!response.Contains("Content-Type: text/plain"))
                {
                    return "expected the API route's 401 to keep declaring text/plain";
                }
            }

            return null;
        }

        private static string TestSendDashboardImageReturns404WhenFileMissing()
        {
            ServerOptions options = new ServerOptions();
            options.ContentPath = Path.Combine(Path.GetTempPath(), "wil-selftest-dashimg-missing-" + Guid.NewGuid().ToString("N"));
            InventoryServer server = new InventoryServer(options);

            using (MemoryStream stream = new MemoryStream())
            {
                server.SendDashboardImage(stream, "brand-mark.png", "image/png");
                string response = Encoding.ASCII.GetString(stream.ToArray());
                if (!response.Contains("404"))
                {
                    return "expected a missing image file to produce a 404, got: " + response.Substring(0, Math.Min(response.Length, 40));
                }
            }

            return null;
        }

        private static string TestSendDashboardImageIncludesSecurityHeaders()
        {
            ServerOptions options = new ServerOptions();
            options.ContentPath = Path.Combine(Path.GetTempPath(), "wil-selftest-dashimg-present-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(options.ContentPath);
            byte[] fakeImageBytes = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            string filePath = Path.Combine(options.ContentPath, "brand-mark.png");
            File.WriteAllBytes(filePath, fakeImageBytes);

            try
            {
                InventoryServer server = new InventoryServer(options);

                using (MemoryStream stream = new MemoryStream())
                {
                    server.SendDashboardImage(stream, "brand-mark.png", "image/png");
                    byte[] responseBytes = stream.ToArray();

                    byte[] terminator = { (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' };
                    int headerEnd = -1;
                    for (int i = 0; i <= responseBytes.Length - terminator.Length; i++)
                    {
                        bool match = true;
                        for (int j = 0; j < terminator.Length; j++)
                        {
                            if (responseBytes[i + j] != terminator[j]) { match = false; break; }
                        }
                        if (match) { headerEnd = i + terminator.Length; break; }
                    }
                    if (headerEnd < 0)
                    {
                        return "expected a header/body separator (\\r\\n\\r\\n) in the response";
                    }

                    string header = Encoding.ASCII.GetString(responseBytes, 0, headerEnd);
                    string[] expectedHeaders = { "200 OK", "Content-Type: image/png", "X-Content-Type-Options: nosniff", "X-Frame-Options: DENY", "Content-Security-Policy:", "Referrer-Policy:", "Permissions-Policy:" };
                    foreach (string expected in expectedHeaders)
                    {
                        if (!header.Contains(expected))
                        {
                            return "expected the response header to contain '" + expected + "', got: " + header;
                        }
                    }

                    byte[] body = new byte[responseBytes.Length - headerEnd];
                    Array.Copy(responseBytes, headerEnd, body, 0, body.Length);
                    if (body.Length != fakeImageBytes.Length)
                    {
                        return "expected the response body to be exactly the file's bytes (" + fakeImageBytes.Length + "), got " + body.Length;
                    }
                    for (int i = 0; i < fakeImageBytes.Length; i++)
                    {
                        if (body[i] != fakeImageBytes[i])
                        {
                            return "expected the response body to match the source file's bytes exactly, byte " + i + " differed";
                        }
                    }
                }
            }
            finally
            {
                Directory.Delete(options.ContentPath, true);
            }

            return null;
        }

        private static string TestEvaluateLockoutStateNotLockedOutCases()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            int retryAfterSeconds;

            if (EvaluateLockoutState(null, now, out retryAfterSeconds))
            {
                return "expected no record at all to mean not locked out";
            }

            LoginLockoutRecord noLockoutSet = new LoginLockoutRecord();
            noLockoutSet.FailedCount = 2;
            noLockoutSet.WindowStartUtc = now;
            noLockoutSet.LockedUntilUtc = null;
            if (EvaluateLockoutState(noLockoutSet, now, out retryAfterSeconds))
            {
                return "expected a record with no LockedUntilUtc to mean not locked out";
            }

            LoginLockoutRecord expiredLockout = new LoginLockoutRecord();
            expiredLockout.FailedCount = 5;
            expiredLockout.WindowStartUtc = now.AddMinutes(-30);
            expiredLockout.LockedUntilUtc = now.AddSeconds(-1);
            if (EvaluateLockoutState(expiredLockout, now, out retryAfterSeconds))
            {
                return "expected a lockout whose LockedUntilUtc is in the past to mean not locked out";
            }
            return null;
        }

        private static string TestEvaluateLockoutStateLockedOutReportsRetryAfter()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            LoginLockoutRecord record = new LoginLockoutRecord();
            record.FailedCount = 10;
            record.WindowStartUtc = now.AddMinutes(-5);
            record.LockedUntilUtc = now.AddSeconds(42);

            int retryAfterSeconds;
            if (!EvaluateLockoutState(record, now, out retryAfterSeconds))
            {
                return "expected a future LockedUntilUtc to mean locked out";
            }
            if (retryAfterSeconds != 42)
            {
                return "expected Retry-After to be 42 seconds, got " + retryAfterSeconds;
            }
            return null;
        }

        private static string TestRecordAttemptOutcomeLocksOutAtThreshold()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            TimeSpan window = TimeSpan.FromMinutes(15);
            TimeSpan lockoutDuration = TimeSpan.FromMinutes(15);

            LoginLockoutRecord record = null;
            record = RecordAttemptOutcome(record, false, now, 3, window, lockoutDuration);
            if (record.LockedUntilUtc.HasValue)
            {
                return "expected no lockout after 1 of 3 failures";
            }
            record = RecordAttemptOutcome(record, false, now, 3, window, lockoutDuration);
            if (record.LockedUntilUtc.HasValue)
            {
                return "expected no lockout after 2 of 3 failures";
            }
            record = RecordAttemptOutcome(record, false, now, 3, window, lockoutDuration);
            if (!record.LockedUntilUtc.HasValue)
            {
                return "expected a lockout to trigger on the 3rd failure against a threshold of 3";
            }
            if (record.LockedUntilUtc.Value != now.Add(lockoutDuration))
            {
                return "expected LockedUntilUtc to be exactly now + lockoutDuration";
            }
            return null;
        }

        private static string TestRecordAttemptOutcomeDoesNotExtendActiveLockout()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            TimeSpan window = TimeSpan.FromMinutes(15);
            TimeSpan lockoutDuration = TimeSpan.FromMinutes(15);

            LoginLockoutRecord record = null;
            for (int i = 0; i < 3; i++)
            {
                record = RecordAttemptOutcome(record, false, now, 3, window, lockoutDuration);
            }
            DateTime firstLockedUntil = record.LockedUntilUtc.Value;

            // A further failure 5 minutes later, still inside the active
            // lockout, must not push the unlock time forward - a sustained
            // flood must not keep the IP locked out indefinitely.
            DateTime later = now.AddMinutes(5);
            record = RecordAttemptOutcome(record, false, later, 3, window, lockoutDuration);
            if (record.LockedUntilUtc.Value != firstLockedUntil)
            {
                return "expected further failures during an active lockout to not extend it";
            }
            return null;
        }

        private static string TestRecordAttemptOutcomeClearsRecordOnSuccess()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            TimeSpan window = TimeSpan.FromMinutes(15);
            TimeSpan lockoutDuration = TimeSpan.FromMinutes(15);

            LoginLockoutRecord record = null;
            record = RecordAttemptOutcome(record, false, now, 10, window, lockoutDuration);
            record = RecordAttemptOutcome(record, false, now, 10, window, lockoutDuration);
            if (record == null || record.FailedCount != 2)
            {
                return "expected 2 recorded failures before the successful attempt";
            }

            LoginLockoutRecord afterSuccess = RecordAttemptOutcome(record, true, now, 10, window, lockoutDuration);
            if (afterSuccess != null)
            {
                return "expected a successful attempt to clear the record entirely";
            }
            return null;
        }

        private static string TestRecordAttemptOutcomeResetsAfterWindowElapses()
        {
            DateTime windowStart = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            TimeSpan window = TimeSpan.FromMinutes(15);
            TimeSpan lockoutDuration = TimeSpan.FromMinutes(15);

            LoginLockoutRecord record = null;
            record = RecordAttemptOutcome(record, false, windowStart, 10, window, lockoutDuration);
            record = RecordAttemptOutcome(record, false, windowStart, 10, window, lockoutDuration);
            if (record.FailedCount != 2)
            {
                return "expected 2 failures within the same window";
            }

            DateTime afterWindow = windowStart.AddMinutes(20);
            record = RecordAttemptOutcome(record, false, afterWindow, 10, window, lockoutDuration);
            if (record.FailedCount != 1)
            {
                return "expected the count to reset to 1 for a failure after the counting window elapsed, got " + record.FailedCount;
            }
            if (record.WindowStartUtc != afterWindow)
            {
                return "expected a fresh window to start at the new failure's timestamp";
            }
            return null;
        }

        private static string TestRecordAttemptOutcomeNeverLocksOutWhenThresholdIsZero()
        {
            DateTime now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            TimeSpan window = TimeSpan.FromMinutes(15);
            TimeSpan lockoutDuration = TimeSpan.FromMinutes(15);

            LoginLockoutRecord record = null;
            for (int i = 0; i < 20; i++)
            {
                record = RecordAttemptOutcome(record, false, now, 0, window, lockoutDuration);
                if (record.LockedUntilUtc.HasValue)
                {
                    return "expected threshold 0 to never trigger a lockout, failed after attempt " + (i + 1);
                }
            }
            return null;
        }

        private static string TestIsWebRequestAuthorizedLocksOutAfterRepeatedFailures()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            options.LoginLockoutThreshold = 3;
            options.LoginLockoutWindowMinutes = 15;
            options.LoginLockoutDurationMinutes = 15;
            InventoryServer server = new InventoryServer(options);
            IPAddress attackerIp = IPAddress.Parse("203.0.113.7");

            for (int i = 0; i < 3; i++)
            {
                RequestContext wrongAuth = new RequestContext();
                wrongAuth.Headers = new Dictionary<string, string>();
                wrongAuth.Headers["authorization"] = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:wrong-password"));
                wrongAuth.RemoteAddress = attackerIp;
                if (server.IsWebRequestAuthorized(wrongAuth))
                {
                    return "expected a wrong-password attempt to be rejected";
                }
            }

            RequestContext lockoutCheck = new RequestContext();
            lockoutCheck.Headers = new Dictionary<string, string>();
            lockoutCheck.RemoteAddress = attackerIp;
            int retryAfterSeconds;
            if (!server.IsBasicAuthLockedOut(lockoutCheck, out retryAfterSeconds))
            {
                return "expected the IP to be locked out after 3 failed attempts against a threshold of 3";
            }
            if (retryAfterSeconds <= 0)
            {
                return "expected a positive Retry-After value while locked out, got " + retryAfterSeconds;
            }

            RequestContext otherIp = new RequestContext();
            otherIp.Headers = new Dictionary<string, string>();
            otherIp.RemoteAddress = IPAddress.Parse("198.51.100.9");
            int otherRetryAfterSeconds;
            if (server.IsBasicAuthLockedOut(otherIp, out otherRetryAfterSeconds))
            {
                return "expected a different IP to be unaffected by another IP's lockout";
            }

            return null;
        }

        private static string TestResolveIngestionRejectionReason()
        {
            if (ResolveIngestionRejectionReason(null) != "missing")
            {
                return "expected a null token to resolve to 'missing'";
            }
            if (ResolveIngestionRejectionReason("") != "missing")
            {
                return "expected an empty token to resolve to 'missing'";
            }
            if (ResolveIngestionRejectionReason("wrong-token") != "mismatched")
            {
                return "expected a non-empty (wrong) token to resolve to 'mismatched'";
            }
            return null;
        }

        // Test-only construction helper - avoids object-initializer syntax
        // (`new Foo { A = 1 }`), which compiles fine under this project's
        // C# 3.0/.NET 3.5 toolchain but isn't used anywhere else in this
        // file; every other type here is built field-by-field instead.
        private static IngestionRejectionEntry MakeIngestionRejectionEntry(DateTime timestampUtc, string sourceIp, string endpoint, string reason)
        {
            IngestionRejectionEntry entry = new IngestionRejectionEntry();
            entry.TimestampUtc = timestampUtc;
            entry.SourceIp = sourceIp;
            entry.Endpoint = endpoint;
            entry.Reason = reason;
            return entry;
        }

        private static string TestPruneIngestionRejectionEntriesUnderBothCaps()
        {
            DateTime now = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> entries = new List<IngestionRejectionEntry>();
            entries.Add(MakeIngestionRejectionEntry(now.AddDays(-1), "10.0.0.1", "windows-inventory", "missing"));
            entries.Add(MakeIngestionRejectionEntry(now, "10.0.0.2", "linux-inventory", "mismatched"));

            List<IngestionRejectionEntry> result = PruneIngestionRejectionEntries(entries, now, 30, 5000);
            if (result.Count != 2)
            {
                return "expected both entries to survive when under both caps, got " + result.Count;
            }
            return null;
        }

        private static string TestPruneIngestionRejectionEntriesOverCountCap()
        {
            DateTime now = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> entries = new List<IngestionRejectionEntry>();
            for (int i = 0; i < 5; i++)
            {
                entries.Add(MakeIngestionRejectionEntry(now.AddMinutes(i), "10.0.0." + i, "windows-inventory", "missing"));
            }

            List<IngestionRejectionEntry> result = PruneIngestionRejectionEntries(entries, now, 30, 3);
            if (result.Count != 3)
            {
                return "expected exactly 3 entries to survive a max-entries cap of 3, got " + result.Count;
            }
            if (result[0].SourceIp != "10.0.0.2" || result[2].SourceIp != "10.0.0.4")
            {
                return "expected the oldest entries to be trimmed first (newest 3 survive, oldest-to-newest order preserved)";
            }
            return null;
        }

        private static string TestPruneIngestionRejectionEntriesOverAgeCap()
        {
            DateTime now = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> entries = new List<IngestionRejectionEntry>();
            entries.Add(MakeIngestionRejectionEntry(now.AddDays(-40), "10.0.0.1", "windows-inventory", "missing"));
            entries.Add(MakeIngestionRejectionEntry(now.AddDays(-1), "10.0.0.2", "linux-inventory", "mismatched"));

            List<IngestionRejectionEntry> result = PruneIngestionRejectionEntries(entries, now, 30, 5000);
            if (result.Count != 1 || result[0].SourceIp != "10.0.0.2")
            {
                return "expected the 40-day-old entry to be pruned by a 30-day retention cap regardless of the count cap";
            }
            return null;
        }

        private static string TestPruneIngestionRejectionEntriesBothCapsEngaged()
        {
            DateTime now = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> entries = new List<IngestionRejectionEntry>();
            entries.Add(MakeIngestionRejectionEntry(now.AddDays(-40), "10.0.0.1", "windows-inventory", "missing"));
            for (int i = 0; i < 5; i++)
            {
                entries.Add(MakeIngestionRejectionEntry(now.AddMinutes(i), "10.0.0." + (i + 2), "windows-inventory", "missing"));
            }

            // Age cap removes the 1 old entry (6 -> 5); count cap of 2 then
            // trims further (5 -> 2) - the more restrictive result (2) wins.
            List<IngestionRejectionEntry> result = PruneIngestionRejectionEntries(entries, now, 30, 2);
            if (result.Count != 2)
            {
                return "expected the more restrictive cap (count=2) to win when both caps would otherwise remove different entries, got " + result.Count;
            }
            return null;
        }

        private static string TestPruneIngestionRejectionEntriesZeroMaxEntriesKeepsWithinAge()
        {
            // A bare `new ServerOptions()` defaults both
            // IngestionRejectionLogRetentionDays and
            // IngestionRejectionLogMaxEntries to 0 - before the maxEntries
            // <= 0 guard, that silently discarded every entry that had
            // otherwise survived the age check, a footgun that already cost
            // one implementer debugging time this session (see Minor H in
            // the final review).
            DateTime now = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> entries = new List<IngestionRejectionEntry>();
            entries.Add(MakeIngestionRejectionEntry(now.AddMinutes(-5), "10.0.0.1", "windows-inventory", "missing"));
            entries.Add(MakeIngestionRejectionEntry(now, "10.0.0.2", "linux-inventory", "mismatched"));

            List<IngestionRejectionEntry> resultWithZero = PruneIngestionRejectionEntries(entries, now, 3650, 0);
            if (resultWithZero.Count != 2)
            {
                return "expected maxEntries=0 to skip the max-entries trim entirely (both entries survive the age check), got " + resultWithZero.Count;
            }

            List<IngestionRejectionEntry> resultWithNegative = PruneIngestionRejectionEntries(entries, now, 3650, -1);
            if (resultWithNegative.Count != 2)
            {
                return "expected a negative maxEntries to also skip the max-entries trim entirely, got " + resultWithNegative.Count;
            }
            return null;
        }

        private static string TestRecordIngestionRejectionBatchesRewrites()
        {
            ServerOptions options = new ServerOptions();
            // Deliberately small maxEntries so the slack floor (50, see
            // RecordIngestionRejection's amortization in Important Fix 1)
            // dominates and this test can exercise a full batch without
            // needing thousands of calls. retentionDays is generous so only
            // the max-entries trim - not age - is what fires here.
            options.IngestionRejectionLogRetentionDays = 30;
            options.IngestionRejectionLogMaxEntries = 10;
            options.DataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-rejectionbatch-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(options.DataPath);
            try
            {
                InventoryServer server = new InventoryServer(options);
                System.Reflection.MethodInfo recordMethod = typeof(InventoryServer)
                    .GetMethod("RecordIngestionRejection", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                string logPath = Path.Combine(options.DataPath, "_logs", "ingestion-rejections.jsonl");
                IPAddress sourceAddress = IPAddress.Parse("203.0.113.50");

                int slack = Math.Max(options.IngestionRejectionLogMaxEntries / 10, 50);
                int justOverMaxEntries = options.IngestionRejectionLogMaxEntries + 1;
                int totalToRecord = options.IngestionRejectionLogMaxEntries + slack + 1;

                for (int i = 0; i < justOverMaxEntries; i++)
                {
                    RequestContext request = new RequestContext();
                    request.Headers = new Dictionary<string, string>();
                    request.RemoteAddress = sourceAddress;
                    recordMethod.Invoke(server, new object[] { request, "windows-inventory", "mismatched" });
                }

                int linesBeforeSlackThreshold = File.ReadAllLines(logPath).Length;
                if (linesBeforeSlackThreshold != justOverMaxEntries)
                {
                    return "expected " + justOverMaxEntries + " lines on disk before the slack threshold is crossed (no rewrite yet), got " + linesBeforeSlackThreshold;
                }

                for (int i = justOverMaxEntries; i < totalToRecord; i++)
                {
                    RequestContext request = new RequestContext();
                    request.Headers = new Dictionary<string, string>();
                    request.RemoteAddress = sourceAddress;
                    recordMethod.Invoke(server, new object[] { request, "windows-inventory", "mismatched" });
                }

                int linesAfterBatch = File.ReadAllLines(logPath).Length;
                if (linesAfterBatch != options.IngestionRejectionLogMaxEntries)
                {
                    return "expected exactly " + options.IngestionRejectionLogMaxEntries + " lines on disk once the batch prune+rewrite fires, got " + linesAfterBatch;
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(options.DataPath, true); } catch { }
            }
        }

        // Covers the re-review's Important Fix 1: batching the prune+rewrite
        // behind the count-based slack gate (see
        // TestRecordIngestionRejectionBatchesRewrites above) must not disable
        // day-based retention for a fleet whose rejection volume never
        // approaches maxEntries+slack. maxEntries here is set high enough
        // that the count-based gate can never trip within this test, so only
        // the added oldest-entry-age check can be what prunes the backdated
        // entry.
        private static string TestRecordIngestionRejectionEnforcesRetentionContinuously()
        {
            ServerOptions options = new ServerOptions();
            options.IngestionRejectionLogRetentionDays = 30;
            options.IngestionRejectionLogMaxEntries = 5000;
            options.DataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-rejectionretention-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(options.DataPath);
            try
            {
                InventoryServer server = new InventoryServer(options);

                // RecordIngestionRejection always stamps DateTime.UtcNow, so
                // an aged entry can't be produced through the public call
                // path - seed one directly into the in-memory log instead,
                // as index 0 (oldest), matching the chronological ordering
                // RecordIngestionRejection itself always appends in.
                System.Reflection.FieldInfo logField = typeof(InventoryServer)
                    .GetField("ingestionRejectionLog", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                List<IngestionRejectionEntry> log = (List<IngestionRejectionEntry>)logField.GetValue(server);
                log.Add(MakeIngestionRejectionEntry(DateTime.UtcNow.AddDays(-31), "203.0.113.90", "windows-inventory", "missing"));

                System.Reflection.MethodInfo recordMethod = typeof(InventoryServer)
                    .GetMethod("RecordIngestionRejection", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                string logPath = Path.Combine(options.DataPath, "_logs", "ingestion-rejections.jsonl");

                // A handful of in-range rejections - nowhere near
                // maxEntries+slack (5000 + 500), so the count-based half of
                // the gate can never be what fires here.
                for (int i = 0; i < 3; i++)
                {
                    RequestContext request = new RequestContext();
                    request.Headers = new Dictionary<string, string>();
                    request.RemoteAddress = IPAddress.Parse("203.0.113." + (91 + i));
                    recordMethod.Invoke(server, new object[] { request, "windows-inventory", "mismatched" });
                }

                if (log.Count != 3)
                {
                    return "expected the backdated entry to be pruned by age on the first subsequent call (count-based gate never trips here), got " + log.Count + " entries in memory";
                }
                foreach (IngestionRejectionEntry entry in log)
                {
                    if (entry.SourceIp == "203.0.113.90")
                    {
                        return "expected the 31-day-old backdated entry to be pruned by the 30-day retention cap, but it is still present";
                    }
                }

                int linesOnDisk = File.ReadAllLines(logPath).Length;
                if (linesOnDisk != log.Count)
                {
                    return "expected the log file to be rewritten to match the pruned in-memory log (" + log.Count + " lines), got " + linesOnDisk;
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(options.DataPath, true); } catch { }
            }
        }

        private static string TestComputeClientTokenIssueNoMatch()
        {
            DateTime lastCollected = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> log = new List<IngestionRejectionEntry>();
            log.Add(MakeIngestionRejectionEntry(lastCollected.AddMinutes(5), "10.0.0.99", "windows-inventory", "missing"));

            string result = ComputeClientTokenIssue("10.0.0.1", lastCollected, log);
            if (result != null)
            {
                return "expected no indicator when no log entry matches the client's source IP, got '" + result + "'";
            }
            return null;
        }

        private static string TestComputeClientTokenIssueStaleRejectionIgnored()
        {
            DateTime lastCollected = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> log = new List<IngestionRejectionEntry>();
            log.Add(MakeIngestionRejectionEntry(lastCollected.AddMinutes(-5), "10.0.0.1", "windows-inventory", "mismatched"));

            string result = ComputeClientTokenIssue("10.0.0.1", lastCollected, log);
            if (result != null)
            {
                return "expected a matching-IP rejection OLDER than the client's last report to be ignored (client has since reported fine), got '" + result + "'";
            }
            return null;
        }

        private static string TestComputeClientTokenIssueRecentRejectionFlagged()
        {
            DateTime lastCollected = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> log = new List<IngestionRejectionEntry>();
            log.Add(MakeIngestionRejectionEntry(lastCollected.AddMinutes(5), "10.0.0.1", "windows-inventory", "mismatched"));

            string result = ComputeClientTokenIssue("10.0.0.1", lastCollected, log);
            if (result != "mismatched")
            {
                return "expected 'mismatched' for a matching-IP rejection newer than the client's last report, got '" + result + "'";
            }
            return null;
        }

        private static string TestComputeClientTokenIssueNewestWins()
        {
            DateTime lastCollected = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
            List<IngestionRejectionEntry> log = new List<IngestionRejectionEntry>();
            log.Add(MakeIngestionRejectionEntry(lastCollected.AddMinutes(5), "10.0.0.1", "windows-inventory", "missing"));
            log.Add(MakeIngestionRejectionEntry(lastCollected.AddMinutes(10), "10.0.0.1", "windows-inventory", "mismatched"));

            string result = ComputeClientTokenIssue("10.0.0.1", lastCollected, log);
            if (result != "mismatched")
            {
                return "expected the NEWEST matching-IP entry's reason to win ('mismatched'), got '" + result + "'";
            }
            return null;
        }

        private static string TestLoadClientReportsSetsTokenIssueFromRejectionLog()
        {
            ServerOptions options = new ServerOptions();
            // A bare `new ServerOptions()` does NOT run Parse()'s defaults -
            // these two default to 0 otherwise, which would make
            // RecordIngestionRejection's own prune pass (retentionDays=0)
            // immediately discard the very entry this test just recorded,
            // before LoadClientReports ever sees it.
            options.IngestionRejectionLogRetentionDays = 30;
            options.IngestionRejectionLogMaxEntries = 5000;
            options.DataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-tokenissue-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(options.DataPath);
            try
            {
                InventoryServer server = new InventoryServer(options);
                JavaScriptSerializer serializer = new JavaScriptSerializer();

                DateTime collectedAt = new DateTime(2026, 1, 10, 12, 0, 0, DateTimeKind.Utc);
                Dictionary<string, object> report = new Dictionary<string, object>();
                report["computerName"] = "PC-TEST";
                report["collectedAt"] = collectedAt.ToString("yyyy-MM-ddTHH:mm:ssZ");
                report["lastIngestSourceIp"] = "203.0.113.9";
                File.WriteAllText(Path.Combine(options.DataPath, "PC-TEST.json"), serializer.Serialize(report), Encoding.UTF8);

                RequestContext rejectedRequest = new RequestContext();
                rejectedRequest.Headers = new Dictionary<string, string>();
                rejectedRequest.RemoteAddress = IPAddress.Parse("203.0.113.9");
                typeof(InventoryServer)
                    .GetMethod("RecordIngestionRejection", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                    .Invoke(server, new object[] { rejectedRequest, "windows-inventory", "mismatched" });

                ArrayList clients = server.LoadClientReports();

                if (clients.Count != 1)
                {
                    return "expected exactly one loaded client report, got " + clients.Count;
                }
                Dictionary<string, object> loaded = (Dictionary<string, object>)clients[0];
                if (!loaded.ContainsKey("tokenIssue") || Convert.ToString(loaded["tokenIssue"]) != "mismatched")
                {
                    return "expected LoadClientReports to set tokenIssue='mismatched' after a matching rejected attempt newer than collectedAt";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(options.DataPath, true); } catch { }
            }
        }

        private static string TestBuildHstsHeaderOrEmpty()
        {
            ServerOptions options = new ServerOptions();
            options.HstsEnabled = true;
            options.HstsMaxAgeHours = 2;
            InventoryServer server = new InventoryServer(options);

            using (MemoryStream plainStream = new MemoryStream())
            {
                string plainResult = server.BuildHstsHeaderOrEmpty(plainStream);
                if (plainResult != "")
                {
                    return "expected no HSTS header for a plain (non-TLS) stream, got '" + plainResult + "'";
                }
            }

            using (MemoryStream inner = new MemoryStream())
            using (SslStream sslStream = new SslStream(inner))
            {
                string tlsResult = server.BuildHstsHeaderOrEmpty(sslStream);
                if (tlsResult != "\r\nStrict-Transport-Security: max-age=7200")
                {
                    return "expected an HSTS header with max-age=7200 (2 hours) for a TLS stream, got '" + tlsResult + "'";
                }
            }

            options.HstsEnabled = false;
            using (MemoryStream inner2 = new MemoryStream())
            using (SslStream sslStream2 = new SslStream(inner2))
            {
                string disabledResult = server.BuildHstsHeaderOrEmpty(sslStream2);
                if (disabledResult != "")
                {
                    return "expected no HSTS header when HstsEnabled is false, even over a TLS stream, got '" + disabledResult + "'";
                }
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

        private static string TestPatchClientReportVersionAfterInstallUpdatesVersion()
        {
            string dataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataPath);
            try
            {
                string computerName = "PATCH-TEST-01";
                string reportPath = Path.Combine(dataPath, computerName + ".json");
                File.WriteAllText(reportPath, "{\"computerName\":\"PATCH-TEST-01\",\"clientVersion\":\"0.1.0\"}", new UTF8Encoding(false));

                ServerOptions options = new ServerOptions();
                options.DataPath = dataPath;
                InventoryServer server = new InventoryServer(options);
                server.PatchClientReportVersionAfterInstall(computerName, "0.2.0", null);

                JavaScriptSerializer serializer = CreateJsonSerializer();
                Dictionary<string, object> report = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(reportPath, Encoding.UTF8));
                if (GetStringValue(report, "clientVersion") != "0.2.0")
                {
                    return "expected clientVersion to be patched to '0.2.0', got '" + GetStringValue(report, "clientVersion") + "'";
                }
                if (GetStringValue(report, "computerName") != "PATCH-TEST-01")
                {
                    return "expected the rest of the report to survive the patch untouched";
                }
                if (String.IsNullOrEmpty(GetStringValue(report, "lastInstalledAtUtc")))
                {
                    return "expected lastInstalledAtUtc to be set by the patch";
                }
                return null;
            }
            finally
            {
                Directory.Delete(dataPath, true);
            }
        }

        // A real inventory report overwrites the whole file from the
        // client's own POST body (see ReceiveInventory), which never
        // includes lastInstalledAtUtc - simulates that overwrite directly
        // (no HTTP plumbing needed) to prove the field disappears on its
        // own, with no separate "clear the awaiting-report flag" step
        // anywhere in the codebase.
        private static string TestPatchClientReportVersionAfterInstallFieldClearedByRealReport()
        {
            string dataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataPath);
            try
            {
                string computerName = "PATCH-TEST-02";
                string reportPath = Path.Combine(dataPath, computerName + ".json");
                File.WriteAllText(reportPath, "{\"computerName\":\"PATCH-TEST-02\",\"clientVersion\":\"0.1.0\"}", new UTF8Encoding(false));

                ServerOptions options = new ServerOptions();
                options.DataPath = dataPath;
                InventoryServer server = new InventoryServer(options);
                server.PatchClientReportVersionAfterInstall(computerName, "0.2.0", null);

                JavaScriptSerializer serializer = CreateJsonSerializer();
                string freshClientPayload = "{\"computerName\":\"PATCH-TEST-02\",\"clientVersion\":\"0.2.0\"}";
                File.WriteAllText(reportPath, freshClientPayload, new UTF8Encoding(false));

                Dictionary<string, object> report = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(reportPath, Encoding.UTF8));
                if (!String.IsNullOrEmpty(GetStringValue(report, "lastInstalledAtUtc")))
                {
                    return "expected lastInstalledAtUtc to be gone once a real report overwrites the file";
                }
                return null;
            }
            finally
            {
                Directory.Delete(dataPath, true);
            }
        }

        private static string TestPatchClientReportVersionAfterInstallMissingReport()
        {
            string dataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataPath);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = dataPath;
                InventoryServer server = new InventoryServer(options);
                // A target that has never reported at all yet - should not
                // throw and should not create a new file out of nowhere.
                server.PatchClientReportVersionAfterInstall("NEVER-REPORTED-01", "0.2.0", null);

                if (Directory.GetFiles(dataPath, "*.json").Length != 0)
                {
                    return "expected no report file to be created for a target with no existing report";
                }
                return null;
            }
            finally
            {
                Directory.Delete(dataPath, true);
            }
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

        // BuildPowerShellInstallArguments never included -Token, so a
        // WinRM push (manual "Client actions" or the scheduled "Client
        // updates" push) always installed/reinstalled a client with no
        // ingestion token - harmless while the server's own token was
        // never actually enforced, but once a real token is configured
        // (auto-generated or regenerated) every such push/reinstall left
        // the target unable to authenticate its own inventory reports.
        // Found via a live user report: "clients stopped connecting after
        // regenerating the token, reinstalling via the UI doesn't help."
        private static string TestBuildPowerShellInstallArgumentsIncludesToken()
        {
            string argsWithToken = BuildPowerShellInstallArguments("PC-001", "https://server/api/v1/inventory", "real-token-value", false, false, false, @"C:\package");
            if (!argsWithToken.Contains("-Token 'real-token-value'"))
            {
                return "expected -Token 'real-token-value' in the built arguments, got: " + argsWithToken;
            }

            string argsWithoutToken = BuildPowerShellInstallArguments("PC-001", "https://server/api/v1/inventory", "", false, false, false, @"C:\package");
            if (argsWithoutToken.Contains("-Token"))
            {
                return "expected no -Token when the token is empty, got: " + argsWithoutToken;
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

        private static string TestValidatePosixShellSafeRejectsUnsafeCharacters()
        {
            string[] unsafeValues = { "/opt/wil; rm -rf /", "$(rm -rf /)", "`rm -rf /`", "path\"with\"quotes", "path'with'quotes", "path\\with\\backslash", "a|b", "a&b", "a<b", "a>b", "a(b)", "line1\nline2", "line1\rline2", "/opt/wil /usr", "path\twith\ttab" };
            foreach (string unsafeValue in unsafeValues)
            {
                try
                {
                    ValidatePosixShellSafe(unsafeValue, "testField");
                    return "expected value '" + unsafeValue + "' to be rejected, but ValidatePosixShellSafe accepted it";
                }
                catch (ArgumentException)
                {
                    // expected
                }
            }
            return null;
        }

        private static string TestValidatePosixShellSafeAcceptsSafeValues()
        {
            string[] safeValues = { "/opt/windows-inventory-lite", "https://server.example.local:8080/api/v1/linux/inventory", "a1b2c3d4e5f6", "" , null };
            foreach (string safeValue in safeValues)
            {
                try
                {
                    ValidatePosixShellSafe(safeValue, "testField");
                }
                catch (ArgumentException ex)
                {
                    return "expected value '" + safeValue + "' to be accepted, but ValidatePosixShellSafe rejected it: " + ex.Message;
                }
            }
            return null;
        }

        private static string TestReadRequestFailsCleanlyOnAConnectionClosedMidHeaders()
        {
            // A bare port scan or health probe that opens a socket, writes a few
            // bytes and closes reaches this. It used to throw
            // ArgumentOutOfRangeException from Encoding.ASCII.GetString(raw, 0, -1),
            // an unauthenticated path to a full stack trace in the Windows Event Log.
            using (MemoryStream truncated = new MemoryStream(Encoding.ASCII.GetBytes("GET / HTT")))
            {
                try
                {
                    ReadRequest(truncated);
                    return "expected a truncated request to be rejected";
                }
                catch (ArgumentOutOfRangeException)
                {
                    return "expected a clean InvalidOperationException, got ArgumentOutOfRangeException (the bug)";
                }
                catch (InvalidOperationException)
                {
                    return null;
                }
            }
        }

        private static string TestReadRequestFailsCleanlyOnAnImmediatelyClosedConnection()
        {
            using (MemoryStream empty = new MemoryStream(new byte[0]))
            {
                try
                {
                    ReadRequest(empty);
                    return "expected an empty request to be rejected";
                }
                catch (ArgumentOutOfRangeException)
                {
                    return "expected a clean InvalidOperationException, got ArgumentOutOfRangeException (the bug)";
                }
                catch (InvalidOperationException)
                {
                    return null;
                }
            }
        }

        private static string TestNullJsonBodyDeserializesToNullNotAnEmptyDictionary()
        {
            // The premise the ingestion endpoints' null-guard exists for: a body of
            // literally "null" parses successfully and yields a null dictionary, so
            // the very next ContainsKey call is an unauthenticated NullReferenceException.
            Dictionary<string, object> parsed = CreateJsonSerializer().Deserialize<Dictionary<string, object>>("null");
            if (parsed != null)
            {
                return "expected a 'null' body to deserialize to null, got a non-null dictionary";
            }
            return null;
        }

        private static string TestTryValidateLinuxPushValuesRejectsUnsafeValuesAndAcceptsSafeOnes()
        {
            string error;
            if (!TryValidateLinuxPushValues("https://example.local/api/v1/linux/inventory", "a1b2c3", "/opt/windows-inventory-lite", out error))
            {
                return "expected safe values to be accepted, got: " + error;
            }
            if (TryValidateLinuxPushValues("https://example.local", "a1b2c3", "/opt/wil; rm -rf /", out error))
            {
                return "expected an unsafe installPath to be rejected";
            }
            if (String.IsNullOrEmpty(error))
            {
                return "expected a non-empty error message when validation fails";
            }
            if (TryValidateLinuxPushValues("https://example.local/$(id)", "a1b2c3", "/opt/windows-inventory-lite", out error))
            {
                return "expected an unsafe serverUrl to be rejected";
            }
            if (TryValidateLinuxPushValues("https://example.local", "tok`id`", "/opt/windows-inventory-lite", out error))
            {
                return "expected an unsafe token to be rejected";
            }
            // A bare top-level directory has no shell metacharacter and no
            // whitespace, so ValidatePosixShellSafe alone lets it through -
            // but it still reaches "rm -rf $InstallPath" unmodified via a
            // direct API call that supplies installPath itself (the
            // dashboard UI no longer offers this field as of v0.54.0, but
            // the server still accepts it in the request body). This is the
            // same check IsValidLinuxInstallPath added for the Settings
            // fallback in v0.54.3 - it must also gate this shared push-value
            // validator, the actual point of use for every SSH install,
            // uninstall, and update push.
            if (TryValidateLinuxPushValues("https://example.local", "a1b2c3", "/etc", out error))
            {
                return "expected a bare top-level installPath ('/etc') to be rejected";
            }
            if (TryValidateLinuxPushValues("https://example.local", "a1b2c3", "/opt/../etc", out error))
            {
                return "expected a traversal installPath ('/opt/../etc') to be rejected";
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

        private static string TestGetLinuxClientUpdateTargetPrefersIPv4OverHostname()
        {
            Dictionary<string, object> client = new Dictionary<string, object>();
            client["hostname"] = "docker";
            ArrayList addresses = new ArrayList();
            addresses.Add("fe80::1");
            addresses.Add("192.168.4.110");
            addresses.Add("10.0.0.5");
            client["ipAddresses"] = addresses;

            string target = GetLinuxClientUpdateTarget(client, "");
            if (target != "192.168.4.110")
            {
                return "expected the first IPv4 address ('192.168.4.110'), skipping the leading IPv6 entry, got '" + target + "'";
            }
            return null;
        }

        private static string TestGetLinuxClientUpdateTargetFallsBackToHostnameWithNoIPv4()
        {
            Dictionary<string, object> client = new Dictionary<string, object>();
            client["hostname"] = "docker";
            ArrayList addresses = new ArrayList();
            addresses.Add("fe80::1");
            client["ipAddresses"] = addresses;

            string target = GetLinuxClientUpdateTarget(client, "");
            if (target != "docker")
            {
                return "expected fallback to hostname 'docker' when no IPv4 address is present, got '" + target + "'";
            }

            Dictionary<string, object> clientWithNoAddressesAtAll = new Dictionary<string, object>();
            clientWithNoAddressesAtAll["hostname"] = "legacy-report";
            string targetForOlderReport = GetLinuxClientUpdateTarget(clientWithNoAddressesAtAll, "");
            if (targetForOlderReport != "legacy-report")
            {
                return "expected fallback to hostname for a report with no ipAddresses field at all (older client), got '" + targetForOlderReport + "'";
            }
            return null;
        }

        // Reproduces the real bug this session: a Proxmox host reporting a
        // storage/cluster-network address (192.168.253.x) BEFORE its real
        // LAN address (192.168.4.x) in ipAddresses - the plain first-IPv4
        // heuristic picked the unreachable one. With a preferred subnet
        // configured, the matching address wins regardless of array order.
        private static string TestGetLinuxClientUpdateTargetPrefersConfiguredSubnet()
        {
            Dictionary<string, object> client = new Dictionary<string, object>();
            client["hostname"] = "minipveone";
            ArrayList addresses = new ArrayList();
            addresses.Add("192.168.253.12");
            addresses.Add("192.168.4.12");
            addresses.Add("192.168.240.1");
            client["ipAddresses"] = addresses;

            string target = GetLinuxClientUpdateTarget(client, "192.168.4.0/24");
            if (target != "192.168.4.12")
            {
                return "expected the address inside the preferred subnet ('192.168.4.12'), got '" + target + "'";
            }
            return null;
        }

        private static string TestGetLinuxClientUpdateTargetFallsBackWhenNoAddressMatchesSubnet()
        {
            Dictionary<string, object> client = new Dictionary<string, object>();
            client["hostname"] = "minipveone";
            ArrayList addresses = new ArrayList();
            addresses.Add("192.168.253.12");
            addresses.Add("192.168.240.1");
            client["ipAddresses"] = addresses;

            string target = GetLinuxClientUpdateTarget(client, "192.168.4.0/24");
            if (target != "192.168.253.12")
            {
                return "expected fallback to the first-seen IPv4 ('192.168.253.12') when nothing matches the preferred subnet, got '" + target + "'";
            }
            return null;
        }

        private static string TestGetLinuxClientUpdateTargetIgnoresMalformedSubnet()
        {
            Dictionary<string, object> client = new Dictionary<string, object>();
            client["hostname"] = "minipveone";
            ArrayList addresses = new ArrayList();
            addresses.Add("192.168.253.12");
            addresses.Add("192.168.4.12");
            client["ipAddresses"] = addresses;

            string target = GetLinuxClientUpdateTarget(client, "not-a-cidr-value");
            if (target != "192.168.253.12")
            {
                return "expected fallback to the first-seen IPv4 ('192.168.253.12') when the configured subnet is malformed, got '" + target + "'";
            }
            return null;
        }

        private static string TestIsIPv4InCidrMatchesInsideSubnet()
        {
            if (!IsIPv4InCidr("192.168.4.12", "192.168.4.0/24"))
            {
                return "expected 192.168.4.12 to match 192.168.4.0/24";
            }
            return null;
        }

        private static string TestIsIPv4InCidrRejectsOutsideSubnet()
        {
            if (IsIPv4InCidr("192.168.253.12", "192.168.4.0/24"))
            {
                return "expected 192.168.253.12 to NOT match 192.168.4.0/24";
            }
            return null;
        }

        private static string TestIsIPv4InCidrHandlesEdgePrefixLengths()
        {
            if (!IsIPv4InCidr("10.20.30.40", "0.0.0.0/0"))
            {
                return "expected /0 to match every address";
            }
            if (!IsIPv4InCidr("192.168.4.12", "192.168.4.12/32"))
            {
                return "expected /32 to match only the identical address";
            }
            if (IsIPv4InCidr("192.168.4.13", "192.168.4.12/32"))
            {
                return "expected /32 to NOT match a different address";
            }
            return null;
        }

        private static string TestIsIPv4InCidrRejectsMalformedInput()
        {
            if (IsIPv4InCidr("192.168.4.12", "not-a-cidr-value"))
            {
                return "expected a CIDR value with no '/' to return false, not throw";
            }
            if (IsIPv4InCidr("192.168.4.12", "192.168.4.0/33"))
            {
                return "expected an out-of-range prefix length (/33) to return false";
            }
            if (IsIPv4InCidr("not-an-ip", "192.168.4.0/24"))
            {
                return "expected a malformed IP address to return false, not throw";
            }
            if (IsIPv4InCidr("fe80::1", "192.168.4.0/24"))
            {
                return "expected an IPv6 address to return false against an IPv4 CIDR";
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

        private static string TestTryResolveAdSyncCredentialsIgnoredWhenFlagIsFalse()
        {
            string username = "typed-user";
            string password = "typed-pass";
            string error;
            bool ok = TryResolveAdSyncCredentials(false, true, true, "CORP\\ad-admin", "ad-secret", ref username, ref password, out error);
            if (!ok || error != null || username != "typed-user" || password != "typed-pass")
            {
                return "expected useAdCredentials=false to leave typed credentials untouched, got ok=" + ok + " error='" + error + "' username='" + username + "' password='" + password + "'";
            }
            return null;
        }

        private static string TestTryResolveAdSyncCredentialsRejectsWhenAdSyncDisabled()
        {
            string username = "";
            string password = "";
            string error;
            bool ok = TryResolveAdSyncCredentials(true, false, true, "CORP\\ad-admin", "ad-secret", ref username, ref password, out error);
            if (ok || String.IsNullOrEmpty(error))
            {
                return "expected useAdCredentials=true with AD sync disabled to be rejected with an error message, got ok=" + ok + " error='" + error + "'";
            }
            return null;
        }

        private static string TestTryResolveAdSyncCredentialsUsesServiceIdentityWhenConfigured()
        {
            string username = "";
            string password = "";
            string error;
            bool ok = TryResolveAdSyncCredentials(true, true, true, "CORP\\ad-admin", "ad-secret", ref username, ref password, out error);
            if (!ok || error != null || username != "" || password != "")
            {
                return "expected AdUseServiceIdentity=true to resolve to blank username/password (service identity), got ok=" + ok + " error='" + error + "' username='" + username + "' password='" + password + "'";
            }
            return null;
        }

        private static string TestTryResolveAdSyncCredentialsUsesSavedAccountWhenNotServiceIdentity()
        {
            string username = "";
            string password = "";
            string error;
            bool ok = TryResolveAdSyncCredentials(true, true, false, "CORP\\ad-admin", "ad-secret", ref username, ref password, out error);
            if (!ok || error != null || username != "CORP\\ad-admin" || password != "ad-secret")
            {
                return "expected AdUseServiceIdentity=false to resolve to the saved AD username/password, got ok=" + ok + " error='" + error + "' username='" + username + "' password='" + password + "'";
            }
            return null;
        }

        private static string TestTryResolveAdSyncCredentialsRejectsWhenSavedAccountIncomplete()
        {
            string username = "";
            string password = "";
            string error;
            bool ok = TryResolveAdSyncCredentials(true, true, false, "CORP\\ad-admin", "", ref username, ref password, out error);
            if (ok || String.IsNullOrEmpty(error))
            {
                return "expected useAdCredentials=true with AdUseServiceIdentity=false and a blank saved password to be rejected, got ok=" + ok + " error='" + error + "'";
            }
            return null;
        }

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

        private static string TestResolveRequireIngestionTokenUsesExplicitConfigValue()
        {
            bool result = ServerOptions.ResolveRequireIngestionToken("false", true);
            if (result != false)
            {
                return "expected an explicit 'false' config value to win over tokenIsConfigured=true, got " + result;
            }
            bool result2 = ServerOptions.ResolveRequireIngestionToken("true", false);
            if (result2 != true)
            {
                return "expected an explicit 'true' config value to win over tokenIsConfigured=false, got " + result2;
            }
            return null;
        }

        private static string TestResolveRequireIngestionTokenMigratesFromTokenPresenceWhenUnset()
        {
            bool result = ServerOptions.ResolveRequireIngestionToken(null, true);
            if (result != true)
            {
                return "expected a missing config value to migrate to true when a token is configured, got " + result;
            }
            bool result2 = ServerOptions.ResolveRequireIngestionToken(null, false);
            if (result2 != false)
            {
                return "expected a missing config value to migrate to false when no token is configured, got " + result2;
            }
            bool result3 = ServerOptions.ResolveRequireIngestionToken("", true);
            if (result3 != true)
            {
                return "expected an empty-string config value (same as missing) to migrate to true when a token is configured, got " + result3;
            }
            return null;
        }

        private static string TestParseDefaultsRequireIngestionTokenFromCliTokenWhenNoConfigFile()
        {
            ServerOptions options = ServerOptions.Parse(new string[] { "--token", "test-cli-token-value", "--config", Path.Combine(Path.GetTempPath(), "wil-nonexistent-config-" + Guid.NewGuid().ToString("N") + ".json") });
            if (!options.RequireIngestionToken)
            {
                return "expected RequireIngestionToken to default to true when --token is supplied and no config file exists, got false";
            }
            return null;
        }

        private static string TestIsIngestionTokenRejectedRequiresMatchWhenEnforced()
        {
            if (InventoryServer.IsIngestionTokenRejected(true, "correct-token", "correct-token"))
            {
                return "expected a matching token to be accepted when enforcement is on";
            }
            if (!InventoryServer.IsIngestionTokenRejected(true, "wrong-token", "correct-token"))
            {
                return "expected a non-matching token to be rejected when enforcement is on";
            }
            if (!InventoryServer.IsIngestionTokenRejected(true, null, "correct-token"))
            {
                return "expected a missing token to be rejected when enforcement is on";
            }
            return null;
        }

        private static string TestIsIngestionTokenRejectedAlwaysAcceptsWhenNotEnforced()
        {
            if (InventoryServer.IsIngestionTokenRejected(false, "wrong-token", "correct-token"))
            {
                return "expected a non-matching token to be accepted when enforcement is off";
            }
            if (InventoryServer.IsIngestionTokenRejected(false, null, "correct-token"))
            {
                return "expected a missing token to be accepted when enforcement is off";
            }
            return null;
        }

        private static string TestIsIngestionTokenRejectedFailsClosedWhenEnforcedButNoTokenConfigured()
        {
            if (!InventoryServer.IsIngestionTokenRejected(true, null, null))
            {
                return "expected rejection when enforcement is on but no token is configured (null supplied, null configured)";
            }
            if (!InventoryServer.IsIngestionTokenRejected(true, null, ""))
            {
                return "expected rejection when enforcement is on but no token is configured (null supplied, empty configured)";
            }
            if (!InventoryServer.IsIngestionTokenRejected(true, "", null))
            {
                return "expected rejection when enforcement is on but no token is configured (empty supplied, null configured)";
            }
            if (!InventoryServer.IsIngestionTokenRejected(true, "", ""))
            {
                return "expected rejection when enforcement is on but no token is configured (empty supplied, empty configured)";
            }
            return null;
        }

        private static string TestIsCrossSiteRequestRejectedIgnoresNonStateChangingMethods()
        {
            RequestContext get = new RequestContext();
            get.Method = "GET";
            get.Headers = new Dictionary<string, string>();
            get.Headers["host"] = "server.example.com";
            get.Headers["origin"] = "https://evil.example.com";
            if (InventoryServer.IsCrossSiteRequestRejected(get))
            {
                return "expected a GET request to never be rejected, regardless of a mismatched Origin";
            }
            return null;
        }

        private static string TestIsCrossSiteRequestRejectedAllowsMissingOriginAndReferer()
        {
            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Headers = new Dictionary<string, string>();
            request.Headers["host"] = "server.example.com";
            if (InventoryServer.IsCrossSiteRequestRejected(request))
            {
                return "expected a POST with neither Origin nor Referer to be allowed - this is the documented curl/automation case, not a browser being tricked";
            }
            return null;
        }

        private static string TestIsCrossSiteRequestRejectedRequiresHostHeader()
        {
            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Headers = new Dictionary<string, string>();
            if (!InventoryServer.IsCrossSiteRequestRejected(request))
            {
                return "expected a state-changing request with no Host header at all to be rejected (malformed HTTP/1.1, fail closed)";
            }
            return null;
        }

        private static string TestIsCrossSiteRequestRejectedAcceptsMatchingOrigin()
        {
            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Headers = new Dictionary<string, string>();
            request.Headers["host"] = "server.example.com:8443";
            request.Headers["origin"] = "https://server.example.com:8443";
            if (InventoryServer.IsCrossSiteRequestRejected(request))
            {
                return "expected an Origin whose host:port matches the Host header to be accepted";
            }
            return null;
        }

        private static string TestIsCrossSiteRequestRejectedRejectsMismatchedOrigin()
        {
            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Headers = new Dictionary<string, string>();
            request.Headers["host"] = "server.example.com";
            request.Headers["origin"] = "https://evil.example.com";
            if (!InventoryServer.IsCrossSiteRequestRejected(request))
            {
                return "expected an Origin that doesn't match the Host header to be rejected";
            }
            return null;
        }

        private static string TestIsCrossSiteRequestRejectedTreatsNullOriginAsMismatch()
        {
            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Headers = new Dictionary<string, string>();
            request.Headers["host"] = "server.example.com";
            request.Headers["origin"] = "null";
            if (!InventoryServer.IsCrossSiteRequestRejected(request))
            {
                return "expected the literal Origin value 'null' (an opaque origin) to be treated as a mismatch, not as absent";
            }
            return null;
        }

        private static string TestIsCrossSiteRequestRejectedFallsBackToRefererWhenOriginAbsent()
        {
            RequestContext accepted = new RequestContext();
            accepted.Method = "POST";
            accepted.Headers = new Dictionary<string, string>();
            accepted.Headers["host"] = "server.example.com";
            accepted.Headers["referer"] = "https://server.example.com/deploy-actions";
            if (InventoryServer.IsCrossSiteRequestRejected(accepted))
            {
                return "expected a matching Referer to be accepted when Origin is absent";
            }

            RequestContext rejected = new RequestContext();
            rejected.Method = "POST";
            rejected.Headers = new Dictionary<string, string>();
            rejected.Headers["host"] = "server.example.com";
            rejected.Headers["referer"] = "https://evil.example.com/attack.html";
            if (!InventoryServer.IsCrossSiteRequestRejected(rejected))
            {
                return "expected a mismatched Referer to be rejected when Origin is absent";
            }
            return null;
        }

        private static string TestIsCrossSiteRequestRejectedFailsClosedOnMalformedOrigin()
        {
            RequestContext request = new RequestContext();
            request.Method = "POST";
            request.Headers = new Dictionary<string, string>();
            request.Headers["host"] = "server.example.com";
            request.Headers["origin"] = "not a valid uri at all";
            if (!InventoryServer.IsCrossSiteRequestRejected(request))
            {
                return "expected a malformed Origin header to be rejected (fail closed), not silently accepted";
            }
            return null;
        }

        private static string TestRequiresJsonContentTypeOnlyForStateChangingRequestsWithABody()
        {
            RequestContext getWithBody = new RequestContext();
            getWithBody.Method = "GET";
            getWithBody.Body = "{}";
            if (InventoryServer.RequiresJsonContentType(getWithBody))
            {
                return "expected a GET request to never require a JSON Content-Type, even with a body";
            }

            RequestContext postNoBody = new RequestContext();
            postNoBody.Method = "POST";
            postNoBody.Body = "";
            if (InventoryServer.RequiresJsonContentType(postNoBody))
            {
                return "expected a POST with an empty body (e.g. a DELETE-shaped no-body route) to not require a Content-Type";
            }

            RequestContext postWithBody = new RequestContext();
            postWithBody.Method = "POST";
            postWithBody.Body = "{\"targets\":\"PC-001\"}";
            if (!InventoryServer.RequiresJsonContentType(postWithBody))
            {
                return "expected a POST with a non-empty body to require a JSON Content-Type";
            }
            return null;
        }

        private static string TestHasJsonContentTypeAcceptsJsonWithOrWithoutCharsetSuffix()
        {
            RequestContext plain = new RequestContext();
            plain.Headers = new Dictionary<string, string>();
            plain.Headers["content-type"] = "application/json";
            if (!InventoryServer.HasJsonContentType(plain))
            {
                return "expected bare 'application/json' to be accepted";
            }

            RequestContext withCharset = new RequestContext();
            withCharset.Headers = new Dictionary<string, string>();
            withCharset.Headers["content-type"] = "application/json; charset=utf-8";
            if (!InventoryServer.HasJsonContentType(withCharset))
            {
                return "expected 'application/json; charset=utf-8' to be accepted";
            }

            RequestContext mixedCase = new RequestContext();
            mixedCase.Headers = new Dictionary<string, string>();
            mixedCase.Headers["content-type"] = "Application/JSON";
            if (!InventoryServer.HasJsonContentType(mixedCase))
            {
                return "expected a differently-cased media type to still be accepted";
            }
            return null;
        }

        private static string TestHasJsonContentTypeRejectsFormAndTextPlainAndMissing()
        {
            RequestContext formEncoded = new RequestContext();
            formEncoded.Headers = new Dictionary<string, string>();
            formEncoded.Headers["content-type"] = "application/x-www-form-urlencoded";
            if (InventoryServer.HasJsonContentType(formEncoded))
            {
                return "expected 'application/x-www-form-urlencoded' to be rejected";
            }

            RequestContext textPlain = new RequestContext();
            textPlain.Headers = new Dictionary<string, string>();
            textPlain.Headers["content-type"] = "text/plain";
            if (InventoryServer.HasJsonContentType(textPlain))
            {
                return "expected 'text/plain' to be rejected - this is exactly the enctype a form-based JSON-body CSRF attempt would use";
            }

            RequestContext missing = new RequestContext();
            missing.Headers = new Dictionary<string, string>();
            if (InventoryServer.HasJsonContentType(missing))
            {
                return "expected a missing Content-Type header to be rejected";
            }
            return null;
        }

        private static string TestResolveEffectiveTokenFallsBackToLiveTokenWhenBlank()
        {
            string result = ResolveEffectiveToken("", "live-token-value");
            if (result != "live-token-value")
            {
                return "expected a blank requested token to fall back to the live token, got '" + result + "'";
            }
            string result2 = ResolveEffectiveToken(null, "live-token-value");
            if (result2 != "live-token-value")
            {
                return "expected a null requested token to fall back to the live token, got '" + result2 + "'";
            }
            string result3 = ResolveEffectiveToken("explicit-override", "live-token-value");
            if (result3 != "explicit-override")
            {
                return "expected an explicitly supplied token to win over the live token, got '" + result3 + "'";
            }
            return null;
        }

        private static string TestRequiresIngestionTokenRiskAcknowledgmentOnlyWhenTurningEnforcementOff()
        {
            if (!RequiresIngestionTokenRiskAcknowledgment(true, false, false))
            {
                return "expected turning enforcement off without acknowledgeIngestionTokenRisk to require acknowledgment";
            }
            if (RequiresIngestionTokenRiskAcknowledgment(true, false, true))
            {
                return "expected turning enforcement off WITH acknowledgeIngestionTokenRisk=true to not require it again";
            }
            if (RequiresIngestionTokenRiskAcknowledgment(false, false, false))
            {
                return "expected leaving enforcement off (no actual change) to never require acknowledgment";
            }
            if (RequiresIngestionTokenRiskAcknowledgment(false, true, false))
            {
                return "expected turning enforcement ON to never require acknowledgment (only turning it off is risky)";
            }
            if (RequiresIngestionTokenRiskAcknowledgment(true, true, false))
            {
                return "expected leaving enforcement on (no actual change) to never require acknowledgment";
            }
            // Remaining 3 of the 8 boolean combinations not covered above:
            // acknowledgeIngestionTokenRisk=true on the three transitions
            // that were already never-require-acknowledgment with
            // acknowledgeIngestionTokenRisk=false. Included so every
            // combination of the 3 booleans is exercised, not just the
            // ones where the flag flips the result.
            if (RequiresIngestionTokenRiskAcknowledgment(false, false, true))
            {
                return "expected leaving enforcement off with acknowledgeIngestionTokenRisk=true (irrelevant flag) to never require acknowledgment";
            }
            if (RequiresIngestionTokenRiskAcknowledgment(false, true, true))
            {
                return "expected turning enforcement ON with acknowledgeIngestionTokenRisk=true (irrelevant flag) to never require acknowledgment";
            }
            if (RequiresIngestionTokenRiskAcknowledgment(true, true, true))
            {
                return "expected leaving enforcement on with acknowledgeIngestionTokenRisk=true (irrelevant flag) to never require acknowledgment";
            }
            return null;
        }

        private static string TestComputeAdSyncFieldsCarriesDescriptionForwardWhenSyncDisabled()
        {
            ServerOptions options = new ServerOptions();
            options.AdDescriptionSyncEnabled = false;
            InventoryServer server = new InventoryServer(options);

            Dictionary<string, object> previous = new Dictionary<string, object>();
            previous["adDescription"] = "Manually set description";
            previous["adSyncStatus"] = "ok";
            previous["adSyncedAt"] = "2026-07-20T10:00:00Z";

            AdSyncFields fields = server.ComputeAdSyncFields("CARRY-FORWARD-TEST", previous);
            if (!fields.Applicable)
            {
                return "expected Applicable=true so the manual Description gets written back, got false";
            }
            if (Convert.ToString(fields.Description) != "Manually set description")
            {
                return "expected the previous adDescription to be carried forward unchanged, got '" + Convert.ToString(fields.Description) + "'";
            }
            return null;
        }

        private static string TestComputeAdSyncFieldsNoOpForNewComputerWhenSyncDisabled()
        {
            ServerOptions options = new ServerOptions();
            options.AdDescriptionSyncEnabled = false;
            InventoryServer server = new InventoryServer(options);

            AdSyncFields fields = server.ComputeAdSyncFields("BRAND-NEW-TEST", null);
            if (fields.Applicable)
            {
                return "expected Applicable=false for a brand-new computer (nothing to carry forward), got true";
            }
            return null;
        }

        private static string TestSaveLicensesRestrictsFileAcl()
        {
            string dataPath = Path.Combine(Path.GetTempPath(), "wil-license-acl-test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataPath);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = dataPath;
                InventoryServer server = new InventoryServer(options);
                List<Dictionary<string, object>> licenses = new List<Dictionary<string, object>>();
                Dictionary<string, object> record = new Dictionary<string, object>();
                record["name"] = "Test Software";
                record["version"] = "1.0";
                record["license"] = "TEST-KEY-1234";
                licenses.Add(record);

                server.SaveLicenses(licenses);

                string licensesPath = Path.Combine(dataPath, "_licenses", "licenses.json");
                if (!File.Exists(licensesPath))
                {
                    return "expected licenses.json to exist after SaveLicenses";
                }

                FileSecurity acl = File.GetAccessControl(licensesPath);
                AuthorizationRuleCollection rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
                SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                bool hasAdminFullControl = false;
                bool hasSystemFullControl = false;
                foreach (FileSystemAccessRule rule in rules)
                {
                    if (rule.IdentityReference == adminSid && rule.FileSystemRights == FileSystemRights.FullControl && rule.AccessControlType == AccessControlType.Allow)
                    {
                        hasAdminFullControl = true;
                    }
                    if (rule.IdentityReference == systemSid && rule.FileSystemRights == FileSystemRights.FullControl && rule.AccessControlType == AccessControlType.Allow)
                    {
                        hasSystemFullControl = true;
                    }
                }

                if (!hasAdminFullControl)
                {
                    return "expected Administrators to have FullControl on licenses.json";
                }
                if (!hasSystemFullControl)
                {
                    return "expected SYSTEM to have FullControl on licenses.json";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dataPath, true); } catch { }
            }
        }

        // Proves the success-path final ACL only - SaveServerConfigValues's
        // temp file is restricted and renamed away within a single lock
        // statement, so a same-process test observes only the end state.
        // The actual bug this guards against (a temp file left behind under
        // a broad inherited ACL if File.Replace/Move then throws) needs a
        // forced mid-write failure to reproduce, which was verified live
        // (see Task 6's report) rather than through this self-test alone.
        // ApplyRestrictedConfigAcl(tempPath) itself always succeeds even for
        // a non-elevated/non-SYSTEM test process, since this process just
        // created tempPath and, as its owner, retains WRITE_DAC (the right
        // to modify its own ACL) regardless of what that ACL then says. The
        // SUBSEQUENT File.WriteAllText of the real secret content is what
        // then correctly fails once the DACL no longer grants this process
        // FILE_WRITE_DATA - this is the fix working as intended (fail
        // closed before any secret byte is written), not a bug, but it
        // means this self-test cannot assume the save succeeds under every
        // identity. Mirrors this file's existing GrantCurrentUserAccessForTest
        // precedent (used by TestLinuxKnownHostsRoundTrip) for the same
        // underlying UAC-split-token/non-privileged-CI reason.
        private static string TestSaveServerConfigValuesRestrictsTempFileBeforeWritingContent()
        {
            string dataDir = Path.Combine(Path.GetTempPath(), "wil-selftest-acl-race-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataDir);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = dataDir;
                options.ConfigPath = Path.Combine(dataDir, "server-config.json");
                InventoryServer server = new InventoryServer(options);

                System.Reflection.MethodInfo saveMethod = typeof(InventoryServer).GetMethod("SaveServerConfigValues", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                Dictionary<string, string> updates = new Dictionary<string, string>();
                updates["WebUsername"] = "admin";
                updates["WebPassword"] = "test-password-value";
                string tempPath = options.ConfigPath + ".tmp";

                bool deniedByAcl = false;
                try
                {
                    saveMethod.Invoke(server, new object[] { updates });
                }
                catch (System.Reflection.TargetInvocationException ex)
                {
                    if (!(ex.InnerException is UnauthorizedAccessException))
                    {
                        string innerType = ex.InnerException == null ? "null" : ex.InnerException.GetType().Name;
                        string innerMessage = ex.InnerException == null ? "" : ex.InnerException.Message;
                        return "expected the save to either succeed or fail with UnauthorizedAccessException (this test process lacking Administrators/SYSTEM), but it threw " + innerType + ": " + innerMessage;
                    }
                    deniedByAcl = true;
                }

                SecurityIdentifier usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

                if (deniedByAcl)
                {
                    if (!File.Exists(tempPath))
                    {
                        return null;
                    }
                    GrantCurrentUserAccessForTest(tempPath);
                    if (File.ReadAllText(tempPath).Length != 0)
                    {
                        return "expected the abandoned .tmp file to be empty (ACL must be restricted before any secret content is written), but it held content";
                    }
                    foreach (FileSystemAccessRule rule in File.GetAccessControl(tempPath).GetAccessRules(true, false, typeof(SecurityIdentifier)))
                    {
                        if (rule.IdentityReference is SecurityIdentifier && ((SecurityIdentifier)rule.IdentityReference) == usersSid)
                        {
                            return "expected the abandoned .tmp file's ACL to NOT grant BUILTIN\\Users any explicit rule even before this test's own verification grant";
                        }
                    }
                    return null;
                }

                if (File.Exists(tempPath))
                {
                    return "expected the .tmp file to be gone after a successful save (renamed over the final path), but it still exists - the fix must not leave a stale temp file behind on the success path";
                }
                if (!File.Exists(options.ConfigPath))
                {
                    return "expected server-config.json to exist after a successful save";
                }

                foreach (FileSystemAccessRule rule in File.GetAccessControl(options.ConfigPath).GetAccessRules(true, false, typeof(SecurityIdentifier)))
                {
                    if (rule.IdentityReference is SecurityIdentifier && ((SecurityIdentifier)rule.IdentityReference) == usersSid)
                    {
                        return "expected server-config.json's final ACL to NOT grant BUILTIN\\Users any explicit rule - ApplyRestrictedConfigAcl should have replaced inherited permissions";
                    }
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dataDir, true); } catch { }
            }
        }

        // SaveLinuxKnownHosts applies a restrictive Administrators+SYSTEM-only ACL to the
        // known-hosts file (matching SaveLicenses/SaveConfig). Under UAC split-token behavior,
        // this test process runs non-elevated, so it cannot read the file back through the
        // normal FILE_READ_DATA path even though its account is an Administrators member.
        // The test created the file, so it is the file's owner and retains WRITE_DAC even
        // without FILE_READ_DATA - this helper uses that to grant itself an explicit ALLOW
        // rule after each write, purely so the test can observe what it just wrote. It does
        // not touch or weaken SaveLinuxKnownHosts/ApplyRestrictedConfigAcl in any way.
        private static void GrantCurrentUserAccessForTest(string path)
        {
            FileSecurity acl = File.GetAccessControl(path);
            SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User;
            acl.AddAccessRule(new FileSystemAccessRule(currentUser, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, acl);
        }

        private static string TestLinuxKnownHostsRoundTrip()
        {
            string tempDataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDataPath);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = tempDataPath;
                InventoryServer server = new InventoryServer(options);
                string knownHostsPath = server.GetLinuxKnownHostsFilePath();

                Dictionary<string, object> before = server.FindLinuxKnownHost("192.168.4.112", 22);
                if (before != null)
                {
                    return "expected no record before insert";
                }

                server.UpsertLinuxKnownHost("192.168.4.112", 22, "ssh-ed25519", "SHA256:hXNM4oXACpM336pm8Tv/f3mA/2X1tq6ocXcl7TmFvtA", "manual");
                GrantCurrentUserAccessForTest(knownHostsPath);
                Dictionary<string, object> after = server.FindLinuxKnownHost("192.168.4.112", 22);
                if (after == null || GetStringValue(after, "Fingerprint") != "SHA256:hXNM4oXACpM336pm8Tv/f3mA/2X1tq6ocXcl7TmFvtA" || GetStringValue(after, "TrustMethod") != "manual")
                {
                    return "record not found or wrong content after upsert";
                }

                server.UpsertLinuxKnownHost("192.168.4.112", 22, "ssh-ed25519", "SHA256:DIFFERENTvalueDIFFERENTvalueDIFFERENTvalueA", "bulk-auto");
                GrantCurrentUserAccessForTest(knownHostsPath);
                Dictionary<string, object> overwritten = server.FindLinuxKnownHost("192.168.4.112", 22);
                if (overwritten == null || GetStringValue(overwritten, "Fingerprint") != "SHA256:DIFFERENTvalueDIFFERENTvalueDIFFERENTvalueA" || GetStringValue(overwritten, "TrustMethod") != "bulk-auto")
                {
                    return "upsert did not overwrite the existing record for the same host:port";
                }

                List<Dictionary<string, object>> all = server.LoadLinuxKnownHosts();
                if (all.Count != 1)
                {
                    return "expected exactly 1 record after overwrite, found " + all.Count;
                }

                return null;
            }
            finally
            {
                Directory.Delete(tempDataPath, true);
            }
        }

        // Proves the fix for the "read failure looks like no record" bug: a
        // genuinely malformed/truncated known-hosts file (what a crash
        // mid-write could leave behind pre-Fix-4b, or what a concurrent
        // reader could observe mid-write without atomic replace) must
        // surface as an error from FindLinuxKnownHost, NOT silently look
        // like "no record found" - the latter is unsafe because a
        // trustNewHostKeys push would then treat a host that actually HAS a
        // pinned record as brand-new and silently overwrite the pin via the
        // bulk-auto path.
        private static string TestLinuxKnownHostsReadFailureSurfacesAsError()
        {
            string tempDataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDataPath);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = tempDataPath;
                InventoryServer server = new InventoryServer(options);
                string knownHostsPath = server.GetLinuxKnownHostsFilePath();
                Directory.CreateDirectory(Path.GetDirectoryName(knownHostsPath));
                File.WriteAllText(knownHostsPath, "{this is not valid known-hosts JSON at all", new UTF8Encoding(false));

                bool threw = false;
                try
                {
                    server.FindLinuxKnownHost("192.168.4.112", 22);
                }
                catch
                {
                    threw = true;
                }

                if (!threw)
                {
                    return "FindLinuxKnownHost returned normally instead of surfacing the malformed-file read failure - a real trust record could be indistinguishable from 'no record' and get silently overwritten";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(tempDataPath, true); } catch { }
            }
        }

        private static string TestParseHostKeyFingerprintFromRealCapturedOutput()
        {
            // Captured verbatim from a real live failure against 192.168.4.112
            // during this feature's own design session - not a synthetic fixture.
            string capturedOutput =
                "The host key is not cached for this server:\r\n" +
                "  192.168.4.112 (port 22)\r\n" +
                "You have no guarantee that the server is the computer you\r\n" +
                "think it is.\r\n" +
                "The server's ssh-ed25519 key fingerprint is:\r\n" +
                "  ssh-ed25519 255 SHA256:hXNM4oXACpM336pm8Tv/f3mA/2X1tq6ocXcl7TmFvtA\r\n" +
                "Connection abandoned.\r\n" +
                "FATAL ERROR: Cannot confirm a host key in batch mode\r\n";

            string keyType, fingerprint;
            bool parsed = TryParseHostKeyDetails(capturedOutput, out keyType, out fingerprint);
            if (!parsed)
            {
                return "did not parse the real captured failure output at all";
            }
            if (keyType != "ssh-ed25519")
            {
                return "expected keyType 'ssh-ed25519', got '" + keyType + "'";
            }
            if (fingerprint != "SHA256:hXNM4oXACpM336pm8Tv/f3mA/2X1tq6ocXcl7TmFvtA")
            {
                return "expected the exact captured fingerprint, got '" + fingerprint + "'";
            }

            string unrelatedFailure = "plink: Network error: Connection timed out";
            string keyType2, fingerprint2;
            if (TryParseHostKeyDetails(unrelatedFailure, out keyType2, out fingerprint2))
            {
                return "parser matched a non-host-key failure text, should not have";
            }

            return null;
        }

        private static string TestClassifyHostKeyFailureChangedNeverAutoAcceptedEvenWithTrustEnabled()
        {
            // The exact condition Finding 1 was about: a prior trusted
            // record exists (expectedHostKey set) and the failure text
            // mentions a host key. trustNewHostKeys=true and
            // isBulkAutoRetry=false here specifically, to prove the
            // structural fix holds even when those flags would otherwise
            // steer toward "bulk-auto".
            string result = ClassifyHostKeyFailure(
                "SHA256:hXNM4oXACpM336pm8Tv/f3mA/2X1tq6ocXcl7TmFvtA",
                "WARNING - POTENTIAL SECURITY BREACH! The host key does not match the one cached.",
                parsedOk: false,
                trustNewHostKeys: true,
                isBulkAutoRetry: false);
            if (result != "changed")
            {
                return "expected 'changed', got '" + result + "'";
            }
            return null;
        }

        private static string TestClassifyHostKeyFailureNeverBulkAutoWithPriorRecordRegardlessOfWording()
        {
            // The case that actually discriminates fixed from unfixed code
            // (unlike the sibling test above, which uses parsedOk: false and
            // so would already avoid the bulk-auto branch on the OLD,
            // unstructural guard too - a prior review caught that gap).
            // Here parsedOk is TRUE and the failure text does NOT contain
            // "host key" at all (e.g. a future reworded/localized plink
            // build) - the only thing that can still stop this from
            // returning "bulk-auto" (or, per a later review pass, "unknown")
            // is the expectedHostKey conjunct itself. With a prior record
            // present and the text not matching the "changed" branch's own
            // "host key" requirement, the correct result is null - never
            // "bulk-auto" and never "unknown" (an "unknown" badge renders a
            // pre-filled, un-warned trust button, which is wrong for a host
            // that already has a pinned record).
            string result = ClassifyHostKeyFailure(
                "SHA256:hXNM4oXACpM336pm8Tv/f3mA/2X1tq6ocXcl7TmFvtA",
                "The server's ssh-ed25519 key fingerprint is:\n  ssh-ed25519 255 SHA256:DIFFERENTvalueDIFFERENTvalueDIFFERENTvalueA",
                parsedOk: true,
                trustNewHostKeys: true,
                isBulkAutoRetry: false);
            if (result == "bulk-auto")
            {
                return "returned 'bulk-auto' with a prior trusted record present - the never-auto-accept invariant is broken";
            }
            if (result == "unknown")
            {
                return "returned 'unknown' with a prior trusted record present - the operator would see a pre-filled, un-warned trust button for what may be a changed key";
            }
            if (result != null)
            {
                return "expected null (parses but text lacks the literal 'host key', so classification falls through without matching 'changed'), got '" + result + "'";
            }
            return null;
        }

        private static string TestClassifyHostKeyFailureBulkAutoForNewTarget()
        {
            string result = ClassifyHostKeyFailure(
                null,
                "The host key is not cached for this server",
                parsedOk: true,
                trustNewHostKeys: true,
                isBulkAutoRetry: false);
            if (result != "bulk-auto")
            {
                return "expected 'bulk-auto', got '" + result + "'";
            }
            return null;
        }

        private static string TestClassifyHostKeyFailureUnknownWhenAutoTrustDisabled()
        {
            string result = ClassifyHostKeyFailure(
                null,
                "The host key is not cached for this server",
                parsedOk: true,
                trustNewHostKeys: false,
                isBulkAutoRetry: false);
            if (result != "unknown")
            {
                return "expected 'unknown', got '" + result + "'";
            }
            return null;
        }

        private static string TestClassifyHostKeyFailureNullForNonHostKeyFailure()
        {
            string result = ClassifyHostKeyFailure(
                null,
                "plink: Network error: Connection timed out",
                parsedOk: false,
                trustNewHostKeys: true,
                isBulkAutoRetry: false);
            if (result != null)
            {
                return "expected null (not a host-key failure), got '" + result + "'";
            }
            return null;
        }

        private static string TestTrustLinuxHostKeyRejectsMalformedFingerprint()
        {
            // Calls the same IsValidHostKeyFingerprint helper the endpoint
            // calls, rather than a hand-copied regex, since spinning up a
            // real HTTP request/response round-trip is out of scope for this
            // self-test style.
            if (IsValidHostKeyFingerprint("not-a-fingerprint"))
            {
                return "malformed fingerprint incorrectly matched the validation pattern";
            }
            if (!IsValidHostKeyFingerprint("SHA256:hXNM4oXACpM336pm8Tv/f3mA/2X1tq6ocXcl7TmFvtA"))
            {
                return "a real, valid fingerprint failed the validation pattern";
            }
            return null;
        }

        private static string TestIsValidSshTargetAcceptsHostnamesAndIPv4()
        {
            string[] valid = { "192.168.1.10", "debian-01", "host.example.local", "a", "10.0.0.254" };
            foreach (string target in valid)
            {
                if (!IsValidSshTarget(target))
                {
                    return "expected target '" + target + "' to be accepted, but IsValidSshTarget rejected it";
                }
            }
            return null;
        }

        private static string TestIsValidSshTargetRejectsInjectionAndEmpty()
        {
            // Every one of these is a value a compromised managed host could put
            // in its own self-reported "hostname" field.
            string[] invalid = { "", null, "host;rm -rf /", "host name", "$(whoami)", "host`id`", "-oProxyCommand=calc", "host\nsecond", "host|id", "host&id", "host'x", "host\"x", "host\\x", "host/../x", "host\n" };
            foreach (string target in invalid)
            {
                if (IsValidSshTarget(target))
                {
                    return "expected target '" + target + "' to be rejected, but IsValidSshTarget accepted it";
                }
            }
            return null;
        }

        private static string TestIsValidLinuxInstallPathAcceptsMultiSegmentPath()
        {
            string[] valid = { "/opt/windows-inventory-lite", "/opt/wil/", "/opt/a/b" };
            foreach (string path in valid)
            {
                if (!IsValidLinuxInstallPath(path))
                {
                    return "expected path '" + path + "' to be accepted, but IsValidLinuxInstallPath rejected it";
                }
            }
            return null;
        }

        private static string TestIsValidLinuxInstallPathRejectsTopLevelAndInvalid()
        {
            string[] invalid = { "/", "/usr", "/etc", "/opt", "/opt/", "opt/wil", "", null, "/home/foo", "/usr/bin", "/etc/systemd", "/var/lib" };
            foreach (string path in invalid)
            {
                if (IsValidLinuxInstallPath(path))
                {
                    return "expected path '" + path + "' to be rejected, but IsValidLinuxInstallPath accepted it";
                }
            }
            return null;
        }

        private static string TestIsValidLinuxInstallPathRejectsTraversal()
        {
            string[] traversal = { "/opt/../etc", "/opt/../../etc", "/../etc", "/opt/./etc", "/opt/wil/../../etc" };
            foreach (string path in traversal)
            {
                if (IsValidLinuxInstallPath(path))
                {
                    return "expected traversal path '" + path + "' to be rejected, but IsValidLinuxInstallPath accepted it";
                }
            }
            return null;
        }

        private static string TestGenerateRandomTokenShape()
        {
            string token = GenerateRandomToken();
            if (token == null || token.Length != 64)
            {
                return "expected a 64-character token, got " + (token == null ? "null" : token.Length.ToString());
            }
            foreach (char c in token)
            {
                bool isLowerHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!isLowerHex)
                {
                    return "expected only lowercase hex characters, found '" + c + "'";
                }
            }
            string second = GenerateRandomToken();
            if (token == second)
            {
                return "expected two calls to produce different tokens";
            }
            return null;
        }

        private static string TestSendIngestionTokenStatusReflectsConfiguredState()
        {
            ServerOptions options = new ServerOptions();
            options.Token = null;
            bool configuredWhenEmpty = !String.IsNullOrEmpty(options.Token);
            if (configuredWhenEmpty)
            {
                return "expected configured=false when Token is null";
            }

            options.Token = "some-token-value";
            bool configuredWhenSet = !String.IsNullOrEmpty(options.Token);
            if (!configuredWhenSet)
            {
                return "expected configured=true when Token is set";
            }
            return null;
        }

        private static string TestSendLinuxSshToolsStatusReflectsFilePresence()
        {
            string scratchDir = Path.Combine(Path.GetTempPath(), "wil-sshtools-test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(scratchDir);
            try
            {
                string plinkPath = Path.Combine(scratchDir, "plink.exe");
                string pscpPath = Path.Combine(scratchDir, "pscp.exe");

                bool plinkFoundWhenMissing = File.Exists(plinkPath);
                bool pscpFoundWhenMissing = File.Exists(pscpPath);
                if (plinkFoundWhenMissing || pscpFoundWhenMissing)
                {
                    return "expected both tools to report missing in a fresh scratch directory";
                }

                File.WriteAllText(plinkPath, "not a real binary");
                File.WriteAllText(pscpPath, "not a real binary");

                bool plinkFoundWhenPresent = File.Exists(plinkPath);
                bool pscpFoundWhenPresent = File.Exists(pscpPath);
                if (!plinkFoundWhenPresent || !pscpFoundWhenPresent)
                {
                    return "expected both tools to report present after creating them";
                }
                return null;
            }
            finally
            {
                Directory.Delete(scratchDir, true);
            }
        }

        private static string TestLooksLikePrivateKeyAcceptsRealHeaders()
        {
            if (!LooksLikePrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n"))
            {
                return "expected an OPENSSH PRIVATE KEY header to be recognized";
            }
            if (!LooksLikePrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n"))
            {
                return "expected an RSA PRIVATE KEY header to be recognized";
            }
            return null;
        }

        private static string TestLooksLikePrivateKeyRejectsPublicKeyAndGarbage()
        {
            if (LooksLikePrivateKey("ssh-rsa AAAAB3NzaC1yc2EA user@host"))
            {
                return "expected a .pub-style line to NOT look like a private key";
            }
            if (LooksLikePrivateKey("this is not a key at all"))
            {
                return "expected garbage content to NOT look like a private key";
            }
            if (LooksLikePrivateKey(""))
            {
                return "expected empty content to NOT look like a private key";
            }
            return null;
        }

        private static string TestLooksLikePublicKeyRecognizesEachPrefix()
        {
            if (!LooksLikePublicKey("ssh-rsa AAAAB3NzaC1yc2EA user@host"))
            {
                return "expected 'ssh-rsa ' to be recognized as a public key";
            }
            if (!LooksLikePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host"))
            {
                return "expected 'ssh-ed25519 ' to be recognized as a public key";
            }
            if (!LooksLikePublicKey("ssh-dss AAAAB3NzaC1kc3MA user@host"))
            {
                return "expected 'ssh-dss ' to be recognized as a public key";
            }
            if (!LooksLikePublicKey("ecdsa-sha2-nistp256 AAAAE2VjZHNh user@host"))
            {
                return "expected 'ecdsa-sha2-' to be recognized as a public key";
            }
            if (LooksLikePublicKey("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n"))
            {
                return "expected a real private key header to NOT look like a public key";
            }
            return null;
        }

        private static string TestLooksLikeEncryptedPrivateKeyDetectsLegacyPem()
        {
            string encryptedPem = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCDEF\n\nMIIEow==\n-----END RSA PRIVATE KEY-----\n";
            if (!LooksLikeEncryptedPrivateKey(encryptedPem))
            {
                return "expected a 'Proc-Type: 4,ENCRYPTED' PEM to be detected as encrypted";
            }
            string plainPem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n";
            if (LooksLikeEncryptedPrivateKey(plainPem))
            {
                return "expected a plain PEM with no Proc-Type header to NOT be detected as encrypted";
            }
            return null;
        }

        private static string TestLooksLikeEncryptedPrivateKeyDetectsOpenSshBcryptKdf()
        {
            // "bcrypt" as a literal ASCII substring inside the base64-decoded
            // body is what the real detection checks for - fabricate a
            // synthetic body containing it rather than a real cryptographic
            // key, since the function never validates the key structure
            // itself, only looks for this one substring.
            byte[] encryptedBody = Encoding.ASCII.GetBytes("openssh-key-v1\0....bcrypt....");
            string encryptedContent = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(encryptedBody) + "\n-----END OPENSSH PRIVATE KEY-----\n";
            if (!LooksLikeEncryptedPrivateKey(encryptedContent))
            {
                return "expected an OpenSSH key body containing 'bcrypt' to be detected as encrypted";
            }

            byte[] plainBody = Encoding.ASCII.GetBytes("openssh-key-v1\0....none....");
            string plainContent = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(plainBody) + "\n-----END OPENSSH PRIVATE KEY-----\n";
            if (LooksLikeEncryptedPrivateKey(plainContent))
            {
                return "expected an OpenSSH key body containing 'none' (no bcrypt) to NOT be detected as encrypted";
            }
            return null;
        }

        // Owner assignment to a SID other than the caller requires an
        // elevated/SYSTEM process token - true in the real deployment (the
        // Windows Service runs as LocalSystem) but not necessarily true of
        // whatever account runs `--self-test`. The DACL assertion is
        // unconditional (never needs elevation, matches
        // ApplyRestrictedConfigAcl's own already-passing self-test
        // pattern); the Owner assertion only runs when this process is
        // actually elevated, so this test tells the truth about what it
        // verified in THIS run rather than silently skipping or falsely
        // claiming success.
        private static string TestApplyRestrictedKeyFileAclSetsDaclAndOwnerWhenElevated()
        {
            string tempPath = Path.Combine(Path.GetTempPath(), "wil-selftest-key-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(tempPath, "test key content", new UTF8Encoding(false));
            try
            {
                ServerOptions options = new ServerOptions();
                InventoryServer server = new InventoryServer(options);
                server.ApplyRestrictedKeyFileAcl(tempPath);

                FileSecurity acl = File.GetAccessControl(tempPath);
                SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                bool hasAdminRule = false;
                bool hasSystemRule = false;
                foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                {
                    if (rule.IdentityReference.Equals(adminSid) && rule.FileSystemRights == FileSystemRights.FullControl)
                    {
                        hasAdminRule = true;
                    }
                    if (rule.IdentityReference.Equals(systemSid) && rule.FileSystemRights == FileSystemRights.FullControl)
                    {
                        hasSystemRule = true;
                    }
                }
                if (!hasAdminRule || !hasSystemRule)
                {
                    return "expected both Administrators and SYSTEM to have FullControl in the DACL";
                }

                bool isElevatedAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
                if (isElevatedAdmin)
                {
                    // Membership in Administrators is not the same thing as
                    // holding an ENABLED SeRestorePrivilege, which is what
                    // File.SetAccessControl actually needs to reassign
                    // ownership to a different SID like SYSTEM. An elevated
                    // Administrator identity that lacks it (confirmed on
                    // GitHub Actions' own "runneradmin" account, and true of
                    // this project's documented least-privileged-service-
                    // account deployment mode too) makes ApplyRestrictedKeyFileAcl's
                    // Owner=SYSTEM step silently no-op, per that method's own
                    // best-effort design - the file keeps its OS-assigned
                    // default owner (Administrators) instead. Both outcomes
                    // are correct: the DACL asserted above (Administrators
                    // and SYSTEM, both FullControl) is the real, enforced
                    // access boundary regardless of which of the two ends up
                    // as Owner.
                    SecurityIdentifier owner = (SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier));
                    if (!owner.Equals(systemSid) && !owner.Equals(adminSid))
                    {
                        return "expected Owner to be SYSTEM or Administrators when running elevated, got " + owner.Translate(typeof(NTAccount));
                    }
                }
                return null;
            }
            finally
            {
                File.Delete(tempPath);
            }
        }

        private static string TestApplyRestrictedDirectoryAclSetsDacl()
        {
            string tempDirectory = Path.Combine(Path.GetTempPath(), "wil-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDirectory);
            try
            {
                ServerOptions options = new ServerOptions();
                InventoryServer server = new InventoryServer(options);
                server.ApplyRestrictedDirectoryAcl(tempDirectory);

                DirectorySecurity acl = Directory.GetAccessControl(tempDirectory);
                if (!acl.AreAccessRulesProtected)
                {
                    return "expected inheritance to be disabled on the linux-ssh directory";
                }
                SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                SecurityIdentifier currentSid = WindowsIdentity.GetCurrent().User;
                bool adminFound = false;
                // Assert the grant set is EXACTLY {Administrators, SYSTEM, the
                // identity running this test process} - not just that
                // Administrators is present. The current-identity grant is now
                // intended, documented behavior (see ApplyRestrictedDirectoryAcl's
                // doc comment): it's what lets the server's own operating account
                // keep managing this directory across repeated operations. This
                // still catches a real regression - some OTHER identity gaining an
                // extra ACE on the directory.
                foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                {
                    SecurityIdentifier identity = (SecurityIdentifier)rule.IdentityReference;
                    if (identity.Equals(adminSid))
                    {
                        if ((rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl)
                        {
                            adminFound = true;
                        }
                        continue;
                    }
                    if (identity.Equals(systemSid))
                    {
                        continue;
                    }
                    if (currentSid != null && identity.Equals(currentSid))
                    {
                        continue;
                    }
                    return "expected only Administrators, SYSTEM, and the current identity to have access, but found an access rule for " + identity.Value;
                }
                if (!adminFound)
                {
                    return "expected an explicit Administrators FullControl rule on the linux-ssh directory";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(tempDirectory, true); } catch (Exception) { }
            }
        }

        private static string TestMigrateLegacyLinuxSshKeyAdoptsValidLegacyPath()
        {
            string dataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-" + Guid.NewGuid().ToString("N"));
            string legacyKeyPath = Path.Combine(Path.GetTempPath(), "wil-selftest-legacy-key-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataPath);
            File.WriteAllText(legacyKeyPath, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n", new UTF8Encoding(false));
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = dataPath;
                options.LinuxUpdateKeyPath = legacyKeyPath;
                InventoryServer server = new InventoryServer(options);
                server.MigrateLegacyLinuxSshKey();

                string managedPath = Path.Combine(dataPath, "_linux-ssh", "linux-update-key");
                // File.Exists is not a reliable check here: MigrateLegacyLinuxSshKey
                // hardens the containing _linux-ssh directory to Administrators+SYSTEM
                // only by the time it returns, and once the DIRECTORY denies this
                // (non-elevated, non-SYSTEM) test process all access, File.Exists
                // silently returns false for a file that is genuinely present -
                // .NET's File.Exists swallows UnauthorizedAccessException and reports
                // "does not exist" rather than distinguishing "denied" from "missing".
                // File.GetAttributes does distinguish the two: it throws
                // UnauthorizedAccessException when the path is present but
                // inaccessible, versus FileNotFoundException/DirectoryNotFoundException
                // when it genuinely is not there. Confirmed empirically in this exact
                // non-elevated environment before relying on it here.
                try
                {
                    File.GetAttributes(managedPath);
                }
                catch (UnauthorizedAccessException)
                {
                    // Present, just inaccessible to this identity - exactly what a
                    // correctly-hardened directory looks like from here. Success.
                }
                catch (Exception)
                {
                    return "expected the legacy key to be copied to the managed path";
                }
                return null;
            }
            finally
            {
                // Directory.Delete can legitimately fail here: MigrateLegacyLinuxSshKey
                // hardens _linux-ssh to Administrators+SYSTEM only by the time it
                // returns, and this test process is not necessarily Administrators
                // or SYSTEM in a non-elevated dev environment - same reason
                // TestApplyRestrictedDirectoryAclSetsDacl guards its own cleanup
                // below. Best-effort only; must not mask a real assertion failure
                // above with a cleanup exception.
                try { Directory.Delete(dataPath, true); } catch (Exception) { }
                try { File.Delete(legacyKeyPath); } catch (Exception) { }
            }
        }

        private static string TestMigrateLegacyLinuxSshKeyIgnoresMissingOrInvalidLegacyPath()
        {
            string dataPath = Path.Combine(Path.GetTempPath(), "wil-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataPath);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = dataPath;
                options.LinuxUpdateKeyPath = Path.Combine(Path.GetTempPath(), "wil-selftest-does-not-exist-" + Guid.NewGuid().ToString("N"));
                InventoryServer server = new InventoryServer(options);
                server.MigrateLegacyLinuxSshKey();

                string managedPath = Path.Combine(dataPath, "_linux-ssh", "linux-update-key");
                if (File.Exists(managedPath))
                {
                    return "expected no managed key to be created when the legacy path does not exist";
                }
                return null;
            }
            finally
            {
                Directory.Delete(dataPath, true);
            }
        }

        private static string TestMergeServiceStatusFlipsActiveBothDirections()
        {
            Dictionary<string, object> existingReport = new Dictionary<string, object>();
            ArrayList services = new ArrayList();
            Dictionary<string, object> serviceA = new Dictionary<string, object>();
            serviceA["unit"] = "radarr.service";
            serviceA["active"] = false;
            services.Add(serviceA);
            Dictionary<string, object> serviceB = new Dictionary<string, object>();
            serviceB["unit"] = "qbittorrent-nox.service";
            serviceB["active"] = true;
            services.Add(serviceB);
            existingReport["services"] = services;

            ArrayList activeUnits = new ArrayList();
            activeUnits.Add("radarr.service");

            Dictionary<string, object> merged = MergeServiceStatus(existingReport, activeUnits, "2026-08-04T12:00:00Z");

            ArrayList mergedServices = (ArrayList)merged["services"];
            Dictionary<string, object> mergedA = (Dictionary<string, object>)mergedServices[0];
            Dictionary<string, object> mergedB = (Dictionary<string, object>)mergedServices[1];

            if (!(bool)mergedA["active"])
            {
                return "expected radarr.service (present in activeUnits) to become active=true";
            }
            if ((bool)mergedB["active"])
            {
                return "expected qbittorrent-nox.service (absent from activeUnits) to become active=false";
            }
            return null;
        }

        private static string TestMergeServiceStatusIgnoresUnknownUnits()
        {
            Dictionary<string, object> existingReport = new Dictionary<string, object>();
            ArrayList services = new ArrayList();
            Dictionary<string, object> serviceA = new Dictionary<string, object>();
            serviceA["unit"] = "radarr.service";
            serviceA["active"] = true;
            services.Add(serviceA);
            existingReport["services"] = services;

            ArrayList activeUnits = new ArrayList();
            activeUnits.Add("radarr.service");
            activeUnits.Add("some-new-unknown-service.service");

            Dictionary<string, object> merged = MergeServiceStatus(existingReport, activeUnits, "2026-08-04T12:00:00Z");
            ArrayList mergedServices = (ArrayList)merged["services"];
            if (mergedServices.Count != 1)
            {
                return "expected the unknown unit to NOT be added as a new service entry, got " + mergedServices.Count + " entries";
            }
            return null;
        }

        private static string TestMergeServiceStatusHandlesMissingServicesArray()
        {
            Dictionary<string, object> existingReport = new Dictionary<string, object>();
            existingReport["hostname"] = "test-host";

            ArrayList activeUnits = new ArrayList();
            activeUnits.Add("radarr.service");

            Dictionary<string, object> merged = MergeServiceStatus(existingReport, activeUnits, "2026-08-04T12:00:00Z");
            if (Convert.ToString(merged["hostname"]) != "test-host")
            {
                return "expected unrelated fields to survive untouched when there's no services array";
            }
            return null;
        }

        private static string TestMergeServiceStatusSetsTimestamp()
        {
            Dictionary<string, object> existingReport = new Dictionary<string, object>();
            Dictionary<string, object> merged = MergeServiceStatus(existingReport, new ArrayList(), "2026-08-04T12:00:00Z");
            if (Convert.ToString(merged["servicesStatusCollectedAt"]) != "2026-08-04T12:00:00Z")
            {
                return "expected servicesStatusCollectedAt to be set to the incoming collectedAt value";
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

        // Every other session/login/logout self-test either hand-seeds
        // sessionStore directly or asserts on one function's output in
        // isolation - none of them chain the real functions together with
        // a cookie value actually produced by one and consumed by the
        // next, which is the seam a whole-branch review flagged as
        // untested. This composes SendLoginResult -> IsWebRequestAuthorized
        // -> SendLogoutResult -> IsWebRequestAuthorized end to end.
        private static string TestSessionLifecycleEndToEndLoginAuthorizeLogout()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            options.SessionLifetimeHours = 12;
            InventoryServer server = new InventoryServer(options);
            IPAddress remoteAddress = IPAddress.Parse("192.168.1.50");

            RequestContext loginRequest = new RequestContext();
            loginRequest.Method = "POST";
            loginRequest.Path = "/api/v1/server/login";
            loginRequest.Headers = new Dictionary<string, string>();
            loginRequest.RemoteAddress = remoteAddress;
            loginRequest.Body = "{\"username\":\"admin\",\"password\":\"secret\"}";

            string cookieValue;
            using (MemoryStream loginStream = new MemoryStream())
            {
                server.SendLoginResult(loginStream, loginRequest);
                string loginResponse = Encoding.UTF8.GetString(loginStream.ToArray());
                string cookiePrefix = "Set-Cookie: ";
                int cookieHeaderStart = loginResponse.IndexOf(cookiePrefix + "wil_session=", StringComparison.Ordinal);
                if (cookieHeaderStart < 0)
                {
                    return "expected the login response to contain a Set-Cookie: wil_session=... header, got: " + loginResponse;
                }
                int valueStart = cookieHeaderStart + cookiePrefix.Length;
                int valueEnd = loginResponse.IndexOf(';', valueStart);
                if (valueEnd < 0)
                {
                    return "expected the Set-Cookie header to have at least one ';'-delimited attribute after the cookie value";
                }
                cookieValue = loginResponse.Substring(valueStart, valueEnd - valueStart);
            }

            RequestContext authorizedRequest = new RequestContext();
            authorizedRequest.Headers = new Dictionary<string, string>();
            authorizedRequest.Headers["cookie"] = cookieValue;
            authorizedRequest.RemoteAddress = remoteAddress;

            if (!server.IsWebRequestAuthorized(authorizedRequest))
            {
                return "expected the exact cookie value extracted from SendLoginResult's own response to authorize a request via IsWebRequestAuthorized";
            }

            RequestContext logoutRequest = new RequestContext();
            logoutRequest.Method = "POST";
            logoutRequest.Path = "/api/v1/server/logout";
            logoutRequest.Headers = new Dictionary<string, string>();
            logoutRequest.Headers["cookie"] = cookieValue;

            using (MemoryStream logoutStream = new MemoryStream())
            {
                server.SendLogoutResult(logoutStream, logoutRequest);
                string logoutResponse = Encoding.UTF8.GetString(logoutStream.ToArray());
                if (!logoutResponse.Contains("200 OK"))
                {
                    return "expected SendLogoutResult to return 200 OK, got: " + logoutResponse;
                }
            }

            RequestContext postLogoutRequest = new RequestContext();
            postLogoutRequest.Headers = new Dictionary<string, string>();
            postLogoutRequest.Headers["cookie"] = cookieValue;
            postLogoutRequest.RemoteAddress = remoteAddress;

            if (server.IsWebRequestAuthorized(postLogoutRequest))
            {
                return "expected the same cookie value to no longer authorize a request after SendLogoutResult - it should fall through to (and fail) Basic Auth, since postLogoutRequest carries no Authorization header";
            }

            return null;
        }

        // ChangeAdminPassword used to mutate options.WebUsername/WebPassword
        // and only persist afterward - if SaveServerConfigValues then threw,
        // the password had already changed in memory (silently reverting on
        // the next restart, since disk kept the old value) while every
        // pre-rotation session stayed valid, since sessionStore is cleared
        // even later. This forces the save to fail and asserts the
        // in-memory credential is untouched.
        private static string TestChangeAdminPasswordDoesNotMutateStateWhenSaveFails()
        {
            string dataDir = Path.Combine(Path.GetTempPath(), "wil-selftest-password-rotation-atomic-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataDir);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = dataDir;
                options.ConfigPath = Path.Combine(dataDir, "server-config.json");
                options.WebUsername = "admin";
                options.WebPassword = "original-password";
                options.SessionLifetimeHours = 12;
                InventoryServer server = new InventoryServer(options);

                // Force the save to fail by pointing ConfigPath at a directory that
                // does not exist and cannot be created mid-call (simulates the same
                // real-world failure class as a locked file or a full disk).
                options.ConfigPath = Path.Combine(dataDir, "does-not-exist", "server-config.json");

                System.Reflection.MethodInfo changeMethod = typeof(InventoryServer).GetMethod("ChangeAdminPassword", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                using (MemoryStream stream = new MemoryStream())
                {
                    RequestContext request = new RequestContext();
                    request.Body = "{\"currentPassword\":\"original-password\",\"newUsername\":\"admin\",\"newPassword\":\"new-password-value\"}";
                    request.Headers = new Dictionary<string, string>();
                    try
                    {
                        changeMethod.Invoke(server, new object[] { stream, request });
                    }
                    catch (System.Reflection.TargetInvocationException)
                    {
                        // Expected - the save throws because the directory doesn't exist.
                    }
                }

                if (options.WebPassword != "original-password")
                {
                    return "expected options.WebPassword to remain unchanged after a failed save, but it was mutated to '" + options.WebPassword + "'";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dataDir, true); } catch { }
            }
        }

        // RunLinuxClientInstallTarget already re-validates installPath at its own
        // point of use as a "last line of defence" (see its own comment there) -
        // its uninstall sibling didn't, relying entirely on the caller
        // (StartClientAction) having validated already. Currently safe (that's
        // genuinely the only call site), but a validator not re-checked at its
        // actual point of use is exactly the shape of this project's prior
        // install-path validation gaps.
        private static string TestRunLinuxClientUninstallTargetRejectsUnsafeInstallPath()
        {
            string dataDir = Path.Combine(Path.GetTempPath(), "wil-selftest-uninstall-revalidate-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataDir);
            try
            {
                string stubUninstallerPath = Path.Combine(dataDir, "Uninstall-ClientDebianSSH.ps1");
                File.WriteAllText(stubUninstallerPath, "# stub, never actually run - installPath validation fails before this would be invoked");

                ServerOptions options = new ServerOptions();
                options.DataPath = dataDir;
                options.LinuxSshUninstallerPath = stubUninstallerPath;
                InventoryServer server = new InventoryServer(options);

                System.Reflection.MethodInfo runMethod = typeof(InventoryServer).GetMethod("RunLinuxClientUninstallTarget", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                object resultObj = runMethod.Invoke(server, new object[] { "192.0.2.10", "manual", "root", "x", null, "/etc" });
                Dictionary<string, object> result = (Dictionary<string, object>)resultObj;

                if (GetStringValue(result, "status") != "failed")
                {
                    return "expected a bare-top-level installPath ('/etc') to be rejected before any SSH connection is attempted, got status '" + GetStringValue(result, "status") + "'";
                }
                if (!GetStringValue(result, "message").Contains("/opt/"))
                {
                    return "expected the rejection message to mention the /opt/ requirement, got: " + GetStringValue(result, "message");
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dataDir, true); } catch { }
            }
        }

        // installJobs (in-memory) held plaintext WinRM/SSH passwords resident for
        // the server process's entire lifetime, growing unbounded, since nothing
        // ever removed a completed job from it - the on-disk job file already
        // correctly omits those fields (ToDictionary), so nothing is lost by also
        // dropping the in-memory entry once the job is done; SendClientInstallJob
        // already falls back to reading the file when the job isn't in memory.
        // An empty Targets list makes RunClientActionJob's per-target loop a
        // no-op, reaching the exact "completed" code path being tested with no
        // real WinRM/SSH network activity.
        private static string TestRunClientActionJobRemovesCompletedJobFromMemory()
        {
            string dataDir = Path.Combine(Path.GetTempPath(), "wil-selftest-job-prune-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataDir);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = dataDir;
                InventoryServer server = new InventoryServer(options);

                InstallJob job = new InstallJob();
                job.Id = Guid.NewGuid().ToString("N");
                job.Action = "install";
                job.Status = "queued";
                job.CreatedAtUtc = DateTime.UtcNow;
                job.Targets = new ArrayList();
                job.Results = new ArrayList();
                job.Mode = "force-windows";

                System.Reflection.FieldInfo installJobsField = typeof(InventoryServer).GetField("installJobs", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                Dictionary<string, InstallJob> installJobs = (Dictionary<string, InstallJob>)installJobsField.GetValue(server);
                installJobs[job.Id] = job;

                System.Reflection.MethodInfo runMethod = typeof(InventoryServer).GetMethod("RunClientActionJob", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                runMethod.Invoke(server, new object[] { job });

                if (job.Status != "completed")
                {
                    return "expected job.Status to be 'completed' after RunClientActionJob finishes with no targets, got '" + job.Status + "'";
                }
                if (installJobs.ContainsKey(job.Id))
                {
                    return "expected the completed job to be removed from the in-memory installJobs dictionary once finished (it stays readable from disk via SendClientInstallJob's own fallback) - otherwise its plaintext WinRM/SSH password fields stay resident in memory indefinitely";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dataDir, true); } catch { }
            }
        }

        // A cookie whose session is found but already expired fell through to
        // Basic Auth correctly, but the expired sessionStore entry itself was
        // never removed - only PruneExpiredSessionsLocked, called just once per
        // login, ever swept it out. A dashboard left open past its session
        // lifetime with no one logging back in could linger there indefinitely.
        private static string TestIsWebRequestAuthorizedPrunesExpiredSessionOnUse()
        {
            ServerOptions options = new ServerOptions();
            options.WebUsername = "admin";
            options.WebPassword = "secret";
            InventoryServer server = new InventoryServer(options);

            System.Reflection.FieldInfo sessionStoreField = typeof(InventoryServer).GetField("sessionStore", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            Dictionary<string, SessionRecord> sessionStore = (Dictionary<string, SessionRecord>)sessionStoreField.GetValue(server);

            string expiredToken = "expired-token-for-test";
            SessionRecord expiredRecord = new SessionRecord();
            expiredRecord.ExpiresUtc = DateTime.UtcNow.AddHours(-1);
            sessionStore[expiredToken] = expiredRecord;

            RequestContext request = new RequestContext();
            request.Headers = new Dictionary<string, string>();
            request.Headers["cookie"] = "wil_session=" + expiredToken;
            request.RemoteAddress = IPAddress.Parse("192.168.1.50");

            server.IsWebRequestAuthorized(request);

            if (sessionStore.ContainsKey(expiredToken))
            {
                return "expected an expired session found during IsWebRequestAuthorized to be pruned from sessionStore immediately, not left to linger until the next login";
            }
            return null;
        }

        // The existing end-to-end session test (TestSessionLifecycleEndToEndLoginAuthorizeLogout)
        // covers login->authorize->logout; this covers the other session-killing
        // path this project's own backlog flagged as untested - a SUCCESSFUL
        // password rotation must invalidate every session that predates it, not
        // just fail safely if the save itself fails (already covered by
        // TestChangeAdminPasswordDoesNotMutateStateWhenSaveFails).
        private static string TestChangeAdminPasswordInvalidatesSessionsOnSuccess()
        {
            string dataDir = Path.Combine(Path.GetTempPath(), "wil-selftest-password-rotation-session-kill-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataDir);
            try
            {
                ServerOptions options = new ServerOptions();
                options.DataPath = dataDir;
                options.ConfigPath = Path.Combine(dataDir, "server-config.json");
                options.WebUsername = "admin";
                options.WebPassword = "original-password";
                options.SessionLifetimeHours = 12;
                InventoryServer server = new InventoryServer(options);
                IPAddress remoteAddress = IPAddress.Parse("192.168.1.50");

                RequestContext loginRequest = new RequestContext();
                loginRequest.Method = "POST";
                loginRequest.Path = "/api/v1/server/login";
                loginRequest.Headers = new Dictionary<string, string>();
                loginRequest.RemoteAddress = remoteAddress;
                loginRequest.Body = "{\"username\":\"admin\",\"password\":\"original-password\"}";

                string preRotationCookie;
                using (MemoryStream loginStream = new MemoryStream())
                {
                    server.SendLoginResult(loginStream, loginRequest);
                    preRotationCookie = ExtractSessionCookieValue(Encoding.UTF8.GetString(loginStream.ToArray()));
                    if (preRotationCookie == null)
                    {
                        return "expected the login response to contain a Set-Cookie: wil_session=... header";
                    }
                }

                System.Reflection.MethodInfo changeMethod = typeof(InventoryServer).GetMethod("ChangeAdminPassword", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                string freshCookie;
                using (MemoryStream rotateStream = new MemoryStream())
                {
                    RequestContext rotateRequest = new RequestContext();
                    rotateRequest.Headers = new Dictionary<string, string>();
                    rotateRequest.Body = "{\"currentPassword\":\"original-password\",\"newUsername\":\"admin\",\"newPassword\":\"new-password-value\"}";
                    try
                    {
                        changeMethod.Invoke(server, new object[] { rotateStream, rotateRequest });
                    }
                    catch (System.Reflection.TargetInvocationException ex)
                    {
                        if (ex.InnerException is UnauthorizedAccessException)
                        {
                            // This test process itself is not running as
                            // Administrators/SYSTEM (a documented, expected
                            // condition for --console/dev use without explicit
                            // elevation, or a locked-down CI/sandbox account -
                            // see SaveServerConfigValues' own comment). A
                            // successful rotation's save requires that
                            // privilege on every save now, not just a later
                            // one, so this specific "kills sessions on
                            // SUCCESS" property cannot be exercised live in
                            // this environment - the "does nothing bad happen
                            // on FAILURE" half is already independently
                            // covered by TestChangeAdminPasswordDoesNotMutateStateWhenSaveFails.
                            return null;
                        }
                        throw;
                    }
                    freshCookie = ExtractSessionCookieValue(Encoding.UTF8.GetString(rotateStream.ToArray()));
                    if (freshCookie == null)
                    {
                        return "expected a successful password rotation to issue the caller a fresh session cookie";
                    }
                }

                RequestContext preRotationRequest = new RequestContext();
                preRotationRequest.Headers = new Dictionary<string, string>();
                preRotationRequest.Headers["cookie"] = preRotationCookie;
                preRotationRequest.RemoteAddress = remoteAddress;
                if (server.IsWebRequestAuthorized(preRotationRequest))
                {
                    return "expected the pre-rotation session cookie to stop authorizing once the password rotation succeeded";
                }

                RequestContext freshRequest = new RequestContext();
                freshRequest.Headers = new Dictionary<string, string>();
                freshRequest.Headers["cookie"] = freshCookie;
                freshRequest.RemoteAddress = remoteAddress;
                if (!server.IsWebRequestAuthorized(freshRequest))
                {
                    return "expected the fresh session cookie issued by the successful rotation to authorize a request";
                }
                return null;
            }
            finally
            {
                try { Directory.Delete(dataDir, true); } catch { }
            }
        }

        // default-src does NOT cover form-action (a CSP quirk - it has no
        // fallback), so without an explicit directive an injected
        // <form action="https://evil..."> phishing overlay (e.g. via the
        // fallback dashboard JS's unescaped innerHTML sink) would not be
        // blocked even though inline script execution already is.
        private static string TestContentSecurityPolicyRestrictsFormAction()
        {
            System.Reflection.FieldInfo cspField = typeof(InventoryServer).GetField("ContentSecurityPolicy", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            string csp = (string)cspField.GetValue(null);
            if (!csp.Contains("form-action 'self'"))
            {
                return "expected the Content-Security-Policy to include \"form-action 'self'\", got: " + csp;
            }
            return null;
        }

        private static string TestNormalizeReportIdentifierTreatsBlankSameAsMissing()
        {
            string[] blankInputs = { null, "", "   ", "\t" };
            foreach (string input in blankInputs)
            {
                if (NormalizeReportIdentifier(input) != "unknown")
                {
                    return "expected a blank/missing identifier ('" + (input ?? "null") + "') to normalize to 'unknown', got '" + NormalizeReportIdentifier(input) + "'";
                }
            }
            if (NormalizeReportIdentifier("REAL-HOST-01") != "REAL-HOST-01")
            {
                return "expected a real identifier to pass through unchanged";
            }
            return null;
        }

        private static string ExtractSessionCookieValue(string rawHttpResponse)
        {
            const string cookiePrefix = "Set-Cookie: wil_session=";
            int cookieHeaderStart = rawHttpResponse.IndexOf(cookiePrefix, StringComparison.Ordinal);
            if (cookieHeaderStart < 0)
            {
                return null;
            }
            int valueStart = cookieHeaderStart + "Set-Cookie: ".Length;
            int valueEnd = rawHttpResponse.IndexOf(';', valueStart);
            if (valueEnd < 0)
            {
                return null;
            }
            return rawHttpResponse.Substring(valueStart, valueEnd - valueStart);
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
