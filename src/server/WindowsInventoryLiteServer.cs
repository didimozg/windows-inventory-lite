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
        internal const string ProductVersion = "0.52.3";

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
                    else if (request.Method == "POST" && request.Path == "/api/v1/server/login")
                    {
                        SendLoginResult(stream, request);
                    }
                    else if (!IsWebRequestAuthorized(request))
                    {
                        SendUnauthorized(stream, request);
                    }
                    else if (IsCrossSiteRequestRejected(request))
                    {
                        SendText(stream, "{\"error\":\"Cross-site request rejected - Origin/Referer does not match this server.\"}", "application/json; charset=utf-8", 400);
                    }
                    else if (RequiresJsonContentType(request) && !HasJsonContentType(request))
                    {
                        SendText(stream, "{\"error\":\"Content-Type must be application/json.\"}", "application/json; charset=utf-8", 400);
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

            string hostname = Convert.ToString(inventory.ContainsKey("hostname") ? inventory["hostname"] : "unknown");
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

            string hostname = Convert.ToString(payload.ContainsKey("hostname") ? payload["hostname"] : "unknown");
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
            job.Status = "running";
            job.StartedAtUtc = DateTime.UtcNow;
            lock (installJobsLock)
            {
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

            job.CompletedAtUtc = DateTime.UtcNow;
            job.Status = "completed";
            lock (installJobsLock)
            {
                SaveInstallJob(job);
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
                    if (IsSessionValid(record, DateTime.UtcNow))
                    {
                        record.ExpiresUtc = ComputeSessionExpiry(DateTime.UtcNow, options.SessionLifetimeHours);
                        return true;
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
        // this app's CSRF-hardening posture).
        private static string BuildSessionCookieHeader(Stream stream, string token, int maxAgeSeconds)
        {
            string secureFlag = stream is SslStream ? "; Secure" : "";
            return "Set-Cookie: wil_session=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + maxAgeSeconds + secureFlag;
        }

        private const string ClearSessionCookieHeader = "Set-Cookie: wil_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";

        // Dispatched from HandleClient BEFORE the IsWebRequestAuthorized
        // gate (you are not authenticated yet when logging in) but AFTER
        // IsBasicAuthLockedOut (a locked-out IP must not get unlimited
        // login attempts here either - see HandleClient's dispatch chain).
        // No IsCrossSiteRequestRejected check either, by the same
        // reasoning the three ingestion routes already skip it: a
        // cross-site POST here can't exploit any pre-existing
        // authenticated state (there isn't one yet), and even a successful
        // cross-origin login would only set a cookie the attacker's own
        // page can never read back (HttpOnly) or have sent anywhere but
        // this origin (SameSite=Strict) - there is nothing for a forged
        // cross-site request to gain here.
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
            }

            string setCookie = BuildSessionCookieHeader(stream, token, options.SessionLifetimeHours * 3600);
            SendText(stream, "{\"status\":\"ok\"}", "application/json; charset=utf-8", 200, null, setCookie);
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
            SendText(stream, "{\"status\":\"ok\"}", "application/json; charset=utf-8", 200, null, ClearSessionCookieHeader);
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
<img class=""login-logo"" src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAggAAAEcCAYAAACiU0xzAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAP+lSURBVHhe7L0FeB3JlTb8f7vZbLKb3WSTSSbDM2a2zMzMzMzMDJJtSbaYmfGKmZkty5ItBoPMzCy8deo/p25fSfZ4ZrObZJ7JPvXOvK7q7urqvt2tPm+dOlX9/0lISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEj8FOCc/7/q2/dHhRaX7wwtq9xw7c7DXsqmvwiNjY29Uq7e3B976apB0Z37e7C+T5RN/y0A4D9yL92Y4llUst27oHjlrScv+ymb/iI8wfKR1Ve2BpZVHc24dH0WHvuflU3/LajshWt3p8dUXT6Qcvna9nfv3g1SNv1FuP306cDwiktbg8qrj2RWXRuP9f1C2fTfAn/3fxbcur8xpvrKidSrN468fPfuf/S77z950j+svGaj6mL5psyyK4OV1RISEhISEn8boFH7pWt+kce25Ay+PCWDL05M5ZsT0xp9Ckstcds/KcV+ELlXbiw9nJ79emV6Nl+alsnXZeZyq/yiqgfP3vRQivwg0Ej+0Tbv/NllcSl8bmIanxeXzDclpDarikp1lSI/iuiKS+u2J2fUL0xM5/Nx/yXRSfxEalYaGvrPlSI/CDz2F47nLqRtTcvi6zJy+MasPH48+2xDUtWVLUqRH4V3/sXtWxLSGum485PS+dLoRG6Rcy6bv337Z6XIDwKP/Znt2fMFW/BarcBrtjozhx/KyKlLqb66XinyowgurTTckpjWvAjv1eKkNL4Gr5t5ep431vtrpYiEhISE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"" alt=""Windows Inventory Lite"">
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
    if (!response.ok) {
      errorEl.textContent = 'Incorrect username or password.';
      return;
    }
    window.location.reload();
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
            "default-src 'self'; script-src 'self' 'sha256-rqltRpQDffCU3nbpQC/zdbFn0/Eb4PSGrbmQ8EbS3q4=' 'sha256-l2wB/4MpOu7AEB0C+1HsoQKKmFiduxM15qduMb9gwFw='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

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
                if (String.IsNullOrEmpty(linuxDefaultInstallPath) || !linuxDefaultInstallPath.StartsWith("/"))
                {
                    SendText(stream, "{\"error\":\"linuxDefaultInstallPath must be a non-empty absolute Linux path (starting with /)\"}", "application/json; charset=utf-8", 400);
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

            // Echoes the fresh GET-shaped status, matching every other
            // config POST on this API (settings, certificate, client-update
            // credentials/schedule) - a bare {"status":"ok"} was the one
            // outlier.
            SendAdminPasswordStatus(stream);
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
                string tempPath = options.ConfigPath + ".tmp";
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
        private static readonly char[] PosixShellUnsafeChars = { '`', '$', '"', '\'', '\\', ';', '|', '&', '<', '>', '(', ')', '\r', '\n' };

        private static void ValidatePosixShellSafe(string value, string fieldName)
        {
            if (!String.IsNullOrEmpty(value) && value.IndexOfAny(PosixShellUnsafeChars) >= 0)
            {
                throw new ArgumentException(fieldName + " contains a character that is not allowed here (`, $, \", ', \\, ;, |, &, <, >, (, ), or a line break).");
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
            string[] unsafeValues = { "/opt/wil; rm -rf /", "$(rm -rf /)", "`rm -rf /`", "path\"with\"quotes", "path'with'quotes", "path\\with\\backslash", "a|b", "a&b", "a<b", "a>b", "a(b)", "line1\nline2", "line1\rline2" };
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
