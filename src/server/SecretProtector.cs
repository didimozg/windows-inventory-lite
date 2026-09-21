using System;
using System.Security.Cryptography;
using System.Text;

namespace WindowsInventoryLite
{
    // Protects a secret (currently just the AD password) at rest in
    // server-config.json using Windows DPAPI, LocalMachine scope - any
    // process on this machine can decrypt it, which matters because this
    // Windows Service may run under LocalSystem/NetworkService/a service
    // account with no loaded interactive profile, so CurrentUser-scoped
    // DPAPI would not reliably work here. Values written before this
    // existed, or hand-edited directly into the config file, are plain
    // strings with no "dpapi:" prefix - Unprotect treats those as
    // already-plaintext rather than failing, and the next save
    // (ConfigureServerSettings or a re-run of Install-Server.ps1)
    // re-encrypts them.
    internal static class SecretProtector
    {
        private const string Prefix = "dpapi:";

        internal static string Protect(string plaintext, ServerOptions options, string fieldName, out bool encryptedSuccessfully)
        {
            return ProtectCore(plaintext, fieldName,
                bytes => ProtectedData.Protect(bytes, null, DataProtectionScope.LocalMachine),
                message => LogProtectionFailure(options, message),
                out encryptedSuccessfully);
        }

        // Testable core - protectBytes/onFailure are injected so a self-test
        // can force the failure path deterministically (a real DPAPI
        // failure can't be reliably triggered from a test) and assert the
        // exact failure message, matching this project's established
        // dependency-injection pattern for hard-to-fake OS operations.
        internal static string ProtectCore(string plaintext, string fieldName, Func<byte[], byte[]> protectBytes, Action<string> onFailure, out bool encryptedSuccessfully)
        {
            encryptedSuccessfully = true;
            if (String.IsNullOrEmpty(plaintext))
            {
                return plaintext;
            }
            if (plaintext.StartsWith(Prefix, StringComparison.Ordinal))
            {
                // Already protected - see the class-level comment.
                return plaintext;
            }
            try
            {
                byte[] encrypted = protectBytes(Encoding.UTF8.GetBytes(plaintext));
                return Prefix + Convert.ToBase64String(encrypted);
            }
            catch
            {
                encryptedSuccessfully = false;
                onFailure(fieldName + " could not be encrypted at rest (DPAPI unavailable) - stored in plaintext instead.");
                return plaintext;
            }
        }

        private static void LogProtectionFailure(ServerOptions options, string message)
        {
            // Logged via the Windows Event Log, not only the opt-in debug
            // log (which is off by default and would otherwise let this
            // confidentiality-control failure go completely unnoticed) -
            // matches this project's existing EventLog.WriteEntry pattern
            // used for other confidentiality/availability-relevant events
            // (e.g. the missing-certificate and listener-startup-failure
            // warnings elsewhere in WindowsInventoryLiteServer.cs).
            DebugLogger.Log(options, "Error", message);
            try
            {
                System.Diagnostics.EventLog.WriteEntry("WindowsInventoryLite", message, System.Diagnostics.EventLogEntryType.Warning);
            }
            catch
            {
            }
        }

        internal static string Unprotect(string stored)
        {
            if (String.IsNullOrEmpty(stored))
            {
                return stored;
            }
            if (!stored.StartsWith(Prefix, StringComparison.Ordinal))
            {
                return stored;
            }
            try
            {
                byte[] encrypted = Convert.FromBase64String(stored.Substring(Prefix.Length));
                byte[] plaintext = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);
                return Encoding.UTF8.GetString(plaintext);
            }
            catch
            {
                return null;
            }
        }
    }
}
