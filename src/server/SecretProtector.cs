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

        internal static string Protect(string plaintext)
        {
            if (String.IsNullOrEmpty(plaintext))
            {
                return plaintext;
            }
            try
            {
                byte[] encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(plaintext), null, DataProtectionScope.LocalMachine);
                return Prefix + Convert.ToBase64String(encrypted);
            }
            catch
            {
                // If DPAPI is unavailable for some reason, fall back to
                // storing the plaintext rather than losing the value
                // entirely - matches this project's existing "AD sync
                // must degrade, never hard-fail" posture.
                return plaintext;
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
