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
            string domain = null;
            string errorDetail = null;
            try
            {
                domain = !String.IsNullOrEmpty(options.AdDomain)
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
                }
                else
                {
                    if (found.Properties["description"].Count > 0)
                    {
                        result.Description = Convert.ToString(found.Properties["description"][0]);
                    }
                    result.Status = "ok";
                }
            }
            catch (Exception ex)
            {
                result.Status = "error";
                errorDetail = ex.Message;
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
                if (entry != null) entry.Dispose();
            }

            // Every real lookup (as opposed to a cache carry-forward - see
            // InventoryServer.ComputeAdSyncFields) gets one line in the debug log
            // (see DebugLogger.cs), success or failure, so an admin can
            // confirm sync is actually running without inspecting the
            // per-computer JSON report by hand. The Windows Event Log stays
            // reserved for failures only, same as before this file's
            // debug-log support was added - a lookup on every inventory
            // report/sweep tick is routine, expected traffic, not something
            // that belongs in the always-on system event log for every
            // fleet-sized deployment.
            try
            {
                string identity = options.AdUseServiceIdentity
                    ? "service identity"
                    : "explicit account '" + DebugLogger.SanitizeForLog(options.AdUsername) + "'";
                string message = "AD lookup for '" + DebugLogger.SanitizeForLog(computerName) + "' in domain '" + (domain ?? "(unresolved)")
                    + "' using " + identity + ": " + result.Status;
                if (errorDetail != null)
                {
                    message += " (" + errorDetail + ")";
                }
                if (result.Status == "error")
                {
                    // Isolated in its own try/catch so a failure to write to
                    // the Event Log (e.g. the "WindowsInventoryLite" source
                    // not registered) cannot suppress the debug-log write
                    // below - the two sinks must be independent.
                    try
                    {
                        System.Diagnostics.EventLog.WriteEntry(
                            "WindowsInventoryLite",
                            message,
                            System.Diagnostics.EventLogEntryType.Warning);
                    }
                    catch { }
                }
                DebugLogger.Log(options, "AD", message);
            }
            catch { }

            return result;
        }
    }
}
