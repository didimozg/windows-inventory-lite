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
            try
            {
                string domain = !String.IsNullOrEmpty(options.AdDomain)
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
                    return result;
                }

                if (found.Properties["description"].Count > 0)
                {
                    result.Description = Convert.ToString(found.Properties["description"][0]);
                }
                result.Status = "ok";
                return result;
            }
            catch (Exception ex)
            {
                try
                {
                    System.Diagnostics.EventLog.WriteEntry(
                        "WindowsInventoryLite",
                        "AD lookup failed for '" + computerName + "': " + ex.Message,
                        System.Diagnostics.EventLogEntryType.Warning);
                }
                catch { }
                result.Status = "error";
                return result;
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
                if (entry != null) entry.Dispose();
            }
        }
    }
}
