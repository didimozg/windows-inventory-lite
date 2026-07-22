using System;
using System.Collections;
using System.Collections.Generic;
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
                    message += " (" + DebugLogger.SanitizeForLog(errorDetail) + ")";
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

        internal sealed class AdComputerSearchResult
        {
            public ArrayList Computers = new ArrayList();
            public ArrayList Warnings = new ArrayList();
            // True once every attempted search (the whole domain, or each
            // configured OU) has failed - the one case SendAdComputers
            // treats as a total failure (500) instead of a partial,
            // warning-carrying success (200).
            public bool AllAttemptsFailed;
        }

        internal static AdComputerSearchResult SearchComputers(ArrayList organizationalUnits, ServerOptions options)
        {
            AdComputerSearchResult result = new AdComputerSearchResult();
            Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            int attempted = 0;
            int failed = 0;

            if (organizationalUnits.Count == 0)
            {
                attempted++;
                if (!SearchOneRoot(null, options, seen, result.Computers, result.Warnings))
                {
                    failed++;
                }
            }
            else
            {
                foreach (string ou in organizationalUnits)
                {
                    attempted++;
                    if (!SearchOneRoot(ou, options, seen, result.Computers, result.Warnings))
                    {
                        failed++;
                    }
                }
            }

            result.Computers.Sort(StringComparer.OrdinalIgnoreCase);
            result.AllAttemptsFailed = failed == attempted;
            return result;
        }

        // Searches AD for computer objects under one root (an OU's DN, or
        // the whole domain when organizationalUnitDn is null) and adds any
        // found computer names into computers/seen (case-insensitive
        // dedup). Returns false (and appends one warning) if the search
        // itself failed - a bad/deleted OU DN, or AD being entirely
        // unreachable for the whole-domain case. Mirrors
        // LookupComputerDescription's own credential/domain-resolution and
        // debug-log conventions above.
        private static bool SearchOneRoot(string organizationalUnitDn, ServerOptions options, Dictionary<string, bool> seen, ArrayList computers, ArrayList warnings)
        {
            DirectoryEntry entry = null;
            DirectorySearcher searcher = null;
            string domain = null;
            string errorDetail = null;
            string status = "ok";
            int foundCount = 0;
            try
            {
                string ldapPath;
                if (organizationalUnitDn != null)
                {
                    ldapPath = "LDAP://" + organizationalUnitDn;
                    // Domain.GetComputerDomain() is not needed to build this
                    // path - it's only used below for the debug-log message,
                    // which already falls back to "(unresolved)" when domain
                    // is null. Skipping it here matters because this method
                    // runs once per configured OU (SearchComputers loops over
                    // the whole AdComputerImportOUs list): calling the DC
                    // locator on every iteration turns one slow lookup (30+
                    // seconds observed when no DC can be located) into N of
                    // them for an N-entry OU list, with no timeout bounding
                    // that call the way ClientTimeout bounds the search
                    // itself.
                    domain = !String.IsNullOrEmpty(options.AdDomain) ? options.AdDomain : null;
                }
                else
                {
                    domain = !String.IsNullOrEmpty(options.AdDomain)
                        ? options.AdDomain
                        : Domain.GetComputerDomain().Name;
                    ldapPath = "LDAP://" + domain;
                }

                entry = options.AdUseServiceIdentity
                    ? new DirectoryEntry(ldapPath)
                    : new DirectoryEntry(ldapPath, options.AdUsername, options.AdPassword);

                searcher = new DirectorySearcher(entry);
                searcher.Filter = "(objectCategory=computer)";
                searcher.PropertiesToLoad.Add("cn");
                searcher.SearchScope = SearchScope.Subtree;
                searcher.PageSize = 1000;
                searcher.ClientTimeout = TimeSpan.FromSeconds(LdapTimeoutSeconds);

                using (SearchResultCollection foundResults = searcher.FindAll())
                {
                    foreach (SearchResult found in foundResults)
                    {
                        if (found.Properties["cn"].Count == 0)
                        {
                            continue;
                        }
                        string name = Convert.ToString(found.Properties["cn"][0]);
                        if (String.IsNullOrEmpty(name) || seen.ContainsKey(name))
                        {
                            continue;
                        }
                        seen[name] = true;
                        computers.Add(name);
                        foundCount++;
                    }
                }
            }
            catch (Exception ex)
            {
                status = "error";
                errorDetail = ex.Message;
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
                if (entry != null) entry.Dispose();
            }

            string rootDescription = organizationalUnitDn ?? "(whole domain)";
            try
            {
                string identity = options.AdUseServiceIdentity
                    ? "service identity"
                    : "explicit account '" + DebugLogger.SanitizeForLog(options.AdUsername) + "'";
                string message = "AD computer search for '" + DebugLogger.SanitizeForLog(rootDescription) + "' in domain '" + (domain ?? "(unresolved)")
                    + "' using " + identity + ": " + status + " (" + foundCount + " found)";
                if (errorDetail != null)
                {
                    message += " (" + DebugLogger.SanitizeForLog(errorDetail) + ")";
                }
                DebugLogger.Log(options, "AD", message);
            }
            catch { }

            if (status == "error")
            {
                string warning = organizationalUnitDn != null
                    ? "OU '" + organizationalUnitDn + "' could not be searched (" + errorDetail + ") - skipped."
                    : "The whole domain could not be searched (" + errorDetail + ").";
                warnings.Add(warning);
                return false;
            }
            return true;
        }
    }
}
