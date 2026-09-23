using System;
using System.Collections.Generic;
using System.Reflection;
using System.ServiceProcess;

namespace WindowsInventoryLite
{
    // Kept as its own file, separate from WindowsInventoryLiteClient.cs -
    // the same reasoning the server already applies to AdLookupService.cs/
    // SecretProtector.cs/DebugLogger.cs: a genuinely separate, isolable
    // concern (here, WUA COM interop) gets its own file. Uses late-bound
    // reflection throughout (Type.GetTypeFromProgID + InvokeMember) since
    // this client's .NET 3.5/4.0 floor has no compile-time typelib
    // reference available for Microsoft.Update.Session.
    internal static class WsusScanner
    {
        // True if wuauserv is not running/disabled - the caller should
        // skip the scan and report wuServiceUnavailable rather than
        // attempting one. Not unit-testable (queries a real Windows
        // service) - verify live before relying on this.
        internal static bool IsWuauservRunning()
        {
            try
            {
                using (ServiceController controller = new ServiceController("wuauserv"))
                {
                    return controller.Status == ServiceControllerStatus.Running;
                }
            }
            catch
            {
                // Service not found, access denied, or any other failure
                // to query it - treat the same as "not running" so the
                // caller skips the scan rather than crashing the poll
                // cycle over a diagnostic query failing.
                return false;
            }
        }

        // Pure comparison, no I/O - the only piece of this file that gets
        // a real self-test. A blank serverCabHash means no cab is
        // configured on the server at all, in which case there is
        // nothing to scan against regardless of what the client last
        // scanned.
        internal static bool ShouldRescan(string serverCabHash, string lastScannedHash)
        {
            if (String.IsNullOrEmpty(serverCabHash))
            {
                return false;
            }
            return !String.Equals(serverCabHash, lastScannedHash, StringComparison.OrdinalIgnoreCase);
        }

        // Real WUA COM interop, late-bound. Not unit-testable (requires a
        // real Windows Update Agent and a real cab file) - MUST be
        // verified live before this feature is considered done. Method
        // shapes verified against Microsoft's own documentation at
        // https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline
        // and https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdate
        // - not guessed.
        internal static List<Dictionary<string, object>> ScanForMissingUpdates(string cabPath)
        {
            List<Dictionary<string, object>> results = new List<Dictionary<string, object>>();

            Type sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
            object session = Activator.CreateInstance(sessionType);
            object searcher = session.GetType().InvokeMember("CreateUpdateSearcher", BindingFlags.InvokeMethod, null, session, null);

            Type managerType = Type.GetTypeFromProgID("Microsoft.Update.ServiceManager");
            object manager = Activator.CreateInstance(managerType);
            object updateService = manager.GetType().InvokeMember("AddScanPackageService", BindingFlags.InvokeMethod, null, manager, new object[] { "Offline Sync Service", cabPath });
            object serviceId = updateService.GetType().InvokeMember("ServiceID", BindingFlags.GetProperty, null, updateService, null);

            searcher.GetType().InvokeMember("ServerSelection", BindingFlags.SetProperty, null, searcher, new object[] { 3 }); // ssOthers
            searcher.GetType().InvokeMember("ServiceID", BindingFlags.SetProperty, null, searcher, new object[] { serviceId });

            object searchResult = searcher.GetType().InvokeMember("Search", BindingFlags.InvokeMethod, null, searcher, new object[] { "IsInstalled=0" });
            object updates = searchResult.GetType().InvokeMember("Updates", BindingFlags.GetProperty, null, searchResult, null);
            int count = (int)updates.GetType().InvokeMember("Count", BindingFlags.GetProperty, null, updates, null);

            for (int i = 0; i < count; i++)
            {
                // IUpdateCollection.Item is a read/write PROPERTY (get_Item/
                // put_Item per Microsoft's own reference), not a method -
                // InvokeMethod here throws DISP_E_MEMBERNOTFOUND against a
                // real WUA COM object, confirmed live against a real Windows
                // 10 host (the exception fired here, right after Count was
                // read successfully, proving everything before this point
                // is correct).
                object update = updates.GetType().InvokeMember("Item", BindingFlags.GetProperty, null, updates, new object[] { i });
                string title = Convert.ToString(update.GetType().InvokeMember("Title", BindingFlags.GetProperty, null, update, null));
                string msrcSeverity = Convert.ToString(update.GetType().InvokeMember("MsrcSeverity", BindingFlags.GetProperty, null, update, null) ?? "");

                object kbArticleIds = update.GetType().InvokeMember("KBArticleIDs", BindingFlags.GetProperty, null, update, null);
                int kbCount = (int)kbArticleIds.GetType().InvokeMember("Count", BindingFlags.GetProperty, null, kbArticleIds, null);
                string kbId = "";
                if (kbCount > 0)
                {
                    // Take the first KB article ID - a single update can
                    // theoretically list more than one, but every KB this
                    // project's catalog targets by ID is expected to have
                    // exactly one; verify this assumption holds during
                    // live verification rather than silently.
                    // Same fix as IUpdateCollection.Item above - IStringCollection.Item
                    // is also a get_Item/put_Item property, not a method.
                    object firstKb = kbArticleIds.GetType().InvokeMember("Item", BindingFlags.GetProperty, null, kbArticleIds, new object[] { 0 });
                    kbId = "KB" + Convert.ToString(firstKb);
                }

                if (String.IsNullOrEmpty(kbId))
                {
                    continue;
                }

                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["kbId"] = kbId;
                entry["title"] = title;
                entry["msrcSeverity"] = msrcSeverity;
                results.Add(entry);
            }

            return results;
        }
    }
}
