using System;
using System.IO;
using System.Text;

namespace WindowsInventoryLite
{
    // Optional, off-by-default plain-text log file. Captures three
    // categories useful for diagnosing a live deployment without needing
    // to reproduce the issue locally: AD lookups ("AD"), inventory-report
    // traffic between client and server ("Client"), and unhandled server
    // errors ("Error"). A no-op when disabled, so it costs nothing in the
    // default configuration. Not rotated or size-capped - meant to be
    // switched on for the duration of a troubleshooting session, not left
    // running indefinitely.
    internal static class DebugLogger
    {
        private static readonly object writeLock = new object();

        internal static void Log(ServerOptions options, string category, string message)
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
                // A logging failure must never break the operation being
                // logged - matches how EventLog.WriteEntry is wrapped
                // everywhere else in this project.
            }
        }

        // internal, not private: also exercised directly by the self-test suite.
        internal static string ResolvePath(ServerOptions options)
        {
            return !String.IsNullOrEmpty(options.DebugLogPath)
                ? options.DebugLogPath
                : Path.Combine(options.DataPath, "_logs", "debug.log");
        }
    }
}
