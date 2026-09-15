using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WindowsInventoryLite
{
    // Optional, off-by-default plain-text log file. Captures categories
    // useful for diagnosing a live deployment without needing to reproduce
    // the issue locally: AD lookups ("AD"), inventory-report traffic
    // between client and server ("Client"), a scheduled client-update
    // push actually starting ("Schedule" - a tick that finds nothing due
    // stays silent, only a real push against real targets logs), and
    // unhandled server errors ("Error"). A no-op when disabled, so it
    // costs nothing in the default configuration. Bounded by
    // DebugLogRetentionDays/DebugLogMaxSizeMb (see PruneDebugLogLines) -
    // oldest lines are dropped first, checked opportunistically on write.
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
                    PruneIfNeeded(path, options);
                }
            }
            catch
            {
                // A logging failure must never break the operation being
                // logged - matches how EventLog.WriteEntry is wrapped
                // everywhere else in this project.
            }
        }

        // Checked on every write but only pays for a read+rewrite when
        // genuinely over budget - mirrors RecordIngestionRejection's own
        // "count > maxEntries + slack OR oldest entry aged out" dual
        // trigger (WindowsInventoryLiteServer.cs, PruneIngestionRejectionEntries
        // call site), adapted from an in-memory list to a flat file: a
        // byte-size slack instead of an entry-count slack, and a cheap
        // single-line read (TryGetOldestLineTimestampUtc) instead of an
        // O(1) list-index check, since the file isn't already in memory.
        // Already inside the caller's lock (writeLock) - must not be
        // called from anywhere else without that same lock held.
        private static void PruneIfNeeded(string path, ServerOptions options)
        {
            long maxSizeBytes = (long)(options.DebugLogMaxSizeMb * 1024 * 1024);
            long slackBytes = Math.Max(maxSizeBytes / 10, 64L * 1024L);

            FileInfo info = new FileInfo(path);
            DateTime oldestTimestampUtc;
            bool oldestLineAgedOut = TryGetOldestLineTimestampUtc(path, out oldestTimestampUtc)
                && (DateTime.UtcNow - oldestTimestampUtc).TotalDays > options.DebugLogRetentionDays;

            if (info.Length <= maxSizeBytes + slackBytes && !oldestLineAgedOut)
            {
                return;
            }

            List<string> lines = new List<string>(File.ReadAllLines(path, Encoding.UTF8));
            List<string> pruned = PruneDebugLogLines(lines, DateTime.UtcNow, options.DebugLogRetentionDays, maxSizeBytes);
            if (pruned.Count != lines.Count)
            {
                File.WriteAllLines(path, pruned, new UTF8Encoding(false));
            }
        }

        // Pure - no I/O. Lines are in chronological (oldest-first) order,
        // matching how DebugLogger.Log appends them. Drops lines older
        // than retentionDays first, then (if still over maxSizeBytes)
        // drops the oldest remaining lines until back under budget.
        // maxSizeBytes <= 0 skips the size trim entirely (same reasoning
        // as PruneIngestionRejectionEntries' maxEntries <= 0 guard - a
        // bare `new ServerOptions()` used directly in a test, rather than
        // one that went through Parse(), would otherwise default
        // DebugLogMaxSizeMb to 0 and silently discard every line).
        internal static List<string> PruneDebugLogLines(List<string> lines, DateTime nowUtc, int retentionDays, long maxSizeBytes)
        {
            List<string> withinAge = new List<string>();
            foreach (string line in lines)
            {
                DateTime lineTimestampUtc;
                if (TryParseDebugLogLineTimestamp(line, out lineTimestampUtc) && (nowUtc - lineTimestampUtc).TotalDays > retentionDays)
                {
                    continue;
                }
                withinAge.Add(line);
            }

            if (maxSizeBytes <= 0)
            {
                return withinAge;
            }

            long totalBytes = 0;
            foreach (string line in withinAge)
            {
                totalBytes += Encoding.UTF8.GetByteCount(line) + Environment.NewLine.Length;
            }
            if (totalBytes <= maxSizeBytes)
            {
                return withinAge;
            }

            int dropCount = 0;
            while (dropCount < withinAge.Count && totalBytes > maxSizeBytes)
            {
                totalBytes -= Encoding.UTF8.GetByteCount(withinAge[dropCount]) + Environment.NewLine.Length;
                dropCount++;
            }
            return withinAge.GetRange(dropCount, withinAge.Count - dropCount);
        }

        // Every line DebugLogger.Log writes starts with
        // "yyyy-MM-ddTHH:mm:ss.fffZ " (24 characters, then a space) - see
        // Log's own line-building above. A line that doesn't match this
        // shape (never written by this class, but defensively handled)
        // is treated as un-datable and only ever removed by the size
        // trim, never the age trim.
        internal static bool TryParseDebugLogLineTimestamp(string line, out DateTime timestampUtc)
        {
            timestampUtc = default(DateTime);
            if (line == null || line.Length < 24)
            {
                return false;
            }
            return DateTime.TryParseExact(
                line.Substring(0, 24),
                "yyyy-MM-ddTHH:mm:ss.fffZ",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal,
                out timestampUtc);
        }

        // Reads only the file's first line - cheap, O(1) relative to file
        // size, avoiding a full read on every single write just to check
        // the oldest line's age (mirrors PruneIngestionRejectionEntries'
        // own reasoning for checking only index 0 of its in-memory list).
        private static bool TryGetOldestLineTimestampUtc(string path, out DateTime timestampUtc)
        {
            timestampUtc = default(DateTime);
            try
            {
                using (StreamReader reader = new StreamReader(path, Encoding.UTF8))
                {
                    string firstLine = reader.ReadLine();
                    return firstLine != null && TryParseDebugLogLineTimestamp(firstLine, out timestampUtc);
                }
            }
            catch
            {
                return false;
            }
        }

        // internal, not private: also exercised directly by the self-test suite.
        internal static string ResolvePath(ServerOptions options)
        {
            return !String.IsNullOrEmpty(options.DebugLogPath)
                ? options.DebugLogPath
                : Path.Combine(options.DataPath, "_logs", "debug.log");
        }

        // Escapes CR/LF in client-supplied values (e.g. a reported computer
        // name) before they are embedded in a log line or Event Log
        // message. Without this, a client that already has a valid
        // ingestion token could forge additional log lines by putting a
        // newline in its reported computer name. internal, not private:
        // also exercised directly by the self-test suite.
        internal static string SanitizeForLog(string value)
        {
            if (value == null)
            {
                return String.Empty;
            }
            return value.Replace("\r", "\\r").Replace("\n", "\\n");
        }
    }
}
