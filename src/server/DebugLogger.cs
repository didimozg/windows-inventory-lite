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

            // SanitizeForLog on the whole message (not just caller-embedded
            // sub-values like a client-reported computer name) guarantees
            // every entry is exactly one physical line, no matter what a
            // caller passes in - e.g. an exception's ToString(), which
            // contains embedded \r\n per stack frame. Without this, only the
            // first line of such a message gets the timestamp prefix the
            // rest of this class's prune/parse logic depends on: the age
            // filter can never remove the resulting untimestamped
            // continuation lines, and if one ever ends up physically first
            // in the file, TryGetOldestLineTimestampUtc (which only reads
            // line 1) returns false permanently, silently disabling the
            // age-based prune trigger for the rest of that file's life.
            string line = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") + " [" + category + "] " + SanitizeForLog(message);

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

        // Reads the file's current content under writeLock, so a concurrent
        // DebugLogger.Log call (a plain append or a PruneIfNeeded rewrite) can
        // never race with a read - without this, File.AppendAllText/
        // File.WriteAllLines's share mode does not permit a concurrent read,
        // producing a sharing-violation IOException on one side or the other.
        internal static string ReadCurrent(ServerOptions options, out long sizeBytes)
        {
            lock (writeLock)
            {
                string path = ResolvePath(options);
                if (!File.Exists(path))
                {
                    sizeBytes = 0;
                    return "";
                }
                string content = File.ReadAllText(path, Encoding.UTF8);
                sizeBytes = new FileInfo(path).Length;
                return content;
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
            bool overSizeCap = info.Length > maxSizeBytes + slackBytes;

            // TryGetOldestLineTimestampUtc opens the file a second time just to
            // read its first line - skippable here when the size check alone
            // already means a prune is needed. It can NOT be skipped in the
            // opposite case: most writes land here comfortably under the size
            // cap, and the age-only trigger (a line ages out while the file is
            // still small) has to keep working in exactly that common case, so
            // the second file open is unavoidable there. This only saves the
            // extra open in the already-over-budget case - a documented
            // trade-off, not a missed optimization; pruning behavior is
            // unchanged either way.
            bool oldestLineAgedOut = false;
            if (!overSizeCap)
            {
                DateTime oldestTimestampUtc;
                oldestLineAgedOut = TryGetOldestLineTimestampUtc(path, out oldestTimestampUtc)
                    && (DateTime.UtcNow - oldestTimestampUtc).TotalDays > options.DebugLogRetentionDays;
            }

            if (!overSizeCap && !oldestLineAgedOut)
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
            List<string> withinAge;
            if (retentionDays <= 0)
            {
                // Same reasoning as maxSizeBytes's own <= 0 guard below: a bare
                // `new ServerOptions()` used directly in a test, rather than one
                // that went through Parse(), would otherwise default
                // DebugLogRetentionDays to 0 and (nowUtc - lineTimestampUtc).TotalDays > 0
                // would evaluate true for almost every parseable line, silently
                // wiping the log via the age filter alone. Skip the age filter
                // entirely instead; the size trim below still applies normally.
                withinAge = lines;
            }
            else
            {
                withinAge = new List<string>();
                foreach (string line in lines)
                {
                    DateTime lineTimestampUtc;
                    if (TryParseDebugLogLineTimestamp(line, out lineTimestampUtc) && (nowUtc - lineTimestampUtc).TotalDays > retentionDays)
                    {
                        continue;
                    }
                    withinAge.Add(line);
                }
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
