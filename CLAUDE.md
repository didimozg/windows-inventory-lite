# Project rules — windows-inventory-lite

These rules are specific to this project and apply in addition to the
workspace-wide rules.

## Self-update wire compatibility is additive-only

Any JSON field a self-updating client (`src/client/WindowsInventoryLiteClient.cs`,
`linux-client/*.go`) reads from a server response is a compatibility
contract, not an internal implementation detail. Self-update is the *only*
channel an already-deployed client has to receive a fix — so breaking that
contract does not just affect the next release, it permanently strands
every client already in the field, since the mechanism meant to get them
off the broken version is the very thing that just broke.

**This happened for real on 2026-09-11.** Splitting the inventory ack's
shared `config.update.version` field into `versionNet35`/`versionNet40`
(server 0.61.1) was correct in isolation and fully self-tested against the
matching new client build — but every client already deployed in the field
was still on the old build, whose `ApplySelfUpdateFromServer` only checked
`update.ContainsKey("version")` to decide an update exists at all. Dropping
that key meant no already-deployed client could see an update again,
through any channel. Self-tests didn't catch it because they validated the
new client's expectations against the new server response — never the old,
already-deployed client's expectations against it. Only a live test against
a real fleet client caught it. Fixed in server 0.61.2 by emitting both the
old key and the new ones. Full writeup: `docs/backlog.md`, "0.61.1's
per-target version-field split silently broke self-update for the entire
already-deployed Windows fleet."

**Rule:** renaming or removing a key in `config` or `config.update` (or any
other field a self-updating client reads from `/api/v1/inventory` or
`/api/v1/linux/inventory`'s response) is additive-only by default. Before
changing the shape of either response:

1. Check what the OLDEST client version that could plausibly still be
   deployed actually reads — via `git log`/`git show <old-commit>:<path>`
   on the client source, not just the current client's own code. Assume
   the oldest ever-shipped version is still out there in the field until
   proven otherwise; this project has no fleet-wide version-floor tracking
   to rule that out.
2. If an old key is being replaced by something more precise (e.g. a
   shared value split per-target, or per-platform), keep emitting the old
   key too, alongside the new one. Treat it as permanent — there is
   currently no mechanism to know the whole fleet has moved past the
   version that needed it, so there is no safe point to stop.
3. Add a self-test that builds the response the way the OLD client parses
   it and asserts the specific key(s) it reads are still present — not
   only a test that the NEW client's own expectations are satisfied. A
   test that only checks the new shape will not catch this class of bug,
   as already demonstrated once.
4. Before calling a self-update-adjacent wire change done, live-test it
   against a real already-deployed client if one is reachable (or a
   scratch server plus a copy of an old client build) — self-tests alone
   already missed this once.
