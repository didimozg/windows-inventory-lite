# Client Update Schedule Design

**Goal:** Let an administrator schedule `Client updates` pushes instead of always triggering them by hand - either a one-time push at a specific date/time, or a recurring push every N hours - targeting whichever clients are currently outdated at the moment the schedule fires.

**Architecture:** One server-side schedule configuration, persisted in `server-config.json` alongside the other settings (mirrors the existing AD sync `AdSyncMode`/`AdSyncIntervalHours` pattern). An in-process timer inside the Windows Service checks the schedule periodically; when it's due, the server computes the current outdated-client list (the same logic `GET /api/v1/client-updates` already uses) and starts a push job against all of them through the existing `POST /api/v1/client-install` pipeline - functionally equivalent to an admin selecting every outdated row and clicking "Update selected". No new push mechanism, no Windows Task Scheduler, no new job type.

**Tech Stack:** C# (.NET Framework 3.5/4.0, hand-rolled server), vanilla JS dashboard - unchanged from the rest of the project.

## Global Constraints

- Single schedule per server, one of three modes: `off`, `once` (a specific date/time), `interval` (every N hours). Only one can be active at a time - selecting a mode replaces whichever was active before, exactly like the AD sync `Sync mode` dropdown.
- Schedule config persists across service restarts, stored in `server-config.json` (same file, same encryption conventions as the rest of the project's settings - the schedule itself carries no secrets, so no encryption is needed for these specific fields).
- A scheduled run always targets the full outdated-client list computed fresh at trigger time (`LoadClientReports()` + `IsClientVersionCurrent()`, the same function `SendClientUpdates` already uses) - never a frozen snapshot of what was outdated when the schedule was configured.
- A scheduled run always uses `force: false` and `addToTrustedHosts: false`, matching the existing hardcoded values in `startClientUpdateJob` for manual pushes from this tab.
- A scheduled run has no user present to type credentials, so it always resolves through the existing `useSavedCredentials: true` / `ResolveUpdateCredentials` path (saved account, falling through to the server's own service identity if nothing is saved) - identical resolution to a manual push with both fields left blank.
- Enabling a schedule without a saved WinRM account is allowed, not blocked - the UI shows a warning, since the service identity may already have sufficient rights (as established this session, this varies per machine and isn't something the dashboard can predict).
- The `interval` mode's "last run" timestamp is tracked separately from manual pushes - only a schedule-triggered run advances it, so a manual push shortly before a scheduled tick does not delay or skip that scheduled run.
- A missed `once` schedule (server was stopped through the scheduled moment) is silently cleared back to `off` on the next startup - it does not fire late and does not notify anyone.
- After a `once` schedule fires, the mode resets to `off` automatically (a `once` schedule is single-shot, same as it never having a "reschedule" concept).
- The resulting install job from a scheduled run is a completely normal entry in the existing install-job history/log - no separate schedule-run history view.
- Manual "Update selected" on the Client updates page is completely unaffected by whether a schedule is configured or active.

## Data Model

New fields on `ServerOptions` / `server-config.json`, alongside the existing `ClientUpdateUsername`/`ClientUpdatePassword`:

| Field | Type | Meaning |
| --- | --- | --- |
| `ClientUpdateScheduleMode` | string | `off` \| `once` \| `interval` |
| `ClientUpdateScheduleOnceAtUtc` | string (ISO 8601 UTC) or null | Target date/time for `once` mode |
| `ClientUpdateScheduleIntervalHours` | int | Hours between runs for `interval` mode (same `1-8760` range as AD sync's interval field) |
| `ClientUpdateScheduleLastRunUtc` | string (ISO 8601 UTC) or null | Last time a *scheduled* run actually fired (not manual pushes) |

## Server-Side Behavior

- The existing service timer loop (or a new tick alongside the AD sync one, whichever the implementation plan finds cleaner given the current timer wiring) checks the schedule once per tick:
  - `off`: no-op.
  - `once`: if `UtcNow >= ClientUpdateScheduleOnceAtUtc`, fire the push, then set `ClientUpdateScheduleMode = "off"` and clear `ClientUpdateScheduleOnceAtUtc`.
  - `interval`: if `ClientUpdateScheduleLastRunUtc` is null or `UtcNow >= ClientUpdateScheduleLastRunUtc + ClientUpdateScheduleIntervalHours`, fire the push and set `ClientUpdateScheduleLastRunUtc = UtcNow`.
- On service startup, before the first tick: if mode is `once` and the target time has already passed, silently reset to `off` (the missed-schedule case) without firing.
- "Fire the push" = compute the outdated list, and if it's non-empty, build the same job payload `startClientUpdateJob` would (targets = all outdated computer names, `force: false`, `addToTrustedHosts: false`, `useSavedCredentials: true`, blank typed username/password) and start it through the existing `RunClientActionJob` pipeline. If the outdated list is empty at trigger time, still update the mode/last-run bookkeeping (so `once` still resets to `off`, `interval` still advances) but skip starting an empty job.

## API

- `GET /api/v1/client-updates/schedule` - returns the current schedule config (mode, once-at, interval hours, last-run), mirroring the shape of `GET /api/v1/client-updates/credentials`.
- `POST /api/v1/client-updates/schedule` - sets the schedule (mode + the relevant field for that mode). Switching to `off` clears the mode-specific fields.

## UI

New "Schedule" settings block on the `Client updates` page (Installation section), directly below the existing "WinRM credentials" block, using the same narrow fixed-width panel pattern (420px) just built for the Active Directory settings:

- "Schedule" dropdown: `Off` / `Run once` / `Every N hours`.
- Conditional field, shown only for the relevant mode (same show/hide pattern as the AD `Sync interval` field):
  - `Run once`: a datetime input for the target date/time.
  - `Every N hours`: a number input (hours), reusing the same `1-8760` validation range as the AD sync interval field.
- A "Save" button, following the same pattern as the WinRM credentials block.
- A warning line (not a blocking error) shown when no WinRM account is saved: something like "No saved WinRM account - scheduled pushes will use the server's own service identity."
- No separate "next run" countdown or run-history UI in this iteration - out of scope, see below.

## Out of Scope (this iteration)

- Multiple concurrent schedules.
- A "next scheduled run" live countdown display.
- Email or other external notification on schedule success/failure (the existing install-job history already records outcome; no new visibility mechanism is being added).
- Any change to the fully-automatic-sweep behavior that was explicitly rejected during the original Client Auto-Update brainstorming - this feature is still admin-configured and admin-controlled, not a background always-on sweep enabled by default.
