# Design: Dashboard Live Auto-Refresh

Status: approved, ready for implementation planning
Date: 2026-07-17

## Purpose

The dashboard currently fetches `/api/v1/clients` exactly once, on page load. If a client reports new inventory data (or an admin edits settings that affect the client list) while the dashboard is open, the page shows stale data until the user manually reloads. This design adds a background poll that keeps the dashboard current without disrupting whatever the user is currently doing — their current page/sort/search per table, and any expanded row detail views.

## Scope

In scope:
- A 30-second polling loop against the existing `/api/v1/clients` endpoint (no new server endpoint, no server-side changes at all — this is a pure dashboard/JS change).
- Skipping re-render work entirely when nothing has changed (compared via the endpoint's existing `generatedAt` field).
- Pausing the poll while the browser tab isn't visible, with one immediate catch-up poll on becoming visible again.
- Making expanded detail rows (Clients/Software/Hardware "show details" toggles) survive a re-render — this fixes an existing rough edge (expanded rows already collapse on every pager Next/Prev click today, not just on a future poll-triggered refresh) as a side effect of the same state-driven-rendering change.
- A small visual cue (brief highlight on the "Generated: ..." timestamp) when a poll brings in new data.

Out of scope:
- Any server-side push mechanism (SSE/WebSocket) — considered and rejected, see Mechanism below.
- A new lightweight "has anything changed" endpoint — `generatedAt` on the existing endpoint already serves this purpose without adding a new server route.
- Preserving browser scroll position explicitly — left to the browser's own default behavior (re-rendering `<tbody>` content in place does not typically cause a visible scroll jump), not specially engineered.
- Anything related to the Licenses view (`state.licenses`) or Install-job polling (`pollInstallJob`) — both are separate data domains, unaffected by this change and not touched by it.
- The `#dashboardTiles` summary stats and charts are refreshed as a natural side effect of reusing the existing `render()` pipeline, not through any new dedicated logic.

## Mechanism: polling, not push

Two approaches were considered:

- **Client-side polling** (chosen): a `setInterval` on the browser side re-fetches `/api/v1/clients` every 30 seconds. No new server code — the endpoint already exists and already returns `generatedAt`. Matches this project's overall shape: a hand-rolled server with no external dependencies, where adding new push infrastructure (SSE or WebSocket support in the raw `TcpListener`/`SslStream` server) would be substantial new server-side complexity for a fleet where inventory reports naturally arrive hours apart, not seconds apart — 30-second polling is already far faster than the underlying data changes, so push's lower latency has no real payoff here.
- **Server push (SSE/WebSocket)**: rejected. Would require the server to hold open connections and broadcast on report-ingestion, a meaningfully larger change to a server that currently handles each HTTP request statelessly, for a workload where near-real-time delivery isn't actually needed (clients report every few hours by default).

## Mechanism: poll loop

```javascript
let lastGeneratedAt = null;
let pollTimer = null;

function pollForUpdates() {
  fetch('/api/v1/clients', { cache: 'no-store' })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then(data => {
      if (data.generatedAt === lastGeneratedAt) return; // nothing changed, skip re-render entirely
      lastGeneratedAt = data.generatedAt;
      state.clients = data.clients || [];
      state.staleHours = data.staleHours || 48;
      byId('generatedAt').textContent = `Generated: ${formatDateTime(data.generatedAt)}`;
      byId('serverVersionBadge').textContent = `Server: v${text(data.serverVersion)}`;
      render();
      flashGeneratedAt();
    })
    .catch(() => {
      // Silent - a background poll failing (network hiccup, brief server
      // restart) isn't worth interrupting the user with. The next tick
      // retries. Only the initial page-load fetch shows an error banner.
    });
}

function startPolling() {
  if (pollTimer) return;
  pollTimer = window.setInterval(pollForUpdates, 30000);
}

function stopPolling() {
  if (!pollTimer) return;
  window.clearInterval(pollTimer);
  pollTimer = null;
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') {
    stopPolling();
  } else {
    startPolling();
    pollForUpdates(); // catch up immediately, don't wait up to 30s
  }
});
```

`lastGeneratedAt` is set once after the existing initial-load fetch succeeds (same value the page already stores today, just also kept for comparison), so the first poll tick correctly treats "nothing changed since page load" as a no-op. `startPolling()` is called once at the bottom of the script (alongside the other one-time `addEventListener` calls), after the initial fetch's `.then()` resolves — not before, so the first poll never races the initial render.

## Mechanism: `state.expandedDetails` (fixes an existing gap, not just future polling)

A single `Set` on `state`, storing prefixed keys so the three different detail-row namespaces (`data-client-details`, `data-software-details`, `data-hw-details`) can't collide: `'client:' + id`, `'software:' + id`, `'hw:' + id`.

The existing delegated click listener (already merged into one `document.addEventListener('click', ...)` handler, per the event-delegation fix from the Inventory Views UX plan) changes from:

```javascript
if (row) row.classList.toggle('hidden');
```

to also updating the Set alongside the existing toggle:

```javascript
if (row) {
  const nowHidden = row.classList.toggle('hidden');
  if (nowHidden) { state.expandedDetails.delete(key); } else { state.expandedDetails.add(key); }
}
```

Each of the three render functions (`renderTable`, `renderSoftwareTable`, `renderHardwarePage`), when building a row's details-row HTML, checks the Set instead of unconditionally starting with `hidden`:

```javascript
const detailsHidden = state.expandedDetails.has('client:' + clientId) ? '' : 'hidden';
// ...
<tr class="details-row ${detailsHidden}" data-client-details="${clientId}">
```

This makes expand/collapse state state-driven rather than DOM-driven, so it survives ANY re-render — a poll-triggered refresh, a pager Next/Prev click, or a live-resize page-size correction (the latter two already silently collapse expanded rows today; this design incidentally fixes that too, since it's the same underlying mechanism).

A deleted client (removed from the fleet, or simply absent from a fresh poll response because its report aged out) leaves a stale entry in `state.expandedDetails` — harmless, since the corresponding row no longer exists to look the key up for; no cleanup needed.

## Mechanism: visual cue

```javascript
function flashGeneratedAt() {
  const el = byId('generatedAt');
  el.classList.add('generated-at-flash');
  window.setTimeout(() => el.classList.remove('generated-at-flash'), 1000);
}
```

`.generated-at-flash` is a small CSS transition (brief background/color highlight, ~1s, using the theme's existing accent color token) added to `styles.css` — no toast/notification library, no layout shift, nothing that steals focus or interrupts an in-progress action.

## Mechanism: what's already safe, and why

- **Search input, current page, current sort per table**: already live in `state`/the DOM input's own value, untouched by anything `render()` does — the existing behavior already doesn't reset these on a normal re-render (confirmed during Inventory Views UX's own design work).
- **License editing form, delete-confirmation dialog**: separate data domain (`state.licenses`, not touched by this poll) and a blocking native `window.confirm()` (JS is single-threaded, so a `setInterval` tick can't fire mid-dialog) respectively — verified by reading the actual current code, not assumed.
- **Scroll position**: not specially handled. Re-rendering `<tbody>` content in place does not typically cause the browser to jump scroll position, and this project's existing tolerance for "good enough, not exhaustively engineered" UX polish (per this session's own prior design calibrations) makes explicit scroll-position preservation unwarranted extra complexity for a real but minor edge case.

## Testing

No functional JS test harness exists in this project for dashboard behavior (consistent with how Inventory Views UX was verified) — verification is live, via Playwright MCP tools against a running server instance:

- Start the server with a fixture data directory, load the dashboard, expand a client's details row, then directly write an updated client JSON file into the data directory (simulating a new inventory report) and wait past one poll interval — confirm the dashboard's data updates (e.g., an `activation`/`collectedAt` field visibly changes) while the expanded row STAYS expanded and the current page/sort/search are unchanged.
- Confirm the visual flash appears briefly after a poll-triggered update and not after a no-change poll tick.
- Confirm polling stops (no further `/api/v1/clients` requests, checked via Playwright's network-request inspection tools) when the tab is hidden (simulated via the Page Visibility API or a background/foreground tab switch), and one immediate catch-up request fires on becoming visible again.
- Confirm a poll failure (e.g., temporarily stopping the server) does not show any error banner or disrupt the currently-displayed data, and polling resumes cleanly once the server is back.

## Open questions

None outstanding. All design decisions were confirmed with the user during brainstorming (2026-07-17): client-side polling over server push (matches the project's dependency-free server philosophy, and the underlying data doesn't change fast enough to need push), 30-second interval (clients report every few hours by default, so this is already far faster than needed), and preserving expanded-detail-row state via an explicit `state.expandedDetails` Set rather than leaving it DOM-only (which incidentally fixes the same collapse-on-re-render behavior that already affects pagination today, not just this new polling feature).
