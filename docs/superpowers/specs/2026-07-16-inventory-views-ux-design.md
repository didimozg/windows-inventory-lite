# Design: Inventory Views UX

Status: approved, ready for implementation planning
Date: 2026-07-16

## Purpose

The dashboard's Clients/Software/Hardware inventory tables currently render every matching record as one unbroken list, and the Inventory summary tiles (client count, activation counts, stale count) sit at the bottom of the Inventory section, below the Hardware breakdown tables. On a large fleet this makes the Clients list long to scroll and pushes the summary stats out of view. This design bundles three related, independently-small dashboard UI changes into one spec, since all three touch the same files (`server/dashboard/index.html`, `app.js`, `styles.css`) and were requested together:

1. Paginate the Clients/Software/Hardware inventory tables, with page size adaptive to the browser window's available height.
2. Move the Inventory summary tiles to the top of the Inventory section and make them visually more compact.
3. Swap the column order of `Collected` and `AD Description` in the Clients table.

## Scope

In scope:
- Independent pagination state per table (Clients, Software, Hardware), each computing its own page size from its own row height.
- Live, resize-responsive page-size calculation (not a fixed page size, not static breakpoint tiers).
- Relocating `#summarySection` (the Inventory tab's tile row) from its current position (after the Hardware table) to just below the search bar, above the Clients/Software/Hardware tab content.
- A new compact tile style for that relocated section only.
- Reordering two adjacent `<th>`/`<td>` pairs in the Clients table.

Out of scope:
- The Dashboard tab's own tile row (`#dashboardTiles`) — unaffected, already positioned at the top of its tab and not part of this request.
- CSV export — already builds its row set independently of what's currently rendered/paginated in the DOM (reads the full filtered client list via the shared `query` filter), so it is unaffected by pagination and needs no change.
- Any change to what data is collected, stored, or reported by the client/server — this is dashboard-rendering-only.
- A full `/frontend-design` visual redesign pass — considered and explicitly declined for the tile-compacting piece; this project's dashboard was already calibrated once this session as a mature internal admin tool, not a page needing a distinctive visual identity, and shrinking an existing tile's font-size/padding doesn't need that skill's full methodology (palette, signature element, hero composition).

## Mechanism: Pagination

**Per-table independent state.** Each of the three tables (Clients, Software, Hardware) gets its own current-page number and computed page size, tracked in module-level JS state, keyed by table id. State resets to page 1 whenever that table's filtered/sorted result set changes (search input changes, sort column/direction changes) — otherwise a user could be stranded on "page 7 of 2" after narrowing a search.

**Page-size calculation — live measurement, not fixed tiers.** On first render of a table (and after any resize), the code:
1. Renders one row to measure its actual `offsetHeight` (row heights differ across the three tables — Clients rows are taller due to the multi-line computer/domain/IP cell).
2. Computes available vertical space as `window.innerHeight` minus the topbar/search-bar height, the table's `<thead>` height, and the pager control's height.
3. Divides available space by row height, floors to a whole number, and clamps to a minimum of 5 rows (so a very small or heavily zoomed window never tries to show 0-1 rows).

This recomputes on a debounced (~150ms) `window resize` listener, and once when a user switches into an Inventory sub-tab (Clients/Software/Hardware), since the previously-inactive tab's table wasn't being measured while hidden.

**Pager controls.** A simple `[Prev] Page N of M [Next]` control below each table's `<tbody>`, matching the existing button styling already used elsewhere in the dashboard (`.link-button`/plain buttons, not a new component). `Prev` disabled on page 1, `Next` disabled on the last page.

**Interaction with existing sort/search.** No change to the existing sort-by-column-header or `searchInput` filtering logic — pagination is a display-layer slice applied *after* the existing filter+sort pipeline produces its result array, immediately before building `<tr>` HTML. Changing the sort key/direction or the search query already re-runs the full render pipeline; the only addition is resetting `currentPage` to 1 as part of that same re-render trigger.

## Mechanism: Summary Tiles

**Relocation.** `#summarySection` currently sits in HTML source order after `#hardwareView`, and is shown/hidden purely via the existing `isInventoryView` class toggle in `app.js` (`byId('summarySection').classList.toggle('hidden', !isInventoryView)`) — it already behaves as a single shared header across all three Inventory sub-tabs, not per-tab content. Moving it in the HTML source to sit immediately after the `<header class="topbar">` (containing `searchInput`) and before `<section id="clientsView">` requires no JS changes — the same toggle logic continues to work unchanged, since visibility is not tied to source position.

**Compact sizing.** A new modifier class, `.summary-compact`, added alongside the existing `.summary` class on `#summarySection` (`class="summary summary-compact"`), rather than any ID-scoped override — this codebase has hit the "more specific selector silently wins" bug twice before, and the established fix is always a plain additive modifier class. `.summary-compact div` reduces padding from 16px to ~7px; `.summary-compact span` reduces font-size from 28px to ~15-16px. The `#dashboardTiles` tile row (Dashboard tab) does not get this class and is visually unaffected.

**Verification.** Live Playwright check at both desktop and 480px mobile widths, and both light/dark themes, confirming: the compact tiles render correctly, don't overlap or clip at narrow widths, and the `#dashboardTiles` row on the Dashboard tab is unchanged.

## Mechanism: Column Swap

In `server/dashboard/index.html`, the two adjacent `<th>` elements for the Clients table:
```html
<th data-sort-table="clients" data-sort-key="collectedAt" class="sortable">Collected</th>
<th>AD Description</th>
```
become:
```html
<th>AD Description</th>
<th data-sort-table="clients" data-sort-key="collectedAt" class="sortable">Collected</th>
```

In `server/dashboard/app.js`, the matching `<td>` pair in the row-rendering template (currently `Collected` then `AD Description`) is reordered to match. The CSV export's own column order (built separately, in a different function, from a hardcoded header array) is untouched — it is a distinct list unrelated to the on-screen table's `<th>` order and was not part of this request.

No CSS in this codebase targets these columns by position (`nth-child`/`nth-of-type`) — confirmed by search — so this is a pure reorder with no other side effects.

## Testing

- Live Playwright verification (per this project's established practice for dashboard changes): pagination behavior on all three tables at desktop and 480px widths, resize recomputing page size correctly, page reset on search/sort change, minimum-page-size clamp on a very short window.
- Compact tile visual check at both widths and both themes; confirm Dashboard tab's own tiles are unaffected.
- Column order check: header and row cells match, CSV export unaffected.
- No new automated self-tests are needed for this change — it is dashboard-rendering logic (client-side JS/HTML/CSS) with no server-side C#/PowerShell code touched, so the existing self-test/Pester suites are unaffected and don't need new cases; verification is via live browser testing instead, consistent with how prior dashboard-only changes in this project were verified.

## Open questions

None outstanding. All design decisions were confirmed with the user during brainstorming (2026-07-16): pagination scope covers all three Inventory tables (not just Clients), page size uses live row-height measurement recomputed on resize (not fixed breakpoint tiers), tile compacting goes further than the first proposal (number ~15-16px, padding ~6-8px) without a dedicated `/frontend-design` pass, and the column swap is a literal position swap of the two named columns.
