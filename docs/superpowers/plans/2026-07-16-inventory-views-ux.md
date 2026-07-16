# Inventory Views UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Paginate the Clients/Software/Hardware inventory tables (page size adaptive to window height for Clients/Software), relocate and shrink the Inventory summary tiles, and swap the `Collected`/`AD Description` column order in the Clients table.

**Architecture:** Pure client-side change to the dashboard's vanilla JS/HTML/CSS (`server/dashboard/app.js`, `index.html`, `styles.css`) — no server (C#) or installer (PowerShell) code is touched. A shared `paginate()`/`renderPager()` helper pair (added once, reused by all five tables) slices each table's already-filtered/sorted array to one page before building row HTML. Clients and Software each compute their own page size live from actual row height and available viewport space; the three Hardware sub-tables (CPU/Storage/RAM) use a fixed page size instead (see Global Constraints for why).

**Tech Stack:** Vanilla JS (no framework, no build step), served as static files by the existing C# server. No new dependencies.

## Global Constraints

- No server-side (C#) or PowerShell code changes in this plan — dashboard-rendering-only. `SecretProtector`, `AdLookupService`, and all server request-handling code are untouched.
- No automated JS test harness exists in this repo. Verification is: (a) the existing Pester `ScriptSyntax.Tests.ps1` "keeps source, dashboard, and examples in English" check, which covers `server/` recursively and fails on any Cyrillic character — every new comment/string must be English-only; (b) live browser verification via Playwright MCP tools against a running local server instance, consistent with how prior dashboard-only changes in this project were verified.
- CSS specificity discipline: this codebase has hit the "a more specific selector silently wins, breaking a lower-specificity rule elsewhere" bug twice already. Every new style in this plan is an additive modifier class (`.pager`, `.summary-compact`, etc.), never an ID-scoped override.
- `#dashboardTiles` (the Dashboard tab's own tile row) is explicitly out of scope and must not change in any way.
- CSV export (`exportClients`/`exportSoftware`/`exportHardwareCpu`/`exportHardwareDisk`/`exportHardwareRam`) already builds its rows from the full filtered dataset independently of what's rendered in the DOM — it is not touched by this plan and must keep exporting the complete filtered set regardless of pagination.
- **Correction found during plan research:** the design spec describes "the Hardware table" as if it were one table like Clients/Software. Reading `index.html`/`app.js` shows Hardware is actually three independent, much smaller aggregate tables (CPU models, Storage/Disk models, RAM configurations — each grouped by distinct hardware spec with a "Machines" count, not one row per client) that render simultaneously in the same view, stacked vertically. Splitting one shared "available viewport height" three ways between differently-sized stacked tables adds real layout-measurement complexity for tables that are rarely large (bounded by distinct hardware models seen across the fleet, not by client count). This plan applies full live viewport-adaptive pagination to Clients and Software only (the two single-dominant-table-per-tab views the spec's "fill the window" behavior is actually about), and a fixed, generous page size (20 rows) to the three Hardware sub-tables — still paginated (so an unusually hardware-diverse fleet doesn't produce an endless list), just not resize-adaptive. This preserves the spec's intent (bound every inventory table's length) without disproportionate complexity for tables that rarely need it.
- MINOR version bump required (new feature, per this workspace's versioning rule): confirm the actual current version via `grep` before assuming a value, bump both `WindowsInventoryLiteServer.cs` and `WindowsInventoryLiteClient.cs`'s `Program.ProductVersion` identically even though client code itself is untouched (matches the precedent set by the prior Dashboard Credential Encryption plan, which bumped both for a server+installer-only change).

---

### Task 1: Swap the `Collected`/`AD Description` columns in the Clients table

**Files:**
- Modify: `server/dashboard/index.html` (Clients table header)
- Modify: `server/dashboard/app.js` (`renderTable`'s row template)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing other tasks depend on — purely a column reorder, independent of every other task in this plan.

- [ ] **Step 1: Swap the header cells**

Find this in `server/dashboard/index.html` (inside `<section id="clientsView">`'s `<thead>`):

```html
                  <th data-sort-table="clients" data-sort-key="collectedAt" class="sortable">Collected</th>
                  <th>AD Description</th>
```

Replace with:

```html
                  <th>AD Description</th>
                  <th data-sort-table="clients" data-sort-key="collectedAt" class="sortable">Collected</th>
```

- [ ] **Step 2: Swap the matching row cells**

Find this in `server/dashboard/app.js` (inside `renderTable`'s row template, the `<tr class="${staleClass}">` block):

```javascript
        <td>${escapeHtml(formatDateTime(client.collectedAt || client.sourceUpdatedAt))}</td>
        <td>${formatAdDescription(client)}</td>
```

Replace with:

```javascript
        <td>${formatAdDescription(client)}</td>
        <td>${escapeHtml(formatDateTime(client.collectedAt || client.sourceUpdatedAt))}</td>
```

- [ ] **Step 3: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass (this confirms no Cyrillic/encoding issue was introduced; there is no server-side code in this task to build or self-test).

- [ ] **Step 4: Live-verify the column order**

Start the server against a scratch data directory with at least one synthetic client report (see Task 2 Step 6 for the fixture-generation script if one doesn't already exist from a prior task in this session — for this task alone, a single hand-written JSON file is enough):

```bash
mkdir -p /tmp/wil-col-swap-test/data
cat > /tmp/wil-col-swap-test/data/TEST-PC01.json << 'EOF'
{"computerName":"TEST-PC01","domain":"example.local","clientVersion":"1.0.0","os":{"caption":"Windows 11 Pro","version":"10.0","buildNumber":"22631"},"office":{"name":"Microsoft 365","version":"16.0"},"activation":{"windows":{"activated":true},"office":{"activated":true}},"software":[],"collectedAt":"2026-07-16T10:00:00Z","adDescription":"Accounting - 3rd floor"}
EOF
tail -f /dev/null | ./build/WindowsInventoryLiteServer.exe --console --prefix http://localhost:18300/ --data /tmp/wil-col-swap-test/data &
sleep 2
```

Use the Playwright MCP tools to navigate to `http://localhost:18300/#clients`, take a snapshot, and confirm: the header row reads `... Software | AD Description | Collected | Actions` (AD Description before Collected), and `TEST-PC01`'s row shows `Accounting - 3rd floor` in the column immediately before the collected-timestamp column.

Clean up:
```bash
taskkill //IM WindowsInventoryLiteServer.exe //F
rm -rf /tmp/wil-col-swap-test
```

- [ ] **Step 5: Commit**

```bash
git add server/dashboard/index.html server/dashboard/app.js
git commit -m "Swap Collected/AD Description column order in the Clients table"
```

---

### Task 2: Pagination core + live-adaptive pagination for the Clients table

**Files:**
- Modify: `server/dashboard/app.js` (new `state.page`/`state.pageSize`, `paginate()`, `renderPager()`, `computeLiveRowsPerPage()`, `recalculateActivePagination()`, resize listener, `renderTable`, `render()`, `searchInput` listener, sort-click listener)
- Modify: `server/dashboard/index.html` (add `#clientsPager` container)
- Modify: `server/dashboard/styles.css` (add `.pager`/`.pager-status`/`.pager-button`)

**Interfaces:**
- Consumes: nothing new from other tasks.
- Produces: `paginate(arr, page, pageSize)` → `{ items, page, totalPages }`, `renderPager(containerId, tableKey, page, totalPages, onChange)`, `computeLiveRowsPerPage(tbodyId)` → `number | null`, and the `state.page`/`state.pageSize` objects keyed `clients`/`software`/`hwCpu`/`hwDisk`/`hwRam`. Task 3 (Software) and Task 4 (Hardware) both call `paginate()`/`renderPager()` directly with their own table key; Task 3 additionally calls `computeLiveRowsPerPage()` the same way this task does for Clients.

- [ ] **Step 1: Add pagination state**

Find this in `server/dashboard/app.js` (the `state` object declaration):

```javascript
    sort: {
      clients: { key: 'computerName', dir: 1 },
      software: { key: 'name', dir: 1 },
      hwCpu: { key: 'name', dir: 1 },
      hwDisk: { key: 'model', dir: 1 },
      hwRam: { key: 'totalMb', dir: -1 },
      licenses: { key: 'name', dir: 1 }
    }
  };
```

Replace with:

```javascript
    sort: {
      clients: { key: 'computerName', dir: 1 },
      software: { key: 'name', dir: 1 },
      hwCpu: { key: 'name', dir: 1 },
      hwDisk: { key: 'model', dir: 1 },
      hwRam: { key: 'totalMb', dir: -1 },
      licenses: { key: 'name', dir: 1 }
    },
    page: { clients: 1, software: 1, hwCpu: 1, hwDisk: 1, hwRam: 1 },
    // clients/software start at a reasonable fallback and are corrected to
    // the real viewport-fitting value the first time their table becomes
    // visible (see computeLiveRowsPerPage/recalculateActivePagination).
    // hwCpu/hwDisk/hwRam are fixed (see HW_PAGE_SIZE) - the three Hardware
    // sub-tables render stacked in one view and are rarely large enough to
    // need viewport-adaptive sizing (see this plan's Global Constraints).
    pageSize: { clients: 20, software: 20, hwCpu: 20, hwDisk: 20, hwRam: 20 }
  };

  const MIN_PAGE_SIZE = 5;
  const HW_PAGE_SIZE = 20;
  // Reserves room below a table's rows for its pager control plus a small
  // bottom margin, so the computed page size doesn't crowd the pager off
  // the bottom edge of the viewport.
  const PAGER_RESERVE_PX = 56;
```

- [ ] **Step 2: Add the shared `paginate()` and `renderPager()` helpers**

Find `function applySort(arr, valueFn, dir) {` in `server/dashboard/app.js` and locate its closing brace (the `}` immediately followed by a blank line before `function clientSortValue`). Add the following two functions immediately after that closing brace:

```javascript
  // Slices an already-filtered/sorted array to one page and returns
  // pagination metadata. page is clamped into [1, totalPages] so a stale
  // page number (e.g. after a search narrows the result set to fewer
  // pages than the user was previously on) always produces a valid slice
  // instead of an empty one.
  function paginate(arr, page, pageSize) {
    const totalPages = Math.max(1, Math.ceil(arr.length / pageSize));
    const clampedPage = Math.min(Math.max(1, page), totalPages);
    const start = (clampedPage - 1) * pageSize;
    return { items: arr.slice(start, start + pageSize), page: clampedPage, totalPages };
  }

  // Renders a "Prev  Page N of M  Next" control into containerId, wiring
  // click handlers that update state.page[tableKey] and invoke onChange
  // (the calling table's own render function) to redraw with the new
  // page. Renders nothing when there's only one page, so small result
  // sets (e.g. a handful of distinct CPU models) don't show a pager that
  // can never do anything.
  function renderPager(containerId, tableKey, page, totalPages, onChange) {
    const container = byId(containerId);
    if (!container) return;
    if (totalPages <= 1) {
      container.innerHTML = '';
      return;
    }
    container.innerHTML = `
      <button class="export-button pager-button" type="button" data-pager-prev${page <= 1 ? ' disabled' : ''}>Prev</button>
      <span class="pager-status">Page ${page} of ${totalPages}</span>
      <button class="export-button pager-button" type="button" data-pager-next${page >= totalPages ? ' disabled' : ''}>Next</button>
    `;
    const prevBtn = container.querySelector('[data-pager-prev]');
    const nextBtn = container.querySelector('[data-pager-next]');
    if (prevBtn) prevBtn.addEventListener('click', () => { state.page[tableKey] = page - 1; onChange(); });
    if (nextBtn) nextBtn.addEventListener('click', () => { state.page[tableKey] = page + 1; onChange(); });
  }

  // Measures how many rows of the table rooted at tbodyId fit between its
  // current top position and the bottom of the viewport, reserving room
  // for its pager control. Returns null when the table isn't actually
  // visible yet (its first row has zero height - e.g. right after a tab
  // switch, before layout has settled) so callers can skip updating
  // rather than compute a bogus size from a zero-height row.
  function computeLiveRowsPerPage(tbodyId) {
    const tbody = byId(tbodyId);
    if (!tbody) return null;
    const firstRow = tbody.querySelector('tr:not(.details-row)');
    if (!firstRow) return null;
    const rowHeight = firstRow.offsetHeight;
    if (!rowHeight) return null;
    const available = window.innerHeight - tbody.getBoundingClientRect().top - PAGER_RESERVE_PX;
    return Math.max(MIN_PAGE_SIZE, Math.floor(available / rowHeight));
  }
```

- [ ] **Step 3: Apply pagination to `renderTable` (Clients)**

Find this in `server/dashboard/app.js`:

```javascript
  function renderTable(clients) {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.clients;
    const rows = applySort(clients.filter(client => clientMatches(client, query)), c => clientSortValue(c, sortKey), sortDir).map(client => {
```

Replace with:

```javascript
  function renderTable(clients) {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.clients;
    const filtered = applySort(clients.filter(client => clientMatches(client, query)), c => clientSortValue(c, sortKey), sortDir);
    const { items: pageItems, page, totalPages } = paginate(filtered, state.page.clients, state.pageSize.clients);
    state.page.clients = page;
    const rows = pageItems.map(client => {
```

Find this later in the same function (its closing lines):

```javascript
    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="10" class="empty">No matching inventory records.</td></tr>';
  }
```

Replace with:

```javascript
    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="10" class="empty">No matching inventory records.</td></tr>';
    renderPager('clientsPager', 'clients', page, totalPages, () => renderTable(state.clients));
  }
```

- [ ] **Step 4: Recalculate the Clients page size when its tab becomes active, and on resize**

Find this in `server/dashboard/app.js` (near the end of `render()`, right after the `isInventoryView`-dependent toggles and before `bindDetails();`):

```javascript
    const isInventoryView = inventoryViews.includes(state.view);
    byId('summarySection').classList.toggle('hidden', !isInventoryView);
    byId('searchInput').classList.toggle('hidden', !isInventoryView);
    byId('generatedAt').classList.toggle('hidden', !isInventoryView);
    bindDetails();
  }
```

Replace with:

```javascript
    const isInventoryView = inventoryViews.includes(state.view);
    byId('summarySection').classList.toggle('hidden', !isInventoryView);
    byId('searchInput').classList.toggle('hidden', !isInventoryView);
    byId('generatedAt').classList.toggle('hidden', !isInventoryView);
    bindDetails();
    recalculateActivePagination();
  }

  // Re-measures and, if it changed, applies a corrected live page size for
  // whichever table is now visible. Only Clients/Software are viewport-
  // adaptive (see this plan's Global Constraints for why Hardware's three
  // sub-tables use a fixed size instead); this function is a no-op for
  // every other view.
  function recalculateActivePagination() {
    if (state.view === 'clients') {
      const size = computeLiveRowsPerPage('inventoryBody');
      if (size && size !== state.pageSize.clients) {
        state.pageSize.clients = size;
        renderTable(state.clients);
      }
    }
  }
```

- [ ] **Step 5: Reset to page 1 on search, and recompute on resize**

Find this in `server/dashboard/app.js`:

```javascript
  byId('searchInput').addEventListener('input', render);
```

Replace with:

```javascript
  byId('searchInput').addEventListener('input', () => {
    state.page.clients = 1;
    state.page.software = 1;
    state.page.hwCpu = 1;
    state.page.hwDisk = 1;
    state.page.hwRam = 1;
    render();
  });

  let paginationResizeTimer = null;
  window.addEventListener('resize', () => {
    clearTimeout(paginationResizeTimer);
    paginationResizeTimer = setTimeout(recalculateActivePagination, 150);
  });
```

- [ ] **Step 6: Reset the Clients table to page 1 when its sort changes**

Find this in `server/dashboard/app.js` (the shared sort-header click listener):

```javascript
    if (current.key === key) {
      current.dir = -current.dir;
    } else {
      current.key = key;
      current.dir = 1;
    }
    render();
```

Replace with:

```javascript
    if (current.key === key) {
      current.dir = -current.dir;
    } else {
      current.key = key;
      current.dir = 1;
    }
    if (state.page[table] !== undefined) state.page[table] = 1;
    render();
```

(This one shared listener handles every sortable table's header clicks, including Software and the three Hardware sub-tables added in later tasks — the `state.page[table] !== undefined` guard is future-proof for `licenses`, which has a `state.sort` entry but no `state.page` entry.)

- [ ] **Step 7: Add the Clients pager container**

Find this in `server/dashboard/index.html`:

```html
              <tbody id="inventoryBody"></tbody>
            </table>
          </div>
        </section>

        <section id="softwareView" class="hidden" aria-label="Software inventory">
```

Replace with:

```html
              <tbody id="inventoryBody"></tbody>
            </table>
          </div>
          <div id="clientsPager" class="pager"></div>
        </section>

        <section id="softwareView" class="hidden" aria-label="Software inventory">
```

- [ ] **Step 8: Add pager CSS**

Find this in `server/dashboard/styles.css`:

```css
.export-button:hover {
  border-color: var(--accent);
  color: var(--accent);
}
```

Replace with:

```css
.export-button:hover {
  border-color: var(--accent);
  color: var(--accent);
}

.pager {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  margin: 12px 0 4px;
}

.pager-button:disabled {
  cursor: default;
  opacity: 0.5;
}

.pager-status {
  font-size: 13px;
  color: var(--muted);
}
```

- [ ] **Step 9: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 10: Write the fixture-generation script and live-verify Clients pagination**

This script is scratch test tooling, not part of the shipped project — write it to the OS temp directory, not into the repo. It generates enough synthetic client reports to force multiple pages at any reasonable window height, matching the exact field names `app.js` reads (confirmed against `renderTable`/`clientSortValue`/`clientMatches` and the server's pass-through storage model, which writes/serves each report's raw JSON keys unchanged).

```bash
mkdir -p /tmp/wil-pagination-test/data
python3 - << 'PYEOF'
import json, os
outdir = "/tmp/wil-pagination-test/data"
for i in range(1, 61):
    name = f"PC-{i:03d}"
    doc = {
        "computerName": name,
        "domain": "example.local",
        "clientVersion": "1.0.0",
        "os": {"caption": "Windows 11 Pro", "version": "10.0", "buildNumber": "22631"},
        "office": {"name": "Microsoft 365", "version": "16.0"},
        "activation": {"windows": {"activated": i % 2 == 0}, "office": {"activated": i % 3 == 0}},
        "software": [{"name": f"App {n}", "version": "1.0", "publisher": "Vendor"} for n in range(i % 4)],
        "collectedAt": "2026-07-16T10:00:00Z",
        "cpu": {"name": "Intel Core i5-1135G7", "cores": 4, "clockMhz": 2400},
        "ramTotalMb": 16384,
        "disks": [{"type": "SSD", "sizeGb": 512, "model": "Samsung 970 EVO", "usb": False}],
        "hasUsbStorage": False,
        "adDescription": f"Desk {i}"
    }
    with open(os.path.join(outdir, name + ".json"), "w", encoding="utf-8") as f:
        json.dump(doc, f)
PYEOF
tail -f /dev/null | ./build/WindowsInventoryLiteServer.exe --console --prefix http://localhost:18301/ --data /tmp/wil-pagination-test/data &
sleep 2
```

Use the Playwright MCP tools to:
1. Navigate to `http://localhost:18301/#clients` at a typical desktop viewport (e.g. 1280x900). Take a snapshot; confirm the table shows fewer than 60 rows and a `Page 1 of N` pager is present.
2. Click `Next`; confirm the page number advances and different `PC-0xx` rows appear.
3. Resize the browser window to a much shorter height (e.g. 1280x500) via `browser_resize`; wait briefly for the debounced recalculation; confirm the row count per page visibly decreases and `Page 1 of N` now shows a larger `N`.
4. Type into the search box (e.g. `PC-00`); confirm the pager resets to `Page 1 of N` with a smaller `N` reflecting the narrowed result set.
5. Resize to a very short height (e.g. 1280x250); confirm the page never shows fewer than 5 rows (the `MIN_PAGE_SIZE` clamp).

Clean up:
```bash
taskkill //IM WindowsInventoryLiteServer.exe //F
rm -rf /tmp/wil-pagination-test
```

- [ ] **Step 11: Commit**

```bash
git add server/dashboard/app.js server/dashboard/index.html server/dashboard/styles.css
git commit -m "Add adaptive pagination to the Clients table"
```

---

### Task 3: Pagination for the Software table

**Files:**
- Modify: `server/dashboard/app.js` (`renderSoftwareTable`, `recalculateActivePagination`)
- Modify: `server/dashboard/index.html` (add `#softwarePager` container)

**Interfaces:**
- Consumes: `paginate()`, `renderPager()`, `computeLiveRowsPerPage()` (Task 2, unchanged).
- Produces: nothing new — completes the `software` entry in the pattern Task 2 established for `clients`.

- [ ] **Step 1: Apply pagination to `renderSoftwareTable`**

Find this in `server/dashboard/app.js`:

```javascript
  function renderSoftwareTable(clients) {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.software;
    const rows = applySort(getSoftwareGroups(clients).filter(group => softwareMatches(group, query)), g => softwareSortValue(g, sortKey), sortDir).map(group => {
```

Replace with:

```javascript
  function renderSoftwareTable(clients) {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.software;
    const filtered = applySort(getSoftwareGroups(clients).filter(group => softwareMatches(group, query)), g => softwareSortValue(g, sortKey), sortDir);
    const { items: pageItems, page, totalPages } = paginate(filtered, state.page.software, state.pageSize.software);
    state.page.software = page;
    const rows = pageItems.map(group => {
```

Find this later in the same function:

```javascript
    byId('softwareBody').innerHTML = rows.join('') || '<tr><td colspan="5" class="empty">No matching software records.</td></tr>';

    document.querySelectorAll('[data-software-license-name]').forEach(button => {
```

Replace with:

```javascript
    byId('softwareBody').innerHTML = rows.join('') || '<tr><td colspan="5" class="empty">No matching software records.</td></tr>';
    renderPager('softwarePager', 'software', page, totalPages, () => renderSoftwareTable(state.clients));

    document.querySelectorAll('[data-software-license-name]').forEach(button => {
```

- [ ] **Step 2: Wire Software into the active-view recalculation**

Find this in `server/dashboard/app.js` (added in Task 2):

```javascript
  function recalculateActivePagination() {
    if (state.view === 'clients') {
      const size = computeLiveRowsPerPage('inventoryBody');
      if (size && size !== state.pageSize.clients) {
        state.pageSize.clients = size;
        renderTable(state.clients);
      }
    }
  }
```

Replace with:

```javascript
  function recalculateActivePagination() {
    if (state.view === 'clients') {
      const size = computeLiveRowsPerPage('inventoryBody');
      if (size && size !== state.pageSize.clients) {
        state.pageSize.clients = size;
        renderTable(state.clients);
      }
    } else if (state.view === 'software') {
      const size = computeLiveRowsPerPage('softwareBody');
      if (size && size !== state.pageSize.software) {
        state.pageSize.software = size;
        renderSoftwareTable(state.clients);
      }
    }
  }
```

- [ ] **Step 3: Add the Software pager container**

Find this in `server/dashboard/index.html`:

```html
              <tbody id="softwareBody"></tbody>
            </table>
          </div>
        </section>

        <section id="hardwareView" class="hidden" aria-label="Hardware inventory">
```

Replace with:

```html
              <tbody id="softwareBody"></tbody>
            </table>
          </div>
          <div id="softwarePager" class="pager"></div>
        </section>

        <section id="hardwareView" class="hidden" aria-label="Hardware inventory">
```

- [ ] **Step 4: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 5: Live-verify Software pagination**

Reuse the same fixture-generation script from Task 2 Step 10 (it already gives each synthetic client a small distinct software list, which is enough to produce more than one page of grouped software rows across 60 clients). Start the server against a fresh copy of that fixture data, then with Playwright MCP tools:
1. Navigate to `http://localhost:18302/#software` at a typical desktop viewport; confirm a pager is present and `Next` changes the visible rows.
2. Resize the window shorter; confirm the Software page size recomputes independently of whatever the Clients tab's page size currently is (switch to Clients first to confirm its own pager is unaffected by Software's resize-triggered recalculation, since only the active view recalculates).

Clean up the scratch server/data directory afterward as in Task 2 Step 10.

- [ ] **Step 6: Commit**

```bash
git add server/dashboard/app.js server/dashboard/index.html
git commit -m "Add adaptive pagination to the Software table"
```

---

### Task 4: Fixed-size pagination for the three Hardware sub-tables

**Files:**
- Modify: `server/dashboard/app.js` (`renderHardwarePage`)
- Modify: `server/dashboard/index.html` (add 3 pager containers, one per Hardware sub-table)

**Interfaces:**
- Consumes: `paginate()`, `renderPager()` (Task 2). Does NOT consume `computeLiveRowsPerPage()` — per this plan's Global Constraints, the three Hardware sub-tables use the fixed `HW_PAGE_SIZE` (Task 2, Step 1) rather than live measurement.
- Produces: nothing new.

- [ ] **Step 1: Apply pagination to all three groups in `renderHardwarePage`**

Find this in `server/dashboard/app.js`:

```javascript
    const { key: cpuSortKey, dir: cpuSortDir } = state.sort.hwCpu;
    const cpuRows = applySort(getCpuGroups(clients).filter(g => hwMatches([g.name, ...g.clients.map(c => c.computerName)].join(' '), query)), g => cpuSortValue(g, cpuSortKey), cpuSortDir).map(g => {
```

Replace with:

```javascript
    const { key: cpuSortKey, dir: cpuSortDir } = state.sort.hwCpu;
    const cpuFiltered = applySort(getCpuGroups(clients).filter(g => hwMatches([g.name, ...g.clients.map(c => c.computerName)].join(' '), query)), g => cpuSortValue(g, cpuSortKey), cpuSortDir);
    const { items: cpuPageItems, page: cpuPage, totalPages: cpuTotalPages } = paginate(cpuFiltered, state.page.hwCpu, state.pageSize.hwCpu);
    state.page.hwCpu = cpuPage;
    const cpuRows = cpuPageItems.map(g => {
```

Find this a few lines later:

```javascript
    byId('hwCpuBody').innerHTML = cpuRows.join('') || '<tr><td colspan="4" class="empty">No CPU data.</td></tr>';

    const { key: diskSortKey, dir: diskSortDir } = state.sort.hwDisk;
    const diskRows = applySort(getDiskGroups(clients).filter(g => hwMatches([g.model, g.type, ...g.clients.map(c => c.computerName)].join(' '), query)), g => diskSortValue(g, diskSortKey), diskSortDir).map(g => {
```

Replace with:

```javascript
    byId('hwCpuBody').innerHTML = cpuRows.join('') || '<tr><td colspan="4" class="empty">No CPU data.</td></tr>';
    renderPager('hwCpuPager', 'hwCpu', cpuPage, cpuTotalPages, () => renderHardwarePage(state.clients));

    const { key: diskSortKey, dir: diskSortDir } = state.sort.hwDisk;
    const diskFiltered = applySort(getDiskGroups(clients).filter(g => hwMatches([g.model, g.type, ...g.clients.map(c => c.computerName)].join(' '), query)), g => diskSortValue(g, diskSortKey), diskSortDir);
    const { items: diskPageItems, page: diskPage, totalPages: diskTotalPages } = paginate(diskFiltered, state.page.hwDisk, state.pageSize.hwDisk);
    state.page.hwDisk = diskPage;
    const diskRows = diskPageItems.map(g => {
```

Find this a few lines later:

```javascript
    byId('hwDiskBody').innerHTML = diskRows.join('') || '<tr><td colspan="4" class="empty">No storage data.</td></tr>';

    const { key: ramSortKey, dir: ramSortDir } = state.sort.hwRam;
    const ramRows = applySort(getRamGroups(clients).filter(g => hwMatches([g.totalGb, ...g.clients.map(c => c.computerName)].join(' '), query)), g => ramSortValue(g, ramSortKey), ramSortDir).map(g => {
```

Replace with:

```javascript
    byId('hwDiskBody').innerHTML = diskRows.join('') || '<tr><td colspan="4" class="empty">No storage data.</td></tr>';
    renderPager('hwDiskPager', 'hwDisk', diskPage, diskTotalPages, () => renderHardwarePage(state.clients));

    const { key: ramSortKey, dir: ramSortDir } = state.sort.hwRam;
    const ramFiltered = applySort(getRamGroups(clients).filter(g => hwMatches([g.totalGb, ...g.clients.map(c => c.computerName)].join(' '), query)), g => ramSortValue(g, ramSortKey), ramSortDir);
    const { items: ramPageItems, page: ramPage, totalPages: ramTotalPages } = paginate(ramFiltered, state.page.hwRam, state.pageSize.hwRam);
    state.page.hwRam = ramPage;
    const ramRows = ramPageItems.map(g => {
```

Find the function's closing lines:

```javascript
    byId('hwRamBody').innerHTML = ramRows.join('') || '<tr><td colspan="3" class="empty">No RAM data.</td></tr>';
  }
```

Replace with:

```javascript
    byId('hwRamBody').innerHTML = ramRows.join('') || '<tr><td colspan="3" class="empty">No RAM data.</td></tr>';
    renderPager('hwRamPager', 'hwRam', ramPage, ramTotalPages, () => renderHardwarePage(state.clients));
  }
```

- [ ] **Step 2: Add the three Hardware pager containers**

Find this in `server/dashboard/index.html`:

```html
                <tbody id="hwCpuBody"></tbody>
              </table>
            </div>
          </div>
```

Replace with:

```html
                <tbody id="hwCpuBody"></tbody>
              </table>
            </div>
            <div id="hwCpuPager" class="pager"></div>
          </div>
```

Find this:

```html
                <tbody id="hwDiskBody"></tbody>
              </table>
            </div>
          </div>
```

Replace with:

```html
                <tbody id="hwDiskBody"></tbody>
              </table>
            </div>
            <div id="hwDiskPager" class="pager"></div>
          </div>
```

Find this:

```html
                <tbody id="hwRamBody"></tbody>
              </table>
            </div>
          </div>
        </section>
```

Replace with:

```html
                <tbody id="hwRamBody"></tbody>
              </table>
            </div>
            <div id="hwRamPager" class="pager"></div>
          </div>
        </section>
```

- [ ] **Step 3: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 4: Live-verify Hardware pagination**

The Task 2 fixture script only produces one CPU model, one disk model, and one RAM configuration across all 60 synthetic clients (since it hardcodes those fields) — enough clients grouped under few hardware rows, which is realistic but won't itself exercise a multi-page Hardware sub-table. Adapt the fixture script for this step by varying `cpu.name`/`disks[0].model`/`ramTotalMb` per client (e.g. `f"CPU Model {i}"`, `f"Disk Model {i}"`, `8192 + (i * 100)`) so each of the 60 synthetic clients produces a distinct CPU/disk/RAM group, forcing all three Hardware sub-tables past the fixed 20-row page size.

With Playwright MCP tools: navigate to `http://localhost:18303/#hardware`; confirm all three sub-tables (CPUs, Storage, RAM) show a `Page 1 of N` pager with `N > 1`; click `Next` on each independently and confirm each sub-table's page advances without affecting the other two's current page.

Clean up the scratch server/data directory afterward as in Task 2 Step 10.

- [ ] **Step 5: Commit**

```bash
git add server/dashboard/app.js server/dashboard/index.html
git commit -m "Add fixed-size pagination to the Hardware CPU/Storage/RAM tables"
```

---

### Task 5: Relocate and compact the Inventory summary tiles

**Files:**
- Modify: `server/dashboard/index.html` (move `#summarySection`, add `summary-compact` class)
- Modify: `server/dashboard/styles.css` (add `.summary-compact`)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing other tasks depend on.

- [ ] **Step 1: Move `#summarySection` to the top of the Inventory area**

Find this in `server/dashboard/index.html` (its current position, after the Hardware view):

```html
        </section>

        <section id="summarySection" class="summary" aria-label="Inventory summary">
          <div><span id="clientCount">0</span><small>Clients</small></div>
          <div><span id="windowsActivated">0</span><small>Windows activated</small></div>
          <div><span id="officeActivated">0</span><small>Office activated</small></div>
          <div id="staleTile"><span id="staleCount">0</span><small id="staleLabel">Stale &gt;48h</small></div>
        </section>
      </main>
```

Replace with:

```html
        </section>
      </main>
```

(This removes the block from its old position — the closing `</section>` that remains is `hardwareView`'s own, immediately followed now by `</main>`.)

Find this in `server/dashboard/index.html` (the top of the Inventory area):

```html
      <main>
        <section id="dashboardView" class="install-panel" aria-label="Dashboard">
```

Replace with:

```html
      <main>
        <section id="summarySection" class="summary summary-compact" aria-label="Inventory summary">
          <div><span id="clientCount">0</span><small>Clients</small></div>
          <div><span id="windowsActivated">0</span><small>Windows activated</small></div>
          <div><span id="officeActivated">0</span><small>Office activated</small></div>
          <div id="staleTile"><span id="staleCount">0</span><small id="staleLabel">Stale &gt;48h</small></div>
        </section>

        <section id="dashboardView" class="install-panel" aria-label="Dashboard">
```

No JS change is needed: `#summarySection`'s visibility is already driven purely by `byId('summarySection').classList.toggle('hidden', !isInventoryView)` in `render()` (unaffected by its position in the DOM), and `renderSummary()` populates it via `byId(...)` lookups that don't depend on source order either.

- [ ] **Step 2: Add the compact tile style**

Find this in `server/dashboard/styles.css`:

```css
.summary span {
  display: block;
  margin-bottom: 4px;
  color: var(--accent);
  font-size: 28px;
  font-weight: 700;
}
```

Replace with:

```css
.summary span {
  display: block;
  margin-bottom: 4px;
  color: var(--accent);
  font-size: 28px;
  font-weight: 700;
}

/* Declared after .summary div/span so it wins at the equal class+type
   specificity both rule pairs share - same reasoning as .tile-alert
   just below, which relies on the same ordering. */
.summary-compact div {
  padding: 7px 10px;
}

.summary-compact span {
  font-size: 15px;
  margin-bottom: 2px;
}
```

- [ ] **Step 3: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 4: Live-verify tile relocation and sizing**

Start the server against any small fixture data directory (a single synthetic client, as in Task 1 Step 4, is enough). With Playwright MCP tools:
1. Navigate to `http://localhost:18304/#clients` at a desktop viewport; take a snapshot; confirm the summary tiles appear immediately below the search bar, above the Clients table, and are visually smaller than before (compare against a screenshot/measurement of `#dashboardTiles` on the Dashboard tab, which must be unchanged and still uses the larger `.summary` sizing).
2. Switch to `#software` and `#hardware`; confirm the same compact tile row appears at the top of each (it's shared across all three Inventory sub-tabs, unchanged from its pre-existing behavior).
3. Switch to `#dashboard`; confirm the relocated `#summarySection` is hidden and `#dashboardTiles` is unaffected (same size as before this task).
4. Resize to a 480px-wide mobile viewport; confirm the compact tiles still lay out in the existing 2-column mobile grid (from the pre-existing `.summary` media-query rule) without overlap or clipping.
5. Repeat the 1280px and 480px checks in both light and dark theme (toggle via the theme button).

Clean up the scratch server/data directory afterward as in Task 1 Step 4.

- [ ] **Step 5: Commit**

```bash
git add server/dashboard/index.html server/dashboard/styles.css
git commit -m "Move Inventory summary tiles to the top and make them more compact"
```

---

### Task 6: Version bump, CHANGELOG, and final combined verification

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `src/server/WindowsInventoryLiteServer.cs` (`Program.ProductVersion`)
- Modify: `src/client/WindowsInventoryLiteClient.cs` (`Program.ProductVersion`)

- [ ] **Step 1: Confirm the current version and bump it**

Run: `grep -n "ProductVersion = " src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs`
Confirm the current value (expected `"0.11.0"` as of this plan's writing — if a different change landed on this branch first and moved it further, use the actual current value and bump a MINOR version from there instead). Update both files to the next MINOR version (patch reset to 0) — identical value in both files.

- [ ] **Step 2: Add the CHANGELOG entry**

Add a new `## [<new-version>] - 2026-07-16` section at the top of `CHANGELOG.md`, after `## [Unreleased]`, matching the file's existing entry format:

```markdown
### Added

- The Clients and Software inventory tables are now paginated, with page size adapting live to the browser window's height. The Hardware CPU/Storage/RAM tables are paginated with a fixed page size.
- The Inventory summary tiles (client count, activation counts, stale count) moved to the top of the Inventory section and are more compact.
- Swapped the `Collected`/`AD Description` column order in the Clients table.
```

- [ ] **Step 3: Full rebuild and verification**

```powershell
.\src\Build-Server.ps1
.\src\Build-Client.ps1 -TargetFramework Net35 -OutputPath '.\build\WindowsInventoryLiteClient-net35.exe'
.\src\Build-Client.ps1 -TargetFramework Net40 -OutputPath '.\build\WindowsInventoryLiteClient-net40.exe'
.\build\WindowsInventoryLiteServer.exe --self-test
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester -Path .\tests -Output Detailed
.\build\WindowsInventoryLiteServer.exe --version
```

Expected: all three builds succeed, self-test suite all `PASS` with exit code 0 (no dashboard-related self-tests exist to add or break — this step exists to prove the version-constant edit compiles cleanly, matching the precedent from the prior Dashboard Credential Encryption plan's final task), Pester all green, printed version matches the new bumped value.

- [ ] **Step 4: Final combined live verification**

Using the varied-hardware fixture from Task 4 Step 4 (60 synthetic clients with distinct CPU/disk/RAM/software per client), start the server and use Playwright MCP tools to walk through the whole feature end to end in one session:
1. Load `#clients`; confirm column order (`AD Description` before `Collected`), compact tiles at the top, and a working pager (`Next`/`Prev`, page count updates on search).
2. Load `#software`; confirm its own independent pager works.
3. Load `#hardware`; confirm all three sub-tables have independent, working pagers.
4. Resize the window across a few sizes; confirm Clients/Software page sizes visibly adapt while Hardware's stay fixed at 20.
5. Toggle dark theme and repeat a spot check of the compact tiles and pager button styling.

Clean up the scratch server/data directory afterward.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs
git commit -m "Bump version for Inventory Views UX"
```
