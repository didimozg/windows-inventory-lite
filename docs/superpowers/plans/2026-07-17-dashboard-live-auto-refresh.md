# Dashboard Live Auto-Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the dashboard's client list current via a 30-second background poll, without disrupting the user's current page/sort/search per table or any expanded detail rows - and, as a side effect, fix an existing rough edge where expanded detail rows already collapse on every pager Next/Prev click today.

**Architecture:** Pure client-side change to `server/dashboard/app.js`/`styles.css` - no server-side (C#) code touched, no new server endpoint. A new `state.expandedDetails` Set makes "which detail rows are open" state-driven instead of DOM-only, so it survives any re-render. A 30-second `setInterval` re-fetches the existing `/api/v1/clients` endpoint, compares a lightweight client-side fingerprint of the response (not the server's `generatedAt`, which reflects request time rather than data time - see Global Constraints) to detect real changes, and only re-renders when something actually changed. Polling pauses while the browser tab is hidden and does one immediate catch-up poll on becoming visible again.

**Tech Stack:** Vanilla JS (no framework, no build step), matching the rest of this dashboard.

## Global Constraints

- No server-side (C#) code changes in this plan - dashboard-rendering-only, matching how the Inventory Views UX plan was scoped.
- **Corrected during plan research:** the design spec originally compared the server's `generatedAt` field between polls to detect changes. `BuildClientIndex()` (server-side) sets `generatedAt` to `DateTime.UtcNow` on every call - it is response-build time, not data time, and differs on every single poll regardless of whether anything changed. The implementation instead computes its own fingerprint from the client data it already receives (`computeClientsFingerprint`, see Task 2) - purely client-side, no server change needed. As a result, the "Generated: ..." label now only updates when the fingerprint actually changes, not on every successful poll - this is a behavior improvement (a genuinely stale-vs-fresh signal) not a regression, since the label previously never updated after page load at all.
- CSS specificity discipline: this codebase has a documented history of "a more specific selector silently wins" bugs. The one new CSS rule in this plan (`.generated-at-flash`) is a plain additive class merged into the existing `.sidebar-footer #generatedAt` rule's `transition` property, not a competing/overriding selector.
- No automated JS test harness exists in this project for dashboard behavior (consistent with how Inventory Views UX was verified) - verification is via the existing Pester `ScriptSyntax.Tests.ps1` "keeps source in English" check (already covers `server/` recursively, no test-file change needed) plus live Playwright browser verification.
- Every task needs real build/test evidence. MINOR version bump required in the final task per this workspace's versioning rule.

---

### Task 1: `state.expandedDetails` - make expanded rows survive any re-render

**Files:**
- Modify: `server/dashboard/app.js`

**Interfaces:**
- Consumes: nothing new.
- Produces: `state.expandedDetails` (a `Set<string>` of prefixed keys `'client:'+id` / `'software:'+id` / `'hw:'+id`) - Task 2's poll-triggered `render()` call relies on this already being wired up correctly so a background refresh doesn't collapse whatever the user has open.

This task is independently valuable and independently testable before any polling code exists - it already fixes today's existing "pager Next/Prev collapses expanded rows" rough edge.

- [ ] **Step 1: Add `state.expandedDetails`**

Find this in `server/dashboard/app.js`:

```javascript
    page: { clients: 1, software: 1, hwCpu: 1, hwDisk: 1, hwRam: 1 },
    // clients/software start at a reasonable fallback and are corrected to
    // the real viewport-fitting value the first time their table becomes
    // visible (see computeLiveRowsPerPage/recalculateActivePagination).
    // hwCpu/hwDisk/hwRam are fixed (see HW_PAGE_SIZE) - the three Hardware
    // sub-tables render stacked in one view and are rarely large enough to
    // need viewport-adaptive sizing (see this plan's Global Constraints).
    pageSize: { clients: 20, software: 20, hwCpu: 20, hwDisk: 20, hwRam: 20 }
  };
```

Replace with:

```javascript
    page: { clients: 1, software: 1, hwCpu: 1, hwDisk: 1, hwRam: 1 },
    // clients/software start at a reasonable fallback and are corrected to
    // the real viewport-fitting value the first time their table becomes
    // visible (see computeLiveRowsPerPage/recalculateActivePagination).
    // hwCpu/hwDisk/hwRam are fixed (see HW_PAGE_SIZE) - the three Hardware
    // sub-tables render stacked in one view and are rarely large enough to
    // need viewport-adaptive sizing (see this plan's Global Constraints).
    pageSize: { clients: 20, software: 20, hwCpu: 20, hwDisk: 20, hwRam: 20 },
    // Prefixed keys ('client:'/'software:'/'hw:' + id) so the three
    // separate data-*-details attribute namespaces can't collide in one
    // Set. Drives each render function's initial hidden/visible class for
    // a details row, instead of every row always starting hidden - keeps
    // "expanded" state alive across any re-render (pager Next/Prev, a
    // live-resize page-size correction, or a background data poll), not
    // just the one that happened to be showing when the row was expanded.
    expandedDetails: new Set()
  };
```

- [ ] **Step 2: Track expand/collapse in the delegated click listener**

Find this in `server/dashboard/app.js`:

```javascript
    const clientBtn = e.target.closest('[data-client]');
    if (clientBtn) {
      const row = document.querySelector(`[data-client-details="${clientBtn.dataset.client}"]`);
      if (row) row.classList.toggle('hidden');
      return;
    }

    const softwareBtn = e.target.closest('[data-software]');
    if (softwareBtn) {
      const row = document.querySelector(`[data-software-details="${softwareBtn.dataset.software}"]`);
      if (row) row.classList.toggle('hidden');
      return;
    }

    const hwBtn = e.target.closest('[data-hw]');
    if (hwBtn) {
      const row = document.querySelector(`[data-hw-details="${hwBtn.dataset.hw}"]`);
      if (row) row.classList.toggle('hidden');
      return;
    }
```

Replace with:

```javascript
    const clientBtn = e.target.closest('[data-client]');
    if (clientBtn) {
      const key = 'client:' + clientBtn.dataset.client;
      const row = document.querySelector(`[data-client-details="${clientBtn.dataset.client}"]`);
      if (row) {
        const nowHidden = row.classList.toggle('hidden');
        if (nowHidden) { state.expandedDetails.delete(key); } else { state.expandedDetails.add(key); }
      }
      return;
    }

    const softwareBtn = e.target.closest('[data-software]');
    if (softwareBtn) {
      const key = 'software:' + softwareBtn.dataset.software;
      const row = document.querySelector(`[data-software-details="${softwareBtn.dataset.software}"]`);
      if (row) {
        const nowHidden = row.classList.toggle('hidden');
        if (nowHidden) { state.expandedDetails.delete(key); } else { state.expandedDetails.add(key); }
      }
      return;
    }

    const hwBtn = e.target.closest('[data-hw]');
    if (hwBtn) {
      const key = 'hw:' + hwBtn.dataset.hw;
      const row = document.querySelector(`[data-hw-details="${hwBtn.dataset.hw}"]`);
      if (row) {
        const nowHidden = row.classList.toggle('hidden');
        if (nowHidden) { state.expandedDetails.delete(key); } else { state.expandedDetails.add(key); }
      }
      return;
    }
```

- [ ] **Step 3: `renderTable` (Clients) - use the Set for the details row's initial class**

Find this in `server/dashboard/app.js`:

```javascript
      const clientId = safeId(client.computerName || '');

      return `<tr class="${staleClass}">
        <td><button class="link-button" type="button" data-client="${clientId}">${escapeHtml(client.computerName)}</button>${usbBadge}<small>${escapeHtml(client.domain)}</small>${ipAddresses ? `<small class="mono">${escapeHtml(ipAddresses)}</small>` : ''}</td>
        <td>${escapeHtml(client.clientVersion)}</td>
        <td>${escapeHtml(os.caption)}<small class="mono">${escapeHtml(os.version)} build ${escapeHtml(os.buildNumber)}</small></td>
        <td>${escapeHtml(office.name)}<small>${escapeHtml(office.version)}</small></td>
        <td>${activationBadge(windowsActivation.activated, 'Windows')}</td>
        <td>${activationBadge(officeActivation.activated, 'Office')}</td>
        <td>${softwareCount}</td>
        <td>${formatAdDescription(client)}</td>
        <td>${escapeHtml(formatDateTime(client.collectedAt || client.sourceUpdatedAt))}</td>
        <td><button class="danger-button-ghost" type="button" data-delete-client="${escapeHtml(client.computerName)}">Delete</button></td>
      </tr>
      <tr class="details-row hidden" data-client-details="${clientId}">
```

Replace with:

```javascript
      const clientId = safeId(client.computerName || '');
      const detailsHidden = state.expandedDetails.has('client:' + clientId) ? '' : 'hidden';

      return `<tr class="${staleClass}">
        <td><button class="link-button" type="button" data-client="${clientId}">${escapeHtml(client.computerName)}</button>${usbBadge}<small>${escapeHtml(client.domain)}</small>${ipAddresses ? `<small class="mono">${escapeHtml(ipAddresses)}</small>` : ''}</td>
        <td>${escapeHtml(client.clientVersion)}</td>
        <td>${escapeHtml(os.caption)}<small class="mono">${escapeHtml(os.version)} build ${escapeHtml(os.buildNumber)}</small></td>
        <td>${escapeHtml(office.name)}<small>${escapeHtml(office.version)}</small></td>
        <td>${activationBadge(windowsActivation.activated, 'Windows')}</td>
        <td>${activationBadge(officeActivation.activated, 'Office')}</td>
        <td>${softwareCount}</td>
        <td>${formatAdDescription(client)}</td>
        <td>${escapeHtml(formatDateTime(client.collectedAt || client.sourceUpdatedAt))}</td>
        <td><button class="danger-button-ghost" type="button" data-delete-client="${escapeHtml(client.computerName)}">Delete</button></td>
      </tr>
      <tr class="details-row ${detailsHidden}" data-client-details="${clientId}">
```

- [ ] **Step 4: `renderSoftwareTable`**

Find this in `server/dashboard/app.js`:

```javascript
      const groupId = safeId(softwareKey(group));

      return `<tr>
        <td><button class="link-button" type="button" data-software="${groupId}">${escapeHtml(group.name)}</button></td>
        <td>${escapeHtml(group.version)}</td>
        <td>${escapeHtml(group.publisher)}</td>
        <td class="hw-num">${group.clients.length}</td>
        <td>${findLicenseForSoftware(group.name) ? `<button class="edit-button" type="button" data-software-license-name="${escapeHtml(group.name)}" data-software-license-version="${escapeHtml(group.version)}">License</button>` : ''}</td>
      </tr>
      <tr class="details-row hidden" data-software-details="${groupId}">
```

Replace with:

```javascript
      const groupId = safeId(softwareKey(group));
      const detailsHidden = state.expandedDetails.has('software:' + groupId) ? '' : 'hidden';

      return `<tr>
        <td><button class="link-button" type="button" data-software="${groupId}">${escapeHtml(group.name)}</button></td>
        <td>${escapeHtml(group.version)}</td>
        <td>${escapeHtml(group.publisher)}</td>
        <td class="hw-num">${group.clients.length}</td>
        <td>${findLicenseForSoftware(group.name) ? `<button class="edit-button" type="button" data-software-license-name="${escapeHtml(group.name)}" data-software-license-version="${escapeHtml(group.version)}">License</button>` : ''}</td>
      </tr>
      <tr class="details-row ${detailsHidden}" data-software-details="${groupId}">
```

- [ ] **Step 5: `renderHardwarePage` - all three sub-tables (CPU/Storage/RAM)**

Find this in `server/dashboard/app.js`:

```javascript
        const id = safeId('cpu:' + g.name);
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        const clock = g.clockMhz ? `${(g.clockMhz / 1000).toFixed(2)} GHz` : 'Unknown';
        return `<tr>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.name)}</button></td>
          <td class="hw-num">${g.cores != null ? g.cores : 'Unknown'}</td>
          <td class="hw-num">${escapeHtml(clock)}</td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row hidden" data-hw-details="${id}">
```

Replace with:

```javascript
        const id = safeId('cpu:' + g.name);
        const detailsHidden = state.expandedDetails.has('hw:' + id) ? '' : 'hidden';
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        const clock = g.clockMhz ? `${(g.clockMhz / 1000).toFixed(2)} GHz` : 'Unknown';
        return `<tr>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.name)}</button></td>
          <td class="hw-num">${g.cores != null ? g.cores : 'Unknown'}</td>
          <td class="hw-num">${escapeHtml(clock)}</td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row ${detailsHidden}" data-hw-details="${id}">
```

Find this:

```javascript
        const id = safeId('disk:' + g.model + g.sizeGb);
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        const usbBadge = g.usb ? ' <span class="usb-badge">USB</span>' : '';
        const size = g.sizeGb ? `${g.sizeGb} GB` : 'Unknown';
        return `<tr${g.usb ? ' class="usb-row"' : ''}>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.model)}</button>${usbBadge}</td>
          <td>${escapeHtml(g.type)}</td>
          <td class="hw-num">${escapeHtml(size)}</td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row hidden" data-hw-details="${id}">
```

Replace with:

```javascript
        const id = safeId('disk:' + g.model + g.sizeGb);
        const detailsHidden = state.expandedDetails.has('hw:' + id) ? '' : 'hidden';
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        const usbBadge = g.usb ? ' <span class="usb-badge">USB</span>' : '';
        const size = g.sizeGb ? `${g.sizeGb} GB` : 'Unknown';
        return `<tr${g.usb ? ' class="usb-row"' : ''}>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.model)}</button>${usbBadge}</td>
          <td>${escapeHtml(g.type)}</td>
          <td class="hw-num">${escapeHtml(size)}</td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row ${detailsHidden}" data-hw-details="${id}">
```

Find this:

```javascript
        const id = safeId('ram:' + g.totalMb + ':' + g.moduleCount);
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        return `<tr>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.totalGb)}</button></td>
          <td class="hw-num">${g.moduleCount || 'Unknown'}</td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row hidden" data-hw-details="${id}">
```

Replace with:

```javascript
        const id = safeId('ram:' + g.totalMb + ':' + g.moduleCount);
        const detailsHidden = state.expandedDetails.has('hw:' + id) ? '' : 'hidden';
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        return `<tr>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.totalGb)}</button></td>
          <td class="hw-num">${g.moduleCount || 'Unknown'}</td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row ${detailsHidden}" data-hw-details="${id}">
```

- [ ] **Step 6: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass (no C# touched; this confirms no Cyrillic/encoding issue was introduced in `app.js`).

- [ ] **Step 7: Live-verify with Playwright**

Start the server against a fixture directory with at least 25 synthetic client JSON files (enough to force pagination past one page - reuse the fixture pattern from the Inventory Views UX plan: distinct `computerName` per client, matching the field names `app.js` reads). Remember `--content ./server/dashboard` on the server's `--console` command (the default `ContentPath` can hold a stale dashboard copy on this machine, a gotcha discovered earlier this session).

With Playwright MCP tools:
1. Navigate to `#clients`. Expand one client's details row (click its name).
2. Click the pager's "Next" button, then "Prev" to return to the original page.
3. Confirm the previously-expanded row is STILL expanded (this is the direct, demonstrable fix - today this row would have silently collapsed).
4. Repeat for `#software` and `#hardware` (expand a row in one of the three hw sub-tables), confirming the same behavior.

Clean up the server process and scratch fixture directory afterward.

- [ ] **Step 8: Commit**

```bash
git add server/dashboard/app.js
git commit -m "Make expanded detail rows survive any table re-render"
```

---

### Task 2: 30-second background poll with change detection and visibility pause

**Files:**
- Modify: `server/dashboard/app.js`
- Modify: `server/dashboard/styles.css`

**Interfaces:**
- Consumes: `state.expandedDetails` (Task 1, unchanged) - the poll's `render()` call relies on Task 1 already being in place so a background refresh doesn't collapse open detail rows.
- Produces: `computeClientsFingerprint`, `pollForUpdates`, `startPolling`, `stopPolling`, `flashGeneratedAt` - Task 3's live verification exercises these directly; no other task depends on their signatures.

- [ ] **Step 1: Add the polling functions**

Find this in `server/dashboard/app.js` (the end of `recalculateActivePagination`, immediately before the initial `fetch` call):

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

  fetch('/api/v1/clients', { cache: 'no-store' })
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

  let lastClientsFingerprint = null;
  let pollTimer = null;

  // A cheap "did anything meaningful change" signal: each client's name
  // and most recent report timestamp, sorted for a stable order
  // regardless of how the server orders its response. Deliberately not a
  // full JSON diff of every field (software lists, hardware specs, etc.)
  // - a new/removed client or an updated report timestamp is what "new
  // data arrived" means here, and that's cheap to compute on every poll
  // tick. Not based on the server's own generatedAt field, which is the
  // HTTP response's build time (DateTime.UtcNow on every call, server
  // side), not the data's time - it differs on every poll regardless of
  // whether anything changed.
  function computeClientsFingerprint(clients) {
    return clients
      .map(c => (c.computerName || '') + '|' + (c.collectedAt || c.sourceUpdatedAt || ''))
      .sort()
      .join(';');
  }

  // Briefly highlights the "Generated: ..." timestamp so an attentive
  // user notices a background poll just brought in new data - no toast,
  // no layout shift, nothing that steals focus.
  function flashGeneratedAt() {
    const el = byId('generatedAt');
    el.classList.add('generated-at-flash');
    window.setTimeout(() => el.classList.remove('generated-at-flash'), 1000);
  }

  // Re-fetches the same endpoint the initial page load uses. Skips all
  // render work entirely when the fingerprint is unchanged, so a no-op
  // poll tick costs one small GET request and nothing else. A failed poll
  // (network hiccup, a brief server restart) is silent by design - only
  // the initial page-load fetch shows an error banner; a background poll
  // just retries next tick.
  function pollForUpdates() {
    fetch('/api/v1/clients', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        const fingerprint = computeClientsFingerprint(data.clients || []);
        if (fingerprint === lastClientsFingerprint) return;
        lastClientsFingerprint = fingerprint;
        state.clients = data.clients || [];
        state.staleHours = data.staleHours || 48;
        byId('generatedAt').textContent = `Generated: ${formatDateTime(data.generatedAt)}`;
        byId('serverVersionBadge').textContent = `Server: v${text(data.serverVersion)}`;
        render();
        flashGeneratedAt();
      })
      .catch(() => {
        // Silent - see function comment above.
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

  fetch('/api/v1/clients', { cache: 'no-store' })
```

- [ ] **Step 2: Set the initial fingerprint and start polling after the first load settles**

Find this in `server/dashboard/app.js`:

```javascript
    .then(data => {
      state.clients = data.clients || [];
      state.staleHours = data.staleHours || 48;
      byId('generatedAt').textContent = `Generated: ${formatDateTime(data.generatedAt)}`;
      byId('serverVersionBadge').textContent = `Server: v${text(data.serverVersion)}`;
      render();
    })
    .catch(error => {
      byId('generatedAt').textContent = `Inventory index is not available: ${error.message}`;
      render();
    });

  loadLicenses();
```

Replace with:

```javascript
    .then(data => {
      state.clients = data.clients || [];
      state.staleHours = data.staleHours || 48;
      lastClientsFingerprint = computeClientsFingerprint(state.clients);
      byId('generatedAt').textContent = `Generated: ${formatDateTime(data.generatedAt)}`;
      byId('serverVersionBadge').textContent = `Server: v${text(data.serverVersion)}`;
      render();
    })
    .catch(error => {
      byId('generatedAt').textContent = `Inventory index is not available: ${error.message}`;
      render();
    })
    .finally(() => {
      // Start polling whether the initial load succeeded or failed - if
      // the server was only briefly unavailable when the page opened, the
      // first successful poll recovers automatically instead of leaving
      // the user stuck on the error message until they manually reload.
      startPolling();
    });

  loadLicenses();
```

- [ ] **Step 3: Add the flash CSS**

Find this in `server/dashboard/styles.css`:

```css
.sidebar-footer #generatedAt {
  font-size: 11px;
}
```

Replace with:

```css
.sidebar-footer #generatedAt {
  font-size: 11px;
  transition: color 0.3s ease;
}

.generated-at-flash {
  color: var(--accent);
}
```

- [ ] **Step 4: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 5: Live-verify with Playwright**

Start the server against a scratch fixture directory (`--content ./server/dashboard`, a handful of synthetic clients is enough). With Playwright MCP tools:

1. Load the dashboard, note the "Generated: ..." text. Confirm no visible change for at least 35 seconds with no data change on disk (proves the fingerprint-match skip works - use `browser_network_requests` to confirm polls ARE firing every ~30s, but no re-render/flash happens since nothing changed).
2. While the page is still open, edit one synthetic client's JSON file on disk to advance its `collectedAt` timestamp (simulating a new inventory report). Wait up to 35 seconds.
3. Confirm: the dashboard's data updates (the edited field is visibly different), the "Generated: ..." text updates, and the `.generated-at-flash` class briefly appears then is removed (check via `browser_evaluate` or a quick snapshot timed right after the update).
4. Simulate the tab going hidden (Playwright can dispatch a `visibilitychange` event or use `browser_evaluate` to set `document.visibilityState` - use whichever the available Playwright MCP tools support most directly) and confirm no further `/api/v1/clients` requests fire while hidden (via `browser_network_requests`). Simulate becoming visible again and confirm one immediate request fires without waiting for the next 30-second tick.
5. Stop the server process temporarily (simulating an outage), confirm no error banner appears and the currently-displayed data is undisturbed, then restart the server and confirm polling recovers on its own within one interval.

Clean up the server process and scratch fixture directory afterward.

- [ ] **Step 6: Commit**

```bash
git add server/dashboard/app.js server/dashboard/styles.css
git commit -m "Add 30-second background poll to keep the dashboard current"
```

---

### Task 3: Combined final verification, version bump, CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `src/server/WindowsInventoryLiteServer.cs` (`Program.ProductVersion`)
- Modify: `src/client/WindowsInventoryLiteClient.cs` (`Program.ProductVersion`)

- [ ] **Step 1: Confirm the current version and bump it**

Run: `grep -n "ProductVersion = " src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs`
Confirm the current value (expected `"0.14.0"` as of this plan's writing - if different, use the real current value and bump a MINOR version from there instead). Update both files to the next MINOR version (patch reset to 0), identical value in both.

- [ ] **Step 2: Add the CHANGELOG entry**

Add a new `## [<new-version>] - 2026-07-17` section at the top of `CHANGELOG.md`, after `## [Unreleased]`:

```markdown
### Added

- The dashboard now polls for new inventory data every 30 seconds and updates in place, without disturbing the current page, sort, search, or any expanded detail rows. Polling pauses while the browser tab isn't visible and catches up immediately when it becomes visible again.

### Fixed

- Expanded detail rows (Clients/Software/Hardware "show details") no longer collapse when the table re-renders for an unrelated reason (e.g. clicking the pager's Next/Prev buttons).
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

Expected: all three builds succeed, self-test all `PASS` exit code 0 (this plan touches no C# code, so the count should be unchanged from before this task), Pester all green, printed version matches the new bumped value.

- [ ] **Step 4: Final combined live verification**

Using a fixture with 25+ synthetic clients (enough to paginate), in one Playwright session:
1. Load `#clients`, sort by a column, search for a substring, navigate to page 2, expand one row's details.
2. Edit a synthetic client's JSON file on disk to trigger a poll-detected change. Wait up to 35 seconds.
3. Confirm ALL of the following survived the background refresh simultaneously: current sort order, the search filter, the current page number, and the expanded row's visible state - this is the actual point of the whole plan, verified as one combined scenario rather than only individually per task.

Clean up the server process and scratch fixture directory afterward.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs
git commit -m "Bump version for Dashboard Live Auto-Refresh"
```
