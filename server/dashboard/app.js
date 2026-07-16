(function () {
  const inventoryViews = ['clients', 'software', 'hardware'];
  const state = {
    clients: [], view: getInitialView(), installJobId: null, installPollTimer: null, installJobs: [],
    packageStatus: null,
    certificateStatus: null, certificateHistory: [],
    staleHours: 48,
    licenses: [], editingLicenseId: null, licenseFormComputers: [],
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

  function byId(id) {
    return document.getElementById(id);
  }

  function currentTheme() {
    const explicit = document.documentElement.getAttribute('data-theme');
    if (explicit === 'light' || explicit === 'dark') return explicit;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function updateThemeToggle() {
    const button = byId('themeToggle');
    if (!button) return;
    const isDark = currentTheme() === 'dark';
    // Icon shown is the theme a click switches TO, not the active one.
    button.innerHTML = isDark ? '&#9728;' : '&#9790;';
    button.title = isDark ? 'Switch to light theme' : 'Switch to dark theme';
    button.setAttribute('aria-label', button.title);
  }

  function toggleTheme() {
    const next = currentTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('wil-theme', next);
    updateThemeToggle();
  }

  function getInitialView() {
    const hash = window.location.hash.replace(/^#/, '').toLowerCase();
    if (hash === 'clients') return 'clients';
    if (hash === 'software') return 'software';
    if (hash === 'hardware') return 'hardware';
    if (hash === 'client-actions' || hash === 'actions' || hash === 'install') return 'install';
    if (hash === 'client-package' || hash === 'package') return 'package';
    if (hash === 'general') return 'general';
    if (hash === 'certificate') return 'certificate';
    if (hash === 'licenses') return 'licenses';
    if (hash === 'admin-password' || hash === 'admin') return 'admin';
    return 'dashboard';
  }

  function setView(view) {
    state.view = view;
    const hash = view === 'install' ? 'client-actions' : view === 'package' ? 'client-package' : view === 'admin' ? 'admin-password' : view;
    if (window.location.hash.replace(/^#/, '') !== hash) {
      window.location.hash = hash;
      return;
    }
    render();
    if (view === 'install') loadInstallHistory();
    if (view === 'package') loadPackageStatus();
    if (view === 'general') loadGeneralSettings();
    if (view === 'certificate') { loadCertificateStatus(); loadCertificateHistory(); }
    if (view === 'licenses') loadLicenses();
    if (view === 'admin') loadAdminPasswordStatus();
  }

  function text(value) {
    return value === undefined || value === null || value === '' ? 'Unknown' : String(value);
  }

  function activated(value) {
    return value ? 'Activated' : 'Not detected';
  }

  // Shared by activationBadge and setStatusDot - both draw the same
  // checkmark dot for an "on" state, reusing the mark from the project logo.
  const CHECK_DOT_SVG = '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 10.5 L8.5 14 L15 6.5"/></svg>';

  // Compact on/off indicator for the Clients table (Windows/Office
  // activation): a checkmark dot reusing the same mark as the app's own
  // logo, or a muted dash. Replaces two "Activated"/"Not detected" text
  // cells that wrapped awkwardly at typical column widths.
  function activationBadge(isActivated, label) {
    const text = `${label}: ${activated(isActivated)}`;
    const icon = isActivated ? CHECK_DOT_SVG : '';
    return `<span class="status-dot ${isActivated ? 'status-dot-on' : 'status-dot-off'}" role="img" aria-label="${escapeHtml(text)}" title="${escapeHtml(text)}">${icon}</span>`;
  }

  // AD Description column for the Clients table. `<small>` already renders
  // muted (see the site-wide `small { color: var(--muted) }` rule), so the
  // placeholder strings need no extra styling class.
  function formatAdDescription(client) {
    if (client.adSyncStatus === 'not-found') {
      return '<small>Not found in AD</small>';
    }
    if (client.adSyncStatus === 'error') {
      return '<small>AD unreachable</small>';
    }
    if (client.adDescription) {
      return escapeHtml(client.adDescription);
    }
    return '';
  }

  function formatDateTime(value) {
    if (!value) return 'Unknown';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return text(value);
    return date.toLocaleString();
  }

  // Older clients (not yet rebuilt/redeployed) still report installDate as the
  // raw 8-digit YYYYMMDD registry value instead of a formatted date. Reformat
  // it here too so existing reports display correctly without waiting for
  // every agent in the fleet to be updated. Anything that isn't exactly 8
  // digits (including an already-formatted dd.MM.yyyy value) passes through.
  function formatInstallDate(raw) {
    if (!raw || !/^\d{8}$/.test(raw)) return raw;
    const year = raw.slice(0, 4);
    const month = Number(raw.slice(4, 6));
    const day = Number(raw.slice(6, 8));
    if (month < 1 || month > 12 || day < 1 || day > 31) return raw;
    return `${String(day).padStart(2, '0')}.${String(month).padStart(2, '0')}.${year}`;
  }

  function formatIpAddresses(client) {
    const addresses = client.ipAddresses || [];
    if (!Array.isArray(addresses) || addresses.length === 0) return '';
    return addresses.join(', ');
  }

  function escapeHtml(value) {
    return text(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Same escaping as escapeHtml, but empty/missing values stay empty instead
  // of becoming "Unknown". Used for free-form license fields where a blank
  // cell is the correct representation of "not entered".
  function escapeHtmlOrEmpty(value) {
    const str = value === undefined || value === null ? '' : String(value);
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function isStale(client) {
    const date = new Date(client.collectedAt || client.sourceUpdatedAt || 0);
    return Number.isNaN(date.getTime()) || ((Date.now() - date.getTime()) / 36e5) > state.staleHours;
  }

  function clientMatches(client, query) {
    if (!query) return true;
    const software = (client.software || []).map(item => `${item.name} ${item.version}`).join(' ');
    const disks = (client.disks || []).map(d => `${d.model} ${d.type}`).join(' ');
    const haystack = [
      client.computerName,
      client.clientVersion,
      client.domain,
      formatIpAddresses(client),
      client.os && client.os.caption,
      client.os && client.os.version,
      client.office && client.office.name,
      client.office && client.office.version,
      client.cpu && client.cpu.name,
      software,
      disks
    ].join(' ').toLowerCase();
    return haystack.indexOf(query.toLowerCase()) !== -1;
  }

  function safeId(value) {
    let hash = 0;
    const source = String(value);
    for (let index = 0; index < source.length; index += 1) {
      hash = ((hash << 5) - hash) + source.charCodeAt(index);
      hash |= 0;
    }
    return `id-${Math.abs(hash)}`;
  }

  function softwareKey(item) {
    return [item.name || '', item.version || '', item.publisher || ''].join('\u001f').toLowerCase();
  }

  function applySort(arr, valueFn, dir) {
    return arr.slice().sort((a, b) => {
      const av = valueFn(a);
      const bv = valueFn(b);
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av).localeCompare(String(bv), undefined, { sensitivity: 'base' }) * dir;
    });
  }

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

  function clientSortValue(client, key) {
    switch (key) {
      case 'computerName': return (client.computerName || '').toLowerCase();
      case 'clientVersion': return client.clientVersion || '';
      case 'os': return ((client.os && client.os.caption) || '').toLowerCase();
      case 'office': return ((client.office && client.office.name) || '').toLowerCase();
      case 'windowsActivated': return (client.activation && client.activation.windows && client.activation.windows.activated) ? 1 : 0;
      case 'officeActivated': return (client.activation && client.activation.office && client.activation.office.activated) ? 1 : 0;
      case 'softwareCount': return (client.software || []).length;
      case 'collectedAt': return new Date(client.collectedAt || client.sourceUpdatedAt || 0).getTime();
      default: return '';
    }
  }

  function softwareSortValue(group, key) {
    switch (key) {
      case 'name': return (group.name || '').toLowerCase();
      case 'version': return group.version || '';
      case 'publisher': return (group.publisher || '').toLowerCase();
      case 'count': return group.clients.length;
      default: return '';
    }
  }

  function cpuSortValue(g, key) {
    switch (key) {
      case 'name': return (g.name || '').toLowerCase();
      case 'cores': return g.cores || 0;
      case 'clockMhz': return g.clockMhz || 0;
      case 'count': return g.clients.length;
      default: return '';
    }
  }

  function diskSortValue(g, key) {
    switch (key) {
      case 'model': return (g.model || '').toLowerCase();
      case 'type': return (g.type || '').toLowerCase();
      case 'sizeGb': return g.sizeGb || 0;
      case 'count': return g.clients.length;
      default: return '';
    }
  }

  function ramSortValue(g, key) {
    switch (key) {
      case 'totalMb': return g.totalMb || 0;
      case 'moduleCount': return g.moduleCount || 0;
      case 'count': return g.clients.length;
      default: return '';
    }
  }

  function licenseSortValue(license, key) {
    switch (key) {
      case 'name': return (license.name || '').toLowerCase();
      case 'version': return (license.version || '').toLowerCase();
      case 'license': return (license.license || '').toLowerCase();
      case 'comment': return (license.comment || '').toLowerCase();
      default: return '';
    }
  }

  function renderSortHeaders() {
    document.querySelectorAll('th[data-sort-key]').forEach(th => {
      const table = th.dataset.sortTable;
      const key = th.dataset.sortKey;
      const current = state.sort[table];
      th.classList.remove('sort-asc', 'sort-desc');
      if (current && current.key === key) {
        th.classList.add(current.dir === 1 ? 'sort-asc' : 'sort-desc');
      }
    });
  }

  // Exported fields (computer names, software titles, license comments, ...)
  // come from client-reported inventory or free-text admin input, not from a
  // fixed set of safe values. A cell starting with =, +, -, or @ is treated
  // as a formula by Excel/Sheets when the file is opened (the classic
  // CSV/formula injection class, CWE-1236). A leading single quote is the
  // standard mitigation: spreadsheet apps treat it as a "this is text" hint
  // and do not display it, so the visible value is unchanged.
  function sanitizeCsvCell(value) {
    return /^[=+\-@]/.test(value) ? "'" + value : value;
  }

  function downloadCsv(filename, rows) {
    const csv = rows.map(row =>
      row.map(cell => {
        const s = sanitizeCsvCell(String(cell == null ? '' : cell));
        return /[";,\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      }).join(';')
    ).join('\r\n');
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function csvDate() {
    return new Date().toISOString().slice(0, 10);
  }

  function exportClients() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.clients;
    const items = applySort(state.clients.filter(c => clientMatches(c, query)), c => clientSortValue(c, sortKey), sortDir);
    const rows = [['Computer', 'Domain', 'IP Addresses', 'Client Version', 'OS', 'OS Version', 'Build', 'Office', 'Office Version', 'Windows Activated', 'Office Activated', 'Software Count', 'Collected', 'Stale', 'CPU', 'RAM', 'Disks', 'USB Storage', 'AD Description']].concat(
      items.map(c => {
        const os = c.os || {};
        const office = c.office || {};
        const activation = c.activation || {};
        const winAct = activation.windows || {};
        const officeAct = activation.office || {};
        const cpu = c.cpu || {};
        const ramText = c.ramTotalMb ? (c.ramTotalMb >= 1024 ? Math.round(c.ramTotalMb / 1024) + ' GB' : c.ramTotalMb + ' MB') : '';
        const disksText = (c.disks || []).map(d => (d.type || '') + ' ' + (d.sizeGb ? d.sizeGb + ' GB' : '') + ' ' + (d.model || '')).join(', ').trim();
        return [
          c.computerName || '', c.domain || '', formatIpAddresses(c), c.clientVersion ? 'v' + c.clientVersion : '',
          os.caption || '', os.version || '', os.buildNumber || '',
          office.name || '', office.version || '',
          winAct.activated ? 'Yes' : 'No', officeAct.activated ? 'Yes' : 'No',
          (c.software || []).length, formatDateTime(c.collectedAt || c.sourceUpdatedAt),
          isStale(c) ? 'Yes' : 'No', cpu.name || '', ramText, disksText,
          c.hasUsbStorage ? 'Yes' : 'No',
          c.adSyncStatus === 'not-found' ? 'Not found in AD' : c.adSyncStatus === 'error' ? 'AD unreachable' : (c.adDescription || '')
        ];
      })
    );
    downloadCsv('clients-' + csvDate() + '.csv', rows);
  }

  function exportSoftware() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.software;
    const groups = applySort(getSoftwareGroups(state.clients).filter(g => softwareMatches(g, query)), g => softwareSortValue(g, sortKey), sortDir);
    const rows = [['Software', 'Version', 'Publisher', 'Installations', 'Computers']].concat(
      groups.map(g => [g.name, g.version, g.publisher, g.clients.length, g.clients.map(c => c.computerName).join(', ')])
    );
    downloadCsv('software-' + csvDate() + '.csv', rows);
  }

  function exportHardwareCpu() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.hwCpu;
    const groups = applySort(
      getCpuGroups(state.clients).filter(g => hwMatches([g.name].concat(g.clients.map(c => c.computerName)).join(' '), query)),
      g => cpuSortValue(g, sortKey), sortDir
    );
    const rows = [['Model', 'Cores', 'Clock GHz', 'Machines', 'Computers']].concat(
      groups.map(g => [g.name, g.cores != null ? g.cores : '', g.clockMhz ? (g.clockMhz / 1000).toFixed(2) + ' GHz' : '', g.clients.length, g.clients.map(c => c.computerName).join(', ')])
    );
    downloadCsv('hardware-cpu-' + csvDate() + '.csv', rows);
  }

  function exportHardwareDisk() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.hwDisk;
    const groups = applySort(
      getDiskGroups(state.clients).filter(g => hwMatches([g.model, g.type].concat(g.clients.map(c => c.computerName)).join(' '), query)),
      g => diskSortValue(g, sortKey), sortDir
    );
    const rows = [['Model', 'Type', 'Size GB', 'USB', 'Machines', 'Computers']].concat(
      groups.map(g => [g.model, g.type, g.sizeGb || '', g.usb ? 'Yes' : 'No', g.clients.length, g.clients.map(c => c.computerName).join(', ')])
    );
    downloadCsv('hardware-storage-' + csvDate() + '.csv', rows);
  }

  function exportHardwareRam() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.hwRam;
    const groups = applySort(
      getRamGroups(state.clients).filter(g => hwMatches([g.totalGb].concat(g.clients.map(c => c.computerName)).join(' '), query)),
      g => ramSortValue(g, sortKey), sortDir
    );
    const rows = [['Total RAM', 'Modules', 'Machines', 'Computers']].concat(
      groups.map(g => [g.totalGb, g.moduleCount || '', g.clients.length, g.clients.map(c => c.computerName).join(', ')])
    );
    downloadCsv('hardware-ram-' + csvDate() + '.csv', rows);
  }

  function exportLicenses() {
    const { key: sortKey, dir: sortDir } = state.sort.licenses;
    const items = applySort(state.licenses, l => licenseSortValue(l, sortKey), sortDir);
    const rows = [['Name', 'Version', 'License', 'Comment', 'Computers']].concat(
      items.map(l => [l.name || '', l.version || '', l.license || '', l.comment || '', (l.computers || []).join(', ')])
    );
    downloadCsv('licenses-' + csvDate() + '.csv', rows);
  }

  function getClientSoftware(client) {
    const seen = new Set();
    const result = [];
    (client.software || []).forEach(item => {
      const key = softwareKey(item);
      if (!seen.has(key)) {
        seen.add(key);
        result.push(item);
      }
    });
    return result;
  }

  function deleteClient(computerName) {
    if (!computerName) return;
    const confirmed = window.confirm(`Delete ${computerName} from the inventory dashboard?`);
    if (!confirmed) return;

    fetch(`/api/v1/clients/${encodeURIComponent(computerName)}`, {
      method: 'DELETE',
      cache: 'no-store'
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        state.clients = state.clients.filter(client => client.computerName !== computerName);
        byId('generatedAt').textContent = `Updated: ${formatDateTime(new Date().toISOString())}`;
        render();
      })
      .catch(error => {
        window.alert(`Failed to delete ${computerName}: ${error.message}`);
      });
  }

  function renderInstallJob(job) {
    const results = job.results || [];
    const rows = results.map(result => `<tr>
      <td>${escapeHtml(result.target)}</td>
      <td>${escapeHtml(result.status)}</td>
      <td>${escapeHtml(result.message)}</td>
      <td><pre class="install-output">${escapeHtml((result.error || result.output || '').trim())}</pre></td>
    </tr>`).join('');

    byId('installStatus').classList.remove('empty');
    byId('installStatus').innerHTML = `<div class="job-header">
        <strong>Job ${escapeHtml(job.id)}</strong>
        <span>${escapeHtml(job.action || 'install')}</span>
        <span>${escapeHtml(job.status)}</span>
      </div>
      <div class="install-results">
        <table class="nested-table install-results-table">
          <thead><tr><th>Target</th><th>Status</th><th>Message</th><th>Output</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="4" class="empty">Waiting for results.</td></tr>'}</tbody>
        </table>
      </div>`;
  }

  function renderInstallHistory() {
    const jobs = state.installJobs || [];
    if (jobs.length === 0) {
      byId('installHistory').classList.add('empty');
      byId('installHistory').textContent = 'No saved client action logs.';
      return;
    }

    const rows = jobs.map(job => `<tr>
      <td><button class="link-button" type="button" data-install-job="${escapeHtml(job.id)}">${escapeHtml(job.id)}</button></td>
      <td>${escapeHtml(job.action || 'install')}</td>
      <td>${escapeHtml(job.status)}</td>
      <td>${escapeHtml(formatDateTime(job.createdAt))}</td>
      <td>${escapeHtml(formatDateTime(job.completedAt))}</td>
      <td>${escapeHtml(job.targetCount)}</td>
      <td>${escapeHtml(job.failedCount)}</td>
      <td>${escapeHtml(job.retentionDays)}</td>
    </tr>`).join('');

    byId('installHistory').classList.remove('empty');
    byId('installHistory').innerHTML = `<h2>Saved client action logs</h2>
      <div class="install-history-results">
        <table class="nested-table install-history-table">
          <thead><tr><th>Job</th><th>Action</th><th>Status</th><th>Started</th><th>Completed</th><th>Targets</th><th>Failed</th><th>Retention</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;

    document.querySelectorAll('[data-install-job]').forEach(button => {
      button.addEventListener('click', () => {
        state.installJobId = button.dataset.installJob;
        pollInstallJob(state.installJobId);
      });
    });
  }

  function loadInstallHistory() {
    fetch('/api/v1/client-install', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.installJobs = data.jobs || [];
        if (data.defaultRetentionDays && byId('installRetentionDays')) {
          byId('installRetentionDays').value = data.defaultRetentionDays;
        }
        renderInstallHistory();
      })
      .catch(error => {
        byId('installHistory').classList.add('empty');
        byId('installHistory').textContent = `Saved client action logs are not available: ${error.message}`;
      });
  }

  function pollInstallJob(jobId) {
    fetch(`/api/v1/client-install/${encodeURIComponent(jobId)}`, { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(job => {
        renderInstallJob(job);
        if (job.status === 'completed' && state.installPollTimer) {
          window.clearInterval(state.installPollTimer);
          state.installPollTimer = null;
          loadInstallHistory();
        }
      })
      .catch(error => {
        byId('installStatus').textContent = `Install job status is not available: ${error.message}`;
      });
  }

  function updateClientActionUi() {
    const action = byId('clientAction').value;
    const isInstall = action === 'install';
    document.querySelectorAll('.install-only').forEach(element => {
      element.classList.toggle('hidden', !isInstall);
    });
    byId('installButton').textContent = isInstall ? 'Install client' : 'Uninstall client';
  }

  function startClientActionJob() {
    const action = byId('clientAction').value;
    const targets = byId('installTargets').value.trim();
    const serverUrl = byId('installServerUrl').value.trim();
    const username = byId('installUsername').value.trim();
    const password = byId('installPassword').value;
    const force = byId('installForce').checked;
    const addToTrustedHosts = byId('installTrustedHosts').checked;
    const retentionDays = Number.parseInt(byId('installRetentionDays').value, 10) || 30;
    if (!targets) {
      window.alert('Enter at least one target.');
      return;
    }
    if (action === 'install' && !serverUrl) {
      window.alert('Enter server URL.');
      return;
    }

    if (action === 'uninstall') {
      const confirmed = window.confirm('Uninstall the client service from the selected targets?');
      if (!confirmed) return;
    }

    byId('installButton').disabled = true;
    byId('installStatus').classList.add('empty');
    byId('installStatus').textContent = `Starting ${action} job...`;

    fetch(action === 'uninstall' ? '/api/v1/client-uninstall' : '/api/v1/client-install', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets, serverUrl, username, password, force, addToTrustedHosts, retentionDays })
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.installJobId = data.jobId;
        if (state.installPollTimer) window.clearInterval(state.installPollTimer);
        pollInstallJob(state.installJobId);
        state.installPollTimer = window.setInterval(() => pollInstallJob(state.installJobId), 3000);
      })
      .catch(error => {
        byId('installStatus').textContent = `Failed to start ${action} job: ${error.message}`;
      })
      .finally(() => {
        byId('installButton').disabled = false;
      });
  }

  function loadPackageStatus() {
    fetch('/api/v1/client-package', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.packageStatus = data;
        renderPackageStatus(data);
        if (data.cmdServerUrl) byId('pkgServerUrl').value = data.cmdServerUrl;
        if (data.cmdIntervalHours) byId('pkgIntervalHours').value = data.cmdIntervalHours;
        if (data.cmdToken) byId('pkgToken').value = data.cmdToken;
        byId('pkgSharePath').value = data.cmdPackageSharePath || '';
      })
      .catch(error => {
        byId('pkgStatus').textContent = `Package status unavailable: ${error.message}`;
      });
  }

  function renderPackageStatus(data) {
    const parts = [];
    const versionPart = (label, present, version, mismatch) => {
      if (!present) return null;
      const text = `${label}: v${escapeHtml(version || 'unknown')}`;
      return mismatch ? `<span class="pkg-status-warning" title="Server is v${escapeHtml(data.serverVersion)} - rebuild the server or run New-ClientGpoPackage.ps1 to refresh this package">${text} (outdated)</span>` : text;
    };
    const net35Part = versionPart('Net 3.5', data.net35Present, data.net35Version, data.net35VersionMismatch);
    const net40Part = versionPart('Net 4.0', data.net40Present, data.net40Version, data.net40VersionMismatch);
    if (net35Part) parts.push(net35Part);
    if (net40Part) parts.push(net40Part);
    if (!data.net35Present && !data.net40Present) parts.push('No client executables in package');
    if (!data.deployScriptPresent) parts.push('Deploy script missing');
    if (data.cmdServerUrl) parts.push('URL: ' + escapeHtml(data.cmdServerUrl));
    if (data.cmdPackageSharePath) parts.push('Share: ' + escapeHtml(data.cmdPackageSharePath));
    byId('pkgStatus').innerHTML = parts.join(' &nbsp;&middot;&nbsp; ');
  }

  function savePackageConfig() {
    const serverUrl = byId('pkgServerUrl').value.trim();
    const token = byId('pkgToken').value.trim();
    const intervalHours = parseInt(byId('pkgIntervalHours').value, 10) || 6;
    const packageSharePath = byId('pkgSharePath').value.trim();
    if (!serverUrl) { window.alert('Enter server URL.'); return; }

    byId('pkgSaveButton').disabled = true;
    byId('pkgMessage').className = 'pkg-message hidden';

    fetch('/api/v1/client-package/configure', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serverUrl, token, intervalHours, packageSharePath })
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.packageStatus = data;
        renderPackageStatus(data);
        showPkgMessage('Configuration saved.', false);
      })
      .catch(error => {
        showPkgMessage(`Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('pkgSaveButton').disabled = false;
      });
  }

  function showPkgMessage(msg, isError) {
    const el = byId('pkgMessage');
    el.textContent = msg;
    el.className = 'pkg-message' + (isError ? ' error' : '');
  }

  function loadCertificateStatus() {
    fetch('/api/v1/server/certificate', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.certificateStatus = data;
        renderCertificateStatus(data);
      })
      .catch(error => {
        byId('certStatus').textContent = `Certificate status unavailable: ${error.message}`;
      });
  }

  function renderCertificateStatus(data) {
    byId('certDeleteButton').classList.toggle('hidden', !data.certificatePresent);
    if (!data.certificatePresent) {
      byId('certStatus').textContent = 'No certificate configured yet.';
      return;
    }
    const risks = data.risks || [];
    const parts = [
      data.useHttps ? 'HTTPS: enabled' : 'HTTPS: disabled (configured but not active - turn on in Settings > General)',
      'Subject: ' + escapeHtml(data.subject || 'Unknown'),
      'Expires: ' + escapeHtml(formatDateTime(data.notAfter)),
      data.isExpired ? '<span class="usb-badge">EXPIRED</span>' : '',
      risks.length ? `<span class="usb-badge">${risks.length} RISK${risks.length > 1 ? 'S' : ''}</span>` : ''
    ].filter(Boolean);
    byId('certStatus').innerHTML = parts.join(' &nbsp;&middot;&nbsp; ');
  }

  function deleteCertificate() {
    const data = state.certificateStatus || {};
    const warning = data.useHttps
      ? 'Delete the installed certificate? HTTPS is currently using it and will be turned off immediately.'
      : 'Delete the installed certificate from the local machine store?';
    if (!window.confirm(warning)) return;

    byId('certDeleteButton').disabled = true;
    fetch('/api/v1/server/certificate', { method: 'DELETE', cache: 'no-store' })
      .then(response => response.json().then(responseData => ({ ok: response.ok, data: responseData })))
      .then(({ ok, data: responseData }) => {
        if (!ok) throw new Error(responseData.error || 'Delete failed');
        state.certificateStatus = responseData;
        renderCertificateStatus(responseData);
        showCertMessage('Certificate deleted.', false);
      })
      .catch(error => {
        showCertMessage(`Delete failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('certDeleteButton').disabled = false;
      });
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result;
        const commaIndex = result.indexOf(',');
        resolve(commaIndex >= 0 ? result.slice(commaIndex + 1) : result);
      };
      reader.onerror = () => reject(reader.error || new Error('Failed to read file'));
      reader.readAsDataURL(file);
    });
  }

  function showCertMessage(msg, isError) {
    const el = byId('certMessage');
    el.textContent = msg;
    el.className = 'pkg-message' + (isError ? ' error' : '');
  }

  function uploadCertificate() {
    const fileInput = byId('certFile');
    const file = fileInput.files && fileInput.files[0];
    const password = byId('certPassword').value;

    if (!file) {
      window.alert('Choose a .pfx or .p12 file.');
      return;
    }

    byId('certUploadButton').disabled = true;
    byId('certMessage').className = 'pkg-message hidden';

    fileToBase64(file)
      .then(pfxBase64 => fetch('/api/v1/server/certificate', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pfxBase64, password })
      }))
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Upload failed');
        state.certificateStatus = data;
        renderCertificateStatus(data);
        loadCertificateHistory();
        fileInput.value = '';
        byId('certPassword').value = '';
        const risks = data.risks || [];
        showCertMessage(
          risks.length
            ? `Certificate uploaded with ${risks.length} risk(s): ${risks.join(' ')} Enable HTTPS from Settings > General when ready.`
            : 'Certificate uploaded. Enable HTTPS from Settings > General when ready.',
          risks.length > 0
        );
      })
      .catch(error => {
        showCertMessage(`Upload failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('certUploadButton').disabled = false;
      });
  }

  function loadCertificateHistory() {
    fetch('/api/v1/server/certificate/history', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.certificateHistory = data.history || [];
        renderCertificateHistory();
      })
      .catch(error => {
        byId('certHistoryBody').innerHTML = `<tr><td colspan="6" class="empty">History unavailable: ${escapeHtml(error.message)}</td></tr>`;
      });
  }

  function renderCertificateHistory() {
    const rows = state.certificateHistory.map(entry => {
      const risks = entry.risks || [];
      // Entries logged before the delete endpoint existed have no id and
      // cannot be targeted individually.
      const deleteCell = entry.id
        ? `<button class="danger-button-ghost" type="button" data-delete-cert-history="${escapeHtml(entry.id)}">Delete</button>`
        : '—';
      return `<tr>
        <td>${escapeHtml(formatDateTime(entry.uploadedAt))}</td>
        <td>${escapeHtml(entry.subject)}</td>
        <td>${escapeHtml(formatDateTime(entry.notAfter))}</td>
        <td class="mono">${escapeHtml(entry.thumbprint)}</td>
        <td>${risks.length ? escapeHtml(risks.join(' ')) : '—'}</td>
        <td>${deleteCell}</td>
      </tr>`;
    });
    byId('certHistoryBody').innerHTML = rows.join('') || '<tr><td colspan="6" class="empty">No certificates uploaded yet.</td></tr>';

    document.querySelectorAll('[data-delete-cert-history]').forEach(button => {
      button.addEventListener('click', () => removeCertificateHistoryEntry(button.dataset.deleteCertHistory));
    });
  }

  function removeCertificateHistoryEntry(id) {
    if (!window.confirm('Delete this entry from the certificate history log? This does not affect the certificate itself.')) return;

    fetch(`/api/v1/server/certificate/history/${encodeURIComponent(id)}`, { method: 'DELETE', cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        state.certificateHistory = state.certificateHistory.filter(entry => entry.id !== id);
        renderCertificateHistory();
      })
      .catch(error => {
        window.alert(`Failed to delete history entry: ${error.message}`);
      });
  }

  function updateAdIdentityFields() {
    const useServiceIdentity = byId('generalAdUseServiceIdentity').checked;
    [byId('generalAdUsernameField'), byId('generalAdPasswordField')].forEach(field => {
      field.classList.toggle('hidden', useServiceIdentity);
    });
  }

  function loadGeneralSettings() {
    fetch('/api/v1/server/settings', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('generalStaleHours').value = data.staleHours || 48;
        byId('generalPort').value = data.port || 8080;
        byId('generalEnableHttp').checked = data.enableHttp !== false;
        byId('generalHttpsPort').value = data.httpsPort || 8443;
        byId('generalUseHttps').checked = !!data.useHttps;
        // Compared against on save to decide whether the "this will disconnect
        // you" confirmation is actually needed - staleHours/useHttps changes
        // alone don't move the port this browser is talking to.
        state.generalLoadedPort = data.port || 8080;
        state.generalLoadedEnableHttp = data.enableHttp !== false;
        const hint = byId('generalCertHint');
        if (!data.certificatePresent) {
          hint.textContent = 'No certificate uploaded yet. Upload one on the Certificate page before enabling HTTPS.';
          hint.classList.remove('hidden');
        } else if ((data.risks || []).length) {
          hint.textContent = `Configured certificate has risks: ${data.risks.join(' ')}`;
          hint.classList.remove('hidden');
        } else {
          hint.classList.add('hidden');
        }
        byId('generalAdSyncEnabled').checked = !!data.adSyncEnabled;
        byId('generalAdSyncMode').value = data.adSyncMode || 'on-report';
        byId('generalAdSyncIntervalHours').value = data.adSyncIntervalHours || 24;
        byId('generalAdDomain').value = data.adDomain || '';
        byId('generalAdUseServiceIdentity').checked = data.adUseServiceIdentity !== false;
        byId('generalAdUsername').value = data.adUsername || '';
        byId('generalAdPassword').value = '';
        updateAdIdentityFields();
        byId('generalDebugLogEnabled').checked = !!data.debugLogEnabled;
        byId('generalDebugLogPath').textContent = data.debugLogPath || '-';
        renderConnectionStatus(data);
      })
      .catch(error => {
        showGeneralMessage(`Settings unavailable: ${error.message}`, true);
      });
  }

  // General settings previously left most of the page empty below the form -
  // this reuses the same settings response to show something an admin
  // actually can't see anywhere else at a glance: is HTTP/HTTPS actually
  // reachable right now, and is the certificate backing HTTPS still good.
  function setStatusDot(dotId, detailId, isOn, detailText) {
    const dot = byId(dotId);
    dot.className = 'status-dot ' + (isOn ? 'status-dot-on' : 'status-dot-off');
    dot.innerHTML = isOn ? CHECK_DOT_SVG : '';
    byId(detailId).textContent = detailText;
  }

  function renderConnectionStatus(data) {
    const httpOn = data.enableHttp !== false;
    setStatusDot('statusHttpDot', 'statusHttpDetail', httpOn, httpOn ? `Port ${data.port}` : 'Disabled');

    const httpsOn = !!data.useHttps;
    setStatusDot('statusHttpsDot', 'statusHttpsDetail', httpsOn, httpsOn ? `Port ${data.httpsPort}` : 'Disabled');

    let certOn = false;
    let certDetail = 'Not configured';
    if (data.certificatePresent) {
      if (data.isExpired) {
        certDetail = 'Expired';
      } else if ((data.risks || []).length) {
        certDetail = `${data.risks.length} risk${data.risks.length === 1 ? '' : 's'} found`;
      } else {
        certOn = true;
        certDetail = data.notAfter ? `Valid until ${formatDateTime(data.notAfter)}` : 'Valid';
      }
    }
    setStatusDot('statusCertDot', 'statusCertDetail', certOn, certDetail);
  }

  function showGeneralMessage(msg, isError) {
    const el = byId('generalMessage');
    el.textContent = msg;
    el.className = 'pkg-message' + (isError ? ' error' : '');
  }

  function saveGeneralSettings(acknowledgeRisks, confirmedDisruption) {
    const staleHours = Number.parseInt(byId('generalStaleHours').value, 10) || 48;
    const port = Number.parseInt(byId('generalPort').value, 10) || 8080;
    const enableHttp = byId('generalEnableHttp').checked;
    const httpsPort = Number.parseInt(byId('generalHttpsPort').value, 10) || 8443;
    const useHttps = byId('generalUseHttps').checked;

    // Only the HTTP port and the Enable HTTP switch can actually move this
    // browser's own connection out from under it - staleHours/httpsPort/
    // useHttps changes don't affect whatever port this page is currently
    // talking to, so they don't need the same warning.
    const networkChanged = port !== state.generalLoadedPort || enableHttp !== state.generalLoadedEnableHttp;
    if (networkChanged && !confirmedDisruption) {
      const confirmed = window.confirm(
        'Changing the HTTP port or the "Enable HTTP" setting will disconnect this browser session immediately. '
          + 'You will need to reload the dashboard at the new address afterward. Continue?'
      );
      if (!confirmed) return;
    }

    byId('generalSaveButton').disabled = true;
    byId('generalMessage').className = 'pkg-message hidden';

    fetch('/api/v1/server/settings', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        staleHours, port, enableHttp, httpsPort, useHttps, acknowledgeRisks: !!acknowledgeRisks,
        adSyncEnabled: byId('generalAdSyncEnabled').checked,
        adSyncMode: byId('generalAdSyncMode').value,
        adSyncIntervalHours: Number.parseInt(byId('generalAdSyncIntervalHours').value, 10) || 24,
        adDomain: byId('generalAdDomain').value.trim(),
        adUseServiceIdentity: byId('generalAdUseServiceIdentity').checked,
        adUsername: byId('generalAdUsername').value.trim(),
        adPassword: byId('generalAdPassword').value,
        debugLogEnabled: byId('generalDebugLogEnabled').checked
      })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
      .then(({ ok, status, data }) => {
        if (!ok) {
          if (status === 409 && (data.risks || []).length) {
            const confirmed = window.confirm(
              `${data.error}\n\n${data.risks.join('\n')}\n\nEnable HTTPS anyway?`
            );
            if (confirmed) {
              saveGeneralSettings(true, true);
              return;
            }
            byId('generalUseHttps').checked = false;
            throw new Error('HTTPS was not enabled.');
          }
          throw new Error(data.error || 'Save failed');
        }
        state.staleHours = data.staleHours || 48;
        state.generalLoadedPort = data.port || 8080;
        state.generalLoadedEnableHttp = data.enableHttp !== false;
        renderSummary(state.clients);
        renderDashboardTiles();
        renderConnectionStatus(data);
        byId('generalAdPassword').value = '';
        showGeneralMessage('Settings saved.', false);
      })
      .catch(error => {
        showGeneralMessage(`Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('generalSaveButton').disabled = false;
      });
  }

  function showAdminPasswordMessage(msg, isError) {
    const el = byId('adminPasswordMessage');
    el.textContent = msg;
    el.className = 'pkg-message' + (isError ? ' error' : '');
  }

  function loadAdminPasswordStatus() {
    fetch('/api/v1/server/admin-password', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.adminPasswordConfigured = !!data.configured;
        byId('adminCurrentPasswordField').classList.toggle('hidden', !data.configured);
        byId('adminUsername').value = data.username || '';
        byId('adminPasswordSaveButton').textContent = data.configured ? 'Change password' : 'Set up Basic Auth';
        byId('adminPasswordStatusText').textContent = data.configured
          ? `Basic Auth is configured for user "${data.username}".`
          : 'Basic Auth is not configured yet. Set a username and password below to turn it on.';
      })
      .catch(error => {
        showAdminPasswordMessage(`Status unavailable: ${error.message}`, true);
      });
  }

  function changeAdminPassword() {
    const configured = !!state.adminPasswordConfigured;
    const newUsername = byId('adminUsername').value.trim();
    const currentPassword = byId('adminCurrentPassword').value;
    const newPassword = byId('adminNewPassword').value;
    const confirmPassword = byId('adminConfirmPassword').value;

    if (!newUsername) {
      window.alert('Enter a username.');
      return;
    }
    if (configured && !currentPassword) {
      window.alert('Enter the current password.');
      return;
    }
    if (newPassword.length < 8) {
      window.alert('New password must be at least 8 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      window.alert('New password and confirmation do not match.');
      return;
    }

    byId('adminPasswordSaveButton').disabled = true;
    byId('adminPasswordMessage').className = 'pkg-message hidden';

    fetch('/api/v1/server/admin-password', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ newUsername, currentPassword, newPassword })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Change failed');
        byId('adminCurrentPassword').value = '';
        byId('adminNewPassword').value = '';
        byId('adminConfirmPassword').value = '';
        showAdminPasswordMessage('Saved. Your browser may prompt for the new credentials on the next request.', false);
        loadAdminPasswordStatus();
      })
      .catch(error => {
        showAdminPasswordMessage(`Change failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('adminPasswordSaveButton').disabled = false;
      });
  }

  function populateSoftwareDatalists() {
    const names = new Set();
    const versionsByName = new Map();
    const allVersions = new Set();
    state.clients.forEach(client => {
      (client.software || []).forEach(item => {
        if (!item.name) return;
        names.add(item.name);
        if (item.version) {
          allVersions.add(item.version);
          const key = item.name.toLowerCase();
          if (!versionsByName.has(key)) versionsByName.set(key, new Set());
          versionsByName.get(key).add(item.version);
        }
      });
    });

    const nameList = byId('softwareNameOptions');
    nameList.innerHTML = Array.from(names).sort((a, b) => a.localeCompare(b))
      .map(name => `<option value="${escapeHtml(name)}"></option>`).join('');

    state.softwareVersionsByName = versionsByName;
    state.softwareAllVersions = allVersions;
    updateVersionDatalist();
  }

  function updateVersionDatalist() {
    const nameField = byId('licenseName');
    const versionList = byId('softwareVersionOptions');
    if (!nameField || !versionList) return;
    const key = nameField.value.trim().toLowerCase();
    const versions = (state.softwareVersionsByName && state.softwareVersionsByName.get(key)) || state.softwareAllVersions || new Set();
    versionList.innerHTML = Array.from(versions).sort((a, b) => a.localeCompare(b))
      .map(version => `<option value="${escapeHtml(version)}"></option>`).join('');
  }

  function loadLicenses() {
    fetch('/api/v1/licenses', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.licenses = data.licenses || [];
        renderLicenses();
        renderSoftwareTable(state.clients);
        renderDashboardTiles();
      })
      .catch(error => {
        byId('licensesBody').innerHTML = `<tr><td colspan="7" class="empty">Licenses are not available: ${escapeHtml(error.message)}</td></tr>`;
      });
  }

  function renderLicenses() {
    const { key: sortKey, dir: sortDir } = state.sort.licenses;
    const items = applySort(state.licenses, l => licenseSortValue(l, sortKey), sortDir);
    const rows = items.map(license => {
      const computers = license.computers || [];
      const licenseId = safeId(license.id);

      return `<tr>
      <td><button class="link-button" type="button" data-license-computers="${licenseId}">${escapeHtml(license.name)}</button></td>
      <td>${escapeHtmlOrEmpty(license.version)}</td>
      <td>${escapeHtmlOrEmpty(license.license)}</td>
      <td>${escapeHtmlOrEmpty(license.comment)}</td>
      <td>${computers.length}</td>
      <td><button class="edit-button" type="button" data-edit-license="${escapeHtml(license.id)}">Edit</button></td>
      <td><button class="danger-button-ghost" type="button" data-delete-license="${escapeHtml(license.id)}">Delete</button></td>
    </tr>
    <tr class="details-row hidden" data-license-computers-details="${licenseId}">
      <td colspan="7"><div class="details"><ul class="computer-list">${computers.map(c => `<li>${escapeHtml(c)}</li>`).join('') || '<li class="empty">No computers linked.</li>'}</ul></div></td>
    </tr>`;
    });

    byId('licensesBody').innerHTML = rows.join('') || '<tr><td colspan="7" class="empty">No license records.</td></tr>';

    document.querySelectorAll('[data-edit-license]').forEach(button => {
      button.addEventListener('click', () => openLicenseForm(button.dataset.editLicense));
    });
    document.querySelectorAll('[data-delete-license]').forEach(button => {
      button.addEventListener('click', () => removeLicense(button.dataset.deleteLicense));
    });
    document.querySelectorAll('[data-license-computers]').forEach(button => {
      button.addEventListener('click', () => {
        const row = document.querySelector(`[data-license-computers-details="${button.dataset.licenseComputers}"]`);
        if (row) row.classList.toggle('hidden');
      });
    });
  }

  function openLicenseForm(licenseId, prefill) {
    state.editingLicenseId = licenseId || null;
    const license = licenseId ? state.licenses.find(l => l.id === licenseId) : null;
    byId('licenseName').value = license ? license.name || '' : (prefill && prefill.name) || '';
    byId('licenseVersion').value = license ? license.version || '' : (prefill && prefill.version) || '';
    byId('licenseKey').value = license ? license.license || '' : '';
    byId('licenseComment').value = license ? license.comment || '' : '';
    byId('licenseComputerInput').value = '';
    state.licenseFormComputers = license ? (license.computers || []).slice() : [];
    byId('licenseMessage').className = 'pkg-message hidden';
    updateVersionDatalist();
    renderLicenseComputerChips();
    byId('licenseForm').classList.remove('hidden');
    byId('licenseName').focus();
  }

  // Matched by name only: one license record commonly covers several
  // installed versions of the same software (e.g. a volume license), so
  // requiring the version to match too would miss those on purpose.
  function findLicenseForSoftware(name) {
    const key = value => (value || '').trim().toLowerCase();
    return state.licenses.find(l => key(l.name) === key(name)) || null;
  }

  // Entry point from the Software table: jump to Licenses and open the
  // matching record for editing. Only reachable when a match already exists -
  // renderSoftwareTable only shows the License button in that case.
  function openLicenseForSoftware(name, version) {
    setView('licenses');
    fetch('/api/v1/licenses', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.licenses = data.licenses || [];
        renderLicenses();
        const existing = findLicenseForSoftware(name);
        openLicenseForm(existing ? existing.id : null, { name, version });
      })
      .catch(error => {
        window.alert(`Could not load licenses: ${error.message}`);
      });
  }

  function closeLicenseForm() {
    state.editingLicenseId = null;
    state.licenseFormComputers = [];
    byId('licenseForm').classList.add('hidden');
  }

  function renderLicenseComputerChips() {
    const list = byId('licenseComputersList');
    list.innerHTML = state.licenseFormComputers.map(name => `<li class="chip">
      ${escapeHtml(name)}
      <button type="button" data-remove-computer="${escapeHtml(name)}" aria-label="Remove ${escapeHtml(name)}">&times;</button>
    </li>`).join('');

    list.querySelectorAll('[data-remove-computer]').forEach(button => {
      button.addEventListener('click', () => removeLicenseComputer(button.dataset.removeComputer));
    });
  }

  function addLicenseComputer(name) {
    const trimmed = (name || '').trim();
    if (!trimmed) return;
    const exists = state.licenseFormComputers.some(c => c.toLowerCase() === trimmed.toLowerCase());
    if (!exists) {
      state.licenseFormComputers.push(trimmed);
      renderLicenseComputerChips();
    }
  }

  function addLicenseComputerFromInput() {
    const input = byId('licenseComputerInput');
    addLicenseComputer(input.value);
    input.value = '';
    input.focus();
  }

  function removeLicenseComputer(name) {
    state.licenseFormComputers = state.licenseFormComputers.filter(c => c !== name);
    renderLicenseComputerChips();
  }

  function getComputersForSoftwareName(name) {
    const key = (name || '').trim().toLowerCase();
    if (!key) return [];
    const computers = [];
    const seen = new Set();
    state.clients.forEach(client => {
      const matches = (client.software || []).some(item => (item.name || '').toLowerCase() === key);
      const computerKey = (client.computerName || '').toLowerCase();
      if (matches && client.computerName && !seen.has(computerKey)) {
        seen.add(computerKey);
        computers.push(client.computerName);
      }
    });
    return computers;
  }

  function applySoftwareComputers() {
    const name = byId('licenseName').value;
    getComputersForSoftwareName(name).forEach(addLicenseComputer);
  }

  function saveLicense() {
    const name = byId('licenseName').value.trim();
    const version = byId('licenseVersion').value.trim();
    const license = byId('licenseKey').value.trim();
    const comment = byId('licenseComment').value.trim();
    const computers = state.licenseFormComputers;

    if (!name) {
      window.alert('Enter a name.');
      return;
    }

    const editingId = state.editingLicenseId;
    const url = editingId ? `/api/v1/licenses/${encodeURIComponent(editingId)}` : '/api/v1/licenses';
    const method = editingId ? 'PUT' : 'POST';

    byId('licenseSaveButton').disabled = true;

    fetch(url, {
      method,
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, version, license, comment, computers })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        closeLicenseForm();
        loadLicenses();
      })
      .catch(error => {
        const el = byId('licenseMessage');
        el.textContent = `Save failed: ${error.message}`;
        el.className = 'pkg-message error';
      })
      .finally(() => {
        byId('licenseSaveButton').disabled = false;
      });
  }

  function removeLicense(licenseId) {
    const license = state.licenses.find(l => l.id === licenseId);
    const confirmed = window.confirm(`Delete license record for ${license ? license.name : 'this item'}?`);
    if (!confirmed) return;

    fetch(`/api/v1/licenses/${encodeURIComponent(licenseId)}`, { method: 'DELETE', cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        state.licenses = state.licenses.filter(l => l.id !== licenseId);
        renderLicenses();
        renderSoftwareTable(state.clients);
        renderDashboardTiles();
      })
      .catch(error => {
        window.alert(`Failed to delete license: ${error.message}`);
      });
  }

  function getSoftwareGroups(clients) {
    const groups = new Map();
    clients.forEach(client => {
      getClientSoftware(client).forEach(item => {
        const key = softwareKey(item);
        if (!groups.has(key)) {
          groups.set(key, {
            name: item.name || '',
            version: item.version || '',
            publisher: item.publisher || '',
            clients: [],
            clientKeys: new Set()
          });
        }
        const group = groups.get(key);
        const clientKey = String(client.computerName || '').toLowerCase();
        if (!group.clientKeys.has(clientKey)) {
          group.clientKeys.add(clientKey);
          group.clients.push(client);
        }
      });
    });

    return Array.from(groups.values()).sort((a, b) => {
      const nameCompare = a.name.localeCompare(b.name);
      return nameCompare || a.version.localeCompare(b.version);
    });
  }

  function getCpuGroups(clients) {
    const groups = new Map();
    clients.forEach(client => {
      const cpu = client.cpu || {};
      if (!cpu.name) return;
      const key = String(cpu.name).toLowerCase();
      if (!groups.has(key)) {
        groups.set(key, { name: cpu.name, cores: cpu.cores, clockMhz: cpu.clockMhz, clients: [], clientKeys: new Set() });
      }
      const group = groups.get(key);
      const clientKey = String(client.computerName || '').toLowerCase();
      if (!group.clientKeys.has(clientKey)) {
        group.clientKeys.add(clientKey);
        group.clients.push(client);
      }
    });
    return Array.from(groups.values()).sort((a, b) => a.name.localeCompare(b.name));
  }

  function getDiskGroups(clients) {
    const groups = new Map();
    clients.forEach(client => {
      (client.disks || []).forEach(disk => {
        if (!disk.model) return;
        const key = [disk.model, disk.type, disk.sizeGb].join('\x1f').toLowerCase();
        if (!groups.has(key)) {
          groups.set(key, { model: disk.model, type: disk.type || 'HDD', sizeGb: disk.sizeGb || 0, usb: disk.usb === true, clients: [], clientKeys: new Set() });
        }
        const group = groups.get(key);
        const clientKey = String(client.computerName || '').toLowerCase();
        if (!group.clientKeys.has(clientKey)) {
          group.clientKeys.add(clientKey);
          group.clients.push(client);
        }
      });
    });
    return Array.from(groups.values()).sort((a, b) => {
      if (a.usb !== b.usb) return a.usb ? 1 : -1;
      return a.model.localeCompare(b.model);
    });
  }

  function getRamGroups(clients) {
    const groups = new Map();
    clients.forEach(client => {
      const totalMb = client.ramTotalMb || 0;
      const modules = client.ramModules || [];
      const key = `${totalMb}:${modules.length}`;
      if (!groups.has(key)) {
        const totalGb = totalMb >= 1024 ? `${Math.round(totalMb / 1024)} GB` : `${totalMb} MB`;
        groups.set(key, { totalMb, totalGb, moduleCount: modules.length, clients: [], clientKeys: new Set() });
      }
      const group = groups.get(key);
      const clientKey = String(client.computerName || '').toLowerCase();
      if (!group.clientKeys.has(clientKey)) {
        group.clientKeys.add(clientKey);
        group.clients.push(client);
      }
    });
    return Array.from(groups.values()).sort((a, b) => b.totalMb - a.totalMb);
  }

  // Top N CPU models by client count, with the rest folded into "Other" so the
  // chart stays readable on fleets with many distinct models.
  function getTopCpuModels(clients, limit) {
    const groups = getCpuGroups(clients)
      .map(g => ({ label: g.name, count: g.clients.length }))
      .sort((a, b) => b.count - a.count);
    if (groups.length <= limit) return groups;
    const top = groups.slice(0, limit);
    const otherCount = groups.slice(limit).reduce((sum, g) => sum + g.count, 0);
    top.push({ label: 'Other', count: otherCount });
    return top;
  }

  // Bucketed at the RAM sizes actually seen in the field (4/8/16 GB); anything
  // above 16 GB is rare enough to lump into one "32 GB+" catch-all rather than
  // spread thin across more bars.
  function getRamBuckets(clients) {
    const buckets = [
      { label: '4 GB', max: 4 * 1024, count: 0 },
      { label: '8 GB', max: 8 * 1024, count: 0 },
      { label: '16 GB', max: 16 * 1024, count: 0 },
      { label: '32 GB+', max: Infinity, count: 0 }
    ];
    clients.forEach(client => {
      const totalMb = client.ramTotalMb || 0;
      if (!totalMb) return;
      const bucket = buckets.find(b => totalMb <= b.max) || buckets[buckets.length - 1];
      bucket.count++;
    });
    return buckets;
  }

  // Counts disks, not clients - a machine with one SSD and one HDD counts in
  // both bars, which matches what the Hardware > Storage table already shows.
  // Disks with no recognizable type are left out entirely rather than shown
  // as a third "Unknown" bar.
  function getStorageTypeBreakdown(clients) {
    const counts = { SSD: 0, HDD: 0 };
    clients.forEach(client => {
      (client.disks || []).forEach(disk => {
        const type = String(disk.type || '').toUpperCase();
        if (type === 'SSD') counts.SSD++;
        else if (type === 'HDD') counts.HDD++;
      });
    });
    return Object.keys(counts)
      .map(label => ({ label, count: counts[label] }))
      .filter(item => item.count > 0);
  }

  // Top N software titles by the number of distinct computers that have any
  // version of it installed - a client with three Chrome versions counts once.
  function getTopSoftwareNames(clients, limit) {
    const counts = new Map();
    clients.forEach(client => {
      const seenNames = new Set();
      getClientSoftware(client).forEach(item => {
        const name = (item.name || '').trim();
        if (!name) return;
        const key = name.toLowerCase();
        if (seenNames.has(key)) return;
        seenNames.add(key);
        if (!counts.has(key)) counts.set(key, { label: name, count: 0 });
        counts.get(key).count++;
      });
    });
    return Array.from(counts.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  function renderBarChart(containerId, items) {
    const container = byId(containerId);
    if (!items.length) {
      container.innerHTML = '<p class="empty">No data yet.</p>';
      return;
    }
    const max = Math.max(1, ...items.map(item => item.count));
    container.innerHTML = items.map(item => {
      const pct = Math.round((item.count / max) * 100);
      return `<div class="bar-row">
        <span class="bar-label" title="${escapeHtml(item.label)}">${escapeHtml(item.label)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        <span class="bar-value">${item.count}</span>
      </div>`;
    }).join('');
  }

  function hwMatches(haystack, query) {
    if (!query) return true;
    return haystack.toLowerCase().indexOf(query.toLowerCase()) !== -1;
  }

  function softwareMatches(group, query) {
    if (!query) return true;
    const computers = group.clients.map(client => client.computerName).join(' ');
    const haystack = [group.name, group.version, group.publisher, computers].join(' ').toLowerCase();
    return haystack.indexOf(query.toLowerCase()) !== -1;
  }

  function renderSummary(clients) {
    byId('clientCount').textContent = clients.length;
    byId('windowsActivated').textContent = clients.filter(client => client.activation && client.activation.windows && client.activation.windows.activated).length;
    byId('officeActivated').textContent = clients.filter(client => client.activation && client.activation.office && client.activation.office.activated).length;
    const staleCount = clients.filter(isStale).length;
    byId('staleCount').textContent = staleCount;
    byId('staleLabel').textContent = `Stale >${state.staleHours}h`;
    byId('staleTile').classList.toggle('tile-alert', staleCount > 0);
  }

  function renderDashboardTiles() {
    const clients = state.clients;
    byId('dashClientCount').textContent = clients.length;
    byId('dashWindowsActivated').textContent = clients.filter(client => client.activation && client.activation.windows && client.activation.windows.activated).length;
    byId('dashOfficeActivated').textContent = clients.filter(client => client.activation && client.activation.office && client.activation.office.activated).length;
    const dashStaleCount = clients.filter(isStale).length;
    byId('dashStaleCount').textContent = dashStaleCount;
    byId('dashStaleLabel').textContent = `Stale >${state.staleHours}h`;
    byId('dashStaleTile').classList.toggle('tile-alert', dashStaleCount > 0);
    byId('dashLicenseCount').textContent = state.licenses.length;
    byId('dashUsbCount').textContent = clients.filter(client => client.hasUsbStorage).length;
    renderBarChart('dashSoftwareChart', getTopSoftwareNames(clients, 5));
    renderBarChart('dashCpuChart', getTopCpuModels(clients, 4));
    renderBarChart('dashRamChart', getRamBuckets(clients));
    renderBarChart('dashStorageChart', getStorageTypeBreakdown(clients));
  }

  function formatRamModules(modules) {
    if (!modules || modules.length === 0) return null;
    return modules.map(m => {
      const cap = m.capacityMb >= 1024 ? `${Math.round(m.capacityMb / 1024)} GB` : `${m.capacityMb} MB`;
      const mfr = m.manufacturer ? ` ${escapeHtml(m.manufacturer)}` : '';
      const spd = m.speedMhz ? ` ${m.speedMhz} MHz` : '';
      return `${cap}${mfr}${spd}`;
    }).join(', ');
  }

  function renderTable(clients) {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.clients;
    const filtered = applySort(clients.filter(client => clientMatches(client, query)), c => clientSortValue(c, sortKey), sortDir);
    const { items: pageItems, page, totalPages } = paginate(filtered, state.page.clients, state.pageSize.clients);
    state.page.clients = page;
    const rows = pageItems.map(client => {
      const staleClass = isStale(client) ? ' stale' : '';
      const os = client.os || {};
      const office = client.office || {};
      const activation = client.activation || {};
      const windowsActivation = activation.windows || {};
      const officeActivation = activation.office || {};
      const clientSoftware = getClientSoftware(client);
      const softwareCount = clientSoftware.length;
      const ipAddresses = formatIpAddresses(client);
      const usbBadge = client.hasUsbStorage ? ' <span class="usb-badge">USB</span>' : '';

      const softwareRows = clientSoftware.map(item => `<tr>
        <td>${escapeHtml(item.name)}</td>
        <td>${escapeHtml(item.version)}</td>
        <td>${escapeHtml(item.publisher)}</td>
        <td>${escapeHtml(formatInstallDate(item.installDate))}</td>
      </tr>`).join('');

      const cpu = client.cpu || {};
      const cpuText = cpu.name
        ? `${escapeHtml(cpu.name)}${cpu.cores ? `, ${cpu.cores} cores` : ''}${cpu.clockMhz ? `, ${(cpu.clockMhz / 1000).toFixed(2)} GHz` : ''}`
        : 'Unknown';
      const ramGb = client.ramTotalMb
        ? (client.ramTotalMb >= 1024 ? `${Math.round(client.ramTotalMb / 1024)} GB` : `${client.ramTotalMb} MB`)
        : 'Unknown';
      const ramModulesSummary = formatRamModules(client.ramModules);
      const disksSummary = (client.disks || []).map(d => {
        const size = d.sizeGb ? ` ${d.sizeGb} GB` : '';
        const badge = d.usb ? ' <span class="usb-badge">USB</span>' : '';
        return `${escapeHtml(d.type)}${escapeHtml(size)}${badge} <small>${escapeHtml(d.model)}</small>`;
      }).join('<br>') || 'Unknown';

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
        <td colspan="10">
          <div class="details">
            <div class="hw-summary">
              <div><strong>CPU</strong><span>${cpuText}</span></div>
              <div><strong>RAM</strong><span>${ramGb}${ramModulesSummary ? ` &mdash; ${ramModulesSummary}` : ''}</span></div>
              <div><strong>Storage</strong><span>${disksSummary}</span></div>
            </div>
            <h2>${escapeHtml(client.computerName)} software</h2>
            <table class="nested-table">
              <thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Install date</th></tr></thead>
              <tbody>${softwareRows || '<tr><td colspan="4" class="empty">No software records.</td></tr>'}</tbody>
            </table>
          </div>
        </td>
      </tr>`;
    });

    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="10" class="empty">No matching inventory records.</td></tr>';
    renderPager('clientsPager', 'clients', page, totalPages, () => renderTable(state.clients));
  }

  function renderSoftwareTable(clients) {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.software;
    const filtered = applySort(getSoftwareGroups(clients).filter(group => softwareMatches(group, query)), g => softwareSortValue(g, sortKey), sortDir);
    const { items: pageItems, page, totalPages } = paginate(filtered, state.page.software, state.pageSize.software);
    state.page.software = page;
    const rows = pageItems.map(group => {
      const computers = group.clients
        .map(client => `<li>${escapeHtml(client.computerName)}<small>${escapeHtml(client.domain)}</small></li>`)
        .join('');

      const groupId = safeId(softwareKey(group));

      return `<tr>
        <td><button class="link-button" type="button" data-software="${groupId}">${escapeHtml(group.name)}</button></td>
        <td>${escapeHtml(group.version)}</td>
        <td>${escapeHtml(group.publisher)}</td>
        <td class="hw-num">${group.clients.length}</td>
        <td>${findLicenseForSoftware(group.name) ? `<button class="edit-button" type="button" data-software-license-name="${escapeHtml(group.name)}" data-software-license-version="${escapeHtml(group.version)}">License</button>` : ''}</td>
      </tr>
      <tr class="details-row hidden" data-software-details="${groupId}">
        <td colspan="5">
          <div class="details">
            <h2>${escapeHtml(group.name)}</h2>
            <ul class="computer-list">${computers}</ul>
          </div>
        </td>
      </tr>`;
    });

    byId('softwareBody').innerHTML = rows.join('') || '<tr><td colspan="5" class="empty">No matching software records.</td></tr>';
    renderPager('softwarePager', 'software', page, totalPages, () => renderSoftwareTable(state.clients));

    document.querySelectorAll('[data-software-license-name]').forEach(button => {
      button.addEventListener('click', () => {
        openLicenseForSoftware(button.dataset.softwareLicenseName, button.dataset.softwareLicenseVersion);
      });
    });
  }

  function renderHardwarePage(clients) {
    const query = byId('searchInput').value.trim();

    const { key: cpuSortKey, dir: cpuSortDir } = state.sort.hwCpu;
    const cpuRows = applySort(getCpuGroups(clients).filter(g => hwMatches([g.name, ...g.clients.map(c => c.computerName)].join(' '), query)), g => cpuSortValue(g, cpuSortKey), cpuSortDir).map(g => {
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
          <td colspan="4"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwCpuBody').innerHTML = cpuRows.join('') || '<tr><td colspan="4" class="empty">No CPU data.</td></tr>';

    const { key: diskSortKey, dir: diskSortDir } = state.sort.hwDisk;
    const diskRows = applySort(getDiskGroups(clients).filter(g => hwMatches([g.model, g.type, ...g.clients.map(c => c.computerName)].join(' '), query)), g => diskSortValue(g, diskSortKey), diskSortDir).map(g => {
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
          <td colspan="4"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwDiskBody').innerHTML = diskRows.join('') || '<tr><td colspan="4" class="empty">No storage data.</td></tr>';

    const { key: ramSortKey, dir: ramSortDir } = state.sort.hwRam;
    const ramRows = applySort(getRamGroups(clients).filter(g => hwMatches([g.totalGb, ...g.clients.map(c => c.computerName)].join(' '), query)), g => ramSortValue(g, ramSortKey), ramSortDir).map(g => {
        const id = safeId('ram:' + g.totalMb + ':' + g.moduleCount);
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        return `<tr>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.totalGb)}</button></td>
          <td class="hw-num">${g.moduleCount || 'Unknown'}</td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row hidden" data-hw-details="${id}">
          <td colspan="3"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwRamBody').innerHTML = ramRows.join('') || '<tr><td colspan="3" class="empty">No RAM data.</td></tr>';
  }

  function render() {
    renderDashboardTiles();
    renderSummary(state.clients);
    renderSortHeaders();
    renderTable(state.clients);
    renderSoftwareTable(state.clients);
    renderHardwarePage(state.clients);
    renderLicenses();
    populateSoftwareDatalists();
    byId('dashboardView').classList.toggle('hidden', state.view !== 'dashboard');
    byId('clientsView').classList.toggle('hidden', state.view !== 'clients');
    byId('softwareView').classList.toggle('hidden', state.view !== 'software');
    byId('hardwareView').classList.toggle('hidden', state.view !== 'hardware');
    byId('installView').classList.toggle('hidden', state.view !== 'install');
    byId('packageView').classList.toggle('hidden', state.view !== 'package');
    byId('generalView').classList.toggle('hidden', state.view !== 'general');
    byId('generalStatusView').classList.toggle('hidden', state.view !== 'general');
    byId('certificateView').classList.toggle('hidden', state.view !== 'certificate');
    byId('licensesView').classList.toggle('hidden', state.view !== 'licenses');
    byId('adminPasswordView').classList.toggle('hidden', state.view !== 'admin');
    byId('dashboardTab').classList.toggle('active', state.view === 'dashboard');
    byId('clientsTab').classList.toggle('active', state.view === 'clients');
    byId('softwareTab').classList.toggle('active', state.view === 'software');
    byId('hardwareTab').classList.toggle('active', state.view === 'hardware');
    byId('installTab').classList.toggle('active', state.view === 'install');
    byId('packageTab').classList.toggle('active', state.view === 'package');
    byId('generalTab').classList.toggle('active', state.view === 'general');
    byId('certificateTab').classList.toggle('active', state.view === 'certificate');
    byId('licensesTab').classList.toggle('active', state.view === 'licenses');
    byId('adminPasswordTab').classList.toggle('active', state.view === 'admin');
    const isInventoryView = inventoryViews.includes(state.view);
    byId('summarySection').classList.toggle('hidden', !isInventoryView);
    byId('searchInput').classList.toggle('hidden', !isInventoryView);
    byId('generatedAt').classList.toggle('hidden', !isInventoryView);
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
    } else if (state.view === 'software') {
      const size = computeLiveRowsPerPage('softwareBody');
      if (size && size !== state.pageSize.software) {
        state.pageSize.software = size;
        renderSoftwareTable(state.clients);
      }
    }
  }

  fetch('/api/v1/clients', { cache: 'no-store' })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
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
  byId('dashboardTab').addEventListener('click', () => {
    setView('dashboard');
  });
  byId('clientsTab').addEventListener('click', () => {
    setView('clients');
  });
  byId('softwareTab').addEventListener('click', () => {
    setView('software');
  });
  byId('hardwareTab').addEventListener('click', () => {
    setView('hardware');
  });
  byId('installTab').addEventListener('click', () => {
    setView('install');
  });
  window.addEventListener('hashchange', () => {
    state.view = getInitialView();
    render();
    if (state.view === 'install') loadInstallHistory();
    if (state.view === 'package') loadPackageStatus();
    if (state.view === 'general') loadGeneralSettings();
    if (state.view === 'certificate') { loadCertificateStatus(); loadCertificateHistory(); }
    if (state.view === 'licenses') loadLicenses();
    if (state.view === 'admin') loadAdminPasswordStatus();
  });
  byId('installServerUrl').value = `${window.location.origin}/api/v1/inventory`;
  byId('clientAction').addEventListener('change', updateClientActionUi);
  byId('installButton').addEventListener('click', startClientActionJob);
  byId('exportClientsBtn').addEventListener('click', exportClients);
  byId('exportSoftwareBtn').addEventListener('click', exportSoftware);
  byId('exportCpuBtn').addEventListener('click', exportHardwareCpu);
  byId('exportDiskBtn').addEventListener('click', exportHardwareDisk);
  byId('exportRamBtn').addEventListener('click', exportHardwareRam);
  // Delegated on document so it keeps working after any of these buttons'
  // rows get replaced outside the full render() pipeline - e.g. a
  // standalone renderTable(state.clients) triggered by the Clients pager's
  // Prev/Next or by recalculateActivePagination's live-resize re-render.
  // Binding listeners on the buttons themselves (as bindDetails() used to)
  // requires re-binding after every innerHTML replacement; delegation needs
  // binding exactly once, here, regardless of how the table DOM changes.
  document.addEventListener('click', e => {
    const th = e.target.closest('th[data-sort-key]');
    if (th) {
      const table = th.dataset.sortTable;
      const key = th.dataset.sortKey;
      const current = state.sort[table];
      if (!current) return;
      if (current.key === key) {
        current.dir = -current.dir;
      } else {
        current.key = key;
        current.dir = 1;
      }
      if (state.page[table] !== undefined) state.page[table] = 1;
      render();
      return;
    }

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

    const deleteBtn = e.target.closest('[data-delete-client]');
    if (deleteBtn) {
      deleteClient(deleteBtn.dataset.deleteClient);
    }
  });
  byId('packageTab').addEventListener('click', () => setView('package'));
  byId('pkgSaveButton').addEventListener('click', savePackageConfig);
  byId('pkgDownloadButton').addEventListener('click', () => {
    const status = state.packageStatus;
    if (status && (status.net35VersionMismatch || status.net40VersionMismatch)) {
      const versions = [
        status.net35VersionMismatch ? `Net 3.5: v${status.net35Version}` : null,
        status.net40VersionMismatch ? `Net 4.0: v${status.net40Version}` : null
      ].filter(Boolean).join(', ');
      const confirmed = window.confirm(
        `The packaged client (${versions}) does not match the server version (v${status.serverVersion}). ` +
        `Rebuild the server (it also builds both client targets) or run New-ClientGpoPackage.ps1 to refresh the package. ` +
        `Download the outdated package anyway?`
      );
      if (!confirmed) return;
    }
    window.location.href = '/api/v1/client-package/download';
  });
  byId('generalTab').addEventListener('click', () => setView('general'));
  byId('generalSaveButton').addEventListener('click', () => saveGeneralSettings(false));
  byId('generalAdUseServiceIdentity').addEventListener('change', updateAdIdentityFields);
  byId('certificateTab').addEventListener('click', () => setView('certificate'));
  byId('certUploadButton').addEventListener('click', uploadCertificate);
  byId('certDeleteButton').addEventListener('click', deleteCertificate);
  byId('licensesTab').addEventListener('click', () => setView('licenses'));
  byId('exportLicensesBtn').addEventListener('click', exportLicenses);
  byId('licenseAddButton').addEventListener('click', () => openLicenseForm(null));
  byId('licenseSaveButton').addEventListener('click', saveLicense);
  byId('licenseCancelButton').addEventListener('click', closeLicenseForm);
  byId('licenseName').addEventListener('input', updateVersionDatalist);
  byId('licenseName').addEventListener('change', applySoftwareComputers);
  byId('licenseComputerAddButton').addEventListener('click', addLicenseComputerFromInput);
  byId('licenseComputerInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addLicenseComputerFromInput();
    }
  });
  byId('adminPasswordTab').addEventListener('click', () => setView('admin'));
  byId('adminPasswordSaveButton').addEventListener('click', changeAdminPassword);
  byId('themeToggle').addEventListener('click', toggleTheme);
  updateThemeToggle();
  if (state.view === 'package') loadPackageStatus();
  if (state.view === 'general') loadGeneralSettings();
  if (state.view === 'certificate') { loadCertificateStatus(); loadCertificateHistory(); }
  if (state.view === 'licenses') loadLicenses();
  if (state.view === 'admin') loadAdminPasswordStatus();
  updateClientActionUi();
  loadInstallHistory();
}());
