(function () {
  const inventoryViews = ['clients', 'software', 'hardware'];
  const linuxInventoryViews = ['linuxServices'];
  // Views whose rendered content depends on state.linuxClients, so the 30s
  // poll keeps Linux data fresh while one of them is open. Deliberately a
  // separate list from linuxInventoryViews, which drives the search box and
  // the "Generated:" line and must stay limited to the Linux-only inventory
  // table - the Dashboard reads Linux data but is not an inventory view,
  // and the merged Clients/Hardware views are already covered for search
  // purposes by inventoryViews.
  const linuxDataViews = ['clients', 'linuxServices', 'dashboard', 'hardware'];
  const state = {
    clients: [], linuxClients: [], ...getInitialViewState(), installJobId: null, installPollTimer: null, installJobs: [],
    updateJobId: null, updatePollTimer: null,
    // Baselined from the first client-updates poll response, then compared
    // on every later one - lets an open dashboard tab pick up a scheduled
    // (server-initiated) push it never itself requested. null until baselined.
    knownScheduledJobId: undefined,
    packageStatus: null,
    clientUpdates: null,
    certificateStatus: null, certificateHistory: [],
    staleHours: 48,
    licenses: [], editingLicenseId: null, licenseFormComputers: [],
    sort: {
      // 'name', not 'computerName': the Clients table is cross-platform
      // now, and its Computer column shows clientDisplayName() - Windows'
      // computerName or Linux' hostname. See allClientSortValue.
      clients: { key: 'name', dir: 1 },
      software: { key: 'name', dir: 1 },
      // Sorts the software list inside a Windows client's expanded detail
      // row (see nestedTable in renderClientsTable). Single shared key, not
      // per-client - same convention as software/licenses above (one sort
      // order for the whole logical table, not one per row/group).
      clientSoftware: { key: 'name', dir: 1 },
      // hwCpu/hwDisk/hwRam drive the single cross-platform Hardware view -
      // these were always per-table, never per-platform, so the merged view
      // reuses them and the former linuxHw* keys are gone.
      hwCpu: { key: 'name', dir: 1 },
      hwDisk: { key: 'model', dir: 1 },
      hwRam: { key: 'totalMb', dir: -1 },
      licenses: { key: 'name', dir: 1 },
      linuxServices: { key: 'name', dir: 1 },
      // Sorts the merged Deploy > Updates table (Windows + Linux outdated
      // clients combined) - same per-view-key convention as every other
      // table above.
      updates: { key: 'computerName', dir: 1 }
    },
    page: { clients: 1, software: 1, hwCpu: 1, hwDisk: 1, hwRam: 1, linuxServices: 1, updates: 1 },
    // clients/software start at a reasonable fallback and are corrected to
    // the real viewport-fitting value the first time their table becomes
    // visible (see computeLiveRowsPerPage/recalculateActivePagination).
    // hwCpu/hwDisk/hwRam are fixed (see HW_PAGE_SIZE) - the three Hardware
    // sub-tables render stacked in one view and are rarely large enough to
    // need viewport-adaptive sizing.
    pageSize: { clients: 20, software: 20, hwCpu: 20, hwDisk: 20, hwRam: 20, linuxServices: 20, updates: 20 },
    // Prefixed keys ('client:'/'software:'/'hw:' + id) so the three
    // separate data-*-details attribute namespaces can't collide in one
    // Set. Drives each render function's initial hidden/visible class for
    // a details row, instead of every row always starting hidden - keeps
    // "expanded" state alive across any re-render (pager Next/Prev, a
    // live-resize page-size correction, or a background data poll), not
    // just the one that happened to be showing when the row was expanded.
    expandedDetails: new Set(),
    // Keyed per consuming view, same convention as state.sort/state.page/
    // state.pageSize. 'all' | 'windows' | 'linux'. The keys are literally
    // view names, so renderOsFilterActive can repaint the one shared pill
    // from state.osFilter[state.view] when the user switches pages.
    // 'deploy', not 'updates': state.view is 'deploy' for every Deploy
    // subview (Actions/Updates/Package), and renderOsFilterActive() reads
    // state.osFilter[state.view] - this key must match that, not the
    // subview name.
    osFilter: { hardware: 'all', clients: 'all', deploy: 'all' }
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

  // Shows whether a write-only password field (AD password, Linux update
  // password, Windows Client updates password) currently has a saved
  // value, as classic dots - without ever revealing the value or its real
  // length (the dot count here is fixed, not derived from the actual
  // password). Only ever touches .placeholder, never .value, so there is
  // no path where this indicator could itself be submitted and overwrite
  // the real saved password. emptyPlaceholder is restored when a
  // previously-saved password is cleared without a full page reload (e.g.
  // "Delete saved credentials").
  function applyPasswordPlaceholder(inputId, hasPassword, emptyPlaceholder) {
    byId(inputId).placeholder = hasPassword ? '••••••••' : emptyPlaceholder;
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

  // Basic Auth has no server-side session to invalidate, so this is a
  // best-effort client-side clear: an explicit, deliberately-wrong
  // Authorization header gives the browser a chance to drop the real
  // cached credentials, but not every browser honors it. The overlay text
  // says so - closing the tab/window is the only guaranteed way out.
  function handleLogout() {
    if (!window.confirm('Log out of Windows Inventory Lite? On some browsers you may need to close this tab to fully clear your saved sign-in.')) return;
    stopPolling();
    fetch('/api/v1/clients', {
      cache: 'no-store',
      headers: { Authorization: 'Basic ' + btoa('logout:' + Math.random().toString(36).slice(2)) }
    }).catch(() => {}).then(() => {
      byId('logoutOverlay').classList.remove('hidden');
    });
  }

  // Returns { view, subview }. Deploy and Settings are consolidated
  // destinations (see docs/superpowers/specs/2026-08-12-dashboard-ui-redesign-design.md,
  // decisions 6-7) - every hash that used to point at one of the 5 old
  // Installation pages or 3 old Settings pages now resolves to 'deploy' or
  // 'settings' plus a subview. Old hashes are kept as aliases (matching this
  // function's existing #linux-hardware precedent) so bookmarks/links still
  // land correctly; deploy-*/settings-* are the new canonical hashes setView
  // itself produces going forward.
  function getInitialViewState() {
    const hash = window.location.hash.replace(/^#/, '').toLowerCase();
    if (hash === 'clients') return { view: 'clients', subview: null };
    if (hash === 'software') return { view: 'software', subview: null };
    if (hash === 'hardware' || hash === 'linux-hardware') return { view: 'hardware', subview: null };
    if (hash === 'licenses') return { view: 'licenses', subview: null };
    // #linux-clients / #linux are kept as aliases of the merged Clients
    // page (same backward-compat pattern as #linux-hardware above and
    // #certificate below) - old bookmarks land on Clients, unfiltered.
    if (hash === 'linux-clients' || hash === 'linux') return { view: 'clients', subview: null };
    if (hash === 'linux-services') return { view: 'linuxServices', subview: null };
    if (hash === 'deploy' || hash === 'deploy-actions' || hash === 'client-actions' || hash === 'actions' || hash === 'install' || hash === 'linux-client-actions') return { view: 'deploy', subview: 'actions' };
    if (hash === 'deploy-updates' || hash === 'client-updates' || hash === 'updates' || hash === 'linux-client-updates') return { view: 'deploy', subview: 'updates' };
    if (hash === 'deploy-package' || hash === 'client-package' || hash === 'package') return { view: 'deploy', subview: 'package' };
    // Old #settings/#settings-general/#general hashes land on Server (the
    // new first tab) rather than disappearing - same backward-compat
    // convention as every other retired hash in this function.
    if (hash === 'settings' || hash === 'settings-general' || hash === 'general' || hash === 'settings-server') return { view: 'settings', subview: 'server' };
    if (hash === 'settings-windows') return { view: 'settings', subview: 'windows' };
    if (hash === 'settings-linux') return { view: 'settings', subview: 'linux' };
    if (hash === 'settings-certificate' || hash === 'certificate') return { view: 'settings', subview: 'certificate' };
    if (hash === 'settings-admin-password' || hash === 'admin-password' || hash === 'admin') return { view: 'settings', subview: 'adminPassword' };
    return { view: 'dashboard', subview: null };
  }

  // View -> canonical hash. Deploy/Settings map through their subview;
  // linuxServices keeps its existing multi-word hash; everything else's
  // hash equals its view name unchanged (the merged Clients page falls
  // through to the default and produces 'clients').
  function computeHashForView(view, subview) {
    if (view === 'deploy') return subview === 'updates' ? 'deploy-updates' : subview === 'package' ? 'deploy-package' : 'deploy-actions';
    if (view === 'settings') {
      if (subview === 'certificate') return 'settings-certificate';
      if (subview === 'adminPassword') return 'settings-admin-password';
      if (subview === 'windows') return 'settings-windows';
      if (subview === 'linux') return 'settings-linux';
      return 'settings-server';
    }
    if (view === 'linuxServices') return 'linux-services';
    return view;
  }

  function loadDeploySubviewData(subview) {
    if (subview === 'actions') { loadInstallHistory(); loadInstallPreferredSubnet(); }
    if (subview === 'updates') { loadClientUpdates(); loadClientUpdateCredentials(); loadClientUpdateSchedule(); }
    if (subview === 'package') { loadPackageStatus(); loadLinuxPackageStatus(); }
    if (subview === 'updates') { loadLinuxClientUpdates(); loadLinuxUpdateSchedule(); }
  }

  function loadSettingsSubviewData(subview) {
    if (subview === 'server') { loadServerSettings(); loadIngestionTokenStatus(); }
    if (subview === 'windows') loadWindowsSettings();
    if (subview === 'linux') { loadLinuxSettings(); loadLinuxUpdateCredentials(); loadLinuxSshToolsStatus(); }
    if (subview === 'certificate') { loadCertificateStatus(); loadCertificateHistory(); }
    if (subview === 'adminPassword') loadAdminPasswordStatus();
  }

  function setView(view, subview) {
    state.view = view;
    state.subview = subview || null;
    const hash = computeHashForView(view, subview);
    if (window.location.hash.replace(/^#/, '') !== hash) {
      window.location.hash = hash;
      return;
    }
    render();
    if (view === 'deploy') loadDeploySubviewData(state.subview);
    if (view === 'settings') loadSettingsSubviewData(state.subview);
    if (view === 'licenses') loadLicenses();
    // 'clients' and 'hardware' are in this list because both merged views
    // read Linux data too - opening either tab re-fetches it rather than
    // waiting up to 30s for the next poll tick.
    if (view === 'clients' || view === 'linuxServices' || view === 'hardware') loadLinuxClients();
  }

  function renderSubtabStrips() {
    byId('deploySubtabs').classList.toggle('hidden', state.view !== 'deploy');
    byId('settingsSubtabs').classList.toggle('hidden', state.view !== 'settings');
    byId('deploySubtabActions').classList.toggle('active', state.view === 'deploy' && state.subview === 'actions');
    byId('deploySubtabActions').setAttribute('aria-selected', String(state.view === 'deploy' && state.subview === 'actions'));
    byId('deploySubtabUpdates').classList.toggle('active', state.view === 'deploy' && state.subview === 'updates');
    byId('deploySubtabUpdates').setAttribute('aria-selected', String(state.view === 'deploy' && state.subview === 'updates'));
    byId('deploySubtabPackage').classList.toggle('active', state.view === 'deploy' && state.subview === 'package');
    byId('deploySubtabPackage').setAttribute('aria-selected', String(state.view === 'deploy' && state.subview === 'package'));
    byId('settingsSubtabServer').classList.toggle('active', state.view === 'settings' && state.subview === 'server');
    byId('settingsSubtabServer').setAttribute('aria-selected', String(state.view === 'settings' && state.subview === 'server'));
    byId('settingsSubtabWindows').classList.toggle('active', state.view === 'settings' && state.subview === 'windows');
    byId('settingsSubtabWindows').setAttribute('aria-selected', String(state.view === 'settings' && state.subview === 'windows'));
    byId('settingsSubtabLinux').classList.toggle('active', state.view === 'settings' && state.subview === 'linux');
    byId('settingsSubtabLinux').setAttribute('aria-selected', String(state.view === 'settings' && state.subview === 'linux'));
    byId('settingsSubtabCertificate').classList.toggle('active', state.view === 'settings' && state.subview === 'certificate');
    byId('settingsSubtabCertificate').setAttribute('aria-selected', String(state.view === 'settings' && state.subview === 'certificate'));
    byId('settingsSubtabAdminPassword').classList.toggle('active', state.view === 'settings' && state.subview === 'adminPassword');
    byId('settingsSubtabAdminPassword').setAttribute('aria-selected', String(state.view === 'settings' && state.subview === 'adminPassword'));
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

  // Same on/off dot as activationBadge, but for a Linux service's own
  // active/inactive state (per the client's latest status report) rather
  // than Windows/Office activation - activationBadge's "Activated"/"Not
  // detected" wording doesn't fit a service. Previously this column only
  // rendered anything for the false case (an INACTIVE text badge), leaving
  // a confirmed-running service's cell blank under an "Active" header -
  // indistinguishable from "no data" at a glance.
  function serviceActiveDot(isActive) {
    const text = `Active: ${isActive ? 'Yes' : 'No'}`;
    const icon = isActive ? CHECK_DOT_SVG : '';
    return `<span class="status-dot ${isActive ? 'status-dot-on' : 'status-dot-off'}" role="img" aria-label="${escapeHtml(text)}" title="${escapeHtml(text)}">${icon}</span>`;
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

  // Editable Description cell, used instead of formatAdDescription's
  // read-only text whenever state.adDescriptionSyncEnabled is false.
  // adSyncStatus ('not-found'/'error') is deliberately ignored here - once
  // sync is off, those statuses are frozen leftovers from whenever sync
  // last ran and are no longer meaningful. data-last-saved-value lets
  // saveClientDescription detect a no-op blur/Enter and skip the network
  // request.
  function formatDescriptionEditor(client, clientId) {
    // escapeHtml() runs every value through text(), which turns an empty
    // string into the literal word "Unknown" - correct for most cells, but
    // this editor's whole point is to show a genuinely blank input when
    // there's no Description yet, not a placeholder word. escapeHtmlOrEmpty
    // is the sibling helper built for exactly this case.
    const value = escapeHtmlOrEmpty(client.adDescription);
    return `<input type="text" class="description-edit-input" data-description-client="${clientId}" data-computer-name="${escapeHtml(client.computerName)}" data-last-saved-value="${value}" value="${value}" maxlength="1024">`;
  }

  // Linux-table counterparts of formatAdDescription/formatDescriptionEditor.
  // Separate functions (rather than branching the Windows ones) because the
  // Linux report shape keys off `hostname` instead of `computerName` and
  // needs data-platform="linux" so the shared saveClientDescription (and the
  // global keydown/blur listeners it's wired to) can tell the two tables apart.
  function formatLinuxDescriptionEditor(client, clientId) {
    // See formatDescriptionEditor's comment - escapeHtml() would turn a
    // genuinely blank Description into the literal word "Unknown" here.
    const value = escapeHtmlOrEmpty(client.adDescription);
    return `<input type="text" class="description-edit-input" data-description-client="${clientId}" data-computer-name="${escapeHtml(client.hostname)}" data-platform="linux" data-last-saved-value="${value}" value="${value}" maxlength="1024">`;
  }

  function formatLinuxAdDescription(client) {
    if (client.adSyncStatus === 'not-found') return 'Not found in AD';
    if (client.adSyncStatus === 'error') return 'AD unreachable';
    return escapeHtmlOrEmpty(client.adDescription);
  }

  function loadLinuxClients() {
    fetch('/api/v1/linux/clients', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.linuxClients = stampClientPlatform(data.clients || [], 'linux');
        state.adDescriptionSyncEnabled = !!data.adDescriptionSyncEnabled;
        renderFilteredClientsTable();
        renderLinuxServicesTable(state.linuxClients);
        // Both of these read Windows and Linux data together, so they have
        // to be redrawn whenever the Linux half lands - including on the
        // unconditional page-load call, which can resolve after render().
        renderFilteredHardwarePage();
        renderDashboardTiles();
      })
      .catch(() => {});
  }

  // Mirrors clientMatches (Windows) - haystack built from the fields a
  // Linux client actually reports (see linux-client/report.go): hostname,
  // client version, IP, OS pretty name, CPU model, service name+version,
  // disk model+type. No publisher/office/domain fields exist on this side.
  function linuxClientMatches(client, query) {
    if (!query) return true;
    const services = (client.services || []).map(item => `${item.name} ${item.version}`).join(' ');
    const disks = (client.disks || []).map(d => `${d.model} ${d.type}`).join(' ');
    const haystack = [
      client.hostname,
      client.clientVersion,
      formatIpAddresses(client),
      client.os && client.os.prettyName,
      client.cpu && client.cpu.model,
      services,
      disks
    ].join(' ').toLowerCase();
    return haystack.indexOf(query.toLowerCase()) !== -1;
  }

  function deleteLinuxClient(hostname) {
    if (!hostname) return;
    const confirmed = window.confirm(`Delete ${hostname} from the inventory dashboard?`);
    if (!confirmed) return;

    fetch(`/api/v1/linux/clients/${encodeURIComponent(hostname)}`, {
      method: 'DELETE',
      cache: 'no-store'
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        state.linuxClients = state.linuxClients.filter(client => client.hostname !== hostname);
        // Every view that reads state.linuxClients has to be redrawn, not just the
        // Linux Clients table. Since the Dashboard/Hardware merge, the combined
        // tiles and the merged Hardware section both read getAllClients(), and
        // Linux Services reads state.linuxClients directly - all three kept
        // counting a deleted client until the next 30s poll, and only then if the
        // active view happened to be in linuxDataViews. This is the same set
        // loadLinuxClients re-renders after every fetch.
        renderFilteredClientsTable();
        renderLinuxServicesTable(state.linuxClients);
        renderFilteredHardwarePage();
        renderDashboardTiles();
        byId('generatedAt').textContent = `Updated: ${formatDateTime(new Date().toISOString())}`;
      })
      .catch(error => {
        window.alert(`Failed to delete ${hostname}: ${error.message}`);
      });
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

  function formatIpAddressesHtml(client) {
    const addresses = client.ipAddresses || [];
    if (!Array.isArray(addresses) || addresses.length === 0) return '';
    return addresses.map(escapeHtml).join('<br>');
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
    // A client just pushed/updated server-side (lastInstalledAtUtc set,
    // see PatchClientReportVersionAfterInstall) genuinely has an old
    // stored report timestamp until its own next check-in - but that's
    // expected, not a problem, so it's deliberately excluded from
    // staleness everywhere this function is used (dashboard tile count,
    // CSV export, row highlighting). The field disappears on its own once
    // a real report lands, so this stops applying automatically too.
    if (client.lastInstalledAtUtc) return false;
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

  // Matches a client against the merged Clients table's search box,
  // delegating to the existing per-platform matcher since each already
  // knows which fields that platform actually reports (Windows has
  // domain/office/publisher fields Linux has no equivalent for; Linux
  // searches service names where Windows searches software names).
  function allClientMatches(client, query) {
    return clientPlatformLabel(client) === 'Windows' ? clientMatches(client, query) : linuxClientMatches(client, query);
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

  function linuxClientSortValue(client, key) {
    switch (key) {
      case 'hostname': return (client.hostname || '').toLowerCase();
      case 'clientVersion': return client.clientVersion || '';
      case 'os': return ((client.os && client.os.prettyName) || '').toLowerCase();
      case 'softwareCount': return Array.isArray(client.services) ? client.services.length : 0;
      case 'collectedAt': return new Date(client.collectedAt || client.sourceUpdatedAt || 0).getTime();
      default: return '';
    }
  }

  // Sort value for the merged Clients table. Delegates to the existing
  // per-platform sort-value functions (each already knows that platform's
  // field names), so platform-specific logic isn't duplicated. The keys
  // here are the data-sort-key values on #clientsView's headers and must
  // stay in sync with them. 'office' and 'activation' have no Linux concept
  // - returning null puts Linux rows at the end regardless of direction,
  // which applySort already does for null (see its av == null / bv == null
  // handling, no change needed there).
  function allClientSortValue(client, key) {
    const isWindows = clientPlatformLabel(client) === 'Windows';
    switch (key) {
      case 'name': return isWindows ? clientSortValue(client, 'computerName') : linuxClientSortValue(client, 'hostname');
      case 'clientVersion': return client.clientVersion || '';
      case 'os': return isWindows ? clientSortValue(client, 'os') : linuxClientSortValue(client, 'os');
      case 'office': return isWindows ? clientSortValue(client, 'office') : null;
      case 'activation': return isWindows ? clientSortValue(client, 'windowsActivated') : null;
      case 'items': return isWindows ? clientSortValue(client, 'softwareCount') : linuxClientSortValue(client, 'softwareCount');
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

  function linuxServicesSortValue(group, key) {
    switch (key) {
      case 'name': return (group.name || '').toLowerCase();
      case 'version': return group.version || '';
      case 'count': return group.clients.length;
      default: return '';
    }
  }

  // No 'clockMhz' case: clock is no longer a group-level field (see
  // getCpuGroups) and the merged CPU table has no Clock column to sort by.
  function cpuSortValue(g, key) {
    switch (key) {
      case 'name': return (g.name || '').toLowerCase();
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

  // No 'moduleCount' case: module count is no longer a group-level field
  // (see getRamGroups) and the merged RAM table has no Modules column.
  function ramSortValue(g, key) {
    switch (key) {
      case 'totalMb': return g.totalMb || 0;
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

  // installDate is raw YYYYMMDD (see formatInstallDate) - zero-padded and
  // already chronologically sortable as a plain string, no Date parsing
  // needed.
  function clientSoftwareSortValue(item, key) {
    switch (key) {
      case 'name': return (item.name || '').toLowerCase();
      case 'version': return item.version || '';
      case 'publisher': return (item.publisher || '').toLowerCase();
      case 'installDate': return item.installDate || '';
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

  // One CSV for the merged Clients table, replacing the former
  // exportClients/exportLinuxClients pair. Columns are the union of the two
  // old sets plus a Platform column (a mixed file without one is
  // ambiguous); a column with no counterpart on a row's platform exports as
  // an empty cell, this file's existing convention for "not applicable".
  // The OS filter is applied here as well as on screen - exporting the full
  // fleet while the table shows one platform would silently return
  // different data than what was asked for.
  function exportClients() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.clients;
    const items = applySort(
      filterClientsByOs(getAllClients(), state.osFilter.clients).filter(c => allClientMatches(c, query)),
      c => allClientSortValue(c, sortKey), sortDir
    );
    const rows = [['Computer', 'Platform', 'Domain', 'IP Addresses', 'Client Version', 'OS', 'OS Version', 'Build', 'Office', 'Office Version', 'Windows Activated', 'Office Activated', 'Software/Services', 'Collected', 'Stale', 'CPU', 'RAM', 'Disks', 'USB Storage', 'AD Description']].concat(
      items.map(c => {
        const isWindows = clientPlatformLabel(c) === 'Windows';
        const os = c.os || {};
        const office = c.office || {};
        const activation = c.activation || {};
        const winAct = activation.windows || {};
        const officeAct = activation.office || {};
        const cpu = c.cpu || {};
        const ramText = c.ramTotalMb ? (c.ramTotalMb >= 1024 ? Math.round(c.ramTotalMb / 1024) + ' GB' : c.ramTotalMb + ' MB') : '';
        const disksText = (c.disks || []).map(d => (d.type || '') + ' ' + (d.sizeGb ? d.sizeGb + ' GB' : '') + ' ' + (d.model || '')).join(', ').trim();
        return [
          (isWindows ? c.computerName : c.hostname) || '', clientPlatformLabel(c),
          isWindows ? (c.domain || '') : '', formatIpAddresses(c),
          c.clientVersion ? 'v' + c.clientVersion : '',
          (isWindows ? os.caption : os.prettyName) || '',
          isWindows ? (os.version || '') : '',
          isWindows ? (os.buildNumber || '') : '',
          isWindows ? (office.name || '') : '',
          isWindows ? (office.version || '') : '',
          isWindows ? (winAct.activated ? 'Yes' : 'No') : '',
          isWindows ? (officeAct.activated ? 'Yes' : 'No') : '',
          isWindows ? (c.software || []).length : (Array.isArray(c.services) ? c.services.length : 0),
          formatDateTime(c.collectedAt || c.sourceUpdatedAt),
          isStale(c) ? 'Yes' : 'No',
          (isWindows ? cpu.name : cpu.model) || '', ramText, disksText,
          isWindows ? (c.hasUsbStorage ? 'Yes' : 'No') : '',
          state.adDescriptionSyncEnabled ? (c.adSyncStatus === 'not-found' ? 'Not found in AD' : c.adSyncStatus === 'error' ? 'AD unreachable' : (c.adDescription || '')) : (c.adDescription || '')
        ];
      })
    );
    downloadCsv('clients-' + csvDate() + '.csv', rows);
  }

  function exportLinuxServices() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.linuxServices;
    const groups = applySort(getLinuxServicesGroups(state.linuxClients).filter(g => linuxServicesMatches(g, query)), g => linuxServicesSortValue(g, sortKey), sortDir);
    const rows = [['Service', 'Version', 'Installations', 'Computers']].concat(
      groups.map(g => [g.name, g.version, g.clients.length, g.clients.map(c => c.hostname + (c.active === false ? ' (inactive)' : '')).join(', ')])
    );
    downloadCsv('linux-services-' + csvDate() + '.csv', rows);
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

  // Computers are exported as "NAME (Platform)" now that one row can list
  // machines from both platforms - the Clock GHz / Modules columns are gone
  // because those fields are no longer group-level (see getCpuGroups /
  // getRamGroups); their per-computer values live in the expanded row on
  // screen and are deliberately not flattened into the CSV.
  function exportHardwareCpu() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.hwCpu;
    const groups = applySort(
      getCpuGroups(filterClientsByOs(getAllClients(), state.osFilter.hardware)).filter(g => hwMatches([g.name].concat(g.clients.map(c => clientDisplayName(c))).join(' '), query)),
      g => cpuSortValue(g, sortKey), sortDir
    );
    const rows = [['Model', 'Machines', 'Computers']].concat(
      groups.map(g => [g.name, g.clients.length, g.clients.map(c => `${clientDisplayName(c)} (${clientPlatformLabel(c)})`).join(', ')])
    );
    downloadCsv('hardware-cpu-' + csvDate() + '.csv', rows);
  }

  function exportHardwareDisk() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.hwDisk;
    const groups = applySort(
      getDiskGroups(filterClientsByOs(getAllClients(), state.osFilter.hardware)).filter(g => hwMatches([g.model, g.type].concat(g.clients.map(c => clientDisplayName(c))).join(' '), query)),
      g => diskSortValue(g, sortKey), sortDir
    );
    const rows = [['Model', 'Type', 'Size GB', 'USB', 'Machines', 'Computers']].concat(
      groups.map(g => [g.model, g.type, g.sizeGb || '', g.usb ? 'Yes' : 'No', g.clients.length, g.clients.map(c => `${clientDisplayName(c)} (${clientPlatformLabel(c)})`).join(', ')])
    );
    downloadCsv('hardware-storage-' + csvDate() + '.csv', rows);
  }

  function exportHardwareRam() {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.hwRam;
    const groups = applySort(
      getRamGroups(filterClientsByOs(getAllClients(), state.osFilter.hardware)).filter(g => hwMatches([g.totalGb].concat(g.clients.map(c => clientDisplayName(c))).join(' '), query)),
      g => ramSortValue(g, sortKey), sortDir
    );
    const rows = [['Total RAM', 'Machines', 'Computers']].concat(
      groups.map(g => [g.totalGb, g.clients.length, g.clients.map(c => `${clientDisplayName(c)} (${clientPlatformLabel(c)})`).join(', ')])
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

  function renderAttemptRows(jobId, index, attempts) {
    if (!attempts || attempts.length === 0) return '';
    const key = 'attempt:' + jobId + ':' + index;
    const isHidden = state.expandedDetails.has(key) ? '' : 'hidden';
    const rows = attempts.map(attempt => `<tr>
        <td>${escapeHtml(attempt.protocol)}</td>
        <td>${escapeHtml(attempt.status)}</td>
        <td>${escapeHtml(attempt.message)}</td>
        <td><pre class="install-output">${escapeHtml((attempt.error || attempt.output || '').trim())}</pre></td>
      </tr>`).join('');
    return `<tr class="details-row ${isHidden}" data-attempt-details="${index}" data-attempt-job="${escapeHtml(jobId)}">
        <td colspan="4">
          <div class="details">
            <table class="nested-table install-results-table">
              <thead><tr><th>Protocol</th><th>Status</th><th>Message</th><th>Output</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </td>
      </tr>`;
  }

  function renderInstallJob(job, statusElementId = 'installStatus') {
    const results = job.results || [];
    const rows = results.map((result, index) => {
      // Trust-and-retry reads the ssh attempt's host-key fields, which
      // mirror onto the summary result when ssh is the last attempt tried
      // (see RunUnifiedInstallTarget) - unchanged shape from before the
      // Windows/Linux merge, just now reachable from any mode. Gated to
      // the merged Actions status box specifically: it submits Deploy >
      // Actions' own form fields (installSshAuthMode/installSshUsername/
      // installSshPassword/etc via trustHostKeyAndRetry),
      // which don't match whatever credentials Deploy > Updates' Linux
      // push actually used - rendering it there would silently resubmit
      // the wrong account. Same restriction the pre-merge code had
      // (previously gated on statusElementId === 'linuxInstallStatus'),
      // just re-pointed at the one surviving Actions status element id.
      let trustControl = '';
      if (statusElementId === 'installStatus') {
        if (result.hostKeyStatus && result.hostKeyFingerprint) {
          trustControl = `<button class="link-button trust-host-key-button" type="button"
             data-trust-host="${escapeHtml(result.target)}"
             data-trust-fingerprint="${escapeHtml(result.hostKeyFingerprint)}">Trust and retry</button>`;
        } else if (result.hostKeyStatus) {
          trustControl = `<span class="trust-host-key-manual">
             <input type="text" class="trust-fingerprint-input" placeholder="SHA256:..." data-trust-host-input="${escapeHtml(result.target)}">
             <button class="link-button trust-host-key-button" type="button" data-trust-host-manual="${escapeHtml(result.target)}">Trust and retry</button>
           </span>`;
        }
      }
      const hostKeyBadge = result.hostKeyStatus === 'changed'
        ? '<span class="usb-badge">HOST KEY CHANGED</span>'
        : (result.hostKeyStatus === 'unknown' ? '<span class="usb-badge">HOST KEY UNKNOWN</span>' : '');
      const attempts = result.attempts || [];
      const hasMultipleAttempts = attempts.length > 1;
      const targetCell = hasMultipleAttempts
        ? `<button class="link-button" type="button" data-attempt-toggle="${index}" data-attempt-job="${escapeHtml(job.id)}">${escapeHtml(result.target)}</button>`
        : escapeHtml(result.target);
      const protocolNote = result.protocol ? ` (${escapeHtml(result.protocol)})` : '';
      return `<tr>
      <td>${targetCell}</td>
      <td>${escapeHtml(result.status)}${protocolNote}${hostKeyBadge}</td>
      <td>${escapeHtml(result.message)}</td>
      <td><pre class="install-output">${escapeHtml((result.error || result.output || '').trim())}</pre>${trustControl}</td>
    </tr>${renderAttemptRows(job.id, index, hasMultipleAttempts ? attempts : null)}`;
    }).join('');

    const statusElement = byId(statusElementId);
    // innerHTML replacement below recreates .install-results from scratch,
    // which would silently reset its scroll position to the top on every
    // poll tick (every 3s while a job runs) - capture it first and restore
    // it after so a user reading further down a long target list doesn't
    // keep getting yanked back to the top.
    const previousResults = statusElement.querySelector('.install-results');
    const previousScrollTop = previousResults ? previousResults.scrollTop : 0;

    // Same innerHTML-replacement problem hits the manual host-key
    // fingerprint inputs (one per target still needing a host key trusted -
    // see trustControl above): a user mid-typing a SHA256 fingerprint when
    // a poll tick fires would otherwise have it silently wiped, and lose
    // focus/cursor position too. Capture every input's value keyed by its
    // target (there can be more than one), plus which one had focus and
    // where the cursor was, before the replacement destroys them all.
    const previousFingerprintValues = new Map();
    let focusedFingerprintTarget = null;
    let focusedSelectionStart = null;
    let focusedSelectionEnd = null;
    statusElement.querySelectorAll('.trust-fingerprint-input').forEach(input => {
      const target = input.dataset.trustHostInput;
      previousFingerprintValues.set(target, input.value);
      if (input === document.activeElement) {
        focusedFingerprintTarget = target;
        focusedSelectionStart = input.selectionStart;
        focusedSelectionEnd = input.selectionEnd;
      }
    });

    statusElement.classList.remove('empty');
    statusElement.innerHTML = `<div class="job-header">
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

    const newResults = statusElement.querySelector('.install-results');
    if (newResults) newResults.scrollTop = previousScrollTop;

    statusElement.querySelectorAll('.trust-fingerprint-input').forEach(input => {
      const target = input.dataset.trustHostInput;
      if (previousFingerprintValues.has(target)) {
        input.value = previousFingerprintValues.get(target);
      }
      if (target === focusedFingerprintTarget) {
        input.focus();
        input.setSelectionRange(focusedSelectionStart, focusedSelectionEnd);
      }
    });

    statusElement.querySelectorAll('[data-trust-host]').forEach(button => {
      button.addEventListener('click', () => trustHostKeyAndRetry(button.dataset.trustHost, button.dataset.trustFingerprint, statusElementId));
    });
    statusElement.querySelectorAll('[data-trust-host-manual]').forEach(button => {
      button.addEventListener('click', () => {
        const host = button.dataset.trustHostManual;
        const input = statusElement.querySelector(`[data-trust-host-input="${CSS.escape(host)}"]`);
        const fingerprint = input ? input.value.trim() : '';
        if (!fingerprint) {
          window.alert('Enter the host key fingerprint (e.g. SHA256:...) before trusting it.');
          return;
        }
        trustHostKeyAndRetry(host, fingerprint, statusElementId);
      });
    });
  }

  // The single "Saved client action logs" card at the bottom of Deploy >
  // Actions. Every job (Windows, Linux, or mixed "auto" targets) now comes
  // from one list (state.installJobs, populated by loadInstallHistory) -
  // each job's own `mode` field labels its row, newest job first.
  function renderMergedInstallHistory() {
    // A job file saved before this phase shipped has no "mode" key at
    // all (GetStringValue returns "" for a missing key) - this directory
    // only ever held Windows/WinRM job files pre-merge, so a blank mode
    // unambiguously means a legacy Windows job, not "Auto".
    const platformLabel = job => job.mode === 'force-linux' ? 'Linux' : (job.mode === 'auto' ? 'Auto' : 'Windows');
    const entries = (state.installJobs || []).map(job => ({ job, platform: platformLabel(job) }))
      .sort((a, b) => new Date(b.job.createdAt) - new Date(a.job.createdAt));

    const loadError = state.installJobsError;

    if (entries.length === 0) {
      byId('installHistory').classList.add('empty');
      byId('installHistory').textContent = loadError
        ? `Saved client action logs are not available: ${loadError}`
        : 'No saved client action logs.';
      return;
    }

    const errorNotice = loadError
      ? `<p class="cert-hint">Client action logs unavailable: ${escapeHtml(loadError)}</p>`
      : '';

    const rows = entries.map(({ job, platform }) => `<tr>
      <td><small class="platform-tag">${escapeHtml(platform)}</small></td>
      <td><button class="link-button" type="button" data-action-job="${escapeHtml(job.id)}">${escapeHtml(job.id)}</button></td>
      <td>${escapeHtml(job.action || 'install')}</td>
      <td>${escapeHtml(job.status)}</td>
      <td>${escapeHtml(formatDateTime(job.createdAt))}</td>
      <td>${escapeHtml(formatDateTime(job.completedAt))}</td>
      <td>${escapeHtml(job.targetCount)}</td>
      <td>${escapeHtml(job.failedCount)}</td>
      <td>${escapeHtml(job.retentionDays)}</td>
    </tr>`).join('');

    byId('installHistory').classList.remove('empty');
    byId('installHistory').innerHTML = `<h2 class="settings-block-title">Saved client action logs</h2>
      ${errorNotice}
      <div class="install-history-results">
        <table class="nested-table install-history-table">
          <thead><tr><th>Mode</th><th>Job</th><th>Action</th><th>Status</th><th>Started</th><th>Completed</th><th>Targets</th><th>Failed</th><th>Retention</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;

    document.querySelectorAll('[data-action-job]').forEach(button => {
      button.addEventListener('click', () => {
        state.installJobId = button.dataset.actionJob;
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
        state.installJobsError = null;
        renderMergedInstallHistory();
      })
      .catch(error => {
        state.installJobsError = error.message;
        renderMergedInstallHistory();
      });
  }

  function pollInstallJob(jobId, statusElementId = 'installStatus', onComplete = loadInstallHistory, timerKey = 'installPollTimer', onProgress = null) {
    fetch(`/api/v1/client-install/${encodeURIComponent(jobId)}`, { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(job => {
        renderInstallJob(job, statusElementId);
        if (onProgress) onProgress(job);
        if (job.status === 'completed' && state[timerKey]) {
          window.clearInterval(state[timerKey]);
          state[timerKey] = null;
          onComplete();
        }
      })
      .catch(error => {
        byId(statusElementId).textContent = `Install job status is not available: ${error.message}`;
      });
  }

  // Parameterized (not hardcoded to the Linux Client actions page's own
  // element ids) so the Linux Client updates page's own auth-mode selector
  // (Task 10) can reuse this instead of duplicating it - the established
  // pattern this project uses for this exact 3-way-select shape (see
  // updateScheduleFieldVisibility).
  function updateLinuxAuthModeFieldsUi(selectElementId, credentialsUserFieldId, passwordFieldId) {
    const mode = byId(selectElementId).value;
    byId(credentialsUserFieldId).classList.toggle('hidden', mode === 'ad');
    byId(passwordFieldId).classList.toggle('hidden', mode !== 'credentials');
  }

  function updateInstallTrustNewHostKeysUi() {
    const trustChecked = byId('installTrustNewHostKeys').checked;
    byId('installAcknowledgeHostKeyRiskField').classList.toggle('hidden', !trustChecked);
    if (!trustChecked) {
      byId('installAcknowledgeHostKeyRisk').checked = false;
    }
    const acknowledgeChecked = byId('installAcknowledgeHostKeyRisk').checked;
    byId('installButton').disabled = trustChecked && !acknowledgeChecked;
  }

  // The Preferred subnet field on this page and on Client updates both edit
  // the SAME saved server setting (see Settings > Linux > Linux client
  // targeting) - this only pre-fills the current value; saving goes through
  // saveInstallPreferredSubnet below.
  function loadInstallPreferredSubnet() {
    fetch('/api/v1/server/settings', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('installPreferredSubnet').value = data.preferredLinuxSubnet || '';
      })
      .catch(() => {});
  }

  function saveInstallPreferredSubnet() {
    const preferredLinuxSubnet = byId('installPreferredSubnet').value.trim();
    byId('installPreferredSubnetSaveButton').disabled = true;
    fetch('/api/v1/server/settings', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preferredLinuxSubnet })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
      })
      .catch(error => {
        window.alert(`Failed to save preferred subnet: ${error.message}`);
      })
      .finally(() => {
        byId('installPreferredSubnetSaveButton').disabled = false;
      });
  }

  function trustHostKeyAndRetry(host, fingerprint, statusElementId) {
    fetch('/api/v1/linux-client-install/trust-host-key', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, port: 22, fingerprint })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
      .then(({ ok, status, data }) => {
        if (!ok) throw new Error(data.error || `HTTP ${status}`);

        const serverUrl = `${window.location.origin}/api/v1/inventory`;
        const intervalHours = Number(byId('installIntervalHours').value) || 6;
        const statusIntervalMinutes = Number(byId('installStatusIntervalMinutes').value) || 30;
        const installPath = byId('installLinuxPath').value.trim() || '/opt/windows-inventory-lite';
        const sshAuthMode = byId('installSshAuthMode').value;
        const sshUsername = sshAuthMode === 'global' ? '' : byId('installSshUsername').value.trim();
        const sshPassword = sshAuthMode === 'manual' ? byId('installSshPassword').value : '';

        return fetch('/api/v1/client-install', {
          method: 'POST',
          cache: 'no-store',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targets: host, mode: 'force-linux', serverUrl, intervalHours, statusIntervalMinutes, installPath, sshAuthMode, sshUsername, sshPassword, trustNewHostKeys: false, acknowledgeHostKeyRisk: false })
        });
      })
      .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
      .then(({ ok, status, data }) => {
        if (!ok) throw new Error(data.error || `HTTP ${status}`);
        state.installJobId = data.jobId;
        if (state.installPollTimer) window.clearInterval(state.installPollTimer);
        pollInstallJob(state.installJobId);
        state.installPollTimer = window.setInterval(() => pollInstallJob(state.installJobId), 3000);
      })
      .catch(error => {
        byId(statusElementId).textContent = `Trust and retry failed: ${error.message}`;
      });
  }

  // Single source of truth for Deploy > Actions' field visibility - it
  // used to be two independent functions (one for the Install/Uninstall
  // action, one for the Auto/Force Windows/Force Linux mode), but 5
  // fields carry BOTH an .install-only class and a .mode-*-field class,
  // so whichever function ran last silently clobbered the other's
  // decision (found live during Phase 3's final review: the SSH
  // host-key-risk acknowledgement checkbox was visible on a fresh page
  // load, and toggling Action after picking Force Windows could resurrect
  // Linux-only fields and even leave the submit button permanently
  // disabled). One function, one pass, always both inputs.
  function updateInstallFieldVisibility() {
    const isInstall = byId('clientAction').value === 'install';
    const mode = byId('clientActionMode').value;
    document.querySelectorAll('#installView .install-only, #installView .mode-windows-field, #installView .mode-linux-field').forEach(element => {
      const hideByAction = element.classList.contains('install-only') && !isInstall;
      const hideByMode = (element.classList.contains('mode-windows-field') && mode === 'force-linux')
        || (element.classList.contains('mode-linux-field') && mode === 'force-windows');
      element.classList.toggle('hidden', hideByAction || hideByMode);
    });
    byId('installButton').textContent = isInstall ? 'Install client' : 'Uninstall client';
    // "Trust new host keys automatically" is Force Linux only, not Auto -
    // the server rejects the combination outright (bulk-auto-trusting an
    // SSH host key the operator never deliberately identified as Linux,
    // just because it happened to answer on port 22, is a real exposure
    // widening - see StartClientAction's own check). Hidden here on top
    // of the .mode-linux-field pass above, which only ever hides it for
    // Force Windows.
    byId('installTrustNewHostKeysField').classList.toggle('hidden', mode !== 'force-linux');
    // Also reset whenever the field above just got hidden (leaving
    // Install, or leaving Force Linux specifically - not just Force
    // Windows): these two checkboxes have no meaning once hidden, and
    // their .checked state otherwise survives a mode switch invisibly
    // (the checkbox itself being hidden doesn't uncheck it), which is
    // exactly what let a stale "trust new host keys" from a prior Force
    // Linux selection disable the submit button after switching away.
    if (!isInstall || mode !== 'force-linux') {
      byId('installTrustNewHostKeys').checked = false;
      byId('installAcknowledgeHostKeyRisk').checked = false;
    }
    // installWinRmUsernameField/installWinRmPasswordField carry their own
    // credential-source-based visibility rule on top of .mode-windows-field -
    // only re-derive it when the mode pass above didn't already hide them,
    // or a Force Linux selection would get silently re-shown regardless of
    // the (irrelevant) credential source.
    if (mode !== 'force-linux') {
      const winRmManual = byId('installWinRmAuthMode').value === 'manual';
      byId('installWinRmUsernameField').classList.toggle('hidden', !winRmManual);
      byId('installWinRmPasswordField').classList.toggle('hidden', !winRmManual);
    }
    // Same idea for installSshCredentialsField/installSshPasswordField,
    // now driven by the three-way Global/Manual/SSH key dropdown instead
    // of the old ad/credentials/key one - Global shows neither field,
    // Manual shows both, SSH key shows only the username.
    if (mode !== 'force-windows') {
      const sshMode = byId('installSshAuthMode').value;
      byId('installSshCredentialsField').classList.toggle('hidden', sshMode === 'global');
      byId('installSshPasswordField').classList.toggle('hidden', sshMode !== 'manual');
    }
    updateInstallTrustNewHostKeysUi();
  }

  // "Use global AD settings" substitutes the typed/saved Client Update account
  // with the AD sync credentials already configured in Settings > Windows.
  function updateUpdatesCredentialFieldsUi() {
    const useAd = byId('updatesUseAdCredentials').checked;
    byId('updatesUsername').disabled = useAd;
    byId('updatesPassword').disabled = useAd;
  }

  function loadLinuxUpdateCredentials() {
    fetch('/api/v1/linux-client-updates/credentials', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('linuxCredsUsername').value = data.username || '';
        applyPasswordPlaceholder('linuxCredsPassword', !!data.hasPassword, 'leave blank to keep the current one');
        byId('linuxSshKeyStatus').textContent = data.hasStoredKey
          ? `Key configured, uploaded ${formatDateTime(data.keyUploadedAtUtc)}`
          : 'No key configured.';
        byId('linuxSshKeyDeleteButton').disabled = !data.hasStoredKey;
      })
      .catch(error => {
        showSavedMessage(byId('linuxCredsMessage'), `Status unavailable: ${error.message}`, true);
        byId('linuxSshKeyStatus').textContent = 'Status unavailable.';
        byId('linuxSshKeyDeleteButton').disabled = true;
      });
  }

  function loadLinuxSshToolsStatus() {
    fetch('/api/v1/server/linux-ssh-tools-status', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        const statusElement = byId('linuxSshToolsStatus');
        if (data.plinkFound && data.pscpFound) {
          statusElement.textContent = 'plink.exe/pscp.exe found - password-based SSH push is available. Key-based push works regardless.';
        } else {
          statusElement.textContent = 'plink.exe/pscp.exe not found - password-based SSH push will fail. See deploy\\linux-client\\NOTICE for how to obtain them. Key-based push works regardless.';
        }
      })
      .catch(error => {
        byId('linuxSshToolsStatus').textContent = `SSH tools status unavailable: ${error.message}`;
      });
  }

  function saveLinuxUpdateCredentials() {
    const username = byId('linuxCredsUsername').value.trim();
    const password = byId('linuxCredsPassword').value;

    byId('linuxCredsSaveButton').disabled = true;
    fetch('/api/v1/linux-client-updates/credentials', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        byId('linuxCredsPassword').value = '';
        showSavedMessage(byId('linuxCredsMessage'), 'Saved.', false);
      })
      .catch(error => {
        showSavedMessage(byId('linuxCredsMessage'), `Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('linuxCredsSaveButton').disabled = false;
      });
  }

  function clearLinuxUpdateCredentials() {
    const confirmed = window.confirm('Delete the saved Linux update username/password?');
    if (!confirmed) return;

    byId('linuxCredsClearButton').disabled = true;
    fetch('/api/v1/linux-client-updates/credentials', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clear: true })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Delete failed');
        byId('linuxCredsUsername').value = '';
        byId('linuxCredsPassword').value = '';
        showSavedMessage(byId('linuxCredsMessage'), 'Deleted.', false);
      })
      .catch(error => {
        showSavedMessage(byId('linuxCredsMessage'), `Delete failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('linuxCredsClearButton').disabled = false;
      });
  }

  function uploadLinuxSshKey() {
    const fileInput = byId('linuxSshKeyFile');
    const file = fileInput.files && fileInput.files[0];

    if (!file) {
      window.alert('Choose a private key file.');
      return;
    }

    byId('linuxSshKeyUploadButton').disabled = true;
    byId('linuxSshKeyMessage').className = 'pkg-message hidden';

    fileToBase64(file)
      .then(keyBase64 => fetch('/api/v1/server/linux-ssh-key', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyBase64 })
      }))
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Upload failed');
        fileInput.value = '';
        loadLinuxUpdateCredentials();
        const risks = data.risks || [];
        const el = byId('linuxSshKeyMessage');
        el.textContent = risks.length
          ? `Key uploaded with ${risks.length} risk(s): ${risks.join(' ')}`
          : 'Key uploaded.';
        el.className = 'pkg-message' + (risks.length ? ' error' : '');
      })
      .catch(error => {
        const el = byId('linuxSshKeyMessage');
        el.textContent = `Upload failed: ${error.message}`;
        el.className = 'pkg-message error';
      })
      .finally(() => {
        byId('linuxSshKeyUploadButton').disabled = false;
      });
  }

  function deleteLinuxSshKey() {
    const confirmed = window.confirm('Delete the configured SSH key? Pushes using "SSH key" auth mode will fail until a new key is uploaded.');
    if (!confirmed) return;

    byId('linuxSshKeyDeleteButton').disabled = true;
    fetch('/api/v1/server/linux-ssh-key', { method: 'DELETE', cache: 'no-store' })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Delete failed');
        loadLinuxUpdateCredentials();
        const el = byId('linuxSshKeyMessage');
        el.textContent = 'Key deleted.';
        el.className = 'pkg-message';
      })
      .catch(error => {
        const el = byId('linuxSshKeyMessage');
        el.textContent = `Delete failed: ${error.message}`;
        el.className = 'pkg-message error';
      })
      .finally(() => {
        byId('linuxSshKeyDeleteButton').disabled = false;
      });
  }

  // onlyMissing=false: every AD computer in the configured scope.
  // onlyMissing=true: the same AD list, filtered (client-side, against the
  // already-loaded state.clients) down to computers with no reporting
  // client yet - no new server endpoint needed, both buttons share the
  // exact same GET /api/v1/ad/computers call and its warnings/error
  // handling.
  function loadTargetsFromAd(onlyMissing) {
    const messageElement = byId('installAdMessage');
    byId('installLoadAdAllButton').disabled = true;
    byId('installLoadAdMissingButton').disabled = true;

    fetch('/api/v1/ad/computers', { cache: 'no-store' })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'AD search failed');

        let computers = data.computers || [];
        const warnings = data.warnings || [];
        const totalFound = computers.length;

        if (onlyMissing) {
          const known = new Set(getAllClients().map(c => (clientDisplayName(c) || '').toLowerCase()));
          computers = computers.filter(name => !known.has(name.toLowerCase()));
        }

        if (computers.length === 0) {
          const noneMessage = onlyMissing && totalFound > 0
            ? 'Every computer in the configured scope already has a reporting client.'
            : 'No computers found for the configured scope.';
          const lines = [noneMessage, ...warnings];
          showSavedMessage(messageElement, lines.join('\n'), false);
          return;
        }

        byId('installTargets').value = computers.join('\n');
        const loadedMessage = onlyMissing
          ? `Loaded ${computers.length} computer(s) without a reporting client (${totalFound} total in scope).`
          : `Loaded ${computers.length} computer(s) from AD.`;
        const lines = [loadedMessage, ...warnings];
        showSavedMessage(messageElement, lines.join('\n'), false);
      })
      .catch(error => {
        showSavedMessage(messageElement, `Failed to load from AD: ${error.message}`, true);
      })
      .finally(() => {
        byId('installLoadAdAllButton').disabled = false;
        byId('installLoadAdMissingButton').disabled = false;
      });
  }

  function startClientActionJob() {
    const action = byId('clientAction').value;
    const mode = byId('clientActionMode').value;
    const targets = byId('installTargets').value.trim();
    // Server URL and Ingestion token are no longer editable fields (removed
    // 2026-08-21) - always the server's own live values. serverUrl is
    // computed the same way the old auto-fill init code always did; token
    // is simply omitted from the payload, and the server already treats a
    // missing/blank token as "use the current live one".
    const serverUrl = `${window.location.origin}/api/v1/inventory`;
    const winRmAuthMode = byId('installWinRmAuthMode').value;
    // Blank whenever the field is hidden too (mode === 'force-linux'),
    // not just when the credential-source dropdown itself says not to use
    // it - a typed value from an earlier mode/dropdown selection survives
    // a mode switch invisibly (the field being hidden doesn't clear it),
    // and would otherwise still ride along on the wire on a submit the
    // server discards it for anyway. Nothing is stored/logged server-side
    // either way, but there's no reason to send it.
    const username = (mode !== 'force-linux' && winRmAuthMode === 'manual') ? byId('installUsername').value.trim() : '';
    const password = (mode !== 'force-linux' && winRmAuthMode === 'manual') ? byId('installPassword').value : '';
    const force = byId('installForce').checked;
    const addToTrustedHosts = byId('installTrustedHosts').checked;
    const sshAuthMode = byId('installSshAuthMode').value;
    const sshUsername = (mode !== 'force-windows' && sshAuthMode !== 'global') ? byId('installSshUsername').value.trim() : '';
    const sshPassword = (mode !== 'force-windows' && sshAuthMode === 'manual') ? byId('installSshPassword').value : '';
    const intervalHours = Number(byId('installIntervalHours').value) || 6;
    const statusIntervalMinutes = Number(byId('installStatusIntervalMinutes').value) || 30;
    const installPath = byId('installLinuxPath').value.trim() || '/opt/windows-inventory-lite';
    const trustNewHostKeys = action === 'install' && byId('installTrustNewHostKeys').checked;
    const acknowledgeHostKeyRisk = action === 'install' && byId('installAcknowledgeHostKeyRisk').checked;

    if (!targets) {
      window.alert('Enter at least one target.');
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
      body: JSON.stringify({ targets, mode, serverUrl, winRmAuthMode, username, password, force, addToTrustedHosts, sshAuthMode, sshUsername, sshPassword, intervalHours, statusIntervalMinutes, installPath, trustNewHostKeys, acknowledgeHostKeyRisk })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
      .then(({ ok, status, data }) => {
        if (!ok) throw new Error(data.error || `HTTP ${status}`);
        return data;
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
        updateInstallTrustNewHostKeysUi();
      });
  }

  function loadClientUpdates() {
    fetch('/api/v1/client-updates', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.clientUpdates = data;
        renderMergedUpdatesTable();
        updateUpdatesBadge(data.packageAvailable ? data.outdatedCount : 0);
      })
      .catch(error => {
        byId('updatesPackageStatus').textContent = `Client update status unavailable: ${error.message}`;
      });
  }

  function formatAvailableVersion(data) {
    if (data.net35Version && data.net40Version && data.net35Version !== data.net40Version) {
      return `net35 v${escapeHtml(data.net35Version)} / net40 v${escapeHtml(data.net40Version)}`;
    }
    const version = data.net35Version || data.net40Version;
    return version ? `v${escapeHtml(version)}` : 'unknown';
  }

  // Merges state.clientUpdates (Windows) and state.linuxClientUpdates
  // (Linux) into one row set, each entry stamped with .platform the same
  // way stampClientPlatform does for state.clients/state.linuxClients -
  // the merged "Update selected" push (Task 3) reads this stamp to decide
  // which protocol/credentials a checked row needs, never inferring it
  // from row content (see clientPlatformLabel's own doc comment on why).
  function stampUpdatePlatform(entries, platform) {
    entries.forEach(entry => { entry.platform = platform; });
    return entries;
  }

  function updateSortValue(entry, key) {
    switch (key) {
      case 'computerName': return (entry.computerName || entry.hostname || '').toLowerCase();
      case 'domain': return (entry.domain || '').toLowerCase();
      case 'clientVersion': return (entry.clientVersion || '').toLowerCase();
      case 'collectedAt': return entry.collectedAt || entry.sourceUpdatedAt || '';
      default: return '';
    }
  }

  function renderMergedUpdatesTable() {
    renderSortHeaders();

    const windowsData = state.clientUpdates;
    const linuxData = state.linuxClientUpdates;
    const windowsAvailable = windowsData && windowsData.packageAvailable;
    const linuxAvailable = linuxData && linuxData.packageAvailable;

    if (!windowsData || !linuxData) {
      byId('updatesPackageStatus').textContent = 'Loading client update status...';
      return;
    }

    const statusParts = [];
    statusParts.push(windowsAvailable
      ? `Windows package: ${formatAvailableVersion(windowsData)} (${windowsData.outdatedCount} outdated)`
      : 'No Windows client package uploaded yet - build or deploy one on Deploy > Package.');
    statusParts.push(linuxAvailable
      ? `Linux package: v${escapeHtml(linuxData.currentVersion)} (${linuxData.outdatedCount} outdated)`
      : 'No Linux client package uploaded yet - build one on Deploy > Package.');
    byId('updatesPackageStatus').textContent = statusParts.join('. ') + '.';

    let entries = []
      .concat(windowsAvailable ? stampUpdatePlatform(windowsData.updates || [], 'windows') : [])
      .concat(linuxAvailable ? stampUpdatePlatform(linuxData.updates || [], 'linux') : []);

    const filter = state.osFilter.deploy || 'all';
    if (filter !== 'all') entries = entries.filter(e => e.platform === filter);

    if (entries.length === 0) {
      byId('updatesBody').innerHTML = '<tr><td colspan="6" class="empty">Every reporting client is up to date.</td></tr>';
      byId('updatesPager').innerHTML = '';
      return;
    }

    const { key: sortKey, dir: sortDir } = state.sort.updates;
    const sorted = applySort(entries, e => updateSortValue(e, sortKey), sortDir);
    const { items: pageItems, page, totalPages } = paginate(sorted, state.page.updates, state.pageSize.updates);
    state.page.updates = page;

    byId('updatesBody').innerHTML = pageItems.map(entry => {
      const isWindows = entry.platform === 'windows';
      const target = isWindows ? entry.computerName : (entry.target || entry.hostname);
      const availableVersion = isWindows ? formatAvailableVersion(windowsData) : `v${escapeHtml(linuxData.currentVersion)}`;
      const collectedAt = isWindows ? entry.collectedAt : entry.sourceUpdatedAt;
      return `<tr>
        <td>${escapeHtml(entry.computerName || entry.hostname)}</td>
        <td>${isWindows ? escapeHtml(entry.domain) : '—'}</td>
        <td>${escapeHtml(entry.clientVersion || 'Unknown')}</td>
        <td>${availableVersion}</td>
        <td>${escapeHtml(formatDateTime(collectedAt))}</td>
        <td><input type="checkbox" class="updates-row-checkbox" data-platform="${entry.platform}" data-target="${escapeHtml(target)}"></td>
      </tr>`;
    }).join('');

    renderPager('updatesPager', 'updates', page, totalPages, renderMergedUpdatesTable);
    updateUpdatesSelectionState();
  }

  function loadLinuxClientUpdates() {
    fetch('/api/v1/linux-client-updates', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        state.linuxClientUpdates = data;
        byId('linuxUpdatesPreferredSubnet').value = data.preferredLinuxSubnet || '';
        renderMergedUpdatesTable();
        updateLinuxUpdatesBadge(data.packageAvailable ? data.outdatedCount : 0);
      })
      .catch(error => {
        byId('updatesPackageStatus').textContent = `Client update status unavailable: ${error.message}`;
      });
  }

  // Saves the SAME server setting Client actions' own field and Settings >
  // Linux > Linux client targeting edit - reloading afterward re-resolves
  // every outdated client's push target (entry.target, the hidden checkbox
  // value in the table below) using the newly saved preference.
  function saveLinuxUpdatesPreferredSubnet() {
    const preferredLinuxSubnet = byId('linuxUpdatesPreferredSubnet').value.trim();
    byId('linuxUpdatesPreferredSubnetSaveButton').disabled = true;
    fetch('/api/v1/server/settings', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preferredLinuxSubnet })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        showSavedMessage(byId('linuxUpdatesPreferredSubnetMessage'), 'Saved.', false);
        loadLinuxClientUpdates();
      })
      .catch(error => {
        showSavedMessage(byId('linuxUpdatesPreferredSubnetMessage'), `Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('linuxUpdatesPreferredSubnetSaveButton').disabled = false;
      });
  }

  function updateLinuxUpdatesBadge(count) {
    const badge = byId('linuxUpdatesBadge');
    if (count > 0) {
      badge.textContent = String(count);
      badge.classList.remove('hidden');
    } else {
      badge.classList.add('hidden');
    }
  }

  // Badge-only counterpart to handleClientUpdatesSummary (Windows), used by
  // the dedicated fetches in pollForUpdates() and the initial page load -
  // updates just the Manage dropdown count, without the full loadLinuxClientUpdates()/
  // renderMergedUpdatesTable() table rebuild.
  function handleLinuxClientUpdatesSummary(data) {
    updateLinuxUpdatesBadge(data.packageAvailable ? data.outdatedCount : 0);
  }

  function updateLinuxUpdatesPushButtonState() {
    const anyChecked = document.querySelectorAll('.linux-update-select:checked').length > 0;
    const trustChecked = byId('linuxUpdatesTrustNewHostKeys').checked;
    const acknowledgeChecked = byId('linuxUpdatesAcknowledgeHostKeyRisk').checked;
    byId('linuxUpdatesPushButton').disabled = !anyChecked || (trustChecked && !acknowledgeChecked);
  }

  // Mirrors updateInstallTrustNewHostKeysUi (Deploy > Actions) - same
  // pairing (risk-ack field only shown/required once "trust new host keys"
  // is checked), reusing this panel's own combined button-state function
  // instead of a bare disabled=false so the trust/ack pairing is still
  // enforced client-side after the checkbox toggles.
  function updateLinuxUpdatesTrustNewHostKeysUi() {
    const trustChecked = byId('linuxUpdatesTrustNewHostKeys').checked;
    byId('linuxUpdatesAcknowledgeHostKeyRiskField').classList.toggle('hidden', !trustChecked);
    if (!trustChecked) {
      byId('linuxUpdatesAcknowledgeHostKeyRisk').checked = false;
    }
    updateLinuxUpdatesPushButtonState();
  }

  function startLinuxUpdatesPush() {
    const selected = Array.from(document.querySelectorAll('.linux-update-select:checked')).map(cb => cb.value);
    if (selected.length === 0) return;

    const sshAuthMode = byId('linuxUpdatesAuthMode').value;
    const sshUsername = sshAuthMode === 'ad' ? '' : byId('linuxUpdatesUsername').value.trim();
    const sshPassword = sshAuthMode === 'credentials' ? byId('linuxUpdatesPassword').value : '';
    const trustNewHostKeys = byId('linuxUpdatesTrustNewHostKeys').checked;
    const acknowledgeHostKeyRisk = byId('linuxUpdatesAcknowledgeHostKeyRisk').checked;
    byId('linuxUpdatesPushButton').disabled = true;
    byId('linuxUpdatesStatus').classList.add('empty');
    byId('linuxUpdatesStatus').textContent = 'Starting update job...';

    fetch('/api/v1/client-install', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets: selected.join('\n'), mode: 'force-linux', sshAuthMode, sshUsername, sshPassword, trustNewHostKeys, acknowledgeHostKeyRisk })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
      .then(({ ok, status, data }) => {
        if (!ok) throw new Error(data.error || `HTTP ${status}`);
        return data;
      })
      .then(data => {
        state.linuxUpdatesJobId = data.jobId;
        if (state.linuxUpdatesPollTimer) window.clearInterval(state.linuxUpdatesPollTimer);
        pollInstallJob(state.linuxUpdatesJobId, 'linuxUpdatesStatus', loadLinuxClientUpdates, 'linuxUpdatesPollTimer');
        state.linuxUpdatesPollTimer = window.setInterval(() => pollInstallJob(state.linuxUpdatesJobId, 'linuxUpdatesStatus', loadLinuxClientUpdates, 'linuxUpdatesPollTimer'), 3000);
      })
      .catch(error => {
        byId('linuxUpdatesStatus').textContent = `Failed to start update job: ${error.message}`;
      })
      .finally(() => {
        updateLinuxUpdatesPushButtonState();
      });
  }

  function updateLinuxUpdatesScheduleFieldVisibility() {
    const mode = byId('linuxUpdatesScheduleMode').value;
    byId('linuxUpdatesScheduleOnceField').classList.toggle('hidden', mode !== 'once');
    byId('linuxUpdatesScheduleIntervalField').classList.toggle('hidden', mode !== 'interval');
  }

  function loadLinuxUpdateSchedule() {
    fetch('/api/v1/linux-client-updates/schedule', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('linuxUpdatesScheduleMode').value = data.mode || 'off';
        if (data.onceAtUtc) byId('linuxUpdatesScheduleOnceAt').value = data.onceAtUtc.slice(0, 16);
        byId('linuxUpdatesScheduleIntervalHours').value = data.intervalHours || 24;
        updateLinuxUpdatesScheduleFieldVisibility();
      })
      .catch(error => {
        showSavedMessage(byId('linuxUpdatesScheduleMessage'), `Schedule status unavailable: ${error.message}`, true);
      });
  }

  function saveLinuxUpdateSchedule() {
    const mode = byId('linuxUpdatesScheduleMode').value;
    const body = { mode };
    if (mode === 'once') {
      body.onceAtUtc = byId('linuxUpdatesScheduleOnceAt').value;
    }
    if (mode === 'interval') {
      body.intervalHours = Number(byId('linuxUpdatesScheduleIntervalHours').value) || 24;
    }

    byId('linuxUpdatesScheduleSaveButton').disabled = true;
    fetch('/api/v1/linux-client-updates/schedule', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        showSavedMessage(byId('linuxUpdatesScheduleMessage'), 'Saved.', false);
      })
      .catch(error => {
        showSavedMessage(byId('linuxUpdatesScheduleMessage'), `Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('linuxUpdatesScheduleSaveButton').disabled = false;
      });
  }

  // Shared by the initial page-load badge fetch and pollForUpdates()'s own
  // badge fetch. A scheduled push runs entirely server-side (the timer
  // calls StartScheduledClientUpdatePush directly, no HTTP request from
  // any browser involved) - lastScheduledJobId is how an open dashboard
  // tab learns that happened at all. Only reacts if the Client updates tab
  // is the active view and no other update push is already being polled
  // (a manually-started push in progress takes priority - never hijack it).
  function handleClientUpdatesSummary(data) {
    updateUpdatesBadge(data.packageAvailable ? data.outdatedCount : 0);

    const scheduledJobId = data.lastScheduledJobId || null;
    if (state.knownScheduledJobId === undefined) {
      state.knownScheduledJobId = scheduledJobId;
      return;
    }
    if (scheduledJobId && scheduledJobId !== state.knownScheduledJobId) {
      state.knownScheduledJobId = scheduledJobId;
      if (state.view === 'deploy' && state.subview === 'updates' && !state.updatePollTimer) {
        state.updateJobId = scheduledJobId;
        pollInstallJob(state.updateJobId, 'updatesStatus', () => loadClientUpdates(), 'updatePollTimer', pruneCompletedUpdateTargets);
        state.updatePollTimer = window.setInterval(() => pollInstallJob(state.updateJobId, 'updatesStatus', () => loadClientUpdates(), 'updatePollTimer', pruneCompletedUpdateTargets), 3000);
      }
    }
  }

  function updateUpdatesBadge(outdatedCount) {
    const badge = byId('updatesBadge');
    if (outdatedCount > 0) {
      badge.textContent = String(outdatedCount);
      badge.classList.remove('hidden');
    } else {
      badge.classList.add('hidden');
    }
  }

  // Every settings panel's "Save" success message used to stay visible
  // forever once shown - only a subsequent save action overwrote it. Error
  // messages are left alone (they should stay until the underlying problem
  // is addressed); a success message auto-hides after 30s. Tracks its own
  // pending timer per element so repeated saves don't stack timers.
  const savedMessageTimers = new WeakMap();

  function showSavedMessage(el, msg, isError) {
    const existingTimer = savedMessageTimers.get(el);
    if (existingTimer) {
      window.clearTimeout(existingTimer);
      savedMessageTimers.delete(el);
    }
    el.textContent = msg;
    el.className = 'pkg-message' + (isError ? ' error' : '');
    if (!isError) {
      savedMessageTimers.set(el, window.setTimeout(() => {
        el.classList.add('hidden');
        savedMessageTimers.delete(el);
      }, 30000));
    }
  }

  // Failed Description saves show a short inline error next to the input,
  // matching the dashboard's existing showSavedMessage pattern - but a
  // table cell's input has no pre-existing message element to reuse (unlike
  // Settings forms), so one is created on demand, right after the input.
  function showDescriptionSaveError(input, message) {
    let errorEl = input.nextElementSibling;
    if (!errorEl || !errorEl.classList.contains('description-save-error')) {
      errorEl = document.createElement('small');
      errorEl.className = 'description-save-error';
      input.insertAdjacentElement('afterend', errorEl);
    }
    const existingTimer = savedMessageTimers.get(errorEl);
    if (existingTimer) {
      window.clearTimeout(existingTimer);
      savedMessageTimers.delete(errorEl);
    }
    errorEl.textContent = message;
    savedMessageTimers.set(errorEl, window.setTimeout(() => {
      errorEl.remove();
      savedMessageTimers.delete(errorEl);
    }, 30000));
  }

  // Saves an inline Description edit. Only fires on an actual change
  // (skips a no-op save when a field loses focus unmodified). Reverts the
  // input to the last known-good value on failure, since a stale client-
  // side value (e.g. after AD Description Sync was re-enabled in another
  // tab between render and save) would otherwise silently diverge from
  // what the server actually has.
  function saveClientDescription(input) {
    const computerName = input.dataset.computerName;
    const newValue = input.value;
    if (newValue === input.dataset.lastSavedValue) return;

    const isLinux = input.dataset.platform === 'linux';
    const endpoint = isLinux
      ? `/api/v1/linux/clients/${encodeURIComponent(computerName)}/description`
      : `/api/v1/clients/${encodeURIComponent(computerName)}/description`;

    input.disabled = true;
    fetch(endpoint, {
      method: 'PUT',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: newValue })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        input.dataset.lastSavedValue = data.description;
        const list = isLinux ? (state.linuxClients || []) : (state.clients || []);
        const key = isLinux ? 'hostname' : 'computerName';
        const client = list.find(c => c[key] === computerName);
        if (client) client.adDescription = data.description;
      })
      .catch(error => {
        input.value = input.dataset.lastSavedValue || '';
        showDescriptionSaveError(input, error.message);
      })
      .finally(() => {
        input.disabled = false;
      });
  }

  function loadClientUpdateCredentials() {
    // The username/password push fields are never pre-filled from the saved
    // account: a form that looks empty but silently carries a stale
    // username (with a genuinely blank password) would send a mismatched
    // credential pair to WinRM instead of either the saved pair or the
    // service identity. This hint is display-only.
    const hint = byId('updatesSavedAccountHint');
    fetch('/api/v1/client-updates/credentials', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        if (data.username) {
          hint.textContent = `Saved account: ${data.username}`;
          hint.classList.remove('hidden');
        } else {
          hint.classList.add('hidden');
        }
        applyPasswordPlaceholder('updatesPassword', !!data.hasPassword, 'leave blank to keep the current one');
      })
      .catch(() => {});
  }

  function saveClientUpdateCredentials() {
    const username = byId('updatesUsername').value.trim();
    const password = byId('updatesPassword').value;
    const messageElement = byId('updatesCredentialsMessage');

    byId('updatesSaveCredentialsButton').disabled = true;
    fetch('/api/v1/client-updates/credentials', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(() => {
        // Clear both fields, not just password: leaving the typed username
        // behind paired with the just-cleared password reproduces the exact
        // mismatched-pair bug fixed in 0.16.6 (real login + blank password
        // sent straight to WinRM) the moment "Update selected" is clicked
        // right after "Save" without retyping anything.
        byId('updatesUsername').value = '';
        byId('updatesPassword').value = '';
        showSavedMessage(messageElement, 'Saved.', false);
        loadClientUpdateCredentials();
      })
      .catch(error => {
        showSavedMessage(messageElement, `Failed to save: ${error.message}`, true);
      })
      .finally(() => {
        byId('updatesSaveCredentialsButton').disabled = false;
      });
  }

  function clearClientUpdateCredentials() {
    const messageElement = byId('updatesCredentialsMessage');

    byId('updatesClearCredentialsButton').disabled = true;
    fetch('/api/v1/client-updates/credentials', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clear: true })
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(() => {
        byId('updatesUsername').value = '';
        byId('updatesPassword').value = '';
        byId('updatesSavedAccountHint').classList.add('hidden');
        showSavedMessage(messageElement, 'Saved credentials deleted.', false);
      })
      .catch(error => {
        showSavedMessage(messageElement, `Failed to delete: ${error.message}`, true);
      })
      .finally(() => {
        byId('updatesClearCredentialsButton').disabled = false;
      });
  }

  // pollInstallJob's onComplete only fires once the whole job finishes -
  // for a batch push to many machines, the outdated-clients table
  // (#updatesBody) previously stayed unchanged until every target was
  // done, even though job.results already grows one entry per target as
  // each one finishes (RunClientActionJob appends and saves after each
  // target, run sequentially). This removes a target's row as soon as
  // ITS OWN result shows up as a success, without waiting for the batch.
  // A failed target is deliberately left in the table - it's still
  // outdated and may need a retry.
  function pruneCompletedUpdateTargets(job) {
    const results = job.results || [];
    const completedTargets = new Set(results.filter(result => result.status === 'completed').map(result => result.target));
    if (completedTargets.size === 0) return;

    document.querySelectorAll('.updates-row-checkbox').forEach(checkbox => {
      if (completedTargets.has(checkbox.dataset.computerName)) {
        checkbox.closest('tr').remove();
      }
    });
    updateUpdatesSelectionState();

    if (!document.querySelector('.updates-row-checkbox')) {
      byId('updatesBody').innerHTML = '<tr><td colspan="6" class="empty">Every reporting client is up to date.</td></tr>';
    }
  }

  function updateUpdatesSelectionState() {
    const checkboxes = Array.from(document.querySelectorAll('.updates-row-checkbox'));
    const anyChecked = checkboxes.some(checkbox => checkbox.checked);
    byId('updatesPushButton').disabled = !anyChecked;
  }

  function startClientUpdateJob() {
    const targets = Array.from(document.querySelectorAll('.updates-row-checkbox:checked'))
      .map(checkbox => checkbox.dataset.computerName);
    if (targets.length === 0) return;

    // Both fields are normally empty here: loadClientUpdateCredentials only
    // ever shows the saved username as a read-only hint, never into these
    // inputs (a pre-filled username paired with an always-blank password
    // would send a mismatched credential pair to WinRM). useSavedCredentials:
    // true below tells the server "if both fields are blank, use the saved
    // account instead of the service identity" - typing a fresh
    // username+password here still overrides that for this one push,
    // matching Client actions' per-action behavior.
    const useAdCredentials = byId('updatesUseAdCredentials').checked;
    const username = useAdCredentials ? '' : byId('updatesUsername').value.trim();
    const password = useAdCredentials ? '' : byId('updatesPassword').value;
    // Same computed value Deploy > Actions now uses inline (Task 3, 2026-08-24)
    // - the Server URL field this used to read from was removed.
    const serverUrl = `${window.location.origin}/api/v1/inventory`;

    byId('updatesPushButton').disabled = true;
    byId('updatesStatus').classList.add('empty');
    byId('updatesStatus').textContent = 'Starting update job...';

    fetch('/api/v1/client-install', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets: targets.join('\n'), mode: 'force-windows', serverUrl, username, password, force: false, addToTrustedHosts: false, useSavedCredentials: true, useAdCredentials })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
      .then(({ ok, status, data }) => {
        if (!ok) throw new Error(data.error || `HTTP ${status}`);
        return data;
      })
      .then(data => {
        state.updateJobId = data.jobId;
        if (state.updatePollTimer) window.clearInterval(state.updatePollTimer);
        pollInstallJob(state.updateJobId, 'updatesStatus', () => loadClientUpdates(), 'updatePollTimer', pruneCompletedUpdateTargets);
        state.updatePollTimer = window.setInterval(() => pollInstallJob(state.updateJobId, 'updatesStatus', () => loadClientUpdates(), 'updatePollTimer', pruneCompletedUpdateTargets), 3000);
      })
      .catch(error => {
        byId('updatesStatus').textContent = `Failed to start update job: ${error.message}`;
      })
      .finally(() => {
        byId('updatesPushButton').disabled = false;
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
        byId('pkgSharePath').value = data.cmdPackageSharePath || '';
        // Only pre-fill from the last-built package's own baked-in token if
        // it still matches the server's current live token - otherwise a
        // regenerate leaves this field silently showing a stale value that
        // looks correct but isn't, and resubmitting it would also defeat
        // ResolveEffectiveToken's blank-means-use-live-token fallback
        // (Task 3), since the field would never actually be blank.
        if (data.cmdToken) {
          fetch('/api/v1/server/ingestion-token', { cache: 'no-store' })
            .then(response => (response.ok ? response.json() : null))
            .then(tokenStatus => {
              if (tokenStatus && tokenStatus.token === data.cmdToken) {
                byId('pkgToken').value = data.cmdToken;
              }
            })
            .catch(() => {});
        }
      })
      .catch(error => {
        byId('pkgStatus').textContent = `Package status unavailable: ${error.message}`;
      });
  }

  function loadLinuxPackageStatus() {
    fetch('/api/v1/linux-client-package', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        const statusText = data.binaryPresent
          ? `Linux client binary present (v${escapeHtml(data.binaryVersion || 'unknown')}).`
          : 'No Linux client binary found - run Build-LinuxClient.ps1 and place the output in the Linux client package directory first.';
        byId('linuxPkgStatus').textContent = statusText;
        // Only overwrite the auto-filled default (see the init-time
        // window.location.origin assignment) when the server actually has
        // a saved value - an unconditional assignment here would blank the
        // field with '' on every page load until something is saved once,
        // same guard as loadPackageStatus's Windows pkgServerUrl above.
        if (data.serverUrl) byId('linuxPkgServerUrl').value = data.serverUrl;
        byId('linuxPkgIntervalHours').value = data.intervalHours || 6;
        byId('linuxPkgStatusIntervalMinutes').value = data.statusIntervalMinutes || 30;
        byId('linuxPkgInstallPath').value = data.installPath || '/opt/windows-inventory-lite';
        // Only pre-fill from the last-saved settings' token if it still
        // matches the server's current live token - see the identical
        // guard in loadPackageStatus for why a stale baked token must
        // never silently resurface here.
        if (data.token) {
          fetch('/api/v1/server/ingestion-token', { cache: 'no-store' })
            .then(response => (response.ok ? response.json() : null))
            .then(tokenStatus => {
              if (tokenStatus && tokenStatus.token === data.token) {
                byId('linuxPkgToken').value = data.token;
              }
            })
            .catch(() => {});
        }
      })
      .catch(error => {
        byId('linuxPkgStatus').textContent = `Linux package status unavailable: ${error.message}`;
      });
  }

  function saveLinuxPackageConfig() {
    const serverUrl = byId('linuxPkgServerUrl').value.trim();
    const token = byId('linuxPkgToken').value.trim();
    const intervalHours = Number(byId('linuxPkgIntervalHours').value) || 6;
    const statusIntervalMinutes = Number(byId('linuxPkgStatusIntervalMinutes').value) || 30;
    const installPath = byId('linuxPkgInstallPath').value.trim() || '/opt/windows-inventory-lite';

    if (!serverUrl) {
      window.alert('Enter server URL.');
      return;
    }

    byId('linuxPkgSaveButton').disabled = true;
    fetch('/api/v1/linux-client-package/configure', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serverUrl, token, intervalHours, statusIntervalMinutes, installPath })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        showSavedMessage(byId('linuxPkgMessage'), 'Saved.', false);
        loadLinuxPackageStatus();
      })
      .catch(error => {
        showSavedMessage(byId('linuxPkgMessage'), `Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('linuxPkgSaveButton').disabled = false;
      });
  }

  function renderPackageStatus(data) {
    const parts = [];
    const versionPart = (label, present, version) => {
      if (!present) return null;
      return `${label}: v${escapeHtml(version || 'unknown')}`;
    };
    const net35Part = versionPart('Net 3.5', data.net35Present, data.net35Version);
    const net40Part = versionPart('Net 4.0', data.net40Present, data.net40Version);
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
    showSavedMessage(byId('pkgMessage'), msg, isError);
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
      data.useHttps ? 'HTTPS: enabled' : 'HTTPS: disabled (configured but not active - turn on in Settings > Server)',
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
            ? `Certificate uploaded with ${risks.length} risk(s): ${risks.join(' ')} Enable HTTPS from Settings > Server when ready.`
            : 'Certificate uploaded. Enable HTTPS from Settings > Server when ready.',
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

  function updateAdSyncIntervalField() {
    const isTimerMode = byId('generalAdSyncMode').value === 'timer';
    byId('generalAdSyncIntervalField').classList.toggle('hidden', !isTimerMode);
  }

  function updateScheduleFieldVisibility() {
    const mode = byId('updatesScheduleMode').value;
    byId('updatesScheduleOnceField').classList.toggle('hidden', mode !== 'once');
    byId('updatesScheduleIntervalField').classList.toggle('hidden', mode !== 'interval');
  }

  // datetime-local inputs work in the browser's local time with no
  // timezone in the string - Date's own constructor/toISOString correctly
  // round-trip that local-time string against the server's UTC storage, so
  // no manual timezone math is needed here.
  function toDatetimeLocalValue(date) {
    const pad = n => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function loadClientUpdateSchedule() {
    fetch('/api/v1/client-updates/schedule', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('updatesScheduleMode').value = data.mode || 'off';
        byId('updatesScheduleOnceAt').value = data.onceAtUtc ? toDatetimeLocalValue(new Date(data.onceAtUtc)) : '';
        byId('updatesScheduleIntervalHours').value = data.intervalHours || 24;
        byId('updatesScheduleCredentialWarning').classList.toggle('hidden', !!data.hasSavedCredentials);
        updateScheduleFieldVisibility();
      })
      .catch(() => {});
  }

  function saveClientUpdateSchedule() {
    const mode = byId('updatesScheduleMode').value;
    const messageElement = byId('updatesScheduleMessage');
    const body = { mode };

    if (mode === 'once') {
      const localValue = byId('updatesScheduleOnceAt').value;
      if (!localValue) {
        showSavedMessage(messageElement, 'Pick a date and time first.', true);
        return;
      }
      body.onceAtUtc = new Date(localValue).toISOString();
    } else if (mode === 'interval') {
      body.intervalHours = Number.parseInt(byId('updatesScheduleIntervalHours').value, 10) || 24;
    }

    byId('updatesScheduleSaveButton').disabled = true;
    fetch('/api/v1/client-updates/schedule', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(() => {
        showSavedMessage(messageElement, 'Saved.', false);
        loadClientUpdateSchedule();
      })
      .catch(error => {
        showSavedMessage(messageElement, `Failed to save: ${error.message}`, true);
      })
      .finally(() => {
        byId('updatesScheduleSaveButton').disabled = false;
      });
  }

  function loadServerSettings() {
    fetch('/api/v1/server/settings', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('generalStaleHours').value = data.staleHours || 48;
        byId('generalInstallLogRetentionDays').value = data.installLogRetentionDays || 30;
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
        byId('generalDebugLogEnabled').checked = !!data.debugLogEnabled;
        byId('generalDebugLogPath').textContent = data.debugLogPath || '-';
        renderConnectionStatus(data);
      })
      .catch(error => {
        showSavedMessage(byId('generalMessage'), `Settings unavailable: ${error.message}`, true);
      });
  }

  function loadWindowsSettings() {
    fetch('/api/v1/server/settings', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('generalAdSyncEnabled').checked = !!data.adSyncEnabled;
        byId('generalAdDescriptionSyncEnabled').checked = !!data.adDescriptionSyncEnabled;
        state.adDescriptionSyncEnabled = !!data.adDescriptionSyncEnabled;
        byId('generalAdSyncMode').value = data.adSyncMode || 'on-report';
        byId('generalAdSyncIntervalHours').value = data.adSyncIntervalHours || 24;
        updateAdSyncIntervalField();
        byId('generalAdDomain').value = data.adDomain || '';
        byId('generalAdUseServiceIdentity').checked = data.adUseServiceIdentity !== false;
        byId('generalAdUsername').value = data.adUsername || '';
        byId('generalAdPassword').value = '';
        applyPasswordPlaceholder('generalAdPassword', !!data.adPasswordConfigured, 'leave blank to keep the current password');
        byId('generalAdComputerImportOUs').value = data.adComputerImportOUs || '';
        updateAdIdentityFields();
      })
      .catch(error => {
        showSavedMessage(byId('windowsSettingsMessage'), `Settings unavailable: ${error.message}`, true);
      });
  }

  function loadLinuxSettings() {
    fetch('/api/v1/server/settings', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        byId('generalPreferredLinuxSubnet').value = data.preferredLinuxSubnet || '';
        byId('linuxDefaultIntervalHours').value = data.linuxDefaultIntervalHours || 6;
        byId('linuxDefaultStatusIntervalMinutes').value = data.linuxDefaultStatusIntervalMinutes || 30;
        byId('linuxDefaultInstallPath').value = data.linuxDefaultInstallPath || '/opt/windows-inventory-lite';
      })
      .catch(error => {
        showSavedMessage(byId('linuxSettingsMessage'), `Settings unavailable: ${error.message}`, true);
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

  function saveServerSettings(acknowledgeRisks, confirmedDisruption, acknowledgeIngestionTokenRisk) {
    const staleHours = Number.parseInt(byId('generalStaleHours').value, 10) || 48;
    const installLogRetentionDays = Number.parseInt(byId('generalInstallLogRetentionDays').value, 10) || 30;
    const port = Number.parseInt(byId('generalPort').value, 10) || 8080;
    const enableHttp = byId('generalEnableHttp').checked;
    const httpsPort = Number.parseInt(byId('generalHttpsPort').value, 10) || 8443;
    const useHttps = byId('generalUseHttps').checked;
    const requireIngestionToken = byId('generalRequireIngestionToken').checked;

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

    const disablingIngestionToken = state.generalLoadedRequireIngestionToken && !requireIngestionToken;
    if (disablingIngestionToken && !acknowledgeIngestionTokenRisk) {
      const confirmed = window.confirm(
        "Turning this off means anyone who can reach this server's port can submit inventory reports with no token at all - "
          + 'both /api/v1/inventory and /api/v1/linux/inventory will accept any request, unauthenticated. Continue?'
      );
      if (!confirmed) return;
      acknowledgeIngestionTokenRisk = true;
    }

    byId('generalSaveButton').disabled = true;
    byId('generalMessage').className = 'pkg-message hidden';

    fetch('/api/v1/server/settings', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        staleHours, installLogRetentionDays, port, enableHttp, httpsPort, useHttps, requireIngestionToken,
        acknowledgeRisks: !!acknowledgeRisks, acknowledgeIngestionTokenRisk: !!acknowledgeIngestionTokenRisk,
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
              saveServerSettings(true, true);
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
        renderDashboardTiles();
        renderConnectionStatus(data);
        showSavedMessage(byId('generalMessage'), 'Settings saved.', false);
        loadIngestionTokenStatus();
      })
      .catch(error => {
        showSavedMessage(byId('generalMessage'), `Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('generalSaveButton').disabled = false;
      });
  }

  function saveWindowsSettings() {
    byId('windowsSettingsSaveButton').disabled = true;
    byId('windowsSettingsMessage').className = 'pkg-message hidden';

    fetch('/api/v1/server/settings', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        adSyncEnabled: byId('generalAdSyncEnabled').checked,
        adDescriptionSyncEnabled: byId('generalAdDescriptionSyncEnabled').checked,
        adSyncMode: byId('generalAdSyncMode').value,
        adSyncIntervalHours: Number.parseInt(byId('generalAdSyncIntervalHours').value, 10) || 24,
        adDomain: byId('generalAdDomain').value.trim(),
        adUseServiceIdentity: byId('generalAdUseServiceIdentity').checked,
        adUsername: byId('generalAdUsername').value.trim(),
        adPassword: byId('generalAdPassword').value,
        adComputerImportOUs: byId('generalAdComputerImportOUs').value
      })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        state.adDescriptionSyncEnabled = byId('generalAdDescriptionSyncEnabled').checked;
        byId('generalAdPassword').value = '';
        showSavedMessage(byId('windowsSettingsMessage'), 'Settings saved.', false);
      })
      .catch(error => {
        showSavedMessage(byId('windowsSettingsMessage'), `Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('windowsSettingsSaveButton').disabled = false;
      });
  }

  function saveLinuxSettings() {
    byId('linuxSettingsSaveButton').disabled = true;
    byId('linuxSettingsMessage').className = 'pkg-message hidden';

    fetch('/api/v1/server/settings', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        preferredLinuxSubnet: byId('generalPreferredLinuxSubnet').value.trim(),
        linuxDefaultIntervalHours: Number.parseInt(byId('linuxDefaultIntervalHours').value, 10) || 6,
        linuxDefaultStatusIntervalMinutes: Number.parseInt(byId('linuxDefaultStatusIntervalMinutes').value, 10) || 30,
        linuxDefaultInstallPath: byId('linuxDefaultInstallPath').value.trim()
      })
    })
      .then(response => response.json().then(data => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) throw new Error(data.error || 'Save failed');
        showSavedMessage(byId('linuxSettingsMessage'), 'Settings saved.', false);
      })
      .catch(error => {
        showSavedMessage(byId('linuxSettingsMessage'), `Save failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('linuxSettingsSaveButton').disabled = false;
      });
  }

  function showAdminPasswordMessage(msg, isError) {
    showSavedMessage(byId('adminPasswordMessage'), msg, isError);
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

  function loadIngestionTokenStatus() {
    fetch('/api/v1/server/ingestion-token', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(data => {
        if (!data.configured && data.requireIngestionToken) {
          // Reachable only via a hand-edited config (RequireIngestionToken
          // explicitly set to true with no Token key) - the server's own
          // guard fails closed in this state (see IsIngestionTokenRejected),
          // so ingestion is rejecting every request, not merely
          // unauthenticated. Worth its own message: an admin debugging
          // "all my clients stopped reporting" needs the opposite of what
          // the token-presence-only message below would tell them.
          byId('ingestionTokenStatusText').textContent = 'No token configured, but enforcement is on - inventory ingestion is currently rejecting every request. Regenerate to set a token.';
        } else if (!data.configured) {
          byId('ingestionTokenStatusText').textContent = 'No token configured - inventory ingestion is unauthenticated. Regenerate to set one.';
        } else if (!data.requireIngestionToken) {
          byId('ingestionTokenStatusText').textContent = 'A token is configured, but enforcement is off - inventory ingestion currently accepts requests with no token.';
        } else {
          byId('ingestionTokenStatusText').textContent = 'A token is configured and required for inventory ingestion.';
        }
        byId('ingestionTokenValue').value = data.token || '';
        byId('generalRequireIngestionToken').checked = !!data.requireIngestionToken;
        state.generalLoadedRequireIngestionToken = !!data.requireIngestionToken;
      })
      .catch(error => {
        // Deliberately writes to the status line, not ingestionTokenMessage -
        // this is also called right after a successful regenerate to refresh
        // the "configured" state, and ingestionTokenMessage may still be
        // showing the one-time token reveal at that point. A failed status
        // fetch here must not clobber the admin's only copy of the token.
        byId('ingestionTokenStatusText').textContent = `Status unavailable: ${error.message}`;
      });
  }

  // Deliberately does NOT use showSavedMessage - that helper auto-hides
  // success messages after 30s, but this one shows the only copy of a
  // freshly generated secret the admin will ever get from this page.
  // isError styling (red) would also be semantically wrong for a
  // successful generation, so this sets the message classes directly.
  function regenerateIngestionToken() {
    const warningText = state.generalLoadedRequireIngestionToken !== false
      ? 'Regenerate the ingestion token? Every already-installed client will stop reporting until it is reconfigured with the new token - and any not-yet-deployed GPO package still has the OLD token baked in, so it must be rebuilt from Deploy > Package, not just redeployed. This cannot be undone.'
      : "Regenerate the ingestion token? Already-installed clients are unaffected right now since 'Require ingestion token' is off - but any package rebuilt after this uses the new value, and turning enforcement back on later will require every client to have this value. Continue?";
    const confirmed = window.confirm(warningText);
    if (!confirmed) return;

    byId('ingestionTokenRegenerateButton').disabled = true;

    fetch('/api/v1/server/ingestion-token/regenerate', {
      method: 'POST',
      cache: 'no-store'
    })
      .then(response => {
        if (response.ok) {
          return response.json().then(data => ({ ok: true, data }));
        }
        // The generic server error handler returns a text/plain body, not
        // JSON (e.g. on a failed config save) - parse defensively so that
        // case falls back to a generic message instead of surfacing a raw
        // "Unexpected token..." JSON-parse error to the admin.
        return response.json()
          .catch(() => null)
          .then(data => ({ ok: false, data, statusText: response.statusText }));
      })
      .then(({ ok, data, statusText }) => {
        if (!ok) throw new Error((data && data.error) || statusText || 'Regenerate failed');
        const messageEl = byId('ingestionTokenMessage');
        // The token is now always visible in the "Current token" field above
        // (populated by loadIngestionTokenStatus below), so this message no
        // longer needs to be the one-and-only place to see it - it just
        // confirms the regenerate happened and shows the new value inline.
        messageEl.textContent = `Token regenerated: ${data.token}`;
        messageEl.className = 'pkg-message';
        loadIngestionTokenStatus();
        // Client Package tab fields were pre-filled from the last-built
        // package's own baked-in token, which is now stale - blank them so
        // an immediate Save on that tab (without reloading first) correctly
        // falls back to the fresh live token via ResolveEffectiveToken,
        // instead of silently resubmitting the token that was just replaced.
        const pkgTokenEl = byId('pkgToken');
        if (pkgTokenEl) pkgTokenEl.value = '';
        const linuxPkgTokenEl = byId('linuxPkgToken');
        if (linuxPkgTokenEl) linuxPkgTokenEl.value = '';
      })
      .catch(error => {
        showSavedMessage(byId('ingestionTokenMessage'), `Regenerate failed: ${error.message}`, true);
      })
      .finally(() => {
        byId('ingestionTokenRegenerateButton').disabled = false;
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

  // Chromium-based browsers (and others) refuse to reopen a <datalist>'s
  // suggestion dropdown once the input's value already exactly matches one
  // of its options - clicking back into a filled licenseName/licenseVersion
  // field to pick something else does nothing until the field is manually
  // cleared or typed into. Clearing on focus forces the browser to treat it
  // as an empty field again (which always shows the full list); restoring
  // on blur - but only if the user left it empty without picking or typing
  // anything - avoids silently wiping out the value on a stray click.
  function handleDatalistFieldFocus(event) {
    const input = event.target;
    input.dataset.preFocusValue = input.value;
    input.value = '';
    if (input.id === 'licenseName') updateVersionDatalist();
  }

  function handleDatalistFieldBlur(event) {
    const input = event.target;
    const preFocusValue = input.dataset.preFocusValue || '';
    delete input.dataset.preFocusValue;
    if (input.value === '' && preFocusValue !== '') {
      input.value = preFocusValue;
      if (input.id === 'licenseName') updateVersionDatalist();
    }
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

  // Mirrors getSoftwareGroups (Windows) - groups by name+version only.
  // Linux ServiceInfo (linux-client/collect/services.go) has no publisher
  // field, unlike Windows software entries.
  function getLinuxServicesGroups(clients) {
    const groups = new Map();
    clients.forEach(client => {
      (client.services || []).forEach(item => {
        if (!item.name) return;
        const key = [item.name, item.version || ''].join('\u001f').toLowerCase();
        if (!groups.has(key)) {
          groups.set(key, { name: item.name, version: item.version || '', clients: [], clientKeys: new Set() });
        }
        const group = groups.get(key);
        const clientKey = String(client.hostname || '').toLowerCase();
        if (!group.clientKeys.has(clientKey)) {
          group.clientKeys.add(clientKey);
          // Only hostname + this client's own active status for THIS
          // service are kept (not the whole client object) - per the
          // client's latest report, per L33.
          group.clients.push({ hostname: client.hostname, active: item.active !== false });
        }
      });
    });

    return Array.from(groups.values()).sort((a, b) => {
      const nameCompare = a.name.localeCompare(b.name);
      return nameCompare || a.version.localeCompare(b.version);
    });
  }

  // Display name for a client from either platform: Windows clients report
  // computerName, Linux clients report hostname. Used everywhere merged
  // cross-platform code needs a computer's name.
  function clientDisplayName(client) {
    return client.computerName || client.hostname || 'Unknown';
  }

  // Which platform a client came from. Reads client.platform, a field this
  // dashboard stamps itself at load time (see stampClientPlatform below,
  // called at every state.clients/state.linuxClients assignment) - never
  // inferred from the client's own report body. Both Windows and Linux
  // reports round-trip through an untyped dictionary server-side (see
  // ReceiveInventory/ReceiveLinuxInventory in WindowsInventoryLiteServer.cs)
  // with no schema enforcement, so a self-reported computerName is not a
  // safe platform discriminator: this label decides which REST endpoint a
  // row's Delete button and Description editor target
  // (renderClientsTable), so inferring it from attacker-controllable data
  // would let a spoofed Linux report's computerName field redirect an
  // admin's Delete click at an unrelated Windows client's record.
  function clientPlatformLabel(client) {
    return client.platform === 'linux' ? 'Linux' : 'Windows';
  }

  // Stamps every client in a freshly-fetched array with which endpoint it
  // came from, overwriting any same-named key the report body itself might
  // already carry (see clientPlatformLabel's comment for why that matters).
  // Called at every state.clients/state.linuxClients assignment site so
  // clientPlatformLabel never has to guess from client-reported fields.
  function stampClientPlatform(clients, platform) {
    clients.forEach(client => { client.platform = platform; });
    return clients;
  }

  // Per-client dedupe key inside a hardware group. Platform-prefixed so a
  // Windows machine and a Linux machine that happen to share a name still
  // count as two distinct computers in a merged group.
  function clientGroupKey(client) {
    return clientPlatformLabel(client) + ':' + String(clientDisplayName(client)).toLowerCase();
  }

  // Every client from both platforms in one array. The merged Hardware view
  // and the combined Dashboard tiles/charts read this instead of
  // state.clients.
  function getAllClients() {
    return state.clients.concat(state.linuxClients);
  }

  // Backs the .os-filter segmented-pill component: 'all' is a no-op
  // passthrough, otherwise keeps only clients matching that platform.
  // Consumers filter *before* any cross-platform grouping (e.g.
  // getCpuGroups) so a group with zero remaining members after the filter
  // never appears, with no changes needed inside the grouping functions.
  function filterClientsByOs(clients, filter) {
    if (filter === 'all') return clients;
    const wantWindows = filter === 'windows';
    return clients.filter(c => (clientPlatformLabel(c) === 'Windows') === wantWindows);
  }

  // Cross-platform CPU grouping. Windows reports the model as cpu.name,
  // Linux as cpu.model - the same underlying concept, so both feed one key.
  // The key is name+cores only: Windows' cpu.clockMhz has no Linux
  // counterpart, so keying on it would split otherwise-identical
  // configurations, and it could not honestly be a group-level column
  // either (a merged group's members would disagree). Clock is rendered
  // per-computer in the expanded row instead.
  // Grouped by model name only - core count is dropped from the key.
  // Virtualized fleets routinely allocate different vCPU counts to VMs
  // sharing the same underlying physical/model CPU, so keying on cores
  // fragmented "the same processor" into multiple rows. Core count is
  // shown per-computer in the expanded row instead (see hardwareComputerItem
  // call sites), matching the clockMhz/moduleCount treatment already used
  // here for the other platform/instance-specific hardware fields.
  function getCpuGroups(clients) {
    const groups = new Map();
    clients.forEach(client => {
      const cpu = client.cpu || {};
      const name = cpu.name || cpu.model;
      if (!name) return;
      const key = String(name).toLowerCase();
      if (!groups.has(key)) {
        groups.set(key, { name, clients: [], clientKeys: new Set() });
      }
      const group = groups.get(key);
      const clientKey = clientGroupKey(client);
      if (!group.clientKeys.has(clientKey)) {
        group.clientKeys.add(clientKey);
        group.clients.push(client);
      }
    });
    return Array.from(groups.values()).sort((a, b) => a.name.localeCompare(b.name));
  }

  // Cross-platform disk grouping. The key (model+type+sizeGb) is already
  // identical on both platforms, so it needs no normalization. usb is the
  // one asymmetric field - only Windows disks ever set it - and is computed
  // here as "any member disk in this group is a USB disk", which keeps the
  // existing USB badge and USB-last sort order behaving exactly as before
  // for Windows-only groups.
  function getDiskGroups(clients) {
    const groups = new Map();
    clients.forEach(client => {
      (client.disks || []).forEach(disk => {
        if (!disk.model) return;
        const key = [disk.model, disk.type, disk.sizeGb].join('\x1f').toLowerCase();
        if (!groups.has(key)) {
          groups.set(key, { model: disk.model, type: disk.type || 'HDD', sizeGb: disk.sizeGb || 0, usb: false, clients: [], clientKeys: new Set() });
        }
        const group = groups.get(key);
        if (disk.usb === true) group.usb = true;
        const clientKey = clientGroupKey(client);
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

  // Cross-platform RAM grouping, keyed on total size only. Windows'
  // per-module breakdown (ramModules) has no Linux counterpart, so keeping
  // module count in the key would prevent any cross-platform merge at all.
  // Module count is rendered per-computer in the expanded row instead, and
  // the group-level "Modules" column is gone.
  function getRamGroups(clients) {
    const groups = new Map();
    clients.forEach(client => {
      const totalMb = client.ramTotalMb || 0;
      const key = String(totalMb);
      if (!groups.has(key)) {
        const totalGb = totalMb >= 1024 ? `${Math.round(totalMb / 1024)} GB` : `${totalMb} MB`;
        groups.set(key, { totalMb, totalGb, clients: [], clientKeys: new Set() });
      }
      const group = groups.get(key);
      const clientKey = clientGroupKey(client);
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

  // One bar per distinct OS release across both platforms: Windows reports
  // it as os.caption, Linux as os.prettyName (collect.OSInfo). Same
  // [{label, count}] shape as getTopCpuModels/getRamBuckets so it can go
  // straight into renderBarChart. Grouped case-insensitively but displayed
  // with the first-seen casing.
  function getOsVersionBreakdown(clients, limit) {
    const counts = new Map();
    clients.forEach(client => {
      const os = client.os || {};
      const label = String(os.caption || os.prettyName || '').trim();
      if (!label) return;
      const key = label.toLowerCase();
      if (!counts.has(key)) counts.set(key, { label, count: 0 });
      counts.get(key).count++;
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

  function linuxServicesMatches(group, query) {
    if (!query) return true;
    const computers = group.clients.map(client => client.hostname).join(' ');
    const haystack = [group.name, group.version, computers].join(' ').toLowerCase();
    return haystack.indexOf(query.toLowerCase()) !== -1;
  }

  function renderDashboardTiles() {
    const clients = state.clients;
    const allClients = getAllClients();
    byId('dashClientCount').textContent = allClients.length;
    // Windows-only by design, not an oversight: neither Windows activation
    // nor Office activation has any Linux equivalent, so these two tiles
    // stay state.clients-only while Clients/Stale go fleet-wide.
    byId('dashWindowsActivated').textContent = clients.filter(client => client.activation && client.activation.windows && client.activation.windows.activated).length;
    byId('dashOfficeActivated').textContent = clients.filter(client => client.activation && client.activation.office && client.activation.office.activated).length;
    // isStale needs no platform handling - it reads collectedAt ||
    // sourceUpdatedAt, both of which Linux client reports also carry.
    const dashStaleCount = allClients.filter(isStale).length;
    byId('dashStaleCount').textContent = dashStaleCount;
    byId('dashStaleLabel').textContent = `Stale >${state.staleHours}h`;
    byId('dashStaleTile').classList.toggle('tile-alert', dashStaleCount > 0);
    byId('dashLicenseCount').textContent = state.licenses.length;
    byId('dashUsbCount').textContent = allClients.filter(client => client.hasUsbStorage).length;
    renderBarChart('dashOsChart', getOsVersionBreakdown(allClients, 5));
    renderBarChart('dashCpuChart', getTopCpuModels(allClients, 4));
    renderBarChart('dashRamChart', getRamBuckets(allClients));
    renderBarChart('dashStorageChart', getStorageTypeBreakdown(allClients));
  }

  // Each module renders as its own grid cell (2 columns) instead of one
  // long comma-joined line - hard to read for machines with 4+ sticks.
  // Matches the same "one item per line" direction already used for
  // disksSummary a few lines below, just laid out in a 2-up grid since RAM
  // module strings are short and a fleet with many sticks would otherwise
  // need many full-width lines.
  function formatRamModulesHtml(modules) {
    if (!modules || modules.length === 0) return null;
    const items = modules.map(m => {
      const cap = m.capacityMb >= 1024 ? `${Math.round(m.capacityMb / 1024)} GB` : `${Number(m.capacityMb) || 0} MB`;
      const mfr = m.manufacturer ? ` ${escapeHtml(m.manufacturer)}` : '';
      const spd = m.speedMhz ? ` ${Number(m.speedMhz) || 0} MHz` : '';
      return `<span>${cap}${mfr}${spd}</span>`;
    });
    return `<span class="ram-modules-grid">${items.join('')}</span>`;
  }

  // The single cross-platform Clients table, replacing the former
  // renderTable (Windows) / renderLinuxClientsTable (Linux) pair. Callers
  // pass the merged, OS-filtered list (see renderFilteredClientsTable) and
  // each row branches on its own client's platform for the cells whose
  // shape genuinely differs: which expand/delete data-* attribute the row
  // carries, whether a domain is shown, the OS sub-line, Office,
  // Activation, the installed-software vs running-services count, which
  // Description formatter applies, and which nested table the expanded row
  // shows. Every per-platform data attribute each old table emitted is
  // emitted here unchanged, so the existing delegated click handlers for
  // [data-client]/[data-linux-client]/[data-delete-client]/
  // [data-delete-linux-client] keep working with no changes at all.
  function renderClientsTable(clients) {
    const activeElement = document.activeElement;
    const editingClientId = activeElement && activeElement.matches('.description-edit-input') ? activeElement.dataset.descriptionClient : null;
    // Both platforms' Description inputs can now be in the same table, and
    // safeId() of a Windows computerName equal to a Linux hostname yields
    // the same id - so the platform is part of the restore lookup below,
    // not just the id.
    const editingIsLinux = editingClientId ? activeElement.dataset.platform === 'linux' : false;
    const editingValue = editingClientId ? activeElement.value : null;
    const editingSelectionStart = editingClientId ? activeElement.selectionStart : null;

    // Also called by render(), but this table is now re-rendered outside
    // the render() pipeline too (loadLinuxClients' poll path, the pager,
    // the OS filter) - same reason the retired renderLinuxClientsTable
    // called it.
    renderSortHeaders();
    byId('descriptionColumnHeader').textContent = state.adDescriptionSyncEnabled ? 'AD Description' : 'Description';

    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.clients;
    const filtered = applySort(clients.filter(client => allClientMatches(client, query)), c => allClientSortValue(c, sortKey), sortDir);
    const { items: pageItems, page, totalPages } = paginate(filtered, state.page.clients, state.pageSize.clients);
    state.page.clients = page;

    const rows = pageItems.map(client => {
      const isWindows = clientPlatformLabel(client) === 'Windows';
      const clientId = safeId((isWindows ? client.computerName : client.hostname) || '');
      const stale = isStale(client);
      const awaitingReport = !!client.lastInstalledAtUtc;
      const staleClass = stale ? ' stale' : '';
      const staleBadge = awaitingReport
        ? ` <span class="usb-badge" title="Pushed at ${escapeHtml(formatDateTime(client.lastInstalledAtUtc))}, waiting for this client to report in">AWAITING REPORT</span>`
        : (stale ? ' <span class="usb-badge">STALE</span>' : '');
      // hasUsbStorage / isStale / lastInstalledAtUtc are all platform-
      // agnostic (the Dashboard's USB and Stale tiles already read them off
      // getAllClients()), so these two badges need no platform branch.
      const usbBadge = client.hasUsbStorage ? ' <span class="usb-badge">USB</span>' : '';
      // Windows only, and only when actually reported - piping an absent
      // domain through escapeHtml would print the literal word "Unknown"
      // under every Linux row (same reasoning as hardwareComputerItem).
      const domainHtml = client.domain ? `<small>${escapeHtml(client.domain)}</small>` : '';
      const ipAddressesHtml = formatIpAddressesHtml(client);
      const expandAttr = isWindows ? `data-client="${clientId}"` : `data-linux-client="${clientId}"`;

      const os = client.os || {};
      const osCell = isWindows
        ? `${escapeHtml(os.caption)}<small class="mono">${escapeHtml(os.version)} build ${escapeHtml(os.buildNumber)}</small>`
        : escapeHtml(os.prettyName);

      const office = client.office || {};
      const activation = client.activation || {};
      const windowsActivation = activation.windows || {};
      const officeActivation = activation.office || {};
      // Office licensing and Windows/Office activation have no Linux
      // counterpart at all. An em dash marks "not applicable on this
      // platform" - the same placeholder renderCertificateHistory already
      // uses for a cell that cannot exist.
      const officeCell = isWindows ? `${escapeHtml(office.name)}<small>${escapeHtml(office.version)}</small>` : '—';
      const activationCell = isWindows
        ? `${activationBadge(windowsActivation.activated, 'Windows')} ${activationBadge(officeActivation.activated, 'Office')}`
        : '—';

      const clientSoftware = isWindows ? getClientSoftware(client) : [];
      const services = Array.isArray(client.services) ? client.services : [];
      const itemCount = isWindows ? clientSoftware.length : services.length;

      const descriptionCell = state.adDescriptionSyncEnabled
        ? (isWindows ? formatAdDescription(client) : formatLinuxAdDescription(client))
        : (isWindows ? formatDescriptionEditor(client, clientId) : formatLinuxDescriptionEditor(client, clientId));

      const cpu = client.cpu || {};
      const cpuName = isWindows ? cpu.name : cpu.model;
      const cpuText = cpuName
        ? `${escapeHtml(cpuName)}${cpu.cores ? `, ${Number(cpu.cores) || 0} cores` : ''}${isWindows && cpu.clockMhz ? `, ${(cpu.clockMhz / 1000).toFixed(2)} GHz` : ''}`
        : 'Unknown';
      const ramGb = client.ramTotalMb
        ? (client.ramTotalMb >= 1024 ? `${Math.round(client.ramTotalMb / 1024)} GB` : `${Number(client.ramTotalMb) || 0} MB`)
        : 'Unknown';
      // ramModules is a Windows-only field (no Linux counterpart in the
      // Go client's report), so the per-module grid only ever renders for
      // Windows rows.
      const ramModulesHtml = isWindows ? formatRamModulesHtml(client.ramModules) : null;
      const disksSummary = (client.disks || []).map(d => {
        const size = d.sizeGb ? ` ${d.sizeGb} GB` : '';
        const badge = d.usb ? ' <span class="usb-badge">USB</span>' : '';
        return `${escapeHtml(d.type)}${escapeHtml(size)}${badge} <small>${escapeHtml(d.model)}</small>`;
      }).join('<br>') || 'Unknown';

      const { key: clientSoftwareSortKey, dir: clientSoftwareSortDir } = state.sort.clientSoftware;
      const sortedClientSoftware = applySort(clientSoftware, item => clientSoftwareSortValue(item, clientSoftwareSortKey), clientSoftwareSortDir);

      const nestedTable = isWindows
        ? `<h2>${escapeHtml(client.computerName)} software</h2>
            <table class="nested-table">
              <thead><tr>
                <th data-sort-table="clientSoftware" data-sort-key="name" class="sortable">Name</th>
                <th data-sort-table="clientSoftware" data-sort-key="version" class="sortable">Version</th>
                <th data-sort-table="clientSoftware" data-sort-key="publisher" class="sortable">Publisher</th>
                <th data-sort-table="clientSoftware" data-sort-key="installDate" class="sortable">Install date</th>
              </tr></thead>
              <tbody>${sortedClientSoftware.map(item => `<tr>
                <td>${escapeHtml(item.name)}</td>
                <td>${escapeHtml(item.version)}</td>
                <td>${escapeHtml(item.publisher)}</td>
                <td>${escapeHtml(formatInstallDate(item.installDate))}</td>
              </tr>`).join('') || '<tr><td colspan="4" class="empty">No software records.</td></tr>'}</tbody>
            </table>`
        : `<h2>${escapeHtml(client.hostname)} services</h2>
            <table class="nested-table">
              <thead><tr><th>Name</th><th>Unit</th><th>Version</th><th>Active</th></tr></thead>
              <tbody>${services.map(item => `<tr>
                <td>${escapeHtml(item.name)}</td>
                <td>${escapeHtml(item.unit || '')}</td>
                <td>${escapeHtml(item.version)}</td>
                <td>${serviceActiveDot(item.active !== false)}</td>
              </tr>`).join('') || '<tr><td colspan="4" class="empty">No service records.</td></tr>'}</tbody>
            </table>`;

      const detailsHidden = state.expandedDetails.has((isWindows ? 'client:' : 'linux-client:') + clientId) ? '' : 'hidden';
      const detailsAttr = isWindows ? `data-client-details="${clientId}"` : `data-linux-client-details="${clientId}"`;
      const deleteAttr = isWindows
        ? `data-delete-client="${escapeHtml(client.computerName)}"`
        : `data-delete-linux-client="${escapeHtml(client.hostname)}"`;

      return `<tr class="${staleClass}">
        <td><button class="link-button" type="button" ${expandAttr}>${escapeHtml(clientDisplayName(client))}</button> <small class="platform-tag">${escapeHtml(clientPlatformLabel(client))}</small>${usbBadge}${staleBadge}${domainHtml}${ipAddressesHtml ? `<small class="mono">${ipAddressesHtml}</small>` : ''}</td>
        <td>${escapeHtml(client.clientVersion)}</td>
        <td>${osCell}</td>
        <td>${officeCell}</td>
        <td>${activationCell}</td>
        <td>${itemCount}</td>
        <td>${descriptionCell}</td>
        <td>${escapeHtml(formatDateTime(client.collectedAt || client.sourceUpdatedAt))}${client.servicesStatusCollectedAt ? `<small>Services checked: ${escapeHtml(formatDateTime(client.servicesStatusCollectedAt))}</small>` : ''}</td>
        <td><button class="danger-button-ghost" type="button" ${deleteAttr}>Delete</button></td>
      </tr>
      <tr class="details-row ${detailsHidden}" ${detailsAttr}>
        <td colspan="9">
          <div class="details">
            <div class="hw-summary">
              <div><strong>CPU</strong><span>${cpuText}</span></div>
              <div><strong>RAM</strong><span>${ramGb}${ramModulesHtml ? `<br>${ramModulesHtml}` : ''}</span></div>
              <div><strong>Storage</strong><span>${disksSummary}</span></div>
            </div>
            ${nestedTable}
          </div>
        </td>
      </tr>`;
    });

    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="9" class="empty">No matching inventory records.</td></tr>';
    // The clientSoftware <th> elements above are rebuilt from scratch on
    // every call (they live inside inventoryBody's innerHTML, unlike the
    // Clients/Software/Hardware/Licenses <thead>s, which are static in
    // index.html and persist across renders) - the earlier renderSortHeaders()
    // call above ran before they existed, so re-run it now that they're in
    // the DOM to give the active clientSoftware sort column its arrow.
    renderSortHeaders();
    if (editingClientId) {
      const platformSelector = editingIsLinux ? '[data-platform="linux"]' : ':not([data-platform])';
      const restoredInput = document.querySelector(`.description-edit-input[data-description-client="${editingClientId}"]${platformSelector}`);
      if (restoredInput) {
        restoredInput.value = editingValue;
        restoredInput.focus();
        restoredInput.setSelectionRange(editingSelectionStart, editingSelectionStart);
      }
    }
    renderPager('clientsPager', 'clients', page, totalPages, () => renderFilteredClientsTable());
  }

  // Applies the .os-filter's current Clients selection before delegating to
  // renderClientsTable - the single place that combines the two, so every
  // call site stays filter-aware without repeating the filter call. Exact
  // mirror of renderFilteredHardwarePage.
  function renderFilteredClientsTable() {
    renderClientsTable(filterClientsByOs(getAllClients(), state.osFilter.clients));
  }

  document.addEventListener('keydown', event => {
    if (!event.target.matches('.description-edit-input')) return;
    if (event.key === 'Enter') {
      event.target.blur();
    } else if (event.key === 'Escape') {
      event.target.value = event.target.dataset.lastSavedValue || '';
      event.target.blur();
    }
  });

  document.addEventListener('blur', event => {
    if (!event.target.matches || !event.target.matches('.description-edit-input')) return;
    saveClientDescription(event.target);
  }, true);

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
      const detailsHidden = state.expandedDetails.has('software:' + groupId) ? '' : 'hidden';

      return `<tr>
        <td><button class="link-button" type="button" data-software="${groupId}">${escapeHtml(group.name)}</button></td>
        <td>${escapeHtml(group.version)}</td>
        <td>${escapeHtml(group.publisher)}</td>
        <td class="hw-num">${group.clients.length}</td>
        <td>${findLicenseForSoftware(group.name) ? `<button class="edit-button" type="button" data-software-license-name="${escapeHtml(group.name)}" data-software-license-version="${escapeHtml(group.version)}">License</button>` : ''}</td>
      </tr>
      <tr class="details-row ${detailsHidden}" data-software-details="${groupId}">
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

  // Mirrors renderSoftwareTable (Windows) - row-expand shows which
  // computers have this service (no License column, no publisher - this
  // project has no Linux licensing concept and ServiceInfo has no
  // publisher field).
  function renderLinuxServicesTable(clients) {
    const tbody = byId('linuxServicesBody');
    if (!tbody) return;

    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.linuxServices;
    const filtered = applySort(getLinuxServicesGroups(clients).filter(g => linuxServicesMatches(g, query)), g => linuxServicesSortValue(g, sortKey), sortDir);
    const { items: pageItems, page, totalPages } = paginate(filtered, state.page.linuxServices, state.pageSize.linuxServices);
    state.page.linuxServices = page;

    const rows = pageItems.map(group => {
      const computers = group.clients.map(client => {
        const badge = client.active === false ? ' <span class="usb-badge">INACTIVE</span>' : '';
        return `<li>${escapeHtml(client.hostname)}${badge}</li>`;
      }).join('');
      const groupId = safeId('linux:' + group.name + '\u001f' + group.version);
      const detailsHidden = state.expandedDetails.has('linux-services:' + groupId) ? '' : 'hidden';

      return `<tr>
        <td><button class="link-button" type="button" data-linux-services="${groupId}">${escapeHtml(group.name)}</button></td>
        <td>${escapeHtml(group.version)}</td>
        <td class="hw-num">${group.clients.length}</td>
      </tr>
      <tr class="details-row ${detailsHidden}" data-linux-services-details="${groupId}">
        <td colspan="3">
          <div class="details">
            <h2>${escapeHtml(group.name)}</h2>
            <ul class="computer-list">${computers}</ul>
          </div>
        </td>
      </tr>`;
    });

    tbody.innerHTML = rows.join('') || '<tr><td colspan="3" class="empty">No matching service records.</td></tr>';
    renderPager('linuxServicesPager', 'linuxServices', page, totalPages, () => renderLinuxServicesTable(state.linuxClients));
  }

  // One <li> per computer inside an expanded hardware group. Cross-platform:
  // the display name falls back to hostname for Linux clients, the platform
  // tag is derived from which name field is present, and domain (Windows
  // only) is rendered only when the client actually reports one - piping an
  // absent domain through escapeHtml would print the literal word "Unknown"
  // under every Linux entry. extraHtml carries the per-computer,
  // instance-specific detail a merged group can no longer show as a table
  // column (CPU cores/clock - VMs sharing a model often have different
  // vCPU allocations, RAM module count).
  function hardwareComputerItem(client, extraHtml) {
    const domain = client.domain ? `<small>${escapeHtml(client.domain)}</small>` : '';
    return `<li>${escapeHtml(clientDisplayName(client))} <small class="platform-tag">${escapeHtml(clientPlatformLabel(client))}</small>${extraHtml || ''}${domain}</li>`;
  }

  // The single cross-platform Hardware page: three stacked group-by tables
  // (CPU/Storage/RAM) built from state.clients and state.linuxClients
  // together (callers pass getAllClients()). Replaces the former
  // renderHardwarePage/renderLinuxHardwarePage pair and reuses the Windows
  // side's DOM ids and hwCpu/hwDisk/hwRam sort+page state, which were always
  // per-table rather than per-platform.
  function renderHardwarePage(clients) {
    const query = byId('searchInput').value.trim();

    const { key: cpuSortKey, dir: cpuSortDir } = state.sort.hwCpu;
    const cpuFiltered = applySort(getCpuGroups(clients).filter(g => hwMatches([g.name, ...g.clients.map(c => clientDisplayName(c))].join(' '), query)), g => cpuSortValue(g, cpuSortKey), cpuSortDir);
    const { items: cpuPageItems, page: cpuPage, totalPages: cpuTotalPages } = paginate(cpuFiltered, state.page.hwCpu, state.pageSize.hwCpu);
    state.page.hwCpu = cpuPage;
    const cpuRows = cpuPageItems.map(g => {
        const id = safeId('cpu:' + g.name);
        const detailsHidden = state.expandedDetails.has('hw:' + id) ? '' : 'hidden';
        const computers = g.clients.map(c => {
          const cpu = c.cpu || {};
          const coresText = cpu.cores != null ? `${Number(cpu.cores) || 0} cores` : '';
          const clockText = cpu.clockMhz ? `${(Number(cpu.clockMhz) / 1000).toFixed(2)} GHz` : '';
          const extra = [coresText, clockText].filter(Boolean).join(', ');
          return hardwareComputerItem(c, extra ? `<small>${extra}</small>` : '');
        }).join('');
        return `<tr>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.name)}</button></td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row ${detailsHidden}" data-hw-details="${id}">
          <td colspan="2"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwCpuBody').innerHTML = cpuRows.join('') || '<tr><td colspan="2" class="empty">No CPU data.</td></tr>';
    renderPager('hwCpuPager', 'hwCpu', cpuPage, cpuTotalPages, () => renderFilteredHardwarePage());

    const { key: diskSortKey, dir: diskSortDir } = state.sort.hwDisk;
    const diskFiltered = applySort(getDiskGroups(clients).filter(g => hwMatches([g.model, g.type, ...g.clients.map(c => clientDisplayName(c))].join(' '), query)), g => diskSortValue(g, diskSortKey), diskSortDir);
    const { items: diskPageItems, page: diskPage, totalPages: diskTotalPages } = paginate(diskFiltered, state.page.hwDisk, state.pageSize.hwDisk);
    state.page.hwDisk = diskPage;
    const diskRows = diskPageItems.map(g => {
        const id = safeId('disk:' + g.model + g.type + g.sizeGb);
        const detailsHidden = state.expandedDetails.has('hw:' + id) ? '' : 'hidden';
        const computers = g.clients.map(c => hardwareComputerItem(c, '')).join('');
        const usbBadge = g.usb ? ' <span class="usb-badge">USB</span>' : '';
        const size = g.sizeGb ? `${g.sizeGb} GB` : 'Unknown';
        return `<tr${g.usb ? ' class="usb-row"' : ''}>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.model)}</button>${usbBadge}</td>
          <td>${escapeHtml(g.type)}</td>
          <td class="hw-num">${escapeHtml(size)}</td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row ${detailsHidden}" data-hw-details="${id}">
          <td colspan="4"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwDiskBody').innerHTML = diskRows.join('') || '<tr><td colspan="4" class="empty">No storage data.</td></tr>';
    renderPager('hwDiskPager', 'hwDisk', diskPage, diskTotalPages, () => renderFilteredHardwarePage());

    const { key: ramSortKey, dir: ramSortDir } = state.sort.hwRam;
    const ramFiltered = applySort(getRamGroups(clients).filter(g => hwMatches([g.totalGb, ...g.clients.map(c => clientDisplayName(c))].join(' '), query)), g => ramSortValue(g, ramSortKey), ramSortDir);
    const { items: ramPageItems, page: ramPage, totalPages: ramTotalPages } = paginate(ramFiltered, state.page.hwRam, state.pageSize.hwRam);
    state.page.hwRam = ramPage;
    const ramRows = ramPageItems.map(g => {
        const id = safeId('ram:' + g.totalMb);
        const detailsHidden = state.expandedDetails.has('hw:' + id) ? '' : 'hidden';
        const computers = g.clients.map(c => hardwareComputerItem(c, c.ramModules && c.ramModules.length ? `<small>${c.ramModules.length} module${c.ramModules.length === 1 ? '' : 's'}</small>` : '')).join('');
        return `<tr>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.totalGb)}</button></td>
          <td class="hw-num">${g.clients.length}</td>
        </tr>
        <tr class="details-row ${detailsHidden}" data-hw-details="${id}">
          <td colspan="2"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwRamBody').innerHTML = ramRows.join('') || '<tr><td colspan="2" class="empty">No RAM data.</td></tr>';
    renderPager('hwRamPager', 'hwRam', ramPage, ramTotalPages, () => renderFilteredHardwarePage());
  }

  // Applies the .os-filter's current Hardware selection before delegating
  // to renderHardwarePage - the single place that combines the two, so
  // every call site (render() and each of the 3 pagers' onChange) stays
  // filter-aware without repeating the filter call at each site.
  function renderFilteredHardwarePage() {
    renderHardwarePage(filterClientsByOs(getAllClients(), state.osFilter.hardware));
  }

  // Repaints the one shared .os-filter pill from the current view's own
  // selection. Hardware and Clients each keep an independent value in
  // state.osFilter, so without this, setting "Windows" on Hardware and then
  // switching to Clients would leave the Windows chip lit while the Clients
  // table is actually unfiltered. state.osFilter's keys are view names
  // exactly so this lookup works; any other view falls back to 'all' (and
  // the pill is hidden there anyway).
  function renderOsFilterActive() {
    const active = state.osFilter[state.view] || 'all';
    document.querySelectorAll('#osFilter .os-filter-option').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.osFilter === active);
    });
  }

  function render() {
    renderDashboardTiles();
    renderSortHeaders();
    renderFilteredClientsTable();
    renderSoftwareTable(state.clients);
    renderFilteredHardwarePage();
    renderLicenses();
    populateSoftwareDatalists();
    byId('dashboardView').classList.toggle('hidden', state.view !== 'dashboard');
    byId('clientsView').classList.toggle('hidden', state.view !== 'clients');
    byId('softwareView').classList.toggle('hidden', state.view !== 'software');
    byId('hardwareView').classList.toggle('hidden', state.view !== 'hardware');
    byId('licensesView').classList.toggle('hidden', state.view !== 'licenses');
    byId('linuxServicesView').classList.toggle('hidden', state.view !== 'linuxServices');
    // Deploy: Actions shows both platforms' sections together (stacked, own
    // headings), Updates and Package are each already cross-platform on one
    // merged section (no stacking needed).
    byId('installView').classList.toggle('hidden', !(state.view === 'deploy' && state.subview === 'actions'));
    byId('installHistoryView').classList.toggle('hidden', !(state.view === 'deploy' && state.subview === 'actions'));
    byId('updatesView').classList.toggle('hidden', !(state.view === 'deploy' && state.subview === 'updates'));
    byId('packageView').classList.toggle('hidden', !(state.view === 'deploy' && state.subview === 'package'));
    // Settings: exactly one of the five shows at a time (no stacking).
    byId('serverSettingsView').classList.toggle('hidden', !(state.view === 'settings' && state.subview === 'server'));
    byId('generalStatusView').classList.toggle('hidden', !(state.view === 'settings' && state.subview === 'server'));
    byId('windowsSettingsView').classList.toggle('hidden', !(state.view === 'settings' && state.subview === 'windows'));
    byId('linuxSettingsView').classList.toggle('hidden', !(state.view === 'settings' && state.subview === 'linux'));
    byId('certificateView').classList.toggle('hidden', !(state.view === 'settings' && state.subview === 'certificate'));
    byId('adminPasswordView').classList.toggle('hidden', !(state.view === 'settings' && state.subview === 'adminPassword'));
    byId('dashboardTab').classList.toggle('active', state.view === 'dashboard');
    byId('clientsTab').classList.toggle('active', state.view === 'clients');
    byId('softwareTab').classList.toggle('active', state.view === 'software');
    byId('hardwareTab').classList.toggle('active', state.view === 'hardware');
    byId('licensesTab').classList.toggle('active', state.view === 'licenses');
    byId('linuxServicesTab').classList.toggle('active', state.view === 'linuxServices');
    byId('fleetDropdownButton').classList.toggle('active', ['clients', 'software', 'linuxServices', 'hardware', 'licenses'].includes(state.view));
    byId('manageDropdownButton').classList.toggle('active', state.view === 'deploy' || state.view === 'settings');
    byId('deployTab').classList.toggle('active', state.view === 'deploy');
    byId('settingsTab').classList.toggle('active', state.view === 'settings');
    const isInventoryView = inventoryViews.includes(state.view);
    const isLinuxInventoryView = linuxInventoryViews.includes(state.view);
    const isUpdatesView = state.view === 'deploy' && state.subview === 'updates';
    byId('searchInput').classList.toggle('hidden', !isInventoryView && !isLinuxInventoryView);
    byId('topbar').classList.toggle('hidden', !isInventoryView && !isLinuxInventoryView && !isUpdatesView);
    byId('generatedAt').classList.toggle('hidden', !isInventoryView && !isLinuxInventoryView);
    byId('osFilter').classList.toggle('hidden', !(state.view === 'hardware' || state.view === 'clients' || (state.view === 'deploy' && state.subview === 'updates')));
    renderOsFilterActive();
    renderSubtabStrips();
    recalculateActivePagination();
  }

  // Re-measures and, if it changed, applies a corrected live page size for
  // whichever table is now visible. Only Clients/Software are viewport-
  // adaptive (Hardware's three sub-tables use a fixed size instead, see
  // HW_PAGE_SIZE above); this function is a no-op for every other view.
  function recalculateActivePagination() {
    if (state.view === 'clients') {
      const size = computeLiveRowsPerPage('inventoryBody');
      if (size && size !== state.pageSize.clients) {
        state.pageSize.clients = size;
        renderFilteredClientsTable();
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
      // Both timestamps, not collectedAt || sourceUpdatedAt - a client
      // that already has a collectedAt from its last real report never
      // falls through to sourceUpdatedAt via ||, so an AD-sync-only
      // update (which advances sourceUpdatedAt but not collectedAt - see
      // ApplyAdSyncFields server-side) would otherwise never change the
      // fingerprint and the poll would silently skip it.
      .map(c => (c.computerName || '') + '|' + (c.collectedAt || '') + '|' + (c.sourceUpdatedAt || ''))
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
        state.clients = stampClientPlatform(data.clients || [], 'windows');
        state.staleHours = data.staleHours || 48;
        state.adDescriptionSyncEnabled = !!data.adDescriptionSyncEnabled;
        byId('generatedAt').textContent = `Generated: ${formatDateTime(data.generatedAt)}`;
        byId('serverVersionBadge').textContent = `Server: v${text(data.serverVersion)}`;
        render();
        flashGeneratedAt();
      })
      .catch(() => {
        // Silent - see function comment above.
      });

    // Linux data has no separate change-fingerprint (its own dataset is
    // much smaller in practice than the Windows fleet this project was
    // built around) - loadLinuxClients() always re-fetches+re-renders on
    // every 30s tick while a view that reads Linux data is open, same
    // silent-on-failure behavior as the Windows poll above. That now
    // includes the Dashboard (combined tiles/charts) and the merged
    // Hardware view, not just the Linux Inventory tabs.
    if (linuxDataViews.includes(state.view)) {
      loadLinuxClients();
    }

    // Separate fetch, badge-only: the Manage dropdown "Client updates" count should
    // stay live even when the Client updates tab itself isn't open. A full
    // loadClientUpdates()/renderMergedUpdatesTable() call is deliberately NOT used
    // here - it rebuilds #updatesBody's row checkboxes, which would silently
    // clear an in-progress selection if the user has this tab open and rows
    // checked when a poll tick lands. handleClientUpdatesSummary also picks
    // up a scheduled push the browser never itself requested.
    fetch('/api/v1/client-updates', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(handleClientUpdatesSummary)
      .catch(() => {
        // Silent - matches the clients-poll fetch above.
      });

    // Same badge-only concern as the Windows fetch above, for the Linux
    // "Client updates" Manage dropdown count - this was missing entirely, so the
    // count only ever appeared after the user opened the Linux Client
    // updates tab directly (which populates it as a side effect of
    // loadLinuxClientUpdates()).
    fetch('/api/v1/linux-client-updates', { cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(handleLinuxClientUpdatesSummary)
      .catch(() => {
        // Silent - matches the clients-poll fetch above.
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
    .then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then(data => {
      state.clients = stampClientPlatform(data.clients || [], 'windows');
      state.staleHours = data.staleHours || 48;
      state.adDescriptionSyncEnabled = !!data.adDescriptionSyncEnabled;
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

  // Same badge-only fetch pollForUpdates() does on every tick, run once
  // immediately on page load - otherwise the Manage dropdown badge stays blank
  // until the first 30s poll tick, a tab visibility change, or the user
  // opening Client updates directly (which populates it as a side effect).
  // Also baselines state.knownScheduledJobId (see handleClientUpdatesSummary).
  fetch('/api/v1/client-updates', { cache: 'no-store' })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then(handleClientUpdatesSummary)
    .catch(() => {
      // Silent - matches pollForUpdates()'s badge fetch.
    });

  // Same badge-only fetch pollForUpdates() does on every tick, run once
  // immediately on page load - otherwise the Linux Manage dropdown badge stays
  // blank until the first 30s poll tick or the user opens Linux Client
  // updates directly (which populates it as a side effect).
  fetch('/api/v1/linux-client-updates', { cache: 'no-store' })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then(handleLinuxClientUpdatesSummary)
    .catch(() => {
      // Silent - matches pollForUpdates()'s badge fetch.
    });

  // Unconditional, mirroring the initial /api/v1/clients fetch above:
  // state.linuxClients must be populated regardless of which view the user
  // lands on, because the Dashboard's combined tiles/charts and the merged
  // Hardware view both read it. Previously this only ran when a Linux
  // Inventory tab was opened, so a user landing on the Dashboard saw
  // Windows-only counts until they clicked into a Linux tab.
  loadLinuxClients();

  loadLicenses();

  byId('searchInput').addEventListener('input', () => {
    state.page.clients = 1;
    state.page.software = 1;
    state.page.hwCpu = 1;
    state.page.hwDisk = 1;
    state.page.hwRam = 1;
    state.page.linuxServices = 1;
    render();
    // The merged Clients table is redrawn by render() itself now; only the
    // Linux Services table still lives outside that pipeline.
    if (state.view === 'linuxServices') {
      renderLinuxServicesTable(state.linuxClients);
    }
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
  window.addEventListener('hashchange', () => {
    Object.assign(state, getInitialViewState());
    render();
    if (state.view === 'deploy') loadDeploySubviewData(state.subview);
    if (state.view === 'settings') loadSettingsSubviewData(state.subview);
    if (state.view === 'licenses') loadLicenses();
    if (state.view === 'clients' || state.view === 'linuxServices' || state.view === 'hardware') loadLinuxClients();
  });
  byId('pkgServerUrl').value = `${window.location.origin}/api/v1/inventory`;
  byId('linuxPkgServerUrl').value = `${window.location.origin}/api/v1/linux/inventory`;
  byId('clientAction').addEventListener('change', updateInstallFieldVisibility);
  byId('clientActionMode').addEventListener('change', updateInstallFieldVisibility);
  byId('installSshAuthMode').addEventListener('change', updateInstallFieldVisibility);
  byId('installPreferredSubnetSaveButton').addEventListener('click', saveInstallPreferredSubnet);
  byId('installTrustNewHostKeys').addEventListener('change', updateInstallTrustNewHostKeysUi);
  byId('installAcknowledgeHostKeyRisk').addEventListener('change', updateInstallTrustNewHostKeysUi);
  byId('linuxUpdatesAuthMode').addEventListener('change', () => updateLinuxAuthModeFieldsUi('linuxUpdatesAuthMode', 'linuxUpdatesCredentialsField', 'linuxUpdatesPasswordField'));
  // linuxUpdatesSelectAll/linuxUpdatesPushButton/updatesUseAdCredentials
  // listeners removed here: Task 1's merged Deploy > Updates markup has no
  // such elements any more (one shared updatesSelectAll/updatesPushButton
  // now covers both platforms, and Windows credentials moved to the
  // updatesWinRmAuthMode dropdown below) - the old byId() calls threw and
  // aborted this whole setup block before it reached the wiring below.
  // Re-wiring push-dispatch/credential-UI to the new elements is Task 3's
  // job, not this one's.
  byId('linuxUpdatesPreferredSubnetSaveButton').addEventListener('click', saveLinuxUpdatesPreferredSubnet);
  byId('linuxUpdatesTrustNewHostKeys').addEventListener('change', updateLinuxUpdatesTrustNewHostKeysUi);
  byId('linuxUpdatesAcknowledgeHostKeyRisk').addEventListener('change', updateLinuxUpdatesTrustNewHostKeysUi);
  byId('linuxUpdatesScheduleMode').addEventListener('change', updateLinuxUpdatesScheduleFieldVisibility);
  byId('linuxUpdatesScheduleSaveButton').addEventListener('click', saveLinuxUpdateSchedule);
  byId('installWinRmAuthMode').addEventListener('change', updateInstallFieldVisibility);
  byId('installButton').addEventListener('click', startClientActionJob);
  byId('installLoadAdAllButton').addEventListener('click', () => loadTargetsFromAd(false));
  byId('installLoadAdMissingButton').addEventListener('click', () => loadTargetsFromAd(true));
  byId('exportClientsBtn').addEventListener('click', exportClients);
  byId('exportSoftwareBtn').addEventListener('click', exportSoftware);
  byId('exportCpuBtn').addEventListener('click', exportHardwareCpu);
  byId('exportDiskBtn').addEventListener('click', exportHardwareDisk);
  byId('exportRamBtn').addEventListener('click', exportHardwareRam);
  // Delegated on document so it keeps working after any of these buttons'
  // rows get replaced outside the full render() pipeline - e.g. a
  // standalone renderFilteredClientsTable() triggered by the Clients
  // pager's Prev/Next, the OS filter, a Linux poll tick, or
  // recalculateActivePagination's live-resize re-render. Binding listeners
  // on the buttons themselves would require re-binding after every
  // innerHTML replacement; delegation needs binding exactly once, here,
  // regardless of how the table DOM changes.
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
      // render() doesn't touch the Linux Services table (it's loaded and
      // rendered through its own loadLinuxClients()/setView('linuxServices')
      // path, not the main render pipeline) - re-render it directly. Every
      // other table, including the merged Clients table
      // (data-sort-table="clients"), goes through render().
      if (table === 'linuxServices') {
        renderLinuxServicesTable(state.linuxClients);
      } else if (table === 'updates') {
        renderMergedUpdatesTable();
      } else {
        render();
      }
      return;
    }

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

    const attemptBtn = e.target.closest('[data-attempt-toggle]');
    if (attemptBtn) {
      const jobId = attemptBtn.dataset.attemptJob;
      const key = 'attempt:' + jobId + ':' + attemptBtn.dataset.attemptToggle;
      // Scoped to the button's own status box (.install-status), not a
      // bare document-wide query - harmless today since only one status
      // box (installStatus) ever renders attempt rows, but a job id +
      // index pair is only unique WITHIN one status box's own render, not
      // guaranteed unique document-wide if a future status box (e.g.
      // Phase 4's Updates view) renders attempt rows too.
      const container = attemptBtn.closest('.install-status');
      const row = container && container.querySelector(`[data-attempt-details="${attemptBtn.dataset.attemptToggle}"][data-attempt-job="${CSS.escape(jobId)}"]`);
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

    const linuxClientBtn = e.target.closest('[data-linux-client]');
    if (linuxClientBtn) {
      const key = 'linux-client:' + linuxClientBtn.dataset.linuxClient;
      const row = document.querySelector(`[data-linux-client-details="${linuxClientBtn.dataset.linuxClient}"]`);
      if (row) {
        const nowHidden = row.classList.toggle('hidden');
        if (nowHidden) { state.expandedDetails.delete(key); } else { state.expandedDetails.add(key); }
      }
      return;
    }

    const linuxServicesBtn = e.target.closest('[data-linux-services]');
    if (linuxServicesBtn) {
      const key = 'linux-services:' + linuxServicesBtn.dataset.linuxServices;
      const row = document.querySelector(`[data-linux-services-details="${linuxServicesBtn.dataset.linuxServices}"]`);
      if (row) {
        const nowHidden = row.classList.toggle('hidden');
        if (nowHidden) { state.expandedDetails.delete(key); } else { state.expandedDetails.add(key); }
      }
      return;
    }

    const deleteBtn = e.target.closest('[data-delete-client]');
    if (deleteBtn) {
      deleteClient(deleteBtn.dataset.deleteClient);
      return;
    }

    const deleteLinuxBtn = e.target.closest('[data-delete-linux-client]');
    if (deleteLinuxBtn) {
      deleteLinuxClient(deleteLinuxBtn.dataset.deleteLinuxClient);
      return;
    }

    const osFilterBtn = e.target.closest('[data-os-filter]');
    if (osFilterBtn) {
      // One pill, two consumers: the chip writes to whichever page is
      // showing, resets that page's own pagination, and redraws only that
      // page. The pill is hidden everywhere else, so no other view can
      // reach this block.
      const filter = osFilterBtn.dataset.osFilter;
      if (state.view === 'clients') {
        state.osFilter.clients = filter;
        state.page.clients = 1;
        renderOsFilterActive();
        renderFilteredClientsTable();
      } else if (state.view === 'hardware') {
        state.osFilter.hardware = filter;
        state.page.hwCpu = 1;
        state.page.hwDisk = 1;
        state.page.hwRam = 1;
        renderOsFilterActive();
        renderFilteredHardwarePage();
      } else if (state.view === 'deploy' && state.subview === 'updates') {
        state.osFilter.deploy = filter;
        state.page.updates = 1;
        renderOsFilterActive();
        renderMergedUpdatesTable();
      }
    }
  });
  byId('deploySubtabActions').addEventListener('click', () => setView('deploy', 'actions'));
  byId('deploySubtabUpdates').addEventListener('click', () => setView('deploy', 'updates'));
  byId('deploySubtabPackage').addEventListener('click', () => setView('deploy', 'package'));
  byId('settingsSubtabServer').addEventListener('click', () => setView('settings', 'server'));
  byId('settingsSubtabWindows').addEventListener('click', () => setView('settings', 'windows'));
  byId('settingsSubtabLinux').addEventListener('click', () => setView('settings', 'linux'));
  byId('settingsSubtabCertificate').addEventListener('click', () => setView('settings', 'certificate'));
  byId('settingsSubtabAdminPassword').addEventListener('click', () => setView('settings', 'adminPassword'));
  byId('deployTab').addEventListener('click', () => setView('deploy', 'actions'));
  byId('settingsTab').addEventListener('click', () => setView('settings', 'server'));

  function toggleDropdown(buttonId, menuId, forceClosed) {
    const button = byId(buttonId);
    const menu = byId(menuId);
    const shouldOpen = forceClosed ? false : menu.classList.contains('hidden');
    menu.classList.toggle('hidden', !shouldOpen);
    button.setAttribute('aria-expanded', String(shouldOpen));
    // Menu opened - move focus onto its first item, matching the standard
    // WAI-ARIA menu-button pattern this markup already declares via
    // role="menu"/menuitem/aria-haspopup/aria-expanded but never actually
    // backed with keyboard behavior. Runs for a mouse open too (not just
    // keyboard) - deliberate, so focus is always inside the menu that's
    // visibly open, which is what handleDropdownKeydown below relies on.
    if (shouldOpen) {
      const firstItem = menu.querySelector('.topnav-dropdown-item');
      if (firstItem) firstItem.focus();
    }
  }

  // Escape closes whichever dropdown the keypress happened inside and
  // returns focus to that menu's own trigger button; ArrowDown/ArrowUp
  // move focus between its items, wrapping at each end. One handler for
  // both Fleet and Manage - they're structurally identical (a trigger
  // button plus a menu of item buttons), read from the closest
  // .topnav-dropdown-menu rather than hardcoded to either one.
  function handleDropdownKeydown(event) {
    if (event.key !== 'Escape' && event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const menu = event.target.closest('.topnav-dropdown-menu');
    if (!menu) return;
    const button = menu.previousElementSibling;
    if (event.key === 'Escape') {
      event.preventDefault();
      menu.classList.add('hidden');
      button.setAttribute('aria-expanded', 'false');
      button.focus();
      return;
    }
    const items = Array.from(menu.querySelectorAll('.topnav-dropdown-item'));
    const currentIndex = items.indexOf(document.activeElement);
    event.preventDefault();
    const nextIndex = event.key === 'ArrowDown'
      ? (currentIndex + 1) % items.length
      : (currentIndex - 1 + items.length) % items.length;
    items[nextIndex].focus();
  }

  byId('fleetDropdownButton').addEventListener('click', (event) => {
    event.stopPropagation();
    toggleDropdown('fleetDropdownButton', 'fleetDropdownMenu');
    toggleDropdown('manageDropdownButton', 'manageDropdownMenu', true);
  });
  byId('manageDropdownButton').addEventListener('click', (event) => {
    event.stopPropagation();
    toggleDropdown('manageDropdownButton', 'manageDropdownMenu');
    toggleDropdown('fleetDropdownButton', 'fleetDropdownMenu', true);
  });
  byId('fleetDropdownMenu').addEventListener('keydown', handleDropdownKeydown);
  byId('manageDropdownMenu').addEventListener('keydown', handleDropdownKeydown);
  // Clicking any dropdown item closes its own menu (the item's own click
  // handler, registered above/in earlier tasks, has already fired and set
  // the view by the time this delegated listener runs).
  document.querySelectorAll('.topnav-dropdown-menu').forEach((menu) => {
    menu.addEventListener('click', (event) => {
      if (event.target.closest('.topnav-dropdown-item')) {
        menu.classList.add('hidden');
        menu.previousElementSibling.setAttribute('aria-expanded', 'false');
      }
    });
  });
  document.addEventListener('click', () => {
    toggleDropdown('fleetDropdownButton', 'fleetDropdownMenu', true);
    toggleDropdown('manageDropdownButton', 'manageDropdownMenu', true);
  });
  byId('updatesSaveCredentialsButton').addEventListener('click', saveClientUpdateCredentials);
  byId('updatesClearCredentialsButton').addEventListener('click', clearClientUpdateCredentials);
  byId('updatesPushButton').addEventListener('click', startClientUpdateJob);
  byId('updatesSelectAll').addEventListener('change', () => {
    const checked = byId('updatesSelectAll').checked;
    document.querySelectorAll('.updates-row-checkbox').forEach(checkbox => { checkbox.checked = checked; });
    updateUpdatesSelectionState();
  });
  document.addEventListener('change', event => {
    if (event.target.classList.contains('updates-row-checkbox')) {
      updateUpdatesSelectionState();
    }
  });
  byId('pkgSaveButton').addEventListener('click', savePackageConfig);
  byId('linuxPkgSaveButton').addEventListener('click', saveLinuxPackageConfig);
  byId('linuxPkgDownloadButton').addEventListener('click', () => {
    window.location.href = '/api/v1/linux-client-package/download';
  });
  byId('pkgDownloadButton').addEventListener('click', () => {
    window.location.href = '/api/v1/client-package/download';
  });
  byId('generalSaveButton').addEventListener('click', () => saveServerSettings(false));
  byId('windowsSettingsSaveButton').addEventListener('click', saveWindowsSettings);
  byId('linuxSettingsSaveButton').addEventListener('click', saveLinuxSettings);
  byId('generalAdUseServiceIdentity').addEventListener('change', updateAdIdentityFields);
  byId('generalAdSyncMode').addEventListener('change', updateAdSyncIntervalField);
  byId('updatesScheduleMode').addEventListener('change', updateScheduleFieldVisibility);
  byId('updatesScheduleSaveButton').addEventListener('click', saveClientUpdateSchedule);
  byId('certUploadButton').addEventListener('click', uploadCertificate);
  byId('certDeleteButton').addEventListener('click', deleteCertificate);
  byId('licensesTab').addEventListener('click', () => setView('licenses'));
  byId('linuxServicesTab').addEventListener('click', () => setView('linuxServices'));
  byId('exportLinuxServicesBtn').addEventListener('click', exportLinuxServices);
  byId('exportLicensesBtn').addEventListener('click', exportLicenses);
  byId('licenseAddButton').addEventListener('click', () => openLicenseForm(null));
  byId('licenseSaveButton').addEventListener('click', saveLicense);
  byId('licenseCancelButton').addEventListener('click', closeLicenseForm);
  byId('licenseName').addEventListener('input', updateVersionDatalist);
  byId('licenseName').addEventListener('change', applySoftwareComputers);
  byId('licenseName').addEventListener('focus', handleDatalistFieldFocus);
  byId('licenseName').addEventListener('blur', handleDatalistFieldBlur);
  byId('licenseVersion').addEventListener('focus', handleDatalistFieldFocus);
  byId('licenseVersion').addEventListener('blur', handleDatalistFieldBlur);
  byId('licenseComputerAddButton').addEventListener('click', addLicenseComputerFromInput);
  byId('licenseComputerInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addLicenseComputerFromInput();
    }
  });
  byId('adminPasswordSaveButton').addEventListener('click', changeAdminPassword);
  byId('ingestionTokenRegenerateButton').addEventListener('click', regenerateIngestionToken);
  byId('linuxCredsSaveButton').addEventListener('click', saveLinuxUpdateCredentials);
  byId('linuxCredsClearButton').addEventListener('click', clearLinuxUpdateCredentials);
  byId('linuxSshKeyUploadButton').addEventListener('click', uploadLinuxSshKey);
  byId('linuxSshKeyDeleteButton').addEventListener('click', deleteLinuxSshKey);
  byId('themeToggle').addEventListener('click', toggleTheme);
  byId('logoutButton').addEventListener('click', handleLogout);
  byId('logoutReloadButton').addEventListener('click', () => window.location.reload());
  updateThemeToggle();
  if (state.view === 'deploy') loadDeploySubviewData(state.subview);
  if (state.view === 'settings') loadSettingsSubviewData(state.subview);
  if (state.view === 'licenses') loadLicenses();
  updateInstallFieldVisibility();
  loadInstallHistory();
  updateLinuxAuthModeFieldsUi('linuxUpdatesAuthMode', 'linuxUpdatesCredentialsField', 'linuxUpdatesPasswordField');
}());
