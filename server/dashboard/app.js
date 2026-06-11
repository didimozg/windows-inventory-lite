(function () {
  const staleHours = 48;
  const state = {
    clients: [], view: getInitialView(), installJobId: null, installPollTimer: null, installJobs: [],
    packageStatus: null,
    sort: {
      clients: { key: 'computerName', dir: 1 },
      software: { key: 'name', dir: 1 },
      hwCpu: { key: 'name', dir: 1 },
      hwDisk: { key: 'model', dir: 1 },
      hwRam: { key: 'totalMb', dir: -1 }
    }
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function getInitialView() {
    const hash = window.location.hash.replace(/^#/, '').toLowerCase();
    if (hash === 'software') return 'software';
    if (hash === 'hardware') return 'hardware';
    if (hash === 'client-actions' || hash === 'actions' || hash === 'install') return 'install';
    if (hash === 'client-package' || hash === 'package') return 'package';
    return 'clients';
  }

  function setView(view) {
    state.view = view;
    const hash = view === 'install' ? 'client-actions' : view === 'package' ? 'client-package' : view;
    if (window.location.hash.replace(/^#/, '') !== hash) {
      window.location.hash = hash;
      return;
    }
    render();
    if (view === 'install') loadInstallHistory();
    if (view === 'package') loadPackageStatus();
  }

  function text(value) {
    return value === undefined || value === null || value === '' ? 'Unknown' : String(value);
  }

  function activated(value) {
    return value ? 'Activated' : 'Not detected';
  }

  function formatDateTime(value) {
    if (!value) return 'Unknown';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return text(value);
    return date.toLocaleString();
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

  function isStale(client) {
    const date = new Date(client.collectedAt || client.sourceUpdatedAt || 0);
    return Number.isNaN(date.getTime()) || ((Date.now() - date.getTime()) / 36e5) > staleHours;
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

  function downloadCsv(filename, rows) {
    const csv = rows.map(row =>
      row.map(cell => {
        const s = String(cell == null ? '' : cell);
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
    const rows = [['Computer', 'Domain', 'IP Addresses', 'Client Version', 'OS', 'OS Version', 'Build', 'Office', 'Office Version', 'Windows Activated', 'Office Activated', 'Software Count', 'Collected', 'Stale', 'CPU', 'RAM', 'Disks', 'USB Storage']].concat(
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
          c.hasUsbStorage ? 'Yes' : 'No'
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
      })
      .catch(error => {
        byId('pkgStatus').textContent = `Package status unavailable: ${error.message}`;
      });
  }

  function renderPackageStatus(data) {
    const parts = [];
    if (data.net35Present) parts.push('Net 3.5: v' + escapeHtml(data.net35Version || 'unknown'));
    if (data.net40Present) parts.push('Net 4.0: v' + escapeHtml(data.net40Version || 'unknown'));
    if (!data.net35Present && !data.net40Present) parts.push('No client executables in package');
    if (!data.deployScriptPresent) parts.push('Deploy script missing');
    if (data.cmdServerUrl) parts.push('URL: ' + escapeHtml(data.cmdServerUrl));
    byId('pkgStatus').innerHTML = parts.join(' &nbsp;&middot;&nbsp; ');
  }

  function savePackageConfig() {
    const serverUrl = byId('pkgServerUrl').value.trim();
    const token = byId('pkgToken').value.trim();
    const intervalHours = parseInt(byId('pkgIntervalHours').value, 10) || 6;
    if (!serverUrl) { window.alert('Enter server URL.'); return; }

    byId('pkgSaveButton').disabled = true;
    byId('pkgMessage').className = 'pkg-message hidden';

    fetch('/api/v1/client-package/configure', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serverUrl, token, intervalHours })
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
    byId('staleCount').textContent = clients.filter(isStale).length;
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
    const rows = applySort(clients.filter(client => clientMatches(client, query)), c => clientSortValue(c, sortKey), sortDir).map(client => {
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
        <td>${escapeHtml(item.installDate)}</td>
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
        <td><button class="link-button" type="button" data-client="${clientId}">${escapeHtml(client.computerName)}</button>${usbBadge}<small>${escapeHtml(client.domain)}</small>${ipAddresses ? `<small>${escapeHtml(ipAddresses)}</small>` : ''}</td>
        <td>${escapeHtml(client.clientVersion)}</td>
        <td>${escapeHtml(os.caption)}<small>${escapeHtml(os.version)} build ${escapeHtml(os.buildNumber)}</small></td>
        <td>${escapeHtml(office.name)}<small>${escapeHtml(office.version)}</small></td>
        <td>${escapeHtml(activated(windowsActivation.activated))}</td>
        <td>${escapeHtml(activated(officeActivation.activated))}</td>
        <td>${softwareCount}</td>
        <td>${escapeHtml(formatDateTime(client.collectedAt || client.sourceUpdatedAt))}</td>
        <td><button class="danger-button" type="button" data-delete-client="${escapeHtml(client.computerName)}">Delete</button></td>
      </tr>
      <tr class="details-row hidden" data-client-details="${clientId}">
        <td colspan="9">
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

    byId('inventoryBody').innerHTML = rows.join('') || '<tr><td colspan="9" class="empty">No matching inventory records.</td></tr>';
  }

  function renderSoftwareTable(clients) {
    const query = byId('searchInput').value.trim();
    const { key: sortKey, dir: sortDir } = state.sort.software;
    const rows = applySort(getSoftwareGroups(clients).filter(group => softwareMatches(group, query)), g => softwareSortValue(g, sortKey), sortDir).map(group => {
      const computers = group.clients
        .map(client => `<li>${escapeHtml(client.computerName)}<small>${escapeHtml(client.domain)}</small></li>`)
        .join('');

      const groupId = safeId(softwareKey(group));

      return `<tr>
        <td><button class="link-button" type="button" data-software="${groupId}">${escapeHtml(group.name)}</button></td>
        <td>${escapeHtml(group.version)}</td>
        <td>${escapeHtml(group.publisher)}</td>
        <td>${group.clients.length}</td>
        <td>${group.clients.map(client => escapeHtml(client.computerName)).join(', ')}</td>
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
          <td>${g.cores != null ? g.cores : 'Unknown'}</td>
          <td>${escapeHtml(clock)}</td>
          <td>${g.clients.length}</td>
          <td>${g.clients.map(c => escapeHtml(c.computerName)).join(', ')}</td>
        </tr>
        <tr class="details-row hidden" data-hw-details="${id}">
          <td colspan="5"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwCpuBody').innerHTML = cpuRows.join('') || '<tr><td colspan="5" class="empty">No CPU data.</td></tr>';

    const { key: diskSortKey, dir: diskSortDir } = state.sort.hwDisk;
    const diskRows = applySort(getDiskGroups(clients).filter(g => hwMatches([g.model, g.type, ...g.clients.map(c => c.computerName)].join(' '), query)), g => diskSortValue(g, diskSortKey), diskSortDir).map(g => {
        const id = safeId('disk:' + g.model + g.sizeGb);
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        const usbBadge = g.usb ? ' <span class="usb-badge">USB</span>' : '';
        const size = g.sizeGb ? `${g.sizeGb} GB` : 'Unknown';
        return `<tr${g.usb ? ' class="usb-row"' : ''}>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.model)}</button>${usbBadge}</td>
          <td>${escapeHtml(g.type)}</td>
          <td>${escapeHtml(size)}</td>
          <td>${g.clients.length}</td>
          <td>${g.clients.map(c => escapeHtml(c.computerName)).join(', ')}</td>
        </tr>
        <tr class="details-row hidden" data-hw-details="${id}">
          <td colspan="5"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwDiskBody').innerHTML = diskRows.join('') || '<tr><td colspan="5" class="empty">No storage data.</td></tr>';

    const { key: ramSortKey, dir: ramSortDir } = state.sort.hwRam;
    const ramRows = applySort(getRamGroups(clients).filter(g => hwMatches([g.totalGb, ...g.clients.map(c => c.computerName)].join(' '), query)), g => ramSortValue(g, ramSortKey), ramSortDir).map(g => {
        const id = safeId('ram:' + g.totalMb + ':' + g.moduleCount);
        const computers = g.clients.map(c => `<li>${escapeHtml(c.computerName)}<small>${escapeHtml(c.domain)}</small></li>`).join('');
        return `<tr>
          <td><button class="link-button" type="button" data-hw="${id}">${escapeHtml(g.totalGb)}</button></td>
          <td>${g.moduleCount || 'Unknown'}</td>
          <td>${g.clients.length}</td>
          <td>${g.clients.map(c => escapeHtml(c.computerName)).join(', ')}</td>
        </tr>
        <tr class="details-row hidden" data-hw-details="${id}">
          <td colspan="4"><div class="details"><ul class="computer-list">${computers}</ul></div></td>
        </tr>`;
      });
    byId('hwRamBody').innerHTML = ramRows.join('') || '<tr><td colspan="4" class="empty">No RAM data.</td></tr>';
  }

  function bindDetails() {
    document.querySelectorAll('[data-client]').forEach(button => {
      button.addEventListener('click', () => {
        const row = document.querySelector(`[data-client-details="${button.dataset.client}"]`);
        if (row) row.classList.toggle('hidden');
      });
    });

    document.querySelectorAll('[data-software]').forEach(button => {
      button.addEventListener('click', () => {
        const row = document.querySelector(`[data-software-details="${button.dataset.software}"]`);
        if (row) row.classList.toggle('hidden');
      });
    });

    document.querySelectorAll('[data-hw]').forEach(button => {
      button.addEventListener('click', () => {
        const row = document.querySelector(`[data-hw-details="${button.dataset.hw}"]`);
        if (row) row.classList.toggle('hidden');
      });
    });

    document.querySelectorAll('[data-delete-client]').forEach(button => {
      button.addEventListener('click', () => {
        deleteClient(button.dataset.deleteClient);
      });
    });
  }

  function render() {
    renderSummary(state.clients);
    renderSortHeaders();
    renderTable(state.clients);
    renderSoftwareTable(state.clients);
    renderHardwarePage(state.clients);
    byId('clientsView').classList.toggle('hidden', state.view !== 'clients');
    byId('softwareView').classList.toggle('hidden', state.view !== 'software');
    byId('hardwareView').classList.toggle('hidden', state.view !== 'hardware');
    byId('installView').classList.toggle('hidden', state.view !== 'install');
    byId('packageView').classList.toggle('hidden', state.view !== 'package');
    byId('clientsTab').classList.toggle('active', state.view === 'clients');
    byId('softwareTab').classList.toggle('active', state.view === 'software');
    byId('hardwareTab').classList.toggle('active', state.view === 'hardware');
    byId('installTab').classList.toggle('active', state.view === 'install');
    byId('packageTab').classList.toggle('active', state.view === 'package');
    bindDetails();
  }

  fetch('/api/v1/clients', { cache: 'no-store' })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then(data => {
      state.clients = data.clients || [];
      byId('generatedAt').textContent = `Generated: ${formatDateTime(data.generatedAt)} | Server version: ${text(data.serverVersion)}`;
      render();
    })
    .catch(error => {
      byId('generatedAt').textContent = `Inventory index is not available: ${error.message}`;
      render();
    });

  byId('searchInput').addEventListener('input', render);
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
  });
  byId('installServerUrl').value = `${window.location.origin}/api/v1/inventory`;
  byId('clientAction').addEventListener('change', updateClientActionUi);
  byId('installButton').addEventListener('click', startClientActionJob);
  byId('exportClientsBtn').addEventListener('click', exportClients);
  byId('exportSoftwareBtn').addEventListener('click', exportSoftware);
  byId('exportCpuBtn').addEventListener('click', exportHardwareCpu);
  byId('exportDiskBtn').addEventListener('click', exportHardwareDisk);
  byId('exportRamBtn').addEventListener('click', exportHardwareRam);
  document.addEventListener('click', e => {
    const th = e.target.closest('th[data-sort-key]');
    if (!th) return;
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
    render();
  });
  byId('packageTab').addEventListener('click', () => setView('package'));
  byId('pkgSaveButton').addEventListener('click', savePackageConfig);
  byId('pkgDownloadButton').addEventListener('click', () => { window.location.href = '/api/v1/client-package/download'; });
  if (state.view === 'package') loadPackageStatus();
  updateClientActionUi();
  loadInstallHistory();
}());
