(() => {
  const tabs = Array.from(document.querySelectorAll('.admin-tab'));
  const configForm = document.getElementById('config-form');
  const configEditor = document.getElementById('config-editor');
  const historyPanel = document.getElementById('history-panel');
  const historyList = document.getElementById('history-list');
  const panelTitle = document.getElementById('panel-title');
  const versionBadge = document.getElementById('version-badge');
  const reasonInput = document.getElementById('reason-input');
  const saveBtn = document.getElementById('save-btn');
  const statusBanner = document.getElementById('status-banner');
  const loadedAtEl = document.getElementById('loaded-at');

  const oauthPanel = document.getElementById('oauth-panel');
  const oauthReloadBtn = document.getElementById('oauth-clients-reload');
  const oauthEmptyState = document.getElementById('oauth-clients-empty');
  const oauthTableWrapper = document.getElementById('oauth-client-table-wrapper');
  const oauthTable = document.getElementById('oauth-client-table');
  const oauthRows = document.getElementById('oauth-client-rows');
  const oauthForm = document.getElementById('oauth-client-form');
  const oauthId = document.getElementById('oauth-client-id');
  const oauthName = document.getElementById('oauth-client-name');
  const oauthRedirects = document.getElementById('oauth-client-redirects');
  const oauthScopes = document.getElementById('oauth-client-scopes');
  const oauthCancel = document.getElementById('oauth-client-cancel');
  const oauthSave = document.getElementById('oauth-client-save');
  const oauthSecretBanner = document.getElementById('oauth-secret-banner');
  const exportBtn = document.getElementById('config-export-btn');
  const importBtn = document.getElementById('config-import-btn');
  const importInput = document.getElementById('config-import-input');
  const helpBtn = document.getElementById('config-help-btn');
  const helpModal = document.getElementById('help-modal');
  const helpModalClose = document.getElementById('help-modal-close');
  const helpModalTitle = document.getElementById('help-modal-title');
  const helpModalBody = document.getElementById('help-modal-body');

  const backupsPanel = document.getElementById('backups-panel');
  const backupRefreshBtn = document.getElementById('backups-refresh-btn');
  const backupRunBtn = document.getElementById('backups-run-btn');
  const backupScheduleForm = document.getElementById('backup-schedule-form');
  const backupScheduleEnabled = document.getElementById('backup-schedule-enabled');
  const backupFrequency = document.getElementById('backup-frequency');
  const backupTime = document.getElementById('backup-time');
  const backupWeekday = document.getElementById('backup-weekday');
  const backupMinute = document.getElementById('backup-minute');
  const backupRetention = document.getElementById('backup-retention');
  const backupScheduleSave = document.getElementById('backup-schedule-save');
  const backupLastRun = document.getElementById('backup-last-run');
  const backupNextRun = document.getElementById('backup-next-run');
  const backupTableWrapper = document.getElementById('backup-table-wrapper');
  const backupTableBody = document.getElementById('backup-rows');
  const backupEmptyState = document.getElementById('backup-empty');
  const backupSectionCheckboxes = Array.from(document.querySelectorAll('.backup-section-checkbox'));
  const backupFrequencyRows = Array.from(document.querySelectorAll('[data-frequency-row]'));
  const appTimeZone = document.body?.dataset?.appTimezone || 'UTC';

  if (
    !configForm ||
    !configEditor ||
    !historyPanel ||
    !historyList ||
    !panelTitle ||
    !versionBadge ||
    !reasonInput ||
    !saveBtn ||
    !statusBanner
  ) {
    return;
  }

  const configSections = ['providers', 'security', 'mfa', 'app-settings'];
  const labels = {
    providers: 'Providers',
    security: 'Security',
    mfa: 'MFA',
    'app-settings': 'App Settings',
  };
  let currentSection = 'providers';

  const state = {
    data: { providers: null, security: null, mfa: null, 'app-settings': null },
    history: { providers: [], security: [], mfa: [], 'app-settings': [] },
    loadedAt: null,
  };

  const oauthState = {
    clients: [],
    loading: false,
  };

  const backupState = {
    loading: false,
    loaded: false,
    savingSchedule: false,
    runningBackup: false,
    schedule: null,
    backups: [],
  };

  const defaultHelpContent = {
    title: 'Configuration Help',
    body: '<p>No help content is available for this section yet.</p>',
  };

  const helpContent = {
    providers: {
      title: 'Providers Configuration',
      body: `
        <p>Use this JSON to choose the active media provider and supply the credentials that AuthPortal needs to manage users on Plex, Emby, or Jellyfin.</p>
        <ul>
          <li><code>active</code> selects the provider key: <code>plex</code>, <code>emby</code>, or <code>jellyfin</code>.</li>
          <li>The nested provider objects hold connection details—only the active provider must be fully populated, but keeping the others filled lets you switch quickly.</li>
          <li>Values such as <code>serverUrl</code> should be fully qualified URLs, and API tokens/keys should be copied from your media server.</li>
        </ul>
        <pre><code>{
  "active": "plex",
  "plex": {
    "ownerToken": "your-plex-token",
    "serverMachineId": "machine-id",
    "serverName": "My Plex Server"
  },
  "emby": {
    "serverUrl": "https://emby.example.com",
    "appName": "AuthPortal",
    "appVersion": "2.0.3",
    "apiKey": "emby-api-key",
    "ownerUsername": "embyadmin",
    "ownerId": "12345"
  },
  "jellyfin": {
    "serverUrl": "https://jellyfin.example.com",
    "appName": "AuthPortal",
    "appVersion": "2.0.3",
    "apiKey": "jellyfin-api-key"
  }
}</code></pre>
        <p>Keep tokens secure&mdash;changes save immediately and update the live provider integration.</p>
      `,
    },
    security: {
      title: 'Security Configuration',
      body: `
        <p>Control cookie lifetimes and browser security posture for the admin and portal experience.</p>
        <ul>
          <li><code>sessionTtl</code> is a Go duration (<code>24h</code>, <code>2h30m</code>, <code>7d</code>) for authenticated sessions.</li>
          <li><code>sessionSameSite</code> accepts <code>lax</code>, <code>strict</code>, or <code>none</code>. Use <code>none</code> only with HTTPS.</li>
          <li><code>forceSecureCookie</code> forces cookies to use the Secure flag even if <code>APP_BASE_URL</code> is HTTP.</li>
          <li><code>sessionCookieDomain</code> can scope cookies to a parent domain (e.g., <code>auth.example.com</code>).</li>
        </ul>
        <pre><code>{
  "sessionTtl": "24h",
  "sessionSameSite": "lax",
  "forceSecureCookie": true,
  "sessionCookieDomain": "auth.example.com"
}</code></pre>
        <p>Trim whitespace and only set <code>forceSecureCookie</code> to <code>true</code> when end-users connect over HTTPS.</p>
      `,
    },
    mfa: {
      title: 'MFA Configuration',
      body: `
        <p>Fine-tune multi-factor authentication behaviour for end-users.</p>
        <ul>
          <li><code>issuer</code> is the label displayed in authenticator apps (short and recognizable).</li>
          <li><code>enrollmentEnabled</code> controls whether users can enroll MFA devices.</li>
          <li><code>enforceForAllUsers</code> forces MFA at sign-in&mdash;make sure enrollment remains enabled if you enforce MFA.</li>
        </ul>
        <pre><code>{
  "issuer": "AuthPortal",
  "enrollmentEnabled": true,
  "enforceForAllUsers": false
}</code></pre>
        <p>After enabling enforcement, communicate the change so users enroll before their next sign-in.</p>
      `,
    },
    'app-settings': {
      title: 'App Settings Configuration',
      body: `
        <p>Customize small pieces of the user experience that do not belong to a specific provider or security setting.</p>
        <ul>
          <li><code>loginExtraLinkUrl</code> and <code>loginExtraLinkText</code> add an optional button to the authorized portal header. Leave either blank to fall back to the shipped defaults.</li>
          <li><code>unauthRequestEmail</code> and <code>unauthRequestSubject</code> power the mailto link shown on the unauthorized page. Provide a valid email address so users can reach you; empty values revert to defaults.</li>
        </ul>
        <pre><code>{
  "loginExtraLinkUrl": "/support",
  "loginExtraLinkText": "Support",
  "unauthRequestEmail": "help@example.com",
  "unauthRequestSubject": "Request Access"
}</code></pre>
        <p>Relative URLs are allowed for the extra login link; absolute URLs must include a scheme such as <code>https://</code>.</p>
      `,
    },
  };

  let helpModalIsOpen = false;

  const isConfigSection = (section) => configSections.includes(section);

  const clearStatus = () => {
    statusBanner.textContent = '';
    statusBanner.className = 'status-banner';
  };

  const showStatus = (message, type = 'info') => {
    statusBanner.textContent = message;
    statusBanner.className = `status-banner ${type} show`;
  };

  const updateLoadedAt = () => {
    if (!loadedAtEl) {
      return;
    }
    if (!state.loadedAt) {
      loadedAtEl.textContent = '-';
      return;
    }
    try {
      loadedAtEl.textContent = new Date(state.loadedAt).toLocaleString();
    } catch {
      loadedAtEl.textContent = state.loadedAt;
    }
  };

  const getHelpContent = (section) => helpContent[section] || defaultHelpContent;

  const handleHelpKeydown = (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeHelpModal();
    }
  };

  const closeHelpModal = () => {
    if (!helpModalIsOpen || !helpModal) {
      return;
    }
    helpModal.hidden = true;
    helpModalIsOpen = false;
    document.body.classList.remove('modal-open');
    document.removeEventListener('keydown', handleHelpKeydown);
    if (helpBtn && !helpBtn.hidden) {
      helpBtn.focus();
    }
  };

  const openHelpModal = (section) => {
    if (!helpModal || !helpModalBody || !helpModalTitle) {
      return;
    }
    const content = getHelpContent(section);
    helpModalTitle.textContent = content.title || defaultHelpContent.title;
    helpModalBody.innerHTML = (content.body || defaultHelpContent.body).trim();
    helpModal.hidden = false;
    helpModalIsOpen = true;
    document.body.classList.add('modal-open');
    document.addEventListener('keydown', handleHelpKeydown);
    if (helpModalClose) {
      helpModalClose.focus();
    }
  };

  const updateHelpButton = (section) => {
    if (!helpBtn) {
      return;
    }
    const show = isConfigSection(section);
    helpBtn.hidden = !show;
    helpBtn.disabled = !show;
    if (show) {
      const label = labels[section] || section;
      helpBtn.dataset.section = section;
      helpBtn.setAttribute('aria-label', `Show help for ${label} configuration`);
      helpBtn.title = `Show ${label} help`;
    } else {
      delete helpBtn.dataset.section;
      helpBtn.removeAttribute('aria-label');
      helpBtn.removeAttribute('title');
      if (helpModalIsOpen) {
        closeHelpModal();
      }
    }
  };

  const setActiveTab = () => {
    tabs.forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.section === currentSection);
    });
  };

  const showConfigPanels = () => {
    configForm.hidden = false;
    historyPanel.hidden = false;
    if (oauthPanel) {
      oauthPanel.hidden = true;
    }
    if (backupsPanel) {
      backupsPanel.hidden = true;
    }
  };

  const showOAuthPanel = () => {
    configForm.hidden = true;
    historyPanel.hidden = true;
    if (oauthPanel) {
      oauthPanel.hidden = false;
    }
    if (backupsPanel) {
      backupsPanel.hidden = true;
    }
  };

  const showBackupsPanel = () => {
    configForm.hidden = true;
    historyPanel.hidden = true;
    if (oauthPanel) {
      oauthPanel.hidden = true;
    }
    if (backupsPanel) {
      backupsPanel.hidden = false;
    }
  };

  const setConfigLoading = (isLoading) => {
    if (configForm.hidden) {
      return;
    }
    if (isLoading) {
      configEditor.value = 'Loading.';
      configEditor.disabled = true;
      reasonInput.disabled = true;
      saveBtn.disabled = true;
      versionBadge.textContent = 'v-';
      historyList.innerHTML = '<li>Loading.</li>';
    } else {
      configEditor.disabled = false;
      reasonInput.disabled = false;
      saveBtn.disabled = false;
    }
  };

  const backupDefaultSections = ['providers', 'security', 'mfa', 'app-settings'];

  const getSelectedBackupSections = () => {
    if (!backupSectionCheckboxes.length) {
      return backupDefaultSections.slice();
    }
    const selected = backupSectionCheckboxes
      .filter((checkbox) => checkbox.checked)
      .map((checkbox) => checkbox.value)
      .filter(Boolean);
    if (!selected.length) {
      return backupDefaultSections.slice();
    }
    return selected;
  };

  const updateBackupControls = () => {
    const busy = backupState.loading || backupState.runningBackup;
    if (backupRunBtn) {
      backupRunBtn.disabled = busy;
    }
    if (backupRefreshBtn) {
      backupRefreshBtn.disabled = backupState.loading;
    }
    if (backupScheduleSave) {
      backupScheduleSave.disabled = backupState.savingSchedule;
    }
    const scheduleInputs = [
      backupScheduleEnabled,
      backupFrequency,
      backupTime,
      backupWeekday,
      backupMinute,
      backupRetention,
    ].filter(Boolean);
    scheduleInputs.forEach((input) => {
      input.disabled = backupState.savingSchedule;
    });
    backupSectionCheckboxes.forEach((checkbox) => {
      checkbox.disabled = backupState.savingSchedule;
    });
  };

  const updateScheduleVisibility = () => {
    if (!backupFrequency || !backupFrequencyRows.length) {
      return;
    }
    const frequency = String(backupFrequency.value || 'daily').toLowerCase();
    backupFrequencyRows.forEach((row) => {
      const allowed = (row.dataset.frequencyRow || '')
        .split(/\s+/)
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
      row.hidden = allowed.length > 0 && !allowed.includes(frequency);
    });
  };

  const downloadBackup = (name) => {
    if (!name) {
      return;
    }
    const link = document.createElement('a');
    link.href = `/api/admin/backups/${encodeURIComponent(name)}`;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const setCheckboxValue = (el, value) => {
    if (el) {
      el.checked = Boolean(value);
    }
  };

  const setInputValue = (el, value) => {
    if (el) {
      el.value = value;
    }
  };

  const renderBackupSchedule = () => {
    if (!backupScheduleForm) {
      return;
    }
    const schedule = backupState.schedule || {};
    setCheckboxValue(backupScheduleEnabled, schedule.enabled);
    setInputValue(backupFrequency, String(schedule.frequency || 'daily'));
    setInputValue(backupTime, schedule.timeOfDay || '02:00');
    setInputValue(backupWeekday, schedule.dayOfWeek || 'sunday');
    const minuteValue = typeof schedule.minute === 'number' ? schedule.minute : 0;
    setInputValue(backupMinute, minuteValue);
    const retentionValue = typeof schedule.retention === 'number' ? schedule.retention : 30;
    setInputValue(backupRetention, retentionValue);

    const sections = schedule.sections?.length ? schedule.sections : backupDefaultSections;
    backupSectionCheckboxes.forEach((checkbox) => {
      checkbox.checked = sections.includes(checkbox.value);
    });
    if (backupLastRun) {
      backupLastRun.textContent = schedule.lastRun ? formatDate(schedule.lastRun) : '-';
    }
    if (backupNextRun) {
      if (schedule.enabled) {
        backupNextRun.textContent = schedule.nextRun ? formatDate(schedule.nextRun) : '-';
      } else {
        backupNextRun.textContent = 'Disabled';
      }
    }
    updateScheduleVisibility();
  };

  const renderBackupList = () => {
    if (!backupTableBody || !backupEmptyState) {
      return;
    }
    backupTableBody.innerHTML = '';
    if (!backupState.backups.length) {
      backupEmptyState.hidden = false;
      if (backupTableWrapper) {
        backupTableWrapper.hidden = true;
      }
      return;
    }
    backupEmptyState.hidden = true;
    if (backupTableWrapper) {
      backupTableWrapper.hidden = false;
    }
    backupState.backups.forEach((item) => {
      const tr = document.createElement('tr');

      const createdTd = document.createElement('td');
      createdTd.textContent = formatDate(item.createdAt);
      tr.appendChild(createdTd);

      const sizeTd = document.createElement('td');
      sizeTd.textContent = formatBytes(item.size);
      tr.appendChild(sizeTd);

      const sectionsTd = document.createElement('td');
      sectionsTd.textContent = (item.sections || []).join(', ') || '-';
      tr.appendChild(sectionsTd);

      const authorTd = document.createElement('td');
      authorTd.textContent = item.createdBy || '-';
      tr.appendChild(authorTd);

      const actionsTd = document.createElement('td');
      actionsTd.className = 'backup-actions';

      const downloadButton = document.createElement('button');
      downloadButton.type = 'button';
      downloadButton.className = 'ghost-btn';
      downloadButton.textContent = 'Download';
      downloadButton.addEventListener('click', () => {
        downloadBackup(item.name);
      });
      actionsTd.appendChild(downloadButton);

      const restoreButton = document.createElement('button');
      restoreButton.type = 'button';
      restoreButton.className = 'primary-btn';
      restoreButton.textContent = 'Restore';
      restoreButton.addEventListener('click', () => {
        restoreBackupByName(item.name);
      });
      actionsTd.appendChild(restoreButton);

      const deleteButton = document.createElement('button');
      deleteButton.type = 'button';
      deleteButton.className = 'danger-btn';
      deleteButton.textContent = 'Delete';
      deleteButton.addEventListener('click', () => {
        deleteBackupByName(item.name);
      });
      actionsTd.appendChild(deleteButton);

      tr.appendChild(actionsTd);
      backupTableBody.appendChild(tr);
    });
  };

  const renderBackups = () => {
    renderBackupSchedule();
    renderBackupList();
    updateBackupControls();
  };

  const loadBackups = async (options = {}) => {
    if (!backupsPanel || backupState.loading) {
      return;
    }
    backupState.loading = true;
    updateBackupControls();
    try {
      const res = await fetch('/api/admin/backups', { credentials: 'same-origin' });
      if (!res.ok) {
        throw new Error(`Backups fetch failed (${res.status})`);
      }
      const json = await res.json();
      if (!(json?.ok)) {
        throw new Error(json?.error || 'Backups fetch failed');
      }
      backupState.schedule = json.schedule || null;
      backupState.backups = Array.isArray(json.backups) ? json.backups : [];
      backupState.loaded = true;
      renderBackups();
      if (options.announce) {
        showStatus('Backups refreshed.', 'success');
      }
    } catch (err) {
      showStatus(err.message || 'Backups load failed', 'error');
    } finally {
      backupState.loading = false;
      updateBackupControls();
    }
  };

  const runBackup = async () => {
    if (backupState.runningBackup) {
      return;
    }
    backupState.runningBackup = true;
    updateBackupControls();
    showStatus('Creating backup.', 'info');
    try {
      const payload = { sections: getSelectedBackupSections() };
      const res = await fetch('/api/admin/backups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      const json = await res.json();
      if (!res.ok || !(json?.ok)) {
        throw new Error(json?.error || `Backup failed (${res.status})`);
      }
      showStatus('Backup created.', 'success');
      await loadBackups();
    } catch (err) {
      showStatus(err.message || 'Backup failed', 'error');
    } finally {
      backupState.runningBackup = false;
      updateBackupControls();
    }
  };

  const saveBackupSchedule = async (event) => {
    if (event) {
      event.preventDefault();
    }
    if (backupState.savingSchedule) {
      return;
    }
    backupState.savingSchedule = true;
    updateBackupControls();
    showStatus('Saving backup schedule.', 'info');
    const payload = {
      enabled: backupScheduleEnabled ? backupScheduleEnabled.checked : false,
      frequency: backupFrequency ? backupFrequency.value : 'daily',
      timeOfDay: backupTime ? backupTime.value : '',
      dayOfWeek: backupWeekday ? backupWeekday.value : '',
      minute: backupMinute ? Number(backupMinute.value || 0) : 0,
      sections: getSelectedBackupSections(),
      retention: backupRetention ? Number(backupRetention.value || 0) : 0,
    };
    try {
      const res = await fetch('/api/admin/backups/schedule', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      const json = await res.json();
      if (!res.ok || !(json?.ok)) {
        throw new Error(json?.error || `Schedule update failed (${res.status})`);
      }
      backupState.schedule = json.schedule || payload;
      showStatus('Backup schedule saved.', 'success');
      renderBackups();
    } catch (err) {
      showStatus(err.message || 'Schedule update failed', 'error');
    } finally {
      backupState.savingSchedule = false;
      updateBackupControls();
    }
  };

  const deleteBackupByName = async (name) => {
    if (!name) {
      return;
    }
    if (!globalThis.confirm('Delete this backup? This cannot be undone.')) {
      return;
    }
    backupState.loading = true;
    updateBackupControls();
    showStatus('Deleting backup.', 'info');
    let deleted = false;
    try {
      const res = await fetch(`/api/admin/backups/${encodeURIComponent(name)}`, {
        method: 'DELETE',
        credentials: 'same-origin',
      });
      const json = await res.json();
      if (!res.ok || !(json?.ok)) {
        throw new Error(json?.error || `Delete failed (${res.status})`);
      }
      deleted = true;
      showStatus('Backup deleted.', 'success');
    } catch (err) {
      showStatus(err.message || 'Delete failed', 'error');
    } finally {
      backupState.loading = false;
      updateBackupControls();
    }
    if (deleted) {
      await loadBackups();
    }
  };

  const restoreBackupByName = async (name) => {
    if (!name) {
      return;
    }
    if (
      !globalThis.confirm(
        'Restore this backup? Current configuration will be overwritten immediately.',
      )
    ) {
      return;
    }
    backupState.loading = true;
    updateBackupControls();
    showStatus('Restoring backup.', 'info');
    let restored = false;
    try {
      const res = await fetch(`/api/admin/backups/${encodeURIComponent(name)}/restore`, {
        method: 'POST',
        credentials: 'same-origin',
      });
      const json = await res.json();
      if (!res.ok || !(json?.ok)) {
        throw new Error(json?.error || `Restore failed (${res.status})`);
      }
      if (json.config) {
        state.data.providers = json.config.providers;
        state.data.security = json.config.security;
        state.data.mfa = json.config.mfa;
        state.loadedAt = json.config.loadedAt;
        updateLoadedAt();
        try {
          await Promise.all(configSections.map((section) => fetchHistory(section)));
        } catch (error_) {
          console.error('Backup restore history refresh failed', error_);
        }
        if (isConfigSection(currentSection)) {
          renderConfigSection(currentSection);
          renderConfigHistory(currentSection);
        }
      }
      restored = true;
      showStatus('Backup restored.', 'success');
    } catch (err) {
      showStatus(err.message || 'Restore failed', 'error');
    } finally {
      backupState.loading = false;
      updateBackupControls();
    }
    if (restored) {
      await loadBackups();
    }
  };

  const exportCurrentConfig = () => {
    if (!isConfigSection(currentSection)) {
      showStatus('Select a configuration tab before exporting.', 'info');
      return;
    }
    let parsed;
    try {
      const raw = configEditor.value?.trim() ? configEditor.value : '{}';
      parsed = JSON.parse(raw);
    } catch (err) {
      showStatus(`Cannot export invalid JSON: ${err.message}`, 'error');
      return;
    }
    const pretty = JSON.stringify(parsed, null, 2);
    const timestamp = new Date().toISOString().replaceAll(/[:.]/g, '-');
    const name = `authportal-${currentSection}-config-${timestamp}.json`;
    const blob = new Blob([pretty], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => {
      URL.revokeObjectURL(link.href);
    }, 0);
    showStatus(`${labels[currentSection] || currentSection} configuration exported.`, 'success');
  };

  const triggerConfigImport = () => {
    if (!isConfigSection(currentSection) || !importInput) {
      showStatus('Select a configuration tab before importing.', 'info');
      return;
    }
    importInput.value = '';
    importInput.click();
  };

  const handleConfigImport = async (event) => {
    if (!event) {
      return;
    }
    const input = event.target;
    const file = input?.files?.[0];
    if (!file) {
      return;
    }
    try {
      const text = await file.text();
      if (!isConfigSection(currentSection)) {
        showStatus('Select a configuration tab before importing.', 'info');
        importInput.value = '';
        return;
      }
      const parsed = JSON.parse(text || '{}');
      configEditor.value = JSON.stringify(parsed, null, 2);
      showStatus('Configuration imported. Review and save to apply changes.', 'success');
    } catch (err) {
      showStatus(`Import failed: ${err.message}`, 'error');
    } finally {
      importInput.value = '';
    }
  };

  const renderConfigSection = (section) => {
    const data = state.data[section];
    panelTitle.textContent = labels[section] || 'Configuration';
    if (!data) {
      configEditor.value = '';
      versionBadge.textContent = 'v-';
      configEditor.dataset.version = '0';
      return;
    }
    configEditor.value = JSON.stringify(data.config ?? {}, null, 2);
    versionBadge.textContent = `v${data.version ?? '-'}`;
    configEditor.dataset.version = String(data.version ?? 0);
  };

  const renderConfigHistory = (section) => {
    const entries = state.history[section] || [];
    if (!entries.length) {
      historyList.innerHTML = '<li>No recent changes.</li>';
      return;
    }
    historyList.innerHTML = '';
    entries.forEach((entry) => {
      const li = document.createElement('li');
      const when = entry.updatedAt ? new Date(entry.updatedAt).toLocaleString() : 'unknown time';
      const who = entry.updatedBy || 'system';
      const reason = entry.reason ? ` - ${entry.reason}` : '';
      li.textContent = `#${entry.version} @ ${when} by ${who}${reason}`;
      historyList.appendChild(li);
    });
  };

  const fetchConfig = async () => {
    const res = await fetch('/api/admin/config', { credentials: 'same-origin' });
    if (!res.ok) {
      throw new Error(`Config fetch failed (${res.status})`);
    }
    const json = await res.json();
    if (!(json?.ok)) {
      throw new Error(json?.error || 'Config fetch failed');
    }
    state.data.providers = json.providers;
    state.data.security = json.security;
    state.data.mfa = json.mfa;
    state.data['app-settings'] = json.appSettings || null;
    state.loadedAt = json.loadedAt;
    updateLoadedAt();
  };

  const fetchHistory = async (section) => {
    const res = await fetch(`/api/admin/config/history/${section}?limit=25`, { credentials: 'same-origin' });
    if (!res.ok) {
      throw new Error(`History fetch failed (${res.status})`);
    }
    const json = await res.json();
    if (!(json?.ok)) {
      throw new Error(json?.error || 'History fetch failed');
    }
    state.history[section] = json.entries || [];
  };

  const loadConfigSection = async (section) => {
    setConfigLoading(true);
    try {
      await fetchConfig();
      renderConfigSection(section);
      try {
        await fetchHistory(section);
        renderConfigHistory(section);
      } catch (error_) {
        console.error('History fetch failed', error_);
      }
    } catch (err) {
      showStatus(err.message || String(err), 'error');
    } finally {
      setConfigLoading(false);
      if (!state.data[section]) {
        configEditor.disabled = true;
        reasonInput.disabled = true;
        saveBtn.disabled = true;
      }
    }
  };

  const parseRedirectList = (value) =>
    (value || '')
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean);

  const parseScopes = (value) =>
    (value || '')
      .split(/[\s,]+/)
      .map((scope) => scope.trim())
      .filter(Boolean);

  const resetOAuthForm = () => {
    if (!oauthForm) {
      return;
    }
    oauthForm.reset();
    oauthId.value = '';
    oauthSave.textContent = 'Save Client';
    if (oauthCancel) {
      oauthCancel.hidden = true;
      oauthCancel.disabled = false;
    }
  };

  const clearSecretBanner = () => {
    if (!oauthSecretBanner) {
      return;
    }
    oauthSecretBanner.hidden = true;
    oauthSecretBanner.textContent = '';
    oauthSecretBanner.className = 'secret-banner';
  };

  const showSecretBanner = (message) => {
    if (!oauthSecretBanner) {
      return;
    }
    oauthSecretBanner.textContent = message;
    oauthSecretBanner.hidden = false;
    oauthSecretBanner.className = 'secret-banner show';
  };

  const setOAuthLoading = (isLoading) => {
    if (!oauthPanel || !oauthEmptyState) {
      return;
    }
    oauthState.loading = isLoading;
    if (isLoading) {
      oauthEmptyState.hidden = false;
      oauthEmptyState.textContent = 'Loading...';
      if (oauthTable) {
        oauthTable.hidden = true;
      }
      if (oauthTableWrapper) {
        oauthTableWrapper.hidden = true;
      }
    } else {
      oauthEmptyState.textContent = 'No OAuth clients registered yet.';
    }
  };

  const createDateFormatter = () => {
    const options = {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    };
    try {
      return new Intl.DateTimeFormat(undefined, { ...options, timeZone: appTimeZone || 'UTC' });
    } catch {
      return new Intl.DateTimeFormat(undefined, options);
    }
  };

  const dateFormatter = createDateFormatter();

  const formatDate = (value) => {
    if (!value) {
      return '-';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    try {
      return dateFormatter.format(date);
    } catch {
      return date.toLocaleString();
    }
  };

  const formatBytes = (value) => {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) {
      return '0 B';
    }
    if (bytes === 0) {
      return '0 B';
    }
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex += 1;
    }
    let precision = 0;
    if (unitIndex !== 0 && size < 10) {
      precision = 1;
    }
    return `${size.toFixed(precision)} ${units[unitIndex]}`;
  };

  const renderOAuthClients = () => {
    if (!oauthRows || !oauthEmptyState || !oauthTable || !oauthTableWrapper) {
      return;
    }
    oauthRows.innerHTML = '';
    if (!oauthState.clients.length) {
      oauthEmptyState.hidden = false;
      oauthTable.hidden = true;
      oauthTableWrapper.hidden = true;
      return;
    }
    oauthEmptyState.hidden = true;
    oauthTableWrapper.hidden = false;
    oauthTable.hidden = false;
    oauthState.clients.forEach((client) => {
      const tr = document.createElement('tr');

      const nameTd = document.createElement('td');
      nameTd.textContent = client.name || '-';
      tr.appendChild(nameTd);

      const idTd = document.createElement('td');
      idTd.textContent = client.clientId;
      idTd.className = 'mono';
      tr.appendChild(idTd);

      const redirectTd = document.createElement('td');
    if (client.redirectUris?.length) {
      client.redirectUris.forEach((uri, index) => {
        if (index > 0) {
          redirectTd.appendChild(document.createElement('br'));
        }
        redirectTd.appendChild(document.createTextNode(uri));
        });
      } else {
        redirectTd.textContent = '-';
      }
      tr.appendChild(redirectTd);

      const scopesTd = document.createElement('td');
      scopesTd.textContent = (client.scopes || []).join(' ') || '-';
      tr.appendChild(scopesTd);

      const updatedTd = document.createElement('td');
      updatedTd.textContent = formatDate(client.updatedAt);
      tr.appendChild(updatedTd);

      const actionsTd = document.createElement('td');
      actionsTd.className = 'actions-cell';

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'ghost-btn';
      editBtn.textContent = 'Edit';
      editBtn.addEventListener('click', () => {
        if (!oauthForm) {
          return;
        }
        oauthId.value = client.clientId;
        oauthName.value = client.name || '';
        oauthRedirects.value = (client.redirectUris || []).join('\n');
        oauthScopes.value = (client.scopes || []).join(' ');
        oauthSave.textContent = 'Update Client';
        if (oauthCancel) {
          oauthCancel.hidden = false;
        }
        oauthName.focus();
      });
      actionsTd.appendChild(editBtn);

      const rotateBtn = document.createElement('button');
      rotateBtn.type = 'button';
      rotateBtn.className = 'ghost-btn';
      rotateBtn.textContent = 'Rotate Secret';
      rotateBtn.addEventListener('click', async () => {
        if (!client.clientId) {
          return;
        }
        rotateBtn.disabled = true;
        showStatus('Rotating client secret.', 'info');
        try {
          const res = await fetch(`/api/admin/oauth/clients/${encodeURIComponent(client.clientId)}/rotate-secret`, {
            method: 'POST',
            credentials: 'same-origin',
          });
          const json = await res.json();
          if (!res.ok || !(json?.ok)) {
            throw new Error(json?.error || `Secret rotation failed (${res.status})`);
          }
          const displayName = client.name || client.clientId;
          showSecretBanner(`New secret for ${displayName}: ${json.clientSecret}`);
          showStatus('Client secret rotated.', 'success');
          await loadOAuthClients();
        } catch (err) {
          showStatus(err.message || 'Secret rotation failed', 'error');
        } finally {
          rotateBtn.disabled = false;
        }
      });
      actionsTd.appendChild(rotateBtn);

      const deleteBtn = document.createElement('button');
      deleteBtn.type = 'button';
      deleteBtn.className = 'danger-btn';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', async () => {
        if (!client.clientId) {
          return;
        }
        const confirmDelete = globalThis.confirm(
          `Delete OAuth client "${client.name || client.clientId}"? This action cannot be undone.`
        );
        if (!confirmDelete) {
          return;
        }
        deleteBtn.disabled = true;
        showStatus('Deleting client.', 'info');
        try {
          const res = await fetch(`/api/admin/oauth/clients/${encodeURIComponent(client.clientId)}`, {
            method: 'DELETE',
            credentials: 'same-origin',
          });
          const json = await res.json();
          if (!res.ok || !(json?.ok)) {
            throw new Error(json?.error || `Delete failed (${res.status})`);
          }
          showStatus('Client deleted.', 'success');
          await loadOAuthClients();
          resetOAuthForm();
        } catch (err) {
          showStatus(err.message || 'Delete failed', 'error');
        } finally {
          deleteBtn.disabled = false;
        }
      });
      actionsTd.appendChild(deleteBtn);

      tr.appendChild(actionsTd);
      oauthRows.appendChild(tr);
    });
  };

  const loadOAuthClients = async (options = {}) => {
    if (!oauthPanel) {
      return;
    }
    if (oauthState.loading) {
      return;
    }
    setOAuthLoading(true);
    try {
      const res = await fetch('/api/admin/oauth/clients', { credentials: 'same-origin' });
      if (!res.ok) {
        throw new Error(`Client fetch failed (${res.status})`);
      }
      const json = await res.json();
      if (!(json?.ok)) {
        throw new Error(json?.error || 'Client fetch failed');
      }
      oauthState.clients = Array.isArray(json.clients) ? json.clients : [];
      renderOAuthClients();
      if (options.announce) {
        showStatus('OAuth clients refreshed.', 'success');
      }
    } catch (err) {
      renderOAuthClients();
      showStatus(err.message || 'Client fetch failed', 'error');
    } finally {
      setOAuthLoading(false);
    }
  };

  const activateSection = async (section) => {
    if (!section) {
      return;
    }
    if (
      section === currentSection &&
      section !== 'oauth' &&
      section !== 'backups' &&
      state.data[section]
    ) {
      return;
    }
    currentSection = section;
    updateHelpButton(section);
    setActiveTab();
    clearStatus();
    if (isConfigSection(section)) {
      showConfigPanels();
      clearSecretBanner();
      await loadConfigSection(section);
      return;
    }
    if (section === 'oauth' && oauthPanel) {
      showOAuthPanel();
      await loadOAuthClients();
      return;
    }
    if (section === 'backups' && backupsPanel) {
      showBackupsPanel();
      clearSecretBanner();
      if (backupState.loaded) {
        renderBackups();
        return;
      }
      await loadBackups();
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const section = tab.dataset.section;
      if (!section) {
        return;
      }
      activateSection(section);
    });
  });

  configForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!isConfigSection(currentSection) || configEditor.disabled) {
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(configEditor.value || '{}');
    } catch (err) {
      showStatus(`Invalid JSON: ${err.message}`, 'error');
      return;
    }

    const payload = {
      version: Number(configEditor.dataset.version || 0),
      reason: reasonInput.value.trim(),
      config: parsed,
    };

    saveBtn.disabled = true;
    configEditor.disabled = true;
    reasonInput.disabled = true;
    showStatus('Saving changes.', 'info');

    try {
      const res = await fetch(`/api/admin/config/${currentSection}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      const json = await res.json();
      if (!res.ok || !(json?.ok)) {
        throw new Error(json?.error || `Save failed (${res.status})`);
      }
      state.data.providers = json.providers;
      state.data.security = json.security;
      state.data.mfa = json.mfa;
      state.loadedAt = json.loadedAt;
      updateLoadedAt();
      renderConfigSection(currentSection);
      reasonInput.value = '';
      showStatus('Configuration saved.', 'success');
      try {
        await fetchHistory(currentSection);
        renderConfigHistory(currentSection);
      } catch (error_) {
        console.error('History refresh failed', error_);
      }
    } catch (err) {
      showStatus(err.message || 'Save failed', 'error');
    } finally {
      configEditor.disabled = false;
      reasonInput.disabled = false;
      saveBtn.disabled = false;
    }
  });

  if (oauthCancel) {
    oauthCancel.addEventListener('click', () => {
      resetOAuthForm();
      clearSecretBanner();
    });
  }

  if (oauthForm) {
    oauthForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (oauthState.loading) {
        return;
      }
      const payload = {
        name: oauthName.value.trim(),
        redirectUris: parseRedirectList(oauthRedirects.value),
        scopes: parseScopes(oauthScopes.value),
      };
      const clientId = oauthId.value.trim();
      const method = clientId ? 'PUT' : 'POST';
      const endpoint = clientId
        ? `/api/admin/oauth/clients/${encodeURIComponent(clientId)}`
        : '/api/admin/oauth/clients';

      oauthSave.disabled = true;
      if (oauthCancel) {
        oauthCancel.disabled = true;
      }
      showStatus(clientId ? 'Updating client.' : 'Creating client.', 'info');

      try {
        const res = await fetch(endpoint, {
          method,
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(payload),
        });
        const json = await res.json();
        if (!res.ok || !(json?.ok)) {
          throw new Error(json?.error || `Save failed (${res.status})`);
        }
        showStatus(clientId ? 'Client updated.' : 'Client created.', 'success');
        if (json.clientSecret) {
          const name = json.client?.name || payload.name || clientId || 'client';
          showSecretBanner(`Client secret for ${name}: ${json.clientSecret}`);
        }
        resetOAuthForm();
        await loadOAuthClients();
      } catch (err) {
        showStatus(err.message || 'Save failed', 'error');
      } finally {
        oauthSave.disabled = false;
        if (oauthCancel) {
          oauthCancel.disabled = false;
        }
      }
    });
  }

  if (oauthReloadBtn) {
    oauthReloadBtn.addEventListener('click', async () => {
      await loadOAuthClients({ announce: true });
    });
  }

  if (helpBtn) {
    helpBtn.addEventListener('click', () => {
      const targetSection =
        helpBtn.dataset.section || (isConfigSection(currentSection) ? currentSection : '');
      openHelpModal(targetSection || currentSection);
    });
  }

  if (helpModalClose) {
    helpModalClose.addEventListener('click', () => {
      closeHelpModal();
    });
  }

  if (helpModal) {
    helpModal.addEventListener('click', (event) => {
      const target = event.target;
      const isClose = target?.dataset?.helpClose !== undefined;
      if (target === helpModal || isClose) {
        closeHelpModal();
      }
    });
  }

  if (exportBtn) {
    exportBtn.addEventListener('click', exportCurrentConfig);
  }

  if (importBtn) {
    importBtn.addEventListener('click', triggerConfigImport);
  }

  if (importInput) {
    importInput.addEventListener('change', handleConfigImport);
  }

  if (backupRunBtn) {
    backupRunBtn.addEventListener('click', async () => {
      await runBackup();
    });
  }

  if (backupRefreshBtn) {
    backupRefreshBtn.addEventListener('click', async () => {
      await loadBackups({ announce: true });
    });
  }

  if (backupScheduleForm) {
    backupScheduleForm.addEventListener('submit', saveBackupSchedule);
  }

  if (backupFrequency) {
    backupFrequency.addEventListener('change', updateScheduleVisibility);
  }

  if (backupsPanel) {
    updateScheduleVisibility();
    updateBackupControls();
  }

  updateHelpButton(currentSection);
  showConfigPanels();
  activateSection(currentSection);
})();
