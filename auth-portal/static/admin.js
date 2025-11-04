(() => {
  const tabs = Array.from(document.querySelectorAll('.admin-tab'));
  const configEditor = document.getElementById('config-editor');
  const historyList = document.getElementById('history-list');
  const panelTitle = document.getElementById('panel-title');
  const versionBadge = document.getElementById('version-badge');
  const reasonInput = document.getElementById('reason-input');
  const saveBtn = document.getElementById('save-btn');
  const statusBanner = document.getElementById('status-banner');
  const loadedAtEl = document.getElementById('loaded-at');
  const configForm = document.getElementById('config-form');

  if (!configEditor || !historyList || !panelTitle || !versionBadge || !reasonInput || !saveBtn || !statusBanner || !configForm) {
    return;
  }

  let currentSection = 'providers';
  const labels = { providers: 'Providers', security: 'Security', mfa: 'MFA' };
  const state = {
    data: { providers: null, security: null, mfa: null },
    history: { providers: [], security: [], mfa: [] },
    loadedAt: null,
  };

  const clearStatus = () => {
    statusBanner.textContent = '';
    statusBanner.className = 'status-banner';
  };

  const showStatus = (message, type = 'info') => {
    statusBanner.textContent = message;
    statusBanner.className = `status-banner ${type} show`;
  };

  const setLoading = (isLoading) => {
    if (isLoading) {
      configEditor.value = 'Loading…';
      configEditor.disabled = true;
      reasonInput.disabled = true;
      saveBtn.disabled = true;
      versionBadge.textContent = 'v—';
      historyList.innerHTML = '<li>Loading…</li>';
    } else {
      configEditor.disabled = false;
      reasonInput.disabled = false;
      saveBtn.disabled = false;
    }
  };

  const updateLoadedAt = () => {
    if (!loadedAtEl) {
      return;
    }
    if (!state.loadedAt) {
      loadedAtEl.textContent = '—';
      return;
    }
    try {
      loadedAtEl.textContent = new Date(state.loadedAt).toLocaleString();
    } catch {
      loadedAtEl.textContent = state.loadedAt;
    }
  };

  const renderSection = () => {
    const data = state.data[currentSection];
    panelTitle.textContent = labels[currentSection] || 'Configuration';
    if (!data) {
      configEditor.value = '';
      versionBadge.textContent = 'v—';
      configEditor.dataset.version = '0';
      return;
    }
    configEditor.value = JSON.stringify(data.config ?? {}, null, 2);
    versionBadge.textContent = `v${data.version ?? '—'}`;
    configEditor.dataset.version = String(data.version ?? 0);
  };

  const renderHistory = () => {
    const entries = state.history[currentSection] || [];
    if (!entries.length) {
      historyList.innerHTML = '<li>No recent changes.</li>';
      return;
    }
    historyList.innerHTML = '';
    entries.forEach((entry) => {
      const li = document.createElement('li');
      const when = entry.updatedAt ? new Date(entry.updatedAt).toLocaleString() : 'unknown time';
      const who = entry.updatedBy || 'system';
      const reason = entry.reason ? ` — ${entry.reason}` : '';
      li.textContent = `#${entry.version} @ ${when} by ${who}${reason}`;
      historyList.appendChild(li);
    });
  };

  const setActiveTab = () => {
    tabs.forEach((tab) => {
      tab.classList.toggle('active', tab.getAttribute('data-section') === currentSection);
    });
  };

  const fetchConfig = async () => {
    const res = await fetch('/api/admin/config', { credentials: 'same-origin' });
    if (!res.ok) {
      throw new Error(`Config fetch failed (${res.status})`);
    }
    const json = await res.json();
    if (!json || !json.ok) {
      throw new Error(json?.error || 'Config fetch failed');
    }
    state.data.providers = json.providers;
    state.data.security = json.security;
    state.data.mfa = json.mfa;
    state.loadedAt = json.loadedAt;
    updateLoadedAt();
  };

  const fetchHistory = async (section) => {
    const res = await fetch(`/api/admin/config/history/${section}?limit=25`, { credentials: 'same-origin' });
    if (!res.ok) {
      throw new Error(`History fetch failed (${res.status})`);
    }
    const json = await res.json();
    if (!json || !json.ok) {
      throw new Error(json?.error || 'History fetch failed');
    }
    state.history[section] = json.entries || [];
  };

  const loadSection = async () => {
    setActiveTab();
    setLoading(true);
    clearStatus();
    try {
      await fetchConfig();
      await fetchHistory(currentSection);
      renderSection();
      renderHistory();
    } catch (err) {
      showStatus(err.message || String(err), 'error');
    } finally {
      setLoading(false);
      if (!state.data[currentSection]) {
        configEditor.disabled = true;
        reasonInput.disabled = true;
        saveBtn.disabled = true;
      }
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const section = tab.getAttribute('data-section');
      if (!section || section === currentSection) {
        return;
      }
      currentSection = section;
      loadSection();
    });
  });

  configForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (configEditor.disabled) {
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
    showStatus('Saving changes…', 'info');

    try {
      const res = await fetch(`/api/admin/config/${currentSection}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      const json = await res.json();
      if (!res.ok || !json || !json.ok) {
        throw new Error(json?.error || `Save failed (${res.status})`);
      }
      state.data.providers = json.providers;
      state.data.security = json.security;
      state.data.mfa = json.mfa;
      state.loadedAt = json.loadedAt;
      updateLoadedAt();
      renderSection();
      reasonInput.value = '';
      showStatus('Configuration saved.', 'success');
      try {
        await fetchHistory(currentSection);
        renderHistory();
      } catch (historyErr) {
        console.error('History refresh failed', historyErr);
      }
    } catch (err) {
      showStatus(err.message || 'Save failed', 'error');
    } finally {
      configEditor.disabled = false;
      reasonInput.disabled = false;
      saveBtn.disabled = false;
    }
  });

  loadSection();
})();
