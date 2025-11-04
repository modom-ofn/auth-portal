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

  const configSections = ['providers', 'security', 'mfa'];
  const labels = { providers: 'Providers', security: 'Security', mfa: 'MFA' };
  let currentSection = 'providers';

  const state = {
    data: { providers: null, security: null, mfa: null },
    history: { providers: [], security: [], mfa: [] },
    loadedAt: null,
  };

  const oauthState = {
    clients: [],
    loading: false,
  };

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

  const setActiveTab = () => {
    tabs.forEach((tab) => {
      tab.classList.toggle('active', tab.getAttribute('data-section') === currentSection);
    });
  };

  const showConfigPanels = () => {
    configForm.hidden = false;
    historyPanel.hidden = false;
    if (oauthPanel) {
      oauthPanel.hidden = true;
    }
  };

  const showOAuthPanel = () => {
    configForm.hidden = true;
    historyPanel.hidden = true;
    if (oauthPanel) {
      oauthPanel.hidden = false;
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

  const loadConfigSection = async (section) => {
    setConfigLoading(true);
    try {
      await fetchConfig();
      renderConfigSection(section);
      try {
        await fetchHistory(section);
        renderConfigHistory(section);
      } catch (historyErr) {
        console.error('History fetch failed', historyErr);
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
    } else {
      oauthEmptyState.textContent = 'No OAuth clients registered yet.';
    }
  };

  const formatDate = (value) => {
    if (!value) {
      return '-';
    }
    try {
      return new Date(value).toLocaleString();
    } catch {
      return value;
    }
  };

  const renderOAuthClients = () => {
    if (!oauthRows || !oauthEmptyState || !oauthTable) {
      return;
    }
    oauthRows.innerHTML = '';
    if (!oauthState.clients.length) {
      oauthEmptyState.hidden = false;
      oauthTable.hidden = true;
      return;
    }
    oauthEmptyState.hidden = true;
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
      if (client.redirectUris && client.redirectUris.length) {
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
          if (!res.ok || !json || !json.ok) {
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
        const confirmDelete = window.confirm(
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
          if (!res.ok || !json || !json.ok) {
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
      if (!json || !json.ok) {
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
    if (section === currentSection && section !== 'oauth') {
      return;
    }
    currentSection = section;
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
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const section = tab.getAttribute('data-section');
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
      if (!res.ok || !json || !json.ok) {
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
        if (!res.ok || !json || !json.ok) {
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

  showConfigPanels();
  activateSection(currentSection);
})();
