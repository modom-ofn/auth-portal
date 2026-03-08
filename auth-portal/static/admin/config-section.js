import { toUserMessage } from './admin-errors.js';

export const createConfigSectionController = ({
  api,
  form,
  formsController,
  panelTitle,
  versionBadge,
  reasonInput,
  saveBtn,
  configEditor,
  importInput,
  labels,
  configSections,
  state,
  showStatus,
  updateLoadedAt,
  recordActivity,
  onHistoryUpdated,
}) => {
  const isConfigSection = (section) => configSections.includes(section);

  const setLoading = (isLoading) => {
    if (form.hidden) {
      return;
    }
    if (isLoading) {
      formsController.setLoadingMessage();
      formsController.setDisabled(true);
      reasonInput.disabled = true;
      saveBtn.disabled = true;
      versionBadge.textContent = 'v-';
    } else {
      formsController.setDisabled(false);
      reasonInput.disabled = false;
      saveBtn.disabled = false;
    }
  };

  const applyConfigResponse = (json) => {
    state.data.providers = json.providers;
    state.data.security = json.security;
    state.data.mfa = json.mfa;
    state.data['app-settings'] = json.appSettings || state.data['app-settings'];
    state.loadedAt = json.loadedAt;
    updateLoadedAt();
  };

  const renderSection = (section) => {
    const data = state.data[section];
    panelTitle.textContent = labels[section] || 'Configuration';
    if (!data) {
      formsController.setEmptyMessage();
      versionBadge.textContent = 'v-';
      configEditor.dataset.version = '0';
      return;
    }
    formsController.renderSection(section, data.config ?? {});
    configEditor.value = JSON.stringify(data.config ?? {}, null, 2);
    versionBadge.textContent = `v${data.version ?? '-'}`;
    configEditor.dataset.version = String(data.version ?? 0);
  };

  const fetchConfig = async () => {
    const json = await api.getConfig();
    state.data.providers = json.providers;
    state.data.security = json.security;
    state.data.mfa = json.mfa;
    state.data['app-settings'] = json.appSettings || null;
    state.loadedAt = json.loadedAt;
    updateLoadedAt();
  };

  const fetchHistory = async (section) => {
    const json = await api.getConfigHistory(section, 25);
    state.history[section] = json.entries || [];
    if (typeof onHistoryUpdated === 'function') {
      onHistoryUpdated(section);
    }
  };

  const loadSection = async (section) => {
    setLoading(true);
    try {
      await fetchConfig();
      renderSection(section);
      try {
        await fetchHistory(section);
      } catch (error_) {
        console.error('History fetch failed', error_);
      }
    } catch (err) {
      showStatus(toUserMessage(err, 'Load failed'), 'error');
    } finally {
      setLoading(false);
      if (!state.data[section]) {
        formsController.setDisabled(true);
        reasonInput.disabled = true;
        saveBtn.disabled = true;
      }
    }
  };

  const exportCurrent = (section) => {
    if (!isConfigSection(section)) {
      showStatus('Select a configuration tab before exporting.', 'info');
      return;
    }
    const parsed = formsController.readSection(section);
    const pretty = JSON.stringify(parsed, null, 2);
    const timestamp = new Date().toISOString().replaceAll(/[:.]/g, '-');
    const name = `authportal-${section}-config-${timestamp}.json`;
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
    showStatus(`${labels[section] || section} configuration exported.`, 'success');
  };

  const triggerImport = (section) => {
    if (!isConfigSection(section) || !importInput) {
      showStatus('Select a configuration tab before importing.', 'info');
      return;
    }
    importInput.value = '';
    importInput.click();
  };

  const handleImport = async (event, section) => {
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
      if (!isConfigSection(section)) {
        showStatus('Select a configuration tab before importing.', 'info');
        importInput.value = '';
        return;
      }
      const parsed = JSON.parse(text || '{}');
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Config file must contain a JSON object');
      }
      formsController.renderSection(section, parsed);
      configEditor.value = JSON.stringify(parsed, null, 2);
      showStatus('Configuration imported. Review and save to apply changes.', 'success');
    } catch (err) {
      showStatus(`Import failed: ${err.message}`, 'error');
    } finally {
      importInput.value = '';
    }
  };

  const saveCurrent = async (section) => {
    if (!isConfigSection(section) || saveBtn.disabled) {
      return;
    }
    const parsed = formsController.readSection(section);
    const payload = {
      version: Number(configEditor.dataset.version || 0),
      reason: reasonInput.value.trim(),
      config: parsed,
    };

    saveBtn.disabled = true;
    formsController.setDisabled(true);
    reasonInput.disabled = true;
    showStatus('Saving changes.', 'info');

    try {
      const json = await api.updateConfig(section, payload);
      recordActivity(section, 'Configuration saved', payload.reason || 'No reason provided');
      applyConfigResponse(json);
      renderSection(section);
      reasonInput.value = '';
      showStatus('Configuration saved.', 'success');
      try {
        await fetchHistory(section);
      } catch (error_) {
        console.error('History refresh failed', error_);
      }
    } catch (err) {
      showStatus(toUserMessage(err, 'Save failed'), 'error');
    } finally {
      formsController.setDisabled(false);
      reasonInput.disabled = false;
      saveBtn.disabled = false;
    }
  };

  const bind = (getCurrentSection) => {
    if (form) {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await saveCurrent(getCurrentSection());
      });
    }
    if (importInput) {
      importInput.addEventListener('change', async (event) => {
        await handleImport(event, getCurrentSection());
      });
    }
  };

  return {
    bind,
    isConfigSection,
    fetchHistory,
    renderSection,
    loadSection,
    applyConfigResponse,
    exportCurrent,
    triggerImport,
    saveCurrent,
  };
};
