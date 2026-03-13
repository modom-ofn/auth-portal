import { toUserMessage } from './admin-errors.js';

export const createLDAPSyncSectionController = ({
  api,
  panel,
  refreshBtn,
  exportBtn,
  importBtn,
  importInput,
  testBtn,
  runBtn,
  form,
  hostInput,
  adminDnInput,
  passwordInput,
  baseDnInput,
  startTlsInput,
  deleteStaleInput,
  scheduleEnabledInput,
  frequencyInput,
  timeInput,
  weekdayInput,
  minuteInput,
  nextRunEl,
  frequencyRows,
  reasonInput,
  saveBtn,
  statusSummary,
  statusState,
  statusStartedAt,
  statusFinishedAt,
  statusSuccessAt,
  statusTriggeredBy,
  testResultEl,
  testDetailsEl,
  testConnectedEl,
  testBoundEl,
  testBaseExistsEl,
  testBaseCreatableEl,
  runRows,
  showStatus,
  recordActivity,
}) => {
  const state = {
    loading: false,
    saving: false,
    testing: false,
    running: false,
    loaded: false,
    config: null,
    version: 0,
    runStatus: null,
    runs: [],
    testResult: null,
  };

  const formatDate = (value) => {
    if (!value) {
      return '-';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  };

  const updateControls = () => {
    const busy = state.loading || state.saving || state.testing || state.running;
    if (refreshBtn) {
      refreshBtn.disabled = state.loading;
    }
    if (testBtn) {
      testBtn.disabled = busy;
    }
    if (runBtn) {
      runBtn.disabled = busy;
    }
    if (saveBtn) {
      saveBtn.disabled = busy;
    }
    [hostInput, adminDnInput, passwordInput, baseDnInput, startTlsInput, deleteStaleInput, scheduleEnabledInput, frequencyInput, timeInput, weekdayInput, minuteInput, reasonInput]
      .filter(Boolean)
      .forEach((input) => {
        input.disabled = state.saving || state.testing || state.running;
      });
  };

  const updateScheduleVisibility = () => {
    if (!frequencyInput || !frequencyRows?.length) {
      return;
    }
    const frequency = String(frequencyInput.value || 'daily').toLowerCase();
    const enabled = Boolean(scheduleEnabledInput?.checked);
    frequencyRows.forEach((row) => {
      const allowed = (row.dataset.ldapFrequencyRow || '')
        .split(/\s+/)
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
      row.hidden = !enabled || (allowed.length > 0 && !allowed.includes(frequency));
    });
  };

  const renderConfig = () => {
    const config = state.config || {};
    if (hostInput) {
      hostInput.value = config.ldapHost || '';
    }
    if (adminDnInput) {
      adminDnInput.value = config.ldapAdminDn || '';
    }
    if (passwordInput) {
      passwordInput.value = config.ldapAdminPassword || '';
    }
    if (baseDnInput) {
      baseDnInput.value = config.baseDn || '';
    }
    if (startTlsInput) {
      startTlsInput.checked = Boolean(config.ldapStartTls);
    }
    if (deleteStaleInput) {
      deleteStaleInput.checked = Boolean(config.deleteStaleEntries);
    }
    if (scheduleEnabledInput) {
      scheduleEnabledInput.checked = Boolean(config.scheduleEnabled);
    }
    if (frequencyInput) {
      frequencyInput.value = config.scheduleFrequency || 'daily';
    }
    if (timeInput) {
      timeInput.value = config.scheduleTimeOfDay || '02:15';
    }
    if (weekdayInput) {
      weekdayInput.value = config.scheduleDayOfWeek || 'sunday';
    }
    if (minuteInput) {
      minuteInput.value = typeof config.scheduleMinute === 'number' ? config.scheduleMinute : 15;
    }
    updateScheduleVisibility();
  };

  const renderStatus = () => {
    const info = state.runStatus || {};
    const result = info.lastResult || {};
    if (statusSummary) {
      statusSummary.textContent = getStatusSummary(info, result);
    }
    if (statusState) {
      statusState.textContent = getStatusState(info);
    }
    if (statusStartedAt) {
      statusStartedAt.textContent = formatDate(info.startedAt);
    }
    if (statusFinishedAt) {
      statusFinishedAt.textContent = formatDate(info.finishedAt);
    }
    if (statusSuccessAt) {
      statusSuccessAt.textContent = formatDate(info.lastSuccessAt);
    }
    if (statusTriggeredBy) {
      statusTriggeredBy.textContent = info.triggeredBy || '-';
    }
    if (nextRunEl) {
      nextRunEl.textContent = getNextRunText(info.nextRun, state.config);
    }
  };

  const renderTestResult = () => {
    if (!testResultEl) {
      return;
    }
    const result = state.testResult;
    if (!result?.message) {
      clearTestResult({
        testResultEl,
        testDetailsEl,
        testConnectedEl,
        testBoundEl,
        testBaseExistsEl,
        testBaseCreatableEl,
      });
      return;
    }
    applyTestResult(result, {
      testResultEl,
      testDetailsEl,
      testConnectedEl,
      testBoundEl,
      testBaseExistsEl,
      testBaseCreatableEl,
    });
  };

  const renderRuns = () => {
    if (!runRows) {
      return;
    }
    runRows.innerHTML = '';
    if (!state.runs.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'muted';
      td.textContent = 'No LDAP sync runs recorded yet.';
      tr.appendChild(td);
      runRows.appendChild(tr);
      return;
    }
    state.runs.forEach((run) => {
      const tr = document.createElement('tr');
      const startedTd = document.createElement('td');
      startedTd.textContent = formatDate(run.startedAt);
      tr.appendChild(startedTd);

      const triggerTd = document.createElement('td');
      triggerTd.textContent = [run.triggerType || 'manual', run.triggeredBy || 'system'].join(' / ');
      tr.appendChild(triggerTd);

      const resultTd = document.createElement('td');
      resultTd.textContent = run.success ? 'Success' : 'Failed';
      tr.appendChild(resultTd);

      const countsTd = document.createElement('td');
      countsTd.textContent = `+${run.entriesAdded || 0} ~${run.entriesUpdated || 0} -${run.entriesDeleted || 0} !${run.failedEntries || 0}`;
      tr.appendChild(countsTd);

      const summaryTd = document.createElement('td');
      summaryTd.textContent = run.summary || run.errorMessage || '-';
      tr.appendChild(summaryTd);

      runRows.appendChild(tr);
    });
  };

  const render = () => {
    renderConfig();
    renderStatus();
    renderTestResult();
    renderRuns();
    updateControls();
  };

  const readConfig = () => ({
    ldapHost: hostInput?.value?.trim() || '',
    ldapAdminDn: adminDnInput?.value?.trim() || '',
    ldapAdminPassword: passwordInput?.value || '',
    baseDn: baseDnInput?.value?.trim() || '',
    ldapStartTls: Boolean(startTlsInput?.checked),
    deleteStaleEntries: Boolean(deleteStaleInput?.checked),
    scheduleEnabled: Boolean(scheduleEnabledInput?.checked),
    scheduleFrequency: frequencyInput?.value || 'daily',
    scheduleTimeOfDay: timeInput?.value || '',
    scheduleDayOfWeek: weekdayInput?.value || '',
    scheduleMinute: minuteInput ? Number(minuteInput.value || 0) : 0,
  });

  const load = async (options = {}) => {
    if (!panel || state.loading) {
      return;
    }
    state.loading = true;
    updateControls();
    try {
      const json = await api.getLDAPSync();
      state.config = json.config?.config || {};
      state.version = Number(json.config?.version || 0);
      state.runStatus = json.status || null;
      state.runs = Array.isArray(json.runs) ? json.runs : [];
      state.loaded = true;
      render();
      if (options.announce) {
        showStatus('LDAP sync status refreshed.', 'success');
        recordActivity('ldap-sync', 'LDAP sync status refreshed');
      }
    } catch (err) {
      showStatus(toUserMessage(err, 'LDAP sync load failed'), 'error');
    } finally {
      state.loading = false;
      updateControls();
    }
  };

  const exportConfig = () => {
    const pretty = JSON.stringify(readConfig(), null, 2);
    const timestamp = new Date().toISOString().replaceAll(/[:.]/g, '-');
    const name = `authportal-ldap-sync-config-${timestamp}.json`;
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
    showStatus('LDAP sync configuration exported.', 'success');
  };

  const triggerImport = () => {
    if (!importInput) {
      showStatus('LDAP sync import is unavailable.', 'error');
      return;
    }
    importInput.value = '';
    importInput.click();
  };

  const handleImport = async (event) => {
    const input = event?.target;
    const file = input?.files?.[0];
    if (!file) {
      return;
    }
    try {
      const text = await file.text();
      const parsed = JSON.parse(text || '{}');
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Config file must contain a JSON object');
      }
      state.config = {
        ...readConfig(),
        ...parsed,
      };
      state.testResult = null;
      render();
      showStatus('LDAP sync configuration imported. Review and save to apply changes.', 'success');
    } catch (err) {
      showStatus(`LDAP sync import failed: ${err.message}`, 'error');
    } finally {
      input.value = '';
    }
  };

  const save = async (event) => {
    if (event) {
      event.preventDefault();
    }
    if (state.saving) {
      return;
    }
    state.saving = true;
    updateControls();
    showStatus('Saving LDAP sync configuration.', 'info');
    const reason = reasonInput?.value?.trim() || '';
    try {
      const json = await api.updateConfig('ldap-sync', {
        version: state.version,
        reason,
        config: readConfig(),
      });
      state.config = json.ldapSync?.config || readConfig();
      state.version = Number(json.ldapSync?.version || state.version);
      if (reasonInput) {
        reasonInput.value = '';
      }
      state.testResult = null;
      await load();
      recordActivity('ldap-sync', 'LDAP sync configuration saved', reason || 'No reason provided');
      showStatus('LDAP sync configuration saved.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'LDAP sync save failed'), 'error');
    } finally {
      state.saving = false;
      updateControls();
    }
  };

  const runSync = async () => {
    if (state.running) {
      return;
    }
    state.running = true;
    updateControls();
    showStatus('Running LDAP sync.', 'info');
    try {
      const json = await api.runLDAPSync();
      state.runStatus = json.status || state.runStatus;
      await load();
      recordActivity('ldap-sync', 'LDAP sync completed', json.result?.summary || '');
      showStatus(json.result?.summary || 'LDAP sync completed.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'LDAP sync failed'), 'error');
    } finally {
      state.running = false;
      updateControls();
    }
  };

  const testConnection = async () => {
    if (state.testing) {
      return;
    }
    state.testing = true;
    updateControls();
    showStatus('Testing LDAP connection.', 'info');
    try {
      const json = await api.testLDAPSyncConnection(readConfig());
      state.testResult = {
        type: 'success',
        message: json.result?.message || 'LDAP connection test succeeded.',
        connected: Boolean(json.result?.connected),
        bound: Boolean(json.result?.bound),
        baseDnExists: Boolean(json.result?.baseDnExists),
        baseDnCreatable: Boolean(json.result?.baseDnCreatable),
      };
      renderTestResult();
      recordActivity('ldap-sync', 'LDAP connection tested', json.result?.message || '');
      showStatus(json.result?.message || 'LDAP connection test succeeded.', 'success');
    } catch (err) {
      state.testResult = {
        type: 'error',
        message: toUserMessage(err, 'LDAP connection test failed'),
        connected: false,
        bound: false,
        baseDnExists: false,
        baseDnCreatable: false,
      };
      renderTestResult();
      showStatus(toUserMessage(err, 'LDAP connection test failed'), 'error');
    } finally {
      state.testing = false;
      updateControls();
    }
  };

  const bind = () => {
    if (refreshBtn) {
      refreshBtn.addEventListener('click', async () => {
        await load({ announce: true });
      });
    }
    if (exportBtn) {
      exportBtn.addEventListener('click', exportConfig);
    }
    if (importBtn) {
      importBtn.addEventListener('click', triggerImport);
    }
    if (importInput) {
      importInput.addEventListener('change', handleImport);
    }
    if (testBtn) {
      testBtn.addEventListener('click', async () => {
        await testConnection();
      });
    }
    if (runBtn) {
      runBtn.addEventListener('click', async () => {
        await runSync();
      });
    }
    if (form) {
      form.addEventListener('submit', save);
    }
    if (frequencyInput) {
      frequencyInput.addEventListener('change', updateScheduleVisibility);
    }
    if (scheduleEnabledInput) {
      scheduleEnabledInput.addEventListener('change', updateScheduleVisibility);
    }
  };

  return {
    bind,
    load,
    render,
    isLoaded: () => state.loaded,
    exportConfig,
    triggerImport,
  };
};

const configScheduleEnabled = (config) => Boolean(config?.scheduleEnabled);

const getStatusSummary = (info, result) => {
  if (result.summary) {
    return result.summary;
  }
  return info.running ? 'LDAP sync is running.' : 'No LDAP sync has been run yet.';
};

const getStatusState = (info) => {
  if (info.running) {
    return 'Running';
  }
  if (info.lastError) {
    return 'Failed';
  }
  return 'Idle';
};

const getNextRunText = (nextRun, config) => {
  if (nextRun) {
    const date = new Date(nextRun);
    if (!Number.isNaN(date.getTime())) {
      return date.toLocaleString();
    }
    return nextRun;
  }
  if (configScheduleEnabled(config)) {
    return '-';
  }
  return 'Disabled';
};

const clearTestResult = ({
  testResultEl,
  testDetailsEl,
  testConnectedEl,
  testBoundEl,
  testBaseExistsEl,
  testBaseCreatableEl,
}) => {
  if (!testResultEl) {
    return;
  }
  testResultEl.hidden = true;
  testResultEl.textContent = '';
  testResultEl.className = 'status-banner';
  if (testDetailsEl) {
    testDetailsEl.hidden = true;
  }
  [testConnectedEl, testBoundEl, testBaseExistsEl, testBaseCreatableEl]
    .filter(Boolean)
    .forEach((el) => {
      el.textContent = '-';
      el.className = 'muted';
    });
};

const applyTestResult = (result, {
  testResultEl,
  testDetailsEl,
  testConnectedEl,
  testBoundEl,
  testBaseExistsEl,
  testBaseCreatableEl,
}) => {
  testResultEl.hidden = false;
  testResultEl.textContent = result.message;
  testResultEl.className = `status-banner ${result.type === 'error' ? 'error' : 'success'}`;
  if (testDetailsEl) {
    testDetailsEl.hidden = false;
  }
  setTestField(testConnectedEl, result.connected);
  setTestField(testBoundEl, result.bound);
  setTestField(testBaseExistsEl, result.baseDnExists);
  setTestField(testBaseCreatableEl, getBaseCreatableValue(result));
};

const getBaseCreatableValue = (result) => {
  if (result.baseDnExists === true) {
    return null;
  }
  return result.baseDnCreatable;
};

const setTestField = (el, value) => {
  if (!el) {
    return;
  }
  el.className = 'version-badge';
  if (value === true) {
    el.textContent = 'PASS';
    el.style.background = '#14532d';
    el.style.color = '#dcfce7';
    el.style.borderColor = '#166534';
    return;
  }
  if (value === false) {
    el.textContent = 'FAIL';
    el.style.background = '#7f1d1d';
    el.style.color = '#fee2e2';
    el.style.borderColor = '#991b1b';
    return;
  }
  el.textContent = 'N/A';
  el.style.background = '#1f2937';
  el.style.color = '#d1d5db';
  el.style.borderColor = '#374151';
};
