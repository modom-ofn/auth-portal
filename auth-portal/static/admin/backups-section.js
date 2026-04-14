import { toUserMessage } from './admin-errors.js';

export const createBackupsSectionController = ({
  api,
  panel,
  refreshBtn,
  runBtn,
  scheduleForm,
  scheduleEnabled,
  frequencyInput,
  timeInput,
  weekdayInput,
  minuteInput,
  retentionInput,
  scheduleSaveBtn,
  reasonInput,
  lastRunEl,
  nextRunEl,
  tableWrapper,
  tableBody,
  emptyState,
  sectionCheckboxes,
  frequencyRows,
  appTimeZone = 'UTC',
  showStatus,
  recordActivity,
  onRestoreConfig,
}) => {
  const state = {
    loading: false,
    loaded: false,
    savingSchedule: false,
    runningBackup: false,
    schedule: null,
    backups: [],
  };

  const defaultSections = ['providers', 'security', 'mfa', 'app-settings', 'ldap-sync'];

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

  const getSelectedSections = () => {
    if (!sectionCheckboxes.length) {
      return defaultSections.slice();
    }
    const selected = sectionCheckboxes
      .filter((checkbox) => checkbox.checked)
      .map((checkbox) => checkbox.value)
      .filter(Boolean);
    if (!selected.length) {
      return defaultSections.slice();
    }
    return selected;
  };

  const updateControls = () => {
    const busy = state.loading || state.runningBackup;
    if (runBtn) {
      runBtn.disabled = busy;
    }
    if (refreshBtn) {
      refreshBtn.disabled = state.loading;
    }
    if (scheduleSaveBtn) {
      scheduleSaveBtn.disabled = state.savingSchedule;
    }
    const scheduleInputs = [
      scheduleEnabled,
      frequencyInput,
      timeInput,
      weekdayInput,
      minuteInput,
      retentionInput,
    ].filter(Boolean);
    scheduleInputs.forEach((input) => {
      input.disabled = state.savingSchedule;
    });
    sectionCheckboxes.forEach((checkbox) => {
      checkbox.disabled = state.savingSchedule;
    });
  };

  const updateScheduleVisibility = () => {
    if (!frequencyInput || !frequencyRows.length) {
      return;
    }
    const frequency = String(frequencyInput.value || 'daily').toLowerCase();
    frequencyRows.forEach((row) => {
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

  const renderSchedule = () => {
    if (!scheduleForm) {
      return;
    }
    const schedule = state.schedule || {};
    setCheckboxValue(scheduleEnabled, schedule.enabled);
    setInputValue(frequencyInput, String(schedule.frequency || 'daily'));
    setInputValue(timeInput, schedule.timeOfDay || '02:00');
    setInputValue(weekdayInput, schedule.dayOfWeek || 'sunday');
    const minuteValue = typeof schedule.minute === 'number' ? schedule.minute : 0;
    setInputValue(minuteInput, minuteValue);
    const retentionValue = typeof schedule.retention === 'number' ? schedule.retention : 30;
    setInputValue(retentionInput, retentionValue);

    const sections = schedule.sections?.length ? schedule.sections : defaultSections;
    sectionCheckboxes.forEach((checkbox) => {
      checkbox.checked = sections.includes(checkbox.value);
    });
    if (lastRunEl) {
      lastRunEl.textContent = schedule.lastRun ? formatDate(schedule.lastRun) : '-';
    }
    if (nextRunEl) {
      if (schedule.enabled) {
        nextRunEl.textContent = schedule.nextRun ? formatDate(schedule.nextRun) : '-';
      } else {
        nextRunEl.textContent = 'Disabled';
      }
    }
    updateScheduleVisibility();
  };

  const renderList = () => {
    if (!tableBody || !emptyState) {
      return;
    }
    tableBody.innerHTML = '';
    if (!state.backups.length) {
      emptyState.hidden = false;
      if (tableWrapper) {
        tableWrapper.hidden = true;
      }
      return;
    }
    emptyState.hidden = true;
    if (tableWrapper) {
      tableWrapper.hidden = false;
    }
    state.backups.forEach((item) => {
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
      tableBody.appendChild(tr);
    });
  };

  const render = () => {
    renderSchedule();
    renderList();
    updateControls();
  };

  const load = async (options = {}) => {
    if (!panel || state.loading) {
      return;
    }
    state.loading = true;
    updateControls();
    try {
      const json = await api.listBackups();
      state.schedule = json.schedule || null;
      state.backups = Array.isArray(json.backups) ? json.backups : [];
      state.loaded = true;
      render();
      if (options.announce) {
        recordActivity('backups', 'Backups refreshed');
        showStatus('Backups refreshed.', 'success');
      }
    } catch (err) {
      showStatus(toUserMessage(err, 'Backups load failed'), 'error');
    } finally {
      state.loading = false;
      updateControls();
    }
  };

  const runBackup = async () => {
    if (state.runningBackup) {
      return;
    }
    state.runningBackup = true;
    updateControls();
    showStatus('Creating backup.', 'info');
    try {
      const payload = { sections: getSelectedSections() };
      await api.createBackup(payload);
      recordActivity('backups', 'Manual backup created', payload.sections?.join(', '));
      showStatus('Backup created.', 'success');
      await load();
    } catch (err) {
      showStatus(toUserMessage(err, 'Backup failed'), 'error');
    } finally {
      state.runningBackup = false;
      updateControls();
    }
  };

  const saveSchedule = async (event) => {
    if (event) {
      event.preventDefault();
    }
    if (state.savingSchedule) {
      return;
    }
    state.savingSchedule = true;
    updateControls();
    showStatus('Saving backup schedule.', 'info');
    const payload = {
      enabled: scheduleEnabled ? scheduleEnabled.checked : false,
      frequency: frequencyInput ? frequencyInput.value : 'daily',
      timeOfDay: timeInput ? timeInput.value : '',
      dayOfWeek: weekdayInput ? weekdayInput.value : '',
      minute: minuteInput ? Number(minuteInput.value || 0) : 0,
      sections: getSelectedSections(),
      retention: retentionInput ? Number(retentionInput.value || 0) : 0,
      reason: reasonInput ? reasonInput.value.trim() : '',
    };
    try {
      const json = await api.updateBackupSchedule(payload);
      state.schedule = json.schedule || payload;
      recordActivity(
        'backups',
        'Backup schedule saved',
        payload.reason || payload.frequency || 'daily',
      );
      if (reasonInput) {
        reasonInput.value = '';
      }
      showStatus('Backup schedule saved.', 'success');
      render();
    } catch (err) {
      showStatus(toUserMessage(err, 'Schedule update failed'), 'error');
    } finally {
      state.savingSchedule = false;
      updateControls();
    }
  };

  const deleteBackupByName = async (name) => {
    if (!name) {
      return;
    }
    if (!globalThis.confirm('Delete this backup? This cannot be undone.')) {
      return;
    }
    state.loading = true;
    updateControls();
    showStatus('Deleting backup.', 'info');
    let deleted = false;
    try {
      await api.deleteBackup(name);
      deleted = true;
      recordActivity('backups', 'Backup deleted', name);
      showStatus('Backup deleted.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'Delete failed'), 'error');
    } finally {
      state.loading = false;
      updateControls();
    }
    if (deleted) {
      await load();
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
    state.loading = true;
    updateControls();
    showStatus('Restoring backup.', 'info');
    let restored = false;
    try {
      const json = await api.restoreBackup(name);
      if (json.config && typeof onRestoreConfig === 'function') {
        await onRestoreConfig(json.config);
      }
      restored = true;
      recordActivity('backups', 'Backup restored', name);
      showStatus('Backup restored.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'Restore failed'), 'error');
    } finally {
      state.loading = false;
      updateControls();
    }
    if (restored) {
      await load();
    }
  };

  const bind = () => {
    if (runBtn) {
      runBtn.addEventListener('click', async () => {
        await runBackup();
      });
    }
    if (refreshBtn) {
      refreshBtn.addEventListener('click', async () => {
        await load({ announce: true });
      });
    }
    if (scheduleForm) {
      scheduleForm.addEventListener('submit', saveSchedule);
    }
    if (frequencyInput) {
      frequencyInput.addEventListener('change', updateScheduleVisibility);
    }
  };

  const init = () => {
    updateScheduleVisibility();
    updateControls();
  };

  return {
    bind,
    init,
    load,
    render,
    isLoaded: () => state.loaded,
  };
};
