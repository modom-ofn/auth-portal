import { toUserMessage } from './admin-errors.js';

export const createLogsSectionController = ({
  api,
  panel,
  refreshBtn,
  historySummaryEl,
  sectionFilterEl,
  userFilterEl,
  sortOrderEl,
  pageSizeEl,
  historyRows,
  pagePrevBtn,
  pageStatusEl,
  pageNextBtn,
  streamStatusEl,
  streamIntervalEl,
  streamStartBtn,
  streamPauseBtn,
  streamRefreshBtn,
  streamEmptyEl,
  streamOutputEl,
  appTimeZone = 'UTC',
  showStatus,
}) => {
  const state = {
    loaded: false,
    loadingHistory: false,
    historyEntries: [],
    currentPage: 1,
    streamActive: false,
    streamLoading: false,
    streamCursor: 0,
    streamTimer: null,
    streamLines: [],
  };

  const sectionLabels = {
    providers: 'Providers',
    security: 'Security',
    mfa: 'MFA',
    'app-settings': 'App Settings',
    oauth: 'OAuth Clients',
    'ldap-sync': 'LDAP Sync',
    'access-control': 'Access Control',
    backups: 'Backups',
    logs: 'Logs',
    rbac: 'Access Control',
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

  const escapeHTML = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

  const getFilteredHistory = () => {
    const section = sectionFilterEl?.value || '';
    const user = userFilterEl?.value || '';
    const order = sortOrderEl?.value || 'desc';

    const filtered = state.historyEntries.filter((entry) => {
      const matchesSection = !section || entry.section === section;
      const matchesUser = !user || (entry.updatedBy || '') === user;
      return matchesSection && matchesUser;
    });

    filtered.sort((a, b) => {
      const aTime = new Date(a.updatedAt || 0).getTime();
      const bTime = new Date(b.updatedAt || 0).getTime();
      return order === 'asc' ? aTime - bTime : bTime - aTime;
    });
    return filtered;
  };

  const getPageSize = () => {
    const raw = String(pageSizeEl?.value || '10').toLowerCase();
    if (raw === 'all') {
      return 0;
    }
    const parsed = Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 10;
  };

  const getPaginatedHistory = () => {
    const entries = getFilteredHistory();
    const pageSize = getPageSize();
    if (pageSize === 0) {
      return {
        entries,
        totalEntries: entries.length,
        pageSize,
        totalPages: 1,
        currentPage: 1,
        startIndex: entries.length ? 1 : 0,
        endIndex: entries.length,
      };
    }

    const totalPages = Math.max(1, Math.ceil(entries.length / pageSize));
    const currentPage = Math.min(state.currentPage, totalPages);
    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    return {
      entries: entries.slice(start, end),
      totalEntries: entries.length,
      pageSize,
      totalPages,
      currentPage,
      startIndex: entries.length ? start + 1 : 0,
      endIndex: Math.min(end, entries.length),
    };
  };

  const populateHistoryFilters = () => {
    if (sectionFilterEl) {
      const current = sectionFilterEl.value;
      const sections = Array.from(new Set(
        state.historyEntries
          .map((entry) => entry.section)
          .filter(Boolean),
      ));
      sectionFilterEl.innerHTML = '<option value="">All tabs</option>';
      sections.forEach((section) => {
        const option = document.createElement('option');
        option.value = section;
        option.textContent = sectionLabels[section] || section;
        sectionFilterEl.appendChild(option);
      });
      sectionFilterEl.value = sections.includes(current) ? current : '';
    }

    if (userFilterEl) {
      const current = userFilterEl.value;
      const users = Array.from(new Set(
        state.historyEntries
          .map((entry) => entry.updatedBy || '')
          .filter(Boolean),
      )).sort((a, b) => a.localeCompare(b));
      userFilterEl.innerHTML = '<option value="">All users</option>';
      users.forEach((user) => {
        const option = document.createElement('option');
        option.value = user;
        option.textContent = user;
        userFilterEl.appendChild(option);
      });
      userFilterEl.value = users.includes(current) ? current : '';
    }
  };

  const renderHistory = () => {
    if (!historyRows) {
      return;
    }
    const paginated = getPaginatedHistory();
    state.currentPage = paginated.currentPage;
    const entries = paginated.entries;
    historyRows.innerHTML = '';
    if (entries.length === 0) {
      historyRows.innerHTML = '<tr><td colspan="5" class="muted">No matching log entries.</td></tr>';
    } else {
      entries.forEach((entry) => {
        const tr = document.createElement('tr');
        const detailPrefix = entry.subject
          ? `${entry.subject}${entry.details ? ' - ' : ''}`
          : '';
        tr.innerHTML = `
          <td>${escapeHTML(formatDate(entry.updatedAt))}</td>
          <td>${escapeHTML(entry.label || sectionLabels[entry.section] || entry.section || '-')}</td>
          <td>${escapeHTML(entry.updatedBy || 'system')}</td>
          <td>${escapeHTML(entry.action || '-')}</td>
          <td>${escapeHTML(detailPrefix)}${escapeHTML(entry.details || '-')}</td>
        `;
        historyRows.appendChild(tr);
      });
    }
    if (historySummaryEl) {
      if (paginated.totalEntries === 0) {
        historySummaryEl.textContent = '0 entries shown';
      } else if (paginated.pageSize === 0) {
        historySummaryEl.textContent = `${paginated.totalEntries} entries shown`;
      } else {
        historySummaryEl.textContent = `${paginated.startIndex}-${paginated.endIndex} of ${paginated.totalEntries} entries`;
      }
    }
    if (pageStatusEl) {
      pageStatusEl.textContent = paginated.pageSize === 0
        ? 'Showing all entries'
        : `Page ${paginated.currentPage} of ${paginated.totalPages}`;
    }
    if (pagePrevBtn) {
      pagePrevBtn.disabled = paginated.pageSize === 0 || paginated.currentPage <= 1;
    }
    if (pageNextBtn) {
      pageNextBtn.disabled = paginated.pageSize === 0 || paginated.currentPage >= paginated.totalPages;
    }
  };

  const renderStream = () => {
    if (!streamOutputEl || !streamEmptyEl) {
      return;
    }
    const hasLines = state.streamLines.length > 0;
    streamOutputEl.hidden = !hasLines;
    streamEmptyEl.hidden = hasLines;
    if (hasLines) {
      streamOutputEl.textContent = state.streamLines
        .map((entry) => `[${formatDate(entry.timestamp)}] ${entry.message}`)
        .join('\n');
      streamOutputEl.scrollTop = streamOutputEl.scrollHeight;
    }
    if (streamStatusEl) {
      if (state.streamActive) {
        const seconds = Math.max(1, Math.round((Number(streamIntervalEl?.value) || 5000) / 1000));
        streamStatusEl.textContent = `Streaming every ${seconds} seconds.`;
      } else if (hasLines) {
        streamStatusEl.textContent = 'Stream paused.';
      } else {
        streamStatusEl.textContent = 'Stream is off.';
      }
    }
    if (streamStartBtn) {
      streamStartBtn.disabled = state.streamActive;
    }
    if (streamPauseBtn) {
      streamPauseBtn.disabled = !state.streamActive;
    }
    if (streamRefreshBtn) {
      streamRefreshBtn.disabled = state.streamActive || state.streamLoading;
    }
    if (streamIntervalEl) {
      streamIntervalEl.disabled = state.streamActive;
    }
  };

  const stopStreamTimer = () => {
    if (state.streamTimer) {
      clearInterval(state.streamTimer);
      state.streamTimer = null;
    }
  };

  const fetchHistory = async (announce = false) => {
    if (state.loadingHistory) {
      return;
    }
    state.loadingHistory = true;
    try {
      const json = await api.getLogsHistory(200);
      state.historyEntries = Array.isArray(json.entries) ? json.entries : [];
      state.currentPage = 1;
      populateHistoryFilters();
      renderHistory();
      state.loaded = true;
      if (announce) {
        showStatus('Logs refreshed.', 'success');
      }
    } catch (err) {
      showStatus(toUserMessage(err, 'Logs fetch failed'), 'error');
    } finally {
      state.loadingHistory = false;
    }
  };

  const fetchStream = async () => {
    if (state.streamLoading) {
      return;
    }
    state.streamLoading = true;
    try {
      const json = await api.getLogStream({ cursor: state.streamCursor, limit: 100 });
      const entries = Array.isArray(json.entries) ? json.entries : [];
      if (entries.length) {
        state.streamLines = state.streamLines.concat(entries).slice(-300);
      }
      state.streamCursor = Number(json.cursor) || state.streamCursor;
      renderStream();
    } catch (err) {
      showStatus(toUserMessage(err, 'Log stream fetch failed'), 'error');
      stopStreamTimer();
      state.streamActive = false;
      renderStream();
    } finally {
      state.streamLoading = false;
    }
  };

  const startStream = async () => {
    if (state.streamActive) {
      return;
    }
    state.streamActive = true;
    renderStream();
    await fetchStream();
    stopStreamTimer();
    state.streamTimer = globalThis.setInterval(() => {
      void fetchStream();
    }, Number(streamIntervalEl?.value) || 5000);
  };

  const pauseStream = () => {
    state.streamActive = false;
    stopStreamTimer();
    renderStream();
  };

  const refreshStreamOnce = async () => {
    if (state.streamActive) {
      return;
    }
    await fetchStream();
  };

  const bind = () => {
    refreshBtn?.addEventListener('click', async () => {
      await fetchHistory(true);
    });
    [sectionFilterEl, userFilterEl, sortOrderEl, pageSizeEl].filter(Boolean).forEach((input) => {
      input.addEventListener('change', () => {
        state.currentPage = 1;
        renderHistory();
      });
    });
    pagePrevBtn?.addEventListener('click', () => {
      if (state.currentPage > 1) {
        state.currentPage -= 1;
        renderHistory();
      }
    });
    pageNextBtn?.addEventListener('click', () => {
      state.currentPage += 1;
      renderHistory();
    });
    streamStartBtn?.addEventListener('click', async () => {
      await startStream();
    });
    streamPauseBtn?.addEventListener('click', () => {
      pauseStream();
    });
    streamRefreshBtn?.addEventListener('click', async () => {
      await refreshStreamOnce();
    });
  };

  return {
    bind,
    load: async () => {
      await fetchHistory(false);
      renderStream();
    },
    cleanup: () => {
      pauseStream();
    },
    isLoaded: () => state.loaded,
  };
};
