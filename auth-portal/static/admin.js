(() => {
  const tabs = Array.from(document.querySelectorAll('.admin-tab'));
  const configView = document.getElementById('config-view');
  const historyView = document.getElementById('history-view');
  const panelTitle = document.getElementById('panel-title');

  if (!tabs.length || !configView || !historyView) {
    return;
  }

  let currentSection = 'providers';

  const setLoading = () => {
    configView.textContent = 'Loading…';
    historyView.textContent = 'Loading…';
  };

  const setError = (msg) => {
    configView.textContent = `Error: ${msg}`;
    historyView.textContent = '—';
  };

  const renderConfig = (data) => {
    if (!data || !data.ok) {
      setError('Unable to load configuration');
      return;
    }
    let sectionData;
    switch (currentSection) {
      case 'security':
        sectionData = data.security;
        panelTitle.textContent = 'Security';
        break;
      case 'mfa':
        sectionData = data.mfa;
        panelTitle.textContent = 'MFA';
        break;
      case 'providers':
      default:
        sectionData = data.providers;
        panelTitle.textContent = 'Providers';
        currentSection = 'providers';
        break;
    }
    configView.textContent = JSON.stringify(sectionData, null, 2);
  };

  const renderHistory = (data) => {
    if (!data || !data.ok) {
      historyView.textContent = 'No history available.';
      return;
    }
    if (!data.entries || !data.entries.length) {
      historyView.textContent = 'No recent changes.';
      return;
    }
    const lines = data.entries.map((entry) => {
      const timestamp = entry.updatedAt ? new Date(entry.updatedAt).toLocaleString() : 'unknown time';
      const by = entry.updatedBy || 'system';
      const reason = entry.reason ? ` — ${entry.reason}` : '';
      return `#${entry.version} @ ${timestamp} by ${by}${reason}`;
    });
    historyView.textContent = lines.join('\n');
  };

  const loadSection = async () => {
    setLoading();
    try {
      const [configRes, historyRes] = await Promise.all([
        fetch('/api/admin/config', { credentials: 'same-origin' }),
        fetch(`/api/admin/config/history/${currentSection}`, { credentials: 'same-origin' }),
      ]);
      const configJson = await configRes.json();
      const historyJson = await historyRes.json();
      renderConfig(configJson);
      renderHistory(historyJson);
    } catch (err) {
      setError(err.message || String(err));
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const section = tab.getAttribute('data-section');
      if (section && section !== currentSection) {
        tabs.forEach((t) => t.classList.remove('active'));
        tab.classList.add('active');
        currentSection = section;
        loadSection();
      }
    });
  });

  loadSection();
})();
