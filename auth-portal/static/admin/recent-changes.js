export const createRecentChangesController = ({
  recentChangesBtn,
  recentChangesModal,
  recentChangesModalClose,
  recentChangesModalTitle,
  recentChangesList,
  inlineHistoryList,
  labels,
  isConfigSection,
  fetchHistory,
  nowISO,
  getCurrentSection,
  historyState,
}) => {
  let recentChangesModalIsOpen = false;

  const recordLocalActivity = (section, message, reason = '') => {
    if (!section || !message) {
      return;
    }
    const entries = historyState[section] || [];
    entries.unshift({
      version: null,
      updatedAt: nowISO(),
      updatedBy: 'admin',
      reason: reason || message,
      config: null,
    });
    historyState[section] = entries.slice(0, 50);
    if (getCurrentSection() === section) {
      renderHistoryList(section);
    }
  };

  const renderEntriesIntoList = (section, listEl, includeTitle = false) => {
    if (!listEl) {
      return;
    }
    const entries = historyState[section] || [];
    if (includeTitle && recentChangesModalTitle) {
      const sectionLabel = labels[section] || String(section || '').toUpperCase();
      recentChangesModalTitle.textContent = `${sectionLabel} Recent Changes`;
    }
    if (!entries.length) {
      listEl.innerHTML = '<li>No recent changes.</li>';
      return;
    }
    listEl.innerHTML = '';
    if (typeof document === 'undefined') {
      return;
    }
    entries.forEach((entry) => {
      const li = document.createElement('li');
      const when = entry.updatedAt ? new Date(entry.updatedAt).toLocaleString() : 'unknown time';
      const who = entry.updatedBy || 'system';
      const reason = entry.reason ? ` - ${entry.reason}` : '';
      const prefix = entry.version ? `#${entry.version} ` : '';
      li.textContent = `${prefix}@ ${when} by ${who}${reason}`;
      listEl.appendChild(li);
    });
  };

  const renderHistoryList = (section) => {
    renderEntriesIntoList(section, recentChangesList, true);
    renderEntriesIntoList(section, inlineHistoryList, false);
  };

  const closeModal = () => {
    if (!recentChangesModalIsOpen || !recentChangesModal) {
      return;
    }
    recentChangesModal.hidden = true;
    recentChangesModalIsOpen = false;
    document.body.classList.remove('modal-open');
    document.removeEventListener('keydown', handleKeydown);
    if (recentChangesBtn) {
      recentChangesBtn.focus();
    }
  };

  const openModal = async (section) => {
    if (!recentChangesModal || !recentChangesList) {
      return;
    }
    if (isConfigSection(section)) {
      try {
        await fetchHistory(section);
      } catch (error_) {
        console.error('History fetch failed', error_);
      }
    }
    renderHistoryList(section);
    recentChangesModal.hidden = false;
    recentChangesModalIsOpen = true;
    document.body.classList.add('modal-open');
    document.addEventListener('keydown', handleKeydown);
    if (recentChangesModalClose) {
      recentChangesModalClose.focus();
    }
  };

  const updateButton = (section) => {
    if (!recentChangesBtn) {
      return;
    }
    const label = labels[section] || section;
    recentChangesBtn.dataset.section = section;
    recentChangesBtn.setAttribute('aria-label', `Show recent changes for ${label}`);
    recentChangesBtn.title = `Show ${label} recent changes`;
  };

  const handleKeydown = (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeModal();
    }
  };

  const bind = () => {
    if (recentChangesBtn) {
      recentChangesBtn.addEventListener('click', async () => {
        const targetSection = recentChangesBtn.dataset.section || getCurrentSection();
        await openModal(targetSection || getCurrentSection());
      });
    }
    if (recentChangesModalClose) {
      recentChangesModalClose.addEventListener('click', () => {
        closeModal();
      });
    }
    if (recentChangesModal) {
      recentChangesModal.addEventListener('click', (event) => {
        const target = event.target;
        const isClose = target?.dataset?.recentClose !== undefined;
        if (target === recentChangesModal || isClose) {
          closeModal();
        }
      });
    }
  };

  return {
    bind,
    updateButton,
    openModal,
    closeModal,
    recordLocalActivity,
    refresh: (section) => renderHistoryList(section),
  };
};
