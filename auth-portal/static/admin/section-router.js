export const createSectionRouter = ({
  tabs,
  configPanel,
  historyPanel,
  oauthPanel,
  ldapSyncPanel,
  backupsPanel,
  initialSection = 'providers',
  isConfigSection,
  hasSectionData,
  onSectionChange,
  onConfigSection,
  onOAuthSection,
  onLDAPSyncSection,
  onBackupsSection,
}) => {
  let currentSection = initialSection;

  const panelVisibility = {
    config: { config: false, history: false, oauth: true, ldapSync: true, backups: true },
    oauth: { config: true, history: true, oauth: false, ldapSync: true, backups: true },
    'ldap-sync': { config: true, history: false, oauth: true, ldapSync: false, backups: true },
    backups: { config: true, history: false, oauth: true, ldapSync: true, backups: false },
  };

  const setActiveTab = () => {
    tabs.forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.section === currentSection);
    });
  };

  const setPanelVisibility = (visibility) => {
    if (configPanel) {
      configPanel.hidden = visibility.config;
    }
    if (historyPanel) {
      historyPanel.hidden = visibility.history;
    }
    if (oauthPanel) {
      oauthPanel.hidden = visibility.oauth;
    }
    if (ldapSyncPanel) {
      ldapSyncPanel.hidden = visibility.ldapSync;
    }
    if (backupsPanel) {
      backupsPanel.hidden = visibility.backups;
    }
  };

  const showPanelsForSection = (section) => {
    if (isConfigSection(section)) {
      setPanelVisibility(panelVisibility.config);
      return;
    }
    if (panelVisibility[section]) {
      setPanelVisibility(panelVisibility[section]);
    }
  };

  const shouldSkipActivation = (section) => (
    section === currentSection &&
    section !== 'oauth' &&
    section !== 'ldap-sync' &&
    section !== 'backups' &&
    hasSectionData(section)
  );

  const activateSection = async (section) => {
    if (isConfigSection(section)) {
      showPanelsForSection(section);
      if (typeof onConfigSection === 'function') {
        await onConfigSection(section);
      }
      return;
    }

    const specialSections = {
      oauth: { panel: oauthPanel, handler: onOAuthSection },
      'ldap-sync': { panel: ldapSyncPanel, handler: onLDAPSyncSection },
      backups: { panel: backupsPanel, handler: onBackupsSection },
    };
    const special = specialSections[section];
    if (!special?.panel || typeof special.handler !== 'function') {
      return;
    }
    showPanelsForSection(section);
    await special.handler(section);
  };

  const activate = async (section) => {
    if (!section) {
      return;
    }
    if (shouldSkipActivation(section)) {
      return;
    }
    currentSection = section;
    setActiveTab();
    if (typeof onSectionChange === 'function') {
      await onSectionChange(section);
    }
    await activateSection(section);
  };

  const bind = () => {
    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const section = tab.dataset.section;
        if (!section) {
          return;
        }
        activate(section);
      });
    });
  };

  const init = () => {
    setActiveTab();
    showPanelsForSection(initialSection);
  };

  return {
    bind,
    init,
    activate,
    getCurrentSection: () => currentSection,
  };
};
