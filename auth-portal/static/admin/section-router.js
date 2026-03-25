export const createSectionRouter = ({
  tabs,
  configPanel,
  oauthPanel,
  ldapSyncPanel,
  accessControlPanel,
  backupsPanel,
  logsPanel,
  initialSection = 'providers',
  isConfigSection,
  hasSectionData,
  onSectionChange,
  onConfigSection,
  onOAuthSection,
  onLDAPSyncSection,
  onAccessControlSection,
  onBackupsSection,
  onLogsSection,
}) => {
  let currentSection = initialSection;

  const panelVisibility = {
    config: { config: false, oauth: true, ldapSync: true, accessControl: true, backups: true, logs: true },
    oauth: { config: true, oauth: false, ldapSync: true, accessControl: true, backups: true, logs: true },
    'ldap-sync': { config: true, oauth: true, ldapSync: false, accessControl: true, backups: true, logs: true },
    'access-control': { config: true, oauth: true, ldapSync: true, accessControl: false, backups: true, logs: true },
    backups: { config: true, oauth: true, ldapSync: true, accessControl: true, backups: false, logs: true },
    logs: { config: true, oauth: true, ldapSync: true, accessControl: true, backups: true, logs: false },
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
    if (oauthPanel) {
      oauthPanel.hidden = visibility.oauth;
    }
    if (ldapSyncPanel) {
      ldapSyncPanel.hidden = visibility.ldapSync;
    }
    if (accessControlPanel) {
      accessControlPanel.hidden = visibility.accessControl;
    }
    if (backupsPanel) {
      backupsPanel.hidden = visibility.backups;
    }
    if (logsPanel) {
      logsPanel.hidden = visibility.logs;
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
      'access-control': { panel: accessControlPanel, handler: onAccessControlSection },
      backups: { panel: backupsPanel, handler: onBackupsSection },
      logs: { panel: logsPanel, handler: onLogsSection },
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
