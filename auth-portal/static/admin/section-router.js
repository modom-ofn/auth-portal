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

  const setActiveTab = () => {
    tabs.forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.section === currentSection);
    });
  };

  const showConfigPanels = () => {
    if (configPanel) {
      configPanel.hidden = false;
    }
    if (historyPanel) {
      historyPanel.hidden = false;
    }
    if (oauthPanel) {
      oauthPanel.hidden = true;
    }
    if (ldapSyncPanel) {
      ldapSyncPanel.hidden = true;
    }
    if (backupsPanel) {
      backupsPanel.hidden = true;
    }
  };

  const showOAuthPanel = () => {
    if (configPanel) {
      configPanel.hidden = true;
    }
    if (historyPanel) {
      historyPanel.hidden = true;
    }
    if (oauthPanel) {
      oauthPanel.hidden = false;
    }
    if (ldapSyncPanel) {
      ldapSyncPanel.hidden = true;
    }
    if (backupsPanel) {
      backupsPanel.hidden = true;
    }
  };

  const showLDAPSyncPanel = () => {
    if (configPanel) {
      configPanel.hidden = true;
    }
    if (historyPanel) {
      historyPanel.hidden = false;
    }
    if (oauthPanel) {
      oauthPanel.hidden = true;
    }
    if (ldapSyncPanel) {
      ldapSyncPanel.hidden = false;
    }
    if (backupsPanel) {
      backupsPanel.hidden = true;
    }
  };

  const showBackupsPanel = () => {
    if (configPanel) {
      configPanel.hidden = true;
    }
    if (historyPanel) {
      historyPanel.hidden = false;
    }
    if (oauthPanel) {
      oauthPanel.hidden = true;
    }
    if (ldapSyncPanel) {
      ldapSyncPanel.hidden = true;
    }
    if (backupsPanel) {
      backupsPanel.hidden = false;
    }
  };

  const activate = async (section) => {
    if (!section) {
      return;
    }
    if (
      section === currentSection &&
      section !== 'oauth' &&
      section !== 'ldap-sync' &&
      section !== 'backups' &&
      hasSectionData(section)
    ) {
      return;
    }
    currentSection = section;
    setActiveTab();
    if (typeof onSectionChange === 'function') {
      await onSectionChange(section);
    }
    if (isConfigSection(section)) {
      showConfigPanels();
      if (typeof onConfigSection === 'function') {
        await onConfigSection(section);
      }
      return;
    }
    if (section === 'oauth' && oauthPanel) {
      showOAuthPanel();
      if (typeof onOAuthSection === 'function') {
        await onOAuthSection(section);
      }
      return;
    }
    if (section === 'ldap-sync' && ldapSyncPanel) {
      showLDAPSyncPanel();
      if (typeof onLDAPSyncSection === 'function') {
        await onLDAPSyncSection(section);
      }
      return;
    }
    if (section === 'backups' && backupsPanel && typeof onBackupsSection === 'function') {
      showBackupsPanel();
      await onBackupsSection(section);
    }
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
    showConfigPanels();
  };

  return {
    bind,
    init,
    activate,
    getCurrentSection: () => currentSection,
  };
};
