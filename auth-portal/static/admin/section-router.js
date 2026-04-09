export const createSectionRouter = ({
  tabs,
  configPanel,         // backwards-compat: single element for all config sections
  configPanels,        // preferred: { providers: el, security: el, mfa: el, 'app-settings': el }
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

  // Resolve to a map (backwards-compat: single configPanel maps to all config sections)
  const resolvedConfigPanels = configPanels || (configPanel ? {
    providers: configPanel,
    security: configPanel,
    mfa: configPanel,
    'app-settings': configPanel,
  } : {});

  const nonConfigPanels = [oauthPanel, ldapSyncPanel, accessControlPanel, backupsPanel, logsPanel];

  const setActiveTab = () => {
    tabs.forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.section === currentSection);
    });
  };

  const hideAllConfigPanels = () => {
    const seen = new Set();
    Object.values(resolvedConfigPanels).forEach((p) => {
      if (p && !seen.has(p)) {
        p.hidden = true;
        seen.add(p);
      }
    });
  };

  const showPanelsForSection = (section) => {
    hideAllConfigPanels();
    nonConfigPanels.forEach((p) => { if (p) p.hidden = true; });

    if (isConfigSection(section)) {
      const panel = resolvedConfigPanels[section];
      if (panel) panel.hidden = false;
      return;
    }

    const specialPanels = {
      oauth: oauthPanel,
      'ldap-sync': ldapSyncPanel,
      'access-control': accessControlPanel,
      backups: backupsPanel,
      logs: logsPanel,
    };
    const panel = specialPanels[section];
    if (panel) panel.hidden = false;
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

    const specialHandlers = {
      oauth: onOAuthSection,
      'ldap-sync': onLDAPSyncSection,
      'access-control': onAccessControlSection,
      backups: onBackupsSection,
      logs: onLogsSection,
    };
    const handler = specialHandlers[section];
    if (typeof handler !== 'function') return;
    showPanelsForSection(section);
    await handler(section);
  };

  const activate = async (section) => {
    if (!section) return;
    if (shouldSkipActivation(section)) return;
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
        if (!section) return;
        activate(section);
      });
    });
  };

  const init = () => {
    setActiveTab();
    showPanelsForSection(initialSection);
  };

  return { bind, init, activate, getCurrentSection: () => currentSection };
};
