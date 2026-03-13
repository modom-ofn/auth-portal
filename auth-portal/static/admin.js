import { createConfigFormsController } from './admin/config-forms.js';
import { createRecentChangesController } from './admin/recent-changes.js';
import { createOAuthSectionController } from './admin/oauth-section.js';
import { createLDAPSyncSectionController } from './admin/ldap-sync-section.js';
import { createBackupsSectionController } from './admin/backups-section.js';
import { createHelpModalController } from './admin/help-modal.js';
import { createConfigSectionController } from './admin/config-section.js';
import { createSectionRouter } from './admin/section-router.js';
import { createLoadedAtController, createStatusBannerController } from './admin/admin-core.js';
import { createAdminAPI } from './admin/admin-api.js';

(() => {
  const tabs = Array.from(document.querySelectorAll('.admin-tab'));
  const configForm = document.getElementById('config-form');
  const configFields = document.getElementById('config-fields');
  const configEditor = document.getElementById('config-editor');
  const historyPanel = document.getElementById('history-panel');
  const historyList = document.getElementById('history-list');
  const panelTitle = document.getElementById('panel-title');
  const versionBadge = document.getElementById('version-badge');
  const reasonInput = document.getElementById('reason-input');
  const saveBtn = document.getElementById('save-btn');
  const statusBanner = document.getElementById('status-banner');
  const loadedAtEl = document.getElementById('loaded-at');

  const oauthPanel = document.getElementById('oauth-panel');
  const oauthReloadBtn = document.getElementById('oauth-clients-reload');
  const oauthEmptyState = document.getElementById('oauth-clients-empty');
  const oauthCards = document.getElementById('oauth-client-cards');
  const oauthForm = document.getElementById('oauth-client-form');
  const oauthId = document.getElementById('oauth-client-id');
  const oauthName = document.getElementById('oauth-client-name');
  const oauthRedirects = document.getElementById('oauth-client-redirects');
  const oauthScopes = document.getElementById('oauth-client-scopes');
  const oauthCancel = document.getElementById('oauth-client-cancel');
  const oauthSave = document.getElementById('oauth-client-save');
  const oauthSecretBanner = document.getElementById('oauth-secret-banner');
  const oauthDetailModal = document.getElementById('oauth-detail-modal');
  const oauthDetailClose = document.getElementById('oauth-detail-close');
  const oauthDetailTitle = document.getElementById('oauth-detail-title');
  const oauthDetailBody = document.getElementById('oauth-detail-body');
  const oauthDetailEdit = document.getElementById('oauth-detail-edit');
  const oauthDetailRotate = document.getElementById('oauth-detail-rotate');
  const oauthDetailDelete = document.getElementById('oauth-detail-delete');
  const exportBtn = document.getElementById('config-export-btn');
  const importBtn = document.getElementById('config-import-btn');
  const importInput = document.getElementById('config-import-input');
  const helpBtn = document.getElementById('config-help-btn');
  const helpModal = document.getElementById('help-modal');
  const helpModalClose = document.getElementById('help-modal-close');
  const helpModalTitle = document.getElementById('help-modal-title');
  const helpModalBody = document.getElementById('help-modal-body');
  const recentChangesBtn = document.getElementById('recent-changes-btn');
  const recentChangesModal = document.getElementById('recent-changes-modal');
  const recentChangesModalClose = document.getElementById('recent-changes-modal-close');
  const recentChangesModalTitle = document.getElementById('recent-changes-modal-title');
  const recentChangesList = document.getElementById('recent-changes-list');

  const ldapSyncPanel = document.getElementById('ldap-sync-panel');
  const ldapSyncRefreshBtn = document.getElementById('ldap-sync-refresh-btn');
  const ldapSyncExportBtn = document.getElementById('ldap-sync-export-btn');
  const ldapSyncImportBtn = document.getElementById('ldap-sync-import-btn');
  const ldapSyncImportInput = document.getElementById('ldap-sync-import-input');
  const ldapSyncTestBtn = document.getElementById('ldap-sync-test-btn');
  const ldapSyncRunBtn = document.getElementById('ldap-sync-run-btn');
  const ldapSyncForm = document.getElementById('ldap-sync-form');
  const ldapSyncHost = document.getElementById('ldap-sync-host');
  const ldapSyncAdminDn = document.getElementById('ldap-sync-admin-dn');
  const ldapSyncAdminPassword = document.getElementById('ldap-sync-admin-password');
  const ldapSyncBaseDn = document.getElementById('ldap-sync-base-dn');
  const ldapSyncStartTLS = document.getElementById('ldap-sync-starttls');
  const ldapSyncDeleteStale = document.getElementById('ldap-sync-delete-stale');
  const ldapSyncScheduleEnabled = document.getElementById('ldap-sync-schedule-enabled');
  const ldapSyncFrequency = document.getElementById('ldap-sync-frequency');
  const ldapSyncTime = document.getElementById('ldap-sync-time');
  const ldapSyncWeekday = document.getElementById('ldap-sync-weekday');
  const ldapSyncMinute = document.getElementById('ldap-sync-minute');
  const ldapSyncNextRun = document.getElementById('ldap-sync-next-run');
  const ldapSyncFrequencyRows = Array.from(document.querySelectorAll('[data-ldap-frequency-row]'));
  const ldapSyncReasonInput = document.getElementById('ldap-sync-reason-input');
  const ldapSyncSaveBtn = document.getElementById('ldap-sync-save-btn');
  const ldapSyncStatusSummary = document.getElementById('ldap-sync-status-summary');
  const ldapSyncStatusState = document.getElementById('ldap-sync-status-state');
  const ldapSyncStatusStarted = document.getElementById('ldap-sync-status-started');
  const ldapSyncStatusFinished = document.getElementById('ldap-sync-status-finished');
  const ldapSyncStatusSuccess = document.getElementById('ldap-sync-status-success');
  const ldapSyncStatusTriggeredBy = document.getElementById('ldap-sync-status-triggered-by');
  const ldapSyncTestResult = document.getElementById('ldap-sync-test-result');
  const ldapSyncTestDetails = document.getElementById('ldap-sync-test-details');
  const ldapSyncTestConnected = document.getElementById('ldap-sync-test-connected');
  const ldapSyncTestBound = document.getElementById('ldap-sync-test-bound');
  const ldapSyncTestBaseExists = document.getElementById('ldap-sync-test-base-exists');
  const ldapSyncTestBaseCreatable = document.getElementById('ldap-sync-test-base-creatable');
  const ldapSyncRunRows = document.getElementById('ldap-sync-run-rows');

  const backupsPanel = document.getElementById('backups-panel');
  const backupRefreshBtn = document.getElementById('backups-refresh-btn');
  const backupRunBtn = document.getElementById('backups-run-btn');
  const backupScheduleForm = document.getElementById('backup-schedule-form');
  const backupScheduleEnabled = document.getElementById('backup-schedule-enabled');
  const backupFrequency = document.getElementById('backup-frequency');
  const backupTime = document.getElementById('backup-time');
  const backupWeekday = document.getElementById('backup-weekday');
  const backupMinute = document.getElementById('backup-minute');
  const backupRetention = document.getElementById('backup-retention');
  const backupScheduleSave = document.getElementById('backup-schedule-save');
  const backupReasonInput = document.getElementById('backup-reason-input');
  const backupLastRun = document.getElementById('backup-last-run');
  const backupNextRun = document.getElementById('backup-next-run');
  const backupTableWrapper = document.getElementById('backup-table-wrapper');
  const backupTableBody = document.getElementById('backup-rows');
  const backupEmptyState = document.getElementById('backup-empty');
  const backupSectionCheckboxes = Array.from(document.querySelectorAll('.backup-section-checkbox'));
  const backupFrequencyRows = Array.from(document.querySelectorAll('[data-frequency-row]'));
  const appTimeZone = document.body?.dataset?.appTimezone || 'UTC';

  if (
    !configForm ||
    !configFields ||
    !configEditor ||
    !historyPanel ||
    !historyList ||
    !panelTitle ||
    !versionBadge ||
    !reasonInput ||
    !saveBtn ||
    !statusBanner
  ) {
    return;
  }

  const configSections = ['providers', 'security', 'mfa', 'app-settings'];
  const labels = {
    providers: 'Providers',
    security: 'Security',
    mfa: 'MFA',
    'app-settings': 'App Settings',
    'ldap-sync': 'LDAP Sync',
    backups: 'Backups',
    oauth: 'OAuth Clients',
  };
  const initialSection = 'providers';
  let sectionRouter = null;
  const getCurrentSection = () => sectionRouter?.getCurrentSection() || initialSection;

  const state = {
    data: { providers: null, security: null, mfa: null, 'app-settings': null },
    history: { providers: [], security: [], mfa: [], 'app-settings': [], oauth: [], 'ldap-sync': [], backups: [] },
    loadedAt: null,
  };

  const defaultHelpContent = {
    title: 'Configuration Help',
    body: '<p>No help content is available for this section yet.</p>',
  };

  const helpContent = {
    providers: {
      title: 'Providers Configuration',
      body: `
        <p>Use this JSON to choose the active media provider and supply the credentials that AuthPortal needs to manage users on Plex, Emby, or Jellyfin.</p>
        <ul>
          <li><code>active</code> selects the provider key: <code>plex</code>, <code>emby</code>, or <code>jellyfin</code>.</li>
          <li>The nested provider objects hold connection details—only the active provider must be fully populated, but keeping the others filled lets you switch quickly.</li>
          <li>Values such as <code>serverUrl</code> should be fully qualified URLs, and API tokens/keys should be copied from your media server.</li>
        </ul>
        <pre><code>{
  "active": "plex",
  "plex": {
    "ownerToken": "your-plex-token",
    "serverMachineId": "machine-id",
    "serverName": "My Plex Server"
  },
  "emby": {
    "serverUrl": "https://emby.example.com",
    "appName": "AuthPortal",
    "appVersion": "2.0.3",
    "apiKey": "emby-api-key",
    "ownerUsername": "embyadmin",
    "ownerId": "12345"
  },
  "jellyfin": {
    "serverUrl": "https://jellyfin.example.com",
    "appName": "AuthPortal",
    "appVersion": "2.0.3",
    "apiKey": "jellyfin-api-key"
  }
}</code></pre>
        <p>Keep tokens secure&mdash;changes save immediately and update the live provider integration.</p>
      `,
    },
    security: {
      title: 'Security Configuration',
      body: `
        <p>Control cookie lifetimes and browser security posture for the admin and portal experience.</p>
        <ul>
          <li><code>sessionTtl</code> is a Go duration (<code>24h</code>, <code>2h30m</code>, <code>7d</code>) for authenticated sessions.</li>
          <li><code>sessionSameSite</code> accepts <code>lax</code>, <code>strict</code>, or <code>none</code>. Use <code>none</code> only with HTTPS.</li>
          <li><code>forceSecureCookie</code> forces cookies to use the Secure flag even if <code>APP_BASE_URL</code> is HTTP.</li>
          <li><code>sessionCookieDomain</code> can scope cookies to a parent domain (e.g., <code>auth.example.com</code>).</li>
        </ul>
        <pre><code>{
  "sessionTtl": "24h",
  "sessionSameSite": "lax",
  "forceSecureCookie": true,
  "sessionCookieDomain": "auth.example.com"
}</code></pre>
        <p>Trim whitespace and only set <code>forceSecureCookie</code> to <code>true</code> when end-users connect over HTTPS.</p>
      `,
    },
    mfa: {
      title: 'MFA Configuration',
      body: `
        <p>Fine-tune multi-factor authentication behaviour for end-users.</p>
        <ul>
          <li><code>issuer</code> is the label displayed in authenticator apps (short and recognizable).</li>
          <li><code>enrollmentEnabled</code> controls whether users can enroll MFA devices.</li>
          <li><code>enforceForAllUsers</code> forces MFA at sign-in&mdash;make sure enrollment remains enabled if you enforce MFA.</li>
        </ul>
        <pre><code>{
  "issuer": "AuthPortal",
  "enrollmentEnabled": true,
  "enforceForAllUsers": false
}</code></pre>
        <p>After enabling enforcement, communicate the change so users enroll before their next sign-in.</p>
      `,
    },
    'app-settings': {
      title: 'App Settings Configuration',
      body: `
        <p>Customize small pieces of the user experience that do not belong to a specific provider or security setting.</p>
        <ul>
          <li><code>loginExtraLinkUrl</code> and <code>loginExtraLinkText</code> add an optional button to the authorized portal header. Leave either blank to fall back to the shipped defaults.</li>
          <li><code>serviceLinks</code> defines zero or more button-style links shown to authorized users. Each entry needs a <code>name</code> and <code>url</code>; optional <code>color</code> accepts <code>#RRGGBB</code>.</li>
          <li><code>portalBackgroundColor</code> controls login/home page background color.</li>
          <li><code>portalModalColor</code> controls authorized/unauthorized modal panel color.</li>
          <li><code>unauthRequestEmail</code> and <code>unauthRequestSubject</code> power the mailto link shown on the unauthorized page. Provide a valid email address so users can reach you; empty values revert to defaults.</li>
        </ul>
        <pre><code>{
  "loginExtraLinkUrl": "/support",
  "loginExtraLinkText": "Support",
  "serviceLinks": [
    { "name": "Home Portal", "url": "/home", "color": "#0a5a35" },
    { "name": "Audiobookshelf", "url": "https://audiobooks.example.com", "color": "#1d4ed8" }
  ],
  "portalBackgroundColor": "#0b1020",
  "portalModalColor": "#111827",
  "unauthRequestEmail": "help@example.com",
  "unauthRequestSubject": "Request Access"
}</code></pre>
        <p>Relative URLs are allowed for the extra login link; absolute URLs must include a scheme such as <code>https://</code>.</p>
      `,
    },
  };

  const nowISO = () => new Date().toISOString();
  const status = createStatusBannerController(statusBanner);
  const loadedAt = createLoadedAtController(loadedAtEl);
  const api = createAdminAPI();

  const configForms = createConfigFormsController(configFields);

  const configSection = createConfigSectionController({
    api,
    form: configForm,
    formsController: configForms,
    panelTitle,
    versionBadge,
    reasonInput,
    saveBtn,
    configEditor,
    importInput,
    labels,
    configSections,
    state,
    showStatus: (message, type) => status.show(message, type),
    updateLoadedAt: () => loadedAt.update(state.loadedAt),
    recordActivity: (...args) => recentChanges.recordLocalActivity(...args),
  });

  const recentChanges = createRecentChangesController({
    recentChangesBtn,
    recentChangesModal,
    recentChangesModalClose,
    recentChangesModalTitle,
    recentChangesList,
    inlineHistoryList: historyList,
    labels,
    isConfigSection: configSection.isConfigSection,
    fetchHistory: async (section) => configSection.fetchHistory(section),
    nowISO,
    getCurrentSection,
    historyState: state.history,
  });
  const helpModalController = createHelpModalController({
    button: helpBtn,
    modal: helpModal,
    closeButton: helpModalClose,
    titleEl: helpModalTitle,
    bodyEl: helpModalBody,
    labels,
    isConfigSection: configSection.isConfigSection,
    getCurrentSection,
    helpContent,
    defaultHelpContent,
  });

  const oauthSection = createOAuthSectionController({
    api,
    panel: oauthPanel,
    reloadBtn: oauthReloadBtn,
    emptyState: oauthEmptyState,
    cardsRoot: oauthCards,
    form: oauthForm,
    idInput: oauthId,
    nameInput: oauthName,
    redirectsInput: oauthRedirects,
    scopesInput: oauthScopes,
    cancelBtn: oauthCancel,
    saveBtn: oauthSave,
    secretBanner: oauthSecretBanner,
    detailModal: oauthDetailModal,
    detailCloseBtn: oauthDetailClose,
    detailTitle: oauthDetailTitle,
    detailBody: oauthDetailBody,
    detailEditBtn: oauthDetailEdit,
    detailRotateBtn: oauthDetailRotate,
    detailDeleteBtn: oauthDetailDelete,
    appTimeZone,
    showStatus: (message, type) => status.show(message, type),
    recordActivity: (section, message, reason = '') =>
      recentChanges.recordLocalActivity(section, message, reason),
  });

  const ldapSyncSection = createLDAPSyncSectionController({
    api,
    panel: ldapSyncPanel,
    refreshBtn: ldapSyncRefreshBtn,
    exportBtn: ldapSyncExportBtn,
    importBtn: ldapSyncImportBtn,
    importInput: ldapSyncImportInput,
    testBtn: ldapSyncTestBtn,
    runBtn: ldapSyncRunBtn,
    form: ldapSyncForm,
    hostInput: ldapSyncHost,
    adminDnInput: ldapSyncAdminDn,
    passwordInput: ldapSyncAdminPassword,
    baseDnInput: ldapSyncBaseDn,
    startTlsInput: ldapSyncStartTLS,
    deleteStaleInput: ldapSyncDeleteStale,
    scheduleEnabledInput: ldapSyncScheduleEnabled,
    frequencyInput: ldapSyncFrequency,
    timeInput: ldapSyncTime,
    weekdayInput: ldapSyncWeekday,
    minuteInput: ldapSyncMinute,
    nextRunEl: ldapSyncNextRun,
    frequencyRows: ldapSyncFrequencyRows,
    reasonInput: ldapSyncReasonInput,
    saveBtn: ldapSyncSaveBtn,
    statusSummary: ldapSyncStatusSummary,
    statusState: ldapSyncStatusState,
    statusStartedAt: ldapSyncStatusStarted,
    statusFinishedAt: ldapSyncStatusFinished,
    statusSuccessAt: ldapSyncStatusSuccess,
    statusTriggeredBy: ldapSyncStatusTriggeredBy,
    testResultEl: ldapSyncTestResult,
    testDetailsEl: ldapSyncTestDetails,
    testConnectedEl: ldapSyncTestConnected,
    testBoundEl: ldapSyncTestBound,
    testBaseExistsEl: ldapSyncTestBaseExists,
    testBaseCreatableEl: ldapSyncTestBaseCreatable,
    runRows: ldapSyncRunRows,
    showStatus: (message, type) => status.show(message, type),
    recordActivity: (section, message, reason = '') =>
      recentChanges.recordLocalActivity(section, message, reason),
  });

  const backupsSection = createBackupsSectionController({
    api,
    panel: backupsPanel,
    refreshBtn: backupRefreshBtn,
    runBtn: backupRunBtn,
    scheduleForm: backupScheduleForm,
    scheduleEnabled: backupScheduleEnabled,
    frequencyInput: backupFrequency,
    timeInput: backupTime,
    weekdayInput: backupWeekday,
    minuteInput: backupMinute,
    retentionInput: backupRetention,
    scheduleSaveBtn: backupScheduleSave,
    reasonInput: backupReasonInput,
    lastRunEl: backupLastRun,
    nextRunEl: backupNextRun,
    tableWrapper: backupTableWrapper,
    tableBody: backupTableBody,
    emptyState: backupEmptyState,
    sectionCheckboxes: backupSectionCheckboxes,
    frequencyRows: backupFrequencyRows,
    appTimeZone,
    showStatus: (message, type) => status.show(message, type),
    recordActivity: (section, message, reason = '') =>
      recentChanges.recordLocalActivity(section, message, reason),
    onRestoreConfig: async (config) => {
      configSection.applyConfigResponse(config);
      try {
        await Promise.all(configSections.map((section) => configSection.fetchHistory(section)));
      } catch (error_) {
        console.error('Backup restore history refresh failed', error_);
      }
      const section = getCurrentSection();
      if (configSection.isConfigSection(section)) {
        configSection.renderSection(section);
        recentChanges.refresh(section);
      }
    },
  });

  sectionRouter = createSectionRouter({
    tabs,
    configPanel: configForm,
    historyPanel,
    oauthPanel,
    ldapSyncPanel,
    backupsPanel,
    initialSection,
    isConfigSection: configSection.isConfigSection,
    hasSectionData: (section) => Boolean(state.data[section]),
    onSectionChange: async (section) => {
      helpModalController.updateButton(section);
      recentChanges.updateButton(section);
      status.clear();
    },
    onConfigSection: async (section) => {
      oauthSection.clearSecretBanner();
      await configSection.loadSection(section);
      recentChanges.refresh(section);
    },
    onOAuthSection: async () => {
      await oauthSection.loadClients();
    },
    onLDAPSyncSection: async () => {
      oauthSection.clearSecretBanner();
      await ldapSyncSection.load();
      try {
        await configSection.fetchHistory('ldap-sync');
      } catch (error_) {
        console.error('LDAP sync history fetch failed', error_);
      }
      recentChanges.refresh('ldap-sync');
    },
    onBackupsSection: async () => {
      oauthSection.clearSecretBanner();
      recentChanges.refresh('backups');
      if (backupsSection.isLoaded()) {
        backupsSection.render();
        return;
      }
      await backupsSection.load();
      recentChanges.refresh('backups');
    },
  });

  configSection.bind(getCurrentSection);

  oauthSection.bind();
  ldapSyncSection.bind();

  helpModalController.bind();

  recentChanges.bind();

  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      configSection.exportCurrent(getCurrentSection());
    });
  }

  if (importBtn) {
    importBtn.addEventListener('click', () => {
      configSection.triggerImport(getCurrentSection());
    });
  }

  backupsSection.bind();
  backupsSection.init();

  sectionRouter.bind();
  sectionRouter.init();
  helpModalController.updateButton(getCurrentSection());
  recentChanges.updateButton(getCurrentSection());
  sectionRouter.activate(getCurrentSection());
})();
