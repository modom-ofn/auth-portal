import { createConfigFormsController } from './admin/config-forms.js';
import { createOAuthSectionController } from './admin/oauth-section.js';
import { createLDAPSyncSectionController } from './admin/ldap-sync-section.js';
import { createAccessControlSectionController } from './admin/access-control-section.js';
import { createBackupsSectionController } from './admin/backups-section.js';
import { createLogsSectionController } from './admin/logs-section.js';
import { createHelpModalController } from './admin/help-modal.js';
import { createConfigSectionController } from './admin/config-section.js';
import { createSectionRouter } from './admin/section-router.js';
import { createLoadedAtController, createStatusBannerController } from './admin/admin-core.js';
import { createAdminAPI } from './admin/admin-api.js';

(() => {
  // ---- Sidebar collapse toggle ----
  const sidebarToggleBtn = document.getElementById('sidebar-toggle');
  const adminLayout = document.getElementById('admin-layout');
  if (sidebarToggleBtn && adminLayout) {
    const COLLAPSED_KEY = 'admin-sidebar-collapsed';
    if (localStorage.getItem(COLLAPSED_KEY) === '1') {
      adminLayout.dataset.collapsed = '';
    }
    sidebarToggleBtn.addEventListener('click', () => {
      if ('collapsed' in adminLayout.dataset) {
        delete adminLayout.dataset.collapsed;
        localStorage.removeItem(COLLAPSED_KEY);
      } else {
        adminLayout.dataset.collapsed = '';
        localStorage.setItem(COLLAPSED_KEY, '1');
      }
    });
  }

  const tabs = Array.from(document.querySelectorAll('.admin-tab'));
  const configForm = document.getElementById('config-form');
  const configFields = document.getElementById('config-fields');
  const configEditor = document.getElementById('config-editor');
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
  const oauthScopePicker = document.getElementById('oauth-client-scope-picker');
  const oauthScopeAdd = document.getElementById('oauth-client-scope-add');
  const oauthScopeSelected = document.getElementById('oauth-client-scope-selected');
  const oauthReason = document.getElementById('oauth-client-reason');
  const oauthCancel = document.getElementById('oauth-client-cancel');
  const oauthSave = document.getElementById('oauth-client-save');
  const oauthSecretBanner = document.getElementById('oauth-secret-banner');
  const oauthDetailModal = document.getElementById('oauth-detail-modal');
  const oauthDetailClose = document.getElementById('oauth-detail-close');
  const oauthDetailTitle = document.getElementById('oauth-detail-title');
  const oauthDetailBody = document.getElementById('oauth-detail-body');
  const oauthDetailReason = document.getElementById('oauth-detail-reason');
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
  const ldapSyncGroupSyncEnabled = document.getElementById('ldap-sync-group-sync-enabled');
  const ldapSyncGroupBaseDn = document.getElementById('ldap-sync-group-base-dn');
  const ldapSyncGroupNameAttribute = document.getElementById('ldap-sync-group-name-attribute');
  const ldapSyncGroupMemberAttribute = document.getElementById('ldap-sync-group-member-attribute');
  const ldapGroupRoleMappingList = document.getElementById('ldap-group-role-mapping-list');
  const ldapGroupRoleAddBtn = document.getElementById('ldap-group-role-add-btn');
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

  const accessControlPanel = document.getElementById('access-control-panel');
  const accessControlRefresh = document.getElementById('access-control-refresh');
  const rbacRoleForm = document.getElementById('rbac-role-form');
  const rbacRoleName = document.getElementById('rbac-role-name');
  const rbacRoleDescription = document.getElementById('rbac-role-description');
  const rbacPermissionCheckboxes = document.getElementById('rbac-permission-checkboxes');
  const rbacRoleReason = document.getElementById('rbac-role-reason');
  const rbacRoleReset = document.getElementById('rbac-role-reset');
  const rbacRoleSave = document.getElementById('rbac-role-save');
  const rbacPermissionForm = document.getElementById('rbac-permission-form');
  const rbacPermissionName = document.getElementById('rbac-permission-name');
  const rbacPermissionDescription = document.getElementById('rbac-permission-description');
  const rbacPermissionReason = document.getElementById('rbac-permission-reason');
  const rbacPermissionReset = document.getElementById('rbac-permission-reset');
  const rbacPermissionSave = document.getElementById('rbac-permission-save');
  const rbacRoleRows = document.getElementById('rbac-role-rows');
  const rbacPermissionRows = document.getElementById('rbac-permission-rows');
  const rbacUserRows = document.getElementById('rbac-user-rows');
  const rbacBindingForm = document.getElementById('rbac-binding-form');
  const rbacBindingUsername = document.getElementById('rbac-binding-username');
  const rbacRoleCheckboxes = document.getElementById('rbac-role-checkboxes');
  const rbacBindingReason = document.getElementById('rbac-binding-reason');
  const rbacBindingReset = document.getElementById('rbac-binding-reset');
  const rbacBindingSave = document.getElementById('rbac-binding-save');

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

  const logsPanel = document.getElementById('logs-panel');
  const logsHistoryRefresh = document.getElementById('logs-history-refresh');
  const logsHistorySummary = document.getElementById('logs-history-summary');
  const logsFilterSection = document.getElementById('logs-filter-section');
  const logsFilterUser = document.getElementById('logs-filter-user');
  const logsSortOrder = document.getElementById('logs-sort-order');
  const logsPageSize = document.getElementById('logs-page-size');
  const logsHistoryRows = document.getElementById('logs-history-rows');
  const logsPagePrev = document.getElementById('logs-page-prev');
  const logsPageStatus = document.getElementById('logs-page-status');
  const logsPageNext = document.getElementById('logs-page-next');
  const logsStreamStatus = document.getElementById('logs-stream-status');
  const logsStreamInterval = document.getElementById('logs-stream-interval');
  const logsStreamStart = document.getElementById('logs-stream-start');
  const logsStreamPause = document.getElementById('logs-stream-pause');
  const logsStreamRefresh = document.getElementById('logs-stream-refresh');
  const logsStreamEmpty = document.getElementById('logs-stream-empty');
  const logsStreamOutput = document.getElementById('logs-stream-output');
  const appTimeZone = document.body?.dataset?.appTimezone || 'UTC';

  if (
    !configForm ||
    !configFields ||
    !configEditor ||
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
    'access-control': 'Access Control',
    backups: 'Backups',
    oauth: 'OAuth Clients',
    logs: 'Logs',
  };
  const initialSection = 'providers';
  let sectionRouter = null;
  const getCurrentSection = () => sectionRouter?.getCurrentSection() || initialSection;

  const state = {
    data: { providers: null, security: null, mfa: null, 'app-settings': null },
    history: { providers: [], security: [], mfa: [], 'app-settings': [], oauth: [], 'ldap-sync': [], 'access-control': [], backups: [] },
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

  const status = createStatusBannerController(statusBanner);
  const loadedAt = createLoadedAtController(loadedAtEl);
  const api = createAdminAPI();
  const recordActivity = () => {};

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
    recordActivity,
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
    scopePicker: oauthScopePicker,
    scopeAddBtn: oauthScopeAdd,
    selectedScopesRoot: oauthScopeSelected,
    reasonInput: oauthReason,
    cancelBtn: oauthCancel,
    saveBtn: oauthSave,
    secretBanner: oauthSecretBanner,
    detailModal: oauthDetailModal,
    detailCloseBtn: oauthDetailClose,
    detailTitle: oauthDetailTitle,
    detailBody: oauthDetailBody,
    detailReasonInput: oauthDetailReason,
    detailEditBtn: oauthDetailEdit,
    detailRotateBtn: oauthDetailRotate,
    detailDeleteBtn: oauthDetailDelete,
    appTimeZone,
    showStatus: (message, type) => status.show(message, type),
    recordActivity,
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
    groupSyncEnabledInput: ldapSyncGroupSyncEnabled,
    groupSearchBaseDnInput: ldapSyncGroupBaseDn,
    groupNameAttributeInput: ldapSyncGroupNameAttribute,
    groupMemberAttributeInput: ldapSyncGroupMemberAttribute,
    groupRoleMappingList: ldapGroupRoleMappingList,
    groupRoleAddBtn: ldapGroupRoleAddBtn,
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
    recordActivity,
  });

  const accessControlSection = createAccessControlSectionController({
    api,
    panel: accessControlPanel,
    refreshBtn: accessControlRefresh,
    roleForm: rbacRoleForm,
    roleNameInput: rbacRoleName,
    roleDescriptionInput: rbacRoleDescription,
    permissionCheckboxes: rbacPermissionCheckboxes,
    roleReasonInput: rbacRoleReason,
    roleResetBtn: rbacRoleReset,
    roleSaveBtn: rbacRoleSave,
    roleRows: rbacRoleRows,
    permissionForm: rbacPermissionForm,
    permissionNameInput: rbacPermissionName,
    permissionDescriptionInput: rbacPermissionDescription,
    permissionReasonInput: rbacPermissionReason,
    permissionResetBtn: rbacPermissionReset,
    permissionSaveBtn: rbacPermissionSave,
    permissionRows: rbacPermissionRows,
    userRows: rbacUserRows,
    form: rbacBindingForm,
    usernameInput: rbacBindingUsername,
    roleCheckboxes: rbacRoleCheckboxes,
    reasonInput: rbacBindingReason,
    resetBtn: rbacBindingReset,
    saveBtn: rbacBindingSave,
    showStatus: (message, type) => status.show(message, type),
    recordActivity,
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
    recordActivity,
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
      }
    },
  });

  const logsSection = createLogsSectionController({
    api,
    panel: logsPanel,
    refreshBtn: logsHistoryRefresh,
    historySummaryEl: logsHistorySummary,
    sectionFilterEl: logsFilterSection,
    userFilterEl: logsFilterUser,
    sortOrderEl: logsSortOrder,
    pageSizeEl: logsPageSize,
    historyRows: logsHistoryRows,
    pagePrevBtn: logsPagePrev,
    pageStatusEl: logsPageStatus,
    pageNextBtn: logsPageNext,
    streamStatusEl: logsStreamStatus,
    streamIntervalEl: logsStreamInterval,
    streamStartBtn: logsStreamStart,
    streamPauseBtn: logsStreamPause,
    streamRefreshBtn: logsStreamRefresh,
    streamEmptyEl: logsStreamEmpty,
    streamOutputEl: logsStreamOutput,
    appTimeZone,
    showStatus: (message, type) => status.show(message, type),
  });

  sectionRouter = createSectionRouter({
    tabs,
    configPanel: configForm,
    oauthPanel,
    ldapSyncPanel,
    accessControlPanel,
    backupsPanel,
    logsPanel,
    initialSection,
    isConfigSection: configSection.isConfigSection,
    hasSectionData: (section) => Boolean(state.data[section]),
    onSectionChange: async (section) => {
      helpModalController.updateButton(section);
      if (section !== 'logs') {
        logsSection.cleanup();
      }
      status.clear();
    },
    onConfigSection: async (section) => {
      oauthSection.clearSecretBanner();
      await configSection.loadSection(section);
    },
    onOAuthSection: async () => {
      await oauthSection.loadClients();
    },
    onLDAPSyncSection: async () => {
      oauthSection.clearSecretBanner();
      await ldapSyncSection.load();
    },
    onAccessControlSection: async () => {
      oauthSection.clearSecretBanner();
      await accessControlSection.load();
    },
    onBackupsSection: async () => {
      oauthSection.clearSecretBanner();
      if (backupsSection.isLoaded()) {
        backupsSection.render();
        return;
      }
      await backupsSection.load();
    },
    onLogsSection: async () => {
      oauthSection.clearSecretBanner();
      await logsSection.load();
    },
  });

  configSection.bind(getCurrentSection);

  oauthSection.bind();
  ldapSyncSection.bind();
  accessControlSection.bind();
  logsSection.bind();

  helpModalController.bind();

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
  sectionRouter.activate(getCurrentSection());
})();
