import assert from 'node:assert/strict';

import { createSectionRouter } from './section-router.js';
import { createConfigSectionController } from './config-section.js';
import { createHelpModalController } from './help-modal.js';
import { createRecentChangesController } from './recent-changes.js';
import { createOAuthSectionController } from './oauth-section.js';
import { createBackupsSectionController } from './backups-section.js';
import { createAdminAPI } from './admin-api.js';

const makeEl = () => {
  const attrs = new Map();
  return {
    hidden: false,
    disabled: false,
    dataset: {},
    className: '',
    textContent: '',
    title: '',
    value: '',
    checked: false,
    setAttribute(name, value) {
      attrs.set(name, value);
    },
    removeAttribute(name) {
      attrs.delete(name);
    },
    getAttribute(name) {
      return attrs.get(name);
    },
    addEventListener() {},
    focus() {},
    appendChild() {},
    remove() {},
  };
};

const runRouterSmoke = async () => {
  const tabs = ['providers', 'oauth', 'backups'].map((section) => ({
    dataset: { section },
    classList: {
      active: false,
      toggle(_name, value) {
        this.active = Boolean(value);
      },
    },
    addEventListener() {},
  }));
  const configPanel = makeEl();
  const oauthPanel = makeEl();
  const backupsPanel = makeEl();
  const events = [];

  const router = createSectionRouter({
    tabs,
    configPanel,
    oauthPanel,
    backupsPanel,
    initialSection: 'providers',
    isConfigSection: (section) => section === 'providers',
    hasSectionData: () => false,
    onSectionChange: async (section) => events.push(`change:${section}`),
    onConfigSection: async (section) => events.push(`config:${section}`),
    onOAuthSection: async (section) => events.push(`oauth:${section}`),
    onBackupsSection: async (section) => events.push(`backups:${section}`),
  });

  router.init();
  await router.activate('providers');
  await router.activate('oauth');
  await router.activate('backups');

  assert.equal(router.getCurrentSection(), 'backups');
  assert.equal(configPanel.hidden, true);
  assert.equal(oauthPanel.hidden, true);
  assert.equal(backupsPanel.hidden, false);
  assert.deepEqual(events, [
    'change:providers',
    'config:providers',
    'change:oauth',
    'oauth:oauth',
    'change:backups',
    'backups:backups',
  ]);
};

const runConfigSmoke = async () => {
  const state = {
    data: { providers: null, security: null, mfa: null, 'app-settings': null },
    history: { providers: [], security: [], mfa: [], 'app-settings': [] },
    loadedAt: null,
  };
  const api = {
    async getConfig() {
      return {
        providers: { version: 1, config: {} },
        security: { version: 1, config: {} },
        mfa: { version: 1, config: {} },
        appSettings: { version: 1, config: {} },
        loadedAt: '2026-03-08T00:00:00Z',
      };
    },
    async getConfigHistory() {
      return { entries: [] };
    },
    async updateConfig(_section, _payload) {
      return {
        providers: { version: 2, config: {} },
        security: { version: 1, config: {} },
        mfa: { version: 1, config: {} },
        appSettings: { version: 1, config: {} },
        loadedAt: '2026-03-08T00:00:00Z',
      };
    },
  };

  let recorded = '';
  const formsController = {
    setLoadingMessage() {},
    setDisabled() {},
    setEmptyMessage() {},
    readSection() {
      return {};
    },
    renderSection() {},
  };

  const controller = createConfigSectionController({
    api,
    form: { hidden: false, addEventListener() {} },
    formsController,
    panelTitle: makeEl(),
    versionBadge: makeEl(),
    reasonInput: makeEl(),
    saveBtn: { ...makeEl(), disabled: false },
    configEditor: { ...makeEl(), dataset: {} },
    importInput: makeEl(),
    labels: { providers: 'Providers' },
    configSections: ['providers'],
    state,
    showStatus() {},
    updateLoadedAt() {},
    recordActivity(section, message) {
      recorded = `${section}:${message}`;
    },
  });

  await controller.loadSection('providers');
  await controller.saveCurrent('providers');
  assert.equal(recorded, 'providers:Configuration saved');
};

const runHelpAndRecentSmoke = () => {
  const helpBtn = makeEl();
  const help = createHelpModalController({
    button: helpBtn,
    modal: makeEl(),
    closeButton: makeEl(),
    titleEl: makeEl(),
    bodyEl: makeEl(),
    labels: { providers: 'Providers' },
    isConfigSection: (section) => section === 'providers',
    getCurrentSection: () => 'providers',
    helpContent: { providers: { title: 'P', body: '<p>x</p>' } },
  });
  help.updateButton('providers');
  assert.equal(helpBtn.hidden, false);
  help.updateButton('oauth');
  assert.equal(helpBtn.hidden, true);

  const historyState = { providers: [] };
  const recent = createRecentChangesController({
    recentChangesBtn: makeEl(),
    recentChangesModal: makeEl(),
    recentChangesModalClose: makeEl(),
    recentChangesModalTitle: makeEl(),
    recentChangesList: { ...makeEl(), innerHTML: '', appendChild() {} },
    labels: { providers: 'Providers' },
    isConfigSection: () => false,
    fetchHistory: async () => {},
    nowISO: () => '2026-03-08T00:00:00Z',
    getCurrentSection: () => 'providers',
    historyState,
  });
  recent.recordLocalActivity('providers', 'Changed');
  assert.equal(historyState.providers.length, 1);
};

const runConstructionSmoke = () => {
  const api = createAdminAPI();
  const methods = [
    'getConfig',
    'getConfigHistory',
    'updateConfig',
    'listOAuthClients',
    'createOAuthClient',
    'updateOAuthClient',
    'deleteOAuthClient',
    'rotateOAuthSecret',
    'listBackups',
    'createBackup',
    'updateBackupSchedule',
    'deleteBackup',
    'restoreBackup',
  ];
  methods.forEach((method) => {
    assert.equal(typeof api[method], 'function', `Missing API method: ${method}`);
  });

  const oauth = createOAuthSectionController({
    api: {},
    panel: makeEl(),
    reloadBtn: makeEl(),
    emptyState: makeEl(),
    tableWrapper: makeEl(),
    table: makeEl(),
    rows: { ...makeEl(), innerHTML: '' },
    form: makeEl(),
    idInput: makeEl(),
    nameInput: makeEl(),
    redirectsInput: makeEl(),
    scopesInput: makeEl(),
    cancelBtn: makeEl(),
    saveBtn: makeEl(),
    secretBanner: makeEl(),
    showStatus() {},
    recordActivity() {},
  });
  assert.equal(typeof oauth.bind, 'function');
  assert.equal(typeof oauth.loadClients, 'function');

  const backups = createBackupsSectionController({
    api: {},
    panel: makeEl(),
    refreshBtn: makeEl(),
    runBtn: makeEl(),
    scheduleForm: makeEl(),
    scheduleEnabled: makeEl(),
    frequencyInput: makeEl(),
    timeInput: makeEl(),
    weekdayInput: makeEl(),
    minuteInput: makeEl(),
    retentionInput: makeEl(),
    scheduleSaveBtn: makeEl(),
    lastRunEl: makeEl(),
    nextRunEl: makeEl(),
    tableWrapper: makeEl(),
    tableBody: { ...makeEl(), innerHTML: '' },
    emptyState: makeEl(),
    sectionCheckboxes: [],
    frequencyRows: [],
    showStatus() {},
    recordActivity() {},
    onRestoreConfig: async () => {},
  });
  assert.equal(typeof backups.bind, 'function');
  assert.equal(typeof backups.load, 'function');
};

const run = async () => {
  await runRouterSmoke();
  await runConfigSmoke();
  runHelpAndRecentSmoke();
  runConstructionSmoke();
  console.log('admin smoke tests passed');
};

run().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
