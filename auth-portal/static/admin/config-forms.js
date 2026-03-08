export const createConfigFormsController = (configFields) => {
  if (!configFields) {
    throw new Error('config fields root is required');
  }

  const queryField = (id) => configFields.querySelector(`#${id}`);

  const setFieldValue = (id, value) => {
    const el = queryField(id);
    if (!el) {
      return;
    }
    el.value = value == null ? '' : String(value);
  };

  const setFieldChecked = (id, value) => {
    const el = queryField(id);
    if (!el) {
      return;
    }
    el.checked = Boolean(value);
  };

  const readFieldValue = (id) => {
    const el = queryField(id);
    return (el?.value || '').trim();
  };

  const readFieldChecked = (id) => Boolean(queryField(id)?.checked);
  const setFieldHelp = (id, message) => {
    const el = queryField(id);
    if (!el || !message) {
      return;
    }
    el.title = message;
    const label = el.closest('label');
    if (label) {
      label.title = message;
    }
  };

  const setSectionFieldHelp = (messages = {}) => {
    Object.entries(messages).forEach(([id, message]) => {
      setFieldHelp(id, message);
    });
  };

  const refreshServiceLinkEmptyState = () => {
    const container = queryField('service-links-list');
    const empty = queryField('service-links-empty');
    if (!container || !empty) {
      return;
    }
    empty.hidden = container.querySelectorAll('.service-link-row').length > 0;
  };

  const renderServiceLinkRow = (name = '', url = '', color = '#0a5a35') => {
    const row = document.createElement('div');
    row.className = 'service-link-row';

    const nameRow = document.createElement('div');
    nameRow.className = 'config-form-row';
    const nameLabel = document.createElement('label');
    nameLabel.textContent = 'Button Label';
    const nameInput = document.createElement('input');
    nameInput.type = 'text';
    nameInput.className = 'service-link-name';
    nameInput.maxLength = 64;
    nameInput.placeholder = 'Home Portal';
    nameInput.value = name;
    nameInput.title = 'Display text shown on the authorized user page for this service button.';
    nameRow.appendChild(nameLabel);
    nameRow.appendChild(nameInput);

    const urlRow = document.createElement('div');
    urlRow.className = 'config-form-row';
    const urlLabel = document.createElement('label');
    urlLabel.textContent = 'Button URL';
    const urlInput = document.createElement('input');
    urlInput.type = 'url';
    urlInput.className = 'service-link-url';
    urlInput.placeholder = '/home or https://example.com';
    urlInput.value = url;
    urlInput.title = 'Destination for this service button. Use a relative path or absolute https:// URL.';
    urlRow.appendChild(urlLabel);
    urlRow.appendChild(urlInput);

    const colorRow = document.createElement('div');
    colorRow.className = 'config-form-row';
    const colorLabel = document.createElement('label');
    colorLabel.textContent = 'Button Color';
    const colorInput = document.createElement('input');
    colorInput.type = 'color';
    colorInput.className = 'service-link-color';
    colorInput.value = /^#[0-9A-Fa-f]{6}$/.test((color || '').trim()) ? color.trim() : '#0a5a35';
    colorInput.title = 'Button color shown on the authorized user page.';
    colorRow.appendChild(colorLabel);
    colorRow.appendChild(colorInput);

    const removeButton = document.createElement('button');
    removeButton.type = 'button';
    removeButton.className = 'danger-btn service-link-remove';
    removeButton.textContent = 'Remove';
    removeButton.addEventListener('click', () => {
      row.remove();
      refreshServiceLinkEmptyState();
    });

    row.appendChild(nameRow);
    row.appendChild(urlRow);
    row.appendChild(colorRow);
    row.appendChild(removeButton);
    return row;
  };

  const readServiceLinks = () => {
    const container = queryField('service-links-list');
    if (!container) {
      return [];
    }
    const links = [];
    const seen = new Set();
    container.querySelectorAll('.service-link-row').forEach((row) => {
      const name = row.querySelector('.service-link-name')?.value?.trim() || '';
      const url = row.querySelector('.service-link-url')?.value?.trim() || '';
      const color = row.querySelector('.service-link-color')?.value?.trim() || '';
      if (!name || !url) {
        return;
      }
      const key = `${name.toLowerCase()}|${url}`;
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      links.push({ name, url, color });
    });
    return links;
  };

  const renderProvidersFields = (config = {}) => {
    configFields.innerHTML = `
      <div class="config-form-grid">
        <div class="config-form-row">
          <label for="providers-active">Active Provider</label>
          <select id="providers-active">
            <option value="plex">Plex</option>
            <option value="emby">Emby</option>
            <option value="jellyfin">Jellyfin</option>
          </select>
        </div>
      </div>
      <div class="config-form-group">
        <h4>Plex</h4>
        <div class="config-form-grid">
          <div class="config-form-row">
            <label for="plex-owner-token">Owner Token</label>
            <input id="plex-owner-token" type="password" autocomplete="off">
          </div>
          <div class="config-form-row">
            <label for="plex-server-machine-id">Server Machine ID</label>
            <input id="plex-server-machine-id" type="text">
          </div>
          <div class="config-form-row">
            <label for="plex-server-name">Server Name</label>
            <input id="plex-server-name" type="text">
          </div>
        </div>
      </div>
      <div class="config-form-group">
        <h4>Emby</h4>
        <div class="config-form-grid">
          <div class="config-form-row">
            <label for="emby-server-url">Server URL</label>
            <input id="emby-server-url" type="url">
          </div>
          <div class="config-form-row">
            <label for="emby-app-name">App Name</label>
            <input id="emby-app-name" type="text">
          </div>
          <div class="config-form-row">
            <label for="emby-app-version">App Version</label>
            <input id="emby-app-version" type="text">
          </div>
          <div class="config-form-row">
            <label for="emby-api-key">API Key</label>
            <input id="emby-api-key" type="password" autocomplete="off">
          </div>
          <div class="config-form-row">
            <label for="emby-owner-username">Owner Username</label>
            <input id="emby-owner-username" type="text">
          </div>
          <div class="config-form-row">
            <label for="emby-owner-id">Owner ID</label>
            <input id="emby-owner-id" type="text">
          </div>
        </div>
      </div>
      <div class="config-form-group">
        <h4>Jellyfin</h4>
        <div class="config-form-grid">
          <div class="config-form-row">
            <label for="jellyfin-server-url">Server URL</label>
            <input id="jellyfin-server-url" type="url">
          </div>
          <div class="config-form-row">
            <label for="jellyfin-app-name">App Name</label>
            <input id="jellyfin-app-name" type="text">
          </div>
          <div class="config-form-row">
            <label for="jellyfin-app-version">App Version</label>
            <input id="jellyfin-app-version" type="text">
          </div>
          <div class="config-form-row">
            <label for="jellyfin-api-key">API Key</label>
            <input id="jellyfin-api-key" type="password" autocomplete="off">
          </div>
        </div>
      </div>
    `;
    setFieldValue('providers-active', config.active || 'plex');
    setFieldValue('plex-owner-token', config.plex?.ownerToken || '');
    setFieldValue('plex-server-machine-id', config.plex?.serverMachineId || '');
    setFieldValue('plex-server-name', config.plex?.serverName || '');
    setFieldValue('emby-server-url', config.emby?.serverUrl || '');
    setFieldValue('emby-app-name', config.emby?.appName || '');
    setFieldValue('emby-app-version', config.emby?.appVersion || '');
    setFieldValue('emby-api-key', config.emby?.apiKey || '');
    setFieldValue('emby-owner-username', config.emby?.ownerUsername || '');
    setFieldValue('emby-owner-id', config.emby?.ownerId || '');
    setFieldValue('jellyfin-server-url', config.jellyfin?.serverUrl || '');
    setFieldValue('jellyfin-app-name', config.jellyfin?.appName || '');
    setFieldValue('jellyfin-app-version', config.jellyfin?.appVersion || '');
    setFieldValue('jellyfin-api-key', config.jellyfin?.apiKey || '');
    setSectionFieldHelp({
      'providers-active': 'Choose which provider AuthPortal actively uses for user management.',
      'plex-owner-token':
        'Plex owner token used for administrative API calls. Keep this secret and rotate if exposed.',
      'plex-server-machine-id': 'Unique Plex server machine identifier from your Plex server instance.',
      'plex-server-name': 'Friendly Plex server name shown in provider matching and logs.',
      'emby-server-url': 'Base Emby URL, including scheme, e.g. https://emby.example.com.',
      'emby-app-name': 'Application name sent in Emby API client metadata.',
      'emby-app-version': 'Application version string sent in Emby API client metadata.',
      'emby-api-key': 'Emby API key with permissions to manage users. Keep this secret.',
      'emby-owner-username': 'Emby admin username used as backup identity for owner operations.',
      'emby-owner-id': 'Optional explicit Emby owner user ID for deterministic owner selection.',
      'jellyfin-server-url': 'Base Jellyfin URL, including scheme, e.g. https://jellyfin.example.com.',
      'jellyfin-app-name': 'Application name sent in Jellyfin API client metadata.',
      'jellyfin-app-version': 'Application version string sent in Jellyfin API client metadata.',
      'jellyfin-api-key': 'Jellyfin API key with permissions to manage users. Keep this secret.',
    });
  };

  const renderSecurityFields = (config = {}) => {
    configFields.innerHTML = `
      <div class="config-form-grid">
        <div class="config-form-row">
          <label for="security-session-ttl">Session TTL</label>
          <input id="security-session-ttl" type="text" placeholder="24h">
        </div>
        <div class="config-form-row">
          <label for="security-session-same-site">Session SameSite</label>
          <select id="security-session-same-site">
            <option value="lax">lax</option>
            <option value="strict">strict</option>
            <option value="none">none</option>
          </select>
        </div>
        <div class="config-form-row">
          <label for="security-session-cookie-domain">Session Cookie Domain</label>
          <input id="security-session-cookie-domain" type="text" placeholder="auth.example.com">
        </div>
      </div>
      <div class="config-form-row">
        <label><input id="security-force-secure-cookie" type="checkbox"> Force Secure Cookie</label>
      </div>
    `;
    setFieldValue('security-session-ttl', config.sessionTtl || '24h');
    setFieldValue('security-session-same-site', config.sessionSameSite || 'lax');
    setFieldValue('security-session-cookie-domain', config.sessionCookieDomain || '');
    setFieldChecked('security-force-secure-cookie', config.forceSecureCookie);
    setSectionFieldHelp({
      'security-session-ttl': 'Session duration in Go format (e.g. 24h, 2h30m, 7d).',
      'security-session-same-site':
        'Cookie SameSite policy: lax (recommended), strict, or none (requires HTTPS).',
      'security-session-cookie-domain':
        'Optional cookie domain scope such as auth.example.com. Leave blank for default host-only.',
      'security-force-secure-cookie':
        'Force Secure cookie flag even behind reverse proxies. Enable only when traffic is HTTPS.',
    });
  };

  const renderMFAFields = (config = {}) => {
    configFields.innerHTML = `
      <div class="config-form-grid">
        <div class="config-form-row">
          <label for="mfa-issuer">Issuer</label>
          <input id="mfa-issuer" type="text" placeholder="AuthPortal">
        </div>
      </div>
      <div class="config-form-row">
        <label><input id="mfa-enrollment-enabled" type="checkbox"> Enrollment Enabled</label>
      </div>
      <div class="config-form-row">
        <label><input id="mfa-enforce-all-users" type="checkbox"> Enforce For All Users</label>
      </div>
    `;
    setFieldValue('mfa-issuer', config.issuer || 'AuthPortal');
    setFieldChecked('mfa-enrollment-enabled', config.enrollmentEnabled);
    setFieldChecked('mfa-enforce-all-users', config.enforceForAllUsers);
    setSectionFieldHelp({
      'mfa-issuer': 'Label shown in authenticator apps during MFA enrollment.',
      'mfa-enrollment-enabled': 'Allow users to enroll MFA devices.',
      'mfa-enforce-all-users':
        'Require MFA for all users at sign-in. Ensure enrollment is enabled before enforcing.',
    });
  };

  const renderAppSettingsFields = (config = {}) => {
    configFields.innerHTML = `
      <div class="config-form-grid">
        <div class="config-form-row">
          <label for="app-unauth-request-email">Request Access Email</label>
          <input id="app-unauth-request-email" type="email" placeholder="admin@example.com">
        </div>
        <div class="config-form-row">
          <label for="app-unauth-request-subject">Request Access Subject</label>
          <input id="app-unauth-request-subject" type="text" placeholder="Request Access">
        </div>
      </div>
      <div class="config-form-group">
        <h4>Portal Styling</h4>
        <div class="portal-bg-grid portal-bg-grid-top">
          <div class="config-form-row">
            <label for="app-portal-bg-color">Background Color</label>
            <input id="app-portal-bg-color" type="color" value="#0b1020">
          </div>
          <div class="config-form-row">
            <label for="app-portal-modal-color">Modal Background Color</label>
            <input id="app-portal-modal-color" type="color" value="#111827">
          </div>
        </div>
      </div>
      <div class="config-form-group">
        <h4>Authorized User Service Buttons</h4>
        <div class="service-links-editor">
          <p id="service-links-empty" class="service-link-empty">No service buttons configured.</p>
          <div id="service-links-list"></div>
          <button id="service-link-add" type="button" class="ghost-btn">Add Service Button</button>
        </div>
      </div>
    `;
    setFieldValue('app-unauth-request-email', config.unauthRequestEmail || '');
    setFieldValue('app-unauth-request-subject', config.unauthRequestSubject || '');
    setFieldValue('app-portal-bg-color', config.portalBackgroundColor || '#0b1020');
    setFieldValue('app-portal-modal-color', config.portalModalColor || '#111827');
    setSectionFieldHelp({
      'app-unauth-request-email':
        'Email address used by the unauthorized page Request Access action.',
      'app-unauth-request-subject':
        'Subject line prefilled in Request Access emails from the unauthorized page.',
      'app-portal-bg-color':
        'Background color for login, authorized, and unauthorized page backgrounds.',
      'app-portal-modal-color':
        'Modal card color for login, authorized, and unauthorized pages.',
    });

    const list = queryField('service-links-list');
    (Array.isArray(config.serviceLinks) ? config.serviceLinks : []).forEach((link) => {
      list?.appendChild(renderServiceLinkRow(link?.name || '', link?.url || '', link?.color || '#0a5a35'));
    });
    refreshServiceLinkEmptyState();
    const addButton = queryField('service-link-add');
    if (addButton && list) {
      addButton.addEventListener('click', () => {
        list.appendChild(renderServiceLinkRow('', ''));
        refreshServiceLinkEmptyState();
      });
    }

  };

  const renderSection = (section, config) => {
    if (section === 'providers') {
      renderProvidersFields(config);
      return;
    }
    if (section === 'security') {
      renderSecurityFields(config);
      return;
    }
    if (section === 'mfa') {
      renderMFAFields(config);
      return;
    }
    if (section === 'app-settings') {
      renderAppSettingsFields(config);
      return;
    }
    configFields.innerHTML = '<p class="muted">No form renderer for this section.</p>';
  };

  const readProviders = () => ({
    active: readFieldValue('providers-active') || 'plex',
    plex: {
      ownerToken: readFieldValue('plex-owner-token'),
      serverMachineId: readFieldValue('plex-server-machine-id'),
      serverName: readFieldValue('plex-server-name'),
    },
    emby: {
      serverUrl: readFieldValue('emby-server-url'),
      appName: readFieldValue('emby-app-name'),
      appVersion: readFieldValue('emby-app-version'),
      apiKey: readFieldValue('emby-api-key'),
      ownerUsername: readFieldValue('emby-owner-username'),
      ownerId: readFieldValue('emby-owner-id'),
    },
    jellyfin: {
      serverUrl: readFieldValue('jellyfin-server-url'),
      appName: readFieldValue('jellyfin-app-name'),
      appVersion: readFieldValue('jellyfin-app-version'),
      apiKey: readFieldValue('jellyfin-api-key'),
    },
  });

  const readSecurity = () => ({
    sessionTtl: readFieldValue('security-session-ttl'),
    sessionSameSite: readFieldValue('security-session-same-site'),
    forceSecureCookie: readFieldChecked('security-force-secure-cookie'),
    sessionCookieDomain: readFieldValue('security-session-cookie-domain'),
  });

  const readMFA = () => ({
    issuer: readFieldValue('mfa-issuer'),
    enrollmentEnabled: readFieldChecked('mfa-enrollment-enabled'),
    enforceForAllUsers: readFieldChecked('mfa-enforce-all-users'),
  });

  const readAppSettings = () => ({
    unauthRequestEmail: readFieldValue('app-unauth-request-email'),
    unauthRequestSubject: readFieldValue('app-unauth-request-subject'),
    portalBackgroundColor: readFieldValue('app-portal-bg-color') || '#0b1020',
    portalModalColor: readFieldValue('app-portal-modal-color') || '#111827',
    serviceLinks: readServiceLinks(),
  });

  const readSection = (section) => {
    if (section === 'providers') {
      return readProviders();
    }
    if (section === 'security') {
      return readSecurity();
    }
    if (section === 'mfa') {
      return readMFA();
    }
    if (section === 'app-settings') {
      return readAppSettings();
    }
    return {};
  };

  const setDisabled = (disabled) => {
    configFields.querySelectorAll('input, select, textarea, button').forEach((el) => {
      el.disabled = disabled;
    });
  };

  return {
    renderSection,
    readSection,
    setDisabled,
    setLoadingMessage: () => {
      configFields.innerHTML = '<p class="muted">Loading configuration.</p>';
    },
    setEmptyMessage: () => {
      configFields.innerHTML = '<p class="muted">No configuration loaded for this section.</p>';
    },
  };
};
