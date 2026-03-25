import { buildAPIError } from './admin-errors.js';

const requestJSON = async (url, options = {}) => {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }
  const res = await fetch(url, { credentials: 'same-origin', ...options, headers });
  const raw = await res.text();
  let json = null;
  if (raw) {
    try {
      json = JSON.parse(raw);
    } catch {
      json = { ok: false, error: raw };
    }
  }
  return { res, json };
};

export const createAdminAPI = () => {
  const getConfig = async () => {
    const { res, json } = await requestJSON('/api/admin/config');
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Config fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const getConfigHistory = async (section, limit = 25) => {
    const { res, json } = await requestJSON(
      `/api/admin/config/history/${encodeURIComponent(section)}?limit=${Number(limit) || 25}`,
    );
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'History fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const updateConfig = async (section, payload) => {
    const { res, json } = await requestJSON(`/api/admin/config/${encodeURIComponent(section)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({ fallback: 'Save failed', status: res.status, serverError: json?.error });
    }
    return json;
  };

  const listOAuthClients = async () => {
    const { res, json } = await requestJSON('/api/admin/oauth/clients');
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Client fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const createOAuthClient = async (payload) => {
    const { res, json } = await requestJSON('/api/admin/oauth/clients', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({ fallback: 'Save failed', status: res.status, serverError: json?.error });
    }
    return json;
  };

  const updateOAuthClient = async (clientId, payload) => {
    const { res, json } = await requestJSON(
      `/api/admin/oauth/clients/${encodeURIComponent(clientId)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      },
    );
    if (!res.ok || !json?.ok) {
      throw buildAPIError({ fallback: 'Save failed', status: res.status, serverError: json?.error });
    }
    return json;
  };

  const deleteOAuthClient = async (clientId, payload = {}) => {
    const { res, json } = await requestJSON(
      `/api/admin/oauth/clients/${encodeURIComponent(clientId)}`,
      {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      },
    );
    if (!res.ok || !json?.ok) {
      throw buildAPIError({ fallback: 'Delete failed', status: res.status, serverError: json?.error });
    }
    return json;
  };

  const rotateOAuthSecret = async (clientId, payload = {}) => {
    const { res, json } = await requestJSON(
      `/api/admin/oauth/clients/${encodeURIComponent(clientId)}/rotate-secret`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      },
    );
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Secret rotation failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const listBackups = async () => {
    const { res, json } = await requestJSON('/api/admin/backups');
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Backups fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const getLDAPSync = async () => {
    const { res, json } = await requestJSON('/api/admin/ldap-sync');
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'LDAP sync fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const runLDAPSync = async () => {
    const { res, json } = await requestJSON('/api/admin/ldap-sync/run', {
      method: 'POST',
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'LDAP sync failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const testLDAPSyncConnection = async (payload) => {
    const { res, json } = await requestJSON('/api/admin/ldap-sync/test-connection', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'LDAP connection test failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const getOAuthHistory = async (limit = 25) => {
    const { res, json } = await requestJSON(
      `/api/admin/oauth/history?limit=${Number(limit) || 25}`,
    );
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'History fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const getConfigPermissions = async () => {
    const { res, json } = await requestJSON('/api/admin/config/permissions');
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Permission catalog fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const listOAuthScopes = async () => {
    const { res, json } = await requestJSON('/api/admin/oauth/scopes');
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Scope catalog fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const getRBAC = async () => {
    const { res, json } = await requestJSON('/api/admin/rbac');
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'RBAC fetch failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const updateRBACBinding = async (payload) => {
    const { res, json } = await requestJSON('/api/admin/rbac/bindings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'RBAC save failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const createRBACRole = async (payload) => {
    const { res, json } = await requestJSON('/api/admin/rbac/roles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Role save failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const updateRBACRole = async (name, payload) => {
    const { res, json } = await requestJSON(`/api/admin/rbac/roles/${encodeURIComponent(name)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Role save failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const deleteRBACRole = async (name) => {
    const { res, json } = await requestJSON(`/api/admin/rbac/roles/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Role delete failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const createRBACPermission = async (payload) => {
    const { res, json } = await requestJSON('/api/admin/rbac/permissions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Permission save failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const updateRBACPermission = async (name, payload) => {
    const { res, json } = await requestJSON(`/api/admin/rbac/permissions/${encodeURIComponent(name)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Permission save failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const deleteRBACPermission = async (name) => {
    const { res, json } = await requestJSON(`/api/admin/rbac/permissions/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Permission delete failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const createBackup = async (payload) => {
    const { res, json } = await requestJSON('/api/admin/backups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({ fallback: 'Backup failed', status: res.status, serverError: json?.error });
    }
    return json;
  };

  const updateBackupSchedule = async (payload) => {
    const { res, json } = await requestJSON('/api/admin/backups/schedule', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({
        fallback: 'Schedule update failed',
        status: res.status,
        serverError: json?.error,
      });
    }
    return json;
  };

  const deleteBackup = async (name) => {
    const { res, json } = await requestJSON(`/api/admin/backups/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
    if (!res.ok || !json?.ok) {
      throw buildAPIError({ fallback: 'Delete failed', status: res.status, serverError: json?.error });
    }
    return json;
  };

  const restoreBackup = async (name) => {
    const { res, json } = await requestJSON(
      `/api/admin/backups/${encodeURIComponent(name)}/restore`,
      {
        method: 'POST',
      },
    );
    if (!res.ok || !json?.ok) {
      throw buildAPIError({ fallback: 'Restore failed', status: res.status, serverError: json?.error });
    }
    return json;
  };

  return {
    getConfig,
    getConfigHistory,
    getConfigPermissions,
    updateConfig,
    listOAuthClients,
    getOAuthHistory,
    listOAuthScopes,
    createOAuthClient,
    updateOAuthClient,
    deleteOAuthClient,
    rotateOAuthSecret,
    listBackups,
    getLDAPSync,
    testLDAPSyncConnection,
    runLDAPSync,
    getRBAC,
    updateRBACBinding,
    createRBACRole,
    updateRBACRole,
    deleteRBACRole,
    createRBACPermission,
    updateRBACPermission,
    deleteRBACPermission,
    createBackup,
    updateBackupSchedule,
    deleteBackup,
    restoreBackup,
  };
};
