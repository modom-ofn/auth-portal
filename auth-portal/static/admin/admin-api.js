import { buildAPIError } from './admin-errors.js';

const requestJSON = async (url, options = {}) => {
  const res = await fetch(url, { credentials: 'same-origin', ...options });
  const json = await res.json();
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

  const deleteOAuthClient = async (clientId) => {
    const { res, json } = await requestJSON(
      `/api/admin/oauth/clients/${encodeURIComponent(clientId)}`,
      {
        method: 'DELETE',
      },
    );
    if (!res.ok || !json?.ok) {
      throw buildAPIError({ fallback: 'Delete failed', status: res.status, serverError: json?.error });
    }
    return json;
  };

  const rotateOAuthSecret = async (clientId) => {
    const { res, json } = await requestJSON(
      `/api/admin/oauth/clients/${encodeURIComponent(clientId)}/rotate-secret`,
      {
        method: 'POST',
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
    updateConfig,
    listOAuthClients,
    createOAuthClient,
    updateOAuthClient,
    deleteOAuthClient,
    rotateOAuthSecret,
    listBackups,
    createBackup,
    updateBackupSchedule,
    deleteBackup,
    restoreBackup,
  };
};
