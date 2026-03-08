import { toUserMessage } from './admin-errors.js';

export const createOAuthSectionController = ({
  api,
  panel,
  reloadBtn,
  emptyState,
  cardsRoot,
  form,
  idInput,
  nameInput,
  redirectsInput,
  scopesInput,
  cancelBtn,
  saveBtn,
  secretBanner,
  detailModal,
  detailCloseBtn,
  detailTitle,
  detailBody,
  detailEditBtn,
  detailRotateBtn,
  detailDeleteBtn,
  appTimeZone = 'UTC',
  showStatus,
  recordActivity,
}) => {
  const state = {
    clients: [],
    loading: false,
    detailOpen: false,
    selectedClientId: '',
  };

  const parseRedirectList = (value) =>
    (value || '')
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean);

  const parseScopes = (value) =>
    (value || '')
      .split(/[\s,]+/)
      .map((scope) => scope.trim())
      .filter(Boolean);

  const createDateFormatter = () => {
    const options = {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    };
    try {
      return new Intl.DateTimeFormat(undefined, { ...options, timeZone: appTimeZone || 'UTC' });
    } catch {
      return new Intl.DateTimeFormat(undefined, options);
    }
  };

  const dateFormatter = createDateFormatter();

  const formatDate = (value) => {
    if (!value) {
      return '-';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    try {
      return dateFormatter.format(date);
    } catch {
      return date.toLocaleString();
    }
  };

  const findClientById = (clientId) => state.clients.find((client) => client.clientId === clientId) || null;

  const resetForm = () => {
    if (!form) {
      return;
    }
    form.reset();
    if (idInput) {
      idInput.value = '';
    }
    if (saveBtn) {
      saveBtn.textContent = 'Save Client';
    }
    if (cancelBtn) {
      cancelBtn.hidden = true;
      cancelBtn.disabled = false;
    }
  };

  const prefillFormForClient = (client) => {
    if (!client || !form) {
      return;
    }
    if (idInput) {
      idInput.value = client.clientId || '';
    }
    if (nameInput) {
      nameInput.value = client.name || '';
      nameInput.focus();
    }
    if (redirectsInput) {
      redirectsInput.value = (client.redirectUris || []).join('\n');
    }
    if (scopesInput) {
      scopesInput.value = (client.scopes || []).join(' ');
    }
    if (saveBtn) {
      saveBtn.textContent = 'Update Client';
    }
    if (cancelBtn) {
      cancelBtn.hidden = false;
      cancelBtn.disabled = false;
    }
  };

  const clearSecretBanner = () => {
    if (!secretBanner) {
      return;
    }
    secretBanner.hidden = true;
    secretBanner.textContent = '';
    secretBanner.className = 'secret-banner';
  };

  const showSecretBanner = (message) => {
    if (!secretBanner) {
      return;
    }
    secretBanner.textContent = message;
    secretBanner.hidden = false;
    secretBanner.className = 'secret-banner show';
  };

  const setLoading = (isLoading) => {
    if (!emptyState) {
      return;
    }
    state.loading = isLoading;
    if (isLoading) {
      emptyState.hidden = false;
      emptyState.textContent = 'Loading...';
      if (cardsRoot) {
        cardsRoot.hidden = true;
      }
      return;
    }
    emptyState.textContent = 'No OAuth clients registered yet.';
  };

  const appendDetailRow = (root, label, value, isMono = false) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'oauth-client-meta';

    const strong = document.createElement('strong');
    strong.textContent = `${label}: `;
    wrapper.appendChild(strong);

    const span = document.createElement('span');
    span.textContent = value;
    if (isMono) {
      span.className = 'mono';
    }
    wrapper.appendChild(span);

    root.appendChild(wrapper);
  };

  const renderDetailBody = (client) => {
    if (!detailBody) {
      return;
    }
    detailBody.innerHTML = '';

    const container = document.createElement('div');
    container.className = 'oauth-detail-meta';

    appendDetailRow(container, 'Client ID', client.clientId || '-', true);
    appendDetailRow(container, 'Name', client.name || '-');
    appendDetailRow(container, 'Updated', formatDate(client.updatedAt));
    appendDetailRow(container, 'Created', formatDate(client.createdAt));

    const scopes = (client.scopes || []).join(' ') || '-';
    appendDetailRow(container, 'Scopes', scopes, true);

    const redirectLabel = document.createElement('div');
    redirectLabel.className = 'oauth-client-meta';
    const redirectTitle = document.createElement('strong');
    redirectTitle.textContent = 'Redirect URIs:';
    redirectLabel.appendChild(redirectTitle);

    const redirectList = document.createElement('ul');
    redirectList.className = 'history-list';
    redirectList.style.marginTop = '.5rem';
    redirectList.style.maxHeight = '180px';

    if ((client.redirectUris || []).length) {
      client.redirectUris.forEach((uri) => {
        const li = document.createElement('li');
        const code = document.createElement('code');
        code.textContent = uri;
        li.appendChild(code);
        redirectList.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.textContent = '-';
      redirectList.appendChild(li);
    }

    redirectLabel.appendChild(redirectList);
    container.appendChild(redirectLabel);

    detailBody.appendChild(container);
  };

  const closeDetailModal = () => {
    if (!detailModal || !state.detailOpen) {
      return;
    }
    detailModal.hidden = true;
    state.detailOpen = false;
    document.body.classList.remove('modal-open');
    document.removeEventListener('keydown', onKeydown);
  };

  const openDetailModal = (client) => {
    if (!detailModal || !client) {
      return;
    }
    state.selectedClientId = client.clientId || '';

    if (detailTitle) {
      detailTitle.textContent = client.name ? `${client.name} Details` : 'OAuth Client Details';
    }
    renderDetailBody(client);

    detailModal.hidden = false;
    state.detailOpen = true;
    document.body.classList.add('modal-open');
    document.addEventListener('keydown', onKeydown);
    if (detailCloseBtn) {
      detailCloseBtn.focus();
    }
  };

  const withClientAction = async (clientId, actionBtn, actionName, action) => {
    if (!clientId) {
      return;
    }
    if (actionBtn) {
      actionBtn.disabled = true;
    }
    try {
      await action();
    } catch (err) {
      showStatus(toUserMessage(err, `${actionName} failed`), 'error');
    } finally {
      if (actionBtn) {
        actionBtn.disabled = false;
      }
    }
  };

  const rotateSecret = async (client, actionBtn) => {
    if (!client?.clientId) {
      return;
    }
    await withClientAction(client.clientId, actionBtn, 'Secret rotation', async () => {
      showStatus('Rotating client secret.', 'info');
      const json = await api.rotateOAuthSecret(client.clientId);
      const displayName = client.name || client.clientId;
      showSecretBanner(`New secret for ${displayName}: ${json.clientSecret}`);
      recordActivity('oauth', 'Client secret rotated', displayName);
      showStatus('Client secret rotated.', 'success');
      await loadClients();
    });
  };

  const deleteClient = async (client, actionBtn) => {
    if (!client?.clientId) {
      return;
    }
    const confirmDelete = globalThis.confirm(
      `Delete OAuth client "${client.name || client.clientId}"? This action cannot be undone.`,
    );
    if (!confirmDelete) {
      return;
    }
    await withClientAction(client.clientId, actionBtn, 'Delete', async () => {
      showStatus('Deleting client.', 'info');
      await api.deleteOAuthClient(client.clientId);
      recordActivity('oauth', 'Client deleted', client.name || client.clientId);
      showStatus('Client deleted.', 'success');
      closeDetailModal();
      await loadClients();
      if ((idInput?.value || '') === client.clientId) {
        resetForm();
      }
    });
  };

  const renderClients = () => {
    if (!cardsRoot || !emptyState) {
      return;
    }
    cardsRoot.innerHTML = '';

    if (!state.clients.length) {
      emptyState.hidden = false;
      cardsRoot.hidden = true;
      return;
    }

    emptyState.hidden = true;
    cardsRoot.hidden = false;

    state.clients.forEach((client) => {
      const card = document.createElement('article');
      card.className = 'oauth-client-card';
      card.tabIndex = 0;

      const title = document.createElement('h4');
      title.textContent = client.name || 'Unnamed Client';
      card.appendChild(title);

      const clientIdMeta = document.createElement('div');
      clientIdMeta.className = 'oauth-client-meta mono';
      clientIdMeta.textContent = client.clientId || '-';
      card.appendChild(clientIdMeta);

      const scopesMeta = document.createElement('div');
      scopesMeta.className = 'oauth-client-meta';
      scopesMeta.textContent = `Scopes: ${(client.scopes || []).join(' ') || '-'}`;
      card.appendChild(scopesMeta);

      const redirectsMeta = document.createElement('div');
      redirectsMeta.className = 'oauth-client-meta';
      redirectsMeta.textContent = `Redirects: ${(client.redirectUris || []).length}`;
      card.appendChild(redirectsMeta);

      const updatedMeta = document.createElement('div');
      updatedMeta.className = 'oauth-client-meta';
      updatedMeta.textContent = `Updated: ${formatDate(client.updatedAt)}`;
      card.appendChild(updatedMeta);

      const actions = document.createElement('div');
      actions.className = 'oauth-client-actions';

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'primary-btn';
      editBtn.textContent = 'Edit';
      editBtn.addEventListener('click', (event) => {
        event.stopPropagation();
        prefillFormForClient(client);
      });
      actions.appendChild(editBtn);

      const rotateBtn = document.createElement('button');
      rotateBtn.type = 'button';
      rotateBtn.className = 'success-btn';
      rotateBtn.textContent = 'Rotate Secret';
      rotateBtn.addEventListener('click', async (event) => {
        event.stopPropagation();
        await rotateSecret(client, rotateBtn);
      });
      actions.appendChild(rotateBtn);

      const deleteBtn = document.createElement('button');
      deleteBtn.type = 'button';
      deleteBtn.className = 'danger-btn';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', async (event) => {
        event.stopPropagation();
        await deleteClient(client, deleteBtn);
      });
      actions.appendChild(deleteBtn);

      card.appendChild(actions);

      card.addEventListener('click', () => openDetailModal(client));
      card.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          openDetailModal(client);
        }
      });

      cardsRoot.appendChild(card);
    });
  };

  const loadClients = async (options = {}) => {
    if (!panel || state.loading) {
      return;
    }
    setLoading(true);
    try {
      const json = await api.listOAuthClients();
      state.clients = Array.isArray(json.clients) ? json.clients : [];
      renderClients();

      if (state.detailOpen && state.selectedClientId) {
        const selected = findClientById(state.selectedClientId);
        if (selected) {
          openDetailModal(selected);
        } else {
          closeDetailModal();
        }
      }

      if (options.announce) {
        showStatus('OAuth clients refreshed.', 'success');
      }
    } catch (err) {
      renderClients();
      showStatus(toUserMessage(err, 'Client fetch failed'), 'error');
    } finally {
      setLoading(false);
    }
  };

  const onKeydown = (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeDetailModal();
    }
  };

  const bind = () => {
    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => {
        resetForm();
        clearSecretBanner();
      });
    }

    if (form) {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (state.loading) {
          return;
        }

        const payload = {
          name: nameInput?.value?.trim() || '',
          redirectUris: parseRedirectList(redirectsInput?.value || ''),
          scopes: parseScopes(scopesInput?.value || ''),
        };
        const clientId = idInput?.value?.trim() || '';

        if (saveBtn) {
          saveBtn.disabled = true;
        }
        if (cancelBtn) {
          cancelBtn.disabled = true;
        }

        showStatus(clientId ? 'Updating client.' : 'Creating client.', 'info');

        try {
          const json = clientId
            ? await api.updateOAuthClient(clientId, payload)
            : await api.createOAuthClient(payload);

          showStatus(clientId ? 'Client updated.' : 'Client created.', 'success');
          const activityName = json.client?.name || payload.name || clientId || 'client';
          recordActivity('oauth', clientId ? 'Client updated' : 'Client created', activityName);

          if (json.clientSecret) {
            showSecretBanner(`Client secret for ${activityName}: ${json.clientSecret}`);
          }

          resetForm();
          await loadClients();
        } catch (err) {
          showStatus(toUserMessage(err, 'Save failed'), 'error');
        } finally {
          if (saveBtn) {
            saveBtn.disabled = false;
          }
          if (cancelBtn) {
            cancelBtn.disabled = false;
          }
        }
      });
    }

    if (reloadBtn) {
      reloadBtn.addEventListener('click', async () => {
        await loadClients({ announce: true });
      });
    }

    if (detailCloseBtn) {
      detailCloseBtn.addEventListener('click', () => {
        closeDetailModal();
      });
    }

    if (detailModal) {
      detailModal.addEventListener('click', (event) => {
        const target = event.target;
        const isClose = target?.dataset?.oauthDetailClose !== undefined;
        if (target === detailModal || isClose) {
          closeDetailModal();
        }
      });
    }

    if (detailEditBtn) {
      detailEditBtn.addEventListener('click', () => {
        const client = findClientById(state.selectedClientId);
        if (!client) {
          return;
        }
        prefillFormForClient(client);
        closeDetailModal();
      });
    }

    if (detailRotateBtn) {
      detailRotateBtn.addEventListener('click', async () => {
        const client = findClientById(state.selectedClientId);
        if (!client) {
          return;
        }
        await rotateSecret(client, detailRotateBtn);
      });
    }

    if (detailDeleteBtn) {
      detailDeleteBtn.addEventListener('click', async () => {
        const client = findClientById(state.selectedClientId);
        if (!client) {
          return;
        }
        await deleteClient(client, detailDeleteBtn);
      });
    }
  };

  return {
    bind,
    loadClients,
    clearSecretBanner,
  };
};
