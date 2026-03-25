import { toUserMessage } from './admin-errors.js';

export const createAccessControlSectionController = ({
  api,
  panel,
  refreshBtn,
  roleForm,
  roleNameInput,
  roleDescriptionInput,
  permissionCheckboxes,
  roleReasonInput,
  roleResetBtn,
  roleSaveBtn,
  roleRows,
  permissionForm,
  permissionNameInput,
  permissionDescriptionInput,
  permissionReasonInput,
  permissionResetBtn,
  permissionSaveBtn,
  permissionRows,
  userRows,
  form,
  usernameInput,
  roleCheckboxes,
  reasonInput,
  resetBtn,
  saveBtn,
  showStatus,
  recordActivity,
}) => {
  const state = {
    loading: false,
    savingBinding: false,
    savingRole: false,
    loaded: false,
    roles: [],
    permissions: [],
    users: [],
    selectedUsername: '',
    selectedRoleName: '',
    selectedPermissionName: '',
  };

  const isBusy = () => state.loading || state.savingBinding || state.savingRole;

  const updateControls = () => {
    const busy = isBusy();
    [refreshBtn, saveBtn, resetBtn, roleSaveBtn, roleResetBtn, permissionSaveBtn, permissionResetBtn]
      .filter(Boolean)
      .forEach((button) => {
      button.disabled = busy;
    });
    [usernameInput, reasonInput, roleNameInput, roleDescriptionInput, roleReasonInput, permissionNameInput, permissionDescriptionInput, permissionReasonInput]
      .filter(Boolean)
      .forEach((input) => {
        input.disabled = busy;
      });
    roleCheckboxes?.querySelectorAll('input').forEach((input) => {
      input.disabled = busy;
    });
    permissionCheckboxes?.querySelectorAll('input').forEach((input) => {
      input.disabled = busy;
    });
  };

  const renderBindingRoleCheckboxes = () => {
    if (!roleCheckboxes) {
      return;
    }
    roleCheckboxes.innerHTML = '';
    state.roles.forEach((role) => {
      const label = document.createElement('label');
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.value = role.name;
      label.append(input, ` ${role.name}`);
      roleCheckboxes.appendChild(label);
    });
  };

  const renderPermissionCheckboxes = () => {
    if (!permissionCheckboxes) {
      return;
    }
    permissionCheckboxes.innerHTML = '';
    state.permissions.forEach((permission) => {
      const label = document.createElement('label');
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.value = permission.name;
      label.append(input, ` ${permission.name}`);
      permissionCheckboxes.appendChild(label);
    });
  };

  const updateBindingFormState = () => {
    if (saveBtn) {
      saveBtn.textContent = state.selectedUsername ? 'Update Role Binding' : 'Save Role Binding';
    }
    if (usernameInput) {
      usernameInput.placeholder = state.selectedUsername || 'alice';
    }
  };

  const updateRoleFormState = () => {
    const selectedRole = state.roles.find((role) => role.name === state.selectedRoleName);
    const systemRole = Boolean(selectedRole?.system);
    if (roleSaveBtn) {
      roleSaveBtn.textContent = state.selectedRoleName ? 'Update Role' : 'Create Role';
      roleSaveBtn.disabled = isBusy() || systemRole;
    }
    if (roleResetBtn) {
      roleResetBtn.textContent = state.selectedRoleName ? 'New Role' : 'Reset';
    }
    if (roleNameInput) {
      roleNameInput.placeholder = state.selectedRoleName || 'music-reader';
      roleNameInput.readOnly = systemRole;
    }
    if (roleDescriptionInput) {
      roleDescriptionInput.readOnly = systemRole;
    }
    permissionCheckboxes?.querySelectorAll('input').forEach((input) => {
      input.disabled = isBusy() || systemRole;
    });
  };

  const updatePermissionFormState = () => {
    const selectedPermission = state.permissions.find((permission) => permission.name === state.selectedPermissionName);
    const systemPermission = Boolean(selectedPermission?.system);
    if (permissionSaveBtn) {
      permissionSaveBtn.textContent = state.selectedPermissionName ? 'Update Permission' : 'Create Permission';
      permissionSaveBtn.disabled = isBusy() || systemPermission;
    }
    if (permissionResetBtn) {
      permissionResetBtn.textContent = state.selectedPermissionName ? 'New Permission' : 'Reset';
    }
    if (permissionNameInput) {
      permissionNameInput.placeholder = state.selectedPermissionName || 'music.read';
      permissionNameInput.readOnly = systemPermission;
    }
    if (permissionDescriptionInput) {
      permissionDescriptionInput.readOnly = systemPermission;
    }
  };

  const resetBindingForm = () => {
    state.selectedUsername = '';
    form?.reset();
    roleCheckboxes?.querySelectorAll('input').forEach((input) => {
      input.checked = false;
    });
    updateBindingFormState();
  };

  const resetRoleForm = () => {
    state.selectedRoleName = '';
    roleForm?.reset();
    permissionCheckboxes?.querySelectorAll('input').forEach((input) => {
      input.checked = false;
    });
    updateRoleFormState();
  };

  const resetPermissionForm = () => {
    state.selectedPermissionName = '';
    permissionForm?.reset();
    updatePermissionFormState();
  };

  const selectUser = (username, manualRoles = []) => {
    state.selectedUsername = username || '';
    if (usernameInput) {
      usernameInput.value = username || '';
    }
    if (reasonInput) {
      reasonInput.value = '';
    }
    const selected = new Set(manualRoles || []);
    roleCheckboxes?.querySelectorAll('input').forEach((input) => {
      input.checked = selected.has(input.value);
    });
    updateBindingFormState();
  };

  const selectRole = (role) => {
    state.selectedRoleName = role?.name || '';
    if (roleNameInput) {
      roleNameInput.value = role?.name || '';
    }
    if (roleDescriptionInput) {
      roleDescriptionInput.value = role?.description || '';
    }
    if (roleReasonInput) {
      roleReasonInput.value = '';
    }
    const selected = new Set(role?.permissions || []);
    permissionCheckboxes?.querySelectorAll('input').forEach((input) => {
      input.checked = selected.has(input.value);
    });
    updateRoleFormState();
  };

  const selectPermission = (permission) => {
    state.selectedPermissionName = permission?.name || '';
    if (permissionNameInput) {
      permissionNameInput.value = permission?.name || '';
    }
    if (permissionDescriptionInput) {
      permissionDescriptionInput.value = permission?.description || '';
    }
    if (permissionReasonInput) {
      permissionReasonInput.value = '';
    }
    updatePermissionFormState();
  };

  const renderRoles = () => {
    if (!roleRows) {
      return;
    }
    roleRows.innerHTML = '';
    if (!state.roles.length) {
      roleRows.innerHTML = '<tr><td colspan="4" class="muted">No roles found.</td></tr>';
      return;
    }
    state.roles.forEach((role) => {
      const tr = document.createElement('tr');
      const systemBadge = role.system ? '<span class="rbac-system-chip">system</span>' : '';
      tr.innerHTML = `
        <td><strong>${escapeHTML(role.name)}</strong> ${systemBadge}</td>
        <td>${escapeHTML(role.description || '-')}</td>
        <td>${escapeHTML((role.permissions || []).join(', ') || '-')}</td>
        <td class="actions-cell">
          <button type="button" class="ghost-btn rbac-role-edit">Edit</button>
          <button type="button" class="danger-btn rbac-role-delete"${role.system ? ' disabled' : ''}>Delete</button>
        </td>
      `;
      tr.querySelector('.rbac-role-edit')?.addEventListener('click', () => {
        selectRole(role);
      });
      tr.querySelector('.rbac-role-delete')?.addEventListener('click', async () => {
        await deleteRole(role);
      });
      roleRows.appendChild(tr);
    });
  };

  const renderUsers = () => {
    if (!userRows) {
      return;
    }
    userRows.innerHTML = '';
    if (!state.users.length) {
      userRows.innerHTML = '<tr><td colspan="5" class="muted">No user bindings found.</td></tr>';
      return;
    }
    state.users.forEach((user) => {
      const tr = document.createElement('tr');
      const hasManualRoles = Array.isArray(user.manualRoles) && user.manualRoles.length > 0;
      tr.innerHTML = `
        <td><button type="button" class="ghost-btn rbac-user-pick">${escapeHTML(user.username)}</button></td>
        <td>${escapeHTML((user.manualRoles || []).join(', ') || '-')}</td>
        <td>${escapeHTML((user.effectiveRoles || []).join(', ') || '-')}</td>
        <td>${escapeHTML((user.permissions || []).join(', ') || '-')}</td>
        <td class="actions-cell">
          <button type="button" class="ghost-btn rbac-user-edit">Edit</button>
          <button type="button" class="danger-btn rbac-user-clear"${hasManualRoles ? '' : ' disabled'}>Clear Manual Roles</button>
        </td>
      `;
      const edit = () => selectUser(user.username, user.manualRoles || []);
      tr.querySelector('.rbac-user-pick')?.addEventListener('click', edit);
      tr.querySelector('.rbac-user-edit')?.addEventListener('click', edit);
      tr.querySelector('.rbac-user-clear')?.addEventListener('click', async () => {
        await clearManualRoles(user.username);
      });
      userRows.appendChild(tr);
    });
  };

  const renderPermissions = () => {
    if (!permissionRows) {
      return;
    }
    permissionRows.innerHTML = '';
    if (!state.permissions.length) {
      permissionRows.innerHTML = '<tr><td colspan="3" class="muted">No permissions found.</td></tr>';
      return;
    }
    state.permissions.forEach((permission) => {
      const tr = document.createElement('tr');
      const systemBadge = permission.system ? '<span class="rbac-system-chip">system</span>' : '';
      tr.innerHTML = `
        <td><strong>${escapeHTML(permission.name)}</strong> ${systemBadge}</td>
        <td>${escapeHTML(permission.description || '-')}</td>
        <td class="actions-cell">
          <button type="button" class="ghost-btn rbac-permission-edit">Edit</button>
          <button type="button" class="danger-btn rbac-permission-delete"${permission.system ? ' disabled' : ''}>Delete</button>
        </td>
      `;
      tr.querySelector('.rbac-permission-edit')?.addEventListener('click', () => {
        selectPermission(permission);
      });
      tr.querySelector('.rbac-permission-delete')?.addEventListener('click', async () => {
        await deletePermission(permission);
      });
      permissionRows.appendChild(tr);
    });
  };

  const render = () => {
    renderBindingRoleCheckboxes();
    renderPermissionCheckboxes();
    renderRoles();
    renderPermissions();
    renderUsers();
    updateBindingFormState();
    updateRoleFormState();
    updatePermissionFormState();
    updateControls();
  };

  const applyResponse = (json) => {
    state.roles = Array.isArray(json.roles) ? json.roles : state.roles;
    state.permissions = Array.isArray(json.permissions) ? json.permissions : state.permissions;
    state.users = Array.isArray(json.users) ? json.users : state.users;
  };

  const readManualRoles = () => Array.from(roleCheckboxes?.querySelectorAll('input:checked') || [])
    .map((input) => input.value)
    .filter(Boolean);

  const readRolePermissions = () => Array.from(permissionCheckboxes?.querySelectorAll('input:checked') || [])
    .map((input) => input.value)
    .filter(Boolean);

  const load = async (options = {}) => {
    if (!panel || state.loading) {
      return;
    }
    state.loading = true;
    updateControls();
    try {
      const json = await api.getRBAC();
      applyResponse(json);
      state.loaded = true;
      render();
      if (options.announce) {
        showStatus('Access control refreshed.', 'success');
      }
    } catch (err) {
      showStatus(toUserMessage(err, 'RBAC load failed'), 'error');
    } finally {
      state.loading = false;
      updateControls();
    }
  };

  const saveBinding = async (event) => {
    event?.preventDefault();
    if (state.savingBinding) {
      return;
    }
    const username = usernameInput?.value?.trim() || '';
    if (!username) {
      showStatus('Username is required.', 'error');
      return;
    }
    state.savingBinding = true;
    updateControls();
    try {
      const json = await api.updateRBACBinding({
        username,
        roles: readManualRoles(),
        reason: reasonInput?.value?.trim() || '',
      });
      applyResponse(json);
      state.selectedUsername = username;
      render();
      recordActivity('access-control', 'Manual role binding saved', username);
      showStatus('Manual role binding saved.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'RBAC save failed'), 'error');
    } finally {
      state.savingBinding = false;
      updateControls();
    }
  };

  const clearManualRoles = async (username) => {
    if (state.savingBinding || !username) {
      return;
    }
    state.savingBinding = true;
    updateControls();
    try {
      const json = await api.updateRBACBinding({
        username,
        roles: [],
        reason: reasonInput?.value?.trim() || 'Cleared manual roles',
      });
      applyResponse(json);
      if ((state.selectedUsername || '').toLowerCase() === username.toLowerCase()) {
        resetBindingForm();
      }
      render();
      recordActivity('access-control', 'Manual role binding removed', username);
      showStatus('Manual role binding removed.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'RBAC save failed'), 'error');
    } finally {
      state.savingBinding = false;
      updateControls();
    }
  };

  const saveRole = async (event) => {
    event?.preventDefault();
    if (state.savingRole) {
      return;
    }
    const name = roleNameInput?.value?.trim() || '';
    if (!name) {
      showStatus('Role name is required.', 'error');
      return;
    }
    const payload = {
      name,
      description: roleDescriptionInput?.value?.trim() || '',
      permissions: readRolePermissions(),
      reason: roleReasonInput?.value?.trim() || '',
    };
    const editing = Boolean(state.selectedRoleName);
    state.savingRole = true;
    updateControls();
    try {
      const json = editing
        ? await api.updateRBACRole(state.selectedRoleName, payload)
        : await api.createRBACRole(payload);
      applyResponse(json);
      state.selectedRoleName = name;
      render();
      recordActivity('access-control', editing ? 'Role updated' : 'Role created', name);
      showStatus(editing ? 'Role updated.' : 'Role created.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'RBAC save failed'), 'error');
    } finally {
      state.savingRole = false;
      updateControls();
    }
  };

  const deleteRole = async (role) => {
    if (state.savingRole || !role?.name || role.system) {
      return;
    }
    state.savingRole = true;
    updateControls();
    try {
      const json = await api.deleteRBACRole(role.name);
      applyResponse(json);
      if ((state.selectedRoleName || '').toLowerCase() === role.name.toLowerCase()) {
        resetRoleForm();
      }
      render();
      recordActivity('access-control', 'Role deleted', role.name);
      showStatus('Role deleted.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'RBAC save failed'), 'error');
    } finally {
      state.savingRole = false;
      updateControls();
    }
  };

  const savePermission = async (event) => {
    event?.preventDefault();
    if (state.savingRole) {
      return;
    }
    const name = permissionNameInput?.value?.trim() || '';
    if (!name) {
      showStatus('Permission name is required.', 'error');
      return;
    }
    const payload = {
      name,
      description: permissionDescriptionInput?.value?.trim() || '',
      reason: permissionReasonInput?.value?.trim() || '',
    };
    const editing = Boolean(state.selectedPermissionName);
    state.savingRole = true;
    updateControls();
    try {
      const json = editing
        ? await api.updateRBACPermission(state.selectedPermissionName, payload)
        : await api.createRBACPermission(payload);
      applyResponse(json);
      state.selectedPermissionName = name;
      render();
      recordActivity('access-control', editing ? 'Permission updated' : 'Permission created', name);
      showStatus(editing ? 'Permission updated.' : 'Permission created.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'RBAC save failed'), 'error');
    } finally {
      state.savingRole = false;
      updateControls();
    }
  };

  const deletePermission = async (permission) => {
    if (state.savingRole || !permission?.name || permission.system) {
      return;
    }
    state.savingRole = true;
    updateControls();
    try {
      const json = await api.deleteRBACPermission(permission.name);
      applyResponse(json);
      if ((state.selectedPermissionName || '').toLowerCase() === permission.name.toLowerCase()) {
        resetPermissionForm();
      }
      render();
      recordActivity('access-control', 'Permission deleted', permission.name);
      showStatus('Permission deleted.', 'success');
    } catch (err) {
      showStatus(toUserMessage(err, 'RBAC save failed'), 'error');
    } finally {
      state.savingRole = false;
      updateControls();
    }
  };

  const bind = () => {
    refreshBtn?.addEventListener('click', async () => {
      await load({ announce: true });
    });
    form?.addEventListener('submit', saveBinding);
    resetBtn?.addEventListener('click', () => {
      resetBindingForm();
    });
    roleForm?.addEventListener('submit', saveRole);
    roleResetBtn?.addEventListener('click', () => {
      resetRoleForm();
    });
    permissionForm?.addEventListener('submit', savePermission);
    permissionResetBtn?.addEventListener('click', () => {
      resetPermissionForm();
    });
  };

  return {
    bind,
    load,
    render,
    isLoaded: () => state.loaded,
  };
};

const escapeHTML = (value) => String(value ?? '')
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#39;');
