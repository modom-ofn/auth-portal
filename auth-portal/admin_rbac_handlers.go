package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"auth-portal/configstore"

	"github.com/gorilla/mux"
)

type adminRBACResponse struct {
	OK          bool                   `json:"ok"`
	Roles       []RoleDefinition       `json:"roles"`
	Permissions []PermissionDefinition `json:"permissions"`
	Users       []UserRoleBinding      `json:"users"`
}

type adminRBACBindingRequest struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Reason   string   `json:"reason,omitempty"`
}

type adminRBACRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
	Reason      string   `json:"reason,omitempty"`
}

type adminRBACPermissionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

func loadAdminRBACResponse() (adminRBACResponse, error) {
	roles, err := listRoleDefinitions()
	if err != nil {
		return adminRBACResponse{}, err
	}
	permissions, err := listPermissionDefinitions()
	if err != nil {
		return adminRBACResponse{}, err
	}
	users, err := listUserRoleBindings()
	if err != nil {
		return adminRBACResponse{}, err
	}
	return adminRBACResponse{
		OK:          true,
		Roles:       roles,
		Permissions: permissions,
		Users:       users,
	}, nil
}

func adminRBACGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	resp, err := loadAdminRBACResponse()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "rbac lookup failed"})
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

func adminRBACBindingUpsertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	var req adminRBACBindingRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "username required"})
		return
	}

	actor := strings.TrimSpace(usernameFrom(r.Context()))
	if actor == "" {
		actor = "admin"
	}
	if err := replaceManualRolesByUsername(req.Username, req.Roles, actor); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "unknown role") || strings.Contains(strings.ToLower(err.Error()), "required") {
			status = http.StatusBadRequest
		}
		respondJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	details := strings.Join(normalizeAdminStringList(req.Roles), ", ")
	if details == "" {
		details = "manual roles cleared"
	}
	recordAdminAudit(r.Context(), configstore.SectionRBAC, actor, "Manual role binding updated", req.Username, details, req.Reason)

	resp, err := loadAdminRBACResponse()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "rbac lookup failed"})
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

func adminRBACRoleCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	var req adminRBACRoleRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request"})
		return
	}
	if err := upsertRoleDefinition("", RoleDefinition{
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "required") ||
			strings.Contains(strings.ToLower(err.Error()), "unknown") ||
			strings.Contains(strings.ToLower(err.Error()), "cannot") {
			status = http.StatusBadRequest
		}
		respondJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	recordAdminAudit(r.Context(), configstore.SectionRBAC, actorFromRequest(r), "Role created", req.Name, strings.Join(normalizeAdminStringList(req.Permissions), ", "), req.Reason)

	resp, err := loadAdminRBACResponse()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "rbac lookup failed"})
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

func adminRBACRoleUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	currentName := strings.TrimSpace(mux.Vars(r)["name"])
	var req adminRBACRoleRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request"})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = currentName
	}
	if err := upsertRoleDefinition(currentName, RoleDefinition{
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "required") ||
			strings.Contains(strings.ToLower(err.Error()), "unknown") ||
			strings.Contains(strings.ToLower(err.Error()), "cannot") {
			status = http.StatusBadRequest
		}
		respondJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	recordAdminAudit(r.Context(), configstore.SectionRBAC, actorFromRequest(r), "Role updated", req.Name, strings.Join(normalizeAdminStringList(req.Permissions), ", "), req.Reason)

	resp, err := loadAdminRBACResponse()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "rbac lookup failed"})
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

func adminRBACRoleDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	name := strings.TrimSpace(mux.Vars(r)["name"])
	if err := deleteRoleDefinition(name); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "required") ||
			strings.Contains(strings.ToLower(err.Error()), "unknown") ||
			strings.Contains(strings.ToLower(err.Error()), "cannot") {
			status = http.StatusBadRequest
		}
		respondJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	recordAdminAudit(r.Context(), configstore.SectionRBAC, actorFromRequest(r), "Role deleted", name, "", "")

	resp, err := loadAdminRBACResponse()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "rbac lookup failed"})
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

func adminRBACPermissionCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	var req adminRBACPermissionRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request"})
		return
	}
	if err := upsertPermissionDefinition("", PermissionDefinition{Name: req.Name, Description: req.Description}); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "required") ||
			strings.Contains(strings.ToLower(err.Error()), "unknown") ||
			strings.Contains(strings.ToLower(err.Error()), "cannot") {
			status = http.StatusBadRequest
		}
		respondJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	recordAdminAudit(r.Context(), configstore.SectionRBAC, actorFromRequest(r), "Permission created", req.Name, strings.TrimSpace(req.Description), req.Reason)

	resp, err := loadAdminRBACResponse()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "rbac lookup failed"})
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

func adminRBACPermissionUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	currentName := strings.TrimSpace(mux.Vars(r)["name"])
	var req adminRBACPermissionRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request"})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = currentName
	}
	if err := upsertPermissionDefinition(currentName, PermissionDefinition{Name: req.Name, Description: req.Description}); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "required") ||
			strings.Contains(strings.ToLower(err.Error()), "unknown") ||
			strings.Contains(strings.ToLower(err.Error()), "cannot") {
			status = http.StatusBadRequest
		}
		respondJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	recordAdminAudit(r.Context(), configstore.SectionRBAC, actorFromRequest(r), "Permission updated", req.Name, strings.TrimSpace(req.Description), req.Reason)

	resp, err := loadAdminRBACResponse()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "rbac lookup failed"})
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

func adminRBACPermissionDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	name := strings.TrimSpace(mux.Vars(r)["name"])
	if err := deletePermissionDefinition(name); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "required") ||
			strings.Contains(strings.ToLower(err.Error()), "unknown") ||
			strings.Contains(strings.ToLower(err.Error()), "cannot") {
			status = http.StatusBadRequest
		}
		respondJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	recordAdminAudit(r.Context(), configstore.SectionRBAC, actorFromRequest(r), "Permission deleted", name, "", "")

	resp, err := loadAdminRBACResponse()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "rbac lookup failed"})
		return
	}
	respondJSON(w, http.StatusOK, resp)
}
