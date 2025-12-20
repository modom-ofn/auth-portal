package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

type adminRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type adminRoleResponse struct {
	Role RoleDefinition `json:"role"`
}

func adminRolesCreateHandler(w http.ResponseWriter, r *http.Request) {
	var req adminRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	role, err := createCustomRole(req.Name, req.Description, req.Permissions, strings.TrimSpace(usernameFrom(r.Context())))
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrForbiddenPermission) || errors.Is(err, ErrReservedRole) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}

	respondJSON(w, http.StatusCreated, adminRoleResponse{Role: role})
}

type adminRolesListResponse struct {
	OK    bool       `json:"ok"`
	Roles []RoleInfo `json:"roles"`
}

func adminRolesListHandler(w http.ResponseWriter, r *http.Request) {
	roles, err := listRoles(r.Context())
	if err != nil {
		http.Error(w, "failed to load roles", http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, adminRolesListResponse{OK: true, Roles: roles})
}

func adminRoleUpdateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleName := strings.TrimSpace(vars["name"])
	if roleName == "" {
		http.Error(w, "role name required", http.StatusBadRequest)
		return
	}
	var req adminRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	role, userIDs, err := updateRole(roleName, req.Description, req.Permissions)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrRoleNotFound) {
			status = http.StatusNotFound
		}
		if errors.Is(err, ErrReservedRole) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"role":         role,
		"sessionReset": len(userIDs),
	})
}

type adminUserRoleRequest struct {
	Role   string `json:"role"`
	Action string `json:"action"`
}

func adminUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := strings.TrimSpace(vars["id"])
	if idStr == "" {
		http.Error(w, "user id required", http.StatusBadRequest)
		return
	}
	userID, err := strconv.Atoi(idStr)
	if err != nil || userID <= 0 {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	var req adminUserRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		http.Error(w, "role required", http.StatusBadRequest)
		return
	}

	user, err := userByID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}
	if !user.MediaAccess {
		http.Error(w, "cannot assign roles to unauthorized/guest user", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "add", "assign", "":
		if err := ensureUserRoleByID(ctx, userID, role, strings.TrimSpace(usernameFrom(ctx))); err != nil {
			if errors.Is(err, ErrRoleNotFound) {
				http.Error(w, "role not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to assign role", http.StatusInternalServerError)
			return
		}
	case "remove", "delete":
		if err := removeUserRoleByID(ctx, userID, role); err != nil {
			if errors.Is(err, ErrRoleNotFound) {
				http.Error(w, "role not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to remove role", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func adminRoleDeleteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := strings.TrimSpace(vars["name"])
	if name == "" {
		http.Error(w, "role name required", http.StatusBadRequest)
		return
	}
	userIDs, err := deleteRoleByName(name)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrRoleNotFound) {
			status = http.StatusNotFound
		}
		if errors.Is(err, ErrReservedRole) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"sessionReset": len(userIDs),
	})
}
