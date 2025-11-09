package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type mfaStartResponse struct {
	OK                bool   `json:"ok"`
	Secret            string `json:"secret"`
	Otpauth           string `json:"otpauth"`
	Issuer            string `json:"issuer"`
	Account           string `json:"account"`
	Digits            int    `json:"digits"`
	Period            int    `json:"period"`
	Drift             int    `json:"drift"`
	Enforced          bool   `json:"enforced"`
	PreviouslyEnabled bool   `json:"previouslyEnabled"`
}

type mfaVerifyRequest struct {
	Code string `json:"code"`
}

type mfaVerifyResponse struct {
	OK            bool     `json:"ok"`
	RecoveryCodes []string `json:"recoveryCodes"`
}

type mfaChallengeVerifyRequest struct {
	Code string `json:"code"`
}

type mfaChallengeVerifyResponse struct {
	OK                     bool   `json:"ok"`
	Redirect               string `json:"redirect"`
	RecoveryUsed           bool   `json:"recoveryUsed"`
	RemainingRecoveryCodes int    `json:"remainingRecoveryCodes"`
}

func mfaEnrollmentStartHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	if !mfaEnrollmentEnabled {
		respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "MFA enrollment disabled"})
		return
	}

	uuid := uuidFrom(r.Context())
	if uuid == "" {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session required"})
		return
	}

	user, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "user not found"})
			return
		}
		log.Printf("mfa enroll: user lookup failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "lookup failed"})
		return
	}

	secret, err := generateTOTPSecret()
	if err != nil {
		log.Printf("mfa enroll: secret generation failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "secret generation failed"})
		return
	}

	sealed, err := SealToken(secret)
	if err != nil {
		log.Printf("mfa enroll: sealing secret failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "secret storage failed"})
		return
	}

	digits, period, drift := defaultMFAMetadata()

	previouslyEnabled := false
	if rec, err := getMFARecord(user.ID); err == nil {
		previouslyEnabled = rec.IsVerified
	} else if !errors.Is(err, sql.ErrNoRows) {
		log.Printf("mfa enroll: load existing record failed: %v", err)
	}

	if err := beginMFAEnrollment(user.ID, sealed, "totp-sha1", digits, period, drift); err != nil {
		log.Printf("mfa enroll: begin failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "enrollment setup failed"})
		return
	}

	account := strings.TrimSpace(usernameFrom(r.Context()))
	if account == "" && user.Email.Valid {
		account = strings.TrimSpace(user.Email.String)
	}
	if account == "" {
		account = uuid
	}

	label := url.PathEscape(fmt.Sprintf("%s:%s", mfaIssuer, account))
	issuerParam := url.QueryEscape(mfaIssuer)
	otpauth := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&period=%d&digits=%d", label, secret, issuerParam, period, digits)

	respondJSON(w, http.StatusOK, mfaStartResponse{
		OK:                true,
		Secret:            secret,
		Otpauth:           otpauth,
		Issuer:            mfaIssuer,
		Account:           account,
		Digits:            digits,
		Period:            period,
		Drift:             drift,
		Enforced:          mfaEnforceForAllUsers,
		PreviouslyEnabled: previouslyEnabled,
	})
}

func mfaEnrollmentVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	uuid := uuidFrom(r.Context())
	if uuid == "" {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session required"})
		return
	}

	var req mfaVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid payload"})
		return
	}
	code := normalizeMFACode(req.Code)
	if code == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "code required"})
		return
	}

	user, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "user not found"})
			return
		}
		log.Printf("mfa verify: user lookup failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "lookup failed"})
		return
	}

	rec, err := getMFARecord(user.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "enrollment not started"})
			return
		}
		log.Printf("mfa verify: load record failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "lookup failed"})
		return
	}
	if !rec.SecretEnc.Valid || strings.TrimSpace(rec.SecretEnc.String) == "" {
		respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "secret unavailable"})
		return
	}

	secret, err := OpenToken(rec.SecretEnc.String)
	if err != nil {
		log.Printf("mfa verify: open secret failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "secret invalid"})
		return
	}

	digits := rec.Digits
	if digits <= 0 {
		digits = defaultMFADigits
	}
	period := rec.PeriodSeconds
	if period <= 0 {
		period = defaultMFAPeriodSeconds
	}
	skew := rec.DriftSteps
	if skew < 0 {
		skew = 0
	}

	if !validateTOTP(code, secret, time.Now(), period, skew, digits) {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid code"})
		return
	}

	if err := markMFASecretVerified(user.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "enrollment missing"})
			return
		}
		log.Printf("mfa verify: mark verified failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "verification save failed"})
		return
	}

	recoveryCodes, err := generateDefaultRecoveryCodes()
	if err != nil {
		log.Printf("mfa verify: recovery code generation failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "recovery generation failed"})
		return
	}

	hashed := make([]string, 0, len(recoveryCodes))
	for _, rc := range recoveryCodes {
		hashed = append(hashed, hashRecoveryCode(rc))
	}
	if err := replaceMFARecoveryCodes(user.ID, hashed); err != nil {
		log.Printf("mfa verify: storing recovery codes failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "recovery persistence failed"})
		return
	}

	username := strings.TrimSpace(usernameFrom(r.Context()))
	if username == "" {
		username = strings.TrimSpace(user.Username)
	}
	if username == "" {
		username = uuid
	}
	if err := setSessionCookie(w, uuid, username); err != nil {
		log.Printf("mfa verify: set session failed for %s (%s): %v", username, uuid, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "session setup failed"})
		return
	}

	respondJSON(w, http.StatusOK, mfaVerifyResponse{OK: true, RecoveryCodes: recoveryCodes})
}

func mfaChallengeVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	claims, err := pendingClaimsFromRequest(r)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "challenge expired"})
		return
	}

	var req mfaChallengeVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid payload"})
		return
	}

	rawCode := strings.TrimSpace(req.Code)
	if rawCode == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "code required"})
		return
	}

	user, err := getUserByUUIDPreferred(claims.UUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "user not found"})
			return
		}
		log.Printf("mfa challenge: user lookup failed for %s (%s): %v", claims.Username, claims.UUID, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "lookup failed"})
		return
	}

	rec, err := getMFARecord(user.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "mfa not enrolled"})
			return
		}
		log.Printf("mfa challenge: load record failed for %s (%s): %v", claims.Username, claims.UUID, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "lookup failed"})
		return
	}
	if !rec.IsVerified {
		respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "mfa enrollment incomplete"})
		return
	}

	digits := rec.Digits
	if digits <= 0 {
		digits = defaultMFADigits
	}
	period := rec.PeriodSeconds
	if period <= 0 {
		period = defaultMFAPeriodSeconds
	}
	skew := rec.DriftSteps
	if skew < 0 {
		skew = 0
	}

	var secret string
	if rec.SecretEnc.Valid {
		secret, err = OpenToken(rec.SecretEnc.String)
		if err != nil {
			log.Printf("mfa challenge: open secret failed for %s (%s): %v", claims.Username, claims.UUID, err)
			respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "secret invalid"})
			return
		}
	}

	normalized := normalizeMFACode(rawCode)
	validated := false
	if secret != "" && normalized != "" {
		if validateTOTP(normalized, secret, time.Now(), period, skew, digits) {
			validated = true
		}
	}

	recoveryUsed := false
	if !validated {
		hashed := hashRecoveryCode(rawCode)
		consumed, err := consumeMFARecoveryCode(user.ID, hashed)
		if err != nil {
			log.Printf("mfa challenge: consume recovery failed for %s (%s): %v", claims.Username, claims.UUID, err)
			respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "recovery validation failed"})
			return
		}
		if consumed {
			validated = true
			recoveryUsed = true
		}
	}

	if !validated {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid or expired code"})
		return
	}

	if err := touchMFALastUsed(user.ID); err != nil {
		log.Printf("mfa challenge: touch last used failed for %s (%s): %v", claims.Username, claims.UUID, err)
	}

	if err := setSessionCookie(w, claims.UUID, claims.Username); err != nil {
		log.Printf("mfa challenge: set session failed for %s (%s): %v", claims.Username, claims.UUID, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "session setup failed"})
		return
	}

	remaining := 0
	if count, err := countUnusedMFARecoveryCodes(user.ID); err == nil {
		remaining = count
	} else {
		log.Printf("mfa challenge: count recovery codes failed for %s (%s): %v", claims.Username, claims.UUID, err)
	}

	respondJSON(w, http.StatusOK, mfaChallengeVerifyResponse{
		OK:                     true,
		Redirect:               "/home",
		RecoveryUsed:           recoveryUsed,
		RemainingRecoveryCodes: remaining,
	})
}

func normalizeMFACode(code string) string {
	cleaned := strings.TrimSpace(code)
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "_", "")
	return cleaned
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if payload != nil {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(payload)
	}
}
func mfaEnrollmentStatusHandler(w http.ResponseWriter, r *http.Request) {
	uuid := uuidFrom(r.Context())
	if uuid == "" {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session required"})
		return
	}

	user, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusUnauthorized
		}
		log.Printf("mfa status: user lookup failed for %s: %v", uuid, err)
		respondJSON(w, status, map[string]any{"ok": false, "error": "user lookup failed"})
		return
	}

	var (
		enabled       bool
		pending       bool
		issuedAt      string
		verifiedAt    string
		lastUsedAt    string
		recoveryCount int
	)

	if rec, err := getMFARecord(user.ID); err == nil {
		enabled = rec.IsVerified
		pending = rec.SecretEnc.Valid && strings.TrimSpace(rec.SecretEnc.String) != "" && !rec.IsVerified
		issuedAt = rec.IssuedAt.UTC().Format(time.RFC3339)
		if rec.VerifiedAt.Valid {
			verifiedAt = rec.VerifiedAt.Time.UTC().Format(time.RFC3339)
		}
		if rec.LastUsedAt.Valid {
			lastUsedAt = rec.LastUsedAt.Time.UTC().Format(time.RFC3339)
		}
		if count, err := countUnusedMFARecoveryCodes(user.ID); err == nil {
			recoveryCount = count
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		log.Printf("mfa status: load record failed for %s (%s): %v", user.Username, uuid, err)
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"username":      user.Username,
		"enforced":      mfaEnforceForAllUsers,
		"enabled":       enabled,
		"pending":       pending,
		"issuedAt":      issuedAt,
		"verifiedAt":    verifiedAt,
		"lastUsedAt":    lastUsedAt,
		"recoveryCount": recoveryCount,
	})
}
