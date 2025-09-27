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
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
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

	respondJSON(w, http.StatusOK, mfaVerifyResponse{OK: true, RecoveryCodes: recoveryCodes})
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
