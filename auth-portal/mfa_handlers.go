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

const (
	errMFAMethodNotAllowed = "method not allowed"
	errMFASessionRequired  = "session required"
	errMFAUserNotFound     = "user not found"
	errMFALookupFailed     = "lookup failed"
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
	Next string `json:"next,omitempty"`
}

type mfaChallengeVerifyResponse struct {
	OK                     bool   `json:"ok"`
	Redirect               string `json:"redirect"`
	RecoveryUsed           bool   `json:"recoveryUsed"`
	RemainingRecoveryCodes int    `json:"remainingRecoveryCodes"`
}

type mfaVerificationContext struct {
	secret string
	digits int
	period int
	skew   int
}

func mfaEnrollmentStartHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMFAMethodNotAllowed})
		return
	}

	if !mfaEnrollmentEnabled {
		respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "MFA enrollment disabled"})
		return
	}

	uuid := uuidFrom(r.Context())
	if uuid == "" {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": errMFASessionRequired})
		return
	}

	user, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": errMFAUserNotFound})
			return
		}
		log.Printf("mfa enroll: user lookup failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": errMFALookupFailed})
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
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMFAMethodNotAllowed})
		return
	}

	uuid := uuidFrom(r.Context())
	if uuid == "" {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": errMFASessionRequired})
		return
	}

	code, ok := decodeMFAVerifyCode(w, r)
	if !ok {
		return
	}

	user, ok := lookupMFAUserByUUID(w, uuid, "mfa verify")
	if !ok {
		return
	}

	verifyCtx, ok := loadMFAEnrollmentVerificationContext(w, user.ID)
	if !ok {
		return
	}

	if !validateTOTP(code, verifyCtx.secret, time.Now(), verifyCtx.period, verifyCtx.skew, verifyCtx.digits) {
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
	if err := persistHashedRecoveryCodes(user.ID, recoveryCodes); err != nil {
		log.Printf("mfa verify: storing recovery codes failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "recovery persistence failed"})
		return
	}

	username := resolveMFASessionUsername(r, user, uuid)
	if err := setSessionCookie(w, uuid, username); err != nil {
		log.Printf("mfa verify: set session failed for %s (%s): %v", username, uuid, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "session setup failed"})
		return
	}

	respondJSON(w, http.StatusOK, mfaVerifyResponse{OK: true, RecoveryCodes: recoveryCodes})
}

func mfaChallengeVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMFAMethodNotAllowed})
		return
	}

	claims, err := pendingClaimsFromRequest(r)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "challenge expired"})
		return
	}

	req, rawCode, ok := decodeMFAChallengeRequest(w, r)
	if !ok {
		return
	}

	user, ok := lookupMFAUserByUUID(w, claims.UUID, "mfa challenge")
	if !ok {
		return
	}

	verifyCtx, ok := loadMFAChallengeVerificationContext(w, user.ID, claims)
	if !ok {
		return
	}

	validated, recoveryUsed, ok := validateMFAChallengeCode(w, user.ID, rawCode, verifyCtx, claims)
	if !ok {
		return
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

	remaining := remainingRecoveryCodeCount(user.ID, claims)

	respondJSON(w, http.StatusOK, mfaChallengeVerifyResponse{
		OK:                     true,
		Redirect:               sanitizeOIDCContinueTarget(req.Next),
		RecoveryUsed:           recoveryUsed,
		RemainingRecoveryCodes: remaining,
	})
}

func decodeMFAVerifyCode(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req mfaVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid payload"})
		return "", false
	}
	code := normalizeMFACode(req.Code)
	if code == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "code required"})
		return "", false
	}
	return code, true
}

func lookupMFAUserByUUID(w http.ResponseWriter, uuid, logPrefix string) (User, bool) {
	user, err := getUserByUUIDPreferred(uuid)
	if err == nil {
		return user, true
	}
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": errMFAUserNotFound})
		return User{}, false
	}
	log.Printf("%s: user lookup failed for %s: %v", logPrefix, uuid, err)
	respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": errMFALookupFailed})
	return User{}, false
}

func loadMFAEnrollmentVerificationContext(w http.ResponseWriter, userID int) (mfaVerificationContext, bool) {
	rec, err := getMFARecord(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "enrollment not started"})
			return mfaVerificationContext{}, false
		}
		log.Printf("mfa verify: load record failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": errMFALookupFailed})
		return mfaVerificationContext{}, false
	}
	if !rec.SecretEnc.Valid || strings.TrimSpace(rec.SecretEnc.String) == "" {
		respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "secret unavailable"})
		return mfaVerificationContext{}, false
	}

	secret, err := OpenToken(rec.SecretEnc.String)
	if err != nil {
		log.Printf("mfa verify: open secret failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "secret invalid"})
		return mfaVerificationContext{}, false
	}

	digits, period, skew := mfaTimingFromRecord(rec)
	return mfaVerificationContext{secret: secret, digits: digits, period: period, skew: skew}, true
}

func mfaTimingFromRecord(rec MFARecord) (int, int, int) {
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
	return digits, period, skew
}

func persistHashedRecoveryCodes(userID int, recoveryCodes []string) error {
	hashed := make([]string, 0, len(recoveryCodes))
	for _, rc := range recoveryCodes {
		hashed = append(hashed, hashRecoveryCode(rc))
	}
	return replaceMFARecoveryCodes(userID, hashed)
}

func resolveMFASessionUsername(r *http.Request, user User, fallbackUUID string) string {
	username := strings.TrimSpace(usernameFrom(r.Context()))
	if username == "" {
		username = strings.TrimSpace(user.Username)
	}
	if username == "" {
		username = fallbackUUID
	}
	return username
}

func decodeMFAChallengeRequest(w http.ResponseWriter, r *http.Request) (mfaChallengeVerifyRequest, string, bool) {
	var req mfaChallengeVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid payload"})
		return mfaChallengeVerifyRequest{}, "", false
	}
	rawCode := strings.TrimSpace(req.Code)
	if rawCode == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "code required"})
		return mfaChallengeVerifyRequest{}, "", false
	}
	return req, rawCode, true
}

func loadMFAChallengeVerificationContext(w http.ResponseWriter, userID int, claims pendingMFAClaims) (mfaVerificationContext, bool) {
	rec, err := getMFARecord(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "mfa not enrolled"})
			return mfaVerificationContext{}, false
		}
		log.Printf("mfa challenge: load record failed for %s (%s): %v", claims.Username, claims.UUID, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": errMFALookupFailed})
		return mfaVerificationContext{}, false
	}
	if !rec.IsVerified {
		respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "mfa enrollment incomplete"})
		return mfaVerificationContext{}, false
	}

	digits, period, skew := mfaTimingFromRecord(rec)
	secret := ""
	if rec.SecretEnc.Valid {
		secret, err = OpenToken(rec.SecretEnc.String)
		if err != nil {
			log.Printf("mfa challenge: open secret failed for %s (%s): %v", claims.Username, claims.UUID, err)
			respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "secret invalid"})
			return mfaVerificationContext{}, false
		}
	}

	return mfaVerificationContext{
		secret: secret,
		digits: digits,
		period: period,
		skew:   skew,
	}, true
}

func validateMFAChallengeCode(
	w http.ResponseWriter,
	userID int,
	rawCode string,
	verifyCtx mfaVerificationContext,
	claims pendingMFAClaims,
) (bool, bool, bool) {
	normalized := normalizeMFACode(rawCode)
	validated := verifyCtx.secret != "" &&
		normalized != "" &&
		validateTOTP(normalized, verifyCtx.secret, time.Now(), verifyCtx.period, verifyCtx.skew, verifyCtx.digits)

	recoveryUsed := false
	if validated {
		return true, recoveryUsed, true
	}

	hashed := hashRecoveryCode(rawCode)
	consumed, err := consumeMFARecoveryCode(userID, hashed)
	if err != nil {
		log.Printf("mfa challenge: consume recovery failed for %s (%s): %v", claims.Username, claims.UUID, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "recovery validation failed"})
		return false, false, false
	}
	if consumed {
		validated = true
		recoveryUsed = true
	}

	return validated, recoveryUsed, true
}

func remainingRecoveryCodeCount(userID int, claims pendingMFAClaims) int {
	if count, err := countUnusedMFARecoveryCodes(userID); err == nil {
		return count
	}
	log.Printf("mfa challenge: count recovery codes failed for %s (%s)", claims.Username, claims.UUID)
	return 0
}

func normalizeMFACode(code string) string {
	cleaned := strings.TrimSpace(code)
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "_", "")
	return cleaned
}

func sanitizeOIDCContinueTarget(raw string) string {
	next := strings.TrimSpace(raw)
	if next == "" {
		return "/home"
	}
	next = strings.ReplaceAll(next, "\\", "/")
	if !strings.HasPrefix(next, "/oidc/authorize") {
		return "/home"
	}
	parsed, err := url.Parse(next)
	if err != nil || parsed.String() == "" || parsed.IsAbs() || parsed.Fragment != "" {
		return "/home"
	}
	if !(strings.HasPrefix(next, "/") && (len(next) == 1 || (next[1] != '/' && next[1] != '\\'))) {
		return "/home"
	}
	return parsed.Path + func() string {
		if parsed.RawQuery == "" {
			return ""
		}
		return "?" + parsed.RawQuery
	}()
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
