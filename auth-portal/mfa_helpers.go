package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	totpSecretBytes          = 20
	defaultMFADigits         = 6
	defaultMFAPeriodSeconds  = 30
	defaultMFADriftSteps     = 1
	defaultRecoveryCodeCount = 10
	recoveryCodeBytes        = 5
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

func generateTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32NoPadding.EncodeToString(buf), nil
}

func generateRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		return []string{}, nil
	}
	codes := make([]string, 0, n)
	seen := make(map[string]struct{}, n)

	for len(codes) < n {
		buf := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		raw := strings.ToUpper(hex.EncodeToString(buf))
		formatted := raw[:5] + "-" + raw[5:]
		if _, exists := seen[formatted]; exists {
			continue
		}
		seen[formatted] = struct{}{}
		codes = append(codes, formatted)
	}

	return codes, nil
}

func generateDefaultRecoveryCodes() ([]string, error) {
	return generateRecoveryCodes(defaultRecoveryCodeCount)
}

func hashRecoveryCode(code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func defaultMFAMetadata() (int, int, int) {
	return defaultMFADigits, defaultMFAPeriodSeconds, defaultMFADriftSteps
}

func validateTOTP(code string, secret string, now time.Time, period, skew, digits int) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}

	if period <= 0 {
		period = defaultMFAPeriodSeconds
	}
	if skew < 0 {
		skew = 0
	}
	if digits <= 0 {
		digits = defaultMFADigits
	}
	if digits > 10 {
		digits = 10
	}
	if len(code) != digits {
		return false
	}
	if strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) != -1 {
		return false
	}

	normalizedSecret := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	key, err := base32NoPadding.DecodeString(normalizedSecret)
	if err != nil {
		return false
	}

	timestep := now.Unix() / int64(period)
	for i := -skew; i <= skew; i++ {
		counter := timestep + int64(i)
		if counter < 0 {
			continue
		}
		otp := hotpValue(key, counter, digits)
		if otp == code {
			return true
		}
	}
	return false
}

func hotpValue(secret []byte, counter int64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binaryCode := (int(sum[offset]&0x7f) << 24) |
		(int(sum[offset+1]) << 16) |
		(int(sum[offset+2]) << 8) |
		int(sum[offset+3])

	modulo := pow10(digits)
	value := binaryCode % modulo
	return fmt.Sprintf("%0*d", digits, value)
}

func pow10(n int) int {
	if n <= 0 {
		return 1
	}
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}
