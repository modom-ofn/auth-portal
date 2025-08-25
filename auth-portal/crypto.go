package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

const tokenSealVersion = "v1"

var (
	tokenAEAD   cipher.AEAD // stdlib AES-GCM
	dataKey32   []byte
)

func init() {
	if err := initCryptoFromEnv(); err != nil {
		log.Fatalf("crypto init: %v", err)
	}
}

func initCryptoFromEnv() error {
	k := os.Getenv("DATA_KEY")
	if k == "" {
		return errors.New("DATA_KEY is required (32 bytes, base64)")
	}

	// Try multiple base64 variants for convenience.
	var key []byte
	var err error
	if b, e := base64.StdEncoding.DecodeString(k); e == nil {
		key = b
	} else if b, e := base64.RawStdEncoding.DecodeString(k); e == nil {
		key = b
	} else if b, e := base64.RawURLEncoding.DecodeString(k); e == nil {
		key = b
	} else {
		return fmt.Errorf("DATA_KEY base64 decode failed")
	}
	if len(key) != 32 {
		return fmt.Errorf("DATA_KEY must decode to 32 bytes (got %d)", len(key))
	}
	dataKey32 = key

	block, err := aes.NewCipher(dataKey32)
	if err != nil {
		return fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block) // AES-256-GCM (12-byte nonce)
	if err != nil {
		return fmt.Errorf("cipher.NewGCM: %w", err)
	}
	tokenAEAD = aead
	return nil
}

// SealToken encrypts and MACs token -> "v1.<nonce>.<ct>" (base64url, no padding).
func SealToken(plaintext string) (string, error) {
	if tokenAEAD == nil {
		return "", errors.New("crypto not initialized")
	}
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, tokenAEAD.NonceSize()) // 12 bytes for GCM
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	ct := tokenAEAD.Seal(nil, nonce, []byte(plaintext), nil)
	enc := base64.RawURLEncoding.EncodeToString
	return tokenSealVersion + "." + enc(nonce) + "." + enc(ct), nil
}

// OpenToken decrypts "v1.<nonce>.<ct>". If it doesn't look sealed, returns as-is (back-compat).
func OpenToken(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	if !strings.HasPrefix(sealed, tokenSealVersion+".") {
		// likely plaintext from an older row
		return sealed, nil
	}
	if tokenAEAD == nil {
		return "", errors.New("crypto not initialized")
	}
	parts := strings.SplitN(sealed, ".", 3)
	if len(parts) != 3 {
		return "", errors.New("bad token format")
	}
	dec := base64.RawURLEncoding.DecodeString
	nonce, err := dec(parts[1])
	if err != nil {
		return "", fmt.Errorf("nonce decode: %w", err)
	}
	ct, err := dec(parts[2])
	if err != nil {
		return "", fmt.Errorf("ciphertext decode: %w", err)
	}
	pt, err := tokenAEAD.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("open token: %w", err)
	}
	return string(pt), nil
}