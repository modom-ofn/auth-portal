// crypto_tokens.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"golang.org/x/crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"sync"
)

var (
	// You can set AUTHPORTAL_TOKEN_KEY; if empty we fall back to SESSION_SECRET.
	// Both should be long, random strings.
	//
	// Example (bash):
	//   export AUTHPORTAL_TOKEN_KEY="$(openssl rand -hex 32)"
	//
	tokenKeyOnce sync.Once
	tokenKey     []byte
	tokenKeyErr  error
)

// getSealKey derives a 32-byte key via HKDF-SHA256 from AUTHPORTAL_TOKEN_KEY
// or, if empty, from SESSION_SECRET.
func getSealKey() ([]byte, error) {
	tokenKeyOnce.Do(func() {
		secret := os.Getenv("AUTHPORTAL_TOKEN_KEY")
		if secret == "" {
			secret = os.Getenv("SESSION_SECRET")
		}
		if secret == "" {
			tokenKeyErr = errors.New("missing AUTHPORTAL_TOKEN_KEY (or SESSION_SECRET)")
			return
		}

		// Derive a stable 32-byte key with HKDF-SHA256.
		// Salt and info can be static constants for an app-wide key.
		salt := []byte("authportal-hkdf-salt-v1")
		info := []byte("authportal-token-key-v1")
		h := hkdf.New(sha256.New, []byte(secret), salt, info)

		key := make([]byte, 32)
		if _, err := io.ReadFull(h, key); err != nil {
			tokenKeyErr = err
			return
		}
		tokenKey = key
	})
	return tokenKey, tokenKeyErr
}

// sealToken encrypts a plaintext token using AES-GCM and returns a base64 string.
// Format: base64( nonce(12) || ciphertext+tag )
func sealToken(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	key, err := getSealKey()
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize()) // GCM standard is 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ct := aead.Seal(nil, nonce, []byte(plain), nil)

	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)

	return base64.RawStdEncoding.EncodeToString(out), nil
}

// unsealToken decodes base64, splits nonce+ciphertext, and decrypts with AES-GCM.
func unsealToken(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	key, err := getSealKey()
	if err != nil {
		return "", err
	}

	data, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce := data[:aead.NonceSize()]
	ct := data[aead.NonceSize():]

	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}