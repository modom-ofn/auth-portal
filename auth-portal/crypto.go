package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

var dataKey []byte

func init() {
    k := os.Getenv("DATA_KEY") // 32 bytes base64 or raw
    if k == "" { panic("DATA_KEY is required for token encryption") }
    // accept raw 32 bytes or base64
    if len(k) == 32 { dataKey = []byte(k) } else {
        b, err := base64.StdEncoding.DecodeString(k); if err != nil || len(b) != 32 {
            panic("DATA_KEY must be 32 raw bytes or base64-encoded 32 bytes")
        }
        dataKey = b
    }
}

func encryptToken(plain string) (string, error) {
    if plain == "" { return "", nil }
    block, err := aes.NewCipher(dataKey); if err != nil { return "", err }
    gcm, err := cipher.NewGCM(block); if err != nil { return "", err }
    nonce := make([]byte, gcm.NonceSize()); if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return "", err }
    ct := gcm.Seal(nonce, nonce, []byte(plain), nil) // nonce||ciphertext
    return base64.StdEncoding.EncodeToString(ct), nil
}
func decryptToken(b64 string) (string, error) {
    if b64 == "" { return "", nil }
    raw, err := base64.StdEncoding.DecodeString(b64); if err != nil { return "", err }
    block, err := aes.NewCipher(dataKey); if err != nil { return "", err }
    gcm, err := cipher.NewGCM(block); if err != nil { return "", err }
    ns := gcm.NonceSize(); if len(raw) < ns { return "", errors.New("cipher too short") }
    nonce, ct := raw[:ns], raw[ns:]
    pt, err := gcm.Open(nil, nonce, ct, nil); if err != nil { return "", err }
    return string(pt), nil
}