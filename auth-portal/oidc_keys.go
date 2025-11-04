package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

var (
	oidcSigningKey   *rsa.PrivateKey
	oidcSigningKeyID string
	oidcJWKSCache    []byte
	oidcKeyGenerated bool
	oidcKeyLoadedAt  time.Time
)

func initOIDCSigningKey() error {
	if oidcSigningKey != nil {
		return nil
	}

	var (
		priv *rsa.PrivateKey
		err  error
	)

	if oidcSigningKeyPEM != "" {
		priv, err = parseRSAPrivateKeyFromPEM([]byte(oidcSigningKeyPEM))
		if err != nil {
			return fmt.Errorf("oidc signing key from OIDC_SIGNING_KEY invalid: %w", err)
		}
	} else if oidcSigningKeyPath != "" {
		raw, readErr := os.ReadFile(oidcSigningKeyPath)
		if readErr != nil {
			return fmt.Errorf("oidc signing key read error: %w", readErr)
		}
		priv, err = parseRSAPrivateKeyFromPEM(raw)
		if err != nil {
			return fmt.Errorf("oidc signing key at %s invalid: %w", oidcSigningKeyPath, err)
		}
	} else {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("oidc signing key generation failed: %w", err)
		}
		oidcKeyGenerated = true
	}

	if err := priv.Validate(); err != nil {
		return fmt.Errorf("oidc signing key validation failed: %w", err)
	}

	keyID, err := computeKeyID(priv.Public().(*rsa.PublicKey))
	if err != nil {
		return fmt.Errorf("oidc signing keyid: %w", err)
	}

	jwks, err := buildJWKS(priv.Public().(*rsa.PublicKey), keyID)
	if err != nil {
		return fmt.Errorf("oidc jwks build: %w", err)
	}

	oidcSigningKey = priv
	oidcSigningKeyID = keyID
	oidcJWKSCache = jwks
	oidcKeyLoadedAt = time.Now().UTC()

	if oidcKeyGenerated {
		log.Printf("OIDC: generated ephemeral RSA signing key (kid=%s)", oidcSigningKeyID)
	} else {
		log.Printf("OIDC: loaded signing key (kid=%s)", oidcSigningKeyID)
	}
	return nil
}

func parseRSAPrivateKeyFromPEM(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := keyAny.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

func computeKeyID(pub *rsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("nil public key")
	}
	nBytes := pub.N.Bytes()
	hash := sha256.Sum256(nBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:8]), nil
}

func buildJWKS(pub *rsa.PublicKey, kid string) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("nil public key")
	}
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())

	// exponent as bytes
	eBytes := make([]byte, 0)
	e := pub.E
	for e > 0 {
		eBytes = append([]byte{byte(e % 256)}, eBytes...)
		e /= 256
	}
	if len(eBytes) == 0 {
		eBytes = []byte{0x01, 0x00, 0x01} // default 65537
	}
	eEnc := base64.RawURLEncoding.EncodeToString(eBytes)

	type jwk struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	type jwks struct {
		Keys []jwk `json:"keys"`
	}

	payload := jwks{
		Keys: []jwk{{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   n,
			E:   eEnc,
		}},
	}

	return json.Marshal(payload)
}

func oidcJWKS() []byte {
	if len(oidcJWKSCache) == 0 {
		return []byte(`{"keys":[]}`)
	}
	return oidcJWKSCache
}

func oidcIssuer() string {
	if v := strings.TrimSpace(oidcIssuerOverride); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(appBaseURL, "/")
}
