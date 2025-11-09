package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestEncodeDecodeBackupDocument(t *testing.T) {
	if tokenAEAD == nil {
		t.Skip("crypto not initialised")
	}
	doc := backupDocument{
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		CreatedBy: "tester",
		Sections: map[string]backupDocumentRecord{
			"security": {
				Version: 2,
				Config:  json.RawMessage(`{"sessionTtl":"24h"}`),
			},
		},
	}
	enc, err := encodeBackupDocument(doc)
	if err != nil {
		t.Fatalf("encodeBackupDocument: %v", err)
	}
	if bytes.Contains(enc, []byte(`"security"`)) {
		t.Fatalf("encrypted payload should not expose plaintext sections")
	}
	decoded, plaintext, err := decodeBackupDocument(enc)
	if err != nil {
		t.Fatalf("decodeBackupDocument: %v", err)
	}
	if !decoded.CreatedAt.Equal(doc.CreatedAt) || decoded.CreatedBy != doc.CreatedBy {
		t.Fatalf("decoded metadata mismatch: %+v", decoded)
	}
	if _, ok := decoded.Sections["security"]; !ok {
		t.Fatalf("decoded sections missing security: %+v", decoded.Sections)
	}
	if !bytes.Contains(plaintext, []byte(`"sessionTtl"`)) {
		t.Fatalf("plaintext missing expected data: %s", string(plaintext))
	}
}

func TestDecodeBackupDocumentLegacy(t *testing.T) {
	doc := backupDocument{
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		CreatedBy: "legacy",
		Sections: map[string]backupDocumentRecord{
			"providers": {Version: 1, Config: json.RawMessage(`{"active":"plex"}`)},
		},
	}
	plain, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded, data, err := decodeBackupDocument(plain)
	if err != nil {
		t.Fatalf("decode legacy: %v", err)
	}
	if !decoded.CreatedAt.Equal(doc.CreatedAt) || decoded.CreatedBy != doc.CreatedBy {
		t.Fatalf("decoded legacy mismatch: %+v", decoded)
	}
	if !bytes.Equal(data, plain) {
		t.Fatalf("expected raw plaintext to round-trip")
	}
}
