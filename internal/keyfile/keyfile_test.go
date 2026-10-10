package keyfile_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"clavicularius/internal/keyfile"
)

func TestSealRoundTrip(t *testing.T) {
	plain := []byte(`{"key_pkcs8_b64":"AQID","cert_pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}`)
	blob, code := keyfile.Seal([]byte("test-passphrase"), plain)
	if code != "" {
		t.Fatal(code)
	}
	got, code := keyfile.Open([]byte("test-passphrase"), blob)
	if code != "" {
		t.Fatal(code)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("plain mismatch")
	}
	if _, code := keyfile.Open([]byte("other-passphrase"), blob); code != keyfile.ErrCallerLocked {
		t.Fatalf("wrong pass: %s", code)
	}
	if _, code := keyfile.Open([]byte("test-passphrase"), []byte(`{"v":1,"kdf":"pbkdf2-sha256","iterations":1,"salt":"","nonce":"","ciphertext":""}`)); code != keyfile.ErrCallerLocked {
		t.Fatalf("downgrade: %s", code)
	}
}

func TestGolden(t *testing.T) {
	blob, err := os.ReadFile("testdata/caller-key.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/caller-key.plain.json")
	if err != nil {
		t.Fatal(err)
	}
	got, code := keyfile.Open([]byte("test-passphrase"), blob)
	if code != "" {
		t.Fatal(code)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatal("golden plaintext mismatch")
	}
	var payload keyfile.Plain
	if json.Unmarshal(got, &payload) != nil {
		t.Fatal("plain json")
	}
	der, err := base64.RawURLEncoding.DecodeString(payload.KeyPKCS8B64)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil || key == nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(payload.CertPEM))
	if block == nil {
		t.Fatal("cert pem")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
}
