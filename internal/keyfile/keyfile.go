// Package keyfile seals a caller private key with a passphrase.
// The file holds no unprotected private bytes.
package keyfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

const (
	ErrCallerLocked = "caller_locked"

	version    = 1
	kdfName    = "pbkdf2-sha256"
	iterations = 600000
	saltLen    = 16
	nonceLen   = 12
	keyLen     = 32
)

// Plain is the sealed payload. key_pkcs8_b64 is unencrypted PKCS#8.
type Plain struct {
	KeyPKCS8B64 string `json:"key_pkcs8_b64"`
	CertPEM     string `json:"cert_pem"`
}

type envelope struct {
	V          int    `json:"v"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Seal encrypts plain with pass. pass must be non-empty.
func Seal(pass, plain []byte) ([]byte, string) {
	if len(pass) == 0 || len(plain) == 0 {
		return nil, ErrCallerLocked
	}
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, ErrCallerLocked
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrCallerLocked
	}
	return seal(pass, plain, salt, nonce)
}

func seal(pass, plain, salt, nonce []byte) ([]byte, string) {
	dk, err := pbkdf2.Key(sha256.New, string(pass), salt, iterations, keyLen)
	if err != nil {
		return nil, ErrCallerLocked
	}
	defer wipe(dk)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, ErrCallerLocked
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCallerLocked
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrCallerLocked
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	env := envelope{
		V:          version,
		KDF:        kdfName,
		Iterations: iterations,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ct),
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, ErrCallerLocked
	}
	return append(out, '\n'), ""
}

// Open decrypts blob. A wrong passphrase and a malformed file both return caller_locked.
func Open(pass, blob []byte) ([]byte, string) {
	if len(pass) == 0 || len(blob) == 0 {
		return nil, ErrCallerLocked
	}
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.DisallowUnknownFields()
	var env envelope
	if err := dec.Decode(&env); err != nil {
		return nil, ErrCallerLocked
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, ErrCallerLocked
	}
	if env.V != version || env.KDF != kdfName || env.Iterations != iterations {
		return nil, ErrCallerLocked
	}
	salt, err := base64.RawURLEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) != saltLen {
		return nil, ErrCallerLocked
	}
	nonce, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return nil, ErrCallerLocked
	}
	ct, err := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ct) == 0 {
		return nil, ErrCallerLocked
	}
	dk, err := pbkdf2.Key(sha256.New, string(pass), salt, iterations, keyLen)
	if err != nil {
		return nil, ErrCallerLocked
	}
	defer wipe(dk)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, ErrCallerLocked
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCallerLocked
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrCallerLocked
	}
	return plain, ""
}

// ParsePlain decodes a sealed payload. Unknown fields are rejected.
func ParsePlain(plain []byte) (Plain, string) {
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	var p Plain
	if err := dec.Decode(&p); err != nil {
		return Plain{}, ErrCallerLocked
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return Plain{}, ErrCallerLocked
	}
	if p.KeyPKCS8B64 == "" || p.CertPEM == "" {
		return Plain{}, ErrCallerLocked
	}
	return p, ""
}

// Wipe zeroes b.
func Wipe(b []byte) {
	wipe(b)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ErrLocked is the tty failure shared with callers that only need the code.
var ErrLocked = errors.New(ErrCallerLocked)
