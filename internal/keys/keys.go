// Package keys generates, stores, and signs with catalog entries.
// ES256 signatures are raw r||s (64 bytes), matching WebCrypto subtle.sign,
// not ASN.1 DER. Ed25519 private JWK field d is the 32-byte seed.
package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"clavicularius/internal/catalog"
)

const (
	ErrKeyAbsent       = "key_absent"
	ErrAlreadyPresent  = "already_present"
	ErrExportForbidden = "export_forbidden"
	ErrNoPublicKey     = "no_public_key"
	ErrNotASigningKey  = "not_a_signing_key"
	ErrKeyPerms        = "key_perms"
	ErrKeySymlink      = "key_symlink"
	ErrKeyInvalid      = "key_invalid"
	ErrCommandFailed   = "command_failed"
)

// PublicJWK is a public key. It has no private component.
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

// PrivateJWK is a private key. Field d is the private component.
type PrivateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type randomFile struct {
	Alg      string `json:"alg"`
	Encoding string `json:"encoding"`
	Value    string `json:"value"`
}

// Dir is the key directory under home.
func Dir(home string) string {
	return filepath.Join(home, "keys")
}

func pathFor(home, id string) string {
	return filepath.Join(Dir(home), id+".json")
}

// Present reports whether a key file exists.
func Present(home, id string) bool {
	info, err := os.Lstat(pathFor(home, id))
	return err == nil && info.Mode().IsRegular()
}

// IDsOnDisk returns ids that have a file under keys/. A missing directory is empty.
func IDsOnDisk(home string) (map[string]struct{}, string) {
	entries, err := os.ReadDir(Dir(home))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]struct{}{}, ""
	}
	if err != nil {
		return nil, ErrCommandFailed
	}
	out := make(map[string]struct{})
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if id == "" {
			continue
		}
		out[id] = struct{}{}
	}
	return out, ""
}

// Generate creates the key described by entry. An existing file is left unchanged.
func Generate(home string, entry catalog.Entry) string {
	if err := os.MkdirAll(Dir(home), 0o700); err != nil {
		return ErrCommandFailed
	}
	if err := os.Chmod(Dir(home), 0o700); err != nil {
		return ErrCommandFailed
	}
	path := pathFor(home, entry.ID)
	if _, err := os.Lstat(path); err == nil {
		return ErrAlreadyPresent
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrCommandFailed
	}
	var body []byte
	var err error
	switch entry.Alg {
	case catalog.AlgES256:
		body, err = newES256(entry.Kid)
	case catalog.AlgEd25519:
		body, err = newEd25519(entry.Kid)
	case catalog.AlgRandom:
		body, err = newRandom(entry.Bytes, entry.Encoding)
	default:
		return ErrCommandFailed
	}
	if err != nil {
		return ErrCommandFailed
	}
	if err := writeNew(path, body); err != nil {
		wipe(body)
		return ErrCommandFailed
	}
	wipe(body)
	return ""
}

// Sign returns a base64url signature over message.
// ES256 is SHA-256 then ECDSA, encoded as raw r||s. Ed25519 signs message itself.
func Sign(home string, entry catalog.Entry, message []byte) (string, string) {
	if entry.Alg == catalog.AlgRandom {
		return "", ErrNotASigningKey
	}
	body, code := readKey(pathFor(home, entry.ID))
	if code != "" {
		return "", code
	}
	defer wipe(body)
	switch entry.Alg {
	case catalog.AlgES256:
		sig, err := signES256(body, message)
		if err != nil {
			return "", ErrKeyInvalid
		}
		return base64.RawURLEncoding.EncodeToString(sig), ""
	case catalog.AlgEd25519:
		sig, err := signEd25519(body, message)
		if err != nil {
			return "", ErrKeyInvalid
		}
		return base64.RawURLEncoding.EncodeToString(sig), ""
	default:
		return "", ErrNotASigningKey
	}
}

// ExportPublic returns the public JWK.
func ExportPublic(home string, entry catalog.Entry) (PublicJWK, string) {
	if entry.Alg == catalog.AlgRandom {
		return PublicJWK{}, ErrNoPublicKey
	}
	body, code := readKey(pathFor(home, entry.ID))
	if code != "" {
		return PublicJWK{}, code
	}
	defer wipe(body)
	priv, err := decodePrivate(body)
	if err != nil {
		return PublicJWK{}, ErrKeyInvalid
	}
	wipe([]byte(priv.D))
	return PublicJWK{
		Kty: priv.Kty,
		Crv: priv.Crv,
		X:   priv.X,
		Y:   priv.Y,
		Kid: priv.Kid,
		Alg: priv.Alg,
	}, ""
}

// ExportPrivateJWK returns the private JWK when the catalog allows export.
func ExportPrivateJWK(home string, entry catalog.Entry) (PrivateJWK, string) {
	if !entry.ExportPrivate {
		return PrivateJWK{}, ErrExportForbidden
	}
	if entry.Alg == catalog.AlgRandom {
		return PrivateJWK{}, ErrNotASigningKey
	}
	body, code := readKey(pathFor(home, entry.ID))
	if code != "" {
		return PrivateJWK{}, code
	}
	defer wipe(body)
	priv, err := decodePrivate(body)
	if err != nil {
		return PrivateJWK{}, ErrKeyInvalid
	}
	return priv, ""
}

// ExportRandom returns the encoded random value when the catalog allows export.
func ExportRandom(home string, entry catalog.Entry) (string, string) {
	if entry.Alg != catalog.AlgRandom {
		return "", ErrNotASigningKey
	}
	if !entry.ExportPrivate {
		return "", ErrExportForbidden
	}
	body, code := readKey(pathFor(home, entry.ID))
	if code != "" {
		return "", code
	}
	defer wipe(body)
	var stored randomFile
	if err := json.Unmarshal(body, &stored); err != nil || stored.Alg != catalog.AlgRandom || stored.Value == "" {
		return "", ErrKeyInvalid
	}
	return stored.Value, ""
}

func newES256(kid string) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	jwk := PrivateJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   fixedB64(priv.X.FillBytes(make([]byte, 32))),
		Y:   fixedB64(priv.Y.FillBytes(make([]byte, 32))),
		D:   fixedB64(priv.D.FillBytes(make([]byte, 32))),
		Kid: kid,
		Alg: "ES256",
	}
	return json.Marshal(jwk)
}

func newEd25519(kid string) ([]byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	jwk := PrivateJWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		D:   base64.RawURLEncoding.EncodeToString(priv.Seed()),
		Kid: kid,
		Alg: "EdDSA",
	}
	return json.Marshal(jwk)
}

func newRandom(n int, encoding string) ([]byte, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	var value string
	switch encoding {
	case catalog.EncodingHex:
		value = hex.EncodeToString(raw)
	case catalog.EncodingBase64:
		value = base64.StdEncoding.EncodeToString(raw)
	default:
		wipe(raw)
		return nil, errors.New("encoding")
	}
	wipe(raw)
	return json.Marshal(randomFile{Alg: catalog.AlgRandom, Encoding: encoding, Value: value})
}

func signES256(jwkJSON, message []byte) ([]byte, error) {
	priv, err := parseES256(jwkJSON)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

func signEd25519(jwkJSON, message []byte) ([]byte, error) {
	priv, err := parseEd25519(jwkJSON)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, message), nil
}

func parseES256(jwkJSON []byte) (*ecdsa.PrivateKey, error) {
	jwk, err := decodePrivate(jwkJSON)
	if err != nil {
		return nil, err
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" {
		return nil, errors.New("alg")
	}
	x, err := fixed32(jwk.X)
	if err != nil {
		return nil, err
	}
	y, err := fixed32(jwk.Y)
	if err != nil {
		return nil, err
	}
	d, err := fixed32(jwk.D)
	if err != nil {
		return nil, err
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.X = new(big.Int).SetBytes(x)
	priv.Y = new(big.Int).SetBytes(y)
	priv.D = new(big.Int).SetBytes(d)
	if !priv.Curve.IsOnCurve(priv.X, priv.Y) {
		return nil, errors.New("curve")
	}
	return priv, nil
}

func parseEd25519(jwkJSON []byte) (ed25519.PrivateKey, error) {
	jwk, err := decodePrivate(jwkJSON)
	if err != nil {
		return nil, err
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" {
		return nil, errors.New("alg")
	}
	seed, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil || len(seed) != 32 {
		return nil, errors.New("seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || !bytesEqual(pub, priv.Public().(ed25519.PublicKey)) {
		return nil, errors.New("pub")
	}
	return priv, nil
}

func decodePrivate(body []byte) (PrivateJWK, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var jwk PrivateJWK
	if err := dec.Decode(&jwk); err != nil {
		return PrivateJWK{}, err
	}
	return jwk, nil
}

func fixed32(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("coord")
	}
	return b, nil
}

func fixedB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func readKey(path string) ([]byte, string) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrKeyAbsent
		}
		return nil, ErrKeyInvalid
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrKeySymlink
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrKeyPerms
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrKeyInvalid
	}
	return b, ""
}

func writeNew(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(path)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(path)
		return cerr
	}
	return os.Chmod(path, 0o600)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

// VerifyES256 reports whether sig is a raw r||s signature over message.
// Tests use it to reject DER and to check interop vectors.
func VerifyES256(jwkJSON, message, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	priv, err := parseES256(jwkJSON)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(message)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(&priv.PublicKey, sum[:], r, s)
}

// VerifyEd25519 reports whether sig verifies message for the private JWK's public key.
func VerifyEd25519(jwkJSON, message, sig []byte) bool {
	priv, err := parseEd25519(jwkJSON)
	if err != nil {
		return false
	}
	return ed25519.Verify(priv.Public().(ed25519.PublicKey), message, sig)
}
