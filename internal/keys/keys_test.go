package keys_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"clavicularius/internal/catalog"
	"clavicularius/internal/keys"
)

func TestES256SignIsRawAndRoundTrips(t *testing.T) {
	home := t.TempDir()
	entry := catalog.Entry{ID: "root", Alg: catalog.AlgES256, Kid: "root"}
	if code := keys.Generate(home, entry); code != "" {
		t.Fatal(code)
	}
	if code := keys.Generate(home, entry); code != keys.ErrAlreadyPresent {
		t.Fatalf("second generate: %s", code)
	}
	info, err := os.Stat(filepath.Join(home, "keys", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	msg := []byte("clavicularius-interop")
	sigB64, code := keys.Sign(home, entry, msg)
	if code != "" {
		t.Fatal(code)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length %d, want raw r||s of 64", len(sig))
	}
	body, err := os.ReadFile(filepath.Join(home, "keys", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !keys.VerifyES256(body, msg, sig) {
		t.Fatal("verify failed")
	}
	pub, code := keys.ExportPublic(home, entry)
	if code != "" {
		t.Fatal(code)
	}
	pubJSON, _ := json.Marshal(pub)
	if strings.Contains(string(pubJSON), `"d"`) {
		t.Fatal("public jwk contains d")
	}
	_, code = keys.ExportPrivateJWK(home, entry)
	if code != keys.ErrExportForbidden {
		t.Fatalf("export private: %s", code)
	}
}

func TestEd25519AndRandom(t *testing.T) {
	home := t.TempDir()
	ed := catalog.Entry{ID: "export-a", Alg: catalog.AlgEd25519, ExportPrivate: true, Kid: "export-a"}
	if code := keys.Generate(home, ed); code != "" {
		t.Fatal(code)
	}
	msg := []byte("ed-message")
	sigB64, code := keys.Sign(home, ed, msg)
	if code != "" {
		t.Fatal(code)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		t.Fatalf("ed25519 sig %d %v", len(sig), err)
	}
	body, err := os.ReadFile(filepath.Join(home, "keys", "export-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !keys.VerifyEd25519(body, msg, sig) {
		t.Fatal("ed25519 verify failed")
	}
	priv, code := keys.ExportPrivateJWK(home, ed)
	if code != "" || priv.D == "" || len(mustDecode(t, priv.D)) != 32 {
		t.Fatalf("seed export %+v %s", priv, code)
	}
	rnd := catalog.Entry{ID: "random-a", Alg: catalog.AlgRandom, ExportPrivate: true, Bytes: 32, Encoding: catalog.EncodingHex}
	if code := keys.Generate(home, rnd); code != "" {
		t.Fatal(code)
	}
	value, code := keys.ExportRandom(home, rnd)
	if code != "" || len(value) != 64 {
		t.Fatalf("random %q %s", value, code)
	}
	if _, code := keys.Sign(home, rnd, msg); code != keys.ErrNotASigningKey {
		t.Fatalf("sign random: %s", code)
	}
	if _, code := keys.ExportPublic(home, rnd); code != keys.ErrNoPublicKey {
		t.Fatalf("public random: %s", code)
	}
}

func TestWebCryptoVector(t *testing.T) {
	for _, name := range []string{"webcrypto-es256.json", "webcrypto-ed25519.json"} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			var vec struct {
				Message    string          `json:"message"`
				PrivateJWK json.RawMessage `json:"private_jwk"`
				Signature  string          `json:"signature"`
			}
			if err := json.Unmarshal(b, &vec); err != nil {
				t.Fatal(err)
			}
			sig, err := base64.RawURLEncoding.DecodeString(vec.Signature)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte(vec.Message)
			switch name {
			case "webcrypto-es256.json":
				if len(sig) != 64 || !keys.VerifyES256(vec.PrivateJWK, msg, sig) {
					t.Fatal("es256 vector")
				}
			default:
				if len(sig) != 64 || !keys.VerifyEd25519(vec.PrivateJWK, msg, sig) {
					t.Fatal("ed25519 vector")
				}
			}
		})
	}
}

func TestNodeVerifiesGoSignature(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	home := t.TempDir()
	entry := catalog.Entry{ID: "root", Alg: catalog.AlgES256, Kid: "root"}
	if code := keys.Generate(home, entry); code != "" {
		t.Fatal(code)
	}
	msg := []byte("clavicularius-interop")
	sig, code := keys.Sign(home, entry, msg)
	if code != "" {
		t.Fatal(code)
	}
	pub, code := keys.ExportPublic(home, entry)
	if code != "" {
		t.Fatal(code)
	}
	payload, _ := json.Marshal(map[string]any{
		"alg": "ES256", "message": string(msg), "signature": sig, "public_jwk": pub,
	})
	cmd := exec.Command("node", "--input-type=module", "-e", nodeVerify)
	cmd.Stdin = strings.NewReader(string(payload))
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("node verify: %v %s", err, out)
	}
}

const nodeVerify = `
import { webcrypto } from 'node:crypto';
const subtle = webcrypto.subtle;
const input = JSON.parse(await new Promise((resolve) => {
  let s = '';
  process.stdin.on('data', (c) => { s += c; });
  process.stdin.on('end', () => resolve(s));
}));
const key = await subtle.importKey('jwk', input.public_jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
const ok = await subtle.verify(
  { name: 'ECDSA', hash: 'SHA-256' },
  key,
  Buffer.from(input.signature, 'base64url'),
  new TextEncoder().encode(input.message),
);
if (!ok) process.exit(1);
process.stdout.write('ok');
`

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
