package remote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitOnce(t *testing.T) {
	home := t.TempDir()
	pin, code := Init(home)
	if code != "" || len(pin) != 64 {
		t.Fatalf("pin %q %s", pin, code)
	}
	info, err := os.Stat(filepath.Join(home, "server.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v %v", info, err)
	}
	before, err := os.ReadFile(filepath.Join(home, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, code := Init(home); code != ErrAlreadyPresent {
		t.Fatalf("second %s", code)
	}
	after, err := os.ReadFile(filepath.Join(home, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("key overwritten")
	}
}

func TestListenRejects(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8756", "[::]:8756", "clavicularius:8756", "127.0.0.1:443", "127.0.0.1", ""} {
		if code := ValidListen(addr); code != ErrListenInvalid {
			t.Fatalf("%s -> %s", addr, code)
		}
	}
	if code := ValidListen("127.0.0.1:8756"); code != "" {
		t.Fatal(code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := Serve(ctx, t.TempDir(), "0.0.0.0:8756"); code != ErrListenInvalid {
		t.Fatalf("serve %s", code)
	}
}

func TestServeRequiresCaller(t *testing.T) {
	home := t.TempDir()
	if _, code := Init(home); code != "" {
		t.Fatal(code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if code := Serve(ctx, home, freeAddr(t)); code != ErrNoCaller {
		t.Fatalf("no caller %s", code)
	}
}

func TestCallerRejectsCA(t *testing.T) {
	home := t.TempDir()
	ca := mintCA(t)
	if code := AddCaller(home, "ca", ca); code != ErrCallerInvalid {
		t.Fatalf("ca %s", code)
	}
	if code := AddCaller(home, "../x", leafPEM(t)); code != ErrCallerInvalid {
		t.Fatalf("name %s", code)
	}
}

func TestServeRoundTrip(t *testing.T) {
	home := t.TempDir()
	pin, code := Init(home)
	if code != "" {
		t.Fatal(code)
	}
	pass := []byte("test-passphrase")
	keyPath := filepath.Join(t.TempDir(), "caller.json")
	certPath := filepath.Join(t.TempDir(), "caller.crt")
	if code := CreateCallerKey(keyPath, certPath, pass); code != "" {
		t.Fatal(code)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if code := AddCaller(home, "lab", certPEM); code != "" {
		t.Fatal(code)
	}
	otherKey := filepath.Join(t.TempDir(), "other.json")
	otherCert := filepath.Join(t.TempDir(), "other.crt")
	if code := CreateCallerKey(otherKey, otherCert, pass); code != "" {
		t.Fatal(code)
	}

	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan string, 1)
	go func() { errCh <- Serve(ctx, home, addr) }()
	waitTCP(t, addr)
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(4 * time.Second):
			t.Error("serve did not stop")
		}
	})

	endpoint := "https://" + addr + "/"
	resp, code := Call(context.Background(), endpoint, pin, keyPath, pass, []byte(`{"op":"generate"}`))
	if code != "" {
		t.Fatal(code)
	}
	if !bytes.Contains(resp, []byte(`"error":"generate_local_only"`)) {
		t.Fatalf("generate %s", resp)
	}

	const canary = "CANARY_7f3a9c2e1b804d66a0c5e9d27f3a9c2e"
	resp, code = Call(context.Background(), endpoint, pin, keyPath, pass, []byte(`{"op":"sign","key_id":"nope","message_b64":"`+canary+`"}`))
	if code != "" {
		t.Fatal(code)
	}
	if bytes.Contains(resp, []byte(canary)) {
		t.Fatal("response echoed the body")
	}
	walkNoCanary(t, home, canary)

	if _, code := Call(context.Background(), endpoint, pin, otherKey, pass, []byte(`{"op":"list"}`)); code == "" {
		t.Fatal("unregistered caller was accepted")
	}
	badPin := pin
	if badPin[0] == 'a' {
		badPin = "b" + badPin[1:]
	} else {
		badPin = "a" + badPin[1:]
	}
	if _, code := Call(context.Background(), endpoint, badPin, keyPath, pass, []byte(`{"op":"put_catalog","catalog":{"keys":[{"id":"`+canary+`","alg":"ES256","export_private":false,"kid":"k"}]}}`)); code != ErrPinMismatch {
		t.Fatalf("pin %s", code)
	}
	if _, err := os.Stat(filepath.Join(home, "catalog.json")); !os.IsNotExist(err) {
		t.Fatal("catalog written on pin mismatch")
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	home := t.TempDir()
	if _, code := Init(home); code != "" {
		t.Fatal(code)
	}
	certPEM := leafPEM(t)
	if code := AddCaller(home, "lab", certPEM); code != "" {
		t.Fatal(code)
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if code := Serve(ctx, home, addr); code != "" {
		t.Fatal(code)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("serve ignored the deadline")
	}
}

func TestWideCallerRefused(t *testing.T) {
	home := t.TempDir()
	if _, code := Init(home); code != "" {
		t.Fatal(code)
	}
	if code := AddCaller(home, "lab", leafPEM(t)); code != "" {
		t.Fatal(code)
	}
	if err := os.Chmod(filepath.Join(home, "callers", "lab.crt"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if code := Serve(ctx, home, freeAddr(t)); code != ErrKeyPerms {
		t.Fatalf("perms %s", code)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if code := ValidListen(addr); code != "" {
		t.Fatalf("free addr %s %s", addr, code)
	}
	return addr
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not listen")
}

func walkNoCanary(t *testing.T, root, canary string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(canary)) {
			t.Fatalf("canary in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func leafPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mintCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
