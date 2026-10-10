// Package remote is the HTTPS listener and the caller certificates it trusts.
// generate stays a local terminal command. This package does not interpret signatures.
package remote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"clavicularius/internal/keyfile"
	"clavicularius/internal/protocol"
)

const (
	ErrAlreadyPresent = "already_present"
	ErrKeyPerms       = "key_perms"
	ErrKeySymlink     = "key_symlink"
	ErrKeyAbsent      = "key_absent"
	ErrKeyInvalid     = "key_invalid"
	ErrNoCaller       = "no_caller"
	ErrListenInvalid  = "listen_invalid"
	ErrCallerUnknown  = "caller_unknown"
	ErrCallerInvalid  = "caller_invalid"
	ErrCallerLocked   = "caller_locked"
	ErrPinMismatch    = "pin_mismatch"
	ErrBadRequest     = "bad_request"
	ErrCommandFailed  = "command_failed"

	maxCertPEM = 16 * 1024
)

var (
	nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	pinRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errPin = errors.New(ErrPinMismatch)
)

// Init writes server.key and server.crt. An existing file is left in place.
// The return string is the lowercase SHA-256 of the server SPKI.
func Init(home string) (string, string) {
	if code := tightenDir(home); code != "" {
		return "", code
	}
	keyPath := filepath.Join(home, "server.key")
	certPath := filepath.Join(home, "server.crt")
	if code := absent(keyPath); code != "" {
		return "", code
	}
	if code := absent(certPath); code != "" {
		return "", code
	}
	keyPEM, certPEM, pin, code := mint("server", x509.ExtKeyUsageServerAuth)
	if code != "" {
		return "", code
	}
	if code := writeNew(keyPath, keyPEM); code != "" {
		return "", code
	}
	if code := writeNew(certPath, certPEM); code != "" {
		_ = os.Remove(keyPath)
		return "", code
	}
	return pin, ""
}

// CreateCallerKey writes an encrypted caller key and a public certificate.
// Existing paths are left in place.
func CreateCallerKey(outPath, certOut string, pass []byte) string {
	if len(pass) == 0 {
		return ErrCallerLocked
	}
	if code := parentReady(outPath); code != "" {
		return code
	}
	if code := parentReady(certOut); code != "" {
		return code
	}
	if code := absent(outPath); code != "" {
		return code
	}
	if code := absent(certOut); code != "" {
		return code
	}
	keyPEM, certPEM, _, code := mint("caller", x509.ExtKeyUsageClientAuth)
	if code != "" {
		return code
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		wipe(keyPEM)
		return ErrCommandFailed
	}
	plainStruct := keyfile.Plain{
		KeyPKCS8B64: base64.RawURLEncoding.EncodeToString(block.Bytes),
		CertPEM:     string(certPEM),
	}
	plain, err := json.Marshal(plainStruct)
	wipe(keyPEM)
	wipe(block.Bytes)
	if err != nil {
		return ErrCommandFailed
	}
	sealed, code := keyfile.Seal(pass, plain)
	keyfile.Wipe(plain)
	if code != "" {
		return code
	}
	if code := writeNew(outPath, sealed); code != "" {
		return code
	}
	if code := writeNew(certOut, certPEM); code != "" {
		_ = os.Remove(outPath)
		return code
	}
	return ""
}

// AddCaller stores one self-signed P-256 leaf under callers/<name>.crt.
func AddCaller(home, name string, pemBytes []byte) string {
	if !nameRE.MatchString(name) {
		return ErrCallerInvalid
	}
	if _, code := parseLeaf(pemBytes); code != "" {
		return code
	}
	dir := filepath.Join(home, "callers")
	if code := tightenDir(dir); code != "" {
		return code
	}
	return writeNew(filepath.Join(dir, name+".crt"), pemBytes)
}

// RemoveCaller deletes callers/<name>.crt. A symlink is left in place.
func RemoveCaller(home, name string) string {
	if !nameRE.MatchString(name) {
		return ErrCallerInvalid
	}
	path := filepath.Join(home, "callers", name+".crt")
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrCallerUnknown
		}
		return ErrCommandFailed
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrKeySymlink
	}
	if !info.Mode().IsRegular() {
		return ErrKeyPerms
	}
	if err := os.Remove(path); err != nil {
		return ErrCommandFailed
	}
	return ""
}

// ValidListen reports whether addr is a specific IP and a port of 1024 or higher.
func ValidListen(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ErrListenInvalid
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return ErrListenInvalid
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1024 || p > 65535 {
		return ErrListenInvalid
	}
	return ""
}

// CanonicalURL accepts https://<ip>:<port>/ with a port above 1023.
func CanonicalURL(raw string) (string, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", ErrBadRequest
	}
	if u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrBadRequest
	}
	if u.Path != "" && u.Path != "/" {
		return "", ErrBadRequest
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || ip.IsUnspecified() {
		return "", ErrBadRequest
	}
	port := u.Port()
	if port == "" {
		return "", ErrBadRequest
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1024 || p > 65535 {
		return "", ErrBadRequest
	}
	return "https://" + net.JoinHostPort(ip.String(), strconv.Itoa(p)) + "/", ""
}

// Serve listens until ctx is done. It returns a code, or an empty string on shutdown.
func Serve(ctx context.Context, home, addr string) string {
	if code := ValidListen(addr); code != "" {
		return code
	}
	cert, pool, code := loadServer(home)
	if code != "" {
		return code
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		NextProtos:   []string{"http/1.1"},
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return ErrCommandFailed
	}
	defer ln.Close()
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handle(w, r, home) }),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	srv.SetKeepAlivesEnabled(false)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(tls.NewListener(ln, tlsCfg))
	}()
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		return ""
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return ""
		}
		return ErrCommandFailed
	}
}

func handle(w http.ResponseWriter, r *http.Request, home string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	if r.Method != http.MethodPost || r.URL.Path != "/" || r.URL.RawQuery != "" {
		_, _ = w.Write(protocol.Encode(protocol.Response{OK: false, Error: protocol.ErrBadRequest}))
		return
	}
	body, code := protocol.ReadBody(r.Body)
	if code != "" {
		_, _ = w.Write(protocol.Encode(protocol.Response{OK: false, Error: code}))
		return
	}
	_, _ = w.Write(protocol.Encode(protocol.Handle(home, body)))
}

// Call posts one JSON body. A pin mismatch does not send the body.
func Call(ctx context.Context, endpoint, pin, keyPath string, pass, body []byte) ([]byte, string) {
	url, code := CanonicalURL(endpoint)
	if code != "" {
		return nil, code
	}
	if !pinRE.MatchString(pin) {
		return nil, ErrBadRequest
	}
	tlsCfg, wipe, code := clientTLS(keyPath, pass, pin)
	if code != "" {
		return nil, code
	}
	defer wipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, ErrCommandFailed
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errPin) {
			return nil, ErrPinMismatch
		}
		return nil, ErrCommandFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrCommandFailed
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, protocolMax+1))
	if err != nil || len(out) > protocolMax {
		return nil, ErrCommandFailed
	}
	return out, ""
}

const protocolMax = 512 * 1024

func clientTLS(keyPath string, pass []byte, pin string) (*tls.Config, func(), string) {
	blob, code := readRegular(keyPath)
	if code != "" {
		return nil, func() {}, code
	}
	plain, code := keyfile.Open(pass, blob)
	wipe(blob)
	if code != "" {
		return nil, func() {}, ErrCallerLocked
	}
	parsed, code := keyfile.ParsePlain(plain)
	if code != "" {
		keyfile.Wipe(plain)
		return nil, func() {}, ErrCallerLocked
	}
	pkcs8, err := base64.RawURLEncoding.DecodeString(parsed.KeyPKCS8B64)
	if err != nil {
		keyfile.Wipe(plain)
		return nil, func() {}, ErrCallerLocked
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	pair, err := tls.X509KeyPair([]byte(parsed.CertPEM), keyPEM)
	wipe(keyPEM)
	wipe(pkcs8)
	if err != nil {
		keyfile.Wipe(plain)
		return nil, func() {}, ErrCallerLocked
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		// The SPKI pin is the server check. Certificate names are not used.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errPin
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return errPin
			}
			got := pinOf(leaf)
			if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return errPin
			}
			return nil
		},
	}
	wipeFn := func() {
		keyfile.Wipe(plain)
		if key, ok := pair.PrivateKey.(*ecdsa.PrivateKey); ok && key != nil && key.D != nil {
			key.D.SetInt64(0)
		}
	}
	return cfg, wipeFn, ""
}

func loadServer(home string) (tls.Certificate, *x509.CertPool, string) {
	keyPEM, code := readRegular(filepath.Join(home, "server.key"))
	if code == ErrKeyAbsent {
		return tls.Certificate{}, nil, ErrKeyAbsent
	}
	if code != "" {
		return tls.Certificate{}, nil, code
	}
	certPEM, code := readRegular(filepath.Join(home, "server.crt"))
	if code != "" {
		wipe(keyPEM)
		if code == ErrKeyAbsent {
			return tls.Certificate{}, nil, ErrKeyAbsent
		}
		return tls.Certificate{}, nil, code
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	wipe(keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, ErrKeyInvalid
	}
	dir := filepath.Join(home, "callers")
	info, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return tls.Certificate{}, nil, ErrNoCaller
		}
		return tls.Certificate{}, nil, ErrCommandFailed
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return tls.Certificate{}, nil, ErrKeySymlink
	}
	if !info.IsDir() {
		return tls.Certificate{}, nil, ErrKeyPerms
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return tls.Certificate{}, nil, ErrCommandFailed
	}
	pool := x509.NewCertPool()
	n := 0
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".crt") || strings.HasPrefix(name, ".") {
			return tls.Certificate{}, nil, ErrCallerInvalid
		}
		body, code := readRegular(filepath.Join(dir, name))
		if code != "" {
			return tls.Certificate{}, nil, code
		}
		leaf, code := parseLeaf(body)
		if code != "" {
			return tls.Certificate{}, nil, code
		}
		pool.AddCert(leaf)
		n++
	}
	if n == 0 {
		return tls.Certificate{}, nil, ErrNoCaller
	}
	return pair, pool, ""
}

func mint(cn string, eku x509.ExtKeyUsage) (keyPEM, certPEM []byte, pin, code string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", ErrCommandFailed
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", ErrCommandFailed
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", ErrCommandFailed
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", ErrCommandFailed
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, "", ErrCommandFailed
	}
	key.D.SetInt64(0)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	wipe(pkcs8)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return keyPEM, certPEM, pinOf(cert), ""
}

func pinOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func parseLeaf(pemBytes []byte) (*x509.Certificate, string) {
	if len(pemBytes) == 0 || len(pemBytes) > maxCertPEM {
		return nil, ErrCallerInvalid
	}
	block, rest := pem.Decode(bytes.TrimSpace(pemBytes))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrCallerInvalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.IsCA {
		return nil, ErrCallerInvalid
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, ErrCallerInvalid
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrCallerInvalid
	}
	return cert, ""
}

func absent(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ""
		}
		return ErrCommandFailed
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrKeySymlink
	}
	return ErrAlreadyPresent
}

func readRegular(path string) ([]byte, string) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrKeyAbsent
		}
		return nil, ErrCommandFailed
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrKeySymlink
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrKeyPerms
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrCommandFailed
	}
	return b, ""
}

func writeNew(path string, body []byte) string {
	if code := absent(path); code != "" {
		return code
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrCommandFailed
	}
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(path)
		return ErrCommandFailed
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		return ErrCommandFailed
	}
	return ""
}

func parentReady(path string) string {
	if path == "" || strings.ContainsAny(path, "\r\n\x00") {
		return ErrBadRequest
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return ErrBadRequest
	}
	return ""
}

func tightenDir(path string) string {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return ErrCommandFailed
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ErrCommandFailed
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrKeySymlink
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return ErrCommandFailed
	}
	return ""
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
