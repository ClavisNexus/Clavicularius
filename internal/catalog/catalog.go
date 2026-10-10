// Package catalog reads the local key catalog. The catalog names keys.
// It does not contain private key bytes.
package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const (
	ErrCatalogMissing  = "catalog_missing"
	ErrCatalogInvalid  = "catalog_invalid"
	ErrCatalogPerms    = "catalog_perms"
	ErrCatalogSymlink  = "catalog_symlink"
	ErrCatalogRejected = "catalog_rejected"
	ErrCommandFailed   = "command_failed"
	AlgES256           = "ES256"
	AlgEd25519         = "Ed25519"
	AlgRandom          = "random"
	EncodingHex        = "hex"
	EncodingBase64     = "base64"
)

var (
	idRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	kidRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// Entry is one catalog line. Adding a line does not require a new binary.
type Entry struct {
	ID            string `json:"id"`
	Alg           string `json:"alg"`
	ExportPrivate bool   `json:"export_private"`
	Kid           string `json:"kid,omitempty"`
	Bytes         int    `json:"bytes,omitempty"`
	Encoding      string `json:"encoding,omitempty"`
}

// Catalog is the set of keys this machine is willing to hold.
type Catalog struct {
	Keys []Entry `json:"keys"`
}

// Path is the catalog file inside home.
func Path(home string) string {
	return filepath.Join(home, "catalog.json")
}

// Load reads path. A missing file is catalog_missing.
// Symlinks and modes wider than 0600 are refused.
func Load(path string) (Catalog, string) {
	cat, ok, code := Read(path)
	if code != "" {
		return Catalog{}, code
	}
	if !ok {
		return Catalog{}, ErrCatalogMissing
	}
	return cat, ""
}

// Read loads path. A missing file returns false and an empty catalog.
// Symlinks and modes wider than 0600 are refused.
func Read(path string) (Catalog, bool, string) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Catalog{}, false, ""
		}
		return Catalog{}, false, ErrCatalogInvalid
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Catalog{}, false, ErrCatalogSymlink
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return Catalog{}, false, ErrCatalogPerms
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, false, ErrCatalogInvalid
	}
	cat, code := Parse(b)
	if code != "" {
		return Catalog{}, true, code
	}
	return cat, true, ""
}

// ConfirmLine is the terminal line shown before generate.
func (e Entry) ConfirmLine() string {
	line := fmt.Sprintf("id=%s alg=%s export_private=%t", e.ID, e.Alg, e.ExportPrivate)
	if e.Kid != "" {
		line += " kid=" + e.Kid
	}
	if e.Bytes != 0 || e.Encoding != "" {
		line += fmt.Sprintf(" bytes=%d encoding=%s", e.Bytes, e.Encoding)
	}
	return line
}

// Admit decides whether next may replace an existing catalog.
// prevOK is false when no catalog file exists yet.
// onDisk holds ids that already have a key file.
// export_private false cannot become true, and that id cannot be dropped,
// even when its key file does not exist yet.
// An id with a key file also keeps alg, kid, bytes, and encoding.
// A key file whose id is absent from the current catalog refuses the replacement.
// The first catalog is accepted only when onDisk is empty.
func Admit(prevOK bool, prev, next Catalog, onDisk map[string]struct{}) string {
	if !prevOK {
		if len(onDisk) > 0 {
			return ErrCatalogRejected
		}
		return ""
	}
	prevBy := indexEntries(prev)
	nextBy := indexEntries(next)
	for id := range onDisk {
		if _, ok := prevBy[id]; !ok {
			return ErrCatalogRejected
		}
	}
	for id, old := range prevBy {
		neu, ok := nextBy[id]
		_, on := onDisk[id]
		if !ok {
			if on || !old.ExportPrivate {
				return ErrCatalogRejected
			}
			continue
		}
		if on && (old.Alg != neu.Alg || old.Kid != neu.Kid || old.Bytes != neu.Bytes || old.Encoding != neu.Encoding) {
			return ErrCatalogRejected
		}
		if neu.ExportPrivate && !old.ExportPrivate {
			return ErrCatalogRejected
		}
	}
	return ""
}

func indexEntries(cat Catalog) map[string]Entry {
	out := make(map[string]Entry, len(cat.Keys))
	for _, e := range cat.Keys {
		out[e.ID] = e
	}
	return out
}

// Write atomically replaces path with cat and sets mode 0600.
// A symbolic link is refused and left in place.
func Write(path string, cat Catalog) string {
	body, err := json.Marshal(cat)
	if err != nil {
		return ErrCommandFailed
	}
	body = append(body, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ErrCommandFailed
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return ErrCatalogSymlink
	case err == nil && !info.Mode().IsRegular():
		return ErrCatalogInvalid
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return ErrCommandFailed
	}
	f, err := os.CreateTemp(dir, ".catalog-*.tmp")
	if err != nil {
		return ErrCommandFailed
	}
	tmp := f.Name()
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return ErrCommandFailed
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return ErrCommandFailed
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return ErrCommandFailed
	}
	return ""
}

// Parse validates catalog JSON. Unknown fields are rejected.
func Parse(b []byte) (Catalog, string) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var raw Catalog
	if err := dec.Decode(&raw); err != nil {
		return Catalog{}, ErrCatalogInvalid
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return Catalog{}, ErrCatalogInvalid
	}
	if raw.Keys == nil {
		return Catalog{}, ErrCatalogInvalid
	}
	seen := map[string]struct{}{}
	for _, e := range raw.Keys {
		if !idRE.MatchString(e.ID) {
			return Catalog{}, ErrCatalogInvalid
		}
		if _, ok := seen[e.ID]; ok {
			return Catalog{}, ErrCatalogInvalid
		}
		seen[e.ID] = struct{}{}
		switch e.Alg {
		case AlgES256, AlgEd25519:
			if !kidRE.MatchString(e.Kid) || e.Bytes != 0 || e.Encoding != "" {
				return Catalog{}, ErrCatalogInvalid
			}
		case AlgRandom:
			if e.Kid != "" || e.Bytes < 1 || e.Bytes > 256 {
				return Catalog{}, ErrCatalogInvalid
			}
			if e.Encoding != EncodingHex && e.Encoding != EncodingBase64 {
				return Catalog{}, ErrCatalogInvalid
			}
			if !e.ExportPrivate {
				return Catalog{}, ErrCatalogInvalid
			}
		default:
			return Catalog{}, ErrCatalogInvalid
		}
	}
	return raw, ""
}

// Find returns the entry for id.
func (c Catalog) Find(id string) (Entry, bool) {
	for _, e := range c.Keys {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}
