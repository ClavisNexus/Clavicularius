// Package protocol is the one-shot JSON command.
// generate creates a catalog key without the terminal confirmation prompt.
// The local `generate` subcommand still requires a tty and the word generate.
package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	"clavicularius/internal/catalog"
	"clavicularius/internal/keys"
)

const (
	maxBody = 512 * 1024

	ErrBadRequest     = "bad_request"
	ErrUnknownField   = "unknown_field"
	ErrBodyTooLarge   = "body_too_large"
	ErrUnknownOp      = "unknown_op"
	ErrKeyIDRequired  = "key_id_required"
	ErrKeyUnknown     = "key_unknown"
	ErrMessageInvalid = "message_invalid"
)

// Request is one command. Unknown fields are rejected.
type Request struct {
	Op         string          `json:"op"`
	KeyID      string          `json:"key_id,omitempty"`
	MessageB64 string          `json:"message_b64,omitempty"`
	Catalog    json.RawMessage `json:"catalog,omitempty"`
}

// KeyInfo is the public metadata for one catalog line.
type KeyInfo struct {
	ID            string `json:"id"`
	Alg           string `json:"alg"`
	Kid           string `json:"kid,omitempty"`
	ExportPrivate bool   `json:"export_private"`
	Present       bool   `json:"present"`
}

// Response is one result. Private material is set only for export_private.
type Response struct {
	OK         bool             `json:"ok"`
	Op         string           `json:"op"`
	Error      string           `json:"error"`
	Keys       []KeyInfo        `json:"keys,omitempty"`
	KeyID      string           `json:"key_id,omitempty"`
	Signature  string           `json:"signature,omitempty"`
	PublicJWK  *keys.PublicJWK  `json:"public_jwk,omitempty"`
	PrivateJWK *keys.PrivateJWK `json:"private_jwk,omitempty"`
	Value      string           `json:"value,omitempty"`
}

// ReadBody reads one request, capped at maxBody.
func ReadBody(r io.Reader) ([]byte, string) {
	b, err := io.ReadAll(io.LimitReader(r, maxBody+1))
	if err != nil {
		return nil, ErrBadRequest
	}
	if len(b) > maxBody {
		return nil, ErrBodyTooLarge
	}
	return b, ""
}

// Handle runs one request against home.
func Handle(home string, body []byte) Response {
	if len(bytes.TrimSpace(body)) == 0 {
		return fail("", ErrBadRequest)
	}
	req, code := decode(body)
	if code != "" {
		return fail("", code)
	}
	switch req.Op {
	case "list":
		if req.KeyID != "" || req.MessageB64 != "" || len(req.Catalog) != 0 {
			return fail(req.Op, ErrUnknownField)
		}
		return list(home)
	case "put_catalog":
		if req.KeyID != "" || req.MessageB64 != "" {
			return fail(req.Op, ErrUnknownField)
		}
		return putCatalog(home, req.Catalog)
	case "generate":
		if req.MessageB64 != "" || len(req.Catalog) != 0 {
			return fail(req.Op, ErrUnknownField)
		}
		if req.KeyID == "" {
			return fail(req.Op, ErrKeyIDRequired)
		}
		return generate(home, req.KeyID)
	case "sign", "export_public", "export_private":
		return keyed(home, req)
	default:
		return fail(req.Op, ErrUnknownOp)
	}
}

func generate(home, id string) Response {
	cat, code := catalog.Load(catalog.Path(home))
	if code != "" {
		return failKey("generate", id, code)
	}
	entry, ok := cat.Find(id)
	if !ok {
		return failKey("generate", id, ErrKeyUnknown)
	}
	if code := keys.Generate(home, entry); code != "" {
		return failKey("generate", id, code)
	}
	return Response{OK: true, Op: "generate", KeyID: id}
}

func putCatalog(home string, raw []byte) Response {
	if len(raw) == 0 {
		return fail("put_catalog", catalog.ErrCatalogInvalid)
	}
	next, code := catalog.Parse(raw)
	if code != "" {
		return fail("put_catalog", code)
	}
	path := catalog.Path(home)
	prev, exists, code := catalog.Read(path)
	if code != "" {
		return fail("put_catalog", code)
	}
	onDisk, code := keys.IDsOnDisk(home)
	if code != "" {
		return fail("put_catalog", code)
	}
	if code := catalog.Admit(exists, prev, next, onDisk); code != "" {
		return fail("put_catalog", code)
	}
	if code := catalog.Write(path, next); code != "" {
		return fail("put_catalog", code)
	}
	return Response{OK: true, Op: "put_catalog"}
}

func keyed(home string, req Request) Response {
	if len(req.Catalog) != 0 {
		return fail(req.Op, ErrUnknownField)
	}
	if req.KeyID == "" {
		return fail(req.Op, ErrKeyIDRequired)
	}
	cat, code := catalog.Load(catalog.Path(home))
	if code != "" {
		return fail(req.Op, code)
	}
	entry, ok := cat.Find(req.KeyID)
	if !ok {
		return failKey(req.Op, req.KeyID, ErrKeyUnknown)
	}
	switch req.Op {
	case "sign":
		if req.MessageB64 == "" {
			return failKey(req.Op, req.KeyID, ErrMessageInvalid)
		}
		msg, err := base64.RawURLEncoding.DecodeString(req.MessageB64)
		if err != nil || len(msg) == 0 {
			return failKey(req.Op, req.KeyID, ErrMessageInvalid)
		}
		sig, code := keys.Sign(home, entry, msg)
		if code != "" {
			return failKey(req.Op, req.KeyID, code)
		}
		return Response{OK: true, Op: req.Op, KeyID: req.KeyID, Signature: sig}
	case "export_public":
		if req.MessageB64 != "" {
			return failKey(req.Op, req.KeyID, ErrUnknownField)
		}
		pub, code := keys.ExportPublic(home, entry)
		if code != "" {
			return failKey(req.Op, req.KeyID, code)
		}
		return Response{OK: true, Op: req.Op, KeyID: req.KeyID, PublicJWK: &pub}
	case "export_private":
		if req.MessageB64 != "" {
			return failKey(req.Op, req.KeyID, ErrUnknownField)
		}
		if entry.Alg == catalog.AlgRandom {
			value, code := keys.ExportRandom(home, entry)
			if code != "" {
				return failKey(req.Op, req.KeyID, code)
			}
			return Response{OK: true, Op: req.Op, KeyID: req.KeyID, Value: value}
		}
		priv, code := keys.ExportPrivateJWK(home, entry)
		if code != "" {
			return failKey(req.Op, req.KeyID, code)
		}
		return Response{OK: true, Op: req.Op, KeyID: req.KeyID, PrivateJWK: &priv}
	default:
		return fail(req.Op, ErrUnknownOp)
	}
}

func list(home string) Response {
	cat, code := catalog.Load(catalog.Path(home))
	if code != "" {
		return fail("list", code)
	}
	out := make([]KeyInfo, 0, len(cat.Keys))
	for _, e := range cat.Keys {
		out = append(out, KeyInfo{
			ID:            e.ID,
			Alg:           e.Alg,
			Kid:           e.Kid,
			ExportPrivate: e.ExportPrivate,
			Present:       keys.Present(home, e.ID),
		})
	}
	return Response{OK: true, Op: "list", Keys: out}
}

func decode(body []byte) (Request, string) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		if isUnknownField(err) {
			return Request{}, ErrUnknownField
		}
		return Request{}, ErrBadRequest
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return Request{}, ErrBadRequest
	}
	if req.Op == "" {
		return Request{}, ErrUnknownOp
	}
	return req, ""
}

func isUnknownField(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unknown field")
}

func fail(op, code string) Response {
	return Response{OK: false, Op: op, Error: code}
}

func failKey(op, id, code string) Response {
	return Response{OK: false, Op: op, KeyID: id, Error: code}
}

// Encode writes one response object and a trailing newline.
func Encode(resp Response) []byte {
	b, err := json.Marshal(resp)
	if err != nil {
		b = []byte(`{"ok":false,"op":"","error":"command_failed"}`)
	}
	return append(b, '\n')
}
