package protocol_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"clavicularius/internal/catalog"
	"clavicularius/internal/keys"
	"clavicularius/internal/protocol"
)

func TestProtocolHidesPrivateMaterial(t *testing.T) {
	home := t.TempDir()
	writeCatalog(t, home, `{
	  "keys": [
	    {"id": "root", "alg": "ES256", "export_private": false, "kid": "root"},
	    {"id": "export-a", "alg": "Ed25519", "export_private": true, "kid": "export-a"},
	    {"id": "random-a", "alg": "random", "export_private": true, "bytes": 32, "encoding": "base64"}
	  ]
	}`)
	if code := keys.Generate(home, catalog.Entry{ID: "root", Alg: catalog.AlgES256, Kid: "root"}); code != "" {
		t.Fatal(code)
	}
	if code := keys.Generate(home, catalog.Entry{ID: "export-a", Alg: catalog.AlgEd25519, ExportPrivate: true, Kid: "export-a"}); code != "" {
		t.Fatal(code)
	}
	if code := keys.Generate(home, catalog.Entry{ID: "random-a", Alg: catalog.AlgRandom, ExportPrivate: true, Bytes: 32, Encoding: catalog.EncodingBase64}); code != "" {
		t.Fatal(code)
	}
	priv, code := keys.ExportPrivateJWK(home, catalog.Entry{ID: "export-a", Alg: catalog.AlgEd25519, ExportPrivate: true, Kid: "export-a"})
	if code != "" {
		t.Fatal(code)
	}

	listed := protocol.Encode(protocol.Handle(home, []byte(`{"op":"list"}`)))
	if strings.Contains(string(listed), priv.D) || strings.Contains(string(listed), `"d"`) {
		t.Fatalf("list leaked private material: %s", listed)
	}

	pub := protocol.Handle(home, []byte(`{"op":"export_public","key_id":"root"}`))
	pubJSON := protocol.Encode(pub)
	if !pub.OK || strings.Contains(string(pubJSON), `"d"`) {
		t.Fatalf("public: %s", pubJSON)
	}

	denied := protocol.Encode(protocol.Handle(home, []byte(`{"op":"export_private","key_id":"root"}`)))
	if strings.Contains(string(denied), `"d"`) || !strings.Contains(string(denied), "export_forbidden") {
		t.Fatalf("denied export: %s", denied)
	}

	msg := base64.RawURLEncoding.EncodeToString([]byte("hello"))
	signed := protocol.Handle(home, []byte(`{"op":"sign","key_id":"root","message_b64":"`+msg+`"}`))
	if !signed.OK || signed.Signature == "" || strings.Contains(signed.Signature, priv.D) {
		t.Fatalf("sign %+v", signed)
	}
	rawSig, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(rawSig) != 64 {
		t.Fatalf("sig %d %v", len(rawSig), err)
	}

	exported := protocol.Handle(home, []byte(`{"op":"export_private","key_id":"export-a"}`))
	if !exported.OK || exported.PrivateJWK == nil || exported.PrivateJWK.D != priv.D {
		t.Fatalf("export %+v", exported)
	}
	random := protocol.Handle(home, []byte(`{"op":"export_private","key_id":"random-a"}`))
	if !random.OK || random.Value == "" || random.PrivateJWK != nil {
		t.Fatalf("random %+v", random)
	}
	gen := protocol.Handle(home, []byte(`{"op":"generate","key_id":"root"}`))
	if gen.OK || gen.Error != protocol.ErrGenerateLocalOnly {
		t.Fatalf("generate %+v", gen)
	}
}

func TestProtocolRejectsBadRequests(t *testing.T) {
	home := t.TempDir()
	writeCatalog(t, home, `{"keys":[]}`)
	cases := []struct {
		body string
		err  string
	}{
		{``, protocol.ErrBadRequest},
		{`{"op":"list","extra":1}`, protocol.ErrUnknownField},
		{`{"op":"nope"}`, protocol.ErrUnknownOp},
		{`{"op":"sign"}`, protocol.ErrKeyIDRequired},
		{`{"op":"sign","key_id":"missing","message_b64":"YQ"}`, protocol.ErrKeyUnknown},
	}
	for _, tc := range cases {
		resp := protocol.Handle(home, []byte(tc.body))
		if resp.OK || resp.Error != tc.err {
			t.Fatalf("%s -> %+v", tc.body, resp)
		}
	}
	big := make([]byte, 512*1024+1)
	if _, code := protocol.ReadBody(strings.NewReader(string(big))); code != protocol.ErrBodyTooLarge {
		t.Fatal(code)
	}
}

func TestExampleCatalogParses(t *testing.T) {
	b, err := os.ReadFile("../../examples/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, code := catalog.Parse(b); code != "" {
		t.Fatal(code)
	}
	if _, code := catalog.Load("../../examples/catalog.json"); code != catalog.ErrCatalogPerms {
		t.Fatalf("example file should not be loaded in place: %s", code)
	}
}

func writeCatalog(t *testing.T, home, body string) {
	t.Helper()
	if err := os.WriteFile(catalog.Path(home), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPutCatalogSuppliesAndRefusesWidening(t *testing.T) {
	home := t.TempDir()
	first := []byte(`{"keys":[
	  {"id":"root","alg":"ES256","export_private":false,"kid":"root"},
	  {"id":"export-a","alg":"Ed25519","export_private":true,"kid":"export-a"}
	]}`)
	resp := protocol.Handle(home, putBody(t, first))
	if !resp.OK || resp.Op != "put_catalog" || resp.Error != "" || resp.PrivateJWK != nil {
		t.Fatalf("%+v", resp)
	}
	info, err := os.Stat(catalog.Path(home))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	before, err := os.ReadFile(catalog.Path(home))
	if err != nil {
		t.Fatal(err)
	}
	widened := []byte(`{"keys":[
	  {"id":"root","alg":"ES256","export_private":true,"kid":"root"},
	  {"id":"export-a","alg":"Ed25519","export_private":true,"kid":"export-a"}
	]}`)
	denied := protocol.Handle(home, putBody(t, widened))
	if denied.OK || denied.Error != catalog.ErrCatalogRejected {
		t.Fatalf("%+v", denied)
	}
	after, err := os.ReadFile(catalog.Path(home))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("catalog changed:\n%s", after)
	}
	if code := keys.Generate(home, catalog.Entry{ID: "root", Alg: catalog.AlgES256, Kid: "root"}); code != "" {
		t.Fatal(code)
	}
	changed := []byte(`{"keys":[
	  {"id":"root","alg":"ES256","export_private":false,"kid":"other"},
	  {"id":"export-a","alg":"Ed25519","export_private":true,"kid":"export-a"}
	]}`)
	if resp := protocol.Handle(home, putBody(t, changed)); resp.Error != catalog.ErrCatalogRejected {
		t.Fatalf("%+v", resp)
	}
	added := []byte(`{"keys":[
	  {"id":"root","alg":"ES256","export_private":false,"kid":"root"},
	  {"id":"export-a","alg":"Ed25519","export_private":true,"kid":"export-a"},
	  {"id":"next","alg":"ES256","export_private":true,"kid":"next"}
	]}`)
	if resp := protocol.Handle(home, putBody(t, added)); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	cat, code := catalog.Load(catalog.Path(home))
	if code != "" {
		t.Fatal(code)
	}
	if _, ok := cat.Find("next"); !ok {
		t.Fatal("missing added line")
	}
	again := protocol.Handle(home, putBody(t, added))
	if !again.OK {
		t.Fatalf("resupply %+v", again)
	}
	if resp := protocol.Handle(home, []byte(`{"op":"put_catalog","key_id":"root"}`)); resp.Error != protocol.ErrUnknownField {
		t.Fatalf("%+v", resp)
	}
	if resp := protocol.Handle(home, []byte(`{"op":"list","catalog":{"keys":[]}}`)); resp.Error != protocol.ErrUnknownField {
		t.Fatalf("%+v", resp)
	}
}

func TestPutCatalogRefusesOrphanAndWideMode(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(home+"/keys", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home+"/keys/root.json", []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	body := putBody(t, []byte(`{"keys":[{"id":"root","alg":"ES256","export_private":true,"kid":"root"}]}`))
	if resp := protocol.Handle(home, body); resp.Error != catalog.ErrCatalogRejected {
		t.Fatalf("orphan %+v", resp)
	}
	home = t.TempDir()
	if err := os.WriteFile(catalog.Path(home), []byte(`{"keys":[{"id":"root","alg":"ES256","export_private":false,"kid":"root"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(catalog.Path(home), 0o644); err != nil {
		t.Fatal(err)
	}
	if resp := protocol.Handle(home, body); resp.Error != catalog.ErrCatalogPerms {
		t.Fatalf("perms %+v", resp)
	}
	home = t.TempDir()
	target := home + "/real.json"
	if err := os.WriteFile(target, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, catalog.Path(home)); err != nil {
		t.Fatal(err)
	}
	if resp := protocol.Handle(home, []byte(`{"op":"put_catalog","catalog":{"keys":[]}}`)); resp.Error != catalog.ErrCatalogSymlink {
		t.Fatalf("symlink %+v", resp)
	}
}

func putBody(t *testing.T, catalogJSON []byte) []byte {
	t.Helper()
	body, err := json.Marshal(struct {
		Op      string          `json:"op"`
		Catalog json.RawMessage `json:"catalog"`
	}{Op: "put_catalog", Catalog: catalogJSON})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestEncodeIsJSON(t *testing.T) {
	var resp protocol.Response
	if err := json.Unmarshal(protocol.Encode(protocol.Response{OK: true, Op: "list", Keys: []protocol.KeyInfo{}}), &resp); err != nil {
		t.Fatal(err)
	}
}
