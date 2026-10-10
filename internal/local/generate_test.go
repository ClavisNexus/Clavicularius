package local_test

import (
	"os"
	"strings"
	"testing"

	"clavicularius/internal/catalog"
	"clavicularius/internal/keys"
	"clavicularius/internal/local"
)

func TestGenerateRequiresTTYAndConfirmation(t *testing.T) {
	home := t.TempDir()
	body := `{"keys":[{"id":"root","alg":"ES256","export_private":false,"kid":"root"}]}`
	if err := os.WriteFile(catalog.Path(home), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := local.RunGenerate(home, "root", strings.NewReader("generate\n"), false); code != local.ErrNotATTY {
		t.Fatalf("pipe: %s", code)
	}
	if keys.Present(home, "root") {
		t.Fatal("key created without a tty")
	}
	if code := local.RunGenerate(home, "root", strings.NewReader("no\n"), true); code != local.ErrConfirmRejected {
		t.Fatalf("confirm: %s", code)
	}
	if code := local.RunGenerate(home, "root", strings.NewReader("generate\n"), true); code != "" {
		t.Fatal(code)
	}
	if !keys.Present(home, "root") {
		t.Fatal("missing key")
	}
}
