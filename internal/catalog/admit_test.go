package catalog

import "testing"

func es(id string, export bool) Entry {
	return Entry{ID: id, Alg: AlgES256, ExportPrivate: export, Kid: id}
}

func TestAdmitKeepsNonExportableLines(t *testing.T) {
	prev := Catalog{Keys: []Entry{es("root", false), es("export-a", true)}}
	cases := []struct {
		name   string
		next   Catalog
		onDisk map[string]struct{}
		want   string
	}{
		{
			name: "same",
			next: prev,
		},
		{
			name: "add",
			next: Catalog{Keys: []Entry{es("root", false), es("export-a", true), es("next", true)}},
		},
		{
			name: "tighten",
			next: Catalog{Keys: []Entry{es("root", false), es("export-a", false)}},
		},
		{
			name: "drop unpublished exportable",
			next: Catalog{Keys: []Entry{es("root", false)}},
		},
		{
			name: "widen before generate",
			next: Catalog{Keys: []Entry{es("root", true), es("export-a", true)}},
			want: ErrCatalogRejected,
		},
		{
			name: "drop non-exportable before generate",
			next: Catalog{Keys: []Entry{es("export-a", true)}},
			want: ErrCatalogRejected,
		},
		{
			name:   "change kid after generate",
			next:   Catalog{Keys: []Entry{{ID: "root", Alg: AlgES256, Kid: "other"}, es("export-a", true)}},
			onDisk: map[string]struct{}{"root": {}},
			want:   ErrCatalogRejected,
		},
		{
			name:   "drop after generate",
			next:   Catalog{Keys: []Entry{es("export-a", true)}},
			onDisk: map[string]struct{}{"root": {}},
			want:   ErrCatalogRejected,
		},
		{
			name:   "orphan file",
			next:   prev,
			onDisk: map[string]struct{}{"root": {}, "stray": {}},
			want:   ErrCatalogRejected,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Admit(true, prev, tc.next, tc.onDisk); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	if got := Admit(false, Catalog{}, prev, map[string]struct{}{"root": {}}); got != ErrCatalogRejected {
		t.Fatalf("first catalog with a key file: %s", got)
	}
	if got := Admit(false, Catalog{}, prev, nil); got != "" {
		t.Fatalf("first catalog: %s", got)
	}
}

func TestConfirmLine(t *testing.T) {
	got := (Entry{ID: "root", Alg: AlgES256, Kid: "root"}).ConfirmLine()
	if got != "id=root alg=ES256 export_private=false kid=root" {
		t.Fatal(got)
	}
	got = (Entry{ID: "random-a", Alg: AlgRandom, ExportPrivate: true, Bytes: 32, Encoding: EncodingHex}).ConfirmLine()
	if got != "id=random-a alg=random export_private=true bytes=32 encoding=hex" {
		t.Fatal(got)
	}
}
