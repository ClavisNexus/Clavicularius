// Package local is the terminal-only key creation command.
package local

import (
	"bufio"
	"io"
	"strings"

	"clavicularius/internal/catalog"

	"clavicularius/internal/keys"
)

const (
	ErrNotATTY         = "not_a_tty"
	ErrConfirmRejected = "confirm_rejected"
	ErrKeyIDRequired   = "key_id_required"
	ErrKeyUnknown      = "key_unknown"
)

// RunGenerate creates one catalog key when tty is true and the reader supplies
// the line "generate".
func RunGenerate(home, keyID string, in io.Reader, tty bool) string {
	if !tty {
		return ErrNotATTY
	}
	if keyID == "" {
		return ErrKeyIDRequired
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return ErrConfirmRejected
	}
	if strings.TrimRight(line, "\r\n") != "generate" {
		return ErrConfirmRejected
	}
	cat, code := catalog.Load(catalog.Path(home))
	if code != "" {
		return code
	}
	entry, ok := cat.Find(keyID)
	if !ok {
		return ErrKeyUnknown
	}
	return keys.Generate(home, entry)
}
