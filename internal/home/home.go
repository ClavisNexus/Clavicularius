// Package home resolves the on-disk root for the catalog and key files.
package home

import (
	"os"
	"path/filepath"
	"strings"
)

// Dir is CLAVICULARIUS_HOME, or ~/.clavicularius when that variable is unset.
func Dir() (string, error) {
	if h := strings.TrimSpace(os.Getenv("CLAVICULARIUS_HOME")); h != "" {
		return filepath.Abs(h)
	}
	user, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(user, ".clavicularius"), nil
}
