//go:build !darwin && !linux

package tty

import "clavicularius/internal/keyfile"

// Read refuses passphrase entry on systems without a local tty implementation.
func Read() ([]byte, error) {
	return ReadPrompt("passphrase")
}

// ReadPrompt refuses passphrase entry on systems without a local tty implementation.
func ReadPrompt(string) ([]byte, error) {
	return nil, keyfile.ErrLocked
}
