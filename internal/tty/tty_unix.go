//go:build darwin || linux

package tty

import (
	"bytes"
	"io"
	"os"
	"syscall"

	"clavicularius/internal/keyfile"
)

// Read reads one passphrase from /dev/tty with echo off.
func Read() ([]byte, error) {
	return ReadPrompt("passphrase")
}

// ReadPrompt is Read with a custom prompt line written to the tty.
func ReadPrompt(prompt string) ([]byte, error) {
	if prompt == "" {
		prompt = "passphrase"
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, keyfile.ErrLocked
	}
	defer f.Close()
	old, err := getTermios(int(f.Fd()))
	if err != nil {
		return nil, keyfile.ErrLocked
	}
	next := *old
	next.Lflag &^= syscall.ECHO | syscall.ECHOE | syscall.ECHOK | syscall.ECHONL
	if err := setTermios(int(f.Fd()), &next); err != nil {
		return nil, keyfile.ErrLocked
	}
	defer func() { _ = setTermios(int(f.Fd()), old) }()
	if _, err := io.WriteString(f, prompt+"\n"); err != nil {
		return nil, keyfile.ErrLocked
	}

	buf := make([]byte, 1025)
	n := 0
	for n < len(buf) {
		r, rerr := f.Read(buf[n:])
		if r > 0 {
			n += r
			if bytes.Contains(buf[:n], []byte{'\n'}) {
				break
			}
		}
		if rerr != nil {
			wipe(buf)
			return nil, keyfile.ErrLocked
		}
	}
	if !bytes.Contains(buf[:n], []byte{'\n'}) || n > 1024 {
		wipe(buf)
		return nil, keyfile.ErrLocked
	}
	line := bytes.TrimRight(buf[:n], "\r\n")
	if len(line) == 0 {
		wipe(buf)
		return nil, keyfile.ErrLocked
	}
	out := make([]byte, len(line))
	copy(out, line)
	wipe(buf)
	_, _ = io.WriteString(f, "\n")
	return out, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
