package main

import (
	"fmt"
	"os"
	"strings"

	"clavicularius/internal/catalog"
	"clavicularius/internal/home"
	"clavicularius/internal/local"
	"clavicularius/internal/protocol"
)

func main() {
	if len(os.Args) == 1 {
		os.Exit(runProtocol())
	}
	switch os.Args[1] {
	case "generate":
		os.Exit(runGenerate(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: clavicularius")
	fmt.Fprintln(os.Stderr, "       clavicularius generate --key-id <id>")
}

func runProtocol() int {
	dir, err := home.Dir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "command_failed")
		return 1
	}
	body, code := protocol.ReadBody(os.Stdin)
	if code != "" {
		_, _ = os.Stdout.Write(protocol.Encode(protocol.Response{OK: false, Error: code}))
		return 0
	}
	_, _ = os.Stdout.Write(protocol.Encode(protocol.Handle(dir, body)))
	return 0
}

func runGenerate(args []string) int {
	keyID, ok := parseKeyID(args)
	if !ok {
		usage()
		return 2
	}
	dir, err := home.Dir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "command_failed")
		return 1
	}
	info, err := os.Stdin.Stat()
	tty := err == nil && info.Mode()&os.ModeCharDevice != 0
	if tty {
		if cat, code := catalog.Load(catalog.Path(dir)); code == "" {
			if entry, ok := cat.Find(keyID); ok {
				fmt.Fprintln(os.Stderr, entry.ConfirmLine())
			}
		}
		fmt.Fprintln(os.Stderr, "type generate to confirm")
	}
	code := local.RunGenerate(dir, keyID, os.Stdin, tty)
	if code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	fmt.Fprintln(os.Stderr, "created")
	return 0
}

func parseKeyID(args []string) (string, bool) {
	if len(args) != 2 || args[0] != "--key-id" {
		return "", false
	}
	id := strings.TrimSpace(args[1])
	if id == "" || strings.HasPrefix(id, "-") {
		return "", false
	}
	return id, true
}
