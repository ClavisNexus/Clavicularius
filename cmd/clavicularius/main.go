package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"clavicularius/internal/catalog"
	"clavicularius/internal/home"
	"clavicularius/internal/keyfile"
	"clavicularius/internal/local"
	"clavicularius/internal/protocol"
	"clavicularius/internal/remote"
	"clavicularius/internal/tty"
)

func main() {
	if len(os.Args) == 1 {
		os.Exit(runProtocol())
	}
	switch os.Args[1] {
	case "generate":
		os.Exit(runGenerate(os.Args[2:]))
	case "init":
		os.Exit(runInit(os.Args[2:]))
	case "caller-key":
		os.Exit(runCallerKey(os.Args[2:]))
	case "caller":
		os.Exit(runCaller(os.Args[2:]))
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "call":
		os.Exit(runCall(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: clavicularius")
	fmt.Fprintln(os.Stderr, "       clavicularius generate --key-id <id>")
	fmt.Fprintln(os.Stderr, "       clavicularius init")
	fmt.Fprintln(os.Stderr, "       clavicularius caller-key --out <file> --cert-out <file>")
	fmt.Fprintln(os.Stderr, "       clavicularius caller add --name <name>")
	fmt.Fprintln(os.Stderr, "       clavicularius caller remove --name <name>")
	fmt.Fprintln(os.Stderr, "       clavicularius serve --listen <ip:port> [--for <duration>]")
	fmt.Fprintln(os.Stderr, "       clavicularius call --server <url> --pin <hex> --key <file>")
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
	ttyOn := err == nil && info.Mode()&os.ModeCharDevice != 0
	if ttyOn {
		if cat, code := catalog.Load(catalog.Path(dir)); code == "" {
			if entry, ok := cat.Find(keyID); ok {
				fmt.Fprintln(os.Stderr, entry.ConfirmLine())
			}
		}
		fmt.Fprintln(os.Stderr, "type generate to confirm")
	}
	code := local.RunGenerate(dir, keyID, os.Stdin, ttyOn)
	if code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	fmt.Fprintln(os.Stderr, "created")
	return 0
}

func runInit(args []string) int {
	if len(args) != 0 {
		usage()
		return 2
	}
	dir, code := homeDir()
	if code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	pin, code := remote.Init(dir)
	if code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	fmt.Println(pin)
	return 0
}

func runCallerKey(args []string) int {
	flags, ok := parseFlags(args)
	if !ok || len(flags) != 2 || flags["out"] == "" || flags["cert-out"] == "" {
		usage()
		return 2
	}
	pass, err := tty.ReadPrompt("passphrase")
	if err != nil {
		fmt.Fprintln(os.Stderr, remote.ErrCallerLocked)
		return 1
	}
	defer keyfile.Wipe(pass)
	again, err := tty.ReadPrompt("repeat passphrase")
	if err != nil {
		fmt.Fprintln(os.Stderr, remote.ErrCallerLocked)
		return 1
	}
	defer keyfile.Wipe(again)
	if !bytesEqual(pass, again) {
		fmt.Fprintln(os.Stderr, remote.ErrCallerLocked)
		return 1
	}
	if code := remote.CreateCallerKey(flags["out"], flags["cert-out"], pass); code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	return 0
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func runCaller(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "add":
		return runCallerAdd(args[1:])
	case "remove":
		return runCallerRemove(args[1:])
	default:
		usage()
		return 2
	}
}

func runCallerAdd(args []string) int {
	flags, ok := parseFlags(args)
	if !ok || len(flags) != 1 || flags["name"] == "" {
		usage()
		return 2
	}
	dir, code := homeDir()
	if code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 16*1024+1))
	if err != nil || len(body) > 16*1024 {
		fmt.Fprintln(os.Stderr, remote.ErrCallerInvalid)
		return 1
	}
	if code := remote.AddCaller(dir, flags["name"], body); code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	return 0
}

func runCallerRemove(args []string) int {
	flags, ok := parseFlags(args)
	if !ok || len(flags) != 1 || flags["name"] == "" {
		usage()
		return 2
	}
	dir, code := homeDir()
	if code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	if code := remote.RemoveCaller(dir, flags["name"]); code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	return 0
}

func runServe(args []string) int {
	flags, ok := parseFlags(args)
	if !ok || flags["listen"] == "" || len(flags) > 2 || (len(flags) == 2 && flags["for"] == "") {
		usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if raw := flags["for"]; raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			usage()
			return 2
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	dir, code := homeDir()
	if code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	if code := remote.Serve(ctx, dir, flags["listen"]); code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	return 0
}

func runCall(args []string) int {
	flags, ok := parseFlags(args)
	if !ok || len(flags) != 3 || flags["server"] == "" || flags["pin"] == "" || flags["key"] == "" {
		usage()
		return 2
	}
	pass, err := tty.Read()
	if err != nil {
		fmt.Fprintln(os.Stderr, remote.ErrCallerLocked)
		return 1
	}
	defer keyfile.Wipe(pass)
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 512*1024+1))
	if err != nil || len(body) > 512*1024 {
		fmt.Fprintln(os.Stderr, protocol.ErrBodyTooLarge)
		return 1
	}
	resp, code := remote.Call(context.Background(), flags["server"], flags["pin"], flags["key"], pass, body)
	if code != "" {
		fmt.Fprintln(os.Stderr, code)
		return 1
	}
	_, _ = os.Stdout.Write(resp)
	return 0
}

func homeDir() (string, string) {
	dir, err := home.Dir()
	if err != nil {
		return "", "command_failed"
	}
	return dir, ""
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

func parseFlags(args []string) (map[string]string, bool) {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") || len(a) == 2 || strings.Contains(a[2:], "=") {
			return nil, false
		}
		name := a[2:]
		if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
			return nil, false
		}
		i++
		if _, dup := out[name]; dup {
			return nil, false
		}
		out[name] = args[i]
	}
	return out, true
}
