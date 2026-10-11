# Clavicularius

A local key custodian. It generates keys, stores them on this machine, and signs bytes you pass in. It does not interpret those bytes, and it does not name any other system.

The module uses only the Go standard library.

## Build

```bash
go build -o clavicularius ./cmd/clavicularius
```

Go 1.25 or newer.

## Layout

`CLAVICULARIUS_HOME`, or `~/.clavicularius` when that variable is unset:

| Path | Mode | Contents |
| --- | --- | --- |
| `catalog.json` | `0600` | Which keys exist. No private bytes. |
| `keys/` | `0700` | One `0600` file per generated key. |
| `server.key` | `0600` | TLS key for `serve`. Not encrypted with a passphrase. |
| `server.crt` | `0600` | Certificate for that key. |
| `callers/` | `0700` | One `0600` leaf certificate per caller. No private bytes. |

Copy [`examples/catalog.json`](examples/catalog.json) to `catalog.json` and edit it, or replace the file with `put_catalog`. A new key is a new line in that file, then a local generate. The binary stays the same.

A catalog line has `id`, `alg`, and `export_private`.

| `alg` | Extra fields | Signature or value |
| --- | --- | --- |
| `ES256` | `kid` | P-256, SHA-256. Raw `r \|\| s`, 64 bytes, base64url. Not ASN.1 DER. |
| `Ed25519` | `kid` | 64 raw bytes, base64url. Private JWK `d` is the 32-byte seed. |
| `random` | `bytes` (1–256), `encoding` (`hex` or `base64`) | No public key. `export_private` returns the encoded value. `export_private` must be true. |

`export_private: false` keeps the private bytes on this machine. `sign` and `export_public` still work.

Modes wider than `0600`, and symbolic links, are refused.

## Generate

Run this at a terminal on the machine that holds the keys:

```bash
clavicularius generate --key-id root
```

The program prints `id`, `alg`, and `export_private`, then asks you to type `generate`. A pipe, or any stdin that is not a terminal, is refused. An existing key file is not overwritten.

## Listen

On the machine that holds the keys:

```bash
clavicularius init
```

This writes `server.key` and `server.crt`. Standard output is one line: the lowercase SHA-256 of the server subject public key info. A second `init` prints `already_present` and does not overwrite the files.

On the machine that will call:

```bash
clavicularius caller-key --out caller.json --cert-out caller.crt
```

The program reads a passphrase from the terminal, then asks for it again. The two lines must match. An empty passphrase is refused. `caller.json` is the encrypted private key (`0600`). `cert-out` is the public certificate. Copy only the certificate to the key machine.

`caller.json` is a JSON object with `v` 1, `kdf` `pbkdf2-sha256`, `iterations` 600000, and `salt`, `nonce`, and `ciphertext` as unpadded base64url. The plaintext is a JSON object with `key_pkcs8_b64` and `cert_pem`. Salt is 16 bytes, the nonce is 12 bytes, and the cipher is AES-256-GCM.

```bash
clavicularius caller add --name lab < caller.crt
clavicularius caller remove --name lab
```

`name` matches `[a-z0-9][a-z0-9-]{0,31}`. The certificate must be one self-signed P-256 leaf. A CA certificate is refused. An existing name is left in place (`already_present`).

```bash
clavicularius serve --listen 192.0.2.10:8756
clavicularius serve --listen 192.0.2.10:8756 --for 8h
```

`serve` exits before it listens when the address is a hostname, an unspecified address (`0.0.0.0` or `::`), or a port below 1024. It also exits when the server key is missing, when no caller certificate is registered, or when a file it needs is a symbolic link or wider than `0600`. Listening is TLS 1.3. Each connection accepts one `POST /` and then closes. The body is one JSON object, the same object as the no-argument process below. Restart `serve` after adding or removing a caller. `--for` stops the process when the duration ends. Certificates are valid for 100 years. Replacing a caller is `caller-key`, then `caller add`, then `caller remove`. The server pin changes when `init` creates a new server key.

```bash
clavicularius call --server https://192.0.2.10:8756/ --pin <hex> --key caller.json
```

`call` reads the passphrase from the terminal and one JSON object from stdin. It writes one JSON object to stdout. It does not send the body when the server pin differs from `--pin`.

Command errors on stderr include `already_present`, `no_caller`, `listen_invalid`, `caller_unknown`, `caller_invalid`, `caller_locked`, `pin_mismatch`, `key_absent`, `key_perms`, `key_symlink`, `key_invalid`, `bad_request`.

## One shot

With no arguments, the process reads one JSON object from stdin and writes one JSON object to stdout. `serve` handles the same object. `generate` on this path is refused.

Requests:

```json
{"op":"list"}
{"op":"sign","key_id":"root","message_b64":"<raw message, base64url>"}
{"op":"export_public","key_id":"root"}
{"op":"export_private","key_id":"export-a"}
{"op":"put_catalog","catalog":{"keys":[{"id":"root","alg":"ES256","export_private":false,"kid":"root"}]}}
```

`put_catalog` replaces `catalog.json` and sets mode `0600`. It refuses with `catalog_rejected` when the replacement would:

- set `export_private` from false to true for an id already in the catalog
- drop an id whose `export_private` is false
- drop, or change `alg`, `kid`, `bytes`, or `encoding` of, an id that already has a key file
- install the first catalog while a key file is already present
- adopt a key file whose id is not in the current catalog

A line with no key file yet can be added. Its `alg`, `kid`, `bytes`, and `encoding` can still be corrected. `export_private` can change from true to false. A line with `export_private` true and no key file can be removed. Supplying the same catalog again is accepted. A person on this machine can still replace the file directly.

`sign` signs the decoded message bytes. For `ES256` it hashes those bytes with SHA-256, the same way WebCrypto `subtle.sign` does. It does not parse the message.

A response has `ok` and `error`. `error` is an empty string on success. Codes include `bad_request`, `unknown_field`, `body_too_large`, `unknown_op`, `key_id_required`, `key_unknown`, `key_absent`, `export_forbidden`, `no_public_key`, `not_a_signing_key`, `generate_local_only`, `catalog_missing`, `catalog_invalid`, `catalog_perms`, `catalog_symlink`, `catalog_rejected`, `key_perms`, `key_symlink`, `key_invalid`.

`list` and `export_public` do not include private components.

## Tests

```bash
go test ./...
```

`testdata/webcrypto-es256.json` and `testdata/webcrypto-ed25519.json` are throwaway keys produced by [`scripts/webcrypto-vector.mjs`](scripts/webcrypto-vector.mjs). They check that signatures from WebCrypto verify here.
