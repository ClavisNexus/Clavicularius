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

## Remote command

With no arguments, the process reads one JSON object from stdin and writes one JSON object to stdout. `generate` on this path is refused.

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
