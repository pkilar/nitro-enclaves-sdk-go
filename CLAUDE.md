# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A small pure-Go library that lets code running inside an AWS Nitro Enclave use KMS's enclave
support: get an attestation document from the Nitro Security Module (NSM), then decrypt the
`CiphertextForRecipient` field KMS returns. It is a library only; there is no binary, and no KMS
client lives here.

## Commands

CI (`.github/workflows/ci.yml`) runs exactly these, and all must pass:

```sh
go vet ./...
go test -race -count=1 ./...
go build ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Run one test:

```sh
go test -race -count=1 -run 'TestDecodeCiphertextForRecipient$' ./crypto/cms
```

- Code is kept `gofmt -s` clean (`gofmt -s -l .` should print nothing). CI does not enforce it.
- Prefer `go run …@latest` for staticcheck and govulncheck over an installed binary. A binary
  built with an older Go than the one in `go.mod` fails with "export data version" internal
  errors instead of reporting findings.
- The Go version comes from the `go` directive in `go.mod`, which CI reads through
  `go-version-file`. The README's sample Dockerfile names a Go image tag too, so update both
  together.

## Architecture

Two packages, one direction of dependency: root `enclave` → `crypto/cms`.

### Root package `enclave` (`enclave.go`)

The package name is `enclave`, not the module's last path element, so callers import it with an
alias.

`EnclaveHandle` pairs an NSM session (`github.com/hf/nsm`) with an in-memory RSA key that never
leaves the process. `Attest` embeds that key's public half in the attestation document by default,
and `DecryptKMSEnvelopedKey` uses the private half to open what KMS sends back. That pairing is
the whole point of the type: KMS encrypts to the key the attestation vouches for.

- The key size is fixed at 2048 bits because the KMS `Recipient` parameter only accepts RSA-2048
  with RSAES-OAEP-SHA-256.
- `GetOrInitializeHandle` is a `sync.Once` singleton. An initialization error is cached and
  returned on every later call; there is no retry.
- The NSM device exists only inside a running enclave, so `nsm.OpenDefaultSession()` fails
  everywhere else. This package has no tests and cannot be exercised on a dev machine or in CI.
  Put logic that needs testing in `crypto/cms`, or keep it free of the NSM session.

### `crypto/cms`

A deliberately narrow parser for the one CMS `EnvelopedData` shape KMS emits. It is not a general
RFC 5652 implementation and should not grow into one.

`DecryptEnvelopedKey` runs this pipeline:

1. `ber2der` (`ber.go`) re-encodes the input. KMS sends BER with indefinite lengths, and Go's
   `encoding/asn1` accepts only DER.
2. `Parse` unmarshals into the private ASN.1 structs and rejects anything but the expected shape:
   EnvelopedData version 2, exactly one key-transport recipient, RSAES-OAEP key encryption,
   AES-256-CBC content encryption.
3. The encrypted content is either a single OCTET STRING or a constructed one whose chunks are
   concatenated. `Parse` handles both forms.
4. `EncryptedKey.Decrypt` unwraps the content key with RSA-OAEP (SHA-256), decrypts with AES-CBC,
   and strips PKCS#7 padding.

Things to preserve here:

- The input arrives over the network and is untrusted. Every offset, length, and padding value is
  checked so that malformed input returns an error and never panics. New parsing code must keep
  that property.
- The package holds no mutable package-level state. `TestDecodeCiphertextForRecipient_Concurrent`
  guards against a data race that such a variable once caused.
- `ber.go` derives from `mozilla-services/pkcs7` and has diverged with local fixes (the race, and
  several panic paths in `readObject`). Do not re-sync it wholesale from upstream.
- This directory is MIT licensed with its own `LICENSE`; the rest of the repository is Apache-2.0.
- The RSA private key and ciphertext in `cms_test.go` are a matched test fixture, not a leaked
  credential.

## Scope boundaries

- Callers make KMS requests with upstream `github.com/aws/aws-sdk-go-v2/service/kms`, which
  supports the `Recipient` field natively. This module once shipped a forked KMS client; it was
  removed on purpose, so do not add an AWS SDK dependency back.
- The module was renamed from `github.com/edgebitio/nitro-enclaves-sdk-go`. The old path appears
  in the README only as a migration note.
- Runtime dependencies are `hf/nsm` and its CBOR codec. `testify` is test-only. Keep it that way.
