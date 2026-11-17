# Nitro Enclaves SDK for Go

[![CI][ci-badge]][ci] [![Go Report Card][go-reportcard-badge]][go-reportcard] [![Go Reference][pkg.go.dev-badge]][pkg.go.dev]

A pure Go library for utilizing AWS KMS's support for Nitro Enclaves, similar to the
[AWS Nitro Enclaves SDK for C](https://github.com/aws/aws-nitro-enclaves-sdk-c).

# Usage

In order to utilize KMS's support for Nitro Enclaves from Go, we must:

1. Obtain an attestation document from the enclave's Nitro Security Module
2. Attach that attestation document to a supported KMS call
3. Decode and decrypt the `CiphertextForRecipient` field of the response

## Pre-Requisites

By default, Nitro Enclaves do not provide network connectivity, or seed the
enclave kernel's entropy pool. To simplify the process of getting a working
enclave, we'll use [Enclaver](https://github.com/edgebitio/enclaver) to automate
building of Enclave Images.

First, if you don't have one already, create a Dockerfile to build your Go app
into a Docker image:

```Dockerfile
# Build Image Stage
FROM golang:1.27-alpine AS app-builder
WORKDIR /usr/src/go-enclave-app
COPY . .
RUN go build -v -o /usr/local/bin/go-enclave-app main.go

# Release Image Stage
FROM alpine:latest AS app-container

COPY --from=app-builder /usr/local/bin/go-enclave-app /usr/local/bin/go-enclave-app
CMD ["/usr/local/bin/go-enclave-app"]
```

Now you can build your app into a Docker image by running:

```sh
go build . -t go-enclave-app
```

Now create an Enclaver manifest called `enclaver.yaml` alongside your Dockerfile:

```yaml
version: v1
name: "go-enclave-app"
target: "go-enclave-app:enclave-latest"
sources:
  app: "go-enclave-app"
egress:
  allow:
    - 169.254.169.254
    - kms.us-west-2.amazonaws.com
```

This will instruct Enclaver to build a distributable Nitro Enclaves-enabled
Docker image tagged as `go-enclave-app:enclave-latest` from the source
`go-enclave-app` image, and cause Enclaver to permit egress traffic to the local
instance metadata service and the `us-west-2` KMS endpoint.

You can test this by running:

```sh
enclaver build
```

## Obtaining an Attestation Document

Attestation documents come from the enclave's Nitro Security Module (NSM). This module talks to
it through its own [`nsm` package](https://pkg.go.dev/github.com/pkilar/nitro-enclaves-sdk-go/nsm),
which follows the request and response model of the official
[Rust NSM API](https://github.com/aws/aws-nitro-enclaves-nsm-api).

In order for KMS to use NSM attestation documents, the attestation documents
must include a public key corresponding to a private key accessible by the
enclave. For simplicity, this library abstracts generation of the key and
interactions with the Nitro Security Module behind the `EnclaveHandle`
interface:

*Note: this private key should never leave the enclave - it is OK for it to be
ephemeral, and generate a new key for each enclave instance.*

First, add this library as a dependency:

```sh
go get github.com/pkilar/nitro-enclaves-sdk-go@latest
```

Then, in your code, grab a reference to the global handle, and use it to request
an attestation document:

```go
import (
	enclave "github.com/pkilar/nitro-enclaves-sdk-go"
)

func MakeKMSRequest() error {
	enclaveHandle, err := enclave.GetOrInitializeHandle()
	if err != nil {
		return err
	}

	attestationDocument, err := enclaveHandle.Attest(enclave.AttestationOptions{})
	if err != nil {
		return err
	}

    ...
}
```

`GetOrInitializeHandle` opens the enclave's NSM device itself. If you already
hold an open [`nsm.Session`](https://pkg.go.dev/github.com/pkilar/nitro-enclaves-sdk-go/nsm#Session),
or want to substitute another device in tests, build the handle from that session
instead:

```go
	session, err := nsm.Open()
	if err != nil {
		return err
	}
	defer session.Close()

	enclaveHandle, err := enclave.NewEnclaveHandle(session)
	if err != nil {
		return err
	}
```

The handle does not take ownership of the session, so closing it stays the
caller's job.

## Making KMS Requests

Modern versions of `github.com/aws/aws-sdk-go-v2/service/kms` natively support
the Nitro Enclaves `Recipient` parameter on `Decrypt`, `GenerateDataKey`, and
`GenerateRandom`. Use the upstream SDK directly — no `replace` directive or
forked client is needed.

> **Note:** Earlier versions of this project (previously published at
> `github.com/edgebitio/nitro-enclaves-sdk-go`) included a forked KMS client
> at `github.com/edgebitio/nitro-enclaves-sdk-go/kms` for use as a drop-in
> replacement. That fork has been removed; consumers should switch to the
> upstream `aws-sdk-go-v2/service/kms` package.

```sh
go get github.com/aws/aws-sdk-go-v2/service/kms@latest
```

You can then instantiate the upstream KMS client and include an attestation
document on supported operations via the `Recipient` input field:

```go
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	if err != nil {
		return err
	}

	kmsClient := kms.NewFromConfig(cfg)

	// Request a 32 byte data key from KMS, for use in AES-256 operations.
	dataKeyRes, err := kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String("arn:aws:kms:us-west-2:xxxxxxxxxx:key/12345678-abcd-ef12-1234-abcdef123456"),
		KeySpec: types.DataKeySpecAes256,
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDocument,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	})
	if err != nil {
		return err
	}
```

## Decoding and Decrypting KMS Responses

When you include a `Recipient` field on a Decrypt, GenerateDataKey, or
GenerateRandom KMS call, KMS returns a null `Plaintext` field, and instead
includes the plaintext data in an encrypted form in the `CiphertextForRecipient`
field.

The `EnclaveHandle` interface provides the ability to decrypt this field using
the private key it generated for the enclave:

```go
	if dataKeyRes.CiphertextForRecipient == nil {
		return fmt.Errorf("CiphertextForRecipient is nil")
	}

	key, err := enclaveHandle.DecryptKMSEnvelopedKey(dataKeyRes.CiphertextForRecipient)
	if err != nil {
		return err
	}

	fmt.Printf("key: %v", key)
```

Now you can use `key` to encrypt data! To persist the encrypted data, you'll need
to also persist the value of `CiphertextBlob`, which can be decrypted at any time
using KMS.

## Separation of Duties

Note that anyone with the ability to perform `Decrypt` calls using your KMS key
will be able to decrypt the data key in `CiphertextBlob`, so for this to be useful
you will likely want:

1. To use a KMS Key Policy to lock down access to the KMS key such that only
   authorized enclave images are permitted to perform `Decrypt` operations.
   See the [AWS docs](https://docs.aws.amazon.com/enclaves/latest/user/kms.html)
   for details.
2. To ensure that only trusted users have permission to modify the KMS key policy
   - ideally these would be a completely different set of users than those who
   have normal production access, so that Nitro Enclaves + KMS can be used to
   enforce separation of duties.


## Other NSM Requests

Besides attestation, the handle exposes the rest of the NSM API:

```go
	description, err := enclaveHandle.Describe()    // version, module ID, PCR count, digest
	pcr, err := enclaveHandle.DescribePCR(16)       // value and lock state
	value, err := enclaveHandle.ExtendPCR(16, data) // returns the PCR's new value
	err = enclaveHandle.LockPCR(16)                 // read-only until the enclave terminates
	err = enclaveHandle.LockPCRs(32)                // locks PCRs [0, 32)
	n, err := enclaveHandle.Read(buf)               // entropy from the NSM
```

When the NSM refuses a request, the error wraps an `*nsm.Error` whose `Code` says why:

```go
	var nsmErr *nsm.Error
	if errors.As(err, &nsmErr) && nsmErr.Code == response.ECReadOnlyIndex {
		// the PCR is locked
	}
```

`nsm.ParseAttestationDoc` decodes the content of an attestation document into an
`nsm.AttestationDoc`. It takes the payload of the document's COSE_Sign1 envelope and verifies
nothing, so check the envelope's signature and certificate chain before trusting what it returns.

## Checking an Enclave's NSM

`cmd/nsm-check` runs a series of checks against the NSM of the enclave it is started in, in the
manner of `nsm-check` from the Rust NSM API. It reads the NSM's description and PCRs, requests
attestation documents and reads random bytes. With `-pcr-writes` it also extends and locks PCRs.

It only works where there is an NSM, so the `Makefile` wraps it in an Enclave Image File (EIF)
and runs that in an enclave:

```sh
make eif   # compile nsm-check, put it in a container image, build build/nsm-check-<arch>.eif
make run   # run the EIF in an enclave, show its console, report PASS or FAIL
```

`make qemu` runs it against QEMU's emulated NSM, which needs no AWS; see
[below](#in-qemu-without-aws). `make help` lists every target and variable.

### What the machine needs

Run both commands on the parent instance, an EC2 instance with Nitro Enclaves enabled. It needs:

- `nitro-cli`, set up as the [AWS guide][nitro-cli-install] describes, with the
  `nitro-enclaves-allocator` service running. `nitro-cli` opens `/dev/nitro_enclaves`, which
  belongs to root and the `ne` group. If your user is not in that group, `make run` and
  `make terminate` call `nitro-cli` through `sudo`, which may ask for your password.
- Docker, running, with your user in the `docker` group. `nitro-cli` reads the image from it.
- `make`, and Go at the version `go.mod` names.
- 1 vCPU and 512 MiB free in the allocator's pool, which `/etc/nitro_enclaves/allocator.yaml`
  sizes. An enclave that is already running holds part of the pool. `make run CPU_COUNT=2
  MEMORY=1024` asks for a different amount. An enclave gets whole cores, so on an instance whose
  cores have two threads the count must be even; with one vCPU there, `nitro-cli` reports that
  full CPU cores have not been set.

An EIF can be built elsewhere and copied over, as long as the machine that builds it has
`nitro-cli`, Docker and the architecture of the instance. Copy `Makefile` and `build/` to the
instance: `make run` uses the EIF it finds and builds one only when there is none.

### Reading the result

`make run` starts the enclave in debug mode with its console attached, because the console is the
only place an enclave can show output. After the kernel's boot messages come one line per check
and then the verdict:

```
ok    NSM description
ok    PCR lengths
ok    initial PCR state
ok    attestation
ok    random bytes
nsm-check: all checks passed
```

The enclave shuts down when `nsm-check` exits. `make run` then prints `PASS`, or prints `FAIL` and
exits with an error when the verdict line is missing. A check that fails prints
`FAIL  <check>: <reason>`. The console output is kept in `build/nsm-check-<arch>.console.log`.
Should the enclave still be running, `make terminate` stops it.

An enclave in debug mode gets attestation documents whose PCRs are made up entirely of zeros.
`nsm-check` does not look at those values.

### Running every check

```sh
make run PCR_WRITES=1
```

This builds a second EIF, `build/nsm-check-pcr-writes-<arch>.eif`, which runs
`nsm-check -pcr-writes`. That adds four checks, which extend PCRs 16 and up and then lock every
PCR. The changes last until the enclave terminates, which here is when the run ends. Give
`-pcr-writes` only in an enclave started for the purpose, never in one that does other work.

### In QEMU, without AWS

`make qemu` runs the same binary on a workstation. It boots the kernel and the NSM driver that
`nitro-cli` puts in every EIF, in QEMU, against QEMU's emulated NSM device:

```sh
make qemu                # the checks that only read
make qemu PCR_WRITES=1   # every check
```

It prints the same lines and the same `PASS` or `FAIL`, and keeps the console output in
`build/nsm-check-<arch>.qemu.log`. It needs:

- `qemu-system-x86_64` from QEMU 9.2 or later, built with the NSM device (`virtio-nsm-device`).
  QEMU emulates the NSM for x86-64 guests only. It uses KVM when it can and runs without it.
- `bzImage` and `nsm.ko` from `nitro-cli`'s x86-64 blobs. They are looked for in
  `/usr/share/nitro_enclaves/blobs`, or in `NITRO_CLI_BLOBS` when that is set.
- `cpio`, `make` and Go.

The guest's init is `internal/qemuinit`. It loads the driver and locks PCRs 0 to 15, which an
enclave's init and the hypervisor do in a real enclave, and then runs `nsm-check`.

This checks the driver against the kernel module that enclaves load and against an NSM written by
someone else, which no unit test can. It does not check AWS's NSM, and it does not boot an EIF.
Run it before `make run`, not in place of it.

### Without make

`make run` runs this, with `sudo` in front where it is needed, and then looks for the verdict line
in the output:

```sh
nitro-cli run-enclave --eif-path build/nsm-check-<arch>.eif --enclave-name nsm-check \
    --cpu-count 1 --memory 512 --attach-console
```

[nitro-cli-install]: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html

[ci-badge]: https://github.com/pkilar/nitro-enclaves-sdk-go/actions/workflows/ci.yml/badge.svg?branch=main
[ci]: https://github.com/pkilar/nitro-enclaves-sdk-go/actions/workflows/ci.yml
[go-reportcard-badge]: https://goreportcard.com/badge/github.com/pkilar/nitro-enclaves-sdk-go
[go-reportcard]: https://goreportcard.com/report/github.com/pkilar/nitro-enclaves-sdk-go
[pkg.go.dev-badge]: https://pkg.go.dev/badge/github.com/pkilar/nitro-enclaves-sdk-go.svg
[pkg.go.dev]: https://pkg.go.dev/github.com/pkilar/nitro-enclaves-sdk-go