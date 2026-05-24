package enclave

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"

	"github.com/pkilar/nitro-enclaves-sdk-go/crypto/cms"
)

// defaultKeyBits is fixed at 2048 because KMS Recipient currently only accepts
// RSA-2048 with OAEP-SHA-256 (per the AWS KMS Recipient documentation). If KMS
// adds larger key sizes, lift this into AttestationOptions.
const defaultKeyBits = 2048

var (
	globalHandle *EnclaveHandle
	initErr      error
	initOnce     sync.Once
)

type AttestationOptions struct {
	// Nonce is an optional cryptographic nonce which may be signed as part of the attestation
	// for use by applications in preventing replay attacks.
	Nonce []byte

	// UserData is an optional opaque blob which will be signed as part of the attestation
	// for application-defined purposes.
	UserData []byte

	// NoPublicKey will prevent the default public key from being included in the attestation.
	NoPublicKey bool

	// PublicKey is an optional public key which will be included in the attestation. Valid types
	// are *rsa.PublicKey, *ecdsa.PublicKey, and ed25519.PublicKey.
	PublicKey any
}

// EnclaveHandle represents a handle to a Nitro Enclave, including the local
// Nitro Security Module, and an in-memory 2048 bit RSA key pair, the public key
// from which can be automatically included in requested attestation documents.
type EnclaveHandle struct {
	nsm *nsm.Session
	key *rsa.PrivateKey
}

func (enclave *EnclaveHandle) initialize() error {
	var err error

	enclave.nsm, err = nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("nsm: open session: %w", err)
	}

	enclave.key, err = rsa.GenerateKey(rand.Reader, defaultKeyBits)
	if err != nil {
		// Drop the NSM session so a single failed init does not leak it for
		// the lifetime of the process. GetOrInitializeHandle caches the error
		// and never retries, so there is no recovery path otherwise.
		_ = enclave.nsm.Close()
		enclave.nsm = nil
		return fmt.Errorf("generate rsa key: %w", err)
	}

	return nil
}

// Attest generates and returns an attestation document from the enclave's Nitro
// Security Module. See AttestationOptions for more details on available
// options.
func (enclave *EnclaveHandle) Attest(args AttestationOptions) ([]byte, error) {
	var publicKey []byte
	var err error
	if args.PublicKey != nil && !args.NoPublicKey {
		publicKey, err = x509.MarshalPKIXPublicKey(args.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("marshal supplied public key: %w", err)
		}
	} else if !args.NoPublicKey {
		publicKey, err = x509.MarshalPKIXPublicKey(enclave.PublicKey())
		if err != nil {
			return nil, fmt.Errorf("marshal enclave public key: %w", err)
		}
	}

	res, err := enclave.nsm.Send(&request.Attestation{
		Nonce:     args.Nonce,
		UserData:  args.UserData,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("nsm: send attestation request: %w", err)
	}

	if res.Error != "" {
		return nil, fmt.Errorf("nsm: attestation failed: %s", res.Error)
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("attestation response missing attestation document")
	}

	return res.Attestation.Document, nil
}

// PublicKey returns a reference to the Handle's public key.
func (enclave *EnclaveHandle) PublicKey() *rsa.PublicKey {
	return &enclave.key.PublicKey
}

// DecryptKMSEnvelopedKey decrypts a KMS 'CiphertextForRecipient' response field,
// using the enclave's private key.
func (enclave *EnclaveHandle) DecryptKMSEnvelopedKey(content []byte) ([]byte, error) {
	return cms.DecryptEnvelopedKey(enclave.key, content)
}

// GetOrInitializeHandle returns a reference to the default global enclave
// handle, initializing that handle in the process if it has not been already.
// If an error occurs during initialization of the global handle (including if
// the error occurred during a previous initialization attempt), the error will
// be returned.
func GetOrInitializeHandle() (*EnclaveHandle, error) {
	initOnce.Do(func() {
		enclave := &EnclaveHandle{}
		if err := enclave.initialize(); err != nil {
			initErr = err
			return
		}
		globalHandle = enclave
	})

	return globalHandle, initErr
}

// MustGlobalHandle returns a reference to the default enclave handle. If no
// handle has been initialized, one will be initialized on-demand. If an error
// occurs during initialization, panic.
func MustGlobalHandle() *EnclaveHandle {
	handle, err := GetOrInitializeHandle()
	if err != nil {
		panic(err)
	}

	return handle
}
