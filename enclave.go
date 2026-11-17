package enclave

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/pkilar/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
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
	session *nsm.Session
	key     *rsa.PrivateKey
}

// NewEnclaveHandle returns a handle that reaches the Nitro Security Module
// through session and holds a newly generated RSA key pair.
//
// The caller keeps ownership of session. The handle never closes it, and it
// must stay open for as long as the handle is in use.
//
// Most callers want GetOrInitializeHandle, which opens the default NSM device
// itself. Use NewEnclaveHandle to share a session that is already open, or to
// substitute a different device.
func NewEnclaveHandle(session *nsm.Session) (*EnclaveHandle, error) {
	if session == nil {
		return nil, errors.New("nsm session is nil")
	}

	key, err := rsa.GenerateKey(rand.Reader, defaultKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	return &EnclaveHandle{session: session, key: key}, nil
}

// Attest generates and returns an attestation document from the enclave's Nitro
// Security Module. See AttestationOptions for more details on available
// options.
//
// If the NSM refuses the request, the error wraps an *nsm.Error.
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

	res, err := enclave.session.Send(&request.Attestation{
		Nonce:     args.Nonce,
		UserData:  args.UserData,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	if res.Attestation == nil || len(res.Attestation.Document) == 0 {
		return nil, fmt.Errorf("attest: %w", &nsm.Error{Code: response.ECInvalidResponse})
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
		session, err := nsm.Open()
		if err != nil {
			initErr = err
			return
		}

		handle, err := NewEnclaveHandle(session)
		if err != nil {
			// The error is cached and initialization is never retried, so
			// close the session here or it stays open for the life of the
			// process.
			initErr = errors.Join(err, session.Close())
			return
		}

		globalHandle = handle
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
