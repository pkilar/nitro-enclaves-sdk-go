package enclave

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkilar/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/pkilar/nitro-enclaves-sdk-go/internal/nsmtest"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// newTestHandle returns a handle on a new simulated NSM, and the NSM.
func newTestHandle(t *testing.T) (*EnclaveHandle, *nsmtest.Device) {
	t.Helper()

	device := nsmtest.NewDevice()
	session := nsm.NewSession(device)
	t.Cleanup(func() { require.NoError(t, session.Close()) })

	handle, err := NewEnclaveHandle(session)
	require.NoError(t, err)

	return handle, device
}

// attestationReply is the reply an NSM gives to an attestation request.
func attestationReply(document []byte) any {
	return map[string]response.Attestation{"Attestation": {Document: document}}
}

func TestNewEnclaveHandle_RejectsNilSession(t *testing.T) {
	t.Parallel()

	handle, err := NewEnclaveHandle(nil)

	require.Error(t, err)
	assert.Nil(t, handle)
}

func TestAttest(t *testing.T) {
	t.Parallel()

	handle, device := newTestHandle(t)
	device.ReplyWith(attestationReply([]byte("signed document")))

	suppliedKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	tests := []struct {
		name         string
		options      AttestationOptions
		wantNonce    []byte
		wantUserData []byte
		// wantKey is the public key the NSM must receive; nil means none.
		wantKey any
	}{
		{
			name:    "sends the enclave public key by default",
			wantKey: handle.PublicKey(),
		},
		{
			name: "passes nonce and user data through",
			options: AttestationOptions{
				Nonce:    []byte("nonce-0001"),
				UserData: []byte("user data"),
			},
			wantNonce:    []byte("nonce-0001"),
			wantUserData: []byte("user data"),
			wantKey:      handle.PublicKey(),
		},
		{
			name:    "sends a supplied public key instead of the enclave key",
			options: AttestationOptions{PublicKey: suppliedKey},
			wantKey: suppliedKey,
		},
		{
			name:    "omits the public key when asked",
			options: AttestationOptions{NoPublicKey: true},
		},
		{
			name:    "omits a supplied public key when asked",
			options: AttestationOptions{NoPublicKey: true, PublicKey: suppliedKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document, err := handle.Attest(tt.options)
			require.NoError(t, err)

			assert.Equal(t, []byte("signed document"), document)
			sent, ok := device.LastAttestation()
			require.True(t, ok, "the NSM received an attestation request")
			assert.Equal(t, tt.wantNonce, sent.Nonce)
			assert.Equal(t, tt.wantUserData, sent.UserData)

			if tt.wantKey == nil {
				assert.Empty(t, sent.PublicKey)
				return
			}
			sentKey, err := x509.ParsePKIXPublicKey(sent.PublicKey)
			require.NoError(t, err)
			assert.Equal(t, tt.wantKey, sentKey)
		})
	}
}

func TestAttest_RejectsUnsupportedPublicKeyType(t *testing.T) {
	t.Parallel()

	handle, device := newTestHandle(t)

	document, err := handle.Attest(AttestationOptions{PublicKey: "not a public key"})

	require.Error(t, err)
	assert.Nil(t, document)
	_, asked := device.LastAttestation()
	assert.False(t, asked, "the NSM must not be asked when the key cannot be encoded")
}

func TestAttest_ReportsRefusalByNSM(t *testing.T) {
	t.Parallel()

	handle, device := newTestHandle(t)
	device.RefuseWith(response.ECInvalidArgument)

	document, err := handle.Attest(AttestationOptions{})

	var nsmErr *nsm.Error
	require.ErrorAs(t, err, &nsmErr)
	assert.Equal(t, response.ECInvalidArgument, nsmErr.Code)
	assert.Nil(t, document)
}

func TestAttest_ReportsReplyWithoutDocument(t *testing.T) {
	t.Parallel()

	handle, device := newTestHandle(t)

	tests := []struct {
		name  string
		reply any
	}{
		{name: "reply is not an attestation", reply: "LockPCR"},
		{name: "document is null", reply: attestationReply(nil)},
		{name: "document is empty", reply: attestationReply([]byte{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device.ReplyWith(tt.reply)

			document, err := handle.Attest(AttestationOptions{})

			var nsmErr *nsm.Error
			require.ErrorAs(t, err, &nsmErr)
			assert.Equal(t, response.ECInvalidResponse, nsmErr.Code)
			assert.Nil(t, document)
		})
	}
}

func TestAttest_ReportsDeviceFailure(t *testing.T) {
	t.Parallel()

	handle, device := newTestHandle(t)
	device.FailWith(&nsm.IoctlError{Errno: syscall.EIO})

	document, err := handle.Attest(AttestationOptions{})

	var ioctlErr *nsm.IoctlError
	require.ErrorAs(t, err, &ioctlErr)
	assert.Equal(t, syscall.EIO, ioctlErr.Errno)
	assert.Nil(t, document)
}

// The handle exists to pair these two halves: KMS encrypts to the key the
// attestation vouches for, and only the handle can open the result.
func TestDecryptKMSEnvelopedKey_OpensEnvelopeEncryptedToAttestedKey(t *testing.T) {
	t.Parallel()

	handle, device := newTestHandle(t)

	_, err := handle.Attest(AttestationOptions{})
	require.NoError(t, err)
	sent, ok := device.LastAttestation()
	require.True(t, ok, "the NSM received an attestation request")
	attested, err := x509.ParsePKIXPublicKey(sent.PublicKey)
	require.NoError(t, err)
	recipient, ok := attested.(*rsa.PublicKey)
	require.True(t, ok, "attested key has type %T, want *rsa.PublicKey", attested)

	dataKey := []byte("0123456789abcdef0123456789abcdef")
	got, err := handle.DecryptKMSEnvelopedKey(kmsEnvelope(t, recipient, dataKey))

	require.NoError(t, err)
	assert.Equal(t, dataKey, got)
}

// The ASN.1 shape of a CMS EnvelopedData with one key-transport recipient
// (RFC 5652, sections 6.1 and 6.2.1), as kmsEnvelope encodes it.
type (
	kmsContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     kmsEnvelopedData `asn1:"explicit,tag:0"`
	}
	kmsEnvelopedData struct {
		Version              int
		RecipientInfos       []kmsRecipientInfo `asn1:"set"`
		EncryptedContentInfo kmsEncryptedContentInfo
	}
	kmsRecipientInfo struct {
		Version                int
		RecipientIdentifier    []byte `asn1:"tag:0"`
		KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedKey           []byte
	}
	kmsEncryptedContentInfo struct {
		ContentType                asn1.ObjectIdentifier
		ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedContent           asn1.RawValue
	}
)

// kmsEnvelope builds the CMS EnvelopedData that KMS returns in
// CiphertextForRecipient: plaintext under AES-256-CBC, with the content key
// wrapped for recipient using RSAES-OAEP and SHA-256.
func kmsEnvelope(t *testing.T, recipient *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()

	contentKey := bytes.Repeat([]byte{0x42}, 32)
	iv := bytes.Repeat([]byte{0x24}, aes.BlockSize)

	block, err := aes.NewCipher(contentKey)
	require.NoError(t, err)
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipient, contentKey, nil)
	require.NoError(t, err)

	envelope, err := asn1.Marshal(kmsContentInfo{
		ContentType: cms.OIDEnvelopedData,
		Content: kmsEnvelopedData{
			Version: cms.EnvelopedDataVersion,
			RecipientInfos: []kmsRecipientInfo{{
				Version:                cms.EnvelopedDataRecipientInfoVersion,
				RecipientIdentifier:    []byte("recipient key id"),
				KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: cms.OIDEncryptionAlgorithmRSAESOAEP},
				EncryptedKey:           wrappedKey,
			}},
			EncryptedContentInfo: kmsEncryptedContentInfo{
				ContentType: cms.OIDData,
				ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm:  cms.OIDEncryptionAlgorithmAES256CBC,
					Parameters: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: iv},
				},
				EncryptedContent: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: ciphertext},
			},
		},
	})
	require.NoError(t, err)

	return envelope
}
