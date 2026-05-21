package cms

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     envelopedData `asn1:"explicit,optional,tag:0"`
}

type envelopedData struct {
	Version              int
	RecipientInfos       []keyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type keyTransRecipientInfo struct {
	Version                int
	RecipientIdentifier    []byte `asn1:"tag:0"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type EncryptedKey struct {
	encryptedKey []byte
	cipherText   []byte
	iv           []byte
}

func (ek *EncryptedKey) Decrypt(key *rsa.PrivateKey) ([]byte, error) {
	contentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ek.encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}

	if len(ek.iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}

	// CryptBlocks panics if src is not a multiple of the block size; ciphertext
	// crosses the network so validate before decrypting.
	if len(ek.cipherText) == 0 || len(ek.cipherText)%block.BlockSize() != 0 {
		return nil, errors.New("cms: ciphertext length is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, ek.iv)
	plaintext := make([]byte, len(ek.cipherText))
	mode.CryptBlocks(plaintext, ek.cipherText)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}

	return plaintext, nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// PKCS#7 padding length must satisfy 1 <= padlen <= blocklen, and cannot
	// exceed the available data. Without these guards a crafted ciphertext can
	// either silently bypass unpadding (padlen == 0) or panic on a negative
	// slice index (padlen > len(data)).
	if padlen == 0 || padlen > blocklen || padlen > len(data) {
		return nil, errors.New("invalid padding")
	}

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func Parse(ber []byte) (*EncryptedKey, error) {
	der, err := ber2der(ber)
	if err != nil {
		return nil, err
	}

	ci := contentInfo{}
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, err
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("cms: trailing data")
	}

	if !ci.ContentType.Equal(OIDEnvelopedData) {
		return nil, fmt.Errorf("cms: content type is not enveloped data")
	}

	if ci.Content.Version != EnvelopedDataVersion {
		return nil, fmt.Errorf("cms: unexpected enveloped data version")
	}

	if len(ci.Content.RecipientInfos) != 1 {
		return nil, fmt.Errorf("cms: expected one recipient, found %d", len(ci.Content.RecipientInfos))
	}

	recipientInfo := ci.Content.RecipientInfos[0]
	if recipientInfo.Version != EnvelopedDataRecipientInfoVersion {
		return nil, fmt.Errorf("cms: unexpected recipient info version")
	}

	if !recipientInfo.KeyEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSAESOAEP) {
		return nil, fmt.Errorf("cms: unexpected encryption algorithm")
	}

	eci := ci.Content.EncryptedContentInfo

	if !eci.ContentType.Equal(OIDData) {
		return nil, fmt.Errorf("cms: unexpected content type for encrypted data")
	}

	if !eci.ContentEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmAES256CBC) {
		return nil, fmt.Errorf("cms: unexpected content encryption algorithm")
	}

	// EncryptedContent can either be constructed of multiple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	var ciphertext []byte
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs.
		// Loop on len(...) > 0 so we never call asn1.Unmarshal on empty
		// input (which would error). Real mid-stream parse errors are now
		// propagated instead of silently terminating the loop.
		var buf bytes.Buffer
		cipherbytes := eci.EncryptedContent.Bytes
		for len(cipherbytes) > 0 {
			var part []byte
			var err error
			cipherbytes, err = asn1.Unmarshal(cipherbytes, &part)
			if err != nil {
				return nil, fmt.Errorf("cms: parse compound OCTET STRING: %w", err)
			}
			buf.Write(part)
		}
		ciphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the ciphertext
		ciphertext = eci.EncryptedContent.Bytes
	}

	return &EncryptedKey{
		encryptedKey: recipientInfo.EncryptedKey,
		iv:           eci.ContentEncryptionAlgorithm.Parameters.Bytes,
		cipherText:   ciphertext,
	}, nil
}

func DecryptEnvelopedKey(key *rsa.PrivateKey, content []byte) ([]byte, error) {
	ek, err := Parse(content)
	if err != nil {
		return nil, err
	}

	return ek.Decrypt(key)
}
