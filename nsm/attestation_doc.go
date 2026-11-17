package nsm

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// PCRs maps a PCR index to its value.
type PCRs map[uint][]byte

// MarshalCBOR encodes the PCRs as a map with ascending indexes, so that an
// AttestationDoc always encodes to the same bytes.
func (p PCRs) MarshalCBOR() ([]byte, error) {
	if p == nil {
		return []byte{0xa0}, nil // an empty map
	}

	return pcrEncoding.Marshal(map[uint][]byte(p))
}

// AttestationDoc is the content of an attestation document: what the NSM
// signs inside the COSE_Sign1 envelope it returns.
type AttestationDoc struct {
	// ModuleID identifies the NSM that issued the document.
	ModuleID string `cbor:"module_id"`
	// Digest is the hash used for the PCRs.
	Digest response.Digest `cbor:"digest"`
	// Timestamp is when the document was issued, in milliseconds since the
	// Unix epoch.
	Timestamp uint64 `cbor:"timestamp"`
	// PCRs holds the value of each locked PCR.
	PCRs PCRs `cbor:"pcrs"`
	// Certificate is the DER-encoded certificate of the key that signed the
	// document.
	Certificate []byte `cbor:"certificate"`
	// CABundle is the DER-encoded issuing chain, root first.
	CABundle [][]byte `cbor:"cabundle"`
	// PublicKey is the DER-encoded key the requester asked to have attested,
	// or nil.
	PublicKey []byte `cbor:"public_key"`
	// UserData is the requester's data, or nil.
	UserData []byte `cbor:"user_data"`
	// Nonce is the requester's nonce, or nil.
	Nonce []byte `cbor:"nonce"`
}

var (
	// pcrEncoding sorts map keys bytewise, which for PCR indexes is ascending
	// numeric order.
	pcrEncoding = mustEncMode(cbor.EncOptions{Sort: cbor.SortBytewiseLexical})

	// docDecoding rejects duplicate keys and bounds how deep and how wide
	// the document may be. Indefinite lengths and tags stay allowed, as in
	// the Rust decoder, because the NSM's encoder is not ours to constrain.
	docDecoding = mustDecMode(cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  4,
		MaxArrayElements: 64,
		MaxMapPairs:      64,
	})
)

// mustEncMode builds an encoding mode from fixed options, which cannot fail
// unless the options are wrong.
func mustEncMode(opts cbor.EncOptions) cbor.EncMode {
	mode, err := opts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("nsm: invalid CBOR encoding options: %v", err))
	}

	return mode
}

// mustDecMode builds a decoding mode from fixed options, which cannot fail
// unless the options are wrong.
func mustDecMode(opts cbor.DecOptions) cbor.DecMode {
	mode, err := opts.DecMode()
	if err != nil {
		panic(fmt.Sprintf("nsm: invalid CBOR decoding options: %v", err))
	}

	return mode
}

// ParseAttestationDoc decodes the content of an attestation document without
// verifying anything. payload is the payload of the COSE_Sign1 envelope, not
// the envelope itself; the caller must have checked the envelope's signature
// and certificate chain before trusting the result.
func ParseAttestationDoc(payload []byte) (*AttestationDoc, error) {
	if len(payload) > MaxResponseSize {
		return nil, fmt.Errorf("nsm: attestation document of %d bytes is over the %d-byte limit",
			len(payload), MaxResponseSize)
	}

	var doc AttestationDoc
	if err := docDecoding.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("nsm: decode attestation document: %w", err)
	}

	return &doc, nil
}

// Marshal encodes the document as the NSM does: fields in declaration order,
// PCR indexes ascending, and absent optional fields as CBOR null.
func (d *AttestationDoc) Marshal() ([]byte, error) {
	encoded, err := cbor.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("nsm: encode attestation document: %w", err)
	}

	return encoded, nil
}
