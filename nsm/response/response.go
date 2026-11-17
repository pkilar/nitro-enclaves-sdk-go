// Package response defines the replies the Nitro Security Module gives.
package response

// Digest names the hash the NSM uses for PCRs.
type Digest string

// The digests an NSM can report.
const (
	DigestSHA256 Digest = "SHA256"
	DigestSHA384 Digest = "SHA384"
	DigestSHA512 Digest = "SHA512"
)

// Size returns the digest's length in bytes, or 0 if the digest is unknown.
func (d Digest) Size() int {
	switch d {
	case DigestSHA256:
		return 32
	case DigestSHA384:
		return 48
	case DigestSHA512:
		return 64
	default:
		return 0
	}
}

// ErrorCode is the reason the NSM gives for refusing a request.
type ErrorCode string

// The error codes an NSM can report.
const (
	// ECSuccess means no error.
	ECSuccess ErrorCode = "Success"
	// ECInvalidArgument means the request's arguments are invalid.
	ECInvalidArgument ErrorCode = "InvalidArgument"
	// ECInvalidIndex means the PCR index is out of range.
	ECInvalidIndex ErrorCode = "InvalidIndex"
	// ECInvalidResponse means the reply does not match the request.
	ECInvalidResponse ErrorCode = "InvalidResponse"
	// ECReadOnlyIndex means the PCR is locked and cannot be changed.
	ECReadOnlyIndex ErrorCode = "ReadOnlyIndex"
	// ECInvalidOperation means the request is missing parameters.
	ECInvalidOperation ErrorCode = "InvalidOperation"
	// ECBufferTooSmall means the reply does not fit the output buffer.
	ECBufferTooSmall ErrorCode = "BufferTooSmall"
	// ECInputTooLarge means the request is larger than the NSM accepts.
	ECInputTooLarge ErrorCode = "InputTooLarge"
	// ECInternalError means the NSM failed while handling the request.
	ECInternalError ErrorCode = "InternalError"
)

// DescribePCR is the reply to a DescribePCR request.
type DescribePCR struct {
	Lock bool   `cbor:"lock" json:"lock"`
	Data []byte `cbor:"data" json:"data"`
}

// ExtendPCR is the reply to an ExtendPCR request. Data is the PCR's new value.
type ExtendPCR struct {
	Data []byte `cbor:"data" json:"data"`
}

// LockPCR is the reply to a LockPCR request.
type LockPCR struct{}

// LockPCRs is the reply to a LockPCRs request.
type LockPCRs struct{}

// DescribeNSM is the reply to a DescribeNSM request.
type DescribeNSM struct {
	VersionMajor uint16   `cbor:"version_major" json:"version_major"`
	VersionMinor uint16   `cbor:"version_minor" json:"version_minor"`
	VersionPatch uint16   `cbor:"version_patch" json:"version_patch"`
	ModuleID     string   `cbor:"module_id" json:"module_id"`
	MaxPCRs      uint16   `cbor:"max_pcrs" json:"max_pcrs"`
	LockedPCRs   []uint16 `cbor:"locked_pcrs" json:"locked_pcrs"`
	Digest       Digest   `cbor:"digest" json:"digest"`
}

// Attestation is the reply to an Attestation request. Document is a signed
// COSE_Sign1 envelope.
type Attestation struct {
	Document []byte `cbor:"document" json:"document"`
}

// GetRandom is the reply to a GetRandom request.
type GetRandom struct {
	Random []byte `cbor:"random" json:"random"`
}

// Response is a reply from the NSM. Exactly one field is non-nil.
type Response struct {
	DescribePCR *DescribePCR `json:"DescribePCR,omitempty"`
	ExtendPCR   *ExtendPCR   `json:"ExtendPCR,omitempty"`
	LockPCR     *LockPCR     `json:"LockPCR,omitempty"`
	LockPCRs    *LockPCRs    `json:"LockPCRs,omitempty"`
	DescribeNSM *DescribeNSM `json:"DescribeNSM,omitempty"`
	Attestation *Attestation `json:"Attestation,omitempty"`
	GetRandom   *GetRandom   `json:"GetRandom,omitempty"`
}
