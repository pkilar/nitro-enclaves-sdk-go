// Package request defines the requests the Nitro Security Module accepts.
package request

// Request is a request that can be sent to the NSM.
type Request interface {
	// Encoded returns the value that is CBOR-encoded and sent to the device.
	// The NSM expects a Rust enum: a variant with fields is a one-entry map
	// keyed by the variant name, and a variant without fields is the bare
	// name as a text string.
	Encoded() any
}

// DescribePCR asks for the value and lock state of one PCR.
type DescribePCR struct {
	Index uint16 `cbor:"index"`
}

// Encoded implements Request.
func (r *DescribePCR) Encoded() any {
	return map[string]*DescribePCR{"DescribePCR": r}
}

// ExtendPCR asks the NSM to extend one PCR with Data.
type ExtendPCR struct {
	Index uint16 `cbor:"index"`
	Data  []byte `cbor:"data"`
}

// Encoded implements Request.
func (r *ExtendPCR) Encoded() any {
	return map[string]*ExtendPCR{"ExtendPCR": r}
}

// LockPCR asks the NSM to make one PCR read-only.
type LockPCR struct {
	Index uint16 `cbor:"index"`
}

// Encoded implements Request.
func (r *LockPCR) Encoded() any {
	return map[string]*LockPCR{"LockPCR": r}
}

// LockPCRs asks the NSM to make the PCRs in [0, Range) read-only.
type LockPCRs struct {
	Range uint16 `cbor:"range"`
}

// Encoded implements Request.
func (r *LockPCRs) Encoded() any {
	return map[string]*LockPCRs{"LockPCRs": r}
}

// DescribeNSM asks for the NSM's version, PCR count and digest.
type DescribeNSM struct{}

// Encoded implements Request.
func (r *DescribeNSM) Encoded() any {
	return "DescribeNSM"
}

// Attestation asks for a signed attestation document. Every field is
// optional; a nil field is sent as CBOR null.
type Attestation struct {
	UserData  []byte `cbor:"user_data"`
	Nonce     []byte `cbor:"nonce"`
	PublicKey []byte `cbor:"public_key"`
}

// Encoded implements Request.
func (r *Attestation) Encoded() any {
	return map[string]*Attestation{"Attestation": r}
}

// GetRandom asks for random bytes from the NSM.
type GetRandom struct{}

// Encoded implements Request.
func (r *GetRandom) Encoded() any {
	return "GetRandom"
}
