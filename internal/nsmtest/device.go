// Package nsmtest provides a simulated Nitro Security Module for tests.
//
// Device implements nsm.Device in pure Go. It keeps PCR state the way a real
// NSM does, so code that extends, locks and attests can be tested outside an
// enclave. Its attestation documents have the real shape but a dummy
// signature.
package nsmtest

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"syscall"

	"github.com/fxamacker/cbor/v2"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

const (
	// MaxPCRs is how many PCRs the simulated NSM has.
	MaxPCRs = 32
	// ReservedPCRs is how many PCRs, counting from 0, start out locked.
	ReservedPCRs = 16
	// ModuleID is the module ID the simulated NSM reports.
	ModuleID = "i-0123456789abcdef0-enc0123456789abcdef"
	// Timestamp is the time on every simulated attestation document.
	Timestamp uint64 = 1700000000000

	// cborTextString is the CBOR major type of a text string.
	cborTextString = 3
)

// Device is a simulated NSM. The zero value is not usable; call NewDevice.
type Device struct {
	mu sync.Mutex

	pcrs        [MaxPCRs][sha512.Size384]byte
	locked      [MaxPCRs]bool
	randomCalls uint64
	closed      bool

	lastAttestation *request.Attestation

	refuseWith response.ErrorCode
	failWith   error
	replyWith  any
}

// NewDevice returns a simulated NSM in the state of a new enclave: every PCR
// zero, and PCRs [0, ReservedPCRs) locked.
func NewDevice() *Device {
	d := &Device{}
	for i := range ReservedPCRs {
		d.locked[i] = true
	}

	return d
}

// RefuseWith makes the device refuse every later request with code. An empty
// code restores normal behaviour.
func (d *Device) RefuseWith(code response.ErrorCode) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.refuseWith = code
}

// FailWith makes every later exchange fail with err, as a failed ioctl would.
// A nil err restores normal behaviour.
func (d *Device) FailWith(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.failWith = err
}

// ReplyWith makes the device answer every later request with reply, encoded
// as CBOR, whatever was asked. A nil reply restores normal behaviour.
func (d *Device) ReplyWith(reply any) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.replyWith = reply
}

// LastAttestation returns the most recent attestation request the device
// received, and whether it has received one.
func (d *Device) LastAttestation() (request.Attestation, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.lastAttestation == nil {
		return request.Attestation{}, false
	}

	return *d.lastAttestation, true
}

// Closed reports whether Close has been called.
func (d *Device) Closed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.closed
}

// Close implements nsm.Device.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.closed = true

	return nil
}

// Exchange implements nsm.Device.
func (d *Device) Exchange(req, res []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return 0, errors.New("nsmtest: device is closed")
	}
	// The real driver rejects an oversized request with EMSGSIZE.
	if len(req) > nsm.MaxRequestSize {
		return 0, syscall.EMSGSIZE
	}
	if d.failWith != nil {
		return 0, d.failWith
	}

	encoded, err := cbor.Marshal(d.reply(req))
	if err != nil {
		return 0, fmt.Errorf("nsmtest: encode reply: %w", err)
	}
	if len(encoded) > len(res) {
		return 0, fmt.Errorf("nsmtest: %d-byte reply does not fit a %d-byte buffer", len(encoded), len(res))
	}

	return copy(res, encoded), nil
}

// wireRequest is the map form of a request: one entry, keyed by the name of
// the variant.
type wireRequest struct {
	DescribePCR *request.DescribePCR `cbor:"DescribePCR"`
	ExtendPCR   *request.ExtendPCR   `cbor:"ExtendPCR"`
	LockPCR     *request.LockPCR     `cbor:"LockPCR"`
	LockPCRs    *request.LockPCRs    `cbor:"LockPCRs"`
	Attestation *request.Attestation `cbor:"Attestation"`
}

// refusal is the reply an NSM gives when it refuses a request.
func refusal(code response.ErrorCode) any {
	return map[string]response.ErrorCode{"Error": code}
}

// reply returns the value to send back for one encoded request.
func (d *Device) reply(req []byte) any {
	if len(req) == 0 {
		return refusal(response.ECInvalidOperation)
	}

	var (
		name string
		wire wireRequest
	)
	target := any(&wire)
	if req[0]>>5 == cborTextString {
		target = &name
	}
	if err := cbor.Unmarshal(req, target); err != nil {
		return refusal(response.ECInvalidOperation)
	}
	if wire.Attestation != nil {
		d.lastAttestation = wire.Attestation
	}

	if d.refuseWith != "" {
		return refusal(d.refuseWith)
	}
	if d.replyWith != nil {
		return d.replyWith
	}

	switch {
	case name == "DescribeNSM":
		return d.describe()
	case name == "GetRandom":
		return d.random()
	case wire.DescribePCR != nil:
		return d.describePCR(wire.DescribePCR.Index)
	case wire.ExtendPCR != nil:
		return d.extendPCR(wire.ExtendPCR.Index, wire.ExtendPCR.Data)
	case wire.LockPCR != nil:
		return d.lockPCR(wire.LockPCR.Index)
	case wire.LockPCRs != nil:
		return d.lockPCRs(wire.LockPCRs.Range)
	case wire.Attestation != nil:
		return d.attest(wire.Attestation)
	default:
		return refusal(response.ECInvalidOperation)
	}
}

func (d *Device) describe() any {
	locked := make([]uint16, 0, MaxPCRs)
	for i := range uint16(MaxPCRs) {
		if d.locked[i] {
			locked = append(locked, i)
		}
	}

	return map[string]response.DescribeNSM{"DescribeNSM": {
		VersionMajor: 1,
		ModuleID:     ModuleID,
		MaxPCRs:      MaxPCRs,
		LockedPCRs:   locked,
		Digest:       response.DigestSHA384,
	}}
}

func (d *Device) describePCR(index uint16) any {
	if index >= MaxPCRs {
		return refusal(response.ECInvalidIndex)
	}

	return map[string]response.DescribePCR{"DescribePCR": {
		Lock: d.locked[index],
		Data: slices.Clone(d.pcrs[index][:]),
	}}
}

// extendPCR replaces a PCR with the hash of its old value followed by data.
func (d *Device) extendPCR(index uint16, data []byte) any {
	if index >= MaxPCRs {
		return refusal(response.ECInvalidIndex)
	}
	if d.locked[index] {
		return refusal(response.ECReadOnlyIndex)
	}

	d.pcrs[index] = sha512.Sum384(slices.Concat(d.pcrs[index][:], data))

	return map[string]response.ExtendPCR{"ExtendPCR": {
		Data: slices.Clone(d.pcrs[index][:]),
	}}
}

// lockPCR locks one PCR. The reserved PCRs cannot be locked by request; which
// code a real NSM gives for that is not documented, so this one is a guess.
func (d *Device) lockPCR(index uint16) any {
	if index >= MaxPCRs {
		return refusal(response.ECInvalidIndex)
	}
	if index < ReservedPCRs {
		return refusal(response.ECReadOnlyIndex)
	}

	d.locked[index] = true

	return "LockPCR"
}

// lockPCRs locks the PCRs in [0, count).
func (d *Device) lockPCRs(count uint16) any {
	if count > MaxPCRs {
		return refusal(response.ECInvalidIndex)
	}

	for i := range count {
		d.locked[i] = true
	}

	return "LockPCRs"
}

// random returns 64 bytes that differ on every call and are the same from one
// run to the next.
func (d *Device) random() any {
	d.randomCalls++
	seed := binary.BigEndian.AppendUint64(nil, d.randomCalls)
	sum := sha512.Sum512(seed)

	return map[string]response.GetRandom{"GetRandom": {Random: sum[:]}}
}

// coseSign1 is the envelope an attestation document arrives in: a CBOR array
// of protected headers, unprotected headers, payload and signature.
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int]any
	Payload     []byte
	Signature   []byte
}

// attest returns an attestation document for the locked PCRs, in a COSE_Sign1
// envelope whose signature is 96 zero bytes.
func (d *Device) attest(req *request.Attestation) any {
	pcrs := nsm.PCRs{}
	for i := range MaxPCRs {
		if d.locked[i] {
			pcrs[uint(i)] = slices.Clone(d.pcrs[i][:])
		}
	}

	doc := nsm.AttestationDoc{
		ModuleID:    ModuleID,
		Digest:      response.DigestSHA384,
		Timestamp:   Timestamp,
		PCRs:        pcrs,
		Certificate: []byte("simulated certificate"),
		CABundle:    [][]byte{[]byte("simulated root certificate")},
		PublicKey:   req.PublicKey,
		UserData:    req.UserData,
		Nonce:       req.Nonce,
	}
	payload, err := doc.Marshal()
	if err != nil {
		return refusal(response.ECInternalError)
	}

	envelope, err := cbor.Marshal(coseSign1{
		Protected:   []byte{0xa1, 0x01, 0x38, 0x22}, // {1: -35}, the ES384 algorithm
		Unprotected: map[int]any{},
		Payload:     payload,
		Signature:   make([]byte, 96),
	})
	if err != nil {
		return refusal(response.ECInternalError)
	}

	return map[string]response.Attestation{"Attestation": {Document: envelope}}
}
