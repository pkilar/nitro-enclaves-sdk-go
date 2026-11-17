// Package nsmcheck checks that a Nitro Security Module behaves as the NSM API
// says it should. It follows nsm-check from aws-nitro-enclaves-nsm-api.
package nsmcheck

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/fxamacker/cbor/v2"

	enclave "github.com/pkilar/nitro-enclaves-sdk-go"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

const (
	// reservedPCRs is how many PCRs, counting from 0, the NSM locks at boot.
	reservedPCRs = 16
	// attestationDataSize is the size of each optional field in the largest
	// attestation request the checks send.
	attestationDataSize = 1024
	// extendRounds is how many times each free PCR is extended.
	extendRounds = 10
	// randomRounds is how many random replies are compared.
	randomRounds = 16
)

// Options selects which checks Run performs.
type Options struct {
	// PCRWrites also runs the checks that extend and lock PCRs. What they
	// change stays changed until the enclave terminates.
	PCRWrites bool
}

// checker carries what the checks learn about the NSM from one to the next.
type checker struct {
	session *nsm.Session
	handle  *enclave.EnclaveHandle
	desc    response.DescribeNSM
	pcrLen  int
}

// Run performs the checks in order against session, writes one line per check
// to out, and returns the first failure. The checks that only read assume an
// enclave whose PCRs have not been extended or locked since boot.
func Run(session *nsm.Session, out io.Writer, opts Options) error {
	handle, err := enclave.NewEnclaveHandle(session)
	if err != nil {
		return err
	}
	c := &checker{session: session, handle: handle}

	type check struct {
		name string
		run  func() error
	}
	checks := []check{
		{name: "NSM description", run: c.description},
		{name: "PCR lengths", run: c.pcrLengths},
		{name: "initial PCR state", run: c.initialPCRs},
		{name: "attestation", run: c.attestation},
		{name: "random bytes", run: c.random},
	}
	if opts.PCRWrites {
		checks = append(checks,
			check{name: "reserved PCRs cannot be locked", run: c.reservedLocks},
			check{name: "extending and locking PCRs", run: c.extendAndLock},
			check{name: "locking PCR ranges", run: c.lockRanges},
			check{name: "locked PCRs are read-only", run: c.lockedAreReadOnly},
		)
	}

	for _, ck := range checks {
		if err := ck.run(); err != nil {
			if _, writeErr := fmt.Fprintf(out, "FAIL  %s: %v\n", ck.name, err); writeErr != nil {
				return errors.Join(fmt.Errorf("%s: %w", ck.name, err), writeErr)
			}
			return fmt.Errorf("%s: %w", ck.name, err)
		}
		if _, err := fmt.Fprintf(out, "ok    %s\n", ck.name); err != nil {
			return fmt.Errorf("write result: %w", err)
		}
	}

	return nil
}

// description checks that the NSM describes itself, and records the PCR
// count and length for the checks that follow.
func (c *checker) description() error {
	desc, err := c.handle.Describe()
	if err != nil {
		return err
	}

	pcrLen := desc.Digest.Size()
	if pcrLen == 0 {
		return fmt.Errorf("unknown digest %q", desc.Digest)
	}
	if desc.MaxPCRs < reservedPCRs {
		return fmt.Errorf("NSM has %d PCRs, want at least %d", desc.MaxPCRs, reservedPCRs)
	}
	if desc.ModuleID == "" {
		return errors.New("module ID is empty")
	}

	c.desc, c.pcrLen = desc, pcrLen

	return nil
}

// pcrLengths checks that every PCR can be described and has the digest's
// length.
func (c *checker) pcrLengths() error {
	for index := range c.desc.MaxPCRs {
		pcr, err := c.handle.DescribePCR(index)
		if err != nil {
			return err
		}
		if len(pcr.Data) != c.pcrLen {
			return fmt.Errorf("PCR %d is %d bytes, want %d", index, len(pcr.Data), c.pcrLen)
		}
	}

	return nil
}

// initialPCRs checks the state a new enclave starts in: PCRs [0, 16) locked,
// the rest unlocked and zero. The values of the reserved PCRs depend on the
// image, the instance and debug mode, so they are not checked.
func (c *checker) initialPCRs() error {
	wantLocked := make([]uint16, reservedPCRs)
	for i := range wantLocked {
		wantLocked[i] = uint16(i)
	}
	if !slices.Equal(c.desc.LockedPCRs, wantLocked) {
		return fmt.Errorf("locked PCRs are %v, want %v", c.desc.LockedPCRs, wantLocked)
	}

	zero := make([]byte, c.pcrLen)
	for index := range c.desc.MaxPCRs {
		pcr, err := c.handle.DescribePCR(index)
		if err != nil {
			return err
		}
		if reserved := index < reservedPCRs; pcr.Lock != reserved {
			return fmt.Errorf("PCR %d locked is %t, want %t", index, pcr.Lock, reserved)
		}
		if index >= reservedPCRs && !bytes.Equal(pcr.Data, zero) {
			return fmt.Errorf("PCR %d is not zero", index)
		}
	}

	return nil
}

// attestation checks that the NSM attests with no optional data and with each
// optional field at its largest, and that the document carries them back.
func (c *checker) attestation() error {
	data := bytes.Repeat([]byte{128}, attestationDataSize)
	requests := []request.Attestation{
		{},
		{UserData: data},
		{UserData: data, Nonce: data},
		{UserData: data, Nonce: data, PublicKey: data},
	}

	for i := range requests {
		if err := c.attestOnce(&requests[i]); err != nil {
			return fmt.Errorf("request %d: %w", i+1, err)
		}
	}

	return nil
}

// attestOnce sends one attestation request and checks the document it gets.
func (c *checker) attestOnce(req *request.Attestation) error {
	res, err := c.session.Send(req)
	if err != nil {
		return err
	}
	if res.Attestation == nil || len(res.Attestation.Document) == 0 {
		return errors.New("reply has no document")
	}

	payload, err := payloadOf(res.Attestation.Document)
	if err != nil {
		return err
	}
	doc, err := nsm.ParseAttestationDoc(payload)
	if err != nil {
		return err
	}

	switch {
	case doc.ModuleID != c.desc.ModuleID:
		return fmt.Errorf("document module ID is %q, want %q", doc.ModuleID, c.desc.ModuleID)
	case doc.Digest != c.desc.Digest:
		return fmt.Errorf("document digest is %q, want %q", doc.Digest, c.desc.Digest)
	case doc.Timestamp == 0:
		return errors.New("document has no timestamp")
	case len(doc.Certificate) == 0 || len(doc.CABundle) == 0:
		return errors.New("document has no certificate chain")
	case len(doc.PCRs) == 0:
		return errors.New("document has no PCRs")
	case !bytes.Equal(doc.UserData, req.UserData):
		return errors.New("document user data differs from the request")
	case !bytes.Equal(doc.Nonce, req.Nonce):
		return errors.New("document nonce differs from the request")
	case !bytes.Equal(doc.PublicKey, req.PublicKey):
		return errors.New("document public key differs from the request")
	}
	for index, value := range doc.PCRs {
		if len(value) != c.pcrLen {
			return fmt.Errorf("document PCR %d is %d bytes, want %d", index, len(value), c.pcrLen)
		}
	}

	return nil
}

// random checks that each random reply has bytes and differs from the last.
func (c *checker) random() error {
	var previous []byte
	for round := range randomRounds {
		res, err := c.session.Send(&request.GetRandom{})
		if err != nil {
			return err
		}
		if res.GetRandom == nil || len(res.GetRandom.Random) == 0 {
			return fmt.Errorf("reply %d has no random bytes", round+1)
		}
		if bytes.Equal(res.GetRandom.Random, previous) {
			return fmt.Errorf("reply %d repeats reply %d", round+1, round)
		}
		previous = res.GetRandom.Random
	}

	return nil
}

// reservedLocks checks that the NSM refuses to lock the PCRs it reserves.
func (c *checker) reservedLocks() error {
	for index := range uint16(reservedPCRs) {
		if err := refused(c.handle.LockPCR(index)); err != nil {
			return fmt.Errorf("lock PCR %d: %w", index, err)
		}
	}

	return nil
}

// extendAndLock checks that extending a free PCR changes it every time, and
// that each free PCR can then be locked.
func (c *checker) extendAndLock() error {
	previous := make(map[uint16][]byte)
	zero := make([]byte, c.pcrLen)

	for range extendRounds {
		for index := uint16(reservedPCRs); index < c.desc.MaxPCRs; index++ {
			value, err := c.handle.ExtendPCR(index, []byte("nsm-check"))
			if err != nil {
				return err
			}
			if len(value) != c.pcrLen {
				return fmt.Errorf("PCR %d is %d bytes after extending, want %d", index, len(value), c.pcrLen)
			}
			if bytes.Equal(value, zero) || bytes.Equal(value, previous[index]) {
				return fmt.Errorf("PCR %d did not change when extended", index)
			}
			previous[index] = value
		}
	}

	for index := uint16(reservedPCRs); index < c.desc.MaxPCRs; index++ {
		if err := c.handle.LockPCR(index); err != nil {
			return err
		}
	}

	return nil
}

// lockRanges checks that every PCR can be locked as one range and that a
// range past the last PCR is refused.
func (c *checker) lockRanges() error {
	if err := c.handle.LockPCRs(c.desc.MaxPCRs); err != nil {
		return err
	}
	if err := refused(c.handle.LockPCRs(c.desc.MaxPCRs + 1)); err != nil {
		return fmt.Errorf("lock PCRs [0, %d): %w", c.desc.MaxPCRs+1, err)
	}

	return nil
}

// lockedAreReadOnly checks that, with every PCR locked, none can be extended
// and each reports the same value twice.
func (c *checker) lockedAreReadOnly() error {
	for index := range c.desc.MaxPCRs {
		_, err := c.handle.ExtendPCR(index, []byte("nsm-check"))
		if err := refused(err); err != nil {
			return fmt.Errorf("extend PCR %d: %w", index, err)
		}

		first, err := c.handle.DescribePCR(index)
		if err != nil {
			return err
		}
		second, err := c.handle.DescribePCR(index)
		if err != nil {
			return err
		}
		if !first.Lock || !second.Lock {
			return fmt.Errorf("PCR %d is not locked", index)
		}
		if !bytes.Equal(first.Data, second.Data) {
			return fmt.Errorf("PCR %d changed between two reads", index)
		}
	}

	return nil
}

// refused returns nil if err shows that the NSM refused a request, and an
// error describing what happened otherwise.
func refused(err error) error {
	if err == nil {
		return errors.New("the NSM accepted a request it should refuse")
	}

	var nsmErr *nsm.Error
	if !errors.As(err, &nsmErr) {
		return fmt.Errorf("want a refusal from the NSM, got: %w", err)
	}

	return nil
}

// coseSign1 is the envelope an attestation document arrives in: a CBOR array
// of protected headers, unprotected headers, payload and signature.
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// payloadOf returns the payload of a COSE_Sign1 envelope. It checks the
// envelope's structure and nothing else: the signature is not verified.
func payloadOf(document []byte) ([]byte, error) {
	var envelope coseSign1
	if err := cbor.Unmarshal(document, &envelope); err != nil {
		return nil, fmt.Errorf("decode COSE_Sign1 envelope: %w", err)
	}
	if len(envelope.Payload) == 0 {
		return nil, errors.New("COSE_Sign1 envelope has no payload")
	}

	return envelope.Payload, nil
}
