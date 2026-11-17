package enclave

import (
	"fmt"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// send performs one NSM request and returns the part of the reply that pick
// selects. A reply of another kind is reported as InvalidResponse.
func send[T any](session *nsm.Session, req request.Request, pick func(response.Response) *T) (*T, error) {
	res, err := session.Send(req)
	if err != nil {
		return nil, err
	}

	reply := pick(res)
	if reply == nil {
		return nil, &nsm.Error{Code: response.ECInvalidResponse}
	}

	return reply, nil
}

// DescribePCR returns the value of one PCR and whether it is locked.
//
// If the NSM refuses the request, the error wraps an *nsm.Error; an index past
// the last PCR is refused with InvalidIndex.
func (enclave *EnclaveHandle) DescribePCR(index uint16) (response.DescribePCR, error) {
	reply, err := send(enclave.session, &request.DescribePCR{Index: index},
		func(res response.Response) *response.DescribePCR { return res.DescribePCR })
	if err != nil {
		return response.DescribePCR{}, fmt.Errorf("describe PCR %d: %w", index, err)
	}

	return *reply, nil
}

// ExtendPCR extends one PCR with data and returns the PCR's new value.
//
// If the NSM refuses the request, the error wraps an *nsm.Error; a locked PCR
// is refused with ReadOnlyIndex.
func (enclave *EnclaveHandle) ExtendPCR(index uint16, data []byte) ([]byte, error) {
	reply, err := send(enclave.session, &request.ExtendPCR{Index: index, Data: data},
		func(res response.Response) *response.ExtendPCR { return res.ExtendPCR })
	if err != nil {
		return nil, fmt.Errorf("extend PCR %d: %w", index, err)
	}

	return reply.Data, nil
}

// LockPCR makes one PCR read-only until the enclave terminates.
//
// If the NSM refuses the request, the error wraps an *nsm.Error.
func (enclave *EnclaveHandle) LockPCR(index uint16) error {
	_, err := send(enclave.session, &request.LockPCR{Index: index},
		func(res response.Response) *response.LockPCR { return res.LockPCR })
	if err != nil {
		return fmt.Errorf("lock PCR %d: %w", index, err)
	}

	return nil
}

// LockPCRs makes the PCRs in [0, count) read-only until the enclave
// terminates.
//
// If the NSM refuses the request, the error wraps an *nsm.Error.
func (enclave *EnclaveHandle) LockPCRs(count uint16) error {
	_, err := send(enclave.session, &request.LockPCRs{Range: count},
		func(res response.Response) *response.LockPCRs { return res.LockPCRs })
	if err != nil {
		return fmt.Errorf("lock PCRs [0, %d): %w", count, err)
	}

	return nil
}

// Describe returns the NSM's version, module ID, PCR count, locked PCRs and
// digest.
//
// If the NSM refuses the request, the error wraps an *nsm.Error.
func (enclave *EnclaveHandle) Describe() (response.DescribeNSM, error) {
	reply, err := send(enclave.session, &request.DescribeNSM{},
		func(res response.Response) *response.DescribeNSM { return res.DescribeNSM })
	if err != nil {
		return response.DescribeNSM{}, fmt.Errorf("describe NSM: %w", err)
	}

	return *reply, nil
}

// Read fills p with entropy from the NSM. It implements io.Reader and returns
// len(p) unless a request fails.
func (enclave *EnclaveHandle) Read(p []byte) (int, error) {
	n, err := enclave.session.Read(p)
	if err != nil {
		return n, fmt.Errorf("read NSM entropy: %w", err)
	}

	return n, nil
}
