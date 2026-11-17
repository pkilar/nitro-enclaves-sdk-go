package nsm

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// cborTextString is the CBOR major type of a text string, held in the top
// three bits of an item's first byte.
const cborTextString = 3

// encodeRequest returns the CBOR encoding of req.
func encodeRequest(req request.Request) ([]byte, error) {
	encoded, err := cbor.Marshal(req.Encoded())
	if err != nil {
		return nil, fmt.Errorf("nsm: encode request: %w", err)
	}

	return encoded, nil
}

// wireResponse is the map form of a reply: one entry, keyed by the name of the
// variant.
type wireResponse struct {
	DescribePCR *response.DescribePCR `cbor:"DescribePCR"`
	ExtendPCR   *response.ExtendPCR   `cbor:"ExtendPCR"`
	DescribeNSM *response.DescribeNSM `cbor:"DescribeNSM"`
	Attestation *response.Attestation `cbor:"Attestation"`
	GetRandom   *response.GetRandom   `cbor:"GetRandom"`
	Error       response.ErrorCode    `cbor:"Error"`
}

// decodeResponse decodes one reply from the NSM. A reply that carries an
// error code is returned as *Error.
//
// The NSM encodes a Rust enum. A variant with fields arrives as a one-entry
// map keyed by the variant name; a variant without fields arrives as the bare
// name in a text string.
func decodeResponse(data []byte) (response.Response, error) {
	if len(data) == 0 {
		return response.Response{}, errors.New("nsm: decode response: empty reply")
	}

	if data[0]>>5 == cborTextString {
		return decodeUnitResponse(data)
	}

	var wire wireResponse
	if err := cbor.Unmarshal(data, &wire); err != nil {
		return response.Response{}, fmt.Errorf("nsm: decode response: %w", err)
	}
	if wire.Error != "" {
		return response.Response{}, &Error{Code: wire.Error}
	}

	res := response.Response{
		DescribePCR: wire.DescribePCR,
		ExtendPCR:   wire.ExtendPCR,
		DescribeNSM: wire.DescribeNSM,
		Attestation: wire.Attestation,
		GetRandom:   wire.GetRandom,
	}
	if res == (response.Response{}) {
		return response.Response{}, errors.New("nsm: decode response: no known reply in map")
	}

	return res, nil
}

// decodeUnitResponse decodes a reply that is a bare variant name.
func decodeUnitResponse(data []byte) (response.Response, error) {
	var name string
	if err := cbor.Unmarshal(data, &name); err != nil {
		return response.Response{}, fmt.Errorf("nsm: decode response: %w", err)
	}

	switch name {
	case "LockPCR":
		return response.Response{LockPCR: &response.LockPCR{}}, nil
	case "LockPCRs":
		return response.Response{LockPCRs: &response.LockPCRs{}}, nil
	default:
		return response.Response{}, fmt.Errorf("nsm: decode response: unknown reply %q", name)
	}
}
