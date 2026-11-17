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

// replyDecoding reads replies the way the NSM's own serde types would: names
// match exactly, and a key may appear only once. Fields it does not know are
// skipped, so a newer NSM that adds one is still understood.
var replyDecoding = mustDecMode(cbor.DecOptions{
	DupMapKey:         cbor.DupMapKeyEnforcedAPF,
	FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
})

// encodeRequest returns the CBOR encoding of req.
func encodeRequest(req request.Request) ([]byte, error) {
	encoded, err := cbor.Marshal(req.Encoded())
	if err != nil {
		return nil, fmt.Errorf("nsm: encode request: %w", err)
	}

	return encoded, nil
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

	var variants map[string]cbor.RawMessage
	if err := replyDecoding.Unmarshal(data, &variants); err != nil {
		return response.Response{}, fmt.Errorf("nsm: decode response: %w", err)
	}
	if len(variants) != 1 {
		return response.Response{}, fmt.Errorf("nsm: decode response: reply map has %d entries, want 1", len(variants))
	}

	var (
		name string
		body cbor.RawMessage
	)
	for name, body = range variants {
	}

	return decodeVariant(name, body)
}

// decodeVariant decodes the fields of the reply variant called name. A byte
// string the variant requires must be present, as it must for serde.
func decodeVariant(name string, body cbor.RawMessage) (response.Response, error) {
	var (
		res     response.Response
		err     error
		missing string
	)

	switch name {
	case "Error":
		var code response.ErrorCode
		if err = decodeBody(name, body, &code); err == nil {
			err = &Error{Code: code}
		}
	case "DescribePCR":
		res.DescribePCR = new(response.DescribePCR)
		if err = decodeBody(name, body, res.DescribePCR); err == nil && res.DescribePCR.Data == nil {
			missing = "data"
		}
	case "ExtendPCR":
		res.ExtendPCR = new(response.ExtendPCR)
		if err = decodeBody(name, body, res.ExtendPCR); err == nil && res.ExtendPCR.Data == nil {
			missing = "data"
		}
	case "DescribeNSM":
		res.DescribeNSM = new(response.DescribeNSM)
		if err = decodeBody(name, body, res.DescribeNSM); err == nil && res.DescribeNSM.Digest == "" {
			missing = "digest"
		}
	case "Attestation":
		res.Attestation = new(response.Attestation)
		if err = decodeBody(name, body, res.Attestation); err == nil && res.Attestation.Document == nil {
			missing = "document"
		}
	case "GetRandom":
		res.GetRandom = new(response.GetRandom)
		if err = decodeBody(name, body, res.GetRandom); err == nil && res.GetRandom.Random == nil {
			missing = "random"
		}
	default:
		err = fmt.Errorf("nsm: decode response: unknown reply %q", name)
	}

	if err == nil && missing != "" {
		err = fmt.Errorf("nsm: decode %s response: missing field %q", name, missing)
	}
	if err != nil {
		return response.Response{}, err
	}

	return res, nil
}

// decodeBody decodes the value of one reply variant into v.
func decodeBody(name string, body cbor.RawMessage, v any) error {
	if err := replyDecoding.Unmarshal(body, v); err != nil {
		return fmt.Errorf("nsm: decode %s response: %w", name, err)
	}

	return nil
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
