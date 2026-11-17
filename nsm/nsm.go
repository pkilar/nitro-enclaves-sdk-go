// Package nsm talks to the Nitro Security Module, the device a Nitro Enclave
// uses for attestation documents, PCRs and entropy.
//
// It is derived from github.com/hf/nsm and follows the request and response
// model of the official Rust crate, aws-nitro-enclaves-nsm-api.
package nsm

import (
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

const (
	// MaxRequestSize is the largest encoded request the NSM accepts.
	MaxRequestSize = 0x1000
	// MaxResponseSize is the largest encoded response the NSM returns.
	MaxResponseSize = 0x3000
)

// Error reports that the NSM refused a request, or that a request or reply
// broke the protocol. Code says why.
type Error struct {
	Code response.ErrorCode
}

// Error implements error.
func (e *Error) Error() string {
	return "nsm: request failed: " + string(e.Code)
}
