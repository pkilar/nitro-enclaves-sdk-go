//go:build !(linux && (amd64 || arm64))

package nsm

import (
	"errors"
	"fmt"
)

// Open reports that there is no NSM device: Nitro Enclaves run Linux on
// x86-64 or arm64 only.
func Open() (*Session, error) {
	return nil, fmt.Errorf("nsm: open device: %w", errors.ErrUnsupported)
}
