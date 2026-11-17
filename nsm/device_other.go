//go:build !linux

package nsm

import (
	"errors"
	"fmt"
)

// Open reports that there is no NSM device: Nitro Enclaves run Linux only.
func Open() (*Session, error) {
	return nil, fmt.Errorf("nsm: open device: %w", errors.ErrUnsupported)
}
