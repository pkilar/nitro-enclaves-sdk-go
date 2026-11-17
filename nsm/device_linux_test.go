//go:build linux

package nsm

import (
	"io/fs"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On a 64-bit kernel struct nsm_message is two 16-byte iovecs, so the command
// is _IOWR(0x0A, 0, 32): direction 3 in bits 30-31, size 32 in bits 16-29,
// type 0x0A in bits 8-15, number 0 in bits 0-7.
func TestIoctlCommand_MatchesKernelEncoding(t *testing.T) {
	t.Parallel()

	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the expected value is for 64-bit systems")
	}

	assert.Equal(t, uintptr(0xC0200A00), ioctlCommand)
}

func TestOpen_ReportsMissingDevice(t *testing.T) {
	t.Parallel()

	if _, err := os.Stat(devicePath); err == nil {
		t.Skip("the NSM device exists here")
	}

	session, err := Open()

	require.ErrorIs(t, err, fs.ErrNotExist)
	assert.Nil(t, session)
}
