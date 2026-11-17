package enclave

import (
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// requireCode fails the test unless err wraps an *nsm.Error with code want.
func requireCode(t *testing.T, err error, want response.ErrorCode) {
	t.Helper()

	var nsmErr *nsm.Error
	require.ErrorAs(t, err, &nsmErr)
	require.Equal(t, want, nsmErr.Code)
}

func TestDescribe_ReturnsNSMDescription(t *testing.T) {
	t.Parallel()

	handle, _ := newTestHandle(t)

	got, err := handle.Describe()

	require.NoError(t, err)
	assert.Equal(t, response.DescribeNSM{
		VersionMajor: 1,
		ModuleID:     "i-0123456789abcdef0-enc0123456789abcdef",
		MaxPCRs:      32,
		LockedPCRs:   []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Digest:       response.DigestSHA384,
	}, got)
}

func TestDescribePCR(t *testing.T) {
	t.Parallel()

	handle, _ := newTestHandle(t)

	tests := []struct {
		name     string
		index    uint16
		wantLock bool
	}{
		{name: "reserved PCR is locked", index: 0, wantLock: true},
		{name: "free PCR is unlocked", index: 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handle.DescribePCR(tt.index)

			require.NoError(t, err)
			assert.Equal(t, response.DescribePCR{Lock: tt.wantLock, Data: make([]byte, 48)}, got)
		})
	}
}

func TestExtendPCR_ReturnsNewValue(t *testing.T) {
	t.Parallel()

	handle, _ := newTestHandle(t)
	want := sha512.Sum384(append(make([]byte, 48), "measurement"...))

	got, err := handle.ExtendPCR(16, []byte("measurement"))
	require.NoError(t, err)
	described, err := handle.DescribePCR(16)
	require.NoError(t, err)

	assert.Equal(t, want[:], got)
	assert.Equal(t, want[:], described.Data)
}

func TestLockPCR_MakesPCRReadOnly(t *testing.T) {
	t.Parallel()

	handle, _ := newTestHandle(t)

	require.NoError(t, handle.LockPCR(16))
	_, extendErr := handle.ExtendPCR(16, []byte("measurement"))
	described, err := handle.DescribePCR(16)
	require.NoError(t, err)

	requireCode(t, extendErr, response.ECReadOnlyIndex)
	assert.True(t, described.Lock, "PCR 16 reports locked")
}

func TestLockPCRs_LocksFromZero(t *testing.T) {
	t.Parallel()

	handle, _ := newTestHandle(t)

	require.NoError(t, handle.LockPCRs(18))
	locked, err := handle.DescribePCR(17)
	require.NoError(t, err)
	free, err := handle.DescribePCR(18)
	require.NoError(t, err)

	assert.True(t, locked.Lock, "PCR 17 is inside the range")
	assert.False(t, free.Lock, "PCR 18 is outside the range")
}

func TestRead_FillsBufferWithEntropy(t *testing.T) {
	t.Parallel()

	handle, _ := newTestHandle(t)
	// The simulated NSM returns 64 bytes a time, so 100 bytes take two requests.
	first := make([]byte, 100)
	second := make([]byte, 100)

	n, err := handle.Read(first)
	require.NoError(t, err)
	_, err = handle.Read(second)
	require.NoError(t, err)

	assert.Equal(t, 100, n)
	assert.NotEqual(t, make([]byte, 100), first)
	assert.NotEqual(t, first[:36], first[64:], "the second request must not repeat the first")
	assert.NotEqual(t, first, second)
}

// Every typed method must surface a refusal from the NSM as *nsm.Error, and
// must treat a reply of another kind as InvalidResponse.
func TestNSMRequests_ReportRefusalAndWrongReply(t *testing.T) {
	t.Parallel()

	calls := []struct {
		name string
		call func(*EnclaveHandle) error
	}{
		{name: "DescribePCR", call: func(h *EnclaveHandle) error { _, err := h.DescribePCR(16); return err }},
		{name: "ExtendPCR", call: func(h *EnclaveHandle) error { _, err := h.ExtendPCR(16, []byte("x")); return err }},
		{name: "LockPCR", call: func(h *EnclaveHandle) error { return h.LockPCR(16) }},
		{name: "LockPCRs", call: func(h *EnclaveHandle) error { return h.LockPCRs(16) }},
		{name: "Describe", call: func(h *EnclaveHandle) error { _, err := h.Describe(); return err }},
		{name: "Read", call: func(h *EnclaveHandle) error { _, err := h.Read(make([]byte, 8)); return err }},
	}

	handle, device := newTestHandle(t)

	for _, tt := range calls {
		t.Run(tt.name+" refused", func(t *testing.T) {
			device.ReplyWith(nil)
			device.RefuseWith(response.ECInternalError)

			requireCode(t, tt.call(handle), response.ECInternalError)
		})
		t.Run(tt.name+" wrong reply", func(t *testing.T) {
			device.RefuseWith("")
			// No request is answered with an attestation except Attest.
			device.ReplyWith(attestationReply([]byte("unexpected")))

			requireCode(t, tt.call(handle), response.ECInvalidResponse)
		})
	}
}

func TestDescribePCR_RefusesIndexPastLastPCR(t *testing.T) {
	t.Parallel()

	handle, _ := newTestHandle(t)

	_, err := handle.DescribePCR(32)

	requireCode(t, err, response.ECInvalidIndex)
}

// A PCR always has a value of the digest's length, so an empty one means the
// reply cannot be trusted.
func TestPCRRequests_RejectEmptyValue(t *testing.T) {
	t.Parallel()

	handle, device := newTestHandle(t)

	t.Run("DescribePCR", func(t *testing.T) {
		device.ReplyWith(map[string]response.DescribePCR{"DescribePCR": {Lock: true, Data: []byte{}}})

		_, err := handle.DescribePCR(16)

		requireCode(t, err, response.ECInvalidResponse)
	})
	t.Run("ExtendPCR", func(t *testing.T) {
		device.ReplyWith(map[string]response.ExtendPCR{"ExtendPCR": {Data: []byte{}}})

		_, err := handle.ExtendPCR(16, []byte("measurement"))

		requireCode(t, err, response.ECInvalidResponse)
	})
}
