package nsmtest_test

import (
	"crypto/sha512"
	"syscall"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkilar/nitro-enclaves-sdk-go/internal/nsmtest"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// newSession returns a session on a new simulated NSM, and the NSM.
func newSession(t *testing.T) (*nsm.Session, *nsmtest.Device) {
	t.Helper()

	device := nsmtest.NewDevice()
	session := nsm.NewSession(device)
	t.Cleanup(func() { require.NoError(t, session.Close()) })

	return session, device
}

// send sends req and fails the test if the NSM does not accept it.
func send(t *testing.T, session *nsm.Session, req request.Request) response.Response {
	t.Helper()

	res, err := session.Send(req)
	require.NoError(t, err)

	return res
}

// reservedPCRs is the indexes [0, 16).
func reservedPCRs() []uint16 {
	return []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
}

func TestDevice_DescribesANewEnclave(t *testing.T) {
	t.Parallel()

	session, _ := newSession(t)

	res := send(t, session, &request.DescribeNSM{})

	require.NotNil(t, res.DescribeNSM)
	assert.Equal(t, response.DescribeNSM{
		VersionMajor: 1,
		ModuleID:     "i-0123456789abcdef0-enc0123456789abcdef",
		MaxPCRs:      32,
		LockedPCRs:   reservedPCRs(),
		Digest:       response.DigestSHA384,
	}, *res.DescribeNSM)
}

func TestDevice_NewPCRsAreZero(t *testing.T) {
	t.Parallel()

	session, _ := newSession(t)

	tests := []struct {
		name     string
		index    uint16
		wantLock bool
	}{
		{name: "reserved PCR is locked", index: 0, wantLock: true},
		{name: "last reserved PCR is locked", index: 15, wantLock: true},
		{name: "first free PCR is unlocked", index: 16},
		{name: "last PCR is unlocked", index: 31},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := send(t, session, &request.DescribePCR{Index: tt.index})

			require.NotNil(t, res.DescribePCR)
			assert.Equal(t, tt.wantLock, res.DescribePCR.Lock)
			assert.Equal(t, make([]byte, 48), res.DescribePCR.Data)
		})
	}
}

func TestDevice_ExtendChainsSHA384(t *testing.T) {
	t.Parallel()

	session, _ := newSession(t)
	first := sha512.Sum384(append(make([]byte, 48), "one"...))
	second := sha512.Sum384(append(first[:], "two"...))

	afterOne := send(t, session, &request.ExtendPCR{Index: 16, Data: []byte("one")})
	afterTwo := send(t, session, &request.ExtendPCR{Index: 16, Data: []byte("two")})
	described := send(t, session, &request.DescribePCR{Index: 16})

	require.NotNil(t, afterOne.ExtendPCR)
	require.NotNil(t, afterTwo.ExtendPCR)
	require.NotNil(t, described.DescribePCR)
	assert.Equal(t, first[:], afterOne.ExtendPCR.Data)
	assert.Equal(t, second[:], afterTwo.ExtendPCR.Data)
	assert.Equal(t, second[:], described.DescribePCR.Data)
}

func TestDevice_LockedPCRCannotBeExtended(t *testing.T) {
	t.Parallel()

	session, _ := newSession(t)
	send(t, session, &request.ExtendPCR{Index: 16, Data: []byte("one")})
	before := send(t, session, &request.DescribePCR{Index: 16})

	locked := send(t, session, &request.LockPCR{Index: 16})
	_, err := session.Send(&request.ExtendPCR{Index: 16, Data: []byte("two")})
	after := send(t, session, &request.DescribePCR{Index: 16})

	assert.NotNil(t, locked.LockPCR)
	var nsmErr *nsm.Error
	require.ErrorAs(t, err, &nsmErr)
	assert.Equal(t, response.ECReadOnlyIndex, nsmErr.Code)
	require.NotNil(t, before.DescribePCR)
	require.NotNil(t, after.DescribePCR)
	assert.True(t, after.DescribePCR.Lock, "PCR 16 reports locked")
	assert.Equal(t, before.DescribePCR.Data, after.DescribePCR.Data)
}

func TestDevice_RefusesInvalidRequests(t *testing.T) {
	t.Parallel()

	session, _ := newSession(t)

	tests := []struct {
		name string
		req  request.Request
		want response.ErrorCode
	}{
		{name: "describe past the last PCR", req: &request.DescribePCR{Index: 32}, want: response.ECInvalidIndex},
		{name: "extend past the last PCR", req: &request.ExtendPCR{Index: 32}, want: response.ECInvalidIndex},
		{name: "extend a reserved PCR", req: &request.ExtendPCR{Index: 0}, want: response.ECReadOnlyIndex},
		{name: "lock a reserved PCR", req: &request.LockPCR{Index: 15}, want: response.ECReadOnlyIndex},
		{name: "lock past the last PCR", req: &request.LockPCR{Index: 32}, want: response.ECInvalidIndex},
		{name: "lock a range past the last PCR", req: &request.LockPCRs{Range: 33}, want: response.ECInvalidIndex},
		{name: "unknown request", req: unknownRequest{}, want: response.ECInvalidOperation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := session.Send(tt.req)

			var nsmErr *nsm.Error
			require.ErrorAs(t, err, &nsmErr)
			assert.Equal(t, tt.want, nsmErr.Code)
		})
	}
}

// unknownRequest is a request no NSM understands.
type unknownRequest struct{}

func (unknownRequest) Encoded() any { return "Bogus" }

func TestDevice_LockPCRsLocksFromZero(t *testing.T) {
	t.Parallel()

	session, _ := newSession(t)

	locked := send(t, session, &request.LockPCRs{Range: 18})
	described := send(t, session, &request.DescribeNSM{})

	assert.NotNil(t, locked.LockPCRs)
	require.NotNil(t, described.DescribeNSM)
	assert.Equal(t, append(reservedPCRs(), 16, 17), described.DescribeNSM.LockedPCRs)
}

func TestDevice_AttestsLockedPCRsAndEchoesRequest(t *testing.T) {
	t.Parallel()

	session, device := newSession(t)
	req := &request.Attestation{
		UserData:  []byte("user data"),
		Nonce:     []byte("nonce"),
		PublicKey: []byte("public key"),
	}

	res := send(t, session, req)

	require.NotNil(t, res.Attestation)
	var envelope []cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(res.Attestation.Document, &envelope))
	require.Len(t, envelope, 4, "COSE_Sign1 is protected, unprotected, payload, signature")
	var payload []byte
	require.NoError(t, cbor.Unmarshal(envelope[2], &payload))
	doc, err := nsm.ParseAttestationDoc(payload)
	require.NoError(t, err)

	assert.Equal(t, "i-0123456789abcdef0-enc0123456789abcdef", doc.ModuleID)
	assert.Equal(t, response.DigestSHA384, doc.Digest)
	assert.Equal(t, uint64(1700000000000), doc.Timestamp)
	assert.Equal(t, []byte("user data"), doc.UserData)
	assert.Equal(t, []byte("nonce"), doc.Nonce)
	assert.Equal(t, []byte("public key"), doc.PublicKey)
	assert.Len(t, doc.PCRs, 16)
	assert.Equal(t, make([]byte, 48), doc.PCRs[15])

	last, ok := device.LastAttestation()
	require.True(t, ok, "the device recorded the attestation request")
	assert.Equal(t, *req, last)
}

func TestDevice_LastAttestationIsEmptyBeforeAnyRequest(t *testing.T) {
	t.Parallel()

	_, device := newSession(t)

	_, ok := device.LastAttestation()

	assert.False(t, ok, "no attestation request has been made")
}

func TestDevice_RandomDiffersBetweenCalls(t *testing.T) {
	t.Parallel()

	session, _ := newSession(t)

	first := send(t, session, &request.GetRandom{})
	second := send(t, session, &request.GetRandom{})

	require.NotNil(t, first.GetRandom)
	require.NotNil(t, second.GetRandom)
	assert.Len(t, first.GetRandom.Random, 64)
	assert.NotEqual(t, first.GetRandom.Random, second.GetRandom.Random)
}

func TestDevice_RefuseWith(t *testing.T) {
	t.Parallel()

	session, device := newSession(t)

	device.RefuseWith(response.ECInternalError)
	_, refused := session.Send(&request.DescribeNSM{})
	device.RefuseWith("")
	_, restored := session.Send(&request.DescribeNSM{})

	var nsmErr *nsm.Error
	require.ErrorAs(t, refused, &nsmErr)
	assert.Equal(t, response.ECInternalError, nsmErr.Code)
	require.NoError(t, restored)
}

func TestDevice_FailWith(t *testing.T) {
	t.Parallel()

	session, device := newSession(t)

	device.FailWith(syscall.EIO)
	_, failed := session.Send(&request.DescribeNSM{})
	device.FailWith(nil)
	_, restored := session.Send(&request.DescribeNSM{})

	require.ErrorIs(t, failed, syscall.EIO)
	require.NoError(t, restored)
}

func TestDevice_ReplyWith(t *testing.T) {
	t.Parallel()

	session, device := newSession(t)

	device.ReplyWith("LockPCRs")
	canned := send(t, session, &request.DescribeNSM{})
	device.ReplyWith(nil)
	restored := send(t, session, &request.DescribeNSM{})

	assert.NotNil(t, canned.LockPCRs)
	assert.NotNil(t, restored.DescribeNSM)
}

func TestDevice_RejectsOversizedRequestLikeTheDriver(t *testing.T) {
	t.Parallel()

	device := nsmtest.NewDevice()

	n, err := device.Exchange(make([]byte, nsm.MaxRequestSize+1), make([]byte, nsm.MaxResponseSize))

	require.ErrorIs(t, err, syscall.EMSGSIZE)
	assert.Zero(t, n)
}

func TestDevice_StopsAnsweringOnceClosed(t *testing.T) {
	t.Parallel()

	device := nsmtest.NewDevice()
	require.False(t, device.Closed(), "a new device is open")

	require.NoError(t, device.Close())
	n, err := device.Exchange([]byte{0x60}, make([]byte, nsm.MaxResponseSize))

	assert.True(t, device.Closed(), "Close marks the device closed")
	require.Error(t, err)
	assert.Zero(t, n)
}
