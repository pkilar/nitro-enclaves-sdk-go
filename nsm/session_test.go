package nsm

import (
	"encoding/hex"
	"errors"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// Replies used across these tests, written out by hand.
const (
	replyLockPCR      = "674c6f636b504352"                                     // "LockPCR"
	replyInvalidIndex = "a1654572726f726c496e76616c6964496e646578"             // {"Error": "InvalidIndex"}
	replyRandom123    = "a16947657452616e646f6da16672616e646f6d43010203"       // {"GetRandom": {"random": h'010203'}}
	replyRandomEmpty  = "a16947657452616e646f6da16672616e646f6d40"             // {"GetRandom": {"random": h''}}
	replyDocument0102 = "a16b4174746573746174696f6ea168646f63756d656e74420102" // {"Attestation": {"document": h'0102'}}
	replyDocument0909 = "a16b4174746573746174696f6ea168646f63756d656e74420909" // {"Attestation": {"document": h'0909'}}
	requestLockPCR16  = "a1674c6f636b504352a165696e64657810"                   // {"LockPCR": {"index": 16}}
)

// scriptedDevice is a Device whose replies each test sets.
type scriptedDevice struct {
	mu sync.Mutex
	// replies are returned in order, one per exchange; the last one repeats.
	replies []string
	// err, when non-nil, fails every exchange.
	err error
	// closeErr is what Close returns.
	closeErr error

	requests [][]byte
	closed   int
}

func (d *scriptedDevice) Exchange(request, response []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.requests = append(d.requests, append([]byte(nil), request...))
	if d.err != nil {
		return 0, d.err
	}
	reply := d.replies[min(len(d.requests), len(d.replies))-1]
	decoded, err := hex.DecodeString(reply)
	if err != nil {
		return 0, err
	}

	return copy(response, decoded), nil
}

func (d *scriptedDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.closed++

	return d.closeErr
}

func (d *scriptedDevice) exchanges() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.requests)
}

// lengthDevice claims a reply of a fixed length without writing one.
type lengthDevice struct{ n int }

func (d lengthDevice) Exchange(_, _ []byte) (int, error) { return d.n, nil }
func (d lengthDevice) Close() error                      { return nil }

func TestSend_SendsEncodedRequestAndReturnsDecodedReply(t *testing.T) {
	t.Parallel()

	device := &scriptedDevice{replies: []string{replyLockPCR}}
	session := NewSession(device)

	got, err := session.Send(&request.LockPCR{Index: 16})

	require.NoError(t, err)
	assert.Equal(t, response.Response{LockPCR: &response.LockPCR{}}, got)
	require.Len(t, device.requests, 1)
	assert.Equal(t, requestLockPCR16, hex.EncodeToString(device.requests[0]))
}

func TestSend_ReturnsNSMErrorCode(t *testing.T) {
	t.Parallel()

	session := NewSession(&scriptedDevice{replies: []string{replyInvalidIndex}})

	_, err := session.Send(&request.DescribePCR{Index: 99})

	var nsmErr *Error
	require.ErrorAs(t, err, &nsmErr)
	assert.Equal(t, response.ECInvalidIndex, nsmErr.Code)
}

// An ExtendPCR request for index 16 encodes to 27 bytes plus its data, so 4069
// bytes of data make a request of exactly MaxRequestSize.
func TestSend_EnforcesMaxRequestSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		dataLen       int
		wantExchanges int
		wantCode      response.ErrorCode
	}{
		{name: "request of exactly the limit is sent", dataLen: 4069, wantExchanges: 1},
		{name: "request one byte over is refused before the device", dataLen: 4070, wantCode: response.ECInputTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := &scriptedDevice{replies: []string{replyLockPCR}}
			session := NewSession(device)

			_, err := session.Send(&request.ExtendPCR{Index: 16, Data: make([]byte, tt.dataLen)})

			assert.Equal(t, tt.wantExchanges, device.exchanges())
			if tt.wantCode == "" {
				require.NoError(t, err)
				return
			}
			var nsmErr *Error
			require.ErrorAs(t, err, &nsmErr)
			assert.Equal(t, tt.wantCode, nsmErr.Code)
		})
	}
}

func TestSend_ReportsEMSGSIZEAsInputTooLarge(t *testing.T) {
	t.Parallel()

	session := NewSession(&scriptedDevice{err: &IoctlError{Errno: syscall.EMSGSIZE}})

	_, err := session.Send(&request.GetRandom{})

	var nsmErr *Error
	require.ErrorAs(t, err, &nsmErr)
	assert.Equal(t, response.ECInputTooLarge, nsmErr.Code)
}

func TestSend_WrapsDeviceFailure(t *testing.T) {
	t.Parallel()

	session := NewSession(&scriptedDevice{err: &IoctlError{Errno: syscall.EIO}})

	_, err := session.Send(&request.GetRandom{})

	var ioctlErr *IoctlError
	require.ErrorAs(t, err, &ioctlErr)
	assert.Equal(t, syscall.EIO, ioctlErr.Errno)
	assert.ErrorIs(t, err, syscall.EIO)
}

func TestSend_RejectsImpossibleReplyLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		n    int
	}{
		{name: "negative", n: -1},
		{name: "longer than the buffer", n: MaxResponseSize + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := NewSession(lengthDevice{n: tt.n})

			_, err := session.Send(&request.GetRandom{})

			require.Error(t, err)
		})
	}
}

func TestSend_ReplyDoesNotShareMemoryWithLaterReplies(t *testing.T) {
	t.Parallel()

	session := NewSession(&scriptedDevice{replies: []string{replyDocument0102, replyDocument0909}})

	first, err := session.Send(&request.Attestation{})
	require.NoError(t, err)
	_, err = session.Send(&request.Attestation{})
	require.NoError(t, err)

	require.NotNil(t, first.Attestation)
	assert.Equal(t, []byte{0x01, 0x02}, first.Attestation.Document)
}

func TestSession_RefusesRequestsOnceClosed(t *testing.T) {
	t.Parallel()

	closed := NewSession(&scriptedDevice{replies: []string{replyLockPCR}})
	require.NoError(t, closed.Close())

	tests := []struct {
		name    string
		session *Session
	}{
		{name: "after Close", session: closed},
		{name: "created without a device", session: NewSession(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, sendErr := tt.session.Send(&request.GetRandom{})
			n, readErr := tt.session.Read(make([]byte, 4))

			require.ErrorIs(t, sendErr, ErrSessionClosed)
			require.ErrorIs(t, readErr, ErrSessionClosed)
			assert.Zero(t, n)
		})
	}
}

func TestClose_ClosesDeviceOnceAndReturnsItsError(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("device close failed")
	device := &scriptedDevice{closeErr: closeErr}
	session := NewSession(device)

	first := session.Close()
	second := session.Close()

	require.ErrorIs(t, first, closeErr)
	require.NoError(t, second)
	assert.Equal(t, 1, device.closed)
}

func TestRead_FillsBufferAcrossSeveralReplies(t *testing.T) {
	t.Parallel()

	device := &scriptedDevice{replies: []string{replyRandom123}}
	session := NewSession(device)
	buf := make([]byte, 8)

	n, err := session.Read(buf)

	require.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.Equal(t, []byte{1, 2, 3, 1, 2, 3, 1, 2}, buf)
	assert.Equal(t, 3, device.exchanges())
}

func TestRead_ReportsUnusableReply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		reply string
	}{
		{name: "no random bytes", reply: replyRandomEmpty},
		{name: "not a random reply", reply: replyLockPCR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := NewSession(&scriptedDevice{replies: []string{tt.reply}})

			n, err := session.Read(make([]byte, 4))

			var nsmErr *Error
			require.ErrorAs(t, err, &nsmErr)
			assert.Equal(t, response.ECInvalidResponse, nsmErr.Code)
			assert.Zero(t, n)
		})
	}
}

func TestRead_ReturnsCountReadBeforeFailure(t *testing.T) {
	t.Parallel()

	session := NewSession(&scriptedDevice{replies: []string{replyRandom123, replyInvalidIndex}})

	n, err := session.Read(make([]byte, 8))

	require.Error(t, err)
	assert.Equal(t, 3, n)
}

// Run with -race: Close must be safe while requests are in flight, and every
// request must either complete or report the closed session.
func TestSession_CloseIsSafeDuringRequests(t *testing.T) {
	t.Parallel()

	session := NewSession(&scriptedDevice{replies: []string{replyLockPCR}})

	const senders = 16
	errs := make(chan error, senders)
	var wg sync.WaitGroup
	for range senders {
		wg.Go(func() {
			for range 50 {
				if _, err := session.Send(&request.LockPCR{Index: 16}); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		})
	}
	require.NoError(t, session.Close())
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			assert.ErrorIs(t, err, ErrSessionClosed)
		}
	}
}
