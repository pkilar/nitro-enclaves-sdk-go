package nsm

import (
	"errors"
	"fmt"
	"sync"
	"syscall"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// ErrSessionClosed is returned by a Session that has been closed, or that was
// created without a device.
var ErrSessionClosed = errors.New("nsm: session is closed")

// IoctlError reports that the call to the NSM device itself failed.
type IoctlError struct {
	Errno syscall.Errno
}

// Error implements error.
func (e *IoctlError) Error() string {
	return fmt.Sprintf("nsm: ioctl failed: %v", e.Errno)
}

// Unwrap returns the errno, so errors.Is(err, syscall.EIO) works.
func (e *IoctlError) Unwrap() error {
	return e.Errno
}

// Device exchanges one encoded request for one encoded response.
type Device interface {
	// Exchange sends request to the device and writes the reply into
	// response, returning the reply's length.
	Exchange(request, response []byte) (int, error)
	// Close releases the device.
	Close() error
}

// responseBuffers recycles the MaxResponseSize buffers that replies are read
// into. Decoding copies what it keeps, so a buffer is free again once Send
// returns.
var responseBuffers = sync.Pool{
	New: func() any {
		buf := make([]byte, MaxResponseSize)
		return &buf
	},
}

// Session is a connection to an NSM. Its methods may be called from several
// goroutines at once.
type Session struct {
	// mu guards device. Send holds it for reading across an exchange; Close
	// takes it for writing, so Close waits for exchanges in flight.
	mu     sync.RWMutex
	device Device // nil once closed
}

// NewSession returns a session on device. The session owns the device and
// closes it in Close. A session on a nil device behaves as a closed one.
func NewSession(device Device) *Session {
	return &Session{device: device}
}

// Send sends req to the NSM and returns its reply. A nil error means the reply
// is usable and exactly one of its fields is set.
//
// If the NSM refuses the request, or the request is larger than
// MaxRequestSize, the error is an *Error carrying the reason. If the call to
// the device fails, the error wraps what the device returned; for the real
// device that is an *IoctlError.
func (s *Session) Send(req request.Request) (response.Response, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.device == nil {
		return response.Response{}, ErrSessionClosed
	}

	encoded, err := encodeRequest(req)
	if err != nil {
		return response.Response{}, err
	}
	if len(encoded) > MaxRequestSize {
		return response.Response{}, &Error{Code: response.ECInputTooLarge}
	}

	buf, ok := responseBuffers.Get().(*[]byte)
	if !ok {
		return response.Response{}, errors.New("nsm: response buffer pool holds the wrong type")
	}
	defer responseBuffers.Put(buf)

	n, err := s.device.Exchange(encoded, *buf)
	if err != nil {
		// The device reports a request it finds too large with EMSGSIZE.
		if errors.Is(err, syscall.EMSGSIZE) {
			return response.Response{}, &Error{Code: response.ECInputTooLarge}
		}
		return response.Response{}, fmt.Errorf("nsm: exchange with device: %w", err)
	}
	if n < 0 || n > len(*buf) {
		return response.Response{}, fmt.Errorf("nsm: device reported a %d-byte reply", n)
	}

	return decodeResponse((*buf)[:n])
}

// Read fills p with entropy from the NSM, asking as many times as it takes.
// It implements io.Reader and returns len(p) unless a request fails.
func (s *Session) Read(p []byte) (int, error) {
	filled := 0
	for filled < len(p) {
		res, err := s.Send(&request.GetRandom{})
		if err != nil {
			return filled, err
		}
		if res.GetRandom == nil || len(res.GetRandom.Random) == 0 {
			return filled, &Error{Code: response.ECInvalidResponse}
		}
		filled += copy(p[filled:], res.GetRandom.Random)
	}

	return filled, nil
}

// Close closes the device. It waits for calls in flight, and calls made
// afterwards return ErrSessionClosed. Closing a closed session does nothing.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.device == nil {
		return nil
	}
	err := s.device.Close()
	s.device = nil

	return err
}
