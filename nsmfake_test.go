package enclave

import (
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/stretchr/testify/require"
)

// fakeNSM stands in for the /dev/nsm device behind a real *nsm.Session, so
// that hf/nsm's own request encoding and response decoding run in tests.
type fakeNSM struct {
	// reply is CBOR-encoded and returned for every request.
	reply any
	// errno, when non-zero, fails the ioctl instead of replying.
	errno syscall.Errno
	// request is the most recent attestation request the device received.
	request request.Attestation

	fd uintptr
}

// attestationReply is the response an NSM gives to an attestation request.
func attestationReply(document []byte) any {
	return map[string]any{"Attestation": map[string]any{"document": document}}
}

// errorReply is the response an NSM gives when it rejects a request.
func errorReply(code string) any {
	return map[string]string{"Error": code}
}

// fakeDevices finds the fakeNSM behind a descriptor. The ioctl hook is a
// plain function that receives only the descriptor, so this is how it reaches
// the device a session was opened on.
var fakeDevices struct {
	sync.Mutex
	byFd   map[uintptr]*fakeNSM
	lastFd uintptr
}

// openFakeNSM returns a real NSM session wired to device instead of /dev/nsm.
func openFakeNSM(t *testing.T, device *fakeNSM) *nsm.Session {
	t.Helper()

	fakeDevices.Lock()
	fakeDevices.lastFd++
	device.fd = fakeDevices.lastFd
	if fakeDevices.byFd == nil {
		fakeDevices.byFd = make(map[uintptr]*fakeNSM)
	}
	fakeDevices.byFd[device.fd] = device
	fakeDevices.Unlock()

	session, err := nsm.OpenSession(nsm.Options{
		Open:    func() (nsm.FileDescriptor, error) { return device, nil },
		Syscall: fakeIoctl,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })

	return session
}

// Fd implements nsm.FileDescriptor.
func (f *fakeNSM) Fd() uintptr { return f.fd }

// Close implements nsm.FileDescriptor.
func (f *fakeNSM) Close() error {
	fakeDevices.Lock()
	delete(fakeDevices.byFd, f.fd)
	fakeDevices.Unlock()

	return nil
}

// ioctlMessage mirrors the unexported struct hf/nsm passes to the NSM ioctl:
// one iovec for the encoded request and one for the response buffer.
type ioctlMessage struct {
	Request  syscall.Iovec
	Response syscall.Iovec
}

// fakeIoctl is the nsm.Options.Syscall hook.
//
// hf/nsm passes the address of an ioctlMessage on its own stack as a uintptr,
// which the runtime does not update if that stack moves. nosplit keeps this
// function from growing the stack on entry, so the address is still valid
// when it is turned back into a pointer; syscall.Syscall, which this hook
// replaces, is nosplit too. From then on the pointer is typed and follows the
// stack.
//
// The conversion reads arg's own memory as a pointer because go vet rejects a
// direct unsafe.Pointer(arg).
//
//go:nosplit
func fakeIoctl(_, fd, _, arg uintptr) (uintptr, uintptr, syscall.Errno) {
	return 0, 0, serveIoctl(fd, *(**ioctlMessage)(unsafe.Pointer(&arg)))
}

// serveIoctl plays the device's part of one ioctl: it records the request and
// writes the configured reply into the response buffer.
func serveIoctl(fd uintptr, msg *ioctlMessage) syscall.Errno {
	fakeDevices.Lock()
	device, ok := fakeDevices.byFd[fd]
	fakeDevices.Unlock()
	if !ok {
		return syscall.EBADF
	}
	if device.errno != 0 {
		return device.errno
	}

	var requests map[string]request.Attestation
	if err := cbor.Unmarshal(unsafe.Slice(msg.Request.Base, msg.Request.Len), &requests); err != nil {
		return syscall.EINVAL
	}
	attestation, ok := requests["Attestation"]
	if !ok {
		return syscall.EINVAL
	}
	device.request = attestation

	reply, err := cbor.Marshal(device.reply)
	if err != nil {
		return syscall.EINVAL
	}
	response := unsafe.Slice(msg.Response.Base, msg.Response.Len)
	if len(reply) > len(response) {
		return syscall.EMSGSIZE
	}
	msg.Response.SetLen(copy(response, reply))

	return 0
}
