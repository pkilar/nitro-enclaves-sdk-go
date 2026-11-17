//go:build linux && (amd64 || arm64)

package nsm

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// devicePath is where the kernel exposes the NSM inside an enclave.
const devicePath = "/dev/nsm"

// ioctlMessage is the argument of the NSM ioctl, the kernel's struct nsm_raw:
// one {u64 address, u64 length} pair for the encoded request and one for the
// buffer the reply is written into. syscall.Iovec has that layout only on a
// 64-bit system, which is why this file is built for amd64 and arm64 alone.
type ioctlMessage struct {
	request  syscall.Iovec
	response syscall.Iovec
}

// The layout of an ioctl command number, from the kernel's
// include/uapi/asm-generic/ioctl.h. It holds for x86-64 and arm64, the
// architectures Nitro Enclaves run on.
const (
	iocNumberBits = 8
	iocTypeBits   = 8
	iocSizeBits   = 14

	iocTypeShift      = iocNumberBits
	iocSizeShift      = iocTypeShift + iocTypeBits
	iocDirectionShift = iocSizeShift + iocSizeBits

	iocWrite = 1
	iocRead  = 2

	// nsmIoctlMagic is the NSM driver's ioctl type.
	nsmIoctlMagic = 0x0A
)

// ioctlCommand is _IOWR(nsmIoctlMagic, 0, struct nsm_message).
const ioctlCommand uintptr = (iocRead|iocWrite)<<iocDirectionShift |
	nsmIoctlMagic<<iocTypeShift |
	unsafe.Sizeof(ioctlMessage{})<<iocSizeShift

// fileDevice is the NSM device file.
type fileDevice struct {
	file *os.File
}

// Open opens the NSM device of the enclave this process runs in.
func Open() (*Session, error) {
	file, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("nsm: open device: %w", err)
	}

	return NewSession(&fileDevice{file: file}), nil
}

// Exchange implements Device.
func (d *fileDevice) Exchange(request, response []byte) (int, error) {
	if len(request) == 0 || len(response) == 0 {
		return 0, errors.New("nsm: exchange needs a request and a response buffer")
	}

	msg := ioctlMessage{
		request:  syscall.Iovec{Base: &request[0]},
		response: syscall.Iovec{Base: &response[0]},
	}
	msg.request.SetLen(len(request))
	msg.response.SetLen(len(response))

	// The pointer is converted in the call expression, which is the form
	// the unsafe.Pointer rules guarantee stays valid for the call.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, d.file.Fd(), ioctlCommand, uintptr(unsafe.Pointer(&msg)))
	runtime.KeepAlive(d.file)
	if errno != 0 {
		return 0, &IoctlError{Errno: errno}
	}

	return int(msg.response.Len), nil
}

// Close implements Device.
func (d *fileDevice) Close() error {
	return d.file.Close()
}
