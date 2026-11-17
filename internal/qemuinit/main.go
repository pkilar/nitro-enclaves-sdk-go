//go:build linux && amd64

// Command qemuinit is process 1 of the guest that `make qemu` boots. It does
// the part of an enclave's start that nsm-check depends on, runs /nsm-check
// and resets the machine, which ends the QEMU run.
//
// It stands in for two things a real enclave gets from elsewhere. An
// enclave's init loads the NSM driver, and this loads the same nsm.ko. The
// hypervisor locks PCRs [0, 16) before any of the enclave's code runs; a bare
// virtio-nsm device has nothing locked, so this locks them through the NSM.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
)

const (
	// sysFinitModule is finit_module(2) on linux/amd64. Package syscall has
	// no constant for it on that architecture.
	sysFinitModule = 313

	// reservedPCRs is how many PCRs, counting from 0, are locked by the time
	// an enclave's code starts.
	reservedPCRs = 16

	// argsVariable names the kernel parameter whose value becomes the
	// arguments of nsm-check. The kernel hands a parameter it does not know
	// to init as an environment variable.
	argsVariable = "nsm_check_args"
)

func main() {
	if err := run(); err != nil {
		// Before the console is attached this goes nowhere, and the run
		// still fails: nsm-check has not reported success.
		_, _ = fmt.Fprintln(os.Stderr, "qemuinit:", err)
	}

	// QEMU is started with -no-reboot, so a reset ends the run. Should the
	// reset fail, returning from process 1 panics the kernel, and panic=-1
	// on its command line resets it then.
	syscall.Sync()
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "qemuinit: reset:", err)
	}
}

// run prepares the guest and runs nsm-check in it.
func run() error {
	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		return fmt.Errorf("mount /dev: %w", err)
	}
	if err := attachConsole(); err != nil {
		return err
	}
	if err := loadModule("/nsm.ko"); err != nil {
		return err
	}
	if err := lockReservedPCRs(); err != nil {
		return err
	}

	check := exec.Command("/nsm-check", strings.Fields(os.Getenv(argsVariable))...)
	check.Stdout, check.Stderr = os.Stdout, os.Stderr
	if err := check.Run(); err != nil {
		return fmt.Errorf("nsm-check: %w", err)
	}

	return nil
}

// attachConsole makes the kernel console this process's standard input,
// output and error. An initramfs has no /dev/console of its own, so process 1
// starts without them.
func attachConsole() error {
	console, err := os.OpenFile("/dev/console", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer console.Close()

	for fd := range 3 {
		if err := syscall.Dup3(int(console.Fd()), fd, 0); err != nil {
			return fmt.Errorf("attach console to descriptor %d: %w", fd, err)
		}
	}

	return nil
}

// loadModule loads a kernel module with no parameters.
func loadModule(path string) error {
	module, err := os.Open(path)
	if err != nil {
		return err
	}
	defer module.Close()

	// The parameters are an empty C string. The pointer is converted in the
	// call expression, the form the unsafe.Pointer rules allow.
	parameters := [1]byte{}
	_, _, errno := syscall.Syscall(sysFinitModule, module.Fd(), uintptr(unsafe.Pointer(&parameters[0])), 0)
	if errno != 0 {
		return fmt.Errorf("load %s: %w", path, errno)
	}

	return nil
}

// lockReservedPCRs locks PCRs [0, reservedPCRs), as a hypervisor has done by
// the time an enclave's code starts.
func lockReservedPCRs() error {
	session, err := nsm.Open()
	if err != nil {
		return err
	}

	_, err = session.Send(&request.LockPCRs{Range: reservedPCRs})
	if err := errors.Join(err, session.Close()); err != nil {
		return fmt.Errorf("lock PCRs [0, %d): %w", reservedPCRs, err)
	}

	return nil
}
