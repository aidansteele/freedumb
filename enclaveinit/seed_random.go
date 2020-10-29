package main

// copied from https://github.com/kata-containers/agent/blob/eec68398287d9491fe648a8e54fb942cf6b6d934/random_linux.go

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	rngDev = "/dev/random"

	// include/uapi/linux/random.h
	// RNDADDTOENTCNT _IOW( 'R', 0x01, int )
	// RNDRESEEDCRNG   _IO( 'R', 0x07 )
	iocRNDADDTOENTCNT = 0x40045201
	iocRNDRESEEDCRNG  = 0x5207
)

func reseedRNG(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("missing entropy data")
	}

	// Write entropy
	f, err := os.OpenFile(rngDev, os.O_WRONLY, 0)
	if err != nil {
	    return errors.WithStack(err)
	}

	defer f.Close()
	n, err := f.Write(data)
	if err != nil {
	    return errors.WithStack(err)
	}

	if n < len(data) {
		return errors.New("Short write to rng device")
	}

	// Add data to the entropy count
	_, _, errNo := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), iocRNDADDTOENTCNT, uintptr(unsafe.Pointer(&n)))
	if errNo != 0 {
		fmt.Fprintln(os.Stderr, "Could not add to rng entropy count, ignoring")
	}

	// Newer kernel supports RNDRESEEDCRNG ioctl to actively kick-off reseed.
	// Let's make use of it if possible.
	_, _, errNo = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), iocRNDRESEEDCRNG, 0)
	if errNo != 0 {
		fmt.Fprintln(os.Stderr, "Could not reseed rng, ignoring")
	}

	return nil
}
