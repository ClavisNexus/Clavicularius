//go:build darwin

package tty

import (
	"syscall"
	"unsafe"
)

func getTermios(fd int) (*syscall.Termios, error) {
	var t syscall.Termios
	if err := ioctl(fd, syscall.TIOCGETA, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func setTermios(fd int, t *syscall.Termios) error {
	return ioctl(fd, syscall.TIOCSETAW, t)
}

func ioctl(fd int, req uint, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}
