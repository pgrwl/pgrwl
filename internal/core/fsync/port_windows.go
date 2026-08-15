//go:build windows

package fsync

import (
	"os"
	"syscall"
)

func Fsync(f *os.File) error {
	return syscall.FlushFileBuffers(syscall.Handle(f.Fd()))
}

func FsyncFd(fd int) error {
	return syscall.FlushFileBuffers(syscall.Handle(fd))
}

// FsyncFname fsyncs path contents and the parent directory contents.
//
//nolint:revive
func FsyncFname(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := Fsync(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// FsyncDir fsyncs dir contents.
//
//nolint:revive
func FsyncDir(dirPath string) error {
	return nil
}

// FsyncFnameAndDir fsyncs the file by its path, and the parent dir
//
//nolint:revive
func FsyncFnameAndDir(fname string) error {
	return FsyncFname(fname)
}
