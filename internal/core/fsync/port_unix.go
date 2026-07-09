//go:build !windows

package fsync

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func Fsync(f *os.File) error {
	//nolint:gosec
	return syscall.Fsync(int(f.Fd()))
}

func FsyncFd(fd int) error {
	//nolint:gosec
	return syscall.Fsync(fd)
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
	d, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("cannot open dir %s: %w", dirPath, err)
	}
	if err := Fsync(d); err != nil {
		_ = d.Close()
		return fmt.Errorf("cannot fsync dir %s: %w", dirPath, err)
	}
	return d.Close()
}

// FsyncFnameAndDir fsyncs the file by its path, and the parent dir
//
//nolint:revive
func FsyncFnameAndDir(fname string) error {
	if err := FsyncFname(fname); err != nil {
		return err
	}
	return FsyncDir(filepath.Dir(fname))
}
