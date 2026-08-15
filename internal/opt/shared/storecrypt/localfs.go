package storecrypt

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pgrwl/pgrwl/internal/core/fsync"
)

type LocalStorageOpts struct {
	BaseDir      string
	FsyncOnWrite bool
}

type localStorage struct {
	baseDir      string
	fsyncOnWrite bool
}

var _ Storage = &localStorage{}

func NewLocal(o *LocalStorageOpts) (Storage, error) {
	bd := strings.TrimSuffix(o.BaseDir, "/")
	if err := os.MkdirAll(bd, 0o750); err != nil {
		return nil, err
	}
	return &localStorage{baseDir: bd, fsyncOnWrite: o.FsyncOnWrite}, nil
}

func (l *localStorage) fullPath(path string) string {
	return filepath.ToSlash(filepath.Join(l.baseDir, filepath.Clean(path)))
}

func (l *localStorage) Put(_ context.Context, remotePath string, r io.Reader) error {
	fullPath := l.fullPath(remotePath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o750); err != nil {
		return err
	}
	f, err := os.Create(fullPath)
	if err != nil {
		return err
	}

	// Copy contents
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close() // ignore close error if we already have a copy error
		return err
	}

	// Fsync if needed
	if l.fsyncOnWrite {
		if err := fsync.Fsync(f); err != nil {
			_ = f.Close() // same here: best-effort
			return err
		}
	}

	// Now close, and return any close error
	return f.Close()
}

func (l *localStorage) Get(_ context.Context, remotePath string) (io.ReadCloser, error) {
	return os.Open(l.fullPath(remotePath))
}

func (l *localStorage) List(_ context.Context, remotePath string) ([]FileInfo, error) {
	fullPath := l.fullPath(remotePath)
	var result []FileInfo

	err := filepath.WalkDir(fullPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %q: %w", path, err)
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(l.baseDir, path)
		if err != nil {
			return err
		}
		stat, err := os.Stat(path)
		if err != nil {
			return err
		}
		result = append(result, FileInfo{
			Path:    filepath.ToSlash(rel),
			ModTime: stat.ModTime(),
			Size:    stat.Size(),
		})
		return nil
	})
	return result, err
}

func (l *localStorage) Delete(_ context.Context, remotePath string) error {
	return os.Remove(l.fullPath(remotePath))
}

func (l *localStorage) DeleteDir(_ context.Context, remotePath string) error {
	return os.RemoveAll(l.fullPath(remotePath))
}

func (l *localStorage) Exists(_ context.Context, remotePath string) (bool, error) {
	fullPath := l.fullPath(remotePath)

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	if info.Mode().IsRegular() {
		return true, nil
	}
	return false, nil
}

func (l *localStorage) ListTopLevelDirs(_ context.Context, prefix string) (map[string]bool, error) {
	fullPath := l.fullPath(prefix)
	result := make(map[string]bool)

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			dirFullPath := filepath.ToSlash(filepath.Join(fullPath, entry.Name()))
			rel, err := filepath.Rel(l.baseDir, dirFullPath)
			if err != nil {
				return nil, err
			}
			result[filepath.ToSlash(rel)] = true
		}
	}
	return result, nil
}

func (l *localStorage) ListPrefix(_ context.Context, remotePath string) ([]FileInfo, error) {
	fullPath := l.fullPath(remotePath)
	dir := filepath.Dir(fullPath)
	namePrefix := filepath.Base(fullPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []FileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), namePrefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(l.baseDir, filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		result = append(result, FileInfo{
			Path:    filepath.ToSlash(rel),
			ModTime: info.ModTime(),
			Size:    info.Size(),
		})
	}
	return result, nil
}

func (l *localStorage) Rename(_ context.Context, oldRemotePath, newRemotePath string) error {
	oldFull := l.fullPath(oldRemotePath)
	newFull := l.fullPath(newRemotePath)

	if oldFull == newFull {
		return nil
	}

	// Ensure target directory exists
	if err := os.MkdirAll(filepath.Dir(newFull), 0o750); err != nil {
		return err
	}

	return os.Rename(oldFull, newFull)
}
