package storecrypt

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
)

type sftpStorage struct {
	client  *sftp.Client
	baseDir string
}

var _ Storage = &sftpStorage{}

func NewSFTPStorage(client *sftp.Client, remoteDir string) Storage {
	return &sftpStorage{
		client:  client,
		baseDir: strings.TrimSuffix(remoteDir, "/"),
	}
}

func (s *sftpStorage) fullPath(p string) string {
	return filepath.ToSlash(filepath.Join(s.baseDir, filepath.Clean(p)))
}

func (s *sftpStorage) Put(_ context.Context, remotePath string, r io.Reader) error {
	fullPath := s.fullPath(remotePath)

	// Ensure directory exists
	dir := path.Dir(fullPath)
	if err := s.client.MkdirAll(dir); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Open file for writing
	f, err := s.client.Create(fullPath)
	if err != nil {
		return fmt.Errorf("sftp create: %w", err)
	}
	defer f.Close()

	_, err = io.Copy(f, r)
	return err
}

func (s *sftpStorage) Get(_ context.Context, remotePath string) (io.ReadCloser, error) {
	fullPath := s.fullPath(remotePath)
	f, err := s.client.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("sftp open: %w", err)
	}
	return f, nil
}

func (s *sftpStorage) List(_ context.Context, remotePath string) ([]FileInfo, error) {
	fullPath := s.fullPath(remotePath)
	var result []FileInfo

	walker := s.client.Walk(fullPath)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			if os.IsNotExist(err) || strings.Contains(err.Error(), "file does not exist") {
				return nil, nil
			}
			return nil, fmt.Errorf("error walking directory: %w", err)
		}
		stat := walker.Stat()
		if stat == nil {
			continue
		}
		if stat.IsDir() {
			continue
		}
		if walker.Path() != fullPath {
			rel, err := filepath.Rel(s.baseDir, walker.Path())
			if err != nil {
				return nil, err
			}
			result = append(result, FileInfo{
				Path:    rel,
				ModTime: stat.ModTime(),
				Size:    stat.Size(),
			})
		}
	}

	return result, nil
}

func (s *sftpStorage) Delete(_ context.Context, remotePath string) error {
	return s.client.Remove(s.fullPath(remotePath))
}

func (s *sftpStorage) DeleteDir(_ context.Context, remotePath string) error {
	return s.client.RemoveAll(s.fullPath(remotePath))
}

func (s *sftpStorage) Exists(_ context.Context, remotePath string) (bool, error) {
	fullPath := s.fullPath(remotePath)
	info, err := s.client.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

func (s *sftpStorage) ListTopLevelDirs(_ context.Context, prefix string) (map[string]bool, error) {
	fullPath := s.fullPath(prefix)
	result := make(map[string]bool)

	entries, err := s.client.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			dirFullPath := filepath.ToSlash(filepath.Join(fullPath, entry.Name()))
			rel, err := filepath.Rel(s.baseDir, dirFullPath)
			if err != nil {
				return nil, err
			}
			result[filepath.ToSlash(rel)] = true
		}
	}
	return result, nil
}

func (s *sftpStorage) ListPrefix(_ context.Context, remotePath string) ([]FileInfo, error) {
	fullPath := s.fullPath(remotePath)
	dir := path.Dir(fullPath)
	namePrefix := path.Base(fullPath)

	entries, err := s.client.ReadDir(dir)
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
		entryPath := filepath.ToSlash(filepath.Join(dir, entry.Name()))
		rel, err := filepath.Rel(s.baseDir, entryPath)
		if err != nil {
			return nil, err
		}
		result = append(result, FileInfo{
			Path:    filepath.ToSlash(rel),
			ModTime: entry.ModTime(),
			Size:    entry.Size(),
		})
	}
	return result, nil
}

func (s *sftpStorage) Rename(_ context.Context, oldRemotePath, newRemotePath string) error {
	oldFull := s.fullPath(oldRemotePath)
	newFull := s.fullPath(newRemotePath)

	if oldFull == newFull {
		return nil
	}

	// Ensure destination directory exists
	dir := path.Dir(newFull)
	if err := s.client.MkdirAll(dir); err != nil {
		return fmt.Errorf("mkdir dest dir %q: %w", dir, err)
	}

	if err := s.client.Rename(oldFull, newFull); err != nil {
		return fmt.Errorf("sftp rename %q -> %q: %w", oldFull, newFull, err)
	}

	return nil
}
