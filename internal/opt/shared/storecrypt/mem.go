package storecrypt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"
)

// Used as mock in unit-tests

type InMemoryStorage struct {
	Files map[string][]byte
	mu    sync.RWMutex
}

var _ Storage = &InMemoryStorage{}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		Files: make(map[string][]byte),
	}
}

func (s *InMemoryStorage) Put(_ context.Context, path string, r io.Reader) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.Files[path] = data
	return nil
}

func (s *InMemoryStorage) Get(_ context.Context, path string) (io.ReadCloser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, ok := s.Files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *InMemoryStorage) List(_ context.Context, path string) ([]FileInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var infos []FileInfo
	prefix := storagePrefix(path)

	for name, data := range s.Files {
		if strings.HasPrefix(name, prefix) {
			infos = append(infos, FileInfo{
				Path:    name,
				ModTime: time.Now(),
				Size:    int64(len(data)),
			})
		}
	}
	return infos, nil
}

func (s *InMemoryStorage) Delete(_ context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.Files[path]; !ok {
		return fs.ErrNotExist
	}
	delete(s.Files, path)
	return nil
}

func (s *InMemoryStorage) DeleteDir(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	prefix := storagePrefix(path)

	for key := range s.Files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if strings.HasPrefix(key, prefix) || key == path {
			delete(s.Files, key)
		}
	}

	return nil
}

func (s *InMemoryStorage) Exists(_ context.Context, path string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.Files[path]
	return ok, nil
}

func (s *InMemoryStorage) ListTopLevelDirs(ctx context.Context, prefix string) (map[string]bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]bool)
	normalizedPrefix := storagePrefix(prefix)

	for filePath := range s.Files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if strings.HasPrefix(filePath, normalizedPrefix) {
			relativePath := strings.TrimPrefix(filePath, normalizedPrefix)
			if idx := strings.Index(relativePath, "/"); idx != -1 {
				dirname := relativePath[:idx]
				if dirname != "" {
					result[dirname] = true
				}
			}
		}
	}

	return result, nil
}

func storagePrefix(path string) string {
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return ""
	}
	return path + "/"
}

func (s *InMemoryStorage) ListPrefix(_ context.Context, prefix string) ([]FileInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var infos []FileInfo
	for name, data := range s.Files {
		if strings.HasPrefix(name, prefix) {
			infos = append(infos, FileInfo{
				Path:    name,
				ModTime: time.Now(),
				Size:    int64(len(data)),
			})
		}
	}
	return infos, nil
}

func (s *InMemoryStorage) Rename(ctx context.Context, oldRemotePath, newRemotePath string) error {
	if oldRemotePath == newRemotePath {
		return nil
	}

	// Quick ctx check before locking
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check again after we hold the lock in case caller cancels while waiting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	data, ok := s.Files[oldRemotePath]
	if !ok {
		return errors.New("file not found")
	}

	// Move entry under new key
	s.Files[newRemotePath] = data
	delete(s.Files, oldRemotePath)

	return nil
}
