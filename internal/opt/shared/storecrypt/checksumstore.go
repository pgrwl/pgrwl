package storecrypt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"strings"
)

const checksumSep = "--"

// ChecksumStorage wraps a Storage and stores each file as
// "{logicalName}--{sha256hex}". On Put the full content is buffered,
// hashed, and stored under the composite name. On Get the hash is verified
// while the data streams to the caller; a mismatch is returned as an error
// at EOF. All other methods translate between logical and physical names
// transparently.
type ChecksumStorage struct {
	inner Storage
}

var _ Storage = (*ChecksumStorage)(nil)

func NewChecksumStorage(inner Storage) *ChecksumStorage {
	return &ChecksumStorage{inner: inner}
}

// Put buffers the entire content, computes SHA-256, and stores as
// "{logicalName}--{sha256hex}".
func (cs *ChecksumStorage) Put(ctx context.Context, logicalName string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("checksumstore read: %w", err)
	}
	sum := sha256.Sum256(data)
	hexHash := hex.EncodeToString(sum[:])
	return cs.inner.Put(ctx, logicalName+checksumSep+hexHash, bytes.NewReader(data))
}

// Get resolves the physical name, retrieves the data, and wraps it in a
// reader that verifies the embedded SHA-256 at EOF.
func (cs *ChecksumStorage) Get(ctx context.Context, logicalName string) (io.ReadCloser, error) {
	physName, hexHash, err := cs.resolve(ctx, logicalName)
	if err != nil {
		return nil, err
	}
	rc, err := cs.inner.Get(ctx, physName)
	if err != nil {
		return nil, err
	}
	if hexHash == "" {
		// Legacy file stored without a checksum - pass through as-is.
		return rc, nil
	}
	return &verifyingReader{rc: rc, h: sha256.New(), expected: hexHash}, nil
}

// Delete finds and deletes the physical (checksummed) object.
func (cs *ChecksumStorage) Delete(ctx context.Context, logicalName string) error {
	physName, _, err := cs.resolve(ctx, logicalName)
	if err != nil {
		if isNotExist(err) {
			return nil
		}
		return err
	}
	return cs.inner.Delete(ctx, physName)
}

// Exists reports whether any checksummed variant of logicalName exists,
// falling back to the plain logical name for backward compatibility.
func (cs *ChecksumStorage) Exists(ctx context.Context, logicalName string) (bool, error) {
	infos, err := cs.inner.ListPrefix(ctx, logicalName+checksumSep)
	if err != nil {
		return false, err
	}
	if len(infos) > 0 {
		return true, nil
	}
	return cs.inner.Exists(ctx, logicalName)
}

// List lists the directory, stripping the "--{hash}" suffix from each path.
func (cs *ChecksumStorage) List(ctx context.Context, remotePath string) ([]FileInfo, error) {
	files, err := cs.inner.List(ctx, remotePath)
	if err != nil {
		return nil, err
	}
	for i := range files {
		files[i].Path = stripChecksumSuffix(files[i].Path)
	}
	return files, nil
}

// ListPrefix does a prefix scan and strips "--{hash}" from returned paths.
func (cs *ChecksumStorage) ListPrefix(ctx context.Context, prefix string) ([]FileInfo, error) {
	files, err := cs.inner.ListPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	for i := range files {
		files[i].Path = stripChecksumSuffix(files[i].Path)
	}
	return files, nil
}

// Rename renames the checksummed object, preserving the hash in the new name.
func (cs *ChecksumStorage) Rename(ctx context.Context, oldLogical, newLogical string) error {
	oldPhys, hexHash, err := cs.resolve(ctx, oldLogical)
	if err != nil {
		return err
	}
	if hexHash == "" {
		return cs.inner.Rename(ctx, oldPhys, newLogical)
	}
	return cs.inner.Rename(ctx, oldPhys, newLogical+checksumSep+hexHash)
}

func (cs *ChecksumStorage) DeleteDir(ctx context.Context, remotePath string) error {
	return cs.inner.DeleteDir(ctx, remotePath)
}

func (cs *ChecksumStorage) ListTopLevelDirs(ctx context.Context, prefix string) (map[string]bool, error) {
	return cs.inner.ListTopLevelDirs(ctx, prefix)
}

// resolve finds the physical name for logicalName. It scans for a
// "{logicalName}--" prefix to discover the hash, falling back to the plain
// logical name for files stored without a checksum.
func (cs *ChecksumStorage) resolve(ctx context.Context, logicalName string) (physName, hexHash string, err error) {
	prefix := logicalName + checksumSep
	infos, err := cs.inner.ListPrefix(ctx, prefix)
	if err != nil {
		return "", "", err
	}
	for _, fi := range infos {
		if strings.HasPrefix(fi.Path, prefix) {
			hash := strings.TrimPrefix(fi.Path, prefix)
			return fi.Path, hash, nil
		}
	}
	// Fallback: plain file stored without a checksum.
	ok, err := cs.inner.Exists(ctx, logicalName)
	if err != nil {
		return "", "", err
	}
	if ok {
		return logicalName, "", nil
	}
	return "", "", fs.ErrNotExist
}

func stripChecksumSuffix(path string) string {
	if idx := strings.LastIndex(path, checksumSep); idx >= 0 {
		return path[:idx]
	}
	return path
}

func isNotExist(err error) bool {
	return err == fs.ErrNotExist
}

// verifyingReader hashes data as it passes through and returns an error at
// EOF if the digest does not match the expected hex hash.
type verifyingReader struct {
	rc       io.ReadCloser
	h        hash.Hash
	expected string
	done     bool
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.rc.Read(p)
	if n > 0 {
		v.h.Write(p[:n])
	}
	if err == io.EOF && !v.done {
		v.done = true
		got := hex.EncodeToString(v.h.Sum(nil))
		if got != v.expected {
			return n, fmt.Errorf("checksumstore: digest mismatch: want %s got %s", v.expected, got)
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error {
	return v.rc.Close()
}
