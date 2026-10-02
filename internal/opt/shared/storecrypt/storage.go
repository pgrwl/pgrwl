package storecrypt

import (
	"context"
	"io"
	"time"
)

type FileInfo struct {
	Path    string
	ModTime time.Time
	Size    int64
}

// Storage is an interface for handling remote file storage.
type Storage interface {
	// Put stores a file from the reader to the destination path.
	Put(ctx context.Context, remotePath string, r io.Reader) error

	// Get retrieves a remote file as a stream. Caller must close the reader.
	Get(ctx context.Context, remotePath string) (io.ReadCloser, error)

	// List returns all file infos under the given directory.
	List(ctx context.Context, remotePath string) ([]FileInfo, error)

	// Delete removes the specified file.
	Delete(ctx context.Context, remotePath string) error

	// DeleteDir removes a directory (or prefix) with its content.
	DeleteDir(ctx context.Context, remotePath string) error

	// Exists checks whether a file exists.
	Exists(ctx context.Context, remotePath string) (bool, error)

	// ListTopLevelDirs retrieves ONLY directories at a given prefix path.
	ListTopLevelDirs(ctx context.Context, prefix string) (map[string]bool, error)

	// Rename moves/renames a single object from oldRemotePath to newRemotePath.
	// For S3 this is implemented as copy+delete (not recursive prefix rename).
	Rename(ctx context.Context, oldRemotePath, newRemotePath string) error

	// ListPrefix returns all file infos whose remote path starts with the given
	// prefix. Unlike List it does NOT append a trailing slash, so it is suitable
	// for raw prefix scans (e.g. "walname--" to discover checksum variants).
	ListPrefix(ctx context.Context, prefix string) ([]FileInfo, error)
}
