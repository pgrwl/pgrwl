package storecrypt

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/minio/minio-go/v7"
)

const (
	MinS3PartSize int64 = 5 * 1024 * 1024
	DefaultS3Conc       = 2

	// MultipartDefaultPartSizeBytes is used for large unknown-size streams
	// such as base backups. 256 MiB x 10000 parts = ~2.44 TiB max object.
	MultipartDefaultPartSizeBytes = 256 * 1024 * 1024
)

type S3Options struct {
	PartSizeBytes int64
	Concurrency   int
	Log           *slog.Logger
}

type s3Storage struct {
	client      *minio.Client
	bucket      string
	prefix      string
	partSize    uint64
	concurrency uint
	log         *slog.Logger
}

var _ Storage = &s3Storage{}

func NewS3Storage(client *minio.Client, bucket, prefix string) Storage {
	return NewS3StorageWithOptions(client, bucket, prefix, S3Options{})
}

func NewS3StorageWithOptions(client *minio.Client, bucket, prefix string, opts S3Options) Storage {
	partSize := opts.PartSizeBytes
	if partSize <= 0 {
		partSize = MultipartDefaultPartSizeBytes
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultS3Conc
	}
	return &s3Storage{
		client:      client,
		bucket:      bucket,
		prefix:      strings.Trim(prefix, "/"),
		partSize:    uint64(partSize),
		concurrency: uint(concurrency),
		log:         opts.Log,
	}
}

func (s *s3Storage) logf() *slog.Logger {
	if s.log != nil {
		return s.log.With(slog.String("component", "storage-s3"), slog.String("bucket", s.bucket))
	}
	return slog.Default().With(slog.String("component", "storage-s3"), slog.String("bucket", s.bucket))
}

func (s *s3Storage) fullPath(path string) string {
	return filepath.ToSlash(filepath.Join(s.prefix, path))
}

// Put uploads r to remotePath.
//
// For *os.File readers the file size is known: part size starts at MinS3PartSize
// (5 MiB) and scales up automatically to stay within the 10 000-part limit.
// For all other readers (pipes, compressed streams) the size is unknown and
// s.partSize (256 MiB by default) is used as the streaming chunk size.
func (s *s3Storage) Put(ctx context.Context, remotePath string, r io.Reader) error {
	fullPath := s.fullPath(remotePath)

	size := int64(-1)
	opts := minio.PutObjectOptions{
		PartSize:   s.partSize,
		NumThreads: s.concurrency,
	}

	if f, ok := r.(*os.File); ok {
		if st, err := f.Stat(); err == nil {
			size = st.Size()
			// Start from MinS3PartSize (5 MiB) so any file larger than that
			// is uploaded via multipart. For very large files, scale up so
			// the part count stays within the 10 000-part S3 limit.
			partSize := MinS3PartSize
			if size > partSize*10000 {
				partSize = (size + 9999) / 10000
			}
			opts.PartSize = uint64(partSize)
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek %q: %w", fullPath, err)
			}
		}
	}

	s.logf().Debug("put object",
		slog.String("s3_key", fullPath),
		slog.Int64("size_bytes", size),
		slog.Uint64("part_size_bytes", opts.PartSize),
	)

	if _, err := s.client.PutObject(ctx, s.bucket, fullPath, r, size, opts); err != nil {
		return fmt.Errorf("put %q: %w", fullPath, err)
	}
	return nil
}

func (s *s3Storage) Get(ctx context.Context, remotePath string) (io.ReadCloser, error) {
	fullPath := s.fullPath(remotePath)
	obj, err := s.client.GetObject(ctx, s.bucket, fullPath, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", fullPath, err)
	}
	return obj, nil
}

func (s *s3Storage) List(ctx context.Context, remotePath string) ([]FileInfo, error) {
	fullPath := s.fullPath(remotePath)
	var objects []FileInfo

	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:    fullPath,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("list %q: %w", fullPath, obj.Err)
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(obj.Key, s.prefix), "/")
		objects = append(objects, FileInfo{
			Path:    filepath.ToSlash(rel),
			ModTime: obj.LastModified,
			Size:    obj.Size,
		})
	}
	return objects, nil
}

func (s *s3Storage) Delete(ctx context.Context, remotePath string) error {
	fullPath := s.fullPath(remotePath)
	if err := s.client.RemoveObject(ctx, s.bucket, fullPath, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete %q: %w", fullPath, err)
	}
	return nil
}

func (s *s3Storage) DeleteDir(ctx context.Context, remotePath string) error {
	prefix := s.fullPath(remotePath)
	if prefix != "" && !endsWithSlash(prefix) {
		prefix += "/"
	}
	if err := s.deleteWithPrefix(ctx, prefix); err != nil {
		return err
	}
	return s.Delete(ctx, remotePath)
}

func (s *s3Storage) deleteWithPrefix(ctx context.Context, prefix string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	objectsCh := s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:       prefix,
		Recursive:    true,
		WithVersions: true,
	})

	removeCh := make(chan minio.ObjectInfo)
	var wg sync.WaitGroup
	var listErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(removeCh)
		for obj := range objectsCh {
			if obj.Err != nil {
				listErr = fmt.Errorf("list %q: %w", prefix, obj.Err)
				return
			}
			select {
			case removeCh <- obj:
			case <-ctx.Done():
				return
			}
		}
	}()

	var removeErr error
	for rErr := range s.client.RemoveObjects(ctx, s.bucket, removeCh, minio.RemoveObjectsOptions{}) {
		removeErr = fmt.Errorf("delete %q: %w", rErr.ObjectName, rErr.Err)
		cancel()
	}

	wg.Wait()

	if removeErr != nil {
		return removeErr
	}
	return listErr
}

func (s *s3Storage) Exists(ctx context.Context, remotePath string) (bool, error) {
	fullPath := s.fullPath(remotePath)
	_, err := s.client.StatObject(ctx, s.bucket, fullPath, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, fmt.Errorf("stat %q: %w", fullPath, err)
	}
	return true, nil
}

func (s *s3Storage) ListTopLevelDirs(ctx context.Context, prefix string) (map[string]bool, error) {
	remotePath := s.fullPath(prefix)
	if !endsWithSlash(remotePath) {
		remotePath += "/"
	}

	prefixes := make(map[string]bool)
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:    remotePath,
		Recursive: false,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("list top-level dirs %q: %w", remotePath, obj.Err)
		}
		if !strings.HasSuffix(obj.Key, "/") {
			continue
		}
		rel := strings.TrimPrefix(obj.Key, s.prefix)
		rel = strings.TrimPrefix(rel, "/")
		rel = strings.TrimSuffix(rel, "/")
		if rel != "" {
			prefixes[rel] = true
		}
	}
	return prefixes, nil
}

func (s *s3Storage) Rename(ctx context.Context, oldRemotePath, newRemotePath string) error {
	srcKey := s.fullPath(oldRemotePath)
	dstKey := s.fullPath(newRemotePath)

	if srcKey == dstKey {
		return nil
	}

	_, err := s.client.CopyObject(ctx,
		minio.CopyDestOptions{Bucket: s.bucket, Object: dstKey},
		minio.CopySrcOptions{Bucket: s.bucket, Object: srcKey},
	)
	if err != nil {
		return fmt.Errorf("copy %q -> %q: %w", srcKey, dstKey, err)
	}

	if err := s.client.RemoveObject(ctx, s.bucket, srcKey, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete source %q after rename: %w", srcKey, err)
	}
	return nil
}

func endsWithSlash(s string) bool {
	return s != "" && s[len(s)-1] == '/'
}
