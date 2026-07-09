package storecrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	MinS3PartSize     int64 = 5 * 1024 * 1024
	MaxS3PartSize     int64 = 5 * 1024 * 1024 * 1024
	DefaultS3PartSize int64 = 16 * 1024 * 1024
	DefaultS3Conc           = 2
	MaxS3Conc               = 16
	MaxS3UploadParts  int64 = 10000

	// MultipartDefaultPartSizeBytes is used for large unknown-size streams
	// such as base backups. 256 MiB x 10000 parts = ~2.44 TiB max object.
	MultipartDefaultPartSizeBytes = 256 * 1024 * 1024

	MultipartAbortTimeout = 30 * time.Second
)

type S3Options struct {
	PartSizeBytes int64
	Concurrency   int
	Log           *slog.Logger
}

type s3Storage struct {
	client         *s3.Client
	bucket         string
	prefix         string
	streamPartSize int64 // part size for the streaming multipart path
	concurrency    int
	log            *slog.Logger
}

var _ Storage = &s3Storage{}

func NewS3Storage(client *s3.Client, bucket, prefix string) Storage {
	return NewS3StorageWithOptions(client, bucket, prefix, S3Options{})
}

func NewS3StorageWithOptions(client *s3.Client, bucket, prefix string, opts S3Options) Storage {
	// streamPartSize: the part size used when the reader has unknown size
	// (e.g. after compression/encryption wraps it in an io.Pipe).
	streamPartSize := opts.PartSizeBytes
	if streamPartSize <= 0 {
		streamPartSize = MultipartDefaultPartSizeBytes
	}
	streamPartSize = normalizeS3PartSize(streamPartSize)

	return &s3Storage{
		client:         client,
		bucket:         bucket,
		prefix:         cleanS3Prefix(prefix),
		streamPartSize: streamPartSize,
		concurrency:    normalizeConcurrency(opts.Concurrency),
		log:            opts.Log,
	}
}

func (s *s3Storage) logf() *slog.Logger {
	if s.log != nil {
		return s.log.With(
			slog.String("component", "storage-s3"),
			slog.String("bucket", s.bucket),
		)
	}
	return slog.Default().With(
		slog.String("component", "storage-s3"),
		slog.String("bucket", s.bucket),
	)
}

func (s *s3Storage) Put(ctx context.Context, remotePath string, r io.Reader) error {
	fullPath := s.fullPath(remotePath)

	log := s.logf().With(
		slog.String("path", remotePath),
		slog.String("s3_key", fullPath),
	)

	// If we know the size, use transfermanager with computed part size.
	if f, ok := isSeekable(r); ok {
		st, err := f.Stat()
		if err == nil {
			size := st.Size()
			partSize := chooseUploadPartSize(size)
			uploader := createUploader(s.client, partSize, s.concurrency)

			log.Debug("using seekable upload path",
				slog.Int64("size_bytes", size),
				slog.Int64("part_size_bytes", partSize),
				slog.Int("concurrency", s.concurrency),
			)

			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek file for %q: %w", fullPath, err)
			}

			_, err = uploader.UploadObject(ctx, &transfermanager.UploadObjectInput{
				Bucket: aws.String(s.bucket),
				Key:    aws.String(fullPath),
				Body:   f,
			})
			if err != nil {
				return fmt.Errorf("s3 upload %q: %w", fullPath, err)
			}
			return nil
		}
	}

	log.Debug("using streaming multipart upload path",
		slog.Int64("part_size_bytes", s.streamPartSize),
	)

	// Unknown-size stream: use manual multipart upload.
	// Part size is configured per-instance: large for backups (256 MiB),
	// small for WAL segments (16 MiB). See WALPartSizeBytes / MultipartDefaultPartSizeBytes.
	return s.putMultipartStream(ctx, fullPath, r, s.streamPartSize)
}

func (s *s3Storage) Get(ctx context.Context, remotePath string) (io.ReadCloser, error) {
	remotePath = s.fullPath(remotePath)

	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(remotePath),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read object from S3: %w", err)
	}
	return out.Body, nil
}

func (s *s3Storage) List(ctx context.Context, remotePath string) ([]FileInfo, error) {
	fullPath := s3DirPrefix(s.fullPath(remotePath))
	var objects []FileInfo

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(fullPath),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get page: %w", err)
		}
		for _, obj := range page.Contents {
			objects = append(objects, FileInfo{
				Path:    s.relativeKey(aws.ToString(obj.Key)),
				ModTime: aws.ToTime(obj.LastModified),
				Size:    aws.ToInt64(obj.Size),
			})
		}
	}

	return objects, nil
}

func (s *s3Storage) Delete(ctx context.Context, remotePath string) error {
	fullPath := s.fullPath(remotePath)

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullPath),
	})
	return err
}

func (s *s3Storage) DeleteDir(ctx context.Context, remotePath string) error {
	err := s.deleteAllVersions(ctx, remotePath)
	if err != nil {
		return err
	}
	return s.Delete(ctx, remotePath)
}

func (s *s3Storage) deleteAllVersions(ctx context.Context, remotePath string) error {
	prefix := s.fullPath(remotePath)
	if prefix != "" && !endsWithSlash(prefix) {
		prefix += "/"
	}

	paginator := s3.NewListObjectVersionsPaginator(s.client, &s3.ListObjectVersionsInput{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})

	var toDelete []s3types.ObjectIdentifier
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list object versions: %w", err)
		}

		for i := range page.Versions {
			version := page.Versions[i]
			toDelete = append(toDelete, s3types.ObjectIdentifier{
				Key:       version.Key,
				VersionId: version.VersionId,
			})
		}
		for _, marker := range page.DeleteMarkers {
			toDelete = append(toDelete, s3types.ObjectIdentifier{
				Key:       marker.Key,
				VersionId: marker.VersionId,
			})
		}
	}

	for i := 0; i < len(toDelete); i += 1000 {
		end := i + 1000
		if end > len(toDelete) {
			end = len(toDelete)
		}

		_, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(s.bucket),
			Delete: &s3types.Delete{
				Objects: toDelete[i:end],
				Quiet:   aws.Bool(true),
			},
		})
		if err != nil {
			return fmt.Errorf("delete versions: %w", err)
		}
	}

	return nil
}

func (s *s3Storage) Exists(ctx context.Context, remotePath string) (bool, error) {
	remotePath = s.fullPath(remotePath)

	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(remotePath),
	})
	if err != nil {
		var nf *s3types.NotFound
		if errors.As(err, &nf) {
			return false, nil
		}
		return false, err
	}
	return true, nil // S3 has no dirs, so it's a valid file
}

func (s *s3Storage) ListTopLevelDirs(ctx context.Context, prefix string) (map[string]bool, error) {
	remotePath := s.fullPath(prefix)
	if !endsWithSlash(remotePath) {
		remotePath += "/"
	}

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket:    aws.String(s.bucket),
		Delimiter: aws.String("/"), // Groups results by prefix (like top-level directories)
		Prefix:    aws.String(remotePath),
	})

	// Extract top-level prefixes (directories)
	prefixes := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects in bucket: %w", err)
		}
		for _, prefix := range page.CommonPrefixes {
			if prefix.Prefix == nil {
				continue
			}
			prefixClean := strings.TrimSuffix(aws.ToString(prefix.Prefix), "/")
			prefixes[s.relativeKey(prefixClean)] = true
		}
	}

	return prefixes, nil
}

func (s *s3Storage) ListPrefix(ctx context.Context, remotePath string) ([]FileInfo, error) {
	fullPath := s.fullPath(remotePath) // no trailing slash - raw prefix scan
	var objects []FileInfo

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(fullPath),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get page: %w", err)
		}
		for _, obj := range page.Contents {
			objects = append(objects, FileInfo{
				Path:    s.relativeKey(aws.ToString(obj.Key)),
				ModTime: aws.ToTime(obj.LastModified),
				Size:    aws.ToInt64(obj.Size),
			})
		}
	}

	return objects, nil
}

func (s *s3Storage) Rename(ctx context.Context, oldRemotePath, newRemotePath string) error {
	srcKey := s.fullPath(oldRemotePath)
	dstKey := s.fullPath(newRemotePath)

	if srcKey == dstKey {
		return nil
	}

	// Copy source object to destination key
	copySource := s.bucket + "/" + srcKey

	_, err := s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(s.bucket),
		CopySource: aws.String(copySource),
		Key:        aws.String(dstKey),
	})
	if err != nil {
		return fmt.Errorf("copy object %q -> %q: %w", srcKey, dstKey, err)
	}

	// Delete source object (only latest version if bucket is versioned)
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(srcKey),
	})
	if err != nil {
		return fmt.Errorf("delete source after copy %q: %w", srcKey, err)
	}

	return nil
}
