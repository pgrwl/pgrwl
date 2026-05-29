package storecrypt

import (
	pathpkg "path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func normalizeS3PartSize(partSize int64) int64 {
	if partSize <= 0 {
		return DefaultS3PartSize
	}
	if partSize < MinS3PartSize {
		return MinS3PartSize
	}
	if partSize > MaxS3PartSize {
		return MaxS3PartSize
	}
	return partSize
}

func normalizeConcurrency(c int) int {
	if c <= 0 {
		return DefaultS3Conc
	}
	if c > MaxS3Conc {
		return MaxS3Conc
	}
	return c
}

func cleanS3Prefix(prefix string) string {
	prefix = strings.Trim(prefix, "/")
	if prefix == "" || prefix == "." {
		return ""
	}
	return pathpkg.Clean(prefix)
}

func joinS3Key(prefix, name string) string {
	name = strings.TrimPrefix(name, "/")
	if name == "" || name == "." {
		return prefix
	}
	if prefix == "" {
		clean := pathpkg.Clean(name)
		if clean == "." {
			return ""
		}
		return clean
	}
	return pathpkg.Join(prefix, name)
}

func s3DirPrefix(key string) string {
	if key == "" {
		return ""
	}
	if !endsWithSlash(key) {
		key += "/"
	}
	return key
}

func (s *s3Storage) fullPath(name string) string {
	return joinS3Key(s.prefix, name)
}

func (s *s3Storage) relativeKey(key string) string {
	key = strings.TrimPrefix(key, "/")

	if s.prefix == "" {
		return key
	}

	if key == s.prefix {
		return ""
	}

	prefix := s.prefix + "/"
	if strings.HasPrefix(key, prefix) {
		return strings.TrimPrefix(key, prefix)
	}

	return key
}

// createUploader creates a new S3 uploader with the given part size and concurrency.
func createUploader(client *s3.Client, partSize int64, concurrency int) *transfermanager.Client {
	normalized := normalizeS3PartSize(partSize)
	return transfermanager.New(client, func(o *transfermanager.Options) {
		o.PartSizeBytes = normalized
		o.MultipartUploadThreshold = normalized
		o.Concurrency = normalizeConcurrency(concurrency)
	})
}

// chooseUploadPartSize returns a safe part size for a known or estimated object size.
// If size <= 0, it returns the default known-size upload part size.
func chooseUploadPartSize(size int64) int64 {
	if size <= 0 {
		return DefaultS3PartSize
	}

	// Examples:
	//
	// object-size = 16Mi = 1048576 bytes
	// (1048576 + 10000 - 1) / 10000 = 106 bytes
	//
	// object-size = 50GiB = 53687091200 bytes
	// (53687091200 + 10000 - 1) / 10000 = 5368710 bytes = ~5.12MiB
	//
	// object-size = 500GiB = 536870912000 bytes
	// (536870912000 + 10000 - 1) / 10000 = 5368710 bytes = ~51.2MiB
	partSize := (size + MaxS3UploadParts - 1) / MaxS3UploadParts
	if partSize < MinS3PartSize {
		partSize = MinS3PartSize
	}

	// round up to whole MiB for cleaner values
	const mib = int64(1024 * 1024)
	if rem := partSize % mib; rem != 0 {
		partSize += mib - rem
	}

	return normalizeS3PartSize(partSize)
}

func endsWithSlash(s string) bool {
	return s != "" && s[len(s)-1] == '/'
}
