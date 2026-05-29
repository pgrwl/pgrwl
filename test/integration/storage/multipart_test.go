//go:build integration_storage

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	storage "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"

	"github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestS3Storage_Put_SeekableFile_MultipartUploader(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	const size = 12*1024*1024 + 123
	key := testKey("seekable-multipart")
	remoteKey := withPrefix(prefix, key)

	tmpFile := createTempPatternFile(t, size)
	defer os.Remove(tmpFile.Name())

	err := st.Put(ctx, key, tmpFile)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))
	assertMultipartETag(t, ctx, client, "backups", remoteKey)

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	wantHash := fileSHA256(t, tmpFile.Name())
	assert.Equal(t, wantHash, gotHash)
}

func TestS3Storage_Put_Stream_ManualMultipart(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	const size = 256*1024*1024 + 777
	key := testKey("stream-manual-multipart")
	remoteKey := withPrefix(prefix, key)

	src := &patternReader{
		remaining: int64(size),
		offset:    0,
	}

	err := st.Put(ctx, key, src)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))
	assertMultipartETag(t, ctx, client, "backups", remoteKey)

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)

	expectedReader := &patternReader{
		remaining: int64(size),
		offset:    0,
	}
	wantHash := readerSHA256(t, expectedReader)

	assert.Equal(t, wantHash, gotHash)
}

func TestS3Storage_Put_EmptyStream(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	key := testKey("empty-stream")
	remoteKey := withPrefix(prefix, key)

	err := st.Put(ctx, key, strings.NewReader(""))
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, 0)

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	sum := sha256.Sum256(nil)
	wantHash := hex.EncodeToString(sum[:])

	assert.Equal(t, wantHash, gotHash)
}

func TestS3Storage_Put_SmallSeekableFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	const size = 1024*1024 + 333
	key := testKey("small-seekable")
	remoteKey := withPrefix(prefix, key)

	tmpFile := createTempPatternFile(t, size)
	defer os.Remove(tmpFile.Name())

	err := st.Put(ctx, key, tmpFile)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	wantHash := fileSHA256(t, tmpFile.Name())

	assert.Equal(t, wantHash, gotHash)
}

func withPrefix(prefix, key string) string {
	prefix = strings.Trim(prefix, "/")
	key = strings.Trim(key, "/")
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

func assertObjectSize(t *testing.T, ctx context.Context, client *minio.Client, bucket, key string, want int64) {
	t.Helper()

	info, err := client.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	require.NoError(t, err)

	assert.Equal(t, want, info.Size)
}

func assertMultipartETag(t *testing.T, ctx context.Context, client *minio.Client, bucket, key string) {
	t.Helper()

	info, err := client.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	require.NoError(t, err)

	etag := strings.Trim(info.ETag, `"`)
	assert.Contains(t, etag, "-", "expected multipart ETag, got %q", etag)
}

func createTempPatternFile(t *testing.T, size int) *os.File {
	t.Helper()

	f, err := os.CreateTemp("", "s3-put-*")
	require.NoError(t, err)

	src := &patternReader{
		remaining: int64(size),
		offset:    0,
	}

	_, err = io.Copy(f, src)
	require.NoError(t, err)

	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)

	return f
}

func downloadObjectSHA256(t *testing.T, ctx context.Context, client *minio.Client, bucket, key string) string {
	t.Helper()

	obj, err := client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	require.NoError(t, err)
	defer obj.Close()

	h := sha256.New()
	_, err = io.Copy(h, obj)
	require.NoError(t, err)

	return hex.EncodeToString(h.Sum(nil))
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)

	return hex.EncodeToString(h.Sum(nil))
}

func readerSHA256(t *testing.T, r io.Reader) string {
	t.Helper()

	h := sha256.New()
	_, err := io.Copy(h, r)
	require.NoError(t, err)

	return hex.EncodeToString(h.Sum(nil))
}

func testKey(name string) string {
	return fmt.Sprintf("integration/put/%s/%d", name, time.Now().UnixNano())
}

type patternReader struct {
	remaining int64
	offset    int64
}

func (r *patternReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}

	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}

	for i := 0; i < n; i++ {
		p[i] = byte((r.offset + int64(i)) % 251)
	}

	r.offset += int64(n)
	r.remaining -= int64(n)
	return n, nil
}

// integrity

func TestS3Storage_Put_Stream_ExactMultipartBoundary(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	// Exactly one manual multipart chunk size.
	const size = 256 * 1024 * 1024
	key := testKey("stream-exact-boundary")
	remoteKey := withPrefix(prefix, key)

	src := &patternReader{
		remaining: int64(size),
		offset:    0,
	}

	err := st.Put(ctx, key, src)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	wantHash := readerSHA256(t, &patternReader{
		remaining: int64(size),
		offset:    0,
	})

	assert.Equal(t, wantHash, gotHash)
}

func TestS3Storage_Put_Stream_JustBelowMultipartBoundary(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	const size = 256*1024*1024 - 1
	key := testKey("stream-below-boundary")
	remoteKey := withPrefix(prefix, key)

	src := &patternReader{
		remaining: int64(size),
		offset:    0,
	}

	err := st.Put(ctx, key, src)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	wantHash := readerSHA256(t, &patternReader{
		remaining: int64(size),
		offset:    0,
	})

	assert.Equal(t, wantHash, gotHash)
}

func TestS3Storage_Put_Stream_JustAboveMultipartBoundary(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	const size = 256*1024*1024 + 1
	key := testKey("stream-above-boundary")
	remoteKey := withPrefix(prefix, key)

	src := &patternReader{
		remaining: int64(size),
		offset:    0,
	}

	err := st.Put(ctx, key, src)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))
	assertMultipartETag(t, ctx, client, "backups", remoteKey)

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	wantHash := readerSHA256(t, &patternReader{
		remaining: int64(size),
		offset:    0,
	})

	assert.Equal(t, wantHash, gotHash)
}

func TestS3Storage_Put_SeekableFile_ExactMinPartBoundary(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	// transfermanager path; minimum part size logic matters here
	const size = 5 * 1024 * 1024
	key := testKey("seekable-exact-5mib")
	remoteKey := withPrefix(prefix, key)

	tmpFile := createTempPatternFile(t, size)
	defer os.Remove(tmpFile.Name())

	err := st.Put(ctx, key, tmpFile)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	wantHash := fileSHA256(t, tmpFile.Name())

	assert.Equal(t, wantHash, gotHash)
}

func TestS3Storage_Put_OverwriteSameKey_ReplacesContent(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	key := testKey("overwrite-same-key")
	remoteKey := withPrefix(prefix, key)

	tmp1 := createTempPatternFileWithSeed(t, 3*1024*1024+17, 11)
	defer os.Remove(tmp1.Name())

	err := st.Put(ctx, key, tmp1)
	require.NoError(t, err)

	hash1 := fileSHA256(t, tmp1.Name())
	got1 := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	assert.Equal(t, hash1, got1)

	tmp2 := createTempPatternFileWithSeed(t, 7*1024*1024+29, 97)
	defer os.Remove(tmp2.Name())

	err = st.Put(ctx, key, tmp2)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(7*1024*1024+29))

	hash2 := fileSHA256(t, tmp2.Name())
	got2 := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)

	assert.Equal(t, hash2, got2)
	assert.NotEqual(t, hash1, got2, "object content should be replaced on overwrite")
}

func TestS3Storage_Put_MultipleSizes_ContentIntegrity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	sizes := []int{
		0,
		1,
		17,
		1024,
		64*1024 + 3,
		1024*1024 + 5,
		5*1024*1024 - 1,
		5 * 1024 * 1024,
		5*1024*1024 + 1,
		12*1024*1024 + 123,
	}

	for i, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			key := testKey(fmt.Sprintf("multi-%d", i))
			remoteKey := withPrefix(prefix, key)

			tmp := createTempPatternFileWithSeed(t, size, int64(i+1))
			defer os.Remove(tmp.Name())

			err := st.Put(ctx, key, tmp)
			require.NoError(t, err)

			assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))

			gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
			wantHash := fileSHA256(t, tmp.Name())

			assert.Equal(t, wantHash, gotHash)
		})
	}
}

func TestS3Storage_Put_Stream_SmallChunkReader_ContentIntegrity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	const size = 8*1024*1024 + 321
	key := testKey("small-chunk-reader")
	remoteKey := withPrefix(prefix, key)

	src := &chunkedPatternReader{
		remaining: int64(size),
		offset:    0,
		chunkSize: 137,
		seed:      23,
	}

	err := st.Put(ctx, key, src)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	wantHash := readerSHA256(t, &chunkedPatternReader{
		remaining: int64(size),
		offset:    0,
		chunkSize: 137,
		seed:      23,
	})

	assert.Equal(t, wantHash, gotHash)
}

func TestS3Storage_Put_Stream_VariableChunkReader_ContentIntegrity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	client := createS3Client()
	prefix := t.Name()
	st := storage.NewS3Storage(client, "backups", prefix)

	const size = 9*1024*1024 + 777
	key := testKey("variable-chunk-reader")
	remoteKey := withPrefix(prefix, key)

	src := &variableChunkPatternReader{
		remaining: int64(size),
		offset:    0,
		seed:      41,
	}

	err := st.Put(ctx, key, src)
	require.NoError(t, err)

	assertObjectSize(t, ctx, client, "backups", remoteKey, int64(size))

	gotHash := downloadObjectSHA256(t, ctx, client, "backups", remoteKey)
	wantHash := readerSHA256(t, &variableChunkPatternReader{
		remaining: int64(size),
		offset:    0,
		seed:      41,
	})

	assert.Equal(t, wantHash, gotHash)
}

func createTempPatternFileWithSeed(t *testing.T, size int, seed int64) *os.File {
	t.Helper()

	f, err := os.CreateTemp("", "s3-put-seeded-*")
	require.NoError(t, err)

	src := &seededPatternReader{
		remaining: int64(size),
		offset:    0,
		seed:      seed,
	}

	_, err = io.Copy(f, src)
	require.NoError(t, err)

	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)

	return f
}

type seededPatternReader struct {
	remaining int64
	offset    int64
	seed      int64
}

func (r *seededPatternReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}

	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}

	for i := 0; i < n; i++ {
		p[i] = byte((r.seed + r.offset + int64(i)*7) % 251)
	}

	r.offset += int64(n)
	r.remaining -= int64(n)
	return n, nil
}

type chunkedPatternReader struct {
	remaining int64
	offset    int64
	chunkSize int
	seed      int64
}

func (r *chunkedPatternReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}

	n := len(p)
	if r.chunkSize > 0 && n > r.chunkSize {
		n = r.chunkSize
	}
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}

	for i := 0; i < n; i++ {
		p[i] = byte((r.seed + r.offset + int64(i)*13) % 251)
	}

	r.offset += int64(n)
	r.remaining -= int64(n)
	return n, nil
}

type variableChunkPatternReader struct {
	remaining int64
	offset    int64
	seed      int64
}

func (r *variableChunkPatternReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}

	// deterministic varying chunk sizes from 1..4096
	limit := int((r.offset*31+r.seed)%4096) + 1

	n := len(p)
	if n > limit {
		n = limit
	}
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}

	for i := 0; i < n; i++ {
		p[i] = byte((r.seed + r.offset*3 + int64(i)*17) % 251)
	}

	r.offset += int64(n)
	r.remaining -= int64(n)
	return n, nil
}
