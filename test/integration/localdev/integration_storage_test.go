//go:build integration_localdev

package localdev

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/opt/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
)

// TestIntegrationLocaldev_ListDoesNotReturnPrefixSiblings verifies that
// List("base") returns only the contents of "base/", not siblings like "base-old/".
func TestIntegrationLocaldev_ListDoesNotReturnPrefixSiblings(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	storage := st.NewS3Storage(s3Client, env.bucket, runPrefix)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = storage.DeleteDir(cleanupCtx, "")
	})

	putIntegrationObject(t, ctx, storage, "20260502070500/manifest.json", `{}`)
	putIntegrationObject(t, ctx, storage, "20260502070500-old/manifest.json", `{}`)
	putIntegrationObject(t, ctx, storage, "20260502070500X/manifest.json", `{}`)

	listed, err := storage.List(ctx, "20260502070500")
	require.NoError(t, err)

	assert.Contains(t, fileInfoToStrList(listed), "20260502070500/manifest.json", "target backup should be listed")
	for _, key := range listed {
		assert.True(t, strings.HasPrefix(key.Path, "20260502070500/"),
			"List returned sibling key %q - expected only \"20260502070500/\" prefix", key)
	}
}

// TestIntegrationLocaldev_DeleteDirDoesNotDeleteSiblings verifies that
// DeleteDir("backupA") leaves sibling prefixes like "backupA-old/" intact.
func TestIntegrationLocaldev_DeleteDirDoesNotDeleteSiblings(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	storage := st.NewS3Storage(s3Client, env.bucket, runPrefix)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = storage.DeleteDir(cleanupCtx, "")
	})

	putIntegrationObject(t, ctx, storage, "20260502070500/20260502070500.json", `{}`)
	putIntegrationObject(t, ctx, storage, "20260502070500/base.tar", "base payload")
	putIntegrationObject(t, ctx, storage, "20260502070500-old/20260502070500-old.json", `{}`)
	putIntegrationObject(t, ctx, storage, "20260502070500X/20260502070500X.json", `{}`)

	err := storage.DeleteDir(ctx, "20260502070500")
	require.NoError(t, err)

	assertIntegrationMissing(t, ctx, storage, "20260502070500/20260502070500.json")
	assertIntegrationMissing(t, ctx, storage, "20260502070500/base.tar")

	assertIntegrationExists(t, ctx, storage, "20260502070500-old/20260502070500-old.json")
	assertIntegrationExists(t, ctx, storage, "20260502070500X/20260502070500X.json")
}

// TestIntegrationLocaldev_EmptyObjectRoundTrip verifies that a zero-byte object
// can be stored and retrieved correctly (regression for the multipart abort path).
func TestIntegrationLocaldev_EmptyObjectRoundTrip(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	storage := st.NewS3Storage(s3Client, env.bucket, runPrefix)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = storage.DeleteDir(cleanupCtx, "")
	})

	err := storage.Put(ctx, "empty.json", strings.NewReader(""))
	require.NoError(t, err)

	exists, err := storage.Exists(ctx, "empty.json")
	require.NoError(t, err)
	assert.True(t, exists, "zero-byte object should exist after Put")

	rc, err := storage.Get(ctx, "empty.json")
	require.NoError(t, err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Empty(t, data, "zero-byte object body should be empty on Get")
}

// TestIntegrationLocaldev_ListTopLevelDirsProjectLayout verifies that S3
// delimiter listing returns only direct backup directories for the project
// layout, excluding loose files and sibling areas such as wal-archive/.
func TestIntegrationLocaldev_ListTopLevelDirsProjectLayout(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	storage := st.NewS3Storage(s3Client, env.bucket, runPrefix)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = storage.DeleteDir(cleanupCtx, "")
	})

	putIntegrationObject(t, ctx, storage, "backups/20260502070500/20260502070500.json", `{}`)
	putIntegrationObject(t, ctx, storage, "backups/20260502070500/base.tar", "base")
	putIntegrationObject(t, ctx, storage, "backups/20260502070500-old/base.tar", "old")
	putIntegrationObject(t, ctx, storage, "backups/README.txt", "loose")
	putIntegrationObject(t, ctx, storage, "wal-archive/000000010000003C000000D9", "wal")

	dirs, err := storage.ListTopLevelDirs(ctx, "backups")
	require.NoError(t, err)

	assert.Equal(t, map[string]bool{
		"backups/20260502070500":     true,
		"backups/20260502070500-old": true,
	}, dirs)
}

// TestIntegrationLocaldev_DeleteAllBulkDeletesExactObjectsOnly verifies that
// bulk deletion of WAL-like object names does not delete prefix siblings.
func TestIntegrationLocaldev_DeleteAllBulkDeletesExactObjectsOnly(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	storage := st.NewS3Storage(s3Client, env.bucket, runPrefix)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = storage.DeleteDir(cleanupCtx, "")
	})

	deleteMe := []string{
		"wal-archive/000000010000003C000000D8",
		"wal-archive/000000010000003C000000DA",
	}
	mustRemain := []string{
		"wal-archive/000000010000003C000000D8.partial",
		"wal-archive/000000010000003C000000D80",
		"wal-archive/000000010000003C000000D9",
		"wal-archive/00000002.history",
		"wal-archive/README.txt",
		"backups/20260502070500/base.tar",
	}

	for _, path := range deleteMe {
		putIntegrationObject(t, ctx, storage, path, "delete-me")
	}
	for _, path := range mustRemain {
		putIntegrationObject(t, ctx, storage, path, "keep-me")
	}

	err := deleteAllBulk(ctx, storage, deleteMe)
	require.NoError(t, err)

	for _, path := range deleteMe {
		assertIntegrationMissing(t, ctx, storage, path)
	}
	for _, path := range mustRemain {
		assertIntegrationExists(t, ctx, storage, path)
	}
}

// TestIntegrationLocaldev_ListInfoReturnsRelativePathSizeAndModTime verifies
// object metadata shape against the local S3-compatible backend.
func TestIntegrationLocaldev_ListInfoReturnsRelativePathSizeAndModTime(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	storage := st.NewS3Storage(s3Client, env.bucket, runPrefix)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = storage.DeleteDir(cleanupCtx, "")
	})

	objects := map[string]string{
		"backups/20260502070500/20260502070500.json": `{"ok":true}`,
		"backups/20260502070500/base.tar":            "base-payload",
	}
	for path, body := range objects {
		putIntegrationObject(t, ctx, storage, path, body)
	}

	infos, err := storage.List(ctx, "backups/20260502070500")
	require.NoError(t, err)
	require.Len(t, infos, len(objects))

	got := make(map[string]st.FileInfo, len(infos))
	for _, info := range infos {
		got[info.Path] = info
	}

	for path, body := range objects {
		info, ok := got[path]
		require.True(t, ok, "expected ListInfo to include %s", path)
		assert.Equal(t, int64(len(body)), info.Size, "size for %s", path)
		assert.False(t, info.ModTime.IsZero(), "mod time for %s should be populated", path)
	}
}

// TestIntegrationLocaldev_RenameCopiesContentAndDeletesSource verifies S3
// copy+delete rename semantics.
func TestIntegrationLocaldev_RenameCopiesContentAndDeletesSource(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	storage := st.NewS3Storage(s3Client, env.bucket, runPrefix)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = storage.DeleteDir(cleanupCtx, "")
	})

	putIntegrationObject(t, ctx, storage, "tmp/object.txt", "rename payload")

	err := storage.Rename(ctx, "tmp/object.txt", "final/object.txt")
	require.NoError(t, err)

	assertIntegrationMissing(t, ctx, storage, "tmp/object.txt")
	assertIntegrationExists(t, ctx, storage, "final/object.txt")

	rc, err := storage.Get(ctx, "final/object.txt")
	require.NoError(t, err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "rename payload", string(data))
}

// TestIntegrationLocaldev_SeekableAndStreamingPutRoundTrip verifies both S3
// upload paths used by pgrwl: seekable files and unknown-size streams.
func TestIntegrationLocaldev_SeekableAndStreamingPutRoundTrip(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	storage := st.NewS3StorageWithOptions(s3Client, env.bucket, runPrefix, st.S3Options{
		PartSizeBytes: st.MinS3PartSize,
	})

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = storage.DeleteDir(cleanupCtx, "")
	})

	seekablePayload := []byte("seekable upload payload")
	tmpFile, err := os.CreateTemp(t.TempDir(), "seekable-*")
	require.NoError(t, err)
	_, err = tmpFile.Write(seekablePayload)
	require.NoError(t, err)
	_, err = tmpFile.Seek(0, io.SeekStart)
	require.NoError(t, err)
	defer tmpFile.Close()

	err = storage.Put(ctx, "uploads/seekable.bin", tmpFile)
	require.NoError(t, err)

	streamingPayload := bytes.Repeat([]byte("s"), int(st.MinS3PartSize)+1024)
	err = storage.Put(ctx, "uploads/streaming.bin", bytes.NewReader(streamingPayload))
	require.NoError(t, err)

	assertIntegrationBytes(t, ctx, storage, "uploads/seekable.bin", seekablePayload)
	assertIntegrationBytes(t, ctx, storage, "uploads/streaming.bin", streamingPayload)
}

// TestIntegrationLocaldev_SetupStorageS3ProjectSubpaths verifies that the app
// storage setup places project data under isolated S3 prefixes.
func TestIntegrationLocaldev_SetupStorageS3ProjectSubpaths(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-storage-it/%d", time.Now().UTC().UnixNano())
	rawStorage := st.NewS3Storage(s3Client, env.bucket, "")

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = rawStorage.DeleteDir(cleanupCtx, runPrefix)
	})

	configPath := writeIntegrationConfig(t, env, runPrefix)
	_, err := config.FromFile(configPath)
	require.NoError(t, err)

	projectA, err := api.SetupStorage(&api.SetupStorageOpts{
		BaseDir: runPrefix + "/project-a",
		SubPath: "wal-archive",
	})
	require.NoError(t, err)

	projectB, err := api.SetupStorage(&api.SetupStorageOpts{
		BaseDir: runPrefix + "/project-b",
		SubPath: "wal-archive",
	})
	require.NoError(t, err)

	putIntegrationObject(t, ctx, projectA, "000000010000003C000000D8", "project-a-wal")
	putIntegrationObject(t, ctx, projectB, "000000010000003C000000D8", "project-b-wal")

	assertIntegrationBytes(t, ctx, rawStorage, runPrefix+"/project-a/wal-archive/000000010000003C000000D8", []byte("project-a-wal"))
	assertIntegrationBytes(t, ctx, rawStorage, runPrefix+"/project-b/wal-archive/000000010000003C000000D8", []byte("project-b-wal"))
}
