//go:build integration_storage

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"

	storage "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/codec"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/crypt/aesgcm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checksumImpls creates ChecksumStorage instances for all backend/codec
// combinations, using isolated sub-paths so tests don't interfere.
func checksumImpls(dir, subpath string) map[string]*storage.ChecksumStorage {
	mkLocal := func(name string) storage.Storage {
		s, err := storage.NewLocal(&storage.LocalStorageOpts{
			BaseDir:      filepath.ToSlash(filepath.Join(dir, subpath, name)),
			FsyncOnWrite: false,
		})
		if err != nil {
			log.Fatal(err)
		}
		return s
	}

	mkS3 := func(name string) storage.Storage {
		return storage.NewS3Storage(
			createS3Client(),
			"backups",
			filepath.ToSlash(filepath.Join(subpath, name)),
		)
	}

	mkSFTP := func(name string) storage.Storage {
		return storage.NewSFTPStorage(
			createSftpClient(),
			filepath.ToSlash(filepath.Join(subpath, name)),
		)
	}

	alg := storage.Algorithms{
		Gzip: &storage.CodecPair{
			Compressor:   codec.GzipCompressor{},
			Decompressor: codec.GzipDecompressor{},
		},
		Zstd: &storage.CodecPair{
			Compressor:   codec.ZstdCompressor{},
			Decompressor: codec.ZstdDecompressor{},
		},
		AES: aesgcm.NewChunkedGCMCrypter("password"),
	}

	newChecksum := func(backend storage.Storage, writeExt string) *storage.ChecksumStorage {
		vs, err := storage.NewVariadicStorage(backend, alg, writeExt)
		if err != nil {
			log.Fatalf("NewVariadicStorage: %v", err)
		}
		return storage.NewChecksumStorage(vs)
	}

	return map[string]*storage.ChecksumStorage{
		"checksum-local-gz.aes": newChecksum(mkLocal("checksum-local-gz.aes"), ".gz.aes"),
		"checksum-s3-gz.aes":    newChecksum(mkS3("checksum-s3-gz.aes"), ".gz.aes"),
		"checksum-sftp-gz.aes":  newChecksum(mkSFTP("checksum-sftp-gz.aes"), ".gz.aes"),

		"checksum-local-gz": newChecksum(mkLocal("checksum-local-gz"), ".gz"),
		"checksum-s3-gz":    newChecksum(mkS3("checksum-s3-gz"), ".gz"),
		"checksum-sftp-gz":  newChecksum(mkSFTP("checksum-sftp-gz"), ".gz"),

		"checksum-local": newChecksum(mkLocal("checksum-local"), ""),
		"checksum-s3":    newChecksum(mkS3("checksum-s3"), ""),
		"checksum-sftp":  newChecksum(mkSFTP("checksum-sftp"), ""),
	}
}

func initChecksumStoragesT(t *testing.T, subpath string) map[string]*storage.ChecksumStorage {
	t.Helper()
	return checksumImpls(t.TempDir(), subpath)
}

// -----------------------------------------------------------------------------
// Put / Get / Exists
// -----------------------------------------------------------------------------

func TestChecksumStorage_PutGetExists_AllBackends(t *testing.T) {
	ctx := context.TODO()
	storages := initChecksumStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			const logical = "wal/000000010000000000000001"
			content := []byte("WAL segment for " + name)

			require.NoError(t, store.Put(ctx, logical, bytes.NewReader(content)),
				"[%s] Put failed", name)

			exists, err := store.Exists(ctx, logical)
			require.NoError(t, err, "[%s] Exists failed", name)
			assert.True(t, exists, "[%s] file should exist after Put", name)

			rc, err := store.Get(ctx, logical)
			require.NoError(t, err, "[%s] Get failed", name)
			got := readAllAndClose(t, rc)
			assert.Equal(t, content, got, "[%s] content mismatch", name)
		})
	}
}

func TestChecksumStorage_Exists_ReturnsFalse_WhenAbsent(t *testing.T) {
	ctx := context.TODO()
	storages := initChecksumStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			exists, err := store.Exists(ctx, "nonexistent")
			require.NoError(t, err, "[%s] Exists failed", name)
			assert.False(t, exists, "[%s] should not exist", name)
		})
	}
}

// -----------------------------------------------------------------------------
// Physical key format
// -----------------------------------------------------------------------------

func TestChecksumStorage_PhysicalKey_ContainsHashSuffix(t *testing.T) {
	// For local backends, inspect the inner VariadicStorage backend directly
	// to confirm the physical key looks like "logical--{sha256hex}.gz.aes".
	ctx := context.TODO()

	dir := t.TempDir()
	local, err := storage.NewLocal(&storage.LocalStorageOpts{BaseDir: dir})
	require.NoError(t, err)

	alg := storage.Algorithms{
		Gzip: &storage.CodecPair{
			Compressor:   codec.GzipCompressor{},
			Decompressor: codec.GzipDecompressor{},
		},
		AES: aesgcm.NewChunkedGCMCrypter("password"),
	}
	vs, err := storage.NewVariadicStorage(local, alg, ".gz.aes")
	require.NoError(t, err)

	cs := storage.NewChecksumStorage(vs)

	const logical = "seg001"
	content := []byte("some wal data")

	require.NoError(t, cs.Put(ctx, logical, bytes.NewReader(content)))

	// The raw backend (local) must contain exactly one key.
	rawKeys, err := local.List(ctx, "")
	require.NoError(t, err)
	require.Len(t, rawKeys, 1, "expected exactly one physical object")

	physKey := rawKeys[0].Path
	assert.True(t, strings.HasPrefix(physKey, logical+"--"),
		"physical key %q should start with %q", physKey, logical+"--")
	assert.True(t, strings.HasSuffix(physKey, ".gz.aes"),
		"physical key %q should end with .gz.aes", physKey)
}

// -----------------------------------------------------------------------------
// ListPrefix
// -----------------------------------------------------------------------------

func TestChecksumStorage_ListPrefix_AllBackends(t *testing.T) {
	ctx := context.TODO()
	storages := initChecksumStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			logicals := []string{
				"wal/000000010000000000000001",
				"wal/000000010000000000000002",
			}
			other := "wal/000000010000000000000003"

			for _, l := range logicals {
				require.NoError(t, store.Put(ctx, l, bytes.NewReader([]byte(l))),
					"[%s] Put %s failed", name, l)
			}
			require.NoError(t, store.Put(ctx, other, bytes.NewReader([]byte(other))),
				"[%s] Put other failed", name)

			// Prefix that matches only the first two WAL segments.
			for _, l := range logicals {
				prefix := l + "--"

				infos, err := store.ListPrefix(ctx, prefix)
				require.NoError(t, err, "[%s] ListPrefix(%q) failed", name, prefix)
				require.Len(t, infos, 1, "[%s] expected exactly one result for prefix %q", name, prefix)
				assert.Equal(t, l, infos[0].Path,
					"[%s] ListPrefix should return logical name (no hash suffix)", name)
			}
		})
	}
}

func TestChecksumStorage_ListPrefix_Empty_WhenNoMatch(t *testing.T) {
	ctx := context.TODO()
	storages := initChecksumStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, store.Put(ctx, "seg001", bytes.NewReader([]byte("x"))))

			infos, err := store.ListPrefix(ctx, "nomatch--")
			require.NoError(t, err, "[%s] ListPrefix failed", name)
			assert.Empty(t, infos, "[%s] expected empty result", name)
		})
	}
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestChecksumStorage_Delete_AllBackends(t *testing.T) {
	ctx := context.TODO()
	storages := initChecksumStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			const logical = "del/seg001"

			require.NoError(t, store.Put(ctx, logical, bytes.NewReader([]byte("delete me"))),
				"[%s] Put failed", name)

			require.NoError(t, store.Delete(ctx, logical), "[%s] Delete failed", name)

			exists, err := store.Exists(ctx, logical)
			require.NoError(t, err, "[%s] Exists after Delete failed", name)
			assert.False(t, exists, "[%s] file should be gone after Delete", name)

			infos, err := store.ListPrefix(ctx, logical+"--")
			require.NoError(t, err, "[%s] ListPrefix after Delete failed", name)
			assert.Empty(t, infos, "[%s] no checksummed object should remain after Delete", name)
		})
	}
}

func TestChecksumStorage_Delete_NonExistent_IsNoOp(t *testing.T) {
	ctx := context.TODO()
	storages := initChecksumStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, store.Delete(ctx, "absent"), "[%s] Delete of absent should not error", name)
		})
	}
}

// -----------------------------------------------------------------------------
// Rename
// -----------------------------------------------------------------------------

func TestChecksumStorage_Rename_AllBackends(t *testing.T) {
	ctx := context.TODO()
	storages := initChecksumStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			const (
				oldLogical = "wal/seg-old"
				newLogical = "wal/seg-new"
			)
			content := []byte("rename me " + name)

			require.NoError(t, store.Put(ctx, oldLogical, bytes.NewReader(content)),
				"[%s] Put failed", name)

			require.NoError(t, store.Rename(ctx, oldLogical, newLogical),
				"[%s] Rename failed", name)

			// Old must be gone.
			exists, err := store.Exists(ctx, oldLogical)
			require.NoError(t, err)
			assert.False(t, exists, "[%s] old logical should not exist after Rename", name)

			// New must exist and round-trip correctly.
			exists, err = store.Exists(ctx, newLogical)
			require.NoError(t, err)
			assert.True(t, exists, "[%s] new logical should exist after Rename", name)

			rc, err := store.Get(ctx, newLogical)
			require.NoError(t, err, "[%s] Get(new) failed", name)
			got := readAllAndClose(t, rc)
			assert.Equal(t, content, got, "[%s] content mismatch after Rename", name)
		})
	}
}

// -----------------------------------------------------------------------------
// Backward compatibility: plain files (no hash suffix)
// -----------------------------------------------------------------------------

func TestChecksumStorage_BackwardCompat_AllBackends(t *testing.T) {
	// A file stored directly in the inner VariadicStorage (without a checksum
	// suffix) must still be readable through ChecksumStorage.
	ctx := context.TODO()

	dir := t.TempDir()
	local, err := storage.NewLocal(&storage.LocalStorageOpts{BaseDir: dir})
	require.NoError(t, err)

	alg := storage.Algorithms{
		Gzip: &storage.CodecPair{
			Compressor:   codec.GzipCompressor{},
			Decompressor: codec.GzipDecompressor{},
		},
		AES: aesgcm.NewChunkedGCMCrypter("password"),
	}
	vs, err := storage.NewVariadicStorage(local, alg, ".gz.aes")
	require.NoError(t, err)

	cs := storage.NewChecksumStorage(vs)

	const logical = "legacy/seg001"
	content := []byte("legacy file without checksum")

	// Store via inner VariadicStorage directly - no checksum in key.
	require.NoError(t, vs.Put(ctx, logical, bytes.NewReader(content)))

	// ChecksumStorage must still be able to read it.
	exists, err := cs.Exists(ctx, logical)
	require.NoError(t, err)
	assert.True(t, exists, "legacy file should be visible via ChecksumStorage")

	rc, err := cs.Get(ctx, logical)
	require.NoError(t, err, "Get of legacy file should not error")
	got := readAllAndClose(t, rc)
	assert.Equal(t, content, got, "content of legacy file should be intact")
}

// -----------------------------------------------------------------------------
// High-volume: 100 WAL segments
// -----------------------------------------------------------------------------

func TestChecksumStorage_HighLoad_AllBackends(t *testing.T) {
	ctx := context.TODO()
	storages := initChecksumStoragesT(t, t.Name())

	const fileCount = 100

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, deleteAll(ctx, store, ""), "[%s] pre-test cleanup failed", name)

			content := bytes.Repeat([]byte("WAL "), 64) // 256 bytes per segment

			// Upload.
			for i := 0; i < fileCount; i++ {
				path := fmt.Sprintf("hl/%04d", i)
				require.NoError(t, store.Put(ctx, path, bytes.NewReader(content)),
					"[%s] Put %s failed", name, path)
			}

			// List and count.
			listed, err := store.List(ctx, "hl")
			require.NoError(t, err, "[%s] List failed", name)
			assert.Len(t, listed, fileCount, "[%s] wrong file count", name)

			// Read all and verify.
			for _, fi := range listed {
				rc, err := store.Get(ctx, fi.Path)
				require.NoError(t, err, "[%s] Get(%s) failed", name, fi.Path)
				got, err := io.ReadAll(rc)
				require.NoError(t, err)
				require.NoError(t, rc.Close())
				assert.Equal(t, content, got, "[%s] content mismatch for %s", name, fi.Path)
			}

			// Cleanup.
			require.NoError(t, deleteAll(ctx, store, "hl"), "[%s] cleanup failed", name)
			finalList, err := store.List(ctx, "hl")
			require.NoError(t, err)
			assert.Empty(t, finalList, "[%s] files not fully cleaned up", name)
		})
	}
}
