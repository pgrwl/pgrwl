//go:build integration_storage

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	storage "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/codec"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/crypt/aesgcm"
	"github.com/stretchr/testify/require"
)

// initDynStoragesSameBackendT creates a single Local backend and several
// VariadicStorage wrappers with different writeExts, all sharing that backend.
func initDynStoragesSameBackendT(t *testing.T, subpath string) map[string]*storage.VariadicStorage {
	t.Helper()

	baseDir := t.TempDir()
	local, err := storage.NewLocal(&storage.LocalStorageOpts{
		BaseDir:      filepath.Join(baseDir, subpath),
		FsyncOnWrite: false,
	})
	require.NoError(t, err)

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

	newVS := func(writeExt string) *storage.VariadicStorage {
		st, err := storage.NewVariadicStorage(local, alg, writeExt)
		require.NoError(t, err, "NewVariadicStorage(%q) failed", writeExt)
		return st
	}

	return map[string]*storage.VariadicStorage{
		"plain":   newVS(""),
		"gz":      newVS(".gz"),
		"zst":     newVS(".zst"),
		"aes":     newVS(".aes"),
		"gz.aes":  newVS(".gz.aes"),
		"zst.aes": newVS(".zst.aes"),
	}
}

func TestDynStorage_CrossReadWrite_AllVariants(t *testing.T) {
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	logicalPath := "wal/000000010000000000000001"
	content := []byte("hello wal world")

	// We only need a single backend for cleanup, pick any.
	var backend storage.Storage
	for _, s := range storages {
		backend = s.Backend
		break
	}
	require.NotNil(t, backend)

	for wName, writer := range storages {
		for rName, reader := range storages {
			t.Run(fmt.Sprintf("write=%s/read=%s", wName, rName), func(t *testing.T) {
				// Clean backend before each pair
				require.NoError(t, deleteAll(ctx, backend, ""), "cleanup before pair")

				// Write through writer
				err := writer.Put(ctx, logicalPath, bytes.NewReader(content))
				require.NoError(t, err, "[write=%s] Put failed", wName)

				// Read through reader using logical name
				exists, err := reader.Exists(ctx, logicalPath)
				require.NoError(t, err)
				assert.True(t, exists, "Exists should be true for logical path")

				rc, err := reader.Get(ctx, logicalPath)
				require.NoError(t, err, "[read=%s] Get failed", rName)
				got, err := io.ReadAll(rc)
				require.NoError(t, err)
				require.NoError(t, rc.Close())

				assert.Equal(t, content, got,
					"content mismatch write=%s read=%s", wName, rName)
			})
		}
	}
}

func TestDynStorage_Get_UsesHighestPriorityVariant(t *testing.T) {
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	// We'll use the "plain" instance to call Get/Exists.
	stPlain := storages["plain"]
	require.NotNil(t, stPlain)

	backend := stPlain.Backend
	require.NoError(t, deleteAll(ctx, backend, ""), "initial cleanup")

	const logical = "wal/000000010000000000000002"

	plainContent := []byte("plain-content")
	gzContent := []byte("gzip-content")
	gzAesContent := []byte("gzip-aes-content")

	// Write plain via "plain" storage
	require.NoError(t, storages["plain"].Put(ctx, logical, bytes.NewReader(plainContent)))
	// Write gzip via "gz" storage
	require.NoError(t, storages["gz"].Put(ctx, logical, bytes.NewReader(gzContent)))
	// Write gzip+aes via "gz.aes" storage
	require.NoError(t, storages["gz.aes"].Put(ctx, logical, bytes.NewReader(gzAesContent)))

	// Now a plain storage Get(logical) should pick the highest-priority variant
	// according to supportedExts() -> ".gz.aes" should win.
	rc, err := stPlain.Get(ctx, logical)
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	assert.Equal(t, gzAesContent, got, "Get should return content from .gz.aes (highest priority)")
}

func TestDynStorage_Delete_RemovesAllVariantsIntegration(t *testing.T) {
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	stPlain := storages["plain"]
	require.NotNil(t, stPlain)
	backend := stPlain.Backend

	require.NoError(t, deleteAll(ctx, backend, ""), "initial cleanup")

	const logical = "wal/000000010000000000000003"
	content := []byte("payload")

	// Create several variants for the same logical name.
	require.NoError(t, storages["plain"].Put(ctx, logical, bytes.NewReader(content)))
	require.NoError(t, storages["gz"].Put(ctx, logical, bytes.NewReader(content)))
	require.NoError(t, storages["aes"].Put(ctx, logical, bytes.NewReader(content)))
	require.NoError(t, storages["gz.aes"].Put(ctx, logical, bytes.NewReader(content)))

	// Sanity: backend should see all encoded paths as existing.
	for _, extName := range []string{logical, logical + ".gz", logical + ".aes", logical + ".gz.aes"} {
		exists, err := backend.Exists(ctx, filepath.ToSlash(extName))
		require.NoError(t, err)
		assert.True(t, exists, "backend should see %q before delete", extName)
	}

	// Now delete via VariadicStorage logical Delete.
	err := stPlain.Delete(ctx, logical)
	require.NoError(t, err)

	// Logical Exists should be false
	exists, err := stPlain.Exists(ctx, logical)
	require.NoError(t, err)
	assert.False(t, exists, "logical Exists should be false after Delete")

	// All encoded variants must be gone
	for _, extName := range []string{logical, logical + ".gz", logical + ".aes", logical + ".gz.aes"} {
		ex, err := backend.Exists(ctx, filepath.ToSlash(extName))
		require.NoError(t, err)
		assert.False(t, ex, "backend should not see %q after delete", extName)
	}
}

func TestDynStorage_Get_WithExplicitExtension(t *testing.T) {
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	stGzAes := storages["gz.aes"]
	require.NotNil(t, stGzAes)
	backend := stGzAes.Backend

	require.NoError(t, deleteAll(ctx, backend, ""), "initial cleanup")

	const logical = "wal/000000010000000000000004"
	content := []byte("explicit gz.aes")

	// Write via gz.aes wrapper using logical name.
	require.NoError(t, stGzAes.Put(ctx, logical, bytes.NewReader(content)))

	// Build explicit path with extension
	fullPath := logical + ".gz.aes"

	// Get by explicit ext through ANY instance - let's use "plain" here.
	stPlain := storages["plain"]

	rc, err := stPlain.Get(ctx, fullPath)
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	assert.Equal(t, content, got, "Get(fullPath) should decode gz.aes correctly")
}

func TestDynStorage_Rename_SingleVariant(t *testing.T) {
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	stGzAes := storages["gz.aes"]
	require.NotNil(t, stGzAes)

	backend := stGzAes.Backend
	require.NoError(t, deleteAll(ctx, backend, ""), "initial cleanup")

	const (
		oldLogical = "wal/000000010000000000000010"
		newLogical = "wal/000000010000000000000010-renamed"
	)
	content := []byte("rename-single-variant")

	// Write via gz.aes wrapper using logical name.
	require.NoError(t, stGzAes.Put(ctx, oldLogical, bytes.NewReader(content)))

	// Sanity: backend sees only encoded .gz.aes path.
	oldPhys := filepath.ToSlash(oldLogical + ".gz.aes")
	newPhys := filepath.ToSlash(newLogical + ".gz.aes")

	exists, err := backend.Exists(ctx, oldPhys)
	require.NoError(t, err)
	assert.True(t, exists, "backend should see %q before rename", oldPhys)

	exists, err = backend.Exists(ctx, newPhys)
	require.NoError(t, err)
	assert.False(t, exists, "backend should not see %q before rename", newPhys)

	// Rename on logical names.
	require.NoError(t, stGzAes.Rename(ctx, oldLogical, newLogical))

	// Old physical path gone, new present.
	exists, err = backend.Exists(ctx, oldPhys)
	require.NoError(t, err)
	assert.False(t, exists, "backend should not see %q after rename", oldPhys)

	exists, err = backend.Exists(ctx, newPhys)
	require.NoError(t, err)
	assert.True(t, exists, "backend should see %q after rename", newPhys)

	// Logical Exists from different wrappers.
	for name, vs := range storages {
		t.Run("exists-"+name, func(t *testing.T) {
			ex, err := vs.Exists(ctx, oldLogical)
			require.NoError(t, err)
			assert.False(t, ex, "[%s] old logical should not exist after rename", name)

			ex, err = vs.Exists(ctx, newLogical)
			require.NoError(t, err)
			assert.True(t, ex, "[%s] new logical should exist after rename", name)

			// Check content via this wrapper.
			rc, err := vs.Get(ctx, newLogical)
			require.NoError(t, err)
			got, err := io.ReadAll(rc)
			require.NoError(t, err)
			require.NoError(t, rc.Close())
			assert.Equal(t, content, got, "[%s] content mismatch after rename", name)
		})
	}
}

func TestDynStorage_Rename_AllVariantsLogical(t *testing.T) {
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	stPlain := storages["plain"]
	require.NotNil(t, stPlain)
	backend := stPlain.Backend

	require.NoError(t, deleteAll(ctx, backend, ""), "initial cleanup")

	const (
		oldLogical = "wal/000000010000000000000011"
		newLogical = "wal/000000010000000000000011-renamed"
	)
	content := []byte("rename-all-variants")

	// Create several variants for the same logical name.
	require.NoError(t, storages["plain"].Put(ctx, oldLogical, bytes.NewReader(content)))
	require.NoError(t, storages["gz"].Put(ctx, oldLogical, bytes.NewReader(content)))
	require.NoError(t, storages["aes"].Put(ctx, oldLogical, bytes.NewReader(content)))
	require.NoError(t, storages["gz.aes"].Put(ctx, oldLogical, bytes.NewReader(content)))

	oldPhys := []string{
		filepath.ToSlash(oldLogical),
		filepath.ToSlash(oldLogical + ".gz"),
		filepath.ToSlash(oldLogical + ".aes"),
		filepath.ToSlash(oldLogical + ".gz.aes"),
	}
	newPhys := []string{
		filepath.ToSlash(newLogical),
		filepath.ToSlash(newLogical + ".gz"),
		filepath.ToSlash(newLogical + ".aes"),
		filepath.ToSlash(newLogical + ".gz.aes"),
	}

	// Sanity: all old physical paths exist.
	for _, p := range oldPhys {
		ex, err := backend.Exists(ctx, p)
		require.NoError(t, err)
		assert.True(t, ex, "backend should see %q before rename", p)
	}

	// Logical rename via plain instance.
	require.NoError(t, stPlain.Rename(ctx, oldLogical, newLogical))

	// Old physical paths gone, new ones present.
	for i := range oldPhys {
		ex, err := backend.Exists(ctx, oldPhys[i])
		require.NoError(t, err)
		assert.False(t, ex, "backend should not see %q after rename", oldPhys[i])

		ex, err = backend.Exists(ctx, newPhys[i])
		require.NoError(t, err)
		assert.True(t, ex, "backend should see %q after rename", newPhys[i])
	}

	// All wrappers should see new logical, not old, and content must be ok.
	for name, vs := range storages {
		t.Run("logical-"+name, func(t *testing.T) {
			ex, err := vs.Exists(ctx, oldLogical)
			require.NoError(t, err)
			assert.False(t, ex, "[%s] old logical should not exist after rename", name)

			ex, err = vs.Exists(ctx, newLogical)
			require.NoError(t, err)
			assert.True(t, ex, "[%s] new logical should exist after rename", name)

			rc, err := vs.Get(ctx, newLogical)
			require.NoError(t, err)
			got, err := io.ReadAll(rc)
			require.NoError(t, err)
			require.NoError(t, rc.Close())
			assert.Equal(t, content, got, "[%s] content mismatch via logical Get after rename", name)
		})
	}
}

func TestDynStorage_ListPrefix_StripsCodecExtension(t *testing.T) {
	// Verify that VariadicStorage.ListPrefix strips the codec extension from
	// each returned path, regardless of which writeExt was used.
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	backend := storages["plain"].Backend
	require.NoError(t, deleteAll(ctx, backend, ""), "initial cleanup")

	const prefix = "wal/seg--"
	logicals := []string{
		"wal/seg--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00001",
		"wal/seg--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00002",
	}
	content := []byte("wal segment data")

	for writeExt, writer := range storages {
		t.Run("writeExt="+writeExt, func(t *testing.T) {
			require.NoError(t, deleteAll(ctx, backend, ""), "cleanup before sub-test")

			for _, logical := range logicals {
				require.NoError(t, writer.Put(ctx, logical, bytes.NewReader(content)))
			}

			infos, err := writer.ListPrefix(ctx, prefix)
			require.NoError(t, err, "[%s] ListPrefix failed", writeExt)

			paths := make([]string, 0, len(infos))
			for _, fi := range infos {
				paths = append(paths, fi.Path)
			}
			assert.ElementsMatch(t, logicals, paths,
				"[%s] ListPrefix should return logical names with codec extension stripped", writeExt)
		})
	}
}

func TestDynStorage_ListPrefix_SameBackend_CrossWriter(t *testing.T) {
	// Files written by one VariadicStorage variant must be discovered by
	// ListPrefix called on a different variant - all share the same backend.
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	backend := storages["plain"].Backend
	require.NoError(t, deleteAll(ctx, backend, ""), "initial cleanup")

	// Write via gz.aes, then call ListPrefix via plain.
	writer := storages["gz.aes"]
	reader := storages["plain"]

	require.NoError(t, writer.Put(ctx, "seg--hash001", bytes.NewReader([]byte("a"))))
	require.NoError(t, writer.Put(ctx, "seg--hash002", bytes.NewReader([]byte("b"))))
	require.NoError(t, writer.Put(ctx, "other--hash003", bytes.NewReader([]byte("c"))))

	infos, err := reader.ListPrefix(ctx, "seg--")
	require.NoError(t, err)

	paths := fileInfoToStrList(infos)
	assert.ElementsMatch(t, []string{"seg--hash001", "seg--hash002"}, paths,
		"ListPrefix via plain reader should see files written by gz.aes writer")
}

func TestDynStorage_Rename_WithExplicitExtension_MultiVariant(t *testing.T) {
	ctx := context.TODO()
	storages := initDynStoragesSameBackendT(t, t.Name())

	stGzAes := storages["gz.aes"]
	require.NotNil(t, stGzAes)
	backend := stGzAes.Backend

	require.NoError(t, deleteAll(ctx, backend, ""), "initial cleanup")

	const (
		baseOld = "wal/000000010000000000000012"
		baseNew = "wal/000000010000000000000012-renamed"
	)
	content := []byte("rename-explicit-ext")

	// Create multiple variants for baseOld.
	require.NoError(t, storages["plain"].Put(ctx, baseOld, bytes.NewReader(content)))
	require.NoError(t, storages["gz"].Put(ctx, baseOld, bytes.NewReader(content)))
	require.NoError(t, storages["aes"].Put(ctx, baseOld, bytes.NewReader(content)))
	require.NoError(t, storages["gz.aes"].Put(ctx, baseOld, bytes.NewReader(content)))

	oldPhys := []string{
		filepath.ToSlash(baseOld),
		filepath.ToSlash(baseOld + ".gz"),
		filepath.ToSlash(baseOld + ".aes"),
		filepath.ToSlash(baseOld + ".gz.aes"),
	}
	newPhys := []string{
		filepath.ToSlash(baseNew),
		filepath.ToSlash(baseNew + ".gz"),
		filepath.ToSlash(baseNew + ".aes"),
		filepath.ToSlash(baseNew + ".gz.aes"),
	}

	// Verify old physical keys exist.
	for _, p := range oldPhys {
		ex, err := backend.Exists(ctx, p)
		require.NoError(t, err)
		assert.True(t, ex, "backend should see %q before rename", p)
	}

	// Call Rename using explicit extension paths.
	oldFull := baseOld + ".gz.aes"
	newFull := baseNew + ".gz.aes"

	require.NoError(t, stGzAes.Rename(ctx, oldFull, newFull))

	// All old phys must be gone, new ones present.
	for i := range oldPhys {
		ex, err := backend.Exists(ctx, oldPhys[i])
		require.NoError(t, err)
		assert.False(t, ex, "backend should not see %q after rename", oldPhys[i])

		ex, err = backend.Exists(ctx, newPhys[i])
		require.NoError(t, err)
		assert.True(t, ex, "backend should see %q after rename", newPhys[i])
	}

	// Logical Get(baseNew) via plain should still work and return content
	// (it will pick highest-priority variant, .gz.aes).
	stPlain := storages["plain"]

	rc, err := stPlain.Get(ctx, baseNew)
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, content, got, "logical Get(baseNew) should see renamed variants correctly")
}
