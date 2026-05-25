//go:build integration_storage

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"testing"

	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/codec"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/crypt/aesgcm"

	storage "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func impls(dir, subpath string) map[string]storage.Storage {
	// Helpers to create *isolated* backends per storage name.
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

	// Algorithms: tell VariadicStorage what we *can* do.
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

	newVariadic := func(backend storage.Storage, writeExt string) storage.Storage {
		st, err := storage.NewVariadicStorage(backend, alg, writeExt)
		if err != nil {
			log.Fatalf("failed to create VariadicStorage: %v", err)
		}
		return st
	}

	return map[string]storage.Storage{
		// dynamic - **each has its own backend** too
		"dyn-local-gz.aes": newVariadic(mkLocal("dyn-local-gz.aes"), ".gz.aes"),
		"dyn-s3-gz.aes":    newVariadic(mkS3("dyn-s3-gz.aes"), ".gz.aes"),
		"dyn-sftp-gz.aes":  newVariadic(mkSFTP("dyn-sftp-gz.aes"), ".gz.aes"),

		"dyn-local-gz": newVariadic(mkLocal("dyn-local-gz"), ".gz"),
		"dyn-s3-gz":    newVariadic(mkS3("dyn-s3-gz"), ".gz"),
		"dyn-sftp-gz":  newVariadic(mkSFTP("dyn-sftp-gz"), ".gz"),

		"dyn-local": newVariadic(mkLocal("dyn-local"), ""),
		"dyn-s3":    newVariadic(mkS3("dyn-s3"), ""),
		"dyn-sftp":  newVariadic(mkSFTP("dyn-sftp"), ""),

		"dyn-local-zst": newVariadic(mkLocal("dyn-local-zst"), ".zst"),
		"dyn-s3-zst":    newVariadic(mkS3("dyn-s3-zst"), ".zst"),
		"dyn-sftp-zst":  newVariadic(mkSFTP("dyn-sftp-zst"), ".zst"),

		"dyn-local-aes": newVariadic(mkLocal("dyn-local-aes"), ".aes"),
		"dyn-s3-aes":    newVariadic(mkS3("dyn-s3-aes"), ".aes"),
		"dyn-sftp-aes":  newVariadic(mkSFTP("dyn-sftp-aes"), ".aes"),
	}
}

func initStoragesT(t *testing.T, subpath string) map[string]storage.Storage {
	t.Helper()
	return impls(t.TempDir(), subpath)
}

func initStoragesB(b *testing.B, subpath string) map[string]storage.Storage {
	b.Helper()
	return impls(b.TempDir(), subpath)
}

func TestStorage_PutGetExists(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			path := "folder/test.txt"
			content := []byte("hello secure world")

			err := store.Put(ctx, path, bytes.NewReader(content))
			require.NoError(t, err, "Put failed for storage: %s", name)

			exists, err := store.Exists(ctx, path)
			require.NoError(t, err, "Exists failed for storage: %s", name)
			assert.True(t, exists, "File should exist for storage: %s", name)

			r, err := store.Get(ctx, path)
			require.NoError(t, err, "Get failed for storage: %s", name)

			readContent, err := io.ReadAll(r)
			require.NoError(t, err)
			require.NoError(t, r.Close())
			assert.Equal(t, content, readContent, "Content mismatch for: %s", name)
		})
	}
}

func TestStorage_List(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			files := []string{
				"list/a.txt",
				"list/b.txt",
				"list/c.txt",
			}

			for _, f := range files {
				err := store.Put(ctx, f, bytes.NewReader([]byte("x")))
				require.NoError(t, err, "[%s] Put failed for %s", name, f)
			}

			listed, err := store.List(ctx, "list")
			require.NoError(t, err, "[%s] List failed", name)
			assert.ElementsMatch(t, files, fileInfoToStrList(listed), "[%s] Listed files mismatch", name)
		})
	}
}

func TestStorage_ListTopLevel(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			files := []string{
				"list/a/b/c/d/e/a.txt",
				"list/1/2/3/4/5/6/7/8/b.txt",
				"list/1/2/c.txt",
			}

			for _, f := range files {
				err := store.Put(ctx, f, bytes.NewReader([]byte("x")))
				require.NoError(t, err, "[%s] Put failed for %s", name, f)
			}

			listed, err := store.ListTopLevelDirs(ctx, "list/1")
			require.NoError(t, err, "[%s] ListTopLevel failed", name)
			assert.Equal(t, map[string]bool{"list/1/2": true}, listed, "[%s] Listed files mismatch", name)
		})
	}
}

func TestStorage_ListInfo(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			files := []string{
				"list/a.txt",
				"list/b.txt",
				"list/c.txt",
			}

			for _, f := range files {
				err := store.Put(ctx, f, bytes.NewReader([]byte("x")))
				require.NoError(t, err, "[%s] Put failed for %s", name, f)
			}

			var listedPaths []string

			listed, err := store.List(ctx, "list")
			require.NoError(t, err, "[%s] List failed", name)

			for _, elem := range listed {
				listedPaths = append(listedPaths, elem.Path)
			}

			assert.ElementsMatch(t, files, listedPaths, "[%s] Listed files mismatch", name)
		})
	}
}

func TestStorage_Delete(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			path := "del/test.txt"

			err := store.Put(ctx, path, bytes.NewReader([]byte("delete me")))
			require.NoError(t, err, "[%s] Put failed", name)

			err = store.Delete(ctx, path)
			require.NoError(t, err, "[%s] Delete failed", name)

			exists, err := store.Exists(ctx, path)
			require.NoError(t, err, "[%s] Exists check failed", name)
			assert.False(t, exists, "[%s] File should be deleted", name)
		})
	}
}

func TestStorage_DeleteAll(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			files := []string{
				"bulk/f1.txt",
				"bulk/f2.txt",
				"bulk/f3.txt",
			}

			for _, f := range files {
				err := store.Put(ctx, f, bytes.NewReader([]byte("bulk content")))
				require.NoError(t, err, "[%s] Put failed for %s", name, f)
			}

			err := deleteAll(ctx, store, "bulk")
			require.NoError(t, err, "[%s] deleteAll failed", name)

			listed, err := store.List(ctx, "bulk")
			require.NoError(t, err, "[%s] List after deleteAll failed", name)
			assert.Empty(t, listed, "[%s] Files not deleted by deleteAll", name)
		})
	}
}

func TestStorage_DeleteDir(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			files := []string{
				"bulk/f1.txt",
				"bulk/f2.txt",
				"bulk/f3.txt",
			}

			for _, f := range files {
				err := store.Put(ctx, f, bytes.NewReader([]byte("bulk content")))
				require.NoError(t, err, "[%s] Put failed for %s", name, f)
			}

			err := store.DeleteDir(ctx, "bulk")
			require.NoError(t, err, "[%s] DeleteDir failed", name)
			ex, err := store.Exists(ctx, "bulk")
			assert.NoError(t, err)
			assert.False(t, ex)
		})
	}
}

func TestStorage_DeleteAllBulk(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			files := []string{
				"bulk/f1.txt",
				"bulk/f2.txt",
				"bulk/f3.txt",
			}

			for _, f := range files {
				err := store.Put(ctx, f, bytes.NewReader([]byte("bulk content")))
				require.NoError(t, err, "[%s] Put failed for %s", name, f)
			}

			err := deleteAllBulk(ctx, store, []string{"bulk/f1.txt", "bulk/f3.txt"})
			require.NoError(t, err, "[%s] deleteAllBulk failed", name)

			listed, err := store.List(ctx, "bulk")
			require.NoError(t, err, "[%s] List after deleteAllBulk failed", name)
			assert.Equal(t, 1, len(listed), "[%s] Expect a single file remain after deleteAllBulk", name)
		})
	}
}

func TestStorage_PutObjectsWithPrefixes(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, r := range storages {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, deleteAll(ctx, r, ""), "[%s] deleteAll before put", name)

			// Upload 100 files with random nested prefixes
			for i := 0; i < 100; i++ {
				content := []byte("gzip + encrypted")
				prefix := genPaths(rnd(1, 14))
				logicalPath := fmt.Sprintf("%s/file-%d.txt", prefix, i)

				err := r.Put(ctx, logicalPath, bytes.NewReader(content))
				require.NoError(t, err, "[%s] Put failed for %s", name, logicalPath)
			}

			// List
			list, err := r.List(ctx, "")
			assert.NoError(t, err, "[%s] List failed", name)
			assert.Equal(t, 100, len(list), "[%s] Expected 100 files, got %d", name, len(list))

			// Cleanup
			require.NoError(t, deleteAll(ctx, r, ""), "[%s] deleteAll after test", name)

			// Confirm clean
			list, err = r.List(ctx, "")
			assert.NoError(t, err, "[%s] List after cleanup failed", name)
			assert.Equal(t, 0, len(list), "[%s] Files not fully cleaned up", name)
		})
	}
}

func TestStorage_Rename(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			src := "rename/src.txt"
			dst := "rename/dst.txt"
			content := []byte("rename me please")

			// Ensure clean state
			require.NoError(t, deleteAll(ctx, store, ""), "[%s] deleteAll before test failed", name)

			// Put source
			err := store.Put(ctx, src, bytes.NewReader(content))
			require.NoError(t, err, "[%s] Put(src) failed", name)

			// Sanity: src exists, dst does not
			exists, err := store.Exists(ctx, src)
			require.NoError(t, err, "[%s] Exists(src) failed", name)
			assert.True(t, exists, "[%s] src should exist before Rename", name)

			exists, err = store.Exists(ctx, dst)
			require.NoError(t, err, "[%s] Exists(dst) failed", name)
			assert.False(t, exists, "[%s] dst should not exist before Rename", name)

			// Do rename
			err = store.Rename(ctx, src, dst)
			require.NoError(t, err, "[%s] Rename failed", name)

			// src should be gone
			exists, err = store.Exists(ctx, src)
			require.NoError(t, err, "[%s] Exists(src) after Rename failed", name)
			assert.False(t, exists, "[%s] src should not exist after Rename", name)

			// dst should exist
			exists, err = store.Exists(ctx, dst)
			require.NoError(t, err, "[%s] Exists(dst) after Rename failed", name)
			assert.True(t, exists, "[%s] dst should exist after Rename", name)

			// Content must be preserved
			r, err := store.Get(ctx, dst)
			require.NoError(t, err, "[%s] Get(dst) failed", name)

			readContent, err := io.ReadAll(r)
			require.NoError(t, err)
			require.NoError(t, r.Close())
			assert.Equal(t, content, readContent, "[%s] content mismatch after Rename", name)

			// List under "rename" should show only dst
			listed, err := store.List(ctx, "rename")
			require.NoError(t, err, "[%s] List(\"rename\") failed", name)
			assert.ElementsMatch(t, []string{dst}, fileInfoToStrList(listed), "[%s] List result mismatch after Rename", name)
		})
	}
}

func TestStorage_RenameSamePathNoop(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			path := "rename-noop/file.txt"
			content := []byte("same path rename")

			// Ensure clean state
			require.NoError(t, deleteAll(ctx, store, ""), "[%s] deleteAll before test failed", name)

			// Put file
			err := store.Put(ctx, path, bytes.NewReader(content))
			require.NoError(t, err, "[%s] Put failed", name)

			// Rename to itself should be a no-op and not error
			err = store.Rename(ctx, path, path)
			require.NoError(t, err, "[%s] Rename(path, path) failed", name)

			// Still exists
			exists, err := store.Exists(ctx, path)
			require.NoError(t, err, "[%s] Exists failed", name)
			assert.True(t, exists, "[%s] file missing after noop Rename", name)

			// Content unchanged
			r, err := store.Get(ctx, path)
			require.NoError(t, err, "[%s] Get failed", name)
			read, err := io.ReadAll(r)
			require.NoError(t, err)
			require.NoError(t, r.Close())
			assert.Equal(t, content, read, "[%s] content changed after noop Rename", name)
		})
	}
}

func TestStorage_HighLoad100(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, deleteAll(ctx, store, ""), "[%s] deleteAll before test", name)

			const fileCount = 100
			content := []byte("this is a stress test file content")

			// Upload
			for i := 0; i < fileCount; i++ {
				path := fmt.Sprintf("hl/%04d.txt", i)
				err := store.Put(ctx, path, bytes.NewReader(content))
				require.NoError(t, err, "[%s] Put failed for %s", name, path)
			}

			// List and check count
			list, err := store.List(ctx, "hl")
			require.NoError(t, err, "[%s] List failed", name)
			assert.Len(t, list, fileCount, "[%s] List returned wrong count", name)

			// Read and verify
			for i := 0; i < fileCount; i++ {
				path := fmt.Sprintf("hl/%04d.txt", i)

				exists, err := store.Exists(ctx, path)
				require.NoError(t, err, "[%s] Exists failed for %s", name, path)
				assert.True(t, exists, "[%s] File missing: %s", name, path)

				r, err := store.Get(ctx, path)
				require.NoError(t, err, "[%s] Get failed for %s", name, path)

				read, err := io.ReadAll(r)
				require.NoError(t, err)
				require.NoError(t, r.Close())
				assert.Equal(t, content, read, "[%s] Content mismatch for %s", name, path)
			}

			// Cleanup
			require.NoError(t, deleteAll(ctx, store, "hl"), "[%s] deleteAll cleanup failed", name)
			finalList, err := store.List(ctx, "hl")
			require.NoError(t, err)
			assert.Empty(t, finalList, "[%s] Files not cleaned up", name)
		})
	}
}

// go test -bench=. -benchmem -gcflags=-m github.com/hashmap-kz/xrepo/test/integration

func BenchmarkStorage_PutGet(b *testing.B) {
	ctx := context.TODO()
	storages := initStoragesB(b, b.Name())

	const (
		sampleCount = 100
		content     = "this is a stress test file content"
	)

	for name, store := range storages {
		b.Run(name, func(b *testing.B) {
			// Setup: upload sample files once
			for i := 0; i < sampleCount; i++ {
				path := fmt.Sprintf("bench/%04d.txt", i)
				err := store.Put(ctx, path, bytes.NewReader([]byte(content)))
				require.NoError(b, err, "[%s] Setup Put failed for %s", name, path)
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				idx := i % sampleCount
				path := fmt.Sprintf("bench/%04d.txt", idx)

				r, err := store.Get(ctx, path)
				if err != nil {
					b.Fatalf("[%s] Get failed: %v", name, err)
				}
				_, err = io.Copy(io.Discard, r)
				r.Close()
				if err != nil {
					b.Fatalf("[%s] Read failed: %v", name, err)
				}
			}

			b.StopTimer()

			// Cleanup
			err := deleteAll(ctx, store, "bench")
			require.NoError(b, err, "[%s] deleteAll cleanup failed", name)
		})
	}
}

func TestStorage_DeleteAllBulk_DoesNotDeletePrefixCollisions(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			files := []string{
				"bulk/f1.txt",
				"bulk/f1.txt.extra",
				"bulk/f10.txt",
				"bulk/f3.txt",
			}

			for _, f := range files {
				require.NoError(t, store.Put(ctx, f, bytes.NewReader([]byte(f))))
			}

			require.NoError(t, deleteAllBulk(ctx, store, []string{"bulk/f1.txt"}))

			ex, err := store.Exists(ctx, "bulk/f1.txt")
			require.NoError(t, err)
			assert.False(t, ex)

			for _, shouldRemain := range []string{"bulk/f1.txt.extra", "bulk/f10.txt", "bulk/f3.txt"} {
				ex, err := store.Exists(ctx, shouldRemain)
				require.NoError(t, err)
				assert.True(t, ex, "%s should not be deleted by prefix collision", shouldRemain)
			}
		})
	}
}

func TestStorage_ListPrefix(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			// Store three files: two share the "wal/seg--" prefix, one does not.
			require.NoError(t, store.Put(ctx, "wal/seg--abc", bytes.NewReader([]byte("a"))))
			require.NoError(t, store.Put(ctx, "wal/seg--def", bytes.NewReader([]byte("b"))))
			require.NoError(t, store.Put(ctx, "wal/other--xyz", bytes.NewReader([]byte("c"))))

			infos, err := store.ListPrefix(ctx, "wal/seg--")
			require.NoError(t, err, "[%s] ListPrefix failed", name)

			paths := fileInfoToStrList(infos)
			assert.ElementsMatch(t, []string{"wal/seg--abc", "wal/seg--def"}, paths,
				"[%s] unexpected ListPrefix result", name)
		})
	}
}

func TestStorage_ListPrefix_EmptyWhenNoMatch(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, store.Put(ctx, "seg--abc", bytes.NewReader([]byte("x"))))

			infos, err := store.ListPrefix(ctx, "nomatch--")
			require.NoError(t, err, "[%s] ListPrefix failed", name)
			assert.Empty(t, infos, "[%s] expected empty result for non-matching prefix", name)
		})
	}
}

func TestStorage_ListPrefix_DoesNotAddTrailingSlash(t *testing.T) {
	// ListPrefix("seg") must match "seg001" and "seg--hash" (no "/" boundary),
	// unlike List("seg") which appends "/" and only matches "seg/child".
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, store.Put(ctx, "seg001", bytes.NewReader([]byte("a"))))
			require.NoError(t, store.Put(ctx, "seg002", bytes.NewReader([]byte("b"))))
			require.NoError(t, store.Put(ctx, "seg/child", bytes.NewReader([]byte("c"))))
			require.NoError(t, store.Put(ctx, "other", bytes.NewReader([]byte("d"))))

			// ListPrefix - prefix without "/" matches any key starting with "seg".
			infos, err := store.ListPrefix(ctx, "seg")
			require.NoError(t, err, "[%s] ListPrefix failed", name)
			paths := fileInfoToStrList(infos)
			assert.ElementsMatch(t, []string{"seg001", "seg002", "seg/child"}, paths,
				"[%s] ListPrefix should not add trailing slash", name)

			// List("seg") - appends "/" internally, so only "seg/child" is returned.
			listed, err := store.List(ctx, "seg")
			require.NoError(t, err, "[%s] List failed", name)
			listedPaths := fileInfoToStrList(listed)
			assert.ElementsMatch(t, []string{"seg/child"}, listedPaths,
				"[%s] List should scope to seg/ prefix", name)
		})
	}
}

func TestStorage_List_DoesNotReturnPrefixSibling(t *testing.T) {
	ctx := context.TODO()
	storages := initStoragesT(t, t.Name())

	for name, store := range storages {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, store.Put(ctx, "repo/base/a.txt", bytes.NewReader([]byte("a"))))
			require.NoError(t, store.Put(ctx, "repo/base-old/b.txt", bytes.NewReader([]byte("b"))))

			listed, err := store.List(ctx, "repo/base")
			require.NoError(t, err)

			paths := fileInfoToStrList(listed)
			assert.Contains(t, paths, "repo/base/a.txt")
			assert.NotContains(t, paths, "repo/base-old/b.txt")
		})
	}
}
