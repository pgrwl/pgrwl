package storecrypt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/codec"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/crypt/aesgcm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hexOf returns the lowercase hex SHA-256 of b.
func hexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// physKey returns the expected physical key for a logical name and content.
func physKey(logical string, content []byte) string {
	return logical + checksumSep + hexOf(content)
}

// readAll reads an io.ReadCloser fully and closes it.
func readAll(t *testing.T, rc io.ReadCloser) []byte {
	t.Helper()
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	return data
}

// -----------------------------------------------------------------------------
// Put
// -----------------------------------------------------------------------------

func TestChecksumStorage_Put_StoresWithHashSuffix(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	content := []byte("hello wal segment")
	require.NoError(t, cs.Put(ctx, "seg001", bytes.NewReader(content)))

	expected := physKey("seg001", content)
	require.Contains(t, mem.Files, expected, "physical key not found in inner storage")
	assert.Equal(t, content, mem.Files[expected])
}

func TestChecksumStorage_Put_EmptyContent(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, cs.Put(ctx, "empty", bytes.NewReader(nil)))

	expected := physKey("empty", []byte{})
	require.Contains(t, mem.Files, expected)
	assert.Empty(t, mem.Files[expected])
}

func TestChecksumStorage_Put_DifferentContentDifferentKey(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	a := []byte("version one")
	b := []byte("version two")

	require.NoError(t, cs.Put(ctx, "seg", bytes.NewReader(a)))
	require.NoError(t, cs.Put(ctx, "seg", bytes.NewReader(b)))

	// Two distinct physical keys must exist.
	assert.Contains(t, mem.Files, physKey("seg", a))
	assert.Contains(t, mem.Files, physKey("seg", b))
}

// -----------------------------------------------------------------------------
// Get - happy path
// -----------------------------------------------------------------------------

func TestChecksumStorage_Get_RoundTrip(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	content := []byte("round trip content")
	require.NoError(t, cs.Put(ctx, "wal/seg", bytes.NewReader(content)))

	rc, err := cs.Get(ctx, "wal/seg")
	require.NoError(t, err)
	got := readAll(t, rc)
	assert.Equal(t, content, got)
}

func TestChecksumStorage_Get_LargeContent(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	content := bytes.Repeat([]byte("abcdefgh"), 1<<16) // 512 KiB
	require.NoError(t, cs.Put(ctx, "big", bytes.NewReader(content)))

	rc, err := cs.Get(ctx, "big")
	require.NoError(t, err)
	got := readAll(t, rc)
	assert.Equal(t, content, got)
}

// -----------------------------------------------------------------------------
// Get - checksum verification
// -----------------------------------------------------------------------------

func TestChecksumStorage_Get_DetectsCorruption(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	content := []byte("correct content")
	require.NoError(t, cs.Put(ctx, "seg", bytes.NewReader(content)))

	// Corrupt the stored bytes.
	for k := range mem.Files {
		if strings.HasPrefix(k, "seg"+checksumSep) {
			mem.Files[k] = []byte("corrupted!!")
		}
	}

	rc, err := cs.Get(ctx, "seg")
	require.NoError(t, err)

	_, err = io.ReadAll(rc)
	assert.ErrorContains(t, err, "digest mismatch")
	rc.Close()
}

func TestChecksumStorage_Get_PartialReadStillVerifies(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	content := bytes.Repeat([]byte("x"), 1024)
	require.NoError(t, cs.Put(ctx, "seg", bytes.NewReader(content)))

	// Corrupt the stored bytes so the hash is wrong.
	for k := range mem.Files {
		if strings.HasPrefix(k, "seg"+checksumSep) {
			corrupted := make([]byte, len(content))
			copy(corrupted, content)
			corrupted[0] = 'Z'
			mem.Files[k] = corrupted
		}
	}

	rc, err := cs.Get(ctx, "seg")
	require.NoError(t, err)

	buf := make([]byte, 16)
	var readErr error
	for readErr == nil {
		_, readErr = rc.Read(buf)
	}
	assert.ErrorContains(t, readErr, "digest mismatch")
	rc.Close()
}

// -----------------------------------------------------------------------------
// Get - backward compatibility (no hash in name)
// -----------------------------------------------------------------------------

func TestChecksumStorage_Get_FallbackToPlainName(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	// Store directly in the inner storage without a checksum suffix.
	content := []byte("legacy file")
	require.NoError(t, mem.Put(ctx, "legacy", bytes.NewReader(content)))

	rc, err := cs.Get(ctx, "legacy")
	require.NoError(t, err)
	got := readAll(t, rc)
	assert.Equal(t, content, got)
}

func TestChecksumStorage_Get_MissingReturnsNotExist(t *testing.T) {
	ctx := context.Background()
	cs := NewChecksumStorage(NewInMemoryStorage())

	_, err := cs.Get(ctx, "nonexistent")
	assert.True(t, errors.Is(err, fs.ErrNotExist))
}

// -----------------------------------------------------------------------------
// Exists
// -----------------------------------------------------------------------------

func TestChecksumStorage_Exists_FindsHashedVariant(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, cs.Put(ctx, "seg", bytes.NewReader([]byte("data"))))

	ok, err := cs.Exists(ctx, "seg")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestChecksumStorage_Exists_FallbackToPlainName(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, mem.Put(ctx, "plain", bytes.NewReader([]byte("old"))))

	ok, err := cs.Exists(ctx, "plain")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestChecksumStorage_Exists_ReturnsFalseWhenAbsent(t *testing.T) {
	ctx := context.Background()
	cs := NewChecksumStorage(NewInMemoryStorage())

	ok, err := cs.Exists(ctx, "missing")
	require.NoError(t, err)
	assert.False(t, ok)
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestChecksumStorage_Delete_RemovesHashedObject(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	content := []byte("to delete")
	require.NoError(t, cs.Put(ctx, "seg", bytes.NewReader(content)))

	require.NoError(t, cs.Delete(ctx, "seg"))

	assert.Empty(t, mem.Files, "inner storage should be empty after delete")
}

func TestChecksumStorage_Delete_NonExistentIsNoOp(t *testing.T) {
	ctx := context.Background()
	cs := NewChecksumStorage(NewInMemoryStorage())

	assert.NoError(t, cs.Delete(ctx, "absent"))
}

func TestChecksumStorage_Delete_PlainFallback(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, mem.Put(ctx, "legacy", bytes.NewReader([]byte("old"))))

	require.NoError(t, cs.Delete(ctx, "legacy"))

	_, err := mem.Get(ctx, "legacy")
	assert.Error(t, err, "legacy file should have been deleted")
}

// -----------------------------------------------------------------------------
// List
// -----------------------------------------------------------------------------

func TestChecksumStorage_List_StripsHashSuffix(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	segs := []string{"dir/seg001", "dir/seg002", "dir/seg003"}
	for _, s := range segs {
		require.NoError(t, cs.Put(ctx, s, bytes.NewReader([]byte(s))))
	}

	infos, err := cs.List(ctx, "dir")
	require.NoError(t, err)
	require.Len(t, infos, len(segs))

	var paths []string
	for _, fi := range infos {
		paths = append(paths, fi.Path)
	}
	assert.ElementsMatch(t, segs, paths)
}

func TestChecksumStorage_List_PreservesLegacyNames(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	// Put one hashed and one legacy file.
	require.NoError(t, cs.Put(ctx, "dir/new", bytes.NewReader([]byte("new"))))
	require.NoError(t, mem.Put(ctx, "dir/old", bytes.NewReader([]byte("old"))))

	infos, err := cs.List(ctx, "dir")
	require.NoError(t, err)

	var paths []string
	for _, fi := range infos {
		paths = append(paths, fi.Path)
	}
	assert.ElementsMatch(t, []string{"dir/new", "dir/old"}, paths)
}

// -----------------------------------------------------------------------------
// ListPrefix
// -----------------------------------------------------------------------------

func TestChecksumStorage_ListPrefix_StripsHashSuffix(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, cs.Put(ctx, "000000010000000000000001", bytes.NewReader([]byte("a"))))
	require.NoError(t, cs.Put(ctx, "000000010000000000000002", bytes.NewReader([]byte("b"))))

	// Prefix that matches only seg001.
	infos, err := cs.ListPrefix(ctx, "000000010000000000000001"+checksumSep)
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, "000000010000000000000001", infos[0].Path)
}

func TestChecksumStorage_ListPrefix_EmptyWhenNoMatch(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, cs.Put(ctx, "abc", bytes.NewReader([]byte("x"))))

	infos, err := cs.ListPrefix(ctx, "xyz"+checksumSep)
	require.NoError(t, err)
	assert.Empty(t, infos)
}

// -----------------------------------------------------------------------------
// Rename
// -----------------------------------------------------------------------------

func TestChecksumStorage_Rename_PreservesHash(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	content := []byte("rename me")
	require.NoError(t, cs.Put(ctx, "old", bytes.NewReader(content)))

	require.NoError(t, cs.Rename(ctx, "old", "new"))

	// The old key is gone; the new key carries the same hash.
	for k := range mem.Files {
		assert.False(t, strings.HasPrefix(k, "old"+checksumSep), "old key should be gone: %s", k)
		if strings.HasPrefix(k, "new"+checksumSep) {
			assert.Equal(t, content, mem.Files[k])
		}
	}

	// Round-trip via Get must still work.
	rc, err := cs.Get(ctx, "new")
	require.NoError(t, err)
	got := readAll(t, rc)
	assert.Equal(t, content, got)
}

func TestChecksumStorage_Rename_LegacyFile(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, mem.Put(ctx, "old", bytes.NewReader([]byte("legacy"))))

	require.NoError(t, cs.Rename(ctx, "old", "new"))

	_, oldErr := mem.Get(ctx, "old")
	assert.Error(t, oldErr)

	rc, err := mem.Get(ctx, "new")
	require.NoError(t, err)
	got := readAll(t, rc)
	assert.Equal(t, []byte("legacy"), got)
}

// -----------------------------------------------------------------------------
// DeleteDir / ListTopLevelDirs - delegation
// -----------------------------------------------------------------------------

func TestChecksumStorage_DeleteDir_Delegates(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, cs.Put(ctx, "dir/a", bytes.NewReader([]byte("1"))))
	require.NoError(t, cs.Put(ctx, "dir/b", bytes.NewReader([]byte("2"))))
	require.NoError(t, cs.Put(ctx, "other/c", bytes.NewReader([]byte("3"))))

	require.NoError(t, cs.DeleteDir(ctx, "dir"))

	infos, err := cs.List(ctx, "dir")
	require.NoError(t, err)
	assert.Empty(t, infos)

	infos2, err := cs.List(ctx, "other")
	require.NoError(t, err)
	assert.Len(t, infos2, 1)
}

func TestChecksumStorage_ListTopLevelDirs_Delegates(t *testing.T) {
	ctx := context.Background()
	mem := NewInMemoryStorage()
	cs := NewChecksumStorage(mem)

	require.NoError(t, cs.Put(ctx, "root/alpha/seg1", bytes.NewReader([]byte("a"))))
	require.NoError(t, cs.Put(ctx, "root/beta/seg2", bytes.NewReader([]byte("b"))))

	dirs, err := cs.ListTopLevelDirs(ctx, "root")
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"alpha": true, "beta": true}, dirs)
}

// -----------------------------------------------------------------------------
// stripChecksumSuffix
// -----------------------------------------------------------------------------

func TestStripChecksumSuffix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"seg--abc123", "seg"},
		{"dir/seg--deadbeef", "dir/seg"},
		{"nohash", "nohash"},
		{"a--b--c", "a--b"}, // strips only the last occurrence
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, stripChecksumSuffix(tt.input))
		})
	}
}

// -----------------------------------------------------------------------------
// Integration: ChecksumStorage wrapping VariadicStorage (gzip + AES)
// -----------------------------------------------------------------------------

func TestChecksumStorage_OverVariadicStorage_RoundTrip(t *testing.T) {
	ctx := context.Background()

	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	aes := aesgcm.NewChunkedGCMCrypter("secret-passphrase")
	alg := Algorithms{Gzip: gzipPair, AES: aes}

	backend := NewInMemoryStorage()
	varic, err := NewVariadicStorage(backend, alg, ".gz.aes")
	require.NoError(t, err)

	cs := NewChecksumStorage(varic)

	content := bytes.Repeat([]byte("WAL segment data "), 1000)
	require.NoError(t, cs.Put(ctx, "000000010000000000000001", bytes.NewReader(content)))

	// The backend key should look like "000000010000000000000001--{hash}.gz.aes".
	require.Len(t, backend.Files, 1)
	var storedKey string
	for k := range backend.Files {
		storedKey = k
	}
	assert.True(t, strings.HasPrefix(storedKey, "000000010000000000000001"+checksumSep), "unexpected key: %s", storedKey)
	assert.True(t, strings.HasSuffix(storedKey, ".gz.aes"), "unexpected key: %s", storedKey)

	// Round-trip Get must decompress, decrypt, and verify the hash.
	rc, err := cs.Get(ctx, "000000010000000000000001")
	require.NoError(t, err)
	got := readAll(t, rc)
	assert.Equal(t, content, got)
}

func TestChecksumStorage_OverVariadicStorage_DetectsCorruption(t *testing.T) {
	ctx := context.Background()

	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	backend := NewInMemoryStorage()
	varic, err := NewVariadicStorage(backend, Algorithms{Gzip: gzipPair}, ".gz")
	require.NoError(t, err)

	cs := NewChecksumStorage(varic)

	content := []byte("important WAL data")
	require.NoError(t, cs.Put(ctx, "seg", bytes.NewReader(content)))

	// Overwrite the compressed bytes in the backend with garbage.
	for k := range backend.Files {
		backend.Files[k] = bytes.Repeat([]byte{0xFF}, len(backend.Files[k]))
	}

	// Get should fail - either during decompression or hash verification.
	rc, err := cs.Get(ctx, "seg")
	if err != nil {
		// Error during resolve or Get from inner storage - acceptable.
		return
	}
	_, readErr := io.ReadAll(rc)
	rc.Close()
	assert.Error(t, readErr)
}
