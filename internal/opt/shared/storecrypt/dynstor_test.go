package storecrypt

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/codec"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/crypt/aesgcm"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// NewVariadicStorage / isSupportedWriteExt
// -----------------------------------------------------------------------------

func TestNewVariadicStorage_ValidationMatrix(t *testing.T) {
	ctx := context.Background()
	_ = ctx // just to have it handy if needed later

	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	zstdPair := &CodecPair{
		Compressor:   codec.ZstdCompressor{},
		Decompressor: codec.ZstdDecompressor{},
	}

	tests := []struct {
		name     string
		alg      Algorithms
		writeExt string
		ok       bool
	}{
		{"plain-only-ok", Algorithms{}, "", true},
		{"plain-only-gz-fail", Algorithms{}, ".gz", false},
		{"gzip-ok", Algorithms{Gzip: gzipPair}, ".gz", true},
		{"gzip-gz.aes-fail-no-aes", Algorithms{Gzip: gzipPair}, ".gz.aes", false},
		{"zstd-ok", Algorithms{Zstd: zstdPair}, ".zst", true},
		{"aes-only-aes-ok", Algorithms{AES: aes}, ".aes", true},
		{"aes-only-gz-fail", Algorithms{AES: aes}, ".gz", false},
		{"gzip-aes-gz.aes-ok", Algorithms{Gzip: gzipPair, AES: aes}, ".gz.aes", true},
		{"zstd-aes-zst.aes-ok", Algorithms{Zstd: zstdPair, AES: aes}, ".zst.aes", true},
		{"gzip-zstd-aes-gz-ok", Algorithms{Gzip: gzipPair, Zstd: zstdPair, AES: aes}, ".gz", true},
		{"gzip-zstd-aes-zst.ok", Algorithms{Gzip: gzipPair, Zstd: zstdPair, AES: aes}, ".zst", true},
		{"unknown-ext-fail", Algorithms{Gzip: gzipPair, AES: aes}, ".xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewInMemoryStorage()
			vs, err := NewVariadicStorage(backend, tt.alg, tt.writeExt)
			if tt.ok {
				require.NoError(t, err)
				require.NotNil(t, vs)
			} else {
				require.Error(t, err)
				require.Nil(t, vs)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// supportedExts
// -----------------------------------------------------------------------------

func TestSupportedExts_OrderAndContent(t *testing.T) {
	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	zstdPair := &CodecPair{
		Compressor:   codec.ZstdCompressor{},
		Decompressor: codec.ZstdDecompressor{},
	}

	tests := []struct {
		name string
		alg  Algorithms
		want []string
	}{
		{
			name: "plain-only",
			alg:  Algorithms{},
			want: []string{""},
		},
		{
			name: "gzip-only",
			alg:  Algorithms{Gzip: gzipPair},
			want: []string{".gz", ""},
		},
		{
			name: "zstd-only",
			alg:  Algorithms{Zstd: zstdPair},
			want: []string{".zst", ""},
		},
		{
			name: "aes-only",
			alg:  Algorithms{AES: aes},
			want: []string{".aes", ""},
		},
		{
			name: "gzip-aes",
			alg:  Algorithms{Gzip: gzipPair, AES: aes},
			want: []string{".gz.aes", ".gz", ".aes", ""},
		},
		{
			name: "zstd-aes",
			alg:  Algorithms{Zstd: zstdPair, AES: aes},
			want: []string{".zst.aes", ".zst", ".aes", ""},
		},
		{
			name: "gzip-zstd-aes",
			alg:  Algorithms{Gzip: gzipPair, Zstd: zstdPair, AES: aes},
			want: []string{".gz.aes", ".zst.aes", ".gz", ".zst", ".aes", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &VariadicStorage{alg: tt.alg}
			got := vs.supportedExts()
			assert.Equal(t, tt.want, got)
		})
	}
}

// -----------------------------------------------------------------------------
// transformsFromName
// -----------------------------------------------------------------------------

func TestTransformsFromName_AllExtensionCombos(t *testing.T) {
	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	zstdPair := &CodecPair{
		Compressor:   codec.ZstdCompressor{},
		Decompressor: codec.ZstdDecompressor{},
	}

	alg := Algorithms{
		Gzip: gzipPair,
		Zstd: zstdPair,
		AES:  aes,
	}
	vs := &VariadicStorage{alg: alg}

	type wantFlags struct {
		compress bool
		aes      bool
	}

	tests := []struct {
		name string
		path string
		want wantFlags
	}{
		{"plain", "file", wantFlags{compress: false, aes: false}},
		{"gzip", "file.gz", wantFlags{compress: true, aes: false}},
		{"zstd", "file.zst", wantFlags{compress: true, aes: false}},
		{"aes-only", "file.aes", wantFlags{compress: false, aes: true}},
		{"gzip-aes", "file.gz.aes", wantFlags{compress: true, aes: true}},
		{"zstd-aes", "file.zst.aes", wantFlags{compress: true, aes: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := vs.transformsFromName(tt.path)

			gotCompress := tr.compressor != nil && tr.decompressor != nil
			gotAES := tr.crypter != nil

			assert.Equal(t, tt.want.compress, gotCompress, "compress flag mismatch")
			assert.Equal(t, tt.want.aes, gotAES, "aes flag mismatch")
		})
	}
}

// -----------------------------------------------------------------------------
// encodePath / decodePath
// -----------------------------------------------------------------------------

func TestEncodeDecodePath_RoundTrip(t *testing.T) {
	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	zstdPair := &CodecPair{
		Compressor:   codec.ZstdCompressor{},
		Decompressor: codec.ZstdDecompressor{},
	}

	alg := Algorithms{
		Gzip: gzipPair,
		Zstd: zstdPair,
		AES:  aes,
	}

	exts := []string{"", ".gz", ".zst", ".aes", ".gz.aes", ".zst.aes"}
	base := "some/dir/file"

	for _, ext := range exts {
		t.Run("writeExt="+ext, func(t *testing.T) {
			vs, err := NewVariadicStorage(NewInMemoryStorage(), alg, ext)
			if ext == ".gz" || ext == ".zst" || ext == ".aes" || ext == ".gz.aes" || ext == ".zst.aes" {
				require.NoError(t, err)
			}

			// encodePath should append writeExt
			stored := vs.encodePath(base)
			assert.Equal(t, base+ext, stored)

			// decodePath should remove any *known* extension combination
			decoded := vs.decodePath(base + ext)
			assert.Equal(t, base, decoded)
		})
	}
}

// -----------------------------------------------------------------------------
// findExistingName
// -----------------------------------------------------------------------------

func TestFindExistingName_Priority(t *testing.T) {
	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	zstdPair := &CodecPair{
		Compressor:   codec.ZstdCompressor{},
		Decompressor: codec.ZstdDecompressor{},
	}

	alg := Algorithms{
		Gzip: gzipPair,
		Zstd: zstdPair,
		AES:  aes,
	}

	ctx := context.Background()

	t.Run("none-exist", func(t *testing.T) {
		mem := NewInMemoryStorage()
		vs, err := NewVariadicStorage(mem, alg, ".gz")
		require.NoError(t, err)

		_, err = vs.findExistingName(ctx, "file")
		require.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("plain-vs-gz-priority", func(t *testing.T) {
		mem := NewInMemoryStorage()
		mem.Files["file"] = []byte("plain")
		mem.Files["file.gz"] = []byte("gz")

		vs, err := NewVariadicStorage(mem, alg, ".gz")
		require.NoError(t, err)

		stored, err := vs.findExistingName(ctx, "file")
		require.NoError(t, err)
		assert.Equal(t, "file.gz", stored) // .gz wins over plain
	})

	t.Run("gz.aes-highest-priority", func(t *testing.T) {
		mem := NewInMemoryStorage()
		mem.Files["file"] = []byte("plain")
		mem.Files["file.gz"] = []byte("gz")
		mem.Files["file.gz.aes"] = []byte("gz.aes")

		vs, err := NewVariadicStorage(mem, alg, ".gz.aes")
		require.NoError(t, err)

		stored, err := vs.findExistingName(ctx, "file")
		require.NoError(t, err)
		assert.Equal(t, "file.gz.aes", stored)
	})
}

// -----------------------------------------------------------------------------
// Put/Get roundtrip for all variants (using real gzip/zstd/aes)
// -----------------------------------------------------------------------------

func TestVariadicStorage_PutGet_RoundTrip_AllWriteExts(t *testing.T) {
	ctx := context.Background()

	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	zstdPair := &CodecPair{
		Compressor:   codec.ZstdCompressor{},
		Decompressor: codec.ZstdDecompressor{},
	}

	tests := []struct {
		name     string
		alg      Algorithms
		writeExt string
	}{
		{"plain", Algorithms{}, ""},
		{"gzip", Algorithms{Gzip: gzipPair}, ".gz"},
		{"zstd", Algorithms{Zstd: zstdPair}, ".zst"},
		{"aes-only", Algorithms{AES: aes}, ".aes"},
		{"gzip-aes", Algorithms{Gzip: gzipPair, AES: aes}, ".gz.aes"},
		{"zstd-aes", Algorithms{Zstd: zstdPair, AES: aes}, ".zst.aes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := NewInMemoryStorage()
			vs, err := NewVariadicStorage(mem, tt.alg, tt.writeExt)
			require.NoError(t, err)

			path := "wal/000000010000000000000001"
			content := []byte("hello variadic storage")

			// Put by logical name
			require.NoError(t, vs.Put(ctx, path, bytes.NewReader(content)))

			// Ensure a single physical object with encoded name exists
			expectedKey := path + tt.writeExt
			require.Contains(t, mem.Files, expectedKey)
			require.Len(t, mem.Files, 1)

			// Exists by logical name
			ok, err := vs.Exists(ctx, path)
			require.NoError(t, err)
			assert.True(t, ok)

			// Get by logical name
			rc, err := vs.Get(ctx, path)
			require.NoError(t, err)
			got, err := io.ReadAll(rc)
			rc.Close()
			require.NoError(t, err)
			assert.Equal(t, content, got)

			// Get by fully encoded name should also work
			rc2, err := vs.Get(ctx, expectedKey)
			require.NoError(t, err)
			got2, err := io.ReadAll(rc2)
			rc2.Close()
			require.NoError(t, err)
			assert.Equal(t, content, got2)
		})
	}
}

// -----------------------------------------------------------------------------
// Delete / Exists
// -----------------------------------------------------------------------------

func TestVariadicStorage_Delete_RemovesAllVariants(t *testing.T) {
	ctx := context.Background()

	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	alg := Algorithms{
		Gzip: gzipPair,
		AES:  aes,
	}

	mem := NewInMemoryStorage()
	mem.Files["wal/seg"] = []byte("plain")
	mem.Files["wal/seg.gz"] = []byte("gz")
	mem.Files["wal/seg.gz.aes"] = []byte("gz.aes")
	mem.Files["wal/seg.aes"] = []byte("aes")

	vs, err := NewVariadicStorage(mem, alg, ".gz.aes")
	require.NoError(t, err)

	require.NoError(t, vs.Delete(ctx, "wal/seg"))

	for k := range mem.Files {
		if strings.HasPrefix(k, "wal/seg") {
			t.Fatalf("expected no wal/seg* variants, found %q", k)
		}
	}
}

func TestVariadicStorage_DeleteDir_DelegatesAndClearsAllVariants(t *testing.T) {
	ctx := context.Background()

	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	alg := Algorithms{Gzip: gzipPair}

	mem := NewInMemoryStorage()
	mem.Files["wal/seg1.gz"] = []byte("gz1")
	mem.Files["wal/seg2.gz"] = []byte("gz2")
	mem.Files["other/seg3.gz"] = []byte("gz3")

	vs, err := NewVariadicStorage(mem, alg, ".gz")
	require.NoError(t, err)

	require.NoError(t, vs.DeleteDir(ctx, "wal"))

	for k := range mem.Files {
		if strings.HasPrefix(k, "wal/") {
			t.Fatalf("expected no wal/* keys after DeleteDir, found %q", k)
		}
	}
	_, ok := mem.Files["other/seg3.gz"]
	require.True(t, ok, "other/ should be untouched")
}

func TestVariadicStorage_Exists_AnyVariant(t *testing.T) {
	ctx := context.Background()

	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	alg := Algorithms{
		Gzip: gzipPair,
		AES:  aes,
	}

	mem := NewInMemoryStorage()
	mem.Files["wal/seg.gz.aes"] = []byte("data")

	vs, err := NewVariadicStorage(mem, alg, ".gz.aes")
	require.NoError(t, err)

	ok, err := vs.Exists(ctx, "wal/seg")
	require.NoError(t, err)
	assert.True(t, ok)

	ok2, err := vs.Exists(ctx, "wal/other")
	require.NoError(t, err)
	assert.False(t, ok2)
}

// -----------------------------------------------------------------------------
// List / ListInfo / ListTopLevelDirs
// -----------------------------------------------------------------------------

func TestVariadicStorage_List_RewritesLogicalNames_NoDedup(t *testing.T) {
	ctx := context.Background()

	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	alg := Algorithms{
		Gzip: gzipPair,
		AES:  aes,
	}

	mem := NewInMemoryStorage()
	mem.Files["p/a.gz"] = []byte("1")
	mem.Files["p/a.gz.aes"] = []byte("2")
	mem.Files["p/b"] = []byte("3")
	mem.Files["p/b.aes"] = []byte("4")

	vs, err := NewVariadicStorage(mem, alg, ".gz.aes")
	require.NoError(t, err)

	list, err := vs.List(ctx, "p")
	require.NoError(t, err)

	//nolint:prealloc
	fileInfoToStrList := func(fi []FileInfo) []string {
		r := []string{}
		for i := range fi {
			r = append(r, fi[i].Path)
		}
		return r
	}

	// decodePath will map:
	//   p/a.gz      -> p/a
	//   p/a.gz.aes  -> p/a
	//   p/b         -> p/b
	//   p/b.aes     -> p/b
	// Important: no dedup => 4 results.
	assert.ElementsMatch(t, []string{"p/a", "p/a", "p/b", "p/b"}, fileInfoToStrList(list))
}

func TestVariadicStorage_ListInfo_RewritesPath(t *testing.T) {
	ctx := context.Background()

	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	alg := Algorithms{
		Gzip: gzipPair,
		AES:  aes,
	}

	mem := NewInMemoryStorage()
	mem.Files["p/a.gz.aes"] = []byte("1")
	mem.Files["p/c"] = []byte("2")

	vs, err := NewVariadicStorage(mem, alg, ".gz.aes")
	require.NoError(t, err)

	info, err := vs.List(ctx, "p")
	require.NoError(t, err)

	//nolint:prealloc
	var paths []string
	for _, fi := range info {
		paths = append(paths, fi.Path)
	}

	assert.ElementsMatch(t, []string{"p/a", "p/c"}, paths)
}

// -----------------------------------------------------------------------------
// ListPrefix
// -----------------------------------------------------------------------------

func TestVariadicStorage_ListPrefix_StripsCodecExtension(t *testing.T) {
	ctx := context.Background()

	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	alg := Algorithms{Gzip: gzipPair, AES: aes}

	mem := NewInMemoryStorage()
	// Store with the full physical name including codec extension.
	mem.Files["seg--abc.gz.aes"] = []byte("1")
	mem.Files["seg--def.gz.aes"] = []byte("2")
	mem.Files["other--xyz.gz.aes"] = []byte("3")

	vs, err := NewVariadicStorage(mem, alg, ".gz.aes")
	require.NoError(t, err)

	infos, err := vs.ListPrefix(ctx, "seg--")
	require.NoError(t, err)

	//nolint:prealloc
	var paths []string
	for _, fi := range infos {
		paths = append(paths, fi.Path)
	}
	assert.ElementsMatch(t, []string{"seg--abc", "seg--def"}, paths)
}

func TestVariadicStorage_ListPrefix_PlainBackend_NoExtension(t *testing.T) {
	ctx := context.Background()

	mem := NewInMemoryStorage()
	mem.Files["seg--abc"] = []byte("x")
	mem.Files["seg--def"] = []byte("y")

	vs, err := NewVariadicStorage(mem, Algorithms{}, "")
	require.NoError(t, err)

	infos, err := vs.ListPrefix(ctx, "seg--")
	require.NoError(t, err)

	//nolint:prealloc
	var paths []string
	for _, fi := range infos {
		paths = append(paths, fi.Path)
	}
	assert.ElementsMatch(t, []string{"seg--abc", "seg--def"}, paths)
}

func TestVariadicStorage_ListPrefix_NoMatch_ReturnsNil(t *testing.T) {
	ctx := context.Background()

	mem := NewInMemoryStorage()
	mem.Files["seg--abc.gz"] = []byte("1")

	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	vs, err := NewVariadicStorage(mem, Algorithms{Gzip: gzipPair}, ".gz")
	require.NoError(t, err)

	infos, err := vs.ListPrefix(ctx, "missing--")
	require.NoError(t, err)
	assert.Nil(t, infos)
}

func TestVariadicStorage_ListPrefix_WithDirectory_PreservesPath(t *testing.T) {
	ctx := context.Background()

	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	alg := Algorithms{Gzip: gzipPair}

	mem := NewInMemoryStorage()
	mem.Files["wal/000000010000000000000001--abc.gz"] = []byte("a")
	mem.Files["wal/000000010000000000000001--def.gz"] = []byte("b")
	mem.Files["wal/000000010000000000000002--xyz.gz"] = []byte("c")

	vs, err := NewVariadicStorage(mem, alg, ".gz")
	require.NoError(t, err)

	infos, err := vs.ListPrefix(ctx, "wal/000000010000000000000001--")
	require.NoError(t, err)

	//nolint:prealloc
	var paths []string
	for _, fi := range infos {
		paths = append(paths, fi.Path)
	}
	assert.ElementsMatch(t, []string{
		"wal/000000010000000000000001--abc",
		"wal/000000010000000000000001--def",
	}, paths)
}

func TestVariadicStorage_ListPrefix_MultipleExtensionVariants(t *testing.T) {
	// If the same logical prefix has objects with different codec extensions,
	// ListPrefix must strip each correctly.
	ctx := context.Background()

	aes := aesgcm.NewChunkedGCMCrypter("password")
	gzipPair := &CodecPair{
		Compressor:   codec.GzipCompressor{},
		Decompressor: codec.GzipDecompressor{},
	}
	zstdPair := &CodecPair{
		Compressor:   codec.ZstdCompressor{},
		Decompressor: codec.ZstdDecompressor{},
	}
	alg := Algorithms{Gzip: gzipPair, Zstd: zstdPair, AES: aes}

	mem := NewInMemoryStorage()
	mem.Files["seg--aaa.gz.aes"] = []byte("1")
	mem.Files["seg--bbb.zst"] = []byte("2")
	mem.Files["seg--ccc"] = []byte("3")

	vs, err := NewVariadicStorage(mem, alg, ".gz.aes")
	require.NoError(t, err)

	infos, err := vs.ListPrefix(ctx, "seg--")
	require.NoError(t, err)

	//nolint:prealloc
	var paths []string
	for _, fi := range infos {
		paths = append(paths, fi.Path)
	}
	assert.ElementsMatch(t, []string{"seg--aaa", "seg--bbb", "seg--ccc"}, paths)
}

func TestVariadicStorage_ListPrefix_DelegatesToBackendWithExactPrefix(t *testing.T) {
	// Verify that the exact prefix string is forwarded to the backend unchanged.
	ctx := context.Background()

	mem := NewInMemoryStorage()
	mem.Files["prefix-with-special.chars--abc"] = []byte("x")
	mem.Files["prefix-with-special.chars--def"] = []byte("y")
	mem.Files["unrelated"] = []byte("z")

	vs, err := NewVariadicStorage(mem, Algorithms{}, "")
	require.NoError(t, err)

	infos, err := vs.ListPrefix(ctx, "prefix-with-special.chars--")
	require.NoError(t, err)
	assert.Len(t, infos, 2)
}
