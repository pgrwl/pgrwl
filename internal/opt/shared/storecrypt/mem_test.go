package storecrypt

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryStorage_PutAndGet(t *testing.T) {
	s := NewInMemoryStorage()
	ctx := context.Background()

	err := s.Put(ctx, "test/file1", bytes.NewBufferString("hello"))
	assert.NoError(t, err)

	r, err := s.Get(ctx, "test/file1")
	assert.NoError(t, err)
	defer r.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(r)
	assert.NoError(t, err)
	assert.Equal(t, "hello", buf.String())
}

func TestInMemoryStorage_Exists(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	exists, err := s.Exists(ctx, "missing.txt")
	assert.NoError(t, err)
	assert.False(t, exists)

	err = s.Put(ctx, "file.txt", bytes.NewReader([]byte("data")))
	assert.NoError(t, err)
	exists, err = s.Exists(ctx, "file.txt")
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestInMemoryStorage_Delete(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	err := s.Put(ctx, "file.txt", bytes.NewReader([]byte("data")))
	assert.NoError(t, err)
	err = s.Delete(ctx, "file.txt")
	assert.NoError(t, err)

	_, err = s.Get(ctx, "file.txt")
	assert.Error(t, err)
}

func TestInMemoryStorage_List(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	// Populate storage with files in different "directories"
	err := s.Put(ctx, "dir1/file1.txt", strings.NewReader("data1"))
	assert.NoError(t, err)

	err = s.Put(ctx, "dir1/file2.txt", strings.NewReader("data2"))
	assert.NoError(t, err)
	err = s.Put(ctx, "dir2/file3.txt", strings.NewReader("data3"))
	assert.NoError(t, err)
	err = s.Put(ctx, "dir1/subdir/file4.txt", strings.NewReader("data4"))
	assert.NoError(t, err)

	// List files under dir1
	files, err := s.List(ctx, "dir1")
	assert.NoError(t, err)

	// We expect file1.txt, file2.txt, and subdir/file4.txt under dir1
	expected := map[string]bool{
		"dir1/file1.txt":        true,
		"dir1/file2.txt":        true,
		"dir1/subdir/file4.txt": true,
	}
	assert.Len(t, files, 3)

	for _, file := range files {
		assert.True(t, expected[file.Path], "unexpected file listed: %s", file)
	}
}

func TestInMemoryStorage_ListInfo(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	err := s.Put(ctx, "a/b/c.txt", bytes.NewReader([]byte("content")))
	assert.NoError(t, err)
	err = s.Put(ctx, "a/b/d.txt", bytes.NewReader([]byte("another")))
	assert.NoError(t, err)
	infos, err := s.List(ctx, "a/b")
	assert.NoError(t, err)
	assert.Len(t, infos, 2)
}

func TestInMemoryStorage_ListTopLevelDirs(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	err := s.Put(ctx, "prefix/dir1/file1.txt", strings.NewReader("data1"))
	assert.NoError(t, err)
	err = s.Put(ctx, "prefix/dir1/subdir/file2.txt", strings.NewReader("data2"))
	assert.NoError(t, err)
	err = s.Put(ctx, "prefix/dir2/file3.txt", strings.NewReader("data3"))
	assert.NoError(t, err)
	err = s.Put(ctx, "prefix/dir3/nested/file4.txt", strings.NewReader("data4"))
	assert.NoError(t, err)
	err = s.Put(ctx, "prefix/file5.txt", strings.NewReader("data5"))
	assert.NoError(t, err)
	err = s.Put(ctx, "other/dir4/file6.txt", strings.NewReader("data6"))
	assert.NoError(t, err)

	result, err := s.ListTopLevelDirs(ctx, "prefix")
	assert.NoError(t, err)

	expected := map[string]bool{
		"dir1": true,
		"dir2": true,
		"dir3": true,
	}

	assert.Len(t, result, 3)
	for dir := range result {
		assert.True(t, expected[dir], "unexpected directory: %s", dir)
	}

	result2, err := s.ListTopLevelDirs(ctx, "prefix/")
	assert.NoError(t, err)
	assert.Equal(t, result, result2)

	result3, err := s.ListTopLevelDirs(ctx, "nonexistent")
	assert.NoError(t, err)
	assert.Empty(t, result3)
}

// -----------------------------------------------------------------------------
// ListPrefix
// -----------------------------------------------------------------------------

func TestInMemoryStorage_ListPrefix_BasicMatch(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	s.Files["seg--aaa"] = []byte("1")
	s.Files["seg--bbb"] = []byte("22")
	s.Files["other--ccc"] = []byte("333")

	infos, err := s.ListPrefix(ctx, "seg--")
	require.NoError(t, err)

	paths := make(map[string]int64)
	for _, fi := range infos {
		paths[fi.Path] = fi.Size
	}

	assert.Len(t, paths, 2)
	assert.Equal(t, int64(1), paths["seg--aaa"])
	assert.Equal(t, int64(2), paths["seg--bbb"])
}

func TestInMemoryStorage_ListPrefix_NoMatch_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	s.Files["seg--aaa"] = []byte("x")

	infos, err := s.ListPrefix(ctx, "xyz--")
	require.NoError(t, err)
	assert.Nil(t, infos)
}

func TestInMemoryStorage_ListPrefix_EmptyPrefix_MatchesAll(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	s.Files["a"] = []byte("1")
	s.Files["b/c"] = []byte("2")

	infos, err := s.ListPrefix(ctx, "")
	require.NoError(t, err)
	assert.Len(t, infos, 2)
}

func TestInMemoryStorage_ListPrefix_NoTrailingSlashAdded(t *testing.T) {
	// Unlike List, ListPrefix must NOT append "/" - so "seg" matches "seg001"
	// and "seg--hash", not just "seg/child".
	ctx := context.Background()
	s := NewInMemoryStorage()

	s.Files["seg001"] = []byte("a")
	s.Files["seg002"] = []byte("b")
	s.Files["seg/child"] = []byte("c")
	s.Files["other"] = []byte("d")

	infos, err := s.ListPrefix(ctx, "seg")
	require.NoError(t, err)

	//nolint:prealloc
	var paths []string
	for _, fi := range infos {
		paths = append(paths, fi.Path)
	}
	assert.ElementsMatch(t, []string{"seg001", "seg002", "seg/child"}, paths)
}

func TestInMemoryStorage_ListPrefix_ExactKeyMatchesItself(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()
	s.Files["exact"] = []byte("hello")

	infos, err := s.ListPrefix(ctx, "exact")
	require.NoError(t, err)

	require.Len(t, infos, 1)
	assert.Equal(t, "exact", infos[0].Path)
	assert.Equal(t, int64(5), infos[0].Size)
}

func TestInMemoryStorage_ListPrefix_EmptyStorage_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	infos, err := NewInMemoryStorage().ListPrefix(ctx, "anything")
	require.NoError(t, err)
	assert.Nil(t, infos)
}

// New tests below

func TestInMemoryStorage_DeleteDir(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	// Files under dir/ and elsewhere
	assert.NoError(t, s.Put(ctx, "dir/file1.txt", strings.NewReader("data1")))
	assert.NoError(t, s.Put(ctx, "dir/sub/file2.txt", strings.NewReader("data2")))
	assert.NoError(t, s.Put(ctx, "other/file3.txt", strings.NewReader("data3")))

	// Delete directory by prefix without trailing slash
	err := s.DeleteDir(ctx, "dir")
	assert.NoError(t, err)

	// All under "dir/" should be gone
	_, err = s.Get(ctx, "dir/file1.txt")
	assert.Error(t, err)
	_, err = s.Get(ctx, "dir/sub/file2.txt")
	assert.Error(t, err)

	// Other paths untouched
	_, err = s.Get(ctx, "other/file3.txt")
	assert.NoError(t, err)

	// Also make sure calling with trailing slash behaves the same
	assert.NoError(t, s.Put(ctx, "dir2/file4.txt", strings.NewReader("data4")))
	assert.NoError(t, s.Put(ctx, "dir2/sub/file5.txt", strings.NewReader("data5")))

	err = s.DeleteDir(ctx, "dir2/")
	assert.NoError(t, err)

	_, err = s.Get(ctx, "dir2/file4.txt")
	assert.Error(t, err)
	_, err = s.Get(ctx, "dir2/sub/file5.txt")
	assert.Error(t, err)
}

func TestInMemoryStorage_GetNonExisting(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	_, err := s.Get(ctx, "nope.txt")
	assert.Error(t, err)
}

func TestInMemoryStorage_DeleteNonExisting(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	err := s.Delete(ctx, "nope.txt")
	assert.Error(t, err)
}

func TestInMemoryStorage_RootPrefixOperations(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStorage()

	require.NoError(t, s.Put(ctx, "dir1/file1.txt", strings.NewReader("1")))
	require.NoError(t, s.Put(ctx, "dir2/file2.txt", strings.NewReader("2")))
	require.NoError(t, s.Put(ctx, "loose.txt", strings.NewReader("3")))

	//nolint:prealloc
	fileInfoToStrList := func(fi []FileInfo) []string {
		r := []string{}
		for i := range fi {
			r = append(r, fi[i].Path)
		}
		return r
	}

	files, err := s.List(ctx, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"dir1/file1.txt",
		"dir2/file2.txt",
		"loose.txt",
	}, fileInfoToStrList(files))

	infos, err := s.List(ctx, "")
	require.NoError(t, err)
	assert.Len(t, infos, 3)

	dirs, err := s.ListTopLevelDirs(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{
		"dir1": true,
		"dir2": true,
	}, dirs)
}
