package storecrypt

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLocalStorage creates a localStorage rooted at a temp directory.
func newLocalStorage(t *testing.T) *localStorage {
	t.Helper()
	dir := t.TempDir()
	st, err := NewLocal(&LocalStorageOpts{BaseDir: dir})
	require.NoError(t, err)
	//nolint:errcheck
	return st.(*localStorage)
}

// writeFile creates a file at baseDir/rel with the given content.
func writeFile(t *testing.T, l *localStorage, rel, content string) {
	t.Helper()
	full := filepath.Join(l.baseDir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
}

// -----------------------------------------------------------------------------
// ListPrefix
// -----------------------------------------------------------------------------

func TestLocalStorage_ListPrefix_BasicMatch(t *testing.T) {
	ctx := context.Background()
	l := newLocalStorage(t)

	writeFile(t, l, "seg--aaa", "hello")
	writeFile(t, l, "seg--bbb", "world!")
	writeFile(t, l, "other--ccc", "nope")

	infos, err := l.ListPrefix(ctx, "seg--")
	require.NoError(t, err)

	paths := make(map[string]int64)
	for _, fi := range infos {
		paths[fi.Path] = fi.Size
	}

	assert.Len(t, paths, 2)
	assert.Equal(t, int64(5), paths["seg--aaa"])
	assert.Equal(t, int64(6), paths["seg--bbb"])
}

func TestLocalStorage_ListPrefix_NoMatch_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	l := newLocalStorage(t)

	writeFile(t, l, "seg--aaa", "x")

	infos, err := l.ListPrefix(ctx, "xyz--")
	require.NoError(t, err)
	assert.Nil(t, infos)
}

func TestLocalStorage_ListPrefix_NonExistentDir_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	l := newLocalStorage(t)

	// Prefix whose parent directory does not exist at all.
	infos, err := l.ListPrefix(ctx, "ghost/seg--")
	require.NoError(t, err)
	assert.Nil(t, infos)
}

func TestLocalStorage_ListPrefix_SkipsSubdirectories(t *testing.T) {
	ctx := context.Background()
	l := newLocalStorage(t)

	writeFile(t, l, "seg--file", "data")
	// A directory whose name starts with the same prefix must be skipped.
	require.NoError(t, os.MkdirAll(filepath.Join(l.baseDir, "seg--dir"), 0o750))

	infos, err := l.ListPrefix(ctx, "seg--")
	require.NoError(t, err)

	require.Len(t, infos, 1)
	assert.Equal(t, "seg--file", infos[0].Path)
}

func TestLocalStorage_ListPrefix_NonRecursive(t *testing.T) {
	// Only files in the immediate parent directory are returned; files inside
	// subdirectories that match the name prefix are ignored.
	ctx := context.Background()
	l := newLocalStorage(t)

	writeFile(t, l, "seg--top", "top")
	writeFile(t, l, "subdir/seg--nested", "nested")

	infos, err := l.ListPrefix(ctx, "seg--")
	require.NoError(t, err)

	require.Len(t, infos, 1)
	assert.Equal(t, "seg--top", infos[0].Path)
}

func TestLocalStorage_ListPrefix_InSubdir(t *testing.T) {
	ctx := context.Background()
	l := newLocalStorage(t)

	writeFile(t, l, "wal/000000010000000000000001--abc", "a")
	writeFile(t, l, "wal/000000010000000000000001--def", "bb")
	writeFile(t, l, "wal/000000010000000000000002--xyz", "ccc")

	infos, err := l.ListPrefix(ctx, "wal/000000010000000000000001--")
	require.NoError(t, err)

	paths := make(map[string]bool)
	for _, fi := range infos {
		paths[fi.Path] = true
	}

	require.Len(t, paths, 2)
	assert.True(t, paths["wal/000000010000000000000001--abc"])
	assert.True(t, paths["wal/000000010000000000000001--def"])
}

func TestLocalStorage_ListPrefix_PathsRelativeToBaseDir(t *testing.T) {
	ctx := context.Background()
	l := newLocalStorage(t)

	writeFile(t, l, "dir/seg--hash", "content")

	infos, err := l.ListPrefix(ctx, "dir/seg--")
	require.NoError(t, err)

	require.Len(t, infos, 1)
	// Path must be relative to baseDir, using forward slashes.
	assert.Equal(t, "dir/seg--hash", infos[0].Path)
}

func TestLocalStorage_ListPrefix_ReportsCorrectSize(t *testing.T) {
	ctx := context.Background()
	l := newLocalStorage(t)

	content := "exactly sixteen!"
	writeFile(t, l, "f--h", content)

	infos, err := l.ListPrefix(ctx, "f--")
	require.NoError(t, err)

	require.Len(t, infos, 1)
	assert.Equal(t, int64(len(content)), infos[0].Size)
}
