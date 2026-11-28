//go:build linux

package xlog

import (
	"bytes"
	"os"
	"syscall"
	"testing"

	"github.com/jackc/pglogrepl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A new WAL segment must be really zero-filled (blocks allocated), not a sparse
// file, same as pg_receivewal does (pg_pwrite_zeros).
func TestOpenWalFile_SegmentIsNotSparse(t *testing.T) {
	stream := setupTestStreamCtl(t)
	require.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
	pathname := stream.walfile.pathname
	defer func() { _ = stream.CloseWalFile() }()

	fi, err := os.Stat(pathname)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	// st_blocks is in 512-byte units
	allocated := st.Blocks * 512
	//nolint:gosec
	assert.GreaterOrEqual(t, allocated, int64(stream.walSegSz), "segment must not be sparse")

	data, err := os.ReadFile(pathname)
	require.NoError(t, err)
	//nolint:gosec
	assert.Equal(t, int(stream.walSegSz), len(data))
	assert.True(t, bytes.Equal(data, make([]byte, len(data))), "segment must be all zeros")
}
