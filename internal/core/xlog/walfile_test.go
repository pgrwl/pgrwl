package xlog

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pglogrepl"
	"github.com/stretchr/testify/assert"
)

func setupTestStreamCtl(t *testing.T) *StreamCtl {
	t.Helper()

	tmpDir := t.TempDir()
	return &StreamCtl{
		receiveDir:    tmpDir,
		timeline:      1,
		walSegSz:      16 * 1024 * 1024, // 16 MiB
		partialSuffix: ".partial",
	}
}

func TestOpenWalFile_CreateAndPad(t *testing.T) {
	stream := setupTestStreamCtl(t)
	lsn := pglogrepl.LSN(0x0)

	err := stream.OpenWalFile(lsn)
	defer func(stream *StreamCtl) {
		err := stream.CloseWalFile()
		if err != nil {
			t.Log("error closing walfile ", t.Name())
		}
	}(stream)
	assert.NoError(t, err)
	assert.NotNil(t, stream.walfile)
	assert.FileExists(t, stream.walfile.pathname)

	stat, err := os.Stat(stream.walfile.pathname)
	assert.NoError(t, err)
	//nolint:gosec
	assert.Equal(t, int64(stream.walSegSz), stat.Size())
}

func TestWriteAtWalFile(t *testing.T) {
	stream := setupTestStreamCtl(t)
	assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
	defer func(stream *StreamCtl) {
		err := stream.CloseWalFile()
		if err != nil {
			t.Log("error closing walfile ", t.Name())
		}
	}(stream)

	n, err := stream.WriteAtWalFile([]byte("hello wal"), 0)
	assert.NoError(t, err)
	assert.Equal(t, len("hello wal"), n)
}

func TestWriteAtWalFile_LoopAndVerify(t *testing.T) {
	stream := setupTestStreamCtl(t)
	err := stream.OpenWalFile(pglogrepl.LSN(0))
	defer func(stream *StreamCtl) {
		err := stream.CloseWalFile()
		if err != nil {
			t.Log("error closing walfile ", t.Name())
		}
	}(stream)
	assert.NoError(t, err)
	assert.NotNil(t, stream.walfile)

	chunks := [][]byte{
		[]byte("AAAA"),
		[]byte("BBBBBB"),
		[]byte("CCCCCCCC"),
	}

	var offset uint64
	var expectedData []byte

	for _, chunk := range chunks {
		n, err := stream.WriteAtWalFile(chunk, offset)
		assert.NoError(t, err)
		assert.Equal(t, len(chunk), n)
		//nolint:gosec
		offset += uint64(n)
		expectedData = append(expectedData, chunk...)
	}

	assert.Equal(t, offset, stream.walfile.currpos)

	// Read back the file content to verify
	fileBytes := make([]byte, offset)
	_, err = stream.walfile.fd.ReadAt(fileBytes, 0)
	assert.NoError(t, err)

	assert.Equal(t, expectedData, fileBytes)
}

func TestWriteAtWalFile_OffsetConversionFails(t *testing.T) {
	// Simulate invalid offset by using a value that overflows int64
	invalidOffset := uint64(math.MaxInt64) + 1 // causes conversion to fail

	stream := setupTestStreamCtl(t)
	assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
	defer func(stream *StreamCtl) {
		err := stream.CloseWalFile()
		if err != nil {
			t.Log("error closing walfile ", t.Name())
		}
	}(stream)

	n, err := stream.WriteAtWalFile([]byte("invalid"), invalidOffset)
	assert.Error(t, err)
	assert.Equal(t, -1, n)
}

func TestWriteAtWalFile_FileIsNil(t *testing.T) {
	stream := setupTestStreamCtl(t)
	assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
	assert.NoError(t, stream.CloseWalFile())

	n, err := stream.WriteAtWalFile([]byte("test"), 0)
	assert.Error(t, err)
	assert.Equal(t, -1, n)
}

func TestWriteAtWalFile_StreamWalfileNil(t *testing.T) {
	stream := setupTestStreamCtl(t)
	stream.walfile = nil

	n, err := stream.WriteAtWalFile([]byte("test"), 0)
	assert.Error(t, err)
	assert.Equal(t, -1, n)
}

func TestWriteAtWalFile_AppendIncreasesCurrpos(t *testing.T) {
	stream := setupTestStreamCtl(t)
	assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
	defer func(stream *StreamCtl) {
		err := stream.CloseWalFile()
		if err != nil {
			t.Log("error closing walfile ", t.Name())
		}
	}(stream)

	data := []byte("12345")
	_, err := stream.WriteAtWalFile(data, 0)
	assert.NoError(t, err)

	assert.Equal(t, uint64(len(data)), stream.walfile.currpos)
}

func TestWriteAtWalFile_WriteFails(t *testing.T) {
	// Simulate file that fails WriteAt using a closed file
	stream := setupTestStreamCtl(t)
	assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))

	_ = stream.walfile.fd.Close() // force it to be invalid

	n, err := stream.WriteAtWalFile([]byte("fail"), 0)
	assert.Error(t, err)
	assert.Equal(t, -1, n)
}

func TestSyncWalFile(t *testing.T) {
	stream := setupTestStreamCtl(t)
	assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
	defer func(stream *StreamCtl) {
		err := stream.CloseWalFile()
		if err != nil {
			t.Log("error closing walfile ", t.Name())
		}
	}(stream)

	err := stream.SyncWalFile()
	assert.NoError(t, err)
}

func TestCloseWalfile_WithIncompleteSegment(t *testing.T) {
	stream := setupTestStreamCtl(t)
	assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
	_, err := stream.WriteAtWalFile([]byte("partial data"), 0)
	assert.NoError(t, err)

	pathname := stream.walfile.pathname
	err = stream.CloseWalFile()
	assert.NoError(t, err)

	// Should not rename due to incomplete segment
	finalName := strings.TrimSuffix(pathname, stream.partialSuffix)
	_, err = os.Stat(finalName)
	assert.True(t, os.IsNotExist(err))
}

func TestCloseWalfile_WithCompleteSegment(t *testing.T) {
	stream := setupTestStreamCtl(t)
	assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))

	// Write exactly segment size
	data := make([]byte, stream.walSegSz)
	_, err := stream.WriteAtWalFile(data, 0)
	assert.NoError(t, err)

	pathname := stream.walfile.pathname
	err = stream.CloseWalFile()
	assert.NoError(t, err)

	// File should be renamed to final path
	expectedFinal := filepath.Join(stream.receiveDir, strings.TrimSuffix(filepath.Base(pathname), stream.partialSuffix))
	_, err = os.Stat(expectedFinal)
	assert.NoError(t, err)
}

func TestCloseWalfile_NoWalfile(t *testing.T) {
	stream := setupTestStreamCtl(t)
	stream.walfile = nil

	err := stream.CloseWalFile()
	assert.NoError(t, err)
}

func TestWriteAtWalFile_Errors(t *testing.T) {
	stream := &StreamCtl{}
	n, err := stream.WriteAtWalFile([]byte("data"), 0)
	assert.Error(t, err)
	assert.Equal(t, -1, n)
}

func TestSyncWalFile_Errors(t *testing.T) {
	stream := &StreamCtl{}
	err := stream.SyncWalFile()
	assert.Error(t, err)
}

// The in-use segment path is what the archive uploader skips; it must be set
// while the receiver owns the segment and cleared once the segment is released.
func TestOpenWalPath_Lifecycle(t *testing.T) {
	t.Run("incomplete segment", func(t *testing.T) {
		stream := setupTestStreamCtl(t)
		assert.Equal(t, "", stream.OpenWalPath())

		assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
		assert.Equal(t, stream.walfile.pathname, stream.OpenWalPath())
		assert.True(t, strings.HasSuffix(stream.OpenWalPath(), stream.partialSuffix))

		assert.NoError(t, stream.CloseWalFile()) // no rename: segment is not complete
		assert.Equal(t, "", stream.OpenWalPath())
	})

	t.Run("complete segment", func(t *testing.T) {
		stream := setupTestStreamCtl(t)
		assert.NoError(t, stream.OpenWalFile(pglogrepl.LSN(0)))
		_, err := stream.WriteAtWalFile(make([]byte, stream.walSegSz), 0)
		assert.NoError(t, err)

		assert.NoError(t, stream.CloseWalFile()) // renamed to the final name
		assert.Equal(t, "", stream.OpenWalPath())
	})
}
