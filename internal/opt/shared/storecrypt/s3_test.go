package storecrypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestS3UnknownSizeStreamDefaultCapacitySupportsOneTiB(t *testing.T) {
	const oneTiB = int64(1 << 40)

	maxUploadSize := MultipartDefaultPartSizeBytes * int64(10_000)

	require.GreaterOrEqual(t, maxUploadSize, oneTiB)

	partsNeeded := (oneTiB + MultipartDefaultPartSizeBytes - 1) / MultipartDefaultPartSizeBytes
	require.LessOrEqual(t, partsNeeded, int64(10_000))
	require.Equal(t, int64(4096), partsNeeded)
}
