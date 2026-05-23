//go:build integration_localdev

package localdev

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pgrwl/pgrwl/internal/opt/supervisors/backupsv"

	"github.com/stretchr/testify/require"

	"github.com/pgrwl/pgrwl/config"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
)

// TestIntegrationRetentionLocaldev exercises the real recovery-window
// retention path against a local SeaweedFS S3 gateway, used through the real
// S3 storage backend.
//
// It intentionally writes objects using the real pgrwl layout:
//
//	<run-id>/backups/<backup-id>/<backup-id>.json
//	<run-id>/backups/<backup-id>/base.tar
//	<run-id>/backups/<backup-id>/25222.tar
//	<run-id>/wal-archive/<wal-file>
func TestIntegrationRetentionLocaldev(t *testing.T) {
	env := loadRetentionIntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	walSegSz := uint64(16 * 1024 * 1024)

	s3Client := newIntegrationS3Client(t, ctx, env)
	ensureIntegrationBucket(t, ctx, s3Client, env.bucket)

	runPrefix := fmt.Sprintf("pgrwl-retention-it/%d", time.Now().UTC().UnixNano())
	backupStorage := st.NewS3Storage(s3Client, env.bucket, runPrefix+"/backups")
	walRawStorage := st.NewS3Storage(s3Client, env.bucket, runPrefix+"/wal-archive")
	walStorage, err := st.NewVariadicStorage(walRawStorage, st.Algorithms{}, "")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		// Delete through both scoped storages first, then delete the whole run prefix
		// as a best-effort safety net.
		_ = backupStorage.DeleteDir(cleanupCtx, "")
		_ = walRawStorage.DeleteDir(cleanupCtx, "")
		_ = st.NewS3Storage(s3Client, env.bucket, runPrefix).DeleteDir(cleanupCtx, "")
	})

	now := time.Now().UTC()

	// With a 1h recovery window, the newest backup before windowStart is the
	// anchor. Here that should be 20260502070500. The older 20260502065500
	// backup should be removed, while anchor/newer backups remain.
	putIntegrationBackupManifest(t, ctx, backupStorage, "20260502065500", now.Add(-4*time.Hour), 1, "3C/D7000000")
	putIntegrationBackupManifest(t, ctx, backupStorage, "20260502070500", now.Add(-2*time.Hour), 1, "3C/D9000000")
	putIntegrationBackupManifest(t, ctx, backupStorage, "20260502071500", now.Add(-30*time.Minute), 1, "3C/DA000000")

	// Broken manifests should be skipped and, importantly, not deleted by this
	// retention run because they are not considered successful backups.
	putIntegrationObject(t, ctx, backupStorage, "20260502070000/20260502070000.json", "{broken-json")
	putIntegrationObject(t, ctx, backupStorage, "20260502070000/base.tar", "broken backup payload")

	putIntegrationObject(t, ctx, walRawStorage, "000000010000003C000000D7", "wal")
	putIntegrationObject(t, ctx, walRawStorage, "000000010000003C000000D8", "wal")
	putIntegrationObject(t, ctx, walRawStorage, "000000010000003C000000D9", "wal")
	putIntegrationObject(t, ctx, walRawStorage, "000000010000003C000000DA", "wal")
	putIntegrationObject(t, ctx, walRawStorage, "000000010000003C000000DB", "wal")
	putIntegrationObject(t, ctx, walRawStorage, "000000010000003C000000DC.partial", "partial")
	putIntegrationObject(t, ctx, walRawStorage, "00000002.history", "history")
	putIntegrationObject(t, ctx, walRawStorage, "README.txt", "not a wal")

	keepLast := 1
	cfg := &config.Config{
		Retention: config.RetentionConfig{
			Enable:             true,
			Type:               config.RetentionTypeRecoveryWindow,
			KeepDurationParsed: time.Hour,
			KeepLast:           &keepLast,
		},
	}

	retention, err := backupsv.NewRetentionService(
		&backupsv.BackupSupervisorOpts{
			WalSegSz:       walSegSz,
			BasebackupStor: backupStorage,
			WalStor:        walStorage,
			Cfg:            cfg,
		},
	)
	require.NoError(t, err)

	err = retention.RunBeforeBackup(ctx)
	require.NoError(t, err)

	assertIntegrationMissing(t, ctx, backupStorage, "20260502065500/20260502065500.json")
	assertIntegrationMissing(t, ctx, backupStorage, "20260502065500/base.tar")
	assertIntegrationMissing(t, ctx, backupStorage, "20260502065500/25222.tar")

	assertIntegrationExists(t, ctx, backupStorage, "20260502070500/20260502070500.json")
	assertIntegrationExists(t, ctx, backupStorage, "20260502071500/20260502071500.json")

	// Broken/unreadable backup manifest is skipped, not deleted.
	assertIntegrationExists(t, ctx, backupStorage, "20260502070000/20260502070000.json")
	assertIntegrationExists(t, ctx, backupStorage, "20260502070000/base.tar")

	assertIntegrationMissing(t, ctx, walRawStorage, "000000010000003C000000D7")
	assertIntegrationMissing(t, ctx, walRawStorage, "000000010000003C000000D8")
	assertIntegrationExists(t, ctx, walRawStorage, "000000010000003C000000D9")
	assertIntegrationExists(t, ctx, walRawStorage, "000000010000003C000000DA")
	assertIntegrationExists(t, ctx, walRawStorage, "000000010000003C000000DB")
	assertIntegrationExists(t, ctx, walRawStorage, "000000010000003C000000DC.partial")
	assertIntegrationExists(t, ctx, walRawStorage, "00000002.history")
	assertIntegrationExists(t, ctx, walRawStorage, "README.txt")
}
