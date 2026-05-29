package localdev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/minio/minio-go/v7"
	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backupdto"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type retentionIntegrationEnv struct {
	s3Endpoint       string
	s3AccessKey      string
	s3SecretKey      string
	bucket           string
	region           string
	usePathStyle     bool
	disableTLSVerify bool
}

func loadRetentionIntegrationEnv(t *testing.T) retentionIntegrationEnv {
	t.Helper()

	s3Endpoint := "http://127.0.0.1:8333"

	return retentionIntegrationEnv{
		s3Endpoint:       s3Endpoint,
		s3AccessKey:      "pgrwl",
		s3SecretKey:      "pgrwl-secret",
		bucket:           "backups",
		region:           "us-east-1",
		usePathStyle:     true,
		disableTLSVerify: true,
	}
}

func newIntegrationS3Client(t *testing.T, _ context.Context, env retentionIntegrationEnv) *minio.Client {
	t.Helper()

	client, err := st.NewS3Client(&st.S3Config{
		EndpointURL:     env.s3Endpoint,
		AccessKeyID:     env.s3AccessKey,
		SecretAccessKey: env.s3SecretKey,
		Bucket:          env.bucket,
		Region:          env.region,
		UsePathStyle:    env.usePathStyle,
		DisableSSL:      env.disableTLSVerify,
	})
	require.NoError(t, err)
	return client.Client()
}

func ensureIntegrationBucket(t *testing.T, ctx context.Context, client *minio.Client, bucket string) {
	t.Helper()

	err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err == nil {
		return
	}

	exists, errExists := client.BucketExists(ctx, bucket)
	if errExists == nil && exists {
		return
	}

	require.NoError(t, err)
}

func putIntegrationBackupManifest(
	t *testing.T,
	ctx context.Context,
	storage st.Storage,
	backupID string,
	startedAt time.Time,
	timeline int32,
	startLSN string,
) {
	t.Helper()

	lsn, err := pglogrepl.ParseLSN(startLSN)
	require.NoError(t, err)

	result := backupdto.Result{
		StartLSN:   lsn,
		TimelineID: timeline,
		StartedAt:  startedAt.UTC(),
		FinishedAt: startedAt.Add(5 * time.Minute).UTC(),
		Manifest: &backupdto.BackupManifest{
			Version: 1,
			WALRanges: []backupdto.ManifestWALRange{
				{
					Timeline: timeline,
					StartLSN: startLSN,
					EndLSN:   startLSN,
				},
			},
		},
	}

	data, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)

	putIntegrationObject(t, ctx, storage, backupID+"/"+backupID+".json", string(data))
	putIntegrationObject(t, ctx, storage, backupID+"/base.tar", "base payload")
	putIntegrationObject(t, ctx, storage, backupID+"/25222.tar", "tablespace payload")
}

func putIntegrationObject(t *testing.T, ctx context.Context, storage st.Storage, path string, body string) {
	t.Helper()

	require.NoError(t, storage.Put(ctx, path, strings.NewReader(body)))
}

func assertIntegrationExists(t *testing.T, ctx context.Context, storage st.Storage, path string) {
	t.Helper()

	exists, err := storage.Exists(ctx, path)
	require.NoError(t, err)
	assert.True(t, exists, "expected %s to exist", path)
}

func assertIntegrationMissing(t *testing.T, ctx context.Context, storage st.Storage, path string) {
	t.Helper()

	exists, err := storage.Exists(ctx, path)
	if err != nil && isIntegrationNotFoundErr(err) {
		exists = false
		err = nil
	}
	require.NoError(t, err)
	assert.False(t, exists, "expected %s to be deleted", path)
}

func assertIntegrationBytes(t *testing.T, ctx context.Context, storage st.Storage, path string, want []byte) {
	t.Helper()

	rc, err := storage.Get(ctx, path)
	require.NoError(t, err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, want, data, "content mismatch for %s", path)
}

func writeIntegrationConfig(t *testing.T, env retentionIntegrationEnv, mainDir string) string {
	t.Helper()

	path := t.TempDir() + "/pgrwl-config.json"
	data := fmt.Sprintf(`{
  "main": {
    "listen_port": 8080,
    "directory": %q
  },
  "receiver": {
    "slot": "pgrwl_integration",
    "uploader": {
      "sync_interval": "10s",
      "max_concurrency": 2
    }
  },
  "backup": {
    "cron": "* * * * *"
  },
  "storage": {
    "name": "s3",
    "s3": {
      "url": %q,
      "access_key_id": %q,
      "secret_access_key": %q,
      "bucket": %q,
      "region": %q,
      "use_path_style": %t,
      "disable_ssl": %t
    }
  }
}`, mainDir, env.s3Endpoint, env.s3AccessKey, env.s3SecretKey, env.bucket, env.region, env.usePathStyle, env.disableTLSVerify)

	require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
	return path
}

func isIntegrationNotFoundErr(err error) bool {
	if err == nil {
		return false
	}

	var responseErr interface{ HTTPStatusCode() int }
	if errors.As(err, &responseErr) && responseErr.HTTPStatusCode() == http.StatusNotFound {
		return true
	}

	return strings.Contains(strings.ToLower(err.Error()), "notfound") || strings.Contains(strings.ToLower(err.Error()), "not found")
}

func deleteAllBulk(ctx context.Context, s st.Storage, paths []string) error {
	for _, p := range paths {
		if err := s.Delete(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func fileInfoToStrList(fi []st.FileInfo) []string {
	r := []string{}
	for i := range fi {
		r = append(r, fi[i].Path)
	}
	return r
}
