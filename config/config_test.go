package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpandEnvsWithPrefix(t *testing.T) {
	// Set test environment variables
	t.Setenv("PGRWL_FOO", "foo-val")
	t.Setenv("PGRWL_BAR", "bar-val")
	t.Setenv("PGRWL_EMPTY", "")
	t.Setenv("OTHER_BAZ", "should-not-expand")

	tests := []struct {
		name     string
		input    string
		prefix   string
		expected string
	}{
		{
			name:     "expand single matching var",
			input:    "value=${PGRWL_FOO}",
			prefix:   "PGRWL_",
			expected: "value=foo-val",
		},
		{
			name:     "expand multiple matching vars",
			input:    "one=${PGRWL_FOO}, two=${PGRWL_BAR}",
			prefix:   "PGRWL_",
			expected: "one=foo-val, two=bar-val",
		},
		{
			name:     "ignore unmatched var (wrong prefix)",
			input:    "value=${OTHER_BAZ}",
			prefix:   "PGRWL_",
			expected: "value=${OTHER_BAZ}",
		},
		{
			name:     "mixed matched and unmatched vars",
			input:    "a=${PGRWL_FOO}, b=${OTHER_BAZ}",
			prefix:   "PGRWL_",
			expected: "a=foo-val, b=${OTHER_BAZ}",
		},
		{
			name:     "undefined env var with correct prefix",
			input:    "value=${PGRWL_UNKNOWN}",
			prefix:   "PGRWL_",
			expected: "value=",
		},
		{
			name:     "defined empty env var with correct prefix",
			input:    "value=${PGRWL_EMPTY}",
			prefix:   "PGRWL_",
			expected: "value=",
		},
		{
			name:     "empty input string",
			input:    "",
			prefix:   "PGRWL_",
			expected: "",
		},
		{
			name:     "no variable placeholders",
			input:    "static string",
			prefix:   "PGRWL_",
			expected: "static string",
		},
		{
			name:     "empty prefix allows all expansions",
			input:    "x=${PGRWL_FOO}, y=${OTHER_BAZ}",
			prefix:   "",
			expected: "x=foo-val, y=should-not-expand",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := expandEnvsWithPrefix(tt.input, tt.prefix)
			assert.Equal(t, tt.expected, out)
		})
	}
}

func TestMustLoadCfgExpandsPGRWLEnvsAndLeavesOtherPlaceholders(t *testing.T) {
	t.Setenv("PGRWL_MAIN_DIRECTORY", "/var/lib/pgrwl")
	t.Setenv("PGRWL_STORAGE_S3_URL", "https://s3.example.com")
	t.Setenv("PGRWL_STORAGE_S3_ACCESS_KEY_ID", "access-key")
	t.Setenv("PGRWL_STORAGE_S3_SECRET_ACCESS_KEY", "secret-key")
	t.Setenv("PGRWL_STORAGE_S3_BUCKET", "wal-bucket")

	path := writeConfigForTest(t, `main:
  listen_port: 9090
  directory: ${PGRWL_MAIN_DIRECTORY}
receiver:
  slot: receive_slot
  uploader:
    sync_interval: 10s
    max_concurrency: 2
backup:
  cron: "* * * * *"
storage:
  name: s3
  s3:
    url: ${PGRWL_STORAGE_S3_URL}
    access_key_id: ${PGRWL_STORAGE_S3_ACCESS_KEY_ID}
    secret_access_key: ${PGRWL_STORAGE_S3_SECRET_ACCESS_KEY}
    bucket: ${PGRWL_STORAGE_S3_BUCKET}
    region: ${OTHER_REGION}
`)

	cfg, err := mustLoadCfg(path)
	assert.NoError(t, err)
	assert.Equal(t, "/var/lib/pgrwl", cfg.Main.Directory)
	assert.Equal(t, "https://s3.example.com", cfg.Storage.S3.URL)
	assert.Equal(t, "access-key", cfg.Storage.S3.AccessKeyID)
	assert.Equal(t, "secret-key", cfg.Storage.S3.SecretAccessKey)
	assert.Equal(t, "wal-bucket", cfg.Storage.S3.Bucket)
	assert.Equal(t, "${OTHER_REGION}", cfg.Storage.S3.Region)
}

func TestFromFileValidatesExpandedEnvPlaceholders(t *testing.T) {
	resetConfigForTest(t)

	t.Setenv("PGRWL_MAIN_DIRECTORY", "/tmp/pgrwl")
	t.Setenv("PGRWL_STORAGE_S3_URL", "https://s3.example.com")
	t.Setenv("PGRWL_STORAGE_S3_ACCESS_KEY_ID", "access-key")
	t.Setenv("PGRWL_STORAGE_S3_SECRET_ACCESS_KEY", "secret-key")
	t.Setenv("PGRWL_STORAGE_S3_BUCKET", "wal-bucket")
	t.Setenv("PGRWL_STORAGE_S3_REGION", "us-east-1")

	path := writeConfigForTest(t, `main:
  listen_port: 9090
  directory: ${PGRWL_MAIN_DIRECTORY}
receiver:
  slot: receive_slot
  uploader:
    sync_interval: 10s
    max_concurrency: 2
log:
  level: trace
  format: json
backup:
  cron: "* * * * *"
storage:
  name: s3
  s3:
    url: ${PGRWL_STORAGE_S3_URL}
    access_key_id: ${PGRWL_STORAGE_S3_ACCESS_KEY_ID}
    secret_access_key: ${PGRWL_STORAGE_S3_SECRET_ACCESS_KEY}
    bucket: ${PGRWL_STORAGE_S3_BUCKET}
    region: ${PGRWL_STORAGE_S3_REGION}
`)

	cfg, err := FromFile(path)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/pgrwl", cfg.Main.Directory)
	assert.Equal(t, 10*time.Second, cfg.Receiver.Uploader.SyncIntervalParsed)
	assert.Equal(t, "secret-key", cfg.Storage.S3.SecretAccessKey)
	assert.True(t, Verbose)
}

func TestFromEnvsAppliesOverridesAndParsesValues(t *testing.T) {
	resetConfigForTest(t)
	setValidReceiveEnvForTest(t)

	cfg, err := FromEnvs()
	assert.NoError(t, err)
	assert.Equal(t, 9090, cfg.Main.ListenPort)
	assert.Equal(t, "/env/pgrwl", cfg.Main.Directory)
	assert.Equal(t, "env_slot", cfg.Receiver.Slot)
	assert.Equal(t, "15s", cfg.Receiver.Uploader.SyncInterval)
	assert.Equal(t, 15*time.Second, cfg.Receiver.Uploader.SyncIntervalParsed)
	assert.Equal(t, 3, cfg.Receiver.Uploader.MaxConcurrency)
	assert.True(t, cfg.Metrics.Enable)
	assert.Equal(t, "https://env-s3.example.com", cfg.Storage.S3.URL)
	assert.Equal(t, "env-secret", cfg.Storage.S3.SecretAccessKey)
	assert.True(t, Verbose)
}

func TestFromEnvsInvalidValuesReturnErrors(t *testing.T) {
	resetConfigForTest(t)
	setValidReceiveEnvForTest(t)
	t.Setenv("PGRWL_RECEIVER_UPLOADER_SYNC_INTERVAL", "not-a-duration")

	cfg, err := FromEnvs()
	assert.Nil(t, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "receiver.uploader.sync_interval cannot parse")
}

func TestValidate_Config(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *Config
		expectError bool
		wantMsgs    []string // optional substring checks
	}{
		{
			name: "valid receive config with s3",
			cfg: &Config{
				Main: MainConfig{
					ListenPort: 8080,
					Directory:  "/var/lib/pgwal",
				},
				Receiver: ReceiveConfig{
					Slot: "slot1",
					Uploader: UploadConfig{
						SyncInterval:   "10s",
						MaxConcurrency: 2,
					},
				},
				Backup: BackupConfig{Cron: "* * * * *"},
				Storage: StorageConfig{
					Name: StorageNameS3,
					S3: S3Config{
						URL:             "https://s3.amazonaws.com",
						AccessKeyID:     "AKIA...",
						SecretAccessKey: "secret",
						Bucket:          "bucket",
						Region:          "us-east-1",
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid mode and missing main",
			cfg: &Config{
				Main: MainConfig{},
			},
			expectError: true,
			wantMsgs: []string{
				"main.listen_port is required",
				"main.directory is required",
			},
		},
		{
			name: "invalid uploader and retention durations",
			cfg: &Config{
				Main: MainConfig{
					ListenPort: 1,
					Directory:  "/pgwal",
				},
				Receiver: ReceiveConfig{
					Slot: "slot",
					Uploader: UploadConfig{
						SyncInterval:   "bad",
						MaxConcurrency: 0,
					},
				},
				Storage: StorageConfig{
					Name: StorageNameS3,
					S3: S3Config{
						URL:             "x",
						AccessKeyID:     "x",
						SecretAccessKey: "x",
						Bucket:          "x",
						Region:          "x",
					},
				},
			},
			expectError: true,
			wantMsgs: []string{
				"uploader.sync_interval cannot parse",
				"uploader.max_concurrency must be > 0",
			},
		},
		{
			name: "invalid sftp config missing pass or key",
			cfg: &Config{
				Main: MainConfig{
					ListenPort: 1234,
					Directory:  "/data",
				},
				Receiver: ReceiveConfig{
					Slot: "slot",
					Uploader: UploadConfig{
						SyncInterval:   "10s",
						MaxConcurrency: 1,
					},
				},
				Storage: StorageConfig{
					Name: StorageNameSFTP,
					SFTP: SFTPConfig{
						Host: "host",
						Port: 22,
						User: "user",
						// Missing Pass and PKeyPath
					},
				},
			},
			expectError: true,
			wantMsgs: []string{
				"either storage.sftp.pass or storage.sftp.pkey_path must be provided",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(tt.cfg)
			if tt.expectError {
				assert.Error(t, err)
				for _, want := range tt.wantMsgs {
					assert.Contains(t, err.Error(), want)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, 10*time.Second, tt.cfg.Receiver.Uploader.SyncIntervalParsed)
			}
		})
	}
}

func TestValidate_SuccessMinimalReceiveConfig(t *testing.T) {
	cfg := &Config{
		Main: MainConfig{
			ListenPort: 8080,
			Directory:  "/var/lib/pgwal",
		},
		Receiver: ReceiveConfig{
			Slot: "replication_slot",
			Uploader: UploadConfig{
				SyncInterval:   "10s",
				MaxConcurrency: 1,
			},
		},
		Storage: StorageConfig{
			Name: "s3",
		},
	}

	err := validate(cfg)
	assert.Error(t, err)
	assert.Equal(t, 10*time.Second, cfg.Receiver.Uploader.SyncIntervalParsed)
}

func resetConfigForTest(t *testing.T) {
	t.Helper()
	once = sync.Once{}
	cfgErr = nil
	config = nil
	Verbose = false
}

func writeConfigForTest(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	err := os.WriteFile(path, []byte(contents), 0o600)
	assert.NoError(t, err)
	return path
}

func setValidReceiveEnvForTest(t *testing.T) {
	t.Helper()
	t.Setenv("PGRWL_MAIN_LISTEN_PORT", "9090")
	t.Setenv("PGRWL_MAIN_DIRECTORY", "/env/pgrwl")
	t.Setenv("PGRWL_RECEIVER_SLOT", "env_slot")
	t.Setenv("PGRWL_RECEIVER_UPLOADER_SYNC_INTERVAL", "15s")
	t.Setenv("PGRWL_RECEIVER_UPLOADER_MAX_CONCURRENCY", "3")
	t.Setenv("PGRWL_BACKUP_CRON", "* * * * *")
	t.Setenv("PGRWL_METRICS_ENABLE", "true")
	t.Setenv("PGRWL_LOG_LEVEL", "trace")
	t.Setenv("PGRWL_LOG_FORMAT", "json")
	t.Setenv("PGRWL_STORAGE_NAME", "s3")
	t.Setenv("PGRWL_STORAGE_S3_URL", "https://env-s3.example.com")
	t.Setenv("PGRWL_STORAGE_S3_ACCESS_KEY_ID", "env-access")
	t.Setenv("PGRWL_STORAGE_S3_SECRET_ACCESS_KEY", "env-secret")
	t.Setenv("PGRWL_STORAGE_S3_BUCKET", "env-bucket")
	t.Setenv("PGRWL_STORAGE_S3_REGION", "us-east-1")
}
