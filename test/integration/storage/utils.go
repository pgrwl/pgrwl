package integration

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/pkg/sftp"

	clients "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"

	"github.com/stretchr/testify/require"
)

func createS3Client() *minio.Client {
	client, err := clients.NewS3Client(&clients.S3Config{
		EndpointURL:     "https://localhost:9000",
		AccessKeyID:     "minioadmin",
		SecretAccessKey: "minioadmin123",
		Bucket:          "backups",
		Region:          "main",
		UsePathStyle:    true,
		DisableSSL:      true,
	})
	if err != nil {
		log.Fatal(err)
	}
	return client.Client()
}

func createSftpClient() *sftp.Client {
	pkeyPath := "./environ/files/dotfiles/.ssh/id_ed25519"
	err := os.Chmod(pkeyPath, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	client, err := clients.NewSFTPClient(&clients.SFTPConfig{
		Host:     "localhost",
		Port:     "2323",
		User:     "testuser",
		PkeyPath: pkeyPath,
	})
	if err != nil {
		log.Fatal(err)
	}
	return client.SFTPClient()
}

func readAllAndClose(t *testing.T, r io.ReadCloser) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return data
}

func genPaths(nested int) string {
	sb := strings.Builder{}
	for i := 0; i < nested; i++ {
		n := rnd(1024, 8192)
		sb.WriteString(fmt.Sprintf("%d/", n))
	}
	return strings.TrimPrefix(sb.String(), "/")
}

func rnd(min, max int) int {
	return rand.Intn(max-min+1) + min
}

func deleteAll(ctx context.Context, s clients.Storage, remotePath string) error {
	files, err := s.List(ctx, remotePath)
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := s.Delete(ctx, f.Path); err != nil {
			return err
		}
	}
	return nil
}

func deleteAllBulk(ctx context.Context, s clients.Storage, paths []string) error {
	for _, p := range paths {
		if err := s.Delete(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func fileInfoToStrList(fi []clients.FileInfo) []string {
	r := []string{}
	for i := range fi {
		r = append(r, fi[i].Path)
	}
	return r
}
