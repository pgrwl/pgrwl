package storecrypt

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Config struct {
	EndpointURL     string
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
	Region          string
	UsePathStyle    bool
	// DisableSSL skips TLS certificate verification. The connection still uses
	// HTTPS when the endpoint URL has the https:// scheme.
	DisableSSL bool
}

type S3Client struct {
	client *minio.Client
	bucket string
}

func NewS3Client(cfg *S3Config) (*S3Client, error) {
	secure := !strings.HasPrefix(cfg.EndpointURL, "http://")
	endpoint := strings.TrimPrefix(cfg.EndpointURL, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")

	lookup := minio.BucketLookupAuto
	if cfg.UsePathStyle {
		lookup = minio.BucketLookupPath
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure:       secure,
		Region:       cfg.Region,
		BucketLookup: lookup,
		Transport:    buildTransport(secure, cfg.DisableSSL),
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}

	return &S3Client{client: client, bucket: cfg.Bucket}, nil
}

func (c *S3Client) Client() *minio.Client { return c.client }
func (c *S3Client) Bucket() string        { return c.bucket }

func buildTransport(secure, insecureSkipVerify bool) http.RoundTripper {
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if secure {
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec
		}
	}
	return t
}
