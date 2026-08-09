package objectstorage

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/outbound"
)

type Config struct {
	Endpoint             string `json:"endpoint"`
	Region               string `json:"region"`
	AccessKeyID          string `json:"access_key_id"`
	SecretAccessKey      string `json:"secret_access_key"`
	ForcePathStyle       bool   `json:"force_path_style"`
	PublicBucket         string `json:"public_bucket,omitempty"`
	PrivateBucket        string `json:"private_bucket,omitempty"`
	PublicBaseURL        string `json:"public_base_url,omitempty"`
	AllowPrivateEndpoint bool   `json:"allow_private_endpoint"`
}

type Head struct {
	ETag        string
	Size        int64
	ContentType string
}

type Client struct {
	config    Config
	s3        *s3.Client
	presigner *s3.PresignClient
	http      *http.Client
}

func New(ctx context.Context, value Config) (*Client, error) {
	if err := Validate(ctx, value); err != nil {
		return nil, err
	}
	httpClient := outbound.NewSafeHTTPClient(20 * time.Second)
	if value.AllowPrivateEndpoint {
		httpClient = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
			Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
		}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	loaded, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(value.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(value.AccessKeyID, value.SecretAccessKey, "")),
		awsconfig.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("load S3 configuration: %w", err)
	}
	client := s3.NewFromConfig(loaded, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(strings.TrimRight(value.Endpoint, "/"))
		options.UsePathStyle = value.ForcePathStyle
	})
	return &Client{config: value, s3: client, presigner: s3.NewPresignClient(client), http: httpClient}, nil
}

func Validate(ctx context.Context, value Config) error {
	value.Endpoint = strings.TrimSpace(value.Endpoint)
	value.Region = strings.TrimSpace(value.Region)
	if value.Endpoint == "" || value.Region == "" || strings.TrimSpace(value.AccessKeyID) == "" || strings.TrimSpace(value.SecretAccessKey) == "" {
		return fmt.Errorf("endpoint, region, access key, and secret key are required")
	}
	parsed, err := url.Parse(value.Endpoint)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if value.AllowPrivateEndpoint {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("private endpoints must use HTTP or HTTPS")
		}
	} else if err = outbound.ValidateHTTPS(ctx, value.Endpoint); err != nil {
		return fmt.Errorf("unsafe S3 endpoint: %w", err)
	}
	if value.PublicBucket == "" && value.PrivateBucket == "" {
		return fmt.Errorf("a public or private bucket is required")
	}
	if value.PublicBucket != "" && value.PublicBucket == value.PrivateBucket {
		return fmt.Errorf("public and private buckets must be different")
	}
	if value.PublicBaseURL != "" {
		if err = outbound.ValidateHTTPS(ctx, value.PublicBaseURL); err != nil {
			return fmt.Errorf("unsafe public base URL: %w", err)
		}
	}
	return nil
}

func (c *Client) PresignPut(ctx context.Context, bucket, key, contentType string, size int64, expires time.Duration) (string, http.Header, error) {
	result, err := c.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), ContentType: aws.String(contentType), ContentLength: aws.Int64(size),
	}, s3.WithPresignExpires(expires))
	if err != nil {
		return "", nil, fmt.Errorf("presign S3 upload: %w", err)
	}
	return result.URL, result.SignedHeader, nil
}

func (c *Client) PresignGet(ctx context.Context, bucket, key string, expires time.Duration) (string, error) {
	result, err := c.presigner.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}, s3.WithPresignExpires(expires))
	if err != nil {
		return "", fmt.Errorf("presign S3 download: %w", err)
	}
	return result.URL, nil
}

func (c *Client) Head(ctx context.Context, bucket, key string) (Head, error) {
	result, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return Head{}, fmt.Errorf("head S3 object: %w", err)
	}
	return Head{ETag: strings.Trim(aws.ToString(result.ETag), `"`), Size: aws.ToInt64(result.ContentLength), ContentType: aws.ToString(result.ContentType)}, nil
}

func (c *Client) ReadPrefix(ctx context.Context, bucket, key string, limit int64) ([]byte, error) {
	if limit < 1 || limit > 1<<20 {
		return nil, fmt.Errorf("invalid object prefix limit")
	}
	result, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), Range: aws.String(fmt.Sprintf("bytes=0-%d", limit-1)),
	})
	if err != nil {
		return nil, fmt.Errorf("read S3 object prefix: %w", err)
	}
	defer result.Body.Close()
	value, err := io.ReadAll(io.LimitReader(result.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("read S3 object prefix: %w", err)
	}
	return value, nil
}

func (c *Client) Delete(ctx context.Context, bucket, key string) error {
	_, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return fmt.Errorf("delete S3 object: %w", err)
	}
	return nil
}

func (c *Client) VerifyBucket(ctx context.Context, bucket string, public bool) error {
	key := ".platform93-verification/" + uuid.NewString()
	body := []byte("platform93-storage-verification")
	_, err := c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))), ContentType: aws.String("text/plain"),
	})
	if err != nil {
		return fmt.Errorf("write verification object: %w", err)
	}
	defer c.Delete(context.WithoutCancel(ctx), bucket, key) // best effort cleanup
	if _, err = c.Head(ctx, bucket, key); err != nil {
		return err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.objectURL(bucket, key, false), nil)
	response, requestErr := c.http.Do(request)
	if requestErr != nil {
		return fmt.Errorf("verify anonymous bucket access: %w", requestErr)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	anonymous := response.StatusCode >= 200 && response.StatusCode < 300
	if public && !anonymous {
		return fmt.Errorf("public bucket verification object is not anonymously readable (HTTP %d)", response.StatusCode)
	}
	if !public && anonymous {
		return fmt.Errorf("private bucket permits anonymous object reads")
	}
	return nil
}

func (c *Client) PublicURL(bucket, key string) string {
	return c.objectURL(bucket, key, true)
}

func (c *Client) objectURL(bucket, key string, preferBase bool) string {
	base := strings.TrimRight(c.config.Endpoint, "/")
	if preferBase && c.config.PublicBaseURL != "" {
		base = strings.TrimRight(c.config.PublicBaseURL, "/")
		parsed, _ := url.Parse(base)
		parsed.Path = path.Join(parsed.Path, strings.TrimLeft(key, "/"))
		return parsed.String()
	}
	parsed, _ := url.Parse(base)
	if c.config.ForcePathStyle {
		parsed.Path = path.Join(parsed.Path, bucket, strings.TrimLeft(key, "/"))
		return parsed.String()
	}
	parsed.Host = bucket + "." + parsed.Host
	parsed.Path = path.Join(parsed.Path, strings.TrimLeft(key, "/"))
	return parsed.String()
}
