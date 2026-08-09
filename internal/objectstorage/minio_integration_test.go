package objectstorage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

func TestMinIODirectTransferAndVisibility(t *testing.T) {
	endpoint := os.Getenv("PLATFORM93_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("PLATFORM93_TEST_S3_ENDPOINT is not configured")
	}
	publicBucket := "p93-public-" + uuid.NewString()
	privateBucket := "p93-private-" + uuid.NewString()
	config := Config{
		Endpoint: endpoint, Region: "us-east-1", AccessKeyID: os.Getenv("PLATFORM93_TEST_S3_ACCESS_KEY"),
		SecretAccessKey: os.Getenv("PLATFORM93_TEST_S3_SECRET_KEY"), PublicBucket: publicBucket,
		PrivateBucket: privateBucket, ForcePathStyle: true, AllowPrivateEndpoint: true,
	}
	client, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	for _, bucket := range []string{publicBucket, privateBucket} {
		if _, err = client.s3.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
			t.Fatal(err)
		}
		defer client.s3.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	}
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::%s/*"]}]}`, publicBucket)
	if _, err = client.s3.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{Bucket: aws.String(publicBucket), Policy: aws.String(policy)}); err != nil {
		t.Fatal(err)
	}
	if err = client.VerifyBucket(context.Background(), publicBucket, true); err != nil {
		t.Fatalf("public verification failed: %v", err)
	}
	if err = client.VerifyBucket(context.Background(), privateBucket, false); err != nil {
		t.Fatalf("private verification failed: %v", err)
	}

	content := []byte("platform93-minio")
	key := "organizations/test/applications/test/application/" + uuid.NewString() + "/file.txt" // gitleaks:allow -- Generated object path, not a credential.
	uploadURL, headers, err := client.PresignPut(context.Background(), privateBucket, key, "text/plain", int64(len(content)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPut, uploadURL, bytes.NewReader(content))
	request.Header = headers.Clone()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("presigned PUT returned HTTP %d", response.StatusCode)
	}
	head, err := client.Head(context.Background(), privateBucket, key)
	if err != nil || head.Size != int64(len(content)) || head.ContentType != "text/plain" {
		t.Fatalf("unexpected HEAD: %#v, %v", head, err)
	}
	prefix, err := client.ReadPrefix(context.Background(), privateBucket, key, 32)
	if err != nil || !bytes.Equal(prefix, content) {
		t.Fatalf("unexpected prefix: %q, %v", prefix, err)
	}
	downloadURL, err := client.PresignGet(context.Background(), privateBucket, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response, err = http.Get(downloadURL)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("presigned GET failed: %v, %#v", err, response)
	}
	response.Body.Close()
	if err = client.Delete(context.Background(), privateBucket, key); err != nil {
		t.Fatal(err)
	}
}
