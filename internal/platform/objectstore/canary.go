package objectstore

import (
	"bytes"
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"io"
	"time"
)

// VerifyWriteRead performs an owner-invoked capability check in an isolated
// internal prefix. It cannot overwrite a business object or create a bucket.
func VerifyWriteRead(ctx context.Context, c Config, node string) (err error) {
	if uuid.Validate(node) != nil || c.Validate() != nil {
		return ErrUnavailable
	}
	id := uuid.NewString()
	key := "logs/_gatebeam-canary/" + node + "/" + id
	body := []byte(id)
	client := Client(c)
	if _, e := client.PutObject(ctx, &sdk.PutObjectInput{Bucket: &c.Bucket, Key: &key, Body: bytes.NewReader(body), ContentLength: aws.Int64(int64(len(body))), IfNoneMatch: aws.String("*")}); e != nil {
		return ErrUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if _, e := client.DeleteObject(cleanup, &sdk.DeleteObjectInput{Bucket: &c.Bucket, Key: &key}); e != nil {
			err = ErrUnavailable
		}
	}()
	result, e := client.GetObject(ctx, &sdk.GetObjectInput{Bucket: &c.Bucket, Key: &key})
	if e != nil {
		return ErrUnavailable
	}
	defer result.Body.Close()
	got, e := io.ReadAll(io.LimitReader(result.Body, 129))
	if e != nil || !bytes.Equal(got, body) {
		return ErrUnavailable
	}
	return nil
}
