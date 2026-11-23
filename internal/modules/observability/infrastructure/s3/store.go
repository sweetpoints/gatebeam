// Package s3 implements verified, immutable archival using the standard AWS SDK v2.
package s3

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/objectstore"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"io"
	"net/url"
	"os"
	"time"
)

var ErrUnavailable = errors.New("archive_unavailable")

type Config = objectstore.Config

var LoadConfig = objectstore.LoadConfig

type Store struct {
	client *sdk.Client
	bucket string
	root   *os.Root
}

func New(c Config, spool string) (*Store, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	var r *os.Root
	var e error
	if spool != "" {
		r, e = os.OpenRoot(spool)
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	client := objectstore.Client(c)
	return &Store{client: client, bucket: c.Bucket, root: r}, nil
}
func (s *Store) Close() error {
	if s.root != nil {
		return s.root.Close()
	}
	return nil
}

// EnsureBucket is exclusively an owned integration-fixture setup operation.
func (s *Store) EnsureBucket(ctx context.Context) error {
	_, e := s.client.HeadBucket(ctx, &sdk.HeadBucketInput{Bucket: &s.bucket})
	if e == nil {
		return nil
	}
	_, e = s.client.CreateBucket(ctx, &sdk.CreateBucketInput{Bucket: &s.bucket})
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) verify(ctx context.Context, key string, o domain.Object) error {
	v, e := s.client.GetObject(ctx, &sdk.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if e != nil {
		return ErrUnavailable
	}
	defer v.Body.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(v.Body, o.Bytes+1))
	if e != nil || n != o.Bytes || fmt.Sprintf("%x", h.Sum(nil)) != o.Checksum {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) Upload(ctx context.Context, b domain.Batch) (domain.Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	m := domain.Manifest{BatchID: b.ID, Objects: b.Objects}
	if s.root == nil || len(b.Objects) > domain.MaxRows {
		return domain.Manifest{}, domain.ErrInvalid
	}
	for _, o := range b.Objects {
		if !domain.ValidObject(o) {
			return domain.Manifest{}, domain.ErrInvalid
		}
		final := "logs/" + o.Key
		// Content is checked, not trusted from a caller-controlled metadata checksum.
		pending := "pending/" + o.Key
		if _, err := s.client.HeadObject(ctx, &sdk.HeadObjectInput{Bucket: &s.bucket, Key: &final}); err == nil {
			if e := s.verify(ctx, final, o); e != nil {
				return domain.Manifest{}, e
			}
			if _, e := s.client.DeleteObject(ctx, &sdk.DeleteObjectInput{Bucket: &s.bucket, Key: &pending}); e != nil {
				return domain.Manifest{}, ErrUnavailable
			}
			continue
		} else {
			var response *smithyhttp.ResponseError
			if !errors.As(err, &response) || response.HTTPStatusCode() != 404 {
				return domain.Manifest{}, ErrUnavailable
			}
		}

		st, e := s.root.Lstat(o.Key)
		if e != nil || !st.Mode().IsRegular() {
			return domain.Manifest{}, ErrUnavailable
		}
		f, e := s.root.Open(o.Key)
		if e != nil {
			return domain.Manifest{}, ErrUnavailable
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, o.Bytes+1))
		if e != nil || n != o.Bytes || fmt.Sprintf("%x", h.Sum(nil)) != o.Checksum {
			f.Close()
			return domain.Manifest{}, ErrUnavailable
		}
		if _, e = f.Seek(0, 0); e != nil {
			f.Close()
			return domain.Manifest{}, ErrUnavailable
		}
		_, e = s.client.PutObject(ctx, &sdk.PutObjectInput{Bucket: &s.bucket, Key: &pending, Body: f, ContentLength: &o.Bytes})
		f.Close()
		if e != nil {
			return domain.Manifest{}, ErrUnavailable
		}
		if e = s.verify(ctx, pending, o); e != nil {
			return domain.Manifest{}, e
		}
		source := url.PathEscape(s.bucket + "/" + pending)
		_, e = s.client.CopyObject(ctx, &sdk.CopyObjectInput{Bucket: &s.bucket, Key: &final, CopySource: &source})
		if e != nil {
			return domain.Manifest{}, ErrUnavailable
		}
		if e = s.verify(ctx, final, o); e != nil {
			return domain.Manifest{}, e
		}
		_, e = s.client.DeleteObject(ctx, &sdk.DeleteObjectInput{Bucket: &s.bucket, Key: &pending})
		if e != nil {
			return domain.Manifest{}, ErrUnavailable
		}
	}
	return m, nil
}
func (s *Store) Delete(ctx context.Context, o domain.Object) error {
	if !domain.ValidObject(o) {
		return domain.ErrInvalid
	}
	key := "logs/" + o.Key
	_, e := s.client.DeleteObject(ctx, &sdk.DeleteObjectInput{Bucket: &s.bucket, Key: &key})
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) Cleanup(o domain.Object) error {
	if !domain.ValidObject(o) || s.root == nil {
		return domain.ErrInvalid
	}
	e := s.root.Remove(o.Key)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	return nil
}
