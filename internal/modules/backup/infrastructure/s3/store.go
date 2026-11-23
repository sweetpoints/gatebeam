package s3

import (
	"bytes"
	"context"
	"gatebeam/internal/modules/backup/application"
	"gatebeam/internal/modules/backup/domain"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	"gatebeam/internal/platform/objectstore"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
)

type Store struct {
	client *sdk.Client
	bucket string
}

func New(c objectstore.Config) (*Store, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	return &Store{objectstore.Client(c), c.Bucket}, nil
}
func (s *Store) PutVerified(ctx context.Context, a application.Artifact) error {
	if !domain.ValidDigest(a.Manifest.ID) || !domain.ValidDigest(a.SHA256) || a.Bytes <= 0 || a.Bytes > domain.MaxArchive {
		return domain.ErrInvalid
	}
	b, e := archive.ReadRegular(a.Path, domain.MaxArchive)
	if e != nil || int64(len(b)) != a.Bytes || archive.Digest(b) != a.SHA256 {
		return domain.ErrInvalid
	}
	key := "backups/" + a.Manifest.ID + ".age"
	none := "*"
	_, e = s.client.PutObject(ctx, &sdk.PutObjectInput{Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(b), ContentLength: &a.Bytes, IfNoneMatch: &none})
	// Retry after an ambiguous upload always reads and hashes the actual object.
	// The digest comparison also detects immutable-key collisions.
	v, readErr := s.client.GetObject(ctx, &sdk.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if readErr != nil {
		return objectstore.ErrUnavailable
	}
	defer v.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(v.Body, a.Bytes+1))
	if readErr != nil || int64(len(body)) != a.Bytes || archive.Digest(body) != a.SHA256 {
		return objectstore.ErrUnavailable
	}
	return nil
}
func (s *Store) Delete(ctx context.Context, id string) error {
	if !domain.ValidDigest(id) {
		return domain.ErrInvalid
	}
	key := "backups/" + id + ".age"
	_, e := s.client.DeleteObject(ctx, &sdk.DeleteObjectInput{Bucket: &s.bucket, Key: &key})
	if e != nil {
		return objectstore.ErrUnavailable
	}
	return nil
}
