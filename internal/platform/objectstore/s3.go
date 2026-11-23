// Package objectstore owns the common bounded S3/R2 transport configuration.
package objectstore

import (
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
)

var ErrUnavailable = errors.New("object storage unavailable")

type Config struct{ Endpoint, Bucket, Region, AccessKey, SecretKey string }

func LoadConfig(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, ErrUnavailable
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return Config{}, ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Config{}, ErrUnavailable
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(c.Bucket) || c.AccessKey == "" || c.SecretKey == "" || len(c.AccessKey) > 256 || len(c.SecretKey) > 1024 {
		return ErrUnavailable
	}
	return nil
}

func Client(c Config) *sdk.Client {
	return sdk.New(sdk.Options{Region: c.Region, Credentials: credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, ""), BaseEndpoint: aws.String(c.Endpoint), UsePathStyle: true, RetryMaxAttempts: 2, HTTPClient: &http.Client{Timeout: 20 * time.Second}, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired})
}
