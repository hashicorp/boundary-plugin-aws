// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	"google.golang.org/protobuf/types/known/structpb"
)

type S3API interface {
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

var customClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
	},
}

type awsStoragePersistedState struct {
	*credential.AwsCredentialPersistedState

	// testS3APIFunc provides a way to provide a factory for a mock EC2 client
	testS3APIFunc s3APIFunc
}

type s3APIFunc func(...aws.Config) (S3API, error)

type awsStoragePersistedStateOption func(s *awsStoragePersistedState) error

func withTestS3APIFunc(f s3APIFunc) awsStoragePersistedStateOption {
	return func(s *awsStoragePersistedState) error {
		if s.testS3APIFunc != nil {
			return errors.New("test API function already set")
		}

		s.testS3APIFunc = f
		return nil
	}
}

func withCredentials(x *credential.AwsCredentialPersistedState) awsStoragePersistedStateOption {
	return func(s *awsStoragePersistedState) error {
		if s.AwsCredentialPersistedState != nil {
			return errors.New("aws credentials already set")
		}

		s.AwsCredentialPersistedState = x
		return nil
	}
}

func newAwsStoragePersistedState(opts ...awsStoragePersistedStateOption) (*awsStoragePersistedState, error) {
	s := new(awsStoragePersistedState)
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *awsStoragePersistedState) toProto() (*storagebuckets.StorageBucketPersisted, error) {

	data, err := structpb.NewStruct(s.ToMap())
	if err != nil {
		return nil, fmt.Errorf("error converting state to structpb.Struct: %w", err)
	}
	return &storagebuckets.StorageBucketPersisted{Data: data}, nil
}

// S3Client returns a configured S3 client based on the session
// information stored in the state.
func (s *awsStoragePersistedState) S3Client(ctx context.Context, opt ...s3Option) (S3API, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing options when fetching S3 client: %w", err)
	}

	awsConfigOpts := []func(*config.LoadOptions) error{}
	sess, err := s.GetSession()
	if err != nil {
		return nil, fmt.Errorf("error getting AWS session when fetching S3 client: %w", err)
	}
	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return nil, fmt.Errorf("error getting AWS session when fetching S3 client: %w", err)
	}
	customCredentials := config.WithCredentialsProvider(
		credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken),
	)
	awsConfigOpts = append(awsConfigOpts, customCredentials)
	if sess.Config.Region != nil {
		awsConfigOpts = append(awsConfigOpts, config.WithRegion(*sess.Config.Region))
	}
	if opts.withRegion != "" {
		awsConfigOpts = append(awsConfigOpts, config.WithRegion(opts.withRegion))
	}
	if opts.withEndpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			if service == s3.ServiceID {
				if opts.withRegion != "" {
					region = opts.withRegion
				}
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           opts.withEndpoint,
					SigningRegion: region,
				}, nil
			}
			// returning EndpointNotFoundError will allow the service to fallback to it's default resolution
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})
		awsConfigOpts = append(awsConfigOpts, config.WithEndpointResolverWithOptions(customResolver))
	}
	cfg, err := config.LoadDefaultConfig(ctx, awsConfigOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading aws configuration when fetching S3 client: %w", err)
	}

	if s.testS3APIFunc != nil {
		return s.testS3APIFunc(cfg)
	}

	cfg.HTTPClient = customClient

	return s3.NewFromConfig(cfg), nil
}

// getOpts iterates the inbound s3Options and returns a struct
func getOpts(opt ...s3Option) (s3Options, error) {
	opts := getDefaultS3Options()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(&opts); err != nil {
			return s3Options{}, err
		}
	}
	return opts, nil
}

// s3Option - how s3Options are passed as arguments
type s3Option func(*s3Options) error

// options = how options are represented
type s3Options struct {
	withRegion   string
	withEndpoint string
}

func getDefaultS3Options() s3Options {
	return s3Options{}
}

// WithRegion contains the region to use
func WithRegion(with string) s3Option {
	return func(o *s3Options) error {
		o.withRegion = with
		return nil
	}
}

// WithEndpoint contains the endpoint to use
func WithEndpoint(with string) s3Option {
	return func(o *s3Options) error {
		o.withEndpoint = with
		return nil
	}
}
