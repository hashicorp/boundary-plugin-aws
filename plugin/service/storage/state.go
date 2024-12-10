// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyEndpoints "github.com/aws/smithy-go/endpoints"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	"google.golang.org/protobuf/types/known/structpb"
)

type S3API interface {
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	Credentials() aws.Credentials
}

type s3Client struct {
	*s3.Client
	creds aws.Credentials
}

func (c *s3Client) Credentials() aws.Credentials {
	return c.creds
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

// s3Client returns a configured S3 client based on the session
// information stored in the state.
func (s *awsStoragePersistedState) s3Client(ctx context.Context, opt ...s3Option) (S3API, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing options when fetching S3 client: %w", err)
	}
	awsCfg, err := s.GenerateCredentialChain(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting AWS configuration when fetching S3 client: %w", err)
	}
	if awsCfg == nil {
		return nil, fmt.Errorf("nil aws configuration")
	}
	var s3Opts []func(*s3.Options)
	if opts.withEndpoint != "" {
		s3Opts = append(s3Opts, s3.WithEndpointResolverV2(&endpointResolver{
			endpoint: opts.withEndpoint,
		}))
	}
	if s.testS3APIFunc != nil {
		return s.testS3APIFunc(*awsCfg)
	}

	// Retrieve the credentials provider from the client
	credsProvider := awsCfg.Credentials
	creds, err := credsProvider.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials: %v\n", err)
	}

	c := s3.NewFromConfig(*awsCfg, s3Opts...)
	return &s3Client{Client: c, creds: creds}, nil
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
	withEndpoint     string
	withCacheRefresh bool
}

func getDefaultS3Options() s3Options {
	return s3Options{}
}

// WithCacheRefresh controls if the cache should be forced to refresh
func WithCacheRefresh(refresh bool) s3Option {
	return func(o *s3Options) error {
		o.withCacheRefresh = refresh
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

type endpointResolver struct {
	endpoint string
}

func (e *endpointResolver) ResolveEndpoint(ctx context.Context, params s3.EndpointParameters) (resolver smithyEndpoints.Endpoint, err error) {
	var uri *url.URL
	resolver, err = s3.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, params)
	if err != nil {
		return
	}
	if e.endpoint == "" {
		// TODO: not sure if we should set an error or ignore the missing endpoint value and continue with the default resolver
		return
	}
	uri, err = url.Parse(e.endpoint)
	if err != nil {
		return
	}
	if uri == nil {
		// TODO: not sure if we should set an error or ignore the missing uri value and continue with the default resolver
		return
	}
	resolver = smithyEndpoints.Endpoint{
		URI: *uri,
	}
	return
}
