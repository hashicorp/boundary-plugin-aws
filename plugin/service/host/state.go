// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

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
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/protobuf/types/known/structpb"
)

type EC2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
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

type awsCatalogPersistedState struct {
	*credential.AwsCredentialPersistedState

	// testEC2APIFunc provides a way to provide a factory for a mock EC2 client
	testEC2APIFunc ec2APIFunc
}

type ec2APIFunc func(...aws.Config) (EC2API, error)

type awsCatalogPersistedStateOption func(s *awsCatalogPersistedState) error

func withTestEC2APIFunc(f ec2APIFunc) awsCatalogPersistedStateOption {
	return func(s *awsCatalogPersistedState) error {
		if s.testEC2APIFunc != nil {
			return errors.New("test API function already set")
		}

		s.testEC2APIFunc = f
		return nil
	}
}

func withCredentials(x *credential.AwsCredentialPersistedState) awsCatalogPersistedStateOption {
	return func(s *awsCatalogPersistedState) error {
		if s.AwsCredentialPersistedState != nil {
			return errors.New("aws credentials already set")
		}

		s.AwsCredentialPersistedState = x
		return nil
	}
}

func newAwsCatalogPersistedState(opts ...awsCatalogPersistedStateOption) (*awsCatalogPersistedState, error) {
	s := new(awsCatalogPersistedState)
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *awsCatalogPersistedState) toProto() (*pb.HostCatalogPersisted, error) {
	data, err := structpb.NewStruct(s.ToMap())
	if err != nil {
		return nil, fmt.Errorf("error converting state to structpb.Struct: %w", err)
	}
	return &pb.HostCatalogPersisted{Secrets: data}, nil
}

// EC2Client returns a configured EC2 client based on the session
// information stored in the state.
func (s *awsCatalogPersistedState) EC2Client(ctx context.Context, opt ...ec2Option) (EC2API, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing options when fetching EC2 client: %w", err)
	}

	awsConfigOpts := []func(*config.LoadOptions) error{}
	sess, err := s.GetSession()
	if err != nil {
		return nil, fmt.Errorf("error getting AWS session when fetching EC2 client: %w", err)
	}
	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return nil, fmt.Errorf("error getting AWS session when fetching EC2 client: %w", err)
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
	cfg, err := config.LoadDefaultConfig(ctx, awsConfigOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading aws configuration when fetching EC2 client: %w", err)
	}

	if s.testEC2APIFunc != nil {
		return s.testEC2APIFunc(cfg)
	}

	cfg.HTTPClient = customClient

	return ec2.NewFromConfig(cfg), nil
}

// getOpts iterates the inbound ec2Options and returns a struct
func getOpts(opt ...ec2Option) (ec2Options, error) {
	opts := getDefaultEC2Options()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(&opts); err != nil {
			return ec2Options{}, err
		}
	}
	return opts, nil
}

// ec2Option - how ec2Options are passed as arguments
type ec2Option func(*ec2Options) error

// options = how options are represented
type ec2Options struct {
	withRegion string
}

func getDefaultEC2Options() ec2Options {
	return ec2Options{}
}

// WithRegion contains the region to use
func WithRegion(with string) ec2Option {
	return func(o *ec2Options) error {
		o.withRegion = with
		return nil
	}
}
