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
func (s *awsCatalogPersistedState) EC2Client(ctx context.Context) (EC2API, error) {
	awsCfg, err := s.GenerateCredentialChain(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting AWS configuration when fetching EC2 client: %w", err)
	}
	if awsCfg == nil {
		return nil, fmt.Errorf("nil aws configuration")
	}
	if s.testEC2APIFunc != nil {
		return s.testEC2APIFunc(*awsCfg)
	}
	return ec2.NewFromConfig(*awsCfg), nil
}
