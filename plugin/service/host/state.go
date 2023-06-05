// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/protobuf/types/known/structpb"
)

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

type ec2APIFunc func(*session.Session, ...*aws.Config) (ec2iface.EC2API, error)

type awsCatalogPersistedStateOption func(s *awsCatalogPersistedState) error

type awsCatalogPersistedState struct {
	*credential.AwsCredentialPersistedState

	// testEC2APIFunc provides a way to provide a factory for a mock EC2 client
	testEC2APIFunc ec2APIFunc
}

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
func (s *awsCatalogPersistedState) EC2Client(region string) (ec2iface.EC2API, error) {
	sess, err := s.GetSession()
	if err != nil {
		return nil, fmt.Errorf("error getting AWS session when fetching EC2 client: %w", err)
	}

	if s.testEC2APIFunc != nil {
		return s.testEC2APIFunc(sess, aws.NewConfig().WithRegion(region))
	}

	cfg := aws.NewConfig()
	if region != "" {
		cfg = cfg.WithRegion(region)
	}

	cfg.HTTPClient = customClient

	return ec2.New(sess, cfg), nil
}
