// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/stretchr/testify/require"
)

func TestAwsStoragePersistedStateS3Client(t *testing.T) {
	cases := []struct {
		name             string
		creds            *awsutil.CredentialsConfig
		opts             []awsStoragePersistedStateOption
		awsOpts          []awsutil.Option
		s3Opts           []s3Option
		expectedRegion   string
		expectedEndpoint string
	}{
		{
			name: "static credentials",
			creds: func() *awsutil.CredentialsConfig {
				creds, err := awsutil.NewCredentialsConfig(
					awsutil.WithRegion("us-west-2"),
					awsutil.WithAccessKey("foobar"),
					awsutil.WithSecretKey("barfoo"),
				)
				require.NoError(t, err)
				return creds
			}(),
			awsOpts: []awsutil.Option{
				awsutil.WithIAMAPIFunc(
					awsutil.NewMockIAM(),
				),
			},
			opts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(nil)),
			},
			s3Opts: []s3Option{
				WithRegion("us-west-2"),
				WithEndpoint("0.0.0.0"),
			},
			expectedRegion:   "us-west-2",
			expectedEndpoint: "0.0.0.0",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			cred, err := credential.NewAwsCredentialPersistedState(
				credential.WithCredentialsConfig(tc.creds),
				credential.WithStateTestOpts(tc.awsOpts),
			)
			require.NoError(err)

			state, err := newAwsStoragePersistedState(
				append(tc.opts, withCredentials(cred))...,
			)
			require.NoError(err)

			clientRaw, err := state.S3Client(context.Background(), tc.s3Opts...)
			require.NoError(err)
			require.NotNil(clientRaw)
			client, ok := clientRaw.(*testMockS3)
			require.True(ok)
			require.NotNil(client)
			require.Equal(tc.expectedRegion, client.Region)

			if tc.expectedEndpoint != "" {
				endpoint, err := client.Endpoint.ResolveEndpoint(s3.ServiceID, client.Region)
				require.NoError(err)
				require.Equal(tc.expectedEndpoint, endpoint.URL)
				require.Equal(tc.expectedRegion, endpoint.SigningRegion)
				require.Equal("aws", endpoint.PartitionID)
			}
		})
	}
}
