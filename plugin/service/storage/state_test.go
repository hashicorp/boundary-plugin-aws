// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	awsutilv2 "github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/stretchr/testify/require"
)

func TestAwsStoragePersistedStateS3Client(t *testing.T) {
	cases := []struct {
		name             string
		creds            *awsutilv2.CredentialsConfig
		opts             []awsStoragePersistedStateOption
		awsOpts          []awsutilv2.Option
		s3Opts           []s3Option
		expectedRegion   string
		expectedEndpoint string
	}{
		{
			name: "static credentials",
			creds: func() *awsutilv2.CredentialsConfig {
				creds, err := awsutilv2.NewCredentialsConfig(
					awsutilv2.WithRegion("us-west-2"),
					awsutilv2.WithAccessKey("foobar"),
					awsutilv2.WithSecretKey("barfoo"),
				)
				require.NoError(t, err)
				return creds
			}(),
			awsOpts: []awsutilv2.Option{
				awsutilv2.WithIAMAPIFunc(
					awsutilv2.NewMockIAM(),
				),
			},
			opts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(nil)),
			},
			s3Opts: []s3Option{
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
		})
	}
}
