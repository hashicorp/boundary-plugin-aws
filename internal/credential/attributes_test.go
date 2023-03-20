// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"testing"

	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetCredentialAttributes(t *testing.T) {
	cases := []struct {
		name                string
		in                  map[string]any
		expected            *CredentialAttributes
		expectedErrContains string
	}{
		{
			name:                "missing region",
			in:                  map[string]any{},
			expectedErrContains: "missing required value \"region\"",
		},
		{
			name: "invalid aws region value",
			in: map[string]any{
				ConstRegion: "dne",
			},
			expectedErrContains: "not a valid region",
		},
		{
			name: "bad value for disable_credential_rotation",
			in: map[string]any{
				ConstRegion:                    "us-west-2",
				ConstDisableCredentialRotation: "sure",
			},
			expectedErrContains: "unexpected type for value \"disable_credential_rotation\": want bool, got string",
		},
		{
			name: "default",
			in: map[string]any{
				ConstRegion: "us-west-2",
			},
			expected: &CredentialAttributes{
				Region:                    "us-west-2",
				DisableCredentialRotation: false,
			},
		},
		{
			name: "with disable_credential_rotation",
			in: map[string]any{
				ConstRegion:                    "us-west-2",
				ConstDisableCredentialRotation: true,
			},
			expected: &CredentialAttributes{
				Region:                    "us-west-2",
				DisableCredentialRotation: true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := GetCredentialAttributes(input)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
			require.EqualValues(tc.expected.Region, actual.Region)
			require.EqualValues(tc.expected.DisableCredentialRotation, actual.DisableCredentialRotation)
		})
	}
}

func TestGetCredentialsConfig(t *testing.T) {
	cases := []struct {
		name                string
		in                  map[string]any
		region              string
		expected            *awsutil.CredentialsConfig
		expectedErrContains string
	}{
		{
			name:                "missing access_key_id",
			in:                  map[string]any{},
			region:              "us-west-2",
			expectedErrContains: "missing required value \"access_key_id\"",
		},
		{
			name: "missing secret_access_key",
			in: map[string]any{
				ConstAccessKeyId: "foobar",
			},
			region:              "us-west-2",
			expectedErrContains: "missing required value \"secret_access_key\"",
		},
		{
			name: "unknown fields",
			in: map[string]any{
				ConstAccessKeyId:     "foobar",
				ConstSecretAccessKey: "bazqux",
				"foo":                true,
				"bar":                true,
			},
			region:              "us-west-2",
			expectedErrContains: "secrets.bar: unrecognized field, secrets.foo: unrecognized field",
		},
		{
			name: "good",
			in: map[string]any{
				ConstAccessKeyId:     "foobar",
				ConstSecretAccessKey: "bazqux",
			},
			region: "us-west-2",
			expected: &awsutil.CredentialsConfig{
				AccessKey: "foobar",
				SecretKey: "bazqux",
				Region:    "us-west-2",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := GetCredentialsConfig(input, tc.region)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected.AccessKey, actual.AccessKey)
			require.Equal(tc.expected.SecretKey, actual.SecretKey)
			require.Equal(tc.expected.Region, actual.Region)
		})
	}
}
