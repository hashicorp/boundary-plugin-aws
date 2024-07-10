// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"testing"

	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
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
		{
			name: "with assume role",
			in: map[string]any{
				ConstRegion:          "us-west-2",
				ConstRoleArn:         "arn:aws:iam::123456789012:role/S3Access",
				ConstRoleExternalId:  "1234567890",
				ConstRoleSessionName: "test-session",
				ConstRoleTags: map[string]interface{}{
					"foo": "bar",
				},
			},
			expected: &CredentialAttributes{
				Region:                    "us-west-2",
				DisableCredentialRotation: false,
				RoleArn:                   "arn:aws:iam::123456789012:role/S3Access",
				RoleExternalId:            "1234567890",
				RoleSessionName:           "test-session",
				RoleTags: map[string]string{
					"foo": "bar",
				},
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
		secrets             *structpb.Struct
		required            bool
		attrs               *CredentialAttributes
		expected            *awsutil.CredentialsConfig
		expectedErrContains string
	}{
		{
			name: "no credentials",
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &awsutil.CredentialsConfig{
				Region: "us-west-2",
			},
		},
		{
			name: "with static credentials",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("AKIAfoobar"),
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &awsutil.CredentialsConfig{
				AccessKey: "AKIAfoobar",
				SecretKey: "bazqux",
				Region:    "us-west-2",
			},
		},
		{
			name: "missing access key",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			required:            true,
			expectedErrContains: "secrets.access_key_id: missing required value",
		},
		{
			name: "missing secret key",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId: structpb.NewStringValue("AKIAfoobar"),
				},
			},
			required: true,
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expectedErrContains: "secrets.secret_access_key: missing required value",
		},
		{
			name: "unknown fields",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("AKIAfoobar"),
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
					"foo":                structpb.NewBoolValue(true),
					"bar":                structpb.NewBoolValue(true),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expectedErrContains: "secrets.bar: unrecognized field, secrets.foo: unrecognized field",
		},
		{
			name: "valid ignore creds_last_rotated_time",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:          structpb.NewStringValue("AKIAfoobar"),
					ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
					ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &awsutil.CredentialsConfig{
				AccessKey: "AKIAfoobar",
				SecretKey: "bazqux",
				Region:    "us-west-2",
			},
		},
		{
			name: "with assume role",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{},
			},
			attrs: &CredentialAttributes{
				Region:          "us-west-2",
				RoleArn:         "arn:aws:iam::123456789012:role/S3Access",
				RoleExternalId:  "1234567890",
				RoleSessionName: "test-session",
				RoleTags: map[string]string{
					"foo": "bar",
				},
				DisableCredentialRotation: true,
			},
			expected: &awsutil.CredentialsConfig{
				Region:          "us-west-2",
				RoleARN:         "arn:aws:iam::123456789012:role/S3Access",
				RoleExternalId:  "1234567890",
				RoleSessionName: "test-session",
				RoleTags: map[string]string{
					"foo": "bar",
				},
			},
		},
		{
			name: "with static credential & assume role",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("AKIAfoobar"),
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
				},
			},
			attrs: &CredentialAttributes{
				Region:          "us-west-2",
				RoleArn:         "arn:aws:iam::123456789012:role/S3Access",
				RoleExternalId:  "1234567890",
				RoleSessionName: "test-session",
				RoleTags: map[string]string{
					"foo": "bar",
				},
			},
			expectedErrContains: "attributes.role_arn: conflicts with access_key_id and secret_access_key values, secrets.access_key_id: conflicts with role_arn value, secrets.secret_access_key: conflicts with role_arn value",
		},
		{
			name:    "with dynamic credentials and no disable credential rotation",
			secrets: &structpb.Struct{Fields: map[string]*structpb.Value{}},
			attrs: &CredentialAttributes{
				Region:          "us-west-2",
				RoleArn:         "arn:aws:iam::123456789012:role/S3Access",
				RoleExternalId:  "1234567890",
				RoleSessionName: "test-session",
				RoleTags: map[string]string{
					"foo": "bar",
				},
			},
			expectedErrContains: "attributes.disable_credential_rotation: disable_credential_rotation attribute is required when providing a role_arn",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			actual, err := GetCredentialsConfig(tc.secrets, tc.attrs, tc.required)
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
			require.Equal(tc.expected.RoleARN, actual.RoleARN)
			require.Equal(tc.expected.RoleExternalId, actual.RoleExternalId)
			require.Equal(tc.expected.RoleSessionName, actual.RoleSessionName)
			require.Equal(tc.expected.RoleTags, actual.RoleTags)
		})
	}
}
