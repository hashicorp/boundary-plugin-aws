// Copyright IBM Corp. 2021, 2026
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

func TestGetTargetCredentialAttributes(t *testing.T) {
	const targetRoleArn = "arn:aws:iam::222222222222:role/Target"

	cases := []struct {
		name                string
		in                  map[string]any
		expected            *CredentialAttributes
		expectedErrContains string
	}{
		{
			name: "missing target_role_arn",
			in: map[string]any{
				ConstRegion: "us-west-2",
			},
			expectedErrContains: "attributes.target_role_arn: missing required value \"target_role_arn\"",
		},
		{
			name:                "missing target_role_arn and region",
			in:                  map[string]any{},
			expectedErrContains: "attributes.target_role_arn: missing required value \"target_role_arn\"",
		},
		{
			name: "empty target_role_arn",
			in: map[string]any{
				ConstRegion:        "us-west-2",
				ConstTargetRoleArn: "",
			},
			expectedErrContains: "attributes.target_role_arn: value \"target_role_arn\" cannot be empty",
		},
		{
			name: "wrong type target_role_arn",
			in: map[string]any{
				ConstRegion:        "us-west-2",
				ConstTargetRoleArn: true,
			},
			expectedErrContains: "attributes.target_role_arn: unexpected type for value \"target_role_arn\": want string, got bool",
		},
		{
			name: "target_region without target_role_arn",
			in: map[string]any{
				ConstRegion:       "us-west-2",
				ConstTargetRegion: "eu-west-1",
			},
			expectedErrContains: "attributes.target_role_arn: missing required value \"target_role_arn\"",
		},
		{
			name: "other target fields without target_role_arn",
			in: map[string]any{
				ConstRegion:                "us-west-2",
				ConstTargetRoleExternalId:  "ext",
				ConstTargetRoleSessionName: "sess",
				ConstTargetRoleTags:        map[string]any{"k": "v"},
			},
			expectedErrContains: "attributes.target_role_arn: missing required value \"target_role_arn\"",
		},
		{
			name: "target_role_arn uses region when target_region omitted",
			in: map[string]any{
				ConstRegion:        "us-west-2",
				ConstTargetRoleArn: targetRoleArn,
			},
			expected: &CredentialAttributes{
				Region:  "us-west-2",
				RoleArn: targetRoleArn,
			},
		},
		{
			name: "target_role_arn without target_region or region",
			in: map[string]any{
				ConstTargetRoleArn: targetRoleArn,
			},
			expectedErrContains: "missing required value \"region\"",
		},
		{
			name: "target_region overrides region",
			in: map[string]any{
				ConstRegion:        "us-west-2",
				ConstTargetRegion:  "eu-west-1",
				ConstTargetRoleArn: targetRoleArn,
			},
			expected: &CredentialAttributes{
				Region:  "eu-west-1",
				RoleArn: targetRoleArn,
			},
		},
		{
			name: "empty target_region falls back to region",
			in: map[string]any{
				ConstRegion:        "us-west-2",
				ConstTargetRegion:  "",
				ConstTargetRoleArn: targetRoleArn,
			},
			expected: &CredentialAttributes{
				Region:  "us-west-2",
				RoleArn: targetRoleArn,
			},
		},
		{
			name: "all optional target fields",
			in: map[string]any{
				ConstRegion:                    "us-west-2",
				ConstDisableCredentialRotation: true,
				ConstTargetRoleArn:             targetRoleArn,
				ConstTargetRegion:              "eu-west-1",
				ConstTargetRoleExternalId:      "target-ext",
				ConstTargetRoleSessionName:     "target-sess",
				ConstTargetRoleTags:            map[string]any{"env": "target"},
			},
			expected: &CredentialAttributes{
				Region:                    "eu-west-1",
				DisableCredentialRotation: true,
				RoleArn:                   targetRoleArn,
				RoleExternalId:            "target-ext",
				RoleSessionName:           "target-sess",
				RoleTags:                  map[string]string{"env": "target"},
			},
		},
		{
			name: "optional target fields omitted do not copy principal role fields",
			in: map[string]any{
				ConstRegion:          "us-west-2",
				ConstRoleArn:         "arn:aws:iam::111111111111:role/Principal",
				ConstRoleExternalId:  "principal-ext",
				ConstRoleSessionName: "principal-sess",
				ConstRoleTags:        map[string]any{"env": "principal"},
				ConstTargetRoleArn:   targetRoleArn,
			},
			expected: &CredentialAttributes{
				Region:  "us-west-2",
				RoleArn: targetRoleArn,
			},
		},
		{
			name: "disable_credential_rotation false is copied",
			in: map[string]any{
				ConstRegion:                    "us-west-2",
				ConstDisableCredentialRotation: false,
				ConstTargetRoleArn:             targetRoleArn,
			},
			expected: &CredentialAttributes{
				Region:                    "us-west-2",
				DisableCredentialRotation: false,
				RoleArn:                   targetRoleArn,
			},
		},
		{
			name: "wrong type target_region",
			in: map[string]any{
				ConstRegion:        "us-west-2",
				ConstTargetRoleArn: targetRoleArn,
				ConstTargetRegion:  true,
			},
			expectedErrContains: "attributes.target_region: unexpected type for value \"target_region\": want string, got bool",
		},
		{
			name: "wrong type target_role_external_id",
			in: map[string]any{
				ConstRegion:               "us-west-2",
				ConstTargetRoleArn:        targetRoleArn,
				ConstTargetRoleExternalId: true,
			},
			expectedErrContains: "attributes.target_role_external_id: unexpected type for value \"target_role_external_id\": want string, got bool",
		},
		{
			name: "wrong type target_role_session_name",
			in: map[string]any{
				ConstRegion:                "us-west-2",
				ConstTargetRoleArn:         targetRoleArn,
				ConstTargetRoleSessionName: true,
			},
			expectedErrContains: "attributes.target_role_session_name: unexpected type for value \"target_role_session_name\": want string, got bool",
		},
		{
			name: "wrong type target_role_tags",
			in: map[string]any{
				ConstRegion:         "us-west-2",
				ConstTargetRoleArn:  targetRoleArn,
				ConstTargetRoleTags: true,
			},
			expectedErrContains: "attributes.target_role_tags: unexpected type for value \"target_role_tags\": want map[string]string, got bool",
		},
		{
			name: "wrong type target_role_tag value",
			in: map[string]any{
				ConstRegion:        "us-west-2",
				ConstTargetRoleArn: targetRoleArn,
				ConstTargetRoleTags: map[string]any{
					"env": true,
				},
			},
			expectedErrContains: `unexpected type for value in map["env"]: want string, got bool`,
		},
		{
			name: "wrong type disable_credential_rotation",
			in: map[string]any{
				ConstRegion:                    "us-west-2",
				ConstTargetRoleArn:             targetRoleArn,
				ConstDisableCredentialRotation: "sure",
			},
			expectedErrContains: "attributes.disable_credential_rotation: unexpected type for value \"disable_credential_rotation\": want bool, got string",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := GetTargetCredentialAttributes(input)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Nil(actual)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(codes.InvalidArgument, status.Code(err))
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestGetCredentialsConfig(t *testing.T) {
	cases := []struct {
		name                string
		secrets             *structpb.Struct
		attrs               *CredentialAttributes
		dualStack           bool
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
			name: "with dualstack",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("AKIAfoobar"),
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
				},
			},
			dualStack: true,
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

			actual, err := GetCredentialsConfig(tc.secrets, tc.attrs, tc.dualStack)
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
			if tc.dualStack {
				require.NotNil(actual.IAMEndpointResolver)
				require.NotNil(actual.STSEndpointResolver)
			} else {
				require.Nil(actual.IAMEndpointResolver)
				require.Nil(actual.STSEndpointResolver)
			}
		})
	}
}
