// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package credential

// TestGetCredentialsConfigRoleArnFallback documents all credential input
// combinations and the CredentialsConfig they produce. The key finding is
// in the "role_arn + no static keys" case: GetCredentialsConfig succeeds and
// populates CredentialsConfig.RoleARN, but no STS call is ever made during
// config construction. At runtime, awsutil.GenerateCredentialChain silently
// falls back to the ambient credential chain (env vars / instance profile)
// without calling sts:AssumeRole, so a bogus or unreachable ARN is never
// detected.
//
// Run this test to confirm the root cause:
//
//	go test ./internal/credential/... -run TestGetCredentialsConfigRoleArnFallback -v
import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetCredentialsConfigRoleArnFallback(t *testing.T) {
	cases := []struct {
		name                string
		secrets             *structpb.Struct
		attrs               *CredentialAttributes
		expectedAccessKey   string
		expectedSecretKey   string
		expectedRoleARN     string
		expectedType        CredentialType
		expectedErrContains string
	}{
		{
			// NOTE: No role_arn and no static keys. GetCredentialsConfig
			// succeeds and returns a CredentialsConfig with no credentials set
			// at all. GetCredentialType returns Unknown because there is no
			// AccessKey prefix to classify. The AWS SDK will use whatever
			// ambient credentials it finds at runtime (env vars, instance
			// profile, etc.).
			name: "ambient only — no role_arn, no static keys",
			attrs: &CredentialAttributes{
				Region:                    "us-east-1",
				DisableCredentialRotation: true,
			},
			expectedAccessKey: "",
			expectedSecretKey: "",
			expectedRoleARN:   "",
			expectedType:      Unknown,
		},
		{
			// NOTE: The normal static-key path. Both keys are provided; no
			// role_arn. GetCredentialType returns StaticAWS because the
			// AccessKey starts with "AKIA".
			name: "static keys only",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("AKIAfoobar"),
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
				},
			},
			attrs: &CredentialAttributes{
				Region:                    "us-east-1",
				DisableCredentialRotation: true,
			},
			expectedAccessKey: "AKIAfoobar",
			expectedSecretKey: "bazqux",
			expectedRoleARN:   "",
			expectedType:      StaticAWS,
		},
		{
			// NOTE: THE BUG SCENARIO. role_arn is set (to a clearly bogus
			// value) and disable_credential_rotation is true, but no static
			// keys are provided. GetCredentialsConfig succeeds — the ARN is
			// stored in CredentialsConfig.RoleARN. GetCredentialType returns
			// DynamicAWS. However, no sts:AssumeRole call is ever made here
			// or during GenerateCredentialChain: the awsutil library skips the
			// assume-role path when AccessKey is empty and falls back to the
			// ambient credential chain instead. The bogus ARN is never
			// validated or exercised.
			name: "role_arn + no static keys (THE BUG SCENARIO)",
			attrs: &CredentialAttributes{
				Region:                    "us-east-1",
				RoleArn:                   "arn:aws:sts::000000000000:assumed-role/fake/whoever",
				DisableCredentialRotation: true,
			},
			expectedAccessKey: "",
			expectedSecretKey: "",
			expectedRoleARN:   "arn:aws:sts::000000000000:assumed-role/fake/whoever",
			expectedType:      DynamicAWS,
		},
		{
			// NOTE: role_arn is set but disable_credential_rotation is false
			// (the default). This is caught by the validation switch and
			// returns an explicit error. Validation works correctly here.
			name: "role_arn without disable_credential_rotation — validation error",
			attrs: &CredentialAttributes{
				Region:  "us-east-1",
				RoleArn: "arn:aws:iam::123456789012:role/MyRole",
			},
			expectedErrContains: "disable_credential_rotation attribute is required when providing a role_arn",
		},
		{
			// NOTE: Both role_arn and static keys are provided together. This
			// is caught by the validation switch and returns an error listing
			// all three conflicting fields. Validation works correctly here.
			name: "role_arn + static keys — conflict error",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("AKIAfoobar"),
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
				},
			},
			attrs: &CredentialAttributes{
				Region:  "us-east-1",
				RoleArn: "arn:aws:iam::123456789012:role/MyRole",
			},
			expectedErrContains: "conflicts with role_arn value",
		},
		{
			// NOTE: access_key_id is provided but secret_access_key is
			// missing. The validation switch catches the incomplete pair.
			name: "static keys — missing secret_access_key",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId: structpb.NewStringValue("AKIAfoobar"),
				},
			},
			attrs:               &CredentialAttributes{Region: "us-east-1"},
			expectedErrContains: "secrets.secret_access_key: missing required value",
		},
		{
			// NOTE: secret_access_key is provided but access_key_id is
			// missing. The validation switch catches the incomplete pair.
			name: "static keys — missing access_key_id",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
				},
			},
			attrs:               &CredentialAttributes{Region: "us-east-1"},
			expectedErrContains: "secrets.access_key_id: missing required value",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			cfg, err := GetCredentialsConfig(tc.secrets, tc.attrs, false)

			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(codes.InvalidArgument, status.Code(err))
				return
			}

			require.NoError(err)
			require.Equal(tc.expectedAccessKey, cfg.AccessKey)
			require.Equal(tc.expectedSecretKey, cfg.SecretKey)
			require.Equal(tc.expectedRoleARN, cfg.RoleARN)
			require.Equal(tc.expectedType, GetCredentialType(cfg),
				"credential type mismatch — see NOTE above the test case for why this matters")
		})
	}
}
