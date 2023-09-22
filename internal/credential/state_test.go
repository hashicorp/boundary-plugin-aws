// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestNewAwsCredentialPersistedState(t *testing.T) {
	staticTime := time.Now()

	cases := []struct {
		name        string
		opts        []AwsCredentialPersistedStateOption
		expected    *AwsCredentialPersistedState
		expectedErr string
	}{
		{
			name: "error",
			opts: []AwsCredentialPersistedStateOption{
				func(s *AwsCredentialPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErr: testOptionErr,
		},
		{
			name: "with credentials config",
			opts: []AwsCredentialPersistedStateOption{
				WithCredentialsConfig(
					&awsutil.CredentialsConfig{
						AccessKey: "foobar",
						SecretKey: "bazqux",
						Region:    "us-west-2",
					},
				),
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
			},
		},
		{
			name: "rotation time",
			opts: []AwsCredentialPersistedStateOption{
				WithCredsLastRotatedTime(staticTime),
			},
			expected: &AwsCredentialPersistedState{
				CredsLastRotatedTime: staticTime,
			},
		},
		{
			name: "double set credentials config",
			opts: []AwsCredentialPersistedStateOption{
				WithCredentialsConfig(&awsutil.CredentialsConfig{}),
				WithCredentialsConfig(&awsutil.CredentialsConfig{}),
			},
			expectedErr: "credentials config already set",
		},
		{
			name: "double set rotation time",
			opts: []AwsCredentialPersistedStateOption{
				WithCredsLastRotatedTime(staticTime),
				WithCredsLastRotatedTime(time.Now()),
			},
			expectedErr: "last rotation time already set",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := NewAwsCredentialPersistedState(tc.opts...)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected.CredsLastRotatedTime, actual.CredsLastRotatedTime)
			if tc.expected.CredentialsConfig != nil {
				require.NotNil(actual.CredentialsConfig)
				require.Equal(tc.expected.CredentialsConfig.AccessKey, actual.CredentialsConfig.AccessKey)
				require.Equal(tc.expected.CredentialsConfig.SecretKey, actual.CredentialsConfig.SecretKey)
				require.Equal(tc.expected.CredentialsConfig.Region, actual.CredentialsConfig.Region)
			}
		})
	}
}

func TestAwsCredentialPersistedStateFromProto(t *testing.T) {
	cases := []struct {
		name        string
		secrets     *structpb.Struct
		attrs       *CredentialAttributes
		opts        []AwsCredentialPersistedStateOption
		expected    *AwsCredentialPersistedState
		expectedErr string
	}{
		{
			name:        "missing credential attributes",
			expectedErr: "missing credential attributes",
		},
		{
			name: "missing secrets",
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					Region: "us-west-2",
				},
			},
		},
		{
			name:    "missing long-term access key id",
			secrets: &structpb.Struct{},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					Region: "us-west-2",
				},
			},
		},
		{
			name:    "missing long-term secret access key",
			secrets: &structpb.Struct{},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					Region: "us-west-2",
				},
			},
		},
		{
			name: "with long-term static credentials",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("foobar"),
					ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					Region:    "us-west-2",
					AccessKey: "foobar",
					SecretKey: "bazqux",
				},
			},
		},
		{
			name: "bad last rotated time",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:          structpb.NewStringValue("foobar"),
					ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
					ConstCredsLastRotatedTime: structpb.NewStringValue("notatime"),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expectedErr: "persisted state integrity error: could not parse time in value \"creds_last_rotated_time\": parsing time \"notatime\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"notatime\" as \"2006\"",
		},
		{
			name: "option error",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:          structpb.NewStringValue("foobar"),
					ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
					ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			opts: []AwsCredentialPersistedStateOption{
				func(s *AwsCredentialPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErr: testOptionErr,
		},
		{
			name: "good with non-zero timestamp",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:          structpb.NewStringValue("foobar"),
					ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
					ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				CredsLastRotatedTime: func() time.Time {
					t, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")
					if err != nil {
						panic(err)
					}
					return t
				}(),
			},
		},
		{
			name: "good with zero timestamp",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:          structpb.NewStringValue("foobar"),
					ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
					ConstCredsLastRotatedTime: structpb.NewStringValue((time.Time{}).Format(time.RFC3339Nano)),
				},
			},
			attrs: &CredentialAttributes{
				Region: "us-west-2",
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				CredsLastRotatedTime: time.Time{},
			},
		},
		{
			name: "with assume role",
			attrs: &CredentialAttributes{
				Region:          "us-west-2",
				RoleArn:         "arn:aws:iam::123456789012:role/S3Access",
				RoleExternalId:  "1234567890",
				RoleSessionName: "test-session",
				RoleTags: map[string]string{
					"foo": "bar",
				},
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					Region:          "us-west-2",
					RoleARN:         "arn:aws:iam::123456789012:role/S3Access",
					RoleExternalId:  "1234567890",
					RoleSessionName: "test-session",
					RoleTags: map[string]string{
						"foo": "bar",
					},
				},
			},
		},
		{
			name: "with assume role & static credentials",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:          structpb.NewStringValue("foobar"),
					ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
					ConstCredsLastRotatedTime: structpb.NewStringValue((time.Time{}).Format(time.RFC3339Nano)),
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
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey:       "foobar",
					SecretKey:       "bazqux",
					Region:          "us-west-2",
					RoleARN:         "arn:aws:iam::123456789012:role/S3Access",
					RoleExternalId:  "1234567890",
					RoleSessionName: "test-session",
					RoleTags: map[string]string{
						"foo": "bar",
					},
				},
				CredsLastRotatedTime: time.Time{},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			actual, err := AwsCredentialPersistedStateFromProto(tc.secrets, tc.attrs, tc.opts...)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.NotNil(actual)
			require.Equal(tc.expected.CredsLastRotatedTime, actual.CredsLastRotatedTime)
			if tc.expected.CredentialsConfig != nil {
				require.NotNil(actual.CredentialsConfig)
				require.Equal(tc.expected.CredentialsConfig.AccessKey, actual.CredentialsConfig.AccessKey)
				require.Equal(tc.expected.CredentialsConfig.SecretKey, actual.CredentialsConfig.SecretKey)
				require.Equal(tc.expected.CredentialsConfig.Region, actual.CredentialsConfig.Region)
				require.Equal(tc.expected.CredentialsConfig.RoleARN, actual.CredentialsConfig.RoleARN)
				require.Equal(tc.expected.CredentialsConfig.RoleExternalId, actual.CredentialsConfig.RoleExternalId)
				require.Equal(tc.expected.CredentialsConfig.RoleSessionName, actual.CredentialsConfig.RoleSessionName)
				require.Equal(tc.expected.CredentialsConfig.RoleTags, actual.CredentialsConfig.RoleTags)
			}
		})
	}
}

func TestAwsCatalogPersistedState_ValidateCreds(t *testing.T) {
	cases := []struct {
		name        string
		in          *AwsCredentialPersistedState
		expectedErr string
	}{
		{
			name:        "missing credentials config",
			in:          &AwsCredentialPersistedState{},
			expectedErr: "missing credentials config",
		},
		{
			name: "validation error",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				testOpts: []awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(
							awsutil.WithGetCallerIdentityError(errors.New(testGetCallerIdentityErr)),
						),
					),
				},
			},
			expectedErr: fmt.Sprintf("error validating credentials: %s", testGetCallerIdentityErr),
		},
		{
			name: "good",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				testOpts: []awsutil.Option{awsutil.WithSTSAPIFunc(awsutil.NewMockSTS())},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			err := tc.in.ValidateCreds(context.Background())
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
		})
	}
}

func TestAwsCatalogPersistedState_RotateCreds(t *testing.T) {
	cases := []struct {
		name                       string
		in                         *AwsCredentialPersistedState
		exepected                  *awsutil.CredentialsConfig
		expectedNonZeroRotatedTime bool
		expectedErr                string
	}{
		{
			name:        "missing credentials config",
			in:          &AwsCredentialPersistedState{},
			expectedErr: "missing credentials config",
		},
		{
			name: "cannot delete dynamic credential type",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "ASIAfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
			},
			expectedErr: "invalid credential type",
		},
		{
			name: "cannot delete unknown credential type",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "DNEfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
			},
			expectedErr: "invalid credential type",
		},
		{
			name: "rotation error",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				},
			},
			expectedErr: fmt.Sprintf("error rotating credentials: error calling CreateAccessKey: error calling iam.GetUser: %s", testGetUserErr),
		},
		{
			name: "good",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				testOpts: []awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(),
					),
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserOutput(
								&iam.GetUserOutput{
									User: &iamTypes.User{
										Arn:      aws.String("arn:aws:iam::123456789012:user/JohnDoe"),
										UserId:   aws.String("AIDAJQABLZS4A3QDU576Q"),
										UserName: aws.String("JohnDoe"),
									},
								},
							),
							awsutil.WithCreateAccessKeyOutput(
								&iam.CreateAccessKeyOutput{
									AccessKey: &iamTypes.AccessKey{
										AccessKeyId:     aws.String("one"),
										SecretAccessKey: aws.String("two"),
										UserName:        aws.String("JohnDoe"),
									},
								},
							),
						),
					),
				},
			},
			exepected: &awsutil.CredentialsConfig{
				AccessKey: "one",
				SecretKey: "two",
				Region:    "us-west-2",
			},
			expectedNonZeroRotatedTime: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			err := tc.in.RotateCreds(context.Background())
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.exepected.AccessKey, tc.in.CredentialsConfig.AccessKey)
			require.Equal(tc.exepected.SecretKey, tc.in.CredentialsConfig.SecretKey)
			require.Equal(tc.expectedNonZeroRotatedTime, !tc.in.CredsLastRotatedTime.IsZero())
		})
	}
}

func TestAwsCatalogPersistedState_ReplaceCreds(t *testing.T) {
	// NOTE: Not safe to run this test in parallel
	state := new(testMockIAMState)
	cases := []struct {
		name                 string
		in                   *AwsCredentialPersistedState
		credentialConfig     *awsutil.CredentialsConfig
		expected             *awsutil.CredentialsConfig
		expectedDeleteCalled bool
		expectedErr          string
	}{
		{
			name:        "missing new credentials config",
			in:          &AwsCredentialPersistedState{},
			expectedErr: "missing new credentials config",
		},
		{
			name:             "missing credentials config",
			in:               &AwsCredentialPersistedState{},
			credentialConfig: &awsutil.CredentialsConfig{},
			expectedErr:      "missing credentials config",
		},
		{
			name: "deletion error",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				},
			},
			credentialConfig: &awsutil.CredentialsConfig{},
			expectedErr:      fmt.Sprintf("error deleting old access key: %s", testDeleteAccessKeyErr),
		},
		{
			name: "good with delete of old rotated",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						newTestMockIAM(state),
					),
				},
			},
			credentialConfig: &awsutil.CredentialsConfig{
				AccessKey: "one",
				SecretKey: "two",
			},
			expected: &awsutil.CredentialsConfig{
				AccessKey: "one",
				SecretKey: "two",
			},
			expectedDeleteCalled: true,
		},
		{
			name: "good without delete of old rotated",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						newTestMockIAM(state),
					),
				},
			},
			credentialConfig: &awsutil.CredentialsConfig{
				AccessKey: "one",
				SecretKey: "two",
			},
			expected: &awsutil.CredentialsConfig{
				AccessKey: "one",
				SecretKey: "two",
			},
			expectedDeleteCalled: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			state.Reset()
			err := tc.in.ReplaceCreds(context.Background(), tc.credentialConfig)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected.AccessKey, tc.in.CredentialsConfig.AccessKey)
			require.Equal(tc.expected.SecretKey, tc.in.CredentialsConfig.SecretKey)
			require.Zero(tc.in.CredsLastRotatedTime)
			require.Equal(tc.expectedDeleteCalled, state.DeleteAccessKeyCalled)
		})
	}
}

func TestAwsCatalogPersistedState_DeleteCreds(t *testing.T) {
	cases := []struct {
		name        string
		in          *AwsCredentialPersistedState
		expectedErr string
	}{
		{
			name:        "missing credentials config",
			in:          &AwsCredentialPersistedState{},
			expectedErr: "missing credentials config",
		},
		{
			name: "cannot delete dynamic credential type",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "ASIAfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
			},
			expectedErr: "invalid credential type",
		},
		{
			name: "cannot delete unknown credential type",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "DNEfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
			},
			expectedErr: "invalid credential type",
		},
		{
			name: "deletion error",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				},
			},
			expectedErr: fmt.Sprintf("error deleting old access key: %s", testDeleteAccessKeyErr),
		},
		{
			name: "deletion error, but OK because key was just gone",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(
								&iamTypes.NoSuchEntityException{},
							),
						),
					),
				},
			},
		},
		{
			name: "good",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(),
					),
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			err := tc.in.DeleteCreds(context.Background())
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Nil(tc.in.CredentialsConfig)
			require.Zero(tc.in.CredsLastRotatedTime)
		})
	}
}

func TestAwsCatalogPersistedState_GenerateCredentialChain(t *testing.T) {
	require := require.New(t)
	cases := []struct {
		name        string
		in          *AwsCredentialPersistedState
		expectedErr string
	}{
		{
			name: "error",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
			},
			expectedErr: fmt.Sprintf("error reading options in GenerateCredentialChain: %s", testOptionErr),
		},
		{
			name: "static credentials",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutil.CredentialsConfig{
					AccessKey: "AKIA_foobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(),
					),
				},
			},
		},
		{
			name: "assume role",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: func() *awsutil.CredentialsConfig {
					config, err := awsutil.NewCredentialsConfig(
						awsutil.WithRegion("us-west-2"),
						awsutil.WithRoleArn("arn:aws:iam::123456789012:role/S3Access"),
						awsutil.WithRoleExternalId("1234567890"),
						awsutil.WithRoleSessionName("assume-role"),
						awsutil.WithRoleTags(map[string]string{
							"foo": "bar",
						}),
					)
					require.NoError(err)
					return config
				}(),
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(),
					),
				},
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.in.GenerateCredentialChain(context.Background())
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}
			require.NoError(err)
		})
	}
}

func TestGetCredentialType(t *testing.T) {
	tests := []struct {
		name             string
		credConfig       *awsutil.CredentialsConfig
		expectedCredType CredentialType
	}{
		{
			name:             "nil credential config",
			credConfig:       nil,
			expectedCredType: Unknown,
		},
		{
			name:             "empty credential config",
			credConfig:       &awsutil.CredentialsConfig{},
			expectedCredType: Unknown,
		},
		{
			name:             "static aws",
			credConfig:       &awsutil.CredentialsConfig{AccessKey: "AKIAfoobar"},
			expectedCredType: StaticAWS,
		},
		{
			name:             "static other",
			credConfig:       &awsutil.CredentialsConfig{AccessKey: "cK3kNFa24foobar"},
			expectedCredType: StaticOther,
		},
		{
			name:             "dynamic aws - role arn",
			credConfig:       &awsutil.CredentialsConfig{RoleARN: "arn:aws:iam::123456789012:role/S3Access"},
			expectedCredType: DynamicAWS,
		},
		{
			name:             "dynamic aws - access key",
			credConfig:       &awsutil.CredentialsConfig{AccessKey: "ASIAfoobar"},
			expectedCredType: DynamicAWS,
		},
		{
			name:             "dynamic aws - role arn and access key",
			credConfig:       &awsutil.CredentialsConfig{AccessKey: "ASIAfoobar", RoleARN: "arn:aws:iam::123456789012:role/S3Access"},
			expectedCredType: DynamicAWS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct := GetCredentialType(tc.credConfig)
			require.Equal(t, tc.expectedCredType, ct)
		})
	}
}
