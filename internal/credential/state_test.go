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
	awsutilv2 "github.com/hashicorp/go-secure-stdlib/awsutil"
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
					&awsutilv2.CredentialsConfig{
						AccessKey: "foobar",
						SecretKey: "bazqux",
						Region:    "us-west-2",
					},
				),
			},
			expected: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				WithCredentialsConfig(&awsutilv2.CredentialsConfig{}),
				WithCredentialsConfig(&awsutilv2.CredentialsConfig{}),
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				testOpts: []awsutilv2.Option{
					awsutilv2.WithSTSAPIFunc(
						awsutilv2.NewMockSTS(
							awsutilv2.WithGetCallerIdentityError(errors.New(testGetCallerIdentityErr)),
						),
					),
				},
			},
			expectedErr: fmt.Sprintf("error validating credentials: %s", testGetCallerIdentityErr),
		},
		{
			name: "good",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				testOpts: []awsutilv2.Option{awsutilv2.WithSTSAPIFunc(awsutilv2.NewMockSTS())},
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
		exepected                  *awsutilv2.CredentialsConfig
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						awsutilv2.NewMockIAM(
							awsutilv2.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				},
			},
			expectedErr: fmt.Sprintf("error rotating credentials: error calling CreateAccessKey: error calling iam.GetUser: %s", testGetUserErr),
		},
		{
			name: "good",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
					Region:    "us-west-2",
				},
				testOpts: []awsutilv2.Option{
					awsutilv2.WithSTSAPIFunc(
						awsutilv2.NewMockSTS(),
					),
					awsutilv2.WithIAMAPIFunc(
						awsutilv2.NewMockIAM(
							awsutilv2.WithGetUserOutput(
								&iam.GetUserOutput{
									User: &iamTypes.User{
										Arn:      aws.String("arn:aws:iam::123456789012:user/JohnDoe"),
										UserId:   aws.String("AIDAJQABLZS4A3QDU576Q"),
										UserName: aws.String("JohnDoe"),
									},
								},
							),
							awsutilv2.WithCreateAccessKeyOutput(
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
			exepected: &awsutilv2.CredentialsConfig{
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
		credentialConfig     *awsutilv2.CredentialsConfig
		expected             *awsutilv2.CredentialsConfig
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
			credentialConfig: &awsutilv2.CredentialsConfig{},
			expectedErr:      "missing credentials config",
		},
		{
			name: "cannot delete dynamic credential type",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "ASIAfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
			},
			credentialConfig: &awsutilv2.CredentialsConfig{},
			expectedErr:      "invalid credential type",
		},
		{
			name: "cannot delete unknown credential type",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "DNEfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
			},
			credentialConfig: &awsutilv2.CredentialsConfig{},
			expectedErr:      "invalid credential type",
		},
		{
			name: "deletion error",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						awsutilv2.NewMockIAM(
							awsutilv2.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				},
			},
			credentialConfig: &awsutilv2.CredentialsConfig{},
			expectedErr:      fmt.Sprintf("error deleting old access key: %s", testDeleteAccessKeyErr),
		},
		{
			name: "good with delete of old rotated",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				CredsLastRotatedTime: time.Now(),
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						newTestMockIAM(state),
					),
				},
			},
			credentialConfig: &awsutilv2.CredentialsConfig{
				AccessKey: "one",
				SecretKey: "two",
			},
			expected: &awsutilv2.CredentialsConfig{
				AccessKey: "one",
				SecretKey: "two",
			},
			expectedDeleteCalled: true,
		},
		{
			name: "good without delete of old rotated",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						newTestMockIAM(state),
					),
				},
			},
			credentialConfig: &awsutilv2.CredentialsConfig{
				AccessKey: "one",
				SecretKey: "two",
			},
			expected: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						awsutilv2.NewMockIAM(
							awsutilv2.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				},
			},
			expectedErr: fmt.Sprintf("error deleting old access key: %s", testDeleteAccessKeyErr),
		},
		{
			name: "deletion error, but OK because key was just gone",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						awsutilv2.NewMockIAM(
							awsutilv2.WithDeleteAccessKeyError(
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIAfoobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						awsutilv2.NewMockIAM(),
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
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "foobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutilv2.Option{awsutilv2.MockOptionErr(errors.New(testOptionErr))},
			},
			expectedErr: fmt.Sprintf("error reading options in GenerateCredentialChain: %s", testOptionErr),
		},
		{
			name: "static credentials",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: &awsutilv2.CredentialsConfig{
					AccessKey: "AKIA_foobar",
					SecretKey: "bazqux",
				},
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						awsutilv2.NewMockIAM(),
					),
				},
			},
		},
		{
			name: "assume role",
			in: &AwsCredentialPersistedState{
				CredentialsConfig: func() *awsutilv2.CredentialsConfig {
					config, err := awsutilv2.NewCredentialsConfig(
						awsutilv2.WithRegion("us-west-2"),
						awsutilv2.WithRoleArn("arn:aws:iam::123456789012:role/S3Access"),
						awsutilv2.WithRoleExternalId("1234567890"),
						awsutilv2.WithRoleSessionName("assume-role"),
						awsutilv2.WithRoleTags(map[string]string{
							"foo": "bar",
						}),
					)
					require.NoError(err)
					return config
				}(),
				testOpts: []awsutilv2.Option{
					awsutilv2.WithIAMAPIFunc(
						awsutilv2.NewMockIAM(),
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

func TestHasStaticCredentials(t *testing.T) {
	require := require.New(t)
	cases := []struct {
		name      string
		accessKey string
		expected  bool
	}{
		{
			name:      "dynamic credential",
			accessKey: "ASIAEXAMPLE",
			expected:  false,
		},
		{
			name:      "static credential",
			accessKey: "AKIAEXAMPLE",
			expected:  true,
		},
		{
			name:      "other credential",
			accessKey: "EXAMPLE",
			expected:  false,
		},
		{
			name:      "empty",
			accessKey: "",
			expected:  false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(tc.expected, HasStaticCredentials(tc.accessKey))
		})
	}
}

func TestHasDynamicCredentials(t *testing.T) {
	require := require.New(t)
	cases := []struct {
		name      string
		accessKey string
		expected  bool
	}{
		{
			name:      "dynamic credential",
			accessKey: "ASIAEXAMPLE",
			expected:  true,
		},
		{
			name:      "static credential",
			accessKey: "AKIAEXAMPLE",
			expected:  false,
		},
		{
			name:      "other credential",
			accessKey: "EXAMPLE",
			expected:  false,
		},
		{
			name:      "empty",
			accessKey: "",
			expected:  false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(tc.expected, HasDynamicCredentials(tc.accessKey))
		})
	}
}
