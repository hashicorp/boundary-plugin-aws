package credential

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
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
			name: "access key id",
			opts: []AwsCredentialPersistedStateOption{
				WithAccessKeyId("foobar"),
			},
			expected: &AwsCredentialPersistedState{
				AccessKeyId: "foobar",
			},
		},
		{
			name: "secret access key",
			opts: []AwsCredentialPersistedStateOption{
				WithSecretAccessKey("bazqux"),
			},
			expected: &AwsCredentialPersistedState{
				SecretAccessKey: "bazqux",
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
			name: "region key",
			opts: []AwsCredentialPersistedStateOption{
				WithRegion("foobar"),
			},
			expected: &AwsCredentialPersistedState{
				region: "foobar",
			},
		},
		{
			name: "double set access key id",
			opts: []AwsCredentialPersistedStateOption{
				WithAccessKeyId("foobar"),
				WithAccessKeyId("onetwo"),
			},
			expectedErr: "access key id already set",
		},
		{
			name: "double set secret access key",
			opts: []AwsCredentialPersistedStateOption{
				WithSecretAccessKey("bazqux"),
				WithSecretAccessKey("threefour"),
			},
			expectedErr: "secret access key already set",
		},
		{
			name: "double set rotation time",
			opts: []AwsCredentialPersistedStateOption{
				WithCredsLastRotatedTime(staticTime),
				WithCredsLastRotatedTime(time.Now()),
			},
			expectedErr: "last rotation time already set",
		},
		{
			name: "double set region",
			opts: []AwsCredentialPersistedStateOption{
				WithRegion("foobar"),
				WithRegion("barfoo"),
			},
			expectedErr: "region already set",
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
			require.Equal(tc.expected, actual)
		})
	}
}

func TestAwsCredentialPersistedStateFromProto(t *testing.T) {
	cases := []struct {
		name        string
		in          map[string]any
		opts        []AwsCredentialPersistedStateOption
		expected    *AwsCredentialPersistedState
		expectedErr string
	}{
		{
			name:        "no secrets",
			in:          nil,
			expectedErr: "missing persisted secrets",
		},
		{
			name:        "missing access key ID",
			in:          map[string]any{},
			expectedErr: "persisted state integrity error: missing required value \"access_key_id\"",
		},
		{
			name: "missing secret access key",
			in: map[string]any{
				ConstAccessKeyId: "foobar",
			},
			expectedErr: "persisted state integrity error: missing required value \"secret_access_key\"",
		},
		{
			name: "bad last rotated time",
			in: map[string]any{
				ConstAccessKeyId:          "foobar",
				ConstSecretAccessKey:      "bazqux",
				ConstCredsLastRotatedTime: "notatime",
			},
			expectedErr: "persisted state integrity error: could not parse time in value \"creds_last_rotated_time\": parsing time \"notatime\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"notatime\" as \"2006\"",
		},
		{
			name: "option error",
			in: map[string]any{
				ConstAccessKeyId:          "foobar",
				ConstSecretAccessKey:      "bazqux",
				ConstCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
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
			in: map[string]any{
				ConstAccessKeyId:          "foobar",
				ConstSecretAccessKey:      "bazqux",
				ConstCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
			},
			expected: &AwsCredentialPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
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
			in: map[string]any{
				ConstAccessKeyId:          "foobar",
				ConstSecretAccessKey:      "bazqux",
				ConstCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
			},
			expected: &AwsCredentialPersistedState{
				AccessKeyId:          "foobar",
				SecretAccessKey:      "bazqux",
				CredsLastRotatedTime: time.Time{},
			},
		},
		{
			name: "good (ignoring non-test options)",
			in: map[string]any{
				ConstAccessKeyId:          "foobar",
				ConstSecretAccessKey:      "bazqux",
				ConstCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
			},
			opts: []AwsCredentialPersistedStateOption{
				WithAccessKeyId("ignored"),
				WithRegion("us-west-2"),
			},
			expected: &AwsCredentialPersistedState{
				AccessKeyId:          "foobar",
				SecretAccessKey:      "bazqux",
				CredsLastRotatedTime: time.Time{},
				region:               "us-west-2",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			var (
				input *structpb.Struct
				err   error
			)
			if tc.in != nil {
				input, err = structpb.NewStruct(tc.in)
				require.NoError(err)
			}

			actual, err := AwsCredentialPersistedStateFromProto(input, tc.opts...)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected.AccessKeyId, actual.AccessKeyId)
			require.Equal(tc.expected.SecretAccessKey, actual.SecretAccessKey)
			require.Equal(tc.expected.region, actual.region)
		})
	}
}

func TestAwsCatalogPersistedStateValidateCreds(t *testing.T) {
	cases := []struct {
		name        string
		in          *AwsCredentialPersistedState
		expectedErr string
	}{
		{
			name: "could not load credentials",
			in: &AwsCredentialPersistedState{
				testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
			},
			expectedErr: fmt.Sprintf("error loading credentials: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "validation error",
			in: &AwsCredentialPersistedState{
				testOpts: []awsutil.Option{awsutil.WithSTSAPIFunc(awsutil.NewMockSTS(awsutil.WithGetCallerIdentityError(errors.New(testGetCallerIdentityErr))))},
			},
			expectedErr: fmt.Sprintf("error validating credentials: %s", testGetCallerIdentityErr),
		},
		{
			name: "good",
			in: &AwsCredentialPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
				testOpts:        []awsutil.Option{awsutil.WithSTSAPIFunc(awsutil.NewMockSTS())},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			err := tc.in.ValidateCreds()
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
		})
	}
}

func TestAwsCatalogPersistedStateRotateCreds(t *testing.T) {
	cases := []struct {
		name                       string
		in                         *AwsCredentialPersistedState
		expectedAccessKeyId        string
		expectedSecretAccessKey    string
		expectedNonZeroRotatedTime bool
		expectedErr                string
	}{
		{
			name: "could not load credentials",
			in: &AwsCredentialPersistedState{
				testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
			},
			expectedErr: fmt.Sprintf("error loading credentials: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "rotation error",
			in: &AwsCredentialPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				},
			},
			expectedErr: fmt.Sprintf("error rotating credentials: error calling CreateAccessKey: error calling aws.GetUser: %s", testGetUserErr),
		},
		{
			name: "good",
			in: &AwsCredentialPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
				testOpts: []awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(),
					),
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserOutput(
								&iam.GetUserOutput{
									User: &iam.User{
										Arn:      aws.String("arn:aws:iam::123456789012:user/JohnDoe"),
										UserId:   aws.String("AIDAJQABLZS4A3QDU576Q"),
										UserName: aws.String("JohnDoe"),
									},
								},
							),
							awsutil.WithCreateAccessKeyOutput(
								&iam.CreateAccessKeyOutput{
									AccessKey: &iam.AccessKey{
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
			expectedAccessKeyId:        "one",
			expectedSecretAccessKey:    "two",
			expectedNonZeroRotatedTime: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			err := tc.in.RotateCreds()
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expectedAccessKeyId, tc.in.AccessKeyId)
			require.Equal(tc.expectedSecretAccessKey, tc.in.SecretAccessKey)
			require.Equal(tc.expectedNonZeroRotatedTime, !tc.in.CredsLastRotatedTime.IsZero())
		})
	}
}

func TestAwsCatalogPersistedStateReplaceCreds(t *testing.T) {
	// NOTE: Not safe to run this test in parallel
	state := new(testMockIAMState)
	cases := []struct {
		name                    string
		in                      *AwsCredentialPersistedState
		accessKeyId             string
		secretAccessKey         string
		expectedAccessKeyId     string
		expectedSecretAccessKey string
		expectedDeleteCalled    bool
		expectedErr             string
	}{
		{
			name:        "missing access key id",
			in:          &AwsCredentialPersistedState{},
			expectedErr: "access key id cannot be empty",
		},
		{
			name:        "missing access key id",
			in:          &AwsCredentialPersistedState{},
			accessKeyId: "one",
			expectedErr: "secret access key cannot be empty",
		},
		{
			name: "identical access key id",
			in: &AwsCredentialPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
			},
			accessKeyId:     "foobar",
			secretAccessKey: "bazqux",
			expectedErr:     "attempting to replace access key with the same one",
		},
		{
			name: "deletion error",
			in: &AwsCredentialPersistedState{
				AccessKeyId:          "foobar",
				SecretAccessKey:      "bazqux",
				CredsLastRotatedTime: time.Now(),
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				},
			},
			accessKeyId:     "one",
			secretAccessKey: "two",
			expectedErr:     fmt.Sprintf("error deleting old access key: %s", testDeleteAccessKeyErr),
		},
		{
			name: "good with delete of old rotated",
			in: &AwsCredentialPersistedState{
				AccessKeyId:          "foobar",
				SecretAccessKey:      "bazqux",
				CredsLastRotatedTime: time.Now(),
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						newTestMockIAM(state),
					),
				},
			},
			accessKeyId:             "one",
			secretAccessKey:         "two",
			expectedAccessKeyId:     "one",
			expectedSecretAccessKey: "two",
			expectedDeleteCalled:    true,
		},
		{
			name: "good without delete of old rotated",
			in: &AwsCredentialPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						newTestMockIAM(state),
					),
				},
			},
			accessKeyId:             "one",
			secretAccessKey:         "two",
			expectedAccessKeyId:     "one",
			expectedSecretAccessKey: "two",
			expectedDeleteCalled:    false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			state.Reset()
			err := tc.in.ReplaceCreds(tc.accessKeyId, tc.secretAccessKey)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expectedAccessKeyId, tc.in.AccessKeyId)
			require.Equal(tc.expectedSecretAccessKey, tc.in.SecretAccessKey)
			require.Zero(tc.in.CredsLastRotatedTime)
			require.Equal(tc.expectedDeleteCalled, state.DeleteAccessKeyCalled)
		})
	}
}

func TestAwsCatalogPersistedStateDeleteCreds(t *testing.T) {
	cases := []struct {
		name        string
		in          *AwsCredentialPersistedState
		expectedErr string
	}{
		{
			name: "could not load credentials",
			in: &AwsCredentialPersistedState{
				testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
			},
			expectedErr: fmt.Sprintf("error loading credentials: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "deletion error",
			in: &AwsCredentialPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
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
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
				testOpts: []awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(
								awserr.New(iam.ErrCodeNoSuchEntityException, "", nil),
							),
						),
					),
				},
			},
		},
		{
			name: "good",
			in: &AwsCredentialPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
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
			err := tc.in.DeleteCreds()
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Empty(tc.in.AccessKeyId)
			require.Empty(tc.in.SecretAccessKey)
			require.Zero(tc.in.CredsLastRotatedTime)
		})
	}
}

func TestAwsCatalogPersistedStateGetSessionErr(t *testing.T) {
	require := require.New(t)
	state := &AwsCredentialPersistedState{
		testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
	}

	_, err := state.GetSession()
	require.EqualError(err, fmt.Sprintf("error reading options in NewCredentialsConfig: %s", testOptionErr))
}
