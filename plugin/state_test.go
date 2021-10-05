package plugin

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/stretchr/testify/require"
)

const testOptionErr = "test option error"
const testGetCallerIdentityErr = "test error for GetCallerIdentity"
const testGetUserErr = "test error for GetUser"
const testDeleteAccessKeyErr = "test error for DeleteAccessKey"

func TestAwsCatalogPersistedStateFromProto(t *testing.T) {
	cases := []struct {
		name        string
		in          *pb.HostCatalogPersisted
		expected    *awsCatalogPersistedState
		expectedErr string
	}{
		{
			name: "no secrets",
			in: &pb.HostCatalogPersisted{
				Secrets: nil,
			},
			expectedErr: "missing persisted secrets",
		},
		{
			name: "missing access key ID",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(nil),
			},
			expectedErr: "persisted state integrity error: missing required value \"access_key_id\"",
		},
		{
			name: "missing secret access key",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId: "foobar",
				}),
			},
			expectedErr: "persisted state integrity error: missing required value \"secret_access_key\"",
		},
		{
			name: "bad last rotated time",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId:          "foobar",
					constSecretAccessKey:      "bazqux",
					constCredsLastRotatedTime: "notatime",
				}),
			},
			expectedErr: "persisted state integrity error: could not parse time in value \"creds_last_rotated_time\": parsing time \"notatime\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"notatime\" as \"2006\"",
		},
		{
			name: "good with non-zero timestamp",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId:          "foobar",
					constSecretAccessKey:      "bazqux",
					constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
				}),
			},
			expected: &awsCatalogPersistedState{
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
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId:          "foobar",
					constSecretAccessKey:      "bazqux",
					constCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
				}),
			},
			expected: &awsCatalogPersistedState{
				AccessKeyId:          "foobar",
				SecretAccessKey:      "bazqux",
				CredsLastRotatedTime: time.Time{},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := awsCatalogPersistedStateFromProto(tc.in)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestAwsCatalogPersistedStateToProto(t *testing.T) {
	cases := []struct {
		name        string
		in          *awsCatalogPersistedState
		expected    *pb.HostCatalogPersisted
		expectedErr string // NOTE: Here for scaffolding but hard to test deep structpb err right now
	}{
		{
			name: "good with non-zero timestamp",
			in: &awsCatalogPersistedState{
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
			expected: &pb.HostCatalogPersisted{
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId:          "foobar",
					constSecretAccessKey:      "bazqux",
					constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
				}),
			},
		},
		{
			name: "good with zero timestamp",
			in: &awsCatalogPersistedState{
				AccessKeyId:          "foobar",
				SecretAccessKey:      "bazqux",
				CredsLastRotatedTime: time.Time{},
			},
			expected: &pb.HostCatalogPersisted{
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId:          "foobar",
					constSecretAccessKey:      "bazqux",
					constCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
				}),
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := tc.in.ToProto()
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestAwsCatalogPersistedStateValidateCreds(t *testing.T) {
	cases := []struct {
		name        string
		in          *awsCatalogPersistedState
		expectedErr string
	}{
		{
			name: "could not load credentials",
			in: &awsCatalogPersistedState{
				testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
			},
			expectedErr: fmt.Sprintf("error loading credentials: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "validation error",
			in: &awsCatalogPersistedState{
				testOpts: []awsutil.Option{awsutil.WithSTSAPIFunc(awsutil.NewMockSTS(awsutil.WithGetCallerIdentityError(errors.New(testGetCallerIdentityErr))))},
			},
			expectedErr: fmt.Sprintf("error validating credentials: %s", testGetCallerIdentityErr),
		},
		{
			name: "good",
			in: &awsCatalogPersistedState{
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
		in                         *awsCatalogPersistedState
		expectedAccessKeyId        string
		expectedSecretAccessKey    string
		expectedNonZeroRotatedTime bool
		expectedErr                string
	}{
		{
			name: "could not load credentials",
			in: &awsCatalogPersistedState{
				testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
			},
			expectedErr: fmt.Sprintf("error loading credentials: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "rotation error",
			in: &awsCatalogPersistedState{
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
			in: &awsCatalogPersistedState{
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
		in                      *awsCatalogPersistedState
		accessKeyId             string
		secretAccessKey         string
		expectedAccessKeyId     string
		expectedSecretAccessKey string
		expectedDeleteCalled    bool
		expectedErr             string
	}{
		{
			name:        "missing access key id",
			in:          &awsCatalogPersistedState{},
			expectedErr: "access key id cannot be empty",
		},
		{
			name:        "missing access key id",
			in:          &awsCatalogPersistedState{},
			accessKeyId: "one",
			expectedErr: "secret access key cannot be empty",
		},
		{
			name: "identical access key id",
			in: &awsCatalogPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
			},
			accessKeyId:     "foobar",
			secretAccessKey: "bazqux",
			expectedErr:     "attempting to replace access key with the same one",
		},
		{
			name: "deletion error",
			in: &awsCatalogPersistedState{
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
			expectedErr:     fmt.Sprintf("error deleting old access key: error deleting old access key: %s", testDeleteAccessKeyErr),
		},
		{
			name: "good with delete of old rotated",
			in: &awsCatalogPersistedState{
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
			in: &awsCatalogPersistedState{
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
		in          *awsCatalogPersistedState
		expectedErr string
	}{
		{
			name: "could not load credentials",
			in: &awsCatalogPersistedState{
				testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
			},
			expectedErr: fmt.Sprintf("error loading credentials: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "deletion error",
			in: &awsCatalogPersistedState{
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
			expectedErr: fmt.Sprintf("error deleting old access key: error deleting old access key: %s", testDeleteAccessKeyErr),
		},
		{
			name: "deletion error, but OK because key was just gone",
			in: &awsCatalogPersistedState{
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
			in: &awsCatalogPersistedState{
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
	state := &awsCatalogPersistedState{
		testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
	}

	_, err := state.GetSession()
	require.EqualError(err, fmt.Sprintf("error reading options in NewCredentialsConfig: %s", testOptionErr))
}

func TestAwsCatalogPersistedStateEC2ClientErr(t *testing.T) {
	require := require.New(t)
	state := &awsCatalogPersistedState{
		testOpts: []awsutil.Option{awsutil.MockOptionErr(errors.New(testOptionErr))},
	}

	_, err := state.EC2Client("someregion")
	require.EqualError(err, fmt.Sprintf("error getting AWS session: error reading options in NewCredentialsConfig: %s", testOptionErr))
}
