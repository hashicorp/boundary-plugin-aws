package storage

import (
	"testing"

	"github.com/hashicorp/boundary-plugin-aws/internal/errors"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_ParseS3Error(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name               string
		req                any
		err                error
		expectedStatusCode codes.Code
		expectedStatusMsg  string
		expectedDetails    *pb.StorageBucketCredentialState
	}{
		{
			name:               "nil-error",
			expectedStatusCode: codes.OK,
		},
		{
			name:               "no-such-bucket",
			req:                &pb.GetObjectRequest{},
			err:                TestAwsS3Error("NoSuchBucket", "GetObject", "no such bucket"),
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws s3 error: test",
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "no such bucket",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:               "no-such-key",
			req:                &pb.GetObjectRequest{},
			err:                TestAwsS3Error("NoSuchKey", "GetObject", "no such key"),
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws s3 error: test",
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:               "not-found",
			req:                &pb.GetObjectRequest{},
			err:                errors.TestAwsHttpResponseError(404, "not found"),
			expectedStatusCode: codes.NotFound,
			// cannot embed services within mock http errors, therefore unknown service
			expectedStatusMsg: "aws service unknown: resource not found error: test",
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:               "invalid-object-state",
			req:                &pb.GetObjectRequest{},
			err:                TestAwsS3Error("InvalidObjectState", "GetObject", "invalid object state"),
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws s3 error: test",
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:               "bad-digest",
			req:                &pb.PutObjectRequest{},
			err:                TestAwsS3Error(s3ErrorBadDigest, "PutObject", "checksum mismatch"),
			expectedStatusCode: codes.Aborted,
			expectedStatusMsg:  "aws s3 error: test",
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:               "fallback-throttle-error",
			req:                &pb.GetObjectRequest{},
			err:                TestAwsS3Error("Throttling", "action", "throttling exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service s3: throttling error: test",
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:               "fallback-connectivity-error",
			req:                &pb.GetObjectRequest{},
			err:                TestAwsS3Error("RequestTimeout", "action", "request timeout"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service s3: connectivity error: test",
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:               "fallback-credentials-error",
			req:                &pb.GetObjectRequest{},
			err:                TestAwsS3Error("AccessDenied", "action", "access denied"),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service s3: invalid credentials error: test",
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "access denied",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			actualStatus := parseS3Error(tt.err, "test", tt.req)
			if tt.expectedStatusCode == codes.OK {
				require.Nil(actualStatus)
				return
			}

			require.Equal(tt.expectedStatusCode, actualStatus.Code())
			require.Equal(tt.expectedStatusMsg, actualStatus.Message())
			require.Len(actualStatus.Details(), 1)

			foundDetail := false
			for _, detail := range actualStatus.Details() {
				switch errDetail := detail.(type) {
				case *pb.StorageBucketCredentialState:
					foundDetail = true
					errors.CheckSimilarPermission(assert, tt.expectedDetails.State.Read, errDetail.State.Read, false)
					errors.CheckSimilarPermission(assert, tt.expectedDetails.State.Write, errDetail.State.Write, false)
					errors.CheckSimilarPermission(assert, tt.expectedDetails.State.Delete, errDetail.State.Delete, false)
				}
			}
			require.True(foundDetail, "did not find error details with status")
		})
	}
}
