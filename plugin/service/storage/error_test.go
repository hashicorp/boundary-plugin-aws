package storage

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/hashicorp/boundary-plugin-aws/internal/errors"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func Test_ParseS3Error(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                string
		err                 error
		expectedStatusCode  codes.Code
		expectedStatusMsg   string
		expectedPluginError *pb.PluginError
	}{
		{
			name:               "nil-error",
			expectedStatusCode: codes.OK,
		},
		{
			name: "no-such-bucket",
			err: &types.NoSuchBucket{
				Message: aws.String("no such bucket"),
			},
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws s3 error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_STORAGE_NO_SUCH_BUCKET,
				Message:      "no such bucket",
				Nonretryable: true,
			},
		},
		{
			name: "no-such-key",
			err: &types.NoSuchKey{
				Message: aws.String("no such key"),
			},
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws s3 error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_STORAGE_NO_SUCH_OBJECT,
				Message:      "no such key",
				Nonretryable: true,
			},
		},
		{
			name: "not-found",
			err: &types.NotFound{
				Message: aws.String("not found"),
			},
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws s3 error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_STORAGE_NO_SUCH_OBJECT,
				Message:      "not found",
				Nonretryable: true,
			},
		},
		{
			name: "invalid-object-state",
			err: &types.InvalidObjectState{
				Message: aws.String("invalid object state"),
			},
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws s3 error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_STORAGE_NO_SUCH_OBJECT,
				Message:      "invalid object state",
				Nonretryable: true,
			},
		},
		{
			name:               "bad-digest",
			err:                errors.TestAwsError(s3ErrorBadDigest, "checksum mismatch"),
			expectedStatusCode: codes.Aborted,
			expectedStatusMsg:  "aws s3 error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_STORAGE_CHECKSUM_MISMATCH,
				Message:      "checksum mismatch",
				Nonretryable: false,
			},
		},
		{
			name:               "fallback-throttle-error",
			err:                TestAwsS3Error("Throttling", "throttling exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service s3: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "throttling exception",
				Nonretryable: false,
			},
		},
		{
			name:               "fallback-connectivity-error",
			err:                TestAwsS3Error("RequestTimeout", "request timeout"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service s3: connectivity error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_TIMEOUT,
				Message:      "request timeout",
				Nonretryable: false,
			},
		},
		{
			name:               "fallback-credentials-error",
			err:                TestAwsS3Error("AccessDenied", "access denied"),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service s3: invalid credentials error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_INVALID_CREDENTIAL,
				Message:      "access denied",
				Nonretryable: true,
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)

			actualStatus := parseS3Error(tt.err, "test")
			if tt.expectedStatusCode == codes.OK {
				require.Nil(actualStatus)
				return
			}

			require.Equal(tt.expectedStatusCode, actualStatus.Code())
			require.Equal(tt.expectedStatusMsg, actualStatus.Message())
			require.Len(actualStatus.Details(), 1)
			for _, detail := range actualStatus.Details() {
				switch errDetail := detail.(type) {
				case *pb.PluginError:
					require.Equal(tt.expectedPluginError.Code, errDetail.Code)
					require.Contains(errDetail.Message, tt.expectedPluginError.Message)
					require.Equal(tt.expectedPluginError.Nonretryable, errDetail.Nonretryable)
				}
			}
		})
	}
}
