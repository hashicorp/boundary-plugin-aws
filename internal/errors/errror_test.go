package errors

import (
	"fmt"
	"testing"

	"net/http"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func Test_ParseAWSError(t *testing.T) {
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
			name:               "default-to-unknwon",
			err:                fmt.Errorf("what can this error be?"),
			expectedStatusCode: codes.Unknown,
			expectedStatusMsg:  "aws service unknown: unknown error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_UNKNOWN,
				Message:      "what can this error be?",
				Nonretryable: false,
			},
		},
		{
			name:               "http-status-code-bad-request",
			err:                TestAwsHttpResponseError(http.StatusBadRequest, "bad request"),
			expectedStatusCode: codes.InvalidArgument,
			expectedStatusMsg:  "aws service unknown: bad request error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_BAD_REQUEST,
				Message:      "bad request",
				Nonretryable: true,
			},
		},
		{
			name:               "http-status-code-unauthorized",
			err:                TestAwsHttpResponseError(http.StatusUnauthorized, "unauthorized request"),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_INVALID_CREDENTIAL,
				Message:      "unauthorized request",
				Nonretryable: false,
			},
		},
		{
			name:               "http-status-code-forbidden",
			err:                TestAwsHttpResponseError(http.StatusForbidden, "forbidden request"),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_INVALID_CREDENTIAL,
				Message:      "forbidden request",
				Nonretryable: true,
			},
		},
		{
			name:               "http-status-code-not-found",
			err:                TestAwsHttpResponseError(http.StatusNotFound, "not found request"),
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws service unknown: resource not found error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_BAD_REQUEST,
				Message:      "not found request",
				Nonretryable: true,
			},
		},
		{
			name:               "http-status-code-too-many-requests",
			err:                TestAwsHttpResponseError(http.StatusTooManyRequests, "too many requests"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "too many requests",
				Nonretryable: false,
			},
		},
		{
			name:               "http-status-code-request-timeout",
			err:                TestAwsHttpResponseError(http.StatusRequestTimeout, "request timeout"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: connectivity error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_TIMEOUT,
				Message:      "request timeout",
				Nonretryable: false,
			},
		},
		{
			name:               "http-status-code-internal-server-error",
			err:                TestAwsHttpResponseError(http.StatusInternalServerError, "internal server error"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: connectivity error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_TIMEOUT,
				Message:      "https response error StatusCode: 500",
				Nonretryable: false,
			},
		},
		{
			name:               "http-status-code-bad-gateway",
			err:                TestAwsHttpResponseError(http.StatusBadGateway, "bad gateway"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: connectivity error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_TIMEOUT,
				Message:      "https response error StatusCode: 502",
				Nonretryable: false,
			},
		},
		{
			name:               "http-status-code-service-unavailable",
			err:                TestAwsHttpResponseError(http.StatusServiceUnavailable, "service unavailable"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: connectivity error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_TIMEOUT,
				Message:      "https response error StatusCode: 503",
				Nonretryable: false,
			},
		},
		{
			name:               "http-status-code-gateway-timeout",
			err:                TestAwsHttpResponseError(http.StatusGatewayTimeout, "gateway timeout"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: connectivity error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_TIMEOUT,
				Message:      "https response error StatusCode: 504",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-throttling",
			err:                TestAwsError("Throttling", "throttling error"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "throttling error",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-throttling-exception",
			err:                TestAwsError("ThrottlingException", "throttling exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "throttling exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-throttled-exception",
			err:                TestAwsError("ThrottledException", "throttled exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "throttled exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-throttled-exception",
			err:                TestAwsError("RequestThrottledException", "request throttled exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "request throttled exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-too-many-requests-exception",
			err:                TestAwsError("TooManyRequestsException", "too many requests exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "too many requests exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-provisioned-throughput-exceeded-exception",
			err:                TestAwsError("ProvisionedThroughputExceededException", "provisioned throughput exceeded exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "provisioned throughput exceeded exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-transaction-in-progress-exception",
			err:                TestAwsError("TransactionInProgressException", "transaction in progress exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "transaction in progress exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-limit-exceeded",
			err:                TestAwsError("RequestLimitExceeded", "request limit exceeded"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "request limit exceeded",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-bandwidth-limit-exceeded",
			err:                TestAwsError("BandwidthLimitExceeded", "bandwidth limit exceeded"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "bandwidth limit exceeded",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-limit-exceeded-exception",
			err:                TestAwsError("LimitExceededException", "limit exceeded exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "limit exceeded exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-throttled",
			err:                TestAwsError("RequestThrottled", "request throttled"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "request throttled",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-slow-down",
			err:                TestAwsError("SlowDown", "slow down"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "slow down",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-prior-request-not-complete",
			err:                TestAwsError("PriorRequestNotComplete", "prior request not complete"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "prior request not complete",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-ec2-throttled-exception",
			err:                TestAwsError("EC2ThrottledException", "ec2 throttled exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_THROTTLING,
				Message:      "ec2 throttled exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-timeout",
			err:                TestAwsError("RequestTimeout", "request timeout"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: connectivity error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_TIMEOUT,
				Message:      "request timeout",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-timeout-exception",
			err:                TestAwsError("RequestTimeoutException", "request timeout exception"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: connectivity error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_TIMEOUT,
				Message:      "request timeout exception",
				Nonretryable: false,
			},
		},
		{
			name:               "aws-request-access-denied",
			err:                TestAwsError(awsErrorAccessDenied, "not authorized to perform action"),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_INVALID_CREDENTIAL,
				Message:      "not authorized to perform action",
				Nonretryable: true,
			},
		},
		{
			name:               "aws-request-invalid-access-key-id",
			err:                TestAwsError(awsErrorInvalidAccessKeyId, "The AWS Access Key Id you provided does not exist in our records."),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_INVALID_CREDENTIAL,
				Message:      "The AWS Access Key Id you provided does not exist in our records.",
				Nonretryable: true,
			},
		},
		{
			name:               "aws-request-expired-token",
			err:                TestAwsError(awsErrorExpiredToken, "The security token included in the request is expired."),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials error: test",
			expectedPluginError: &pb.PluginError{
				Code:         pb.ERROR_ERROR_INVALID_CREDENTIAL,
				Message:      "The security token included in the request is expired.",
				Nonretryable: false,
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)

			actualStatus := ParseAWSError(tt.err, "test")
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
