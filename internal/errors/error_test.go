// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package errors

import (
	"fmt"
	"testing"

	"net/http"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_ParseAWSError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name               string
		err                error
		expectedStatusCode codes.Code
		expectedStatusMsg  string
		expectedPermission *pb.Permission
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
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "http-status-code-bad-request",
			err:                TestAwsHttpResponseError(http.StatusBadRequest, "bad request"),
			expectedStatusCode: codes.InvalidArgument,
			expectedStatusMsg:  "aws service unknown: bad request: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "http-status-code-unauthorized",
			err:                TestAwsHttpResponseError(http.StatusUnauthorized, "unauthorized request"),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials: test",
			expectedPermission: &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: "unauthorized request",
				CheckedAt:    timestamppb.Now(),
			},
		},
		{
			name:               "http-status-code-forbidden",
			err:                TestAwsHttpResponseError(http.StatusForbidden, "forbidden request"),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials: test",
			expectedPermission: &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: "forbidden request",
				CheckedAt:    timestamppb.Now(),
			},
		},
		{
			name:               "http-status-code-not-found",
			err:                TestAwsHttpResponseError(http.StatusNotFound, "not found request"),
			expectedStatusCode: codes.NotFound,
			expectedStatusMsg:  "aws service unknown: resource not found: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "http-status-code-too-many-requests",
			err:                TestAwsHttpResponseError(http.StatusTooManyRequests, "too many requests"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "http-status-code-request-timeout",
			err:                TestAwsHttpResponseError(http.StatusRequestTimeout, "request timeout"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: timeout: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "http-status-code-internal-server-error",
			err:                TestAwsHttpResponseError(http.StatusInternalServerError, "internal server error"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: connectivity: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "http-status-code-bad-gateway",
			err:                TestAwsHttpResponseError(http.StatusBadGateway, "bad gateway"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: connectivity: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "http-status-code-service-unavailable",
			err:                TestAwsHttpResponseError(http.StatusServiceUnavailable, "service unavailable"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: connectivity: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "http-status-code-gateway-timeout",
			err:                TestAwsHttpResponseError(http.StatusGatewayTimeout, "gateway timeout"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: timeout: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-throttling",
			err:                TestAwsError("Throttling", "throttling error"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-throttling-exception",
			err:                TestAwsError("ThrottlingException", "throttling exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-throttled-exception",
			err:                TestAwsError("ThrottledException", "throttled exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-throttled-exception",
			err:                TestAwsError("RequestThrottledException", "request throttled exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-too-many-requests-exception",
			err:                TestAwsError("TooManyRequestsException", "too many requests exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-provisioned-throughput-exceeded-exception",
			err:                TestAwsError("ProvisionedThroughputExceededException", "provisioned throughput exceeded exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-transaction-in-progress-exception",
			err:                TestAwsError("TransactionInProgressException", "transaction in progress exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-limit-exceeded",
			err:                TestAwsError("RequestLimitExceeded", "request limit exceeded"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-bandwidth-limit-exceeded",
			err:                TestAwsError("BandwidthLimitExceeded", "bandwidth limit exceeded"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-limit-exceeded-exception",
			err:                TestAwsError("LimitExceededException", "limit exceeded exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-throttled",
			err:                TestAwsError("RequestThrottled", "request throttled"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-slow-down",
			err:                TestAwsError("SlowDown", "slow down"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-prior-request-not-complete",
			err:                TestAwsError("PriorRequestNotComplete", "prior request not complete"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-ec2-throttled-exception",
			err:                TestAwsError("EC2ThrottledException", "ec2 throttled exception"),
			expectedStatusCode: codes.Unavailable,
			expectedStatusMsg:  "aws service unknown: throttling: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-timeout",
			err:                TestAwsError("RequestTimeout", "request timeout"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-timeout-exception",
			err:                TestAwsError("RequestTimeoutException", "request timeout exception"),
			expectedStatusCode: codes.DeadlineExceeded,
			expectedStatusMsg:  "aws service unknown: test",
			expectedPermission: &pb.Permission{
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
		},
		{
			name:               "aws-request-access-denied",
			err:                TestAwsError(awsErrorAccessDenied, "not authorized to perform action"),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials: test",
			expectedPermission: &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: "not authorized to perform action",
				CheckedAt:    timestamppb.Now(),
			},
		},
		{
			name:               "aws-request-invalid-access-key-id",
			err:                TestAwsError(awsErrorInvalidAccessKeyId, "The AWS Access Key Id you provided does not exist in our records."),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials: test",
			expectedPermission: &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: "The AWS Access Key Id you provided does not exist in our records.",
				CheckedAt:    timestamppb.Now(),
			},
		},
		{
			name:               "aws-request-expired-token",
			err:                TestAwsError(awsErrorExpiredToken, "The security token included in the request is expired."),
			expectedStatusCode: codes.PermissionDenied,
			expectedStatusMsg:  "aws service unknown: invalid credentials: test",
			expectedPermission: &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: "The security token included in the request is expired.",
				CheckedAt:    timestamppb.Now(),
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			actualStatus, permission := ParseAWSError("test", tt.err)
			if tt.expectedStatusCode == codes.OK {
				require.Nil(actualStatus)
				return
			}

			require.Equal(tt.expectedStatusCode, actualStatus.Code())
			require.Contains(actualStatus.Message(), tt.expectedStatusMsg)
			require.Len(actualStatus.Details(), 0)
			CheckSimilarPermission(assert, tt.expectedPermission, permission, true)
		})
	}
}

func Test_BadRequestStatus(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	err := BadRequestStatus("test: %s", "hello world")
	assert.ErrorContains(err, "test: hello world")
	assert.Equal(status.Code(err), codes.InvalidArgument)
	_, ok := status.FromError(err)
	require.True(ok)
}

func Test_UnknownStatus(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	err := UnknownStatus("test: %s", "hello world")
	assert.ErrorContains(err, "test: hello world")
	assert.Equal(status.Code(err), codes.Internal)
	_, ok := status.FromError(err)
	require.True(ok)
}
