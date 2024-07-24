// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package errors

import (
	"io"
	"net/http"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestAwsHttpResponseError returns an aws http response error
func TestAwsHttpResponseError(code int, msg string) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{
				Response: &http.Response{
					StatusCode: code,
					Body:       io.NopCloser(strings.NewReader(msg)),
				},
			},
		},
	}
}

// TestAwsError returns an generic api error
func TestAwsError(code, msg string) error {
	return &smithy.GenericAPIError{
		Code:    code,
		Message: msg,
		Fault:   smithy.FaultServer,
	}
}

func CheckSimilarPermission(assert *assert.Assertions, expected, actual *pb.Permission, substituteNilWithDefaultOk bool) {
	if expected == nil && substituteNilWithDefaultOk {
		expected = &pb.Permission{
			State:     pb.StateType_STATE_TYPE_OK,
			CheckedAt: timestamppb.Now(),
		}
	}

	if expected != nil {
		assert.NotNil(actual)
		if actual != nil {
			assert.Equal(expected.State, actual.State, "StateType mismatch")
			assert.Equal(expected.ErrorDetails, actual.ErrorDetails)
			assert.NotNil(actual.CheckedAt)
		}
	} else {
		assert.Equal(expected, actual)
	}
}
