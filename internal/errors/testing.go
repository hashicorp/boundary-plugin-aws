package errors

import (
	"io"
	"net/http"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
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
