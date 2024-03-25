// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package errors

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

const (
	// awsErrorAccessDenied is returned when the credentials do not have
	// the required permissions to do a specific action on a resource.
	// This error will persist until the IAM Role Policy is updated by
	// the owner. This error cannot be resolved by retrying the request.
	awsErrorAccessDenied = "AccessDenied"

	// awsErrorInvalidAccessKeyId is returned when the credential does
	// not exist. This error will persist until the credentials attached
	// to the storage bucket is updated. This error can occur when the
	// given credentials are deleted, deactivated, or rotated. This
	// error cannot be resolved by retrying the request.
	awsErrorInvalidAccessKeyId = "InvalidAccessKeyId"

	// awsErrorExpiredToken is returned when the provided credential is
	// expired. This error can only be returned by a dynamic credential
	// type. This error can resolve itself by retrying the request.
	awsErrorExpiredToken = "ExpiredToken"
)

// InvalidArgumentError returns an grpc invalid argument status error.
func InvalidArgumentError(msg string, f map[string]string) error {
	var fieldMsgs []string
	for field, val := range f {
		fieldMsgs = append(fieldMsgs, fmt.Sprintf("%s: %s", field, val))
	}
	if len(fieldMsgs) > 0 {
		sort.Strings(fieldMsgs)
		msg = fmt.Sprintf("%s: [%s]", msg, strings.Join(fieldMsgs, ", "))
	}
	return status.Error(codes.InvalidArgument, msg)
}

// ParseAWSError converts an aws service error into a RPC status. This method
// will handle parsing the following aws error codes: throttling, connections,
// and credentials. This method will fallback to parsing the http status code
// when it cannot match an aws error code. This method does not handle specific
// service type errors such as S3 or EC2.
func ParseAWSError(err error, msg string) (st *status.Status) {
	if err == nil {
		return nil
	}

	// find the service name of the aws api
	serviceName := "unknown"
	var oe *smithy.OperationError
	if errors.As(err, &oe) {
		serviceName = oe.Service()
	}

	// The unknown plugin error code will be used
	// when the aws service returns an error that
	// has failed to be parsed. By default, this
	// error code is retryable.
	plgErr := &pb.PluginError{
		Code:         pb.ERROR_ERROR_UNKNOWN,
		Message:      err.Error(),
		Nonretryable: false,
	}

	defer func() {
		if st == nil {
			statusMsg := fmt.Sprintf("aws service %s: unknown error: %s", serviceName, msg)
			st = status.New(codes.Unknown, statusMsg)
		}
		st, err = st.WithDetails(plgErr)
		if err != nil {
			st = status.New(codes.Internal, err.Error())
		}
	}()

	// evaluate against aws throttling error codes
	throttleErr := retry.ThrottleErrorCode{
		Codes: retry.DefaultThrottleErrorCodes,
	}
	if throttleErr.IsErrorThrottle(err).Bool() {
		plgErr.Code = pb.ERROR_ERROR_THROTTLING
		statusMsg := fmt.Sprintf("aws service %s: throttling error: %s", serviceName, msg)
		return status.New(codes.Unavailable, statusMsg)
	}
	// evaluate against aws connection error codes
	connectionErr := retry.IsErrorRetryables([]retry.IsErrorRetryable{
		retry.NoRetryCanceledError{},
		retry.RetryableError{},
		retry.RetryableConnectionError{},
		retry.RetryableHTTPStatusCode{
			Codes: retry.DefaultRetryableHTTPStatusCodes,
		},
		retry.RetryableErrorCode{
			Codes: retry.DefaultRetryableErrorCodes,
		},
	})
	if connectionErr.IsErrorRetryable(err).Bool() {
		plgErr.Code = pb.ERROR_ERROR_TIMEOUT
		statusMsg := fmt.Sprintf("aws service %s: connectivity error: %s", serviceName, msg)
		return status.New(codes.DeadlineExceeded, statusMsg)
	}
	// evaluate against aws credentials error codes
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		statusMsg := fmt.Sprintf("aws service %s: invalid credentials error: %s", serviceName, msg)
		switch apiErr.ErrorCode() {
		case awsErrorAccessDenied:
			fallthrough
		case awsErrorInvalidAccessKeyId:
			plgErr.Code = pb.ERROR_ERROR_INVALID_CREDENTIAL
			plgErr.Nonretryable = true
			return status.New(codes.PermissionDenied, statusMsg)
		case awsErrorExpiredToken:
			plgErr.Code = pb.ERROR_ERROR_INVALID_CREDENTIAL
			return status.New(codes.PermissionDenied, statusMsg)
		}
	}

	// default to evaluating the http status code
	if httpErr, ok := err.(*awshttp.ResponseError); ok {
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(httpErr.Response.Body)
		if err != nil {
			return status.New(codes.Internal, err.Error())
		}
		defer httpErr.Response.Body.Close()
		plgErr.Message = buf.String()
		switch httpErr.HTTPStatusCode() {
		case http.StatusBadRequest:
			plgErr.Code = pb.ERROR_ERROR_BAD_REQUEST
			plgErr.Nonretryable = true
			statusMsg := fmt.Sprintf("aws service %s: bad request error: %s", serviceName, msg)
			return status.New(codes.InvalidArgument, statusMsg)
		case http.StatusUnauthorized:
			plgErr.Code = pb.ERROR_ERROR_INVALID_CREDENTIAL
			statusMsg := fmt.Sprintf("aws service %s: invalid credentials error: %s", serviceName, msg)
			return status.New(codes.PermissionDenied, statusMsg)
		case http.StatusForbidden:
			plgErr.Code = pb.ERROR_ERROR_INVALID_CREDENTIAL
			plgErr.Nonretryable = true
			statusMsg := fmt.Sprintf("aws service %s: invalid credentials error: %s", serviceName, msg)
			return status.New(codes.PermissionDenied, statusMsg)
		case http.StatusNotFound:
			plgErr.Code = pb.ERROR_ERROR_BAD_REQUEST
			plgErr.Nonretryable = true
			statusMsg := fmt.Sprintf("aws service %s: resource not found error: %s", serviceName, msg)
			return status.New(codes.NotFound, statusMsg)
		case http.StatusTooManyRequests:
			plgErr.Code = pb.ERROR_ERROR_THROTTLING
			statusMsg := fmt.Sprintf("aws service %s: throttling error: %s", serviceName, msg)
			return status.New(codes.Unavailable, statusMsg)
		case http.StatusRequestTimeout:
			fallthrough
		case http.StatusInternalServerError:
			fallthrough
		case http.StatusBadGateway:
			fallthrough
		case http.StatusServiceUnavailable:
			fallthrough
		case http.StatusGatewayTimeout:
			plgErr.Code = pb.ERROR_ERROR_TIMEOUT
			statusMsg := fmt.Sprintf("aws service %s: connectivity error: %s", serviceName, msg)
			return status.New(codes.DeadlineExceeded, statusMsg)
		}
	}

	return st
}
