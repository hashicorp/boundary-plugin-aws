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
	"google.golang.org/protobuf/types/known/timestamppb"
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

	// NoSuchBucket is returned when the specified S3 storage bucket does
	// not exist
	awsErrorNoSuchBucket = "NoSuchBucket"

	// BadDigest is returned when an S3 PUT OBJECT request's calculated
	// checksum does not match the checksum which was sent by the client
	awsErrorBadDigest = "BadDigest"

	// NoSuchKey is returned when attempting to interact with an S3 object
	// whose key does not exist
	awsErrorNoSuchKey = "NoSuchKey"

	// The InvalidObjectState error is returned when trying to
	// access an object that was moved into cold storage.
	awsErrorInvalidObjectState = "InvalidObjectState"

	// RequestTimeout is returned when an http request takes longer than allowed
	awsErrorRequestTimeout = "RequestTimeout"

	// RequestTimeoutException is returned when an http request takes longer than allowed
	awsErrorRequestTimeoutException = "RequestTimeoutException"
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
	return BadRequestStatus(msg)
}

// ParseAWSError converts an aws service error into a RPC status. This method
// will handle parsing the following aws error codes: throttling, connections,
// and credentials. This method will fallback to parsing the http status code
// when it cannot match an aws error code. This method does not handle specific
// service type errors such as S3 or EC2.
func ParseAWSError(op string, err error) (st *status.Status, permission *pb.Permission) {
	if err == nil {
		return nil, nil
	}

	msg := fmt.Sprintf("%s: %v", op, err)
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

	defer func() {
		if st == nil {
			statusMsg := fmt.Sprintf("aws service %s: unknown error: %s", serviceName, msg)
			st = status.New(codes.Unknown, statusMsg)
		}
		if permission == nil {
			permission = &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, CheckedAt: timestamppb.Now()}
		}
	}()

	// evaluate against aws throttling error codes
	throttleErr := retry.ThrottleErrorCode{
		Codes: retry.DefaultThrottleErrorCodes,
	}
	if throttleErr.IsErrorThrottle(err).Bool() {
		statusMsg := fmt.Sprintf("aws service %s: throttling: %s", serviceName, msg)
		return status.New(codes.Unavailable, statusMsg), nil
	}

	// parse some specific aws error codes that we have special cred states for
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case awsErrorAccessDenied:
			fallthrough
		case awsErrorInvalidAccessKeyId:
			fallthrough
		case awsErrorExpiredToken:
			statusMsg := fmt.Sprintf("aws service %s: invalid credentials: %s", serviceName, msg)
			return status.New(codes.PermissionDenied, statusMsg), &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: apiErr.ErrorMessage(),
				CheckedAt:    timestamppb.Now(),
			}
		case awsErrorNoSuchBucket:
			statusMsg := fmt.Sprintf("aws service %s: %s", serviceName, msg)
			return status.New(codes.NotFound, statusMsg), &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: apiErr.ErrorMessage(),
				CheckedAt:    timestamppb.Now(),
			}
		case awsErrorBadDigest:
			statusMsg := fmt.Sprintf("aws service %s: %s", serviceName, msg)
			return status.New(codes.Aborted, statusMsg), nil
		case awsErrorNoSuchKey:
			fallthrough
		case awsErrorInvalidObjectState:
			statusMsg := fmt.Sprintf("aws service %s: %s", serviceName, msg)
			return status.New(codes.NotFound, statusMsg), nil
		case awsErrorRequestTimeout:
			fallthrough
		case awsErrorRequestTimeoutException:
			statusMsg := fmt.Sprintf("aws service %s: %s", serviceName, msg)
			return status.New(codes.DeadlineExceeded, statusMsg), nil
		}
	}

	// default to evaluating the http status code
	if httpErr, ok := err.(*awshttp.ResponseError); ok {
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(httpErr.Response.Body)
		if err != nil {
			return status.New(codes.Internal, err.Error()), nil
		}
		defer httpErr.Response.Body.Close()
		switch httpErr.HTTPStatusCode() {
		case http.StatusBadRequest:
			statusMsg := fmt.Sprintf("aws service %s: bad request: %s", serviceName, msg)
			return status.New(codes.InvalidArgument, statusMsg), nil
		case http.StatusUnauthorized:
			statusMsg := fmt.Sprintf("aws service %s: invalid credentials: %s", serviceName, msg)
			return status.New(codes.PermissionDenied, statusMsg), &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: buf.String(),
				CheckedAt:    timestamppb.Now(),
			}
		case http.StatusForbidden:
			statusMsg := fmt.Sprintf("aws service %s: invalid credentials: %s", serviceName, msg)
			return status.New(codes.PermissionDenied, statusMsg), &pb.Permission{
				State:        pb.StateType_STATE_TYPE_ERROR,
				ErrorDetails: buf.String(),
				CheckedAt:    timestamppb.Now(),
			}
		case http.StatusNotFound:
			statusMsg := fmt.Sprintf("aws service %s: resource not found: %s", serviceName, msg)
			return status.New(codes.NotFound, statusMsg), nil
		case http.StatusTooManyRequests:
			statusMsg := fmt.Sprintf("aws service %s: throttling: %s", serviceName, msg)
			return status.New(codes.Unavailable, statusMsg), nil
		case http.StatusInternalServerError:
			fallthrough
		case http.StatusBadGateway:
			fallthrough
		case http.StatusServiceUnavailable:
			statusMsg := fmt.Sprintf("aws service %s: connectivity: %s", serviceName, msg)
			return status.New(codes.Unavailable, statusMsg), nil
		case http.StatusRequestTimeout:
			fallthrough
		case http.StatusGatewayTimeout:
			statusMsg := fmt.Sprintf("aws service %s: timeout: %s", serviceName, msg)
			return status.New(codes.DeadlineExceeded, statusMsg), nil
		}
	}

	return st, nil
}

// BadRequestStatus returns a status error with an invalid
// argument code
func BadRequestStatus(format string, args ...any) error {
	return status.New(codes.InvalidArgument, fmt.Sprintf(format, args...)).Err()
}

// UnknownStatus returns a status error with an internal
// error code
func UnknownStatus(format string, args ...any) error {
	return status.New(codes.Internal, fmt.Sprintf(format, args...)).Err()
}
