// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"github.com/hashicorp/boundary-plugin-aws/internal/errors"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	s3StatusErrMsg = "aws s3 error: %s"

	// s3ErrorBadDigest is returned when there is a checksum
	// mismatch between the request and the s3 service. This
	// error code is returned for the PutObject request.
	s3ErrorBadDigest = "BadDigest"
)

func setStatePermission(req any, permission *pb.Permission) *pb.StorageBucketCredentialState {
	state := &pb.StorageBucketCredentialState{
		State: &pb.Permissions{},
	}
	switch req.(type) {
	case pb.HeadObjectRequest:
		state.State.Read = permission
	case *pb.HeadObjectRequest:
		state.State.Read = permission
	case pb.GetObjectRequest:
		state.State.Read = permission
	case *pb.GetObjectRequest:
		state.State.Read = permission
	case pb.PutObjectRequest:
		state.State.Write = permission
	case *pb.PutObjectRequest:
		state.State.Write = permission
	case pb.DeleteObjectsRequest:
		state.State.Delete = permission
	case *pb.DeleteObjectsRequest:
		state.State.Delete = permission
	}
	return state
}

// parseS3Error will convert an S3 api error into a RPC status. If the
// error does not match against an s3 error type, it will fallback to
// evaluating against generic aws service errors. This includes throttling,
// credentials, and connectivity error types.
//
// https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
func parseS3Error(op string, err error, req any) *status.Status {
	if err == nil {
		return nil
	}

	st, p := errors.ParseAWSError(op, err)
	if p != nil {
		state := setStatePermission(req, p)
		if st, err = st.WithDetails(state); err != nil {
			st = status.New(codes.Internal, err.Error())
		}
	}

	return st
}

func checksumMistmatchStatus() error {
	return status.New(codes.Aborted, "mismatched checksum").Err()
}
