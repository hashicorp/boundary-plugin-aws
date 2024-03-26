package storage

import (
	stderr "errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
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

// parseS3Error will convert an S3 api error into a RPC status. If the
// error does not match against an s3 error type, it will fallback to
// evaluating against generic aws service errors. This includes throttling,
// credentials, and connectivity error types.
//
// https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
func parseS3Error(err error, msg string) (st *status.Status) {
	if err == nil {
		return nil
	}

	var plgErr *pb.PluginError
	defer func() {
		if plgErr != nil {
			st, err = st.WithDetails(plgErr)
			if err != nil {
				st = status.New(codes.Internal, err.Error())
			}
		}
	}()

	// The NoSuchBucket error is returned when trying to access
	// an s3 bucket that does not exist.
	var missingStore *types.NoSuchBucket
	if stderr.As(err, &missingStore) {
		plgErr = &pb.PluginError{
			Code:         pb.ERROR_ERROR_STORAGE_NO_SUCH_BUCKET,
			Message:      missingStore.ErrorMessage(),
			Nonretryable: true,
		}
		return status.New(codes.NotFound, fmt.Sprintf(s3StatusErrMsg, msg))
	}

	// The NoSuchKey error is returned when trying to download
	// an object from s3 that does not exist.
	var missingObject *types.NoSuchKey
	if stderr.As(err, &missingObject) {
		plgErr = &pb.PluginError{
			Code:         pb.ERROR_ERROR_STORAGE_NO_SUCH_OBJECT,
			Message:      missingObject.ErrorMessage(),
			Nonretryable: true,
		}
		return status.New(codes.NotFound, fmt.Sprintf(s3StatusErrMsg, msg))
	}

	var notFound *types.NotFound
	if stderr.As(err, &notFound) {
		plgErr = &pb.PluginError{
			Code:         pb.ERROR_ERROR_STORAGE_NO_SUCH_OBJECT,
			Message:      notFound.ErrorMessage(),
			Nonretryable: true,
		}
		return status.New(codes.NotFound, fmt.Sprintf(s3StatusErrMsg, msg))
	}

	// The InvalidObjectState error is returned when trying to
	// access an object that was moved into cold storage.
	var invalidState *types.InvalidObjectState
	if stderr.As(err, &invalidState) {
		plgErr = &pb.PluginError{
			Code:         pb.ERROR_ERROR_STORAGE_NO_SUCH_OBJECT,
			Message:      invalidState.ErrorMessage(),
			Nonretryable: true,
		}
		return status.New(codes.NotFound, fmt.Sprintf(s3StatusErrMsg, msg))
	}

	var apiErr smithy.APIError
	if stderr.As(err, &apiErr) {
		if apiErr.ErrorCode() == s3ErrorBadDigest {
			plgErr = &pb.PluginError{
				Code:         pb.ERROR_ERROR_STORAGE_CHECKSUM_MISMATCH,
				Message:      apiErr.ErrorMessage(),
				Nonretryable: false,
			}
			return status.New(codes.Aborted, fmt.Sprintf(s3StatusErrMsg, msg))
		}
	}

	return errors.ParseAWSError(err, msg)
}
