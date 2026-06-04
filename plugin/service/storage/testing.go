// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testOptionErr            = "test option error"
	testGetUserErr           = "test error for GetUser"
	testGetCallerIdentityErr = "test error for GetCallerIdentity"
	testDeleteAccessKeyErr   = "test error for DeleteAccessKey"
)

type testMockS3State struct {
	GetObjectCalled      bool
	GetObjectInputParams *s3.GetObjectInput

	PutObjectCalled      bool
	PutObjectInputParams *s3.PutObjectInput
	PutObjectBody        []byte

	CreateMultipartUploadCalled      bool
	CreateMultipartUploadInputParams *s3.CreateMultipartUploadInput

	UploadPartCalled      bool
	UploadPartCallCount   int
	UploadPartInputParams []*s3.UploadPartInput
	// UploadPartBody is the concatenation, in part-number order, of every
	// part body received by UploadPart. It can be compared against the full
	// object that was expected to be uploaded.
	UploadPartBody []byte

	CompleteMultipartUploadCalled      bool
	CompleteMultipartUploadInputParams *s3.CompleteMultipartUploadInput

	AbortMultipartUploadCalled      bool
	AbortMultipartUploadInputParams *s3.AbortMultipartUploadInput

	HeadObjectCalled      bool
	HeadObjectInputParams *s3.HeadObjectInput

	ListObjectsV2Called      bool
	ListObjectsV2InputParams *s3.ListObjectsV2Input

	DeleteObjectCalled       bool
	DeleteObjectInputParams  *s3.DeleteObjectInput
	DeleteObjectsCalled      bool
	DeleteObjectsInputParams *s3.DeleteObjectsInput
}

func (s *testMockS3State) Reset() {
	s.GetObjectCalled = false
	s.GetObjectInputParams = nil
	s.PutObjectCalled = false
	s.PutObjectInputParams = nil
	s.PutObjectBody = nil
	s.CreateMultipartUploadCalled = false
	s.CreateMultipartUploadInputParams = nil
	s.UploadPartCalled = false
	s.UploadPartCallCount = 0
	s.UploadPartInputParams = nil
	s.UploadPartBody = nil
	s.CompleteMultipartUploadCalled = false
	s.CompleteMultipartUploadInputParams = nil
	s.AbortMultipartUploadCalled = false
	s.AbortMultipartUploadInputParams = nil
	s.HeadObjectCalled = false
	s.HeadObjectInputParams = nil
	s.ListObjectsV2Called = false
	s.ListObjectsV2InputParams = nil
	s.DeleteObjectCalled = false
	s.DeleteObjectInputParams = nil
	s.DeleteObjectsCalled = false
	s.DeleteObjectsInputParams = nil
}

type testMockS3 struct {
	S3API

	State  *testMockS3State
	Region string

	// mocked responses for getObject
	GetObjectOutput *s3.GetObjectOutput
	GetObjectErr    error

	// mocked responses for putObject
	PutObjectOutput *s3.PutObjectOutput
	PutObjectErr    error

	// mocked responses for the multipart upload calls
	CreateMultipartUploadOutput *s3.CreateMultipartUploadOutput
	CreateMultipartUploadErr    error
	UploadPartOutput            *s3.UploadPartOutput
	UploadPartErr               error
	// UploadPartErrOnPart, when greater than zero, causes UploadPart to return
	// UploadPartErr (or a generic error) only for the matching part number.
	UploadPartErrOnPart           int32
	CompleteMultipartUploadOutput *s3.CompleteMultipartUploadOutput
	CompleteMultipartUploadErr    error
	AbortMultipartUploadOutput    *s3.AbortMultipartUploadOutput
	AbortMultipartUploadErr       error

	// mocked responses for headObject
	HeadObjectOutput *s3.HeadObjectOutput
	HeadObjectErr    error

	// mocked responses for ListObjectsV2 (needed for delete)
	ListObjectsV2Output *s3.ListObjectsV2Output
	ListObjectsV2Err    error
	// sometimes we need to create a wildcard output
	ListObjectsV2OutputFunc func(*s3.ListObjectsV2Input) *s3.ListObjectsV2Output

	// mocked responses for DeleteObject(s)
	DeleteObjectOutput  *s3.DeleteObjectOutput
	DeleteObjectErr     error
	DeleteObjectsOutput *s3.DeleteObjectsOutput
	DeleteObjectsErr    error
}

type testMockS3Option func(m *testMockS3) error

func testMockS3WithPutObjectOutput(o *s3.PutObjectOutput) testMockS3Option {
	return func(m *testMockS3) error {
		m.PutObjectOutput = o
		return nil
	}
}

func testMockS3WithPutObjectError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.PutObjectErr = e
		return nil
	}
}

func testMockS3WithCreateMultipartUploadOutput(o *s3.CreateMultipartUploadOutput) testMockS3Option {
	return func(m *testMockS3) error {
		m.CreateMultipartUploadOutput = o
		return nil
	}
}

func testMockS3WithCreateMultipartUploadError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.CreateMultipartUploadErr = e
		return nil
	}
}

func testMockS3WithUploadPartOutput(o *s3.UploadPartOutput) testMockS3Option {
	return func(m *testMockS3) error {
		m.UploadPartOutput = o
		return nil
	}
}

func testMockS3WithUploadPartError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.UploadPartErr = e
		return nil
	}
}

func testMockS3WithUploadPartErrorOnPart(partNumber int32, e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.UploadPartErr = e
		m.UploadPartErrOnPart = partNumber
		return nil
	}
}

func testMockS3WithCompleteMultipartUploadOutput(o *s3.CompleteMultipartUploadOutput) testMockS3Option {
	return func(m *testMockS3) error {
		m.CompleteMultipartUploadOutput = o
		return nil
	}
}

func testMockS3WithCompleteMultipartUploadError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.CompleteMultipartUploadErr = e
		return nil
	}
}

func testMockS3WithAbortMultipartUploadError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.AbortMultipartUploadErr = e
		return nil
	}
}

func testMockS3WithGetObjectOutput(o *s3.GetObjectOutput) testMockS3Option {
	return func(m *testMockS3) error {
		m.GetObjectOutput = o
		return nil
	}
}

func testMockS3WithGetObjectError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.GetObjectErr = e
		return nil
	}
}

func testMockS3WithHeadObjectOutput(o *s3.HeadObjectOutput) testMockS3Option {
	return func(m *testMockS3) error {
		m.HeadObjectOutput = o
		return nil
	}
}

func testMockS3WithHeadObjectError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.HeadObjectErr = e
		return nil
	}
}

func testMockS3WithListObjectsV2Output(o *s3.ListObjectsV2Output) testMockS3Option {
	return func(m *testMockS3) error {
		m.ListObjectsV2Output = o
		return nil
	}
}

func testMockS3WithListObjectsV2Error(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.ListObjectsV2Err = e
		return nil
	}
}

func testMockS3WithListObjectsV2OutputFunc(o func(*s3.ListObjectsV2Input) *s3.ListObjectsV2Output) testMockS3Option {
	return func(m *testMockS3) error {
		m.ListObjectsV2OutputFunc = o
		return nil
	}
}

func testMockS3WithDeleteObjectOutput(o *s3.DeleteObjectOutput) testMockS3Option {
	return func(m *testMockS3) error {
		m.DeleteObjectOutput = o
		return nil
	}
}

func testMockS3WithDeleteObjectError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.DeleteObjectErr = e
		return nil
	}
}

func testMockS3WithDeleteObjectsOutput(o *s3.DeleteObjectsOutput) testMockS3Option {
	return func(m *testMockS3) error {
		m.DeleteObjectsOutput = o
		return nil
	}
}

func testMockS3WithDeleteObjectsError(e error) testMockS3Option {
	return func(m *testMockS3) error {
		m.DeleteObjectsErr = e
		return nil
	}
}

func newTestMockS3(state *testMockS3State, opts ...testMockS3Option) s3APIFunc {
	return func(cfgs ...aws.Config) (S3API, error) {
		m := &testMockS3{
			State: state,
		}

		for _, opt := range opts {
			if err := opt(m); err != nil {
				return nil, err
			}
		}

		for _, cfg := range cfgs {
			// Last region takes precedence
			if cfg.Region != "" {
				m.Region = cfg.Region
			}
		}

		return m, nil
	}
}

func (m *testMockS3) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.State != nil {
		m.State.GetObjectCalled = true
		m.State.GetObjectInputParams = params
	}

	if m.GetObjectErr != nil {
		return nil, m.GetObjectErr
	}

	return m.GetObjectOutput, nil
}

func (m *testMockS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.State != nil {
		m.State.PutObjectCalled = true
		m.State.PutObjectInputParams = params
	}

	if m.PutObjectErr != nil {
		return nil, m.PutObjectErr
	}

	// Reads and Writes on the pipe are matched one to one except when multiple Reads are needed to consume a single Write.
	// Therefore, we need to read the entire body to ensure that the pipe is not blocked.
	if params.Body != nil {
		data, err := io.ReadAll(params.Body)
		if err != nil {
			return nil, err
		}
		if m.State == nil || m.State.PutObjectBody == nil {
			return m.PutObjectOutput, nil
		}
		if !bytes.Equal(data, m.State.PutObjectBody) {
			return nil, fmt.Errorf("expected body %q, got %q", m.State.PutObjectBody, data)
		}
	}

	return m.PutObjectOutput, nil
}

func (m *testMockS3) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	if m.State != nil {
		m.State.CreateMultipartUploadCalled = true
		m.State.CreateMultipartUploadInputParams = params
	}

	if m.CreateMultipartUploadErr != nil {
		return nil, m.CreateMultipartUploadErr
	}

	if m.CreateMultipartUploadOutput != nil {
		return m.CreateMultipartUploadOutput, nil
	}
	return &s3.CreateMultipartUploadOutput{
		UploadId: aws.String("test-upload-id"),
	}, nil
}

func (m *testMockS3) UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	if m.State != nil {
		m.State.UploadPartCalled = true
		m.State.UploadPartCallCount++
		m.State.UploadPartInputParams = append(m.State.UploadPartInputParams, params)
	}

	// always drain the body so the part data can be asserted on and so the
	// reader is not left dangling.
	var data []byte
	if params.Body != nil {
		var err error
		data, err = io.ReadAll(params.Body)
		if err != nil {
			return nil, err
		}
		if m.State != nil {
			m.State.UploadPartBody = append(m.State.UploadPartBody, data...)
		}
	}

	if m.UploadPartErr != nil {
		if m.UploadPartErrOnPart == 0 || (params.PartNumber != nil && *params.PartNumber == m.UploadPartErrOnPart) {
			return nil, m.UploadPartErr
		}
	}

	if m.UploadPartOutput != nil {
		return m.UploadPartOutput, nil
	}
	// echo the supplied part checksum so CompleteMultipartUpload can be built
	// the way the real service would allow.
	sum := sha256.Sum256(data)
	return &s3.UploadPartOutput{
		ETag:           aws.String(fmt.Sprintf("etag-%d", aws.ToInt32(params.PartNumber))),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])),
	}, nil
}

func (m *testMockS3) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	if m.State != nil {
		m.State.CompleteMultipartUploadCalled = true
		m.State.CompleteMultipartUploadInputParams = params
	}

	if m.CompleteMultipartUploadErr != nil {
		return nil, m.CompleteMultipartUploadErr
	}

	if m.CompleteMultipartUploadOutput != nil {
		return m.CompleteMultipartUploadOutput, nil
	}
	return &s3.CompleteMultipartUploadOutput{}, nil
}

func (m *testMockS3) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	if m.State != nil {
		m.State.AbortMultipartUploadCalled = true
		m.State.AbortMultipartUploadInputParams = params
	}

	if m.AbortMultipartUploadErr != nil {
		return nil, m.AbortMultipartUploadErr
	}

	if m.AbortMultipartUploadOutput != nil {
		return m.AbortMultipartUploadOutput, nil
	}
	return &s3.AbortMultipartUploadOutput{}, nil
}

func (m *testMockS3) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if m.State != nil {
		m.State.ListObjectsV2Called = true
		m.State.ListObjectsV2InputParams = params
	}

	if m.ListObjectsV2Err != nil {
		return nil, m.ListObjectsV2Err
	}

	if m.ListObjectsV2OutputFunc != nil {
		return m.ListObjectsV2OutputFunc(params), nil
	}

	return m.ListObjectsV2Output, nil
}

func (m *testMockS3) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if m.State != nil {
		m.State.DeleteObjectCalled = true
		m.State.DeleteObjectInputParams = params
	}

	if m.DeleteObjectErr != nil {
		return nil, m.DeleteObjectErr
	}

	return m.DeleteObjectOutput, nil
}

func (m *testMockS3) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	if m.State != nil {
		m.State.DeleteObjectsCalled = true
		m.State.DeleteObjectsInputParams = params
	}

	if m.DeleteObjectsErr != nil {
		return nil, m.DeleteObjectsErr
	}

	return m.DeleteObjectsOutput, nil
}

func (m *testMockS3) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if m.State != nil {
		m.State.HeadObjectCalled = true
		m.State.HeadObjectInputParams = params
	}

	if m.HeadObjectErr != nil {
		return nil, m.HeadObjectErr
	}

	return m.HeadObjectOutput, nil
}

type getObjectStreamMock struct {
	grpc.ServerStream
	ctx  context.Context
	err  error
	data *pb.GetObjectResponse
}

func (s *getObjectStreamMock) Context() context.Context {
	return s.ctx
}

// Send streams a response message to the client.
// This function should only be called on the server side.
func (g *getObjectStreamMock) Send(req *pb.GetObjectResponse) error {
	if req == nil {
		return fmt.Errorf(`parameter arg "resp GetObjectResponse" cannot be nil.`)
	}
	g.data = req
	return nil
}

// Recv streams a response message from the server.
// This function should only be called on the client side.
func (g *getObjectStreamMock) Recv() (*pb.GetObjectResponse, error) {
	if g.data == nil {
		if g.err != nil {
			return nil, g.err
		}
		return nil, io.EOF
	}
	resp := &pb.GetObjectResponse{
		FileChunk: append([]byte{}, g.data.FileChunk...),
	}
	g.data = nil
	return resp, nil
}

func newGetObjectStreamMock() *getObjectStreamMock {
	return &getObjectStreamMock{
		ctx: context.Background(),
	}
}

func createTime(t *testing.T, timestamp string) time.Time {
	require := require.New(t)
	testTime, err := time.Parse(time.RFC3339, timestamp)
	require.NoError(err)
	return testTime
}

func deepCopyPutObjectRequest(v *pb.PutObjectRequest) *pb.PutObjectRequest {
	deepCopy := &pb.PutObjectRequest{
		Key:  v.Key,
		Path: v.Path,
	}
	if v.Bucket != nil {
		deepCopy.Bucket = &storagebuckets.StorageBucket{
			BucketName:   v.Bucket.BucketName,
			BucketPrefix: v.Bucket.BucketPrefix,
		}
		if v.Bucket.Attributes != nil {
			attrs, _ := structpb.NewStruct(v.Bucket.Attributes.AsMap())
			deepCopy.Bucket.Attributes = attrs
		}
		if v.Bucket.Secrets != nil {
			secrets, _ := structpb.NewStruct(v.Bucket.Secrets.AsMap())
			deepCopy.Bucket.Secrets = secrets
		}
	}
	return deepCopy
}

func validSTSMock() []credential.AwsCredentialPersistedStateOption {
	return []credential.AwsCredentialPersistedStateOption{
		credential.WithStateTestOpts([]awsutil.Option{
			awsutil.WithSTSAPIFunc(
				awsutil.NewMockSTS(
					awsutil.WithGetCallerIdentityOutput(&sts.GetCallerIdentityOutput{
						Account: aws.String("0123456789"),
						Arn:     aws.String("arn:aws:iam::0123456789:user/test"),
						UserId:  aws.String("test"),
					}),
				),
			),
		}),
	}
}

// TestAwsS3Error returns an s3 api error
func TestAwsS3Error(code, op, msg string) error {
	return &smithy.OperationError{
		ServiceID:     "s3",
		OperationName: op,
		Err: &smithy.GenericAPIError{
			Code:    code,
			Message: msg,
			Fault:   smithy.FaultServer,
		},
	}
}
