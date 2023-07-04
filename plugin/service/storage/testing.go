// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testOptionErr            = "test option error"
	testGetUserErr           = "test error for GetUser"
	testGetCallerIdentityErr = "test error for GetCallerIdentity"
	testDeleteAccessKeyErr   = "test error for DeleteAccessKey"
	testGetObjectErr         = "test error for GetObject"
	testPutObjectErr         = "test error for PutObject"
	testHeadObjectErr        = "test error for HeadObject"
)

// throttleErr is a mocked error used for testing the aws s3 client
type throttleErr struct{}

func (e *throttleErr) ErrorCode() string {
	return "ThrottlingException"
}

func (e *throttleErr) Error() string {
	return "ThrottlingException"
}

type testMockS3State struct {
	GetObjectCalled      bool
	GetObjectInputParams *s3.GetObjectInput

	PutObjectCalled      bool
	PutObjectInputParams *s3.PutObjectInput
	PutObjectBody        []byte

	HeadObjectCalled      bool
	HeadObjectInputParams *s3.HeadObjectInput
}

func (s *testMockS3State) Reset() {
	s.GetObjectCalled = false
	s.GetObjectInputParams = nil
	s.PutObjectCalled = false
	s.PutObjectInputParams = nil
	s.PutObjectBody = nil
	s.HeadObjectCalled = false
	s.HeadObjectInputParams = nil
}

type testMockS3 struct {
	S3API

	State    *testMockS3State
	Region   string
	Endpoint aws.EndpointResolverWithOptions

	// mocked responses for getObject
	GetObjectOutput *s3.GetObjectOutput
	GetObjectErr    error

	// mocked responses for putObject
	PutObjectOutput *s3.PutObjectOutput
	PutObjectErr    error

	// mocked responses for headObject
	HeadObjectOutput *s3.HeadObjectOutput
	HeadObjectErr    error
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
			if cfg.EndpointResolverWithOptions != nil {
				m.Endpoint = cfg.EndpointResolverWithOptions
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

func (m *testMockS3) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	return &s3.DeleteObjectOutput{}, nil
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