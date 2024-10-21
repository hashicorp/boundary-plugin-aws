// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	internal "github.com/hashicorp/boundary-plugin-aws/internal/errors"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStoragePlugin_OnCreateStorageBucket(t *testing.T) {
	validRequest := func() *pb.OnCreateStorageBucketRequest {
		return &pb.OnCreateStorageBucketRequest{
			Bucket: &storagebuckets.StorageBucket{
				BucketName: "foo",
				Secrets:    credential.MockStaticCredentialSecrets(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
						credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
					},
				},
			},
		}
	}
	cases := []struct {
		name                  string
		req                   *pb.OnCreateStorageBucketRequest
		credOpts              []credential.AwsCredentialPersistedStateOption
		storageOpts           []awsStoragePersistedStateOption
		expectedErrContains   string
		expectedErrCode       codes.Code
		expectedDetails       *pb.StorageBucketCredentialState
		expectedPersistedData map[string]any
	}{
		{
			name:                "nil storage bucket",
			req:                 &pb.OnCreateStorageBucketRequest{},
			expectedErrContains: "bucket is required",
			expectedErrCode:     codes.InvalidArgument,
			expectedDetails:     nil,
		},
		{
			name: "empty bucket name",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "bucketName is required",
			expectedErrCode:     codes.InvalidArgument,
			expectedDetails:     nil,
		},
		{
			name: "nil attributes",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
				},
			},
			expectedErrContains: "attributes is required",
			expectedErrCode:     codes.InvalidArgument,
			expectedDetails:     nil,
		},
		{
			name: "error reading attributes",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: new(structpb.Struct),
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
			expectedDetails:     nil,
		},
		{
			name: "dynamic credentials without disable credential rotation",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    &structpb.Struct{Fields: map[string]*structpb.Value{}},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:  structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn: structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
						},
					},
				},
			},
			expectedErrContains: "disable_credential_rotation attribute is required when providing a role_arn",
			expectedErrCode:     codes.InvalidArgument,
			expectedDetails:     nil,
		},
		{
			name:     "persisted state setup error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				func(s *awsStoragePersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
			expectedDetails:     nil,
		},
		{
			name: "rotation error",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    credential.MockStaticCredentialSecrets(),
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				}),
			},
			expectedErrContains: "aws service unknown: unknown error: rotating credentials:",
			expectedErrCode:     codes.Unknown,
			expectedDetails:     nil,
		},
		{
			name:     "dryRunValidation-failed-putObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(TestAwsS3Error("AccessDenied", "PutObject", "not authorized")),
					testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
					testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
					testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
						return &s3.ListObjectsV2Output{
							Contents: []s3types.Object{
								{
									Key: i.Prefix,
								},
							},
						}
					}),
				)),
			},
			expectedErrContains: "aws service s3: invalid credentials: put object:",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation putObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(TestAwsS3Error("ThrottlingException", "PutObject", "throttling exception")),
					testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
					testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
					testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
						return &s3.ListObjectsV2Output{
							Contents: []s3types.Object{
								{
									Key: i.Prefix,
								},
							},
						}
					}),
				)),
			},
			expectedErrContains: "aws service s3: throttling: put object:",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed getObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectError(TestAwsS3Error("AccessDenied", "GetObject", "not authorized")),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: get object:",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed getObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
						testMockS3WithGetObjectError(TestAwsS3Error("ThrottlingException", "GetObject", "throttling exception")),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: get object:",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed headObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
						testMockS3WithHeadObjectError(TestAwsS3Error("AccessDenied", "HeadObject", "not authorized")),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: head object:",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed headObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
						testMockS3WithHeadObjectError(TestAwsS3Error("ThrottlingException", "HeadObject", "throttling exception")),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: head object:",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed deleteObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
						testMockS3WithDeleteObjectError(TestAwsS3Error("AccessDenied", "DeleteObject", "not authorized")),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: delete object:",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Delete: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "success",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
						testMockS3WithDeleteObjectsOutput(&s3.DeleteObjectsOutput{}),
					),
				),
			},
			expectedPersistedData: credential.MockStaticCredentialSecrets().AsMap(),
		},
		{
			name: "success rotate static creds",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    credential.MockStaticCredentialSecrets(),
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(false),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts(
					[]awsutil.Option{
						awsutil.WithSTSAPIFunc(
							awsutil.NewMockSTS(),
						),
						awsutil.WithIAMAPIFunc(
							awsutil.NewMockIAM(
								awsutil.WithGetUserOutput(
									&iam.GetUserOutput{
										User: &iamTypes.User{
											Arn:      aws.String("arn:aws:iam::123456789012:user/JohnDoe"),
											UserId:   aws.String("AIDAJQABLZS4A3QDU576Q"),
											UserName: aws.String("JohnDoe"),
										},
									},
								),
								awsutil.WithCreateAccessKeyOutput(
									&iam.CreateAccessKeyOutput{
										AccessKey: &iamTypes.AccessKey{
											AccessKeyId:     aws.String("one"),
											SecretAccessKey: aws.String("two"),
											UserName:        aws.String("JohnDoe"),
										},
									},
								),
							),
						),
					},
				),
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{
				credential.ConstAccessKeyId:     "one",
				credential.ConstSecretAccessKey: "two",
			},
		},
		{
			name: "success with dynamic credentials",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    &structpb.Struct{},
					Attributes: credential.MockAssumeRoleAttributes("us-west-2", true),
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts(
					[]awsutil.Option{
						awsutil.WithSTSAPIFunc(
							awsutil.NewMockSTS(
								awsutil.WithAssumeRoleOutput(&sts.AssumeRoleOutput{
									Credentials: &types.Credentials{
										AccessKeyId:     aws.String("ASIAfoobar"),
										Expiration:      aws.Time(time.Now().Add(time.Hour)),
										SecretAccessKey: aws.String("secretkeyfoobar"),
									},
								}),
							),
						),
					},
				),
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{}, // No credentials sent back to Boundary as they are temporary.
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.OnCreateStorageBucket(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.expectedErrContains)
				assert.Equal(tc.expectedErrCode, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				if tc.expectedDetails != nil {
					var state *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							state = errDetail
							break
						}
					}
					require.NotNil(state)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Read, state.State.Read, true)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Write, state.State.Write, true)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Delete, state.State.Delete, true)
				} else {
					assert.Len(st.Details(), 0)
				}
				return
			}
			require.NoError(err)
			require.NotNil(resp)
			require.NotNil(resp.GetPersisted())
			require.NotNil(resp.GetPersisted().GetData())

			actualPersistedData := resp.GetPersisted().GetData().AsMap()
			if len(tc.expectedPersistedData) != 0 {
				require.NotEmpty(actualPersistedData)
				require.Equal(tc.expectedPersistedData[credential.ConstAccessKeyId], actualPersistedData[credential.ConstAccessKeyId])
				require.Equal(tc.expectedPersistedData[credential.ConstSecretAccessKey], actualPersistedData[credential.ConstSecretAccessKey])
				require.NotEmpty(actualPersistedData[credential.ConstCredsLastRotatedTime])
			}
		})
	}
}

func TestStoragePlugin_OnUpdateStorageBucket(t *testing.T) {
	validRequest := func() *pb.OnUpdateStorageBucketRequest {
		return &pb.OnUpdateStorageBucketRequest{
			NewBucket: &storagebuckets.StorageBucket{
				BucketName: "foo",
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
						credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
					},
				},
			},
			CurrentBucket: &storagebuckets.StorageBucket{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion: structpb.NewStringValue("us-west-2"),
					},
				},
			},
			Persisted: &storagebuckets.StorageBucketPersisted{
				Data: credential.MockStaticCredentialSecrets(),
			},
		}
	}
	cases := []struct {
		name                       string
		req                        *pb.OnUpdateStorageBucketRequest
		credOpts                   []credential.AwsCredentialPersistedStateOption
		storageOpts                []awsStoragePersistedStateOption
		expectedPersistedData      map[string]any
		expectCredsLastRotatedTime bool
		expectedErrContains        string
		expectedErrCode            codes.Code
		expectedDetails            *pb.StorageBucketCredentialState
	}{
		{
			name:                "nil new bucket",
			req:                 &pb.OnUpdateStorageBucketRequest{},
			expectedErrContains: "new bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "empty new bucketName",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "new bucketName is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil current bucket",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
				},
			},
			expectedErrContains: "current bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil current bucket attributes",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
				},
				CurrentBucket: &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "current bucket attributes is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil new bucket attributes",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
			},
			expectedErrContains: "new bucket attributes is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				func(s *awsStoragePersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "cannot disable rotation for already rotated credentials",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			expectedErrContains: "cannot disable rotation for already-rotated credentials",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "attempt to enable credential rotation with dynamic credentials",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(false),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: credential.MockAssumeRoleAttributes("us-west-2", true),
				},
			},
			expectedErrContains: "disable_credential_rotation attribute is required when providing a role_arn",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "updating secrets, replace error",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_onetwo"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("threefour"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				}),
			},
			expectedErrContains: "aws service unknown: unknown error: deleting credentials:",
			expectedErrCode:     codes.Unknown,
		},
		{
			name: "rotation error",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				}),
			},
			expectedErrContains: "aws service unknown: unknown error: rotating credentials",
			expectedErrCode:     codes.Unknown,
		},
		{
			name:     "dryRunValidation failed putObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
					testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
					testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
						return &s3.ListObjectsV2Output{
							Contents: []s3types.Object{
								{
									Key: i.Prefix,
								},
							},
						}
					}),
					testMockS3WithPutObjectError(TestAwsS3Error("AccessDenied", "PutObject", "not authorized")),
				)),
			},
			expectedErrContains: "aws service s3: invalid credentials: put object:",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed putObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
					testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
					testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
						return &s3.ListObjectsV2Output{
							Contents: []s3types.Object{
								{
									Key: i.Prefix,
								},
							},
						}
					}),
					testMockS3WithPutObjectError(TestAwsS3Error("ThrottlingException", "PutObject", "throttling exception")),
				)),
			},
			expectedErrContains: "aws service s3: throttling: put object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed getObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectError(TestAwsS3Error("AccessDenied", "GetObject", "not authorized")),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: get object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed getObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectError(TestAwsS3Error("ThrottlingException", "GetObject", "throttling exception")),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: get object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed headObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectError(TestAwsS3Error("AccessDenied", "HeadObject", "not authorized")),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: head object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed headObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectError(TestAwsS3Error("ThrottlingException", "HeadObject", "throttling exception")),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: head object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name: "success with credential rotation",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(),
					),
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserOutput(
								&iam.GetUserOutput{
									User: &iamTypes.User{
										Arn:      aws.String("arn:aws:iam::123456789012:user/JohnDoe"),
										UserId:   aws.String("AIDAJQABLZS4A3QDU576Q"),
										UserName: aws.String("JohnDoe"),
									},
								},
							),
							awsutil.WithCreateAccessKeyOutput(
								&iam.CreateAccessKeyOutput{
									AccessKey: &iamTypes.AccessKey{
										AccessKeyId:     aws.String("AKIA_one"),
										SecretAccessKey: aws.String("two"),
										UserName:        aws.String("JohnDoe"),
									},
								},
							),
						),
					),
				}),
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{
				credential.ConstAccessKeyId:     "AKIA_one",
				credential.ConstSecretAccessKey: "two",
			},
			expectCredsLastRotatedTime: true,
		},
		{
			name:     "success",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{
				credential.ConstAccessKeyId:     "AKIA_foobar",
				credential.ConstSecretAccessKey: "bazqux",
			},
		},
		{
			name: "dry run fail on dynamic to dynamic credentials update",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{Data: &structpb.Struct{}},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithHeadObjectError(TestAwsS3Error("AccessDenied", "HeadObject", "not authorized")),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: head object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name: "dynamic to dynamic credentials success",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{Data: &structpb.Struct{}},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{},
		},
		{
			name: "dry run fail on static non rotated to dynamic credentials update",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIAfoobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("secretkey"),
						},
					},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectError(TestAwsS3Error("AccessDenied", "PutObject", "not authorized")),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: put object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name: "success static non rotated to dynamic credentials",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIAfoobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("secretkey"),
						},
					},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{},
		},
		{
			name: "DeleteAccessKey error on static rotated to dynamic credentials update",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIAfoobar_rotated_accesskeyid"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("secretkey"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue(time.Now().Add(-time.Hour).Format(time.RFC3339Nano)),
						},
					},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(fmt.Errorf("delete access key fail oops")),
						),
					),
				}),
			},
			expectedErrContains: "aws service unknown: unknown error: deleting credentials",
			expectedErrCode:     codes.Unknown,
		},
		{
			name: "success static rotated to dynamic credentials",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIAfoobar_rotated_accesskeyid"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("secretkey"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue(time.Now().Add(-time.Hour).Format(time.RFC3339Nano)),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(), // DeleteAccessKey Success
					),
				}),
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{},
		},
		{
			name: "dry run fail on dynamic to static non-rotated credentials update",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("secretkey"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{Fields: map[string]*structpb.Value{}},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectError(TestAwsS3Error("AccessDenied", "PutObject", "not authorized")),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: put object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name: "success dynamic to static non-rotated credentials",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("secretkey"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{Fields: map[string]*structpb.Value{}},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{
				credential.ConstAccessKeyId:     "AKIA_foobar",
				credential.ConstSecretAccessKey: "secretkey",
			},
		},
		{
			name: "create access key error on dynamic to static rotated credentials update",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("secretkey"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{Fields: map[string]*structpb.Value{}},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(),
					),
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserOutput(
								&iam.GetUserOutput{
									User: &iamTypes.User{
										Arn:      aws.String("arn:aws:iam::123456789012:user/JohnDoe"),
										UserId:   aws.String("AIDAJQABLZS4A3QDU576Q"),
										UserName: aws.String("JohnDoe"),
									},
								},
							),
							awsutil.WithCreateAccessKeyError(fmt.Errorf("create access key fail oops")),
						),
					),
				}),
			},
			expectedErrContains: "aws service unknown: unknown error: rotating credentials",
			expectedErrCode:     codes.Unknown,
		},
		{
			name: "success dynamic to static rotated credentials",
			req: &pb.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("secretkey"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{Fields: map[string]*structpb.Value{}},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(),
					),
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserOutput(
								&iam.GetUserOutput{
									User: &iamTypes.User{
										Arn:      aws.String("arn:aws:iam::123456789012:user/JohnDoe"),
										UserId:   aws.String("AIDAJQABLZS4A3QDU576Q"),
										UserName: aws.String("JohnDoe"),
									},
								},
							),
							awsutil.WithCreateAccessKeyOutput(
								&iam.CreateAccessKeyOutput{
									AccessKey: &iamTypes.AccessKey{
										AccessKeyId:     aws.String("AKIA_one"),
										SecretAccessKey: aws.String("two"),
										UserName:        aws.String("JohnDoe"),
									},
								},
							),
						),
					),
				}),
			},
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedPersistedData: map[string]any{
				credential.ConstAccessKeyId:     "AKIA_one",
				credential.ConstSecretAccessKey: "two",
			},
			expectCredsLastRotatedTime: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.OnUpdateStorageBucket(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.expectedErrContains)
				assert.Equal(tc.expectedErrCode, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				if tc.expectedDetails != nil {
					var state *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							state = errDetail
							break
						}
					}
					require.NotNil(state)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Read, state.State.Read, true)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Write, state.State.Write, true)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Delete, state.State.Delete, true)
				} else {
					assert.Len(st.Details(), 0)
				}
				return
			}
			require.NoError(err)
			require.NotNil(resp)
			require.NotNil(resp.GetPersisted())
			require.NotNil(resp.GetPersisted().GetData())

			actualPersistedData := resp.GetPersisted().GetData().AsMap()
			if len(actualPersistedData) > 0 && len(tc.expectedPersistedData) == 0 {
				t.Fatalf("test case expected no persisted data, but got %#v", actualPersistedData)
			}
			if len(tc.expectedPersistedData) != 0 {
				require.NotEmpty(actualPersistedData)
				require.Equal(tc.expectedPersistedData[credential.ConstAccessKeyId], actualPersistedData[credential.ConstAccessKeyId])
				require.Equal(tc.expectedPersistedData[credential.ConstSecretAccessKey], actualPersistedData[credential.ConstSecretAccessKey])
				if tc.expectCredsLastRotatedTime {
					require.NotEmpty(actualPersistedData[credential.ConstCredsLastRotatedTime])
				}
			}
		})
	}
}

func TestStoragePlugin_OnDeleteStorageBucket(t *testing.T) {
	cases := []struct {
		name                string
		req                 *pb.OnDeleteStorageBucketRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		storageOpts         []awsStoragePersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
		expectedDetails     *pb.StorageBucketCredentialState
	}{
		{
			name:                "nil bucket",
			req:                 &pb.OnDeleteStorageBucketRequest{},
			expectedErrContains: "bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil attributes",
			req: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "attributes is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			req: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					Attributes: new(structpb.Struct),
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
			req: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			storageOpts: []awsStoragePersistedStateOption{
				func(s *awsStoragePersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "delete error",
			req: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				}),
			},
			expectedErrContains: "aws service unknown: unknown error: deleting credentials",
			expectedErrCode:     codes.Unknown,
		},
		{
			name: "success",
			req: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(nil),
						),
					),
				}),
			},
		},
		{
			name: "success with dynamic credentials",
			req: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::098765432109:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{Fields: map[string]*structpb.Value{}},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.OnDeleteStorageBucket(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.expectedErrContains)
				assert.Equal(tc.expectedErrCode, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				if tc.expectedDetails != nil {
					var state *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							state = errDetail
							break
						}
					}
					require.NotNil(state)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Read, state.State.Read, true)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Write, state.State.Write, true)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Delete, state.State.Delete, true)
				} else {
					assert.Len(st.Details(), 0)
				}
				return
			}
			require.NoError(err)
			require.NotNil(resp)
		})
	}
}

func TestStoragePlugin_HeadObject(t *testing.T) {
	validRequest := func() *pb.HeadObjectRequest {
		return &pb.HeadObjectRequest{
			Key: "/foo/bar/key",
			Bucket: &storagebuckets.StorageBucket{
				BucketName: "foo",
				Secrets:    credential.MockStaticCredentialSecrets(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion: structpb.NewStringValue("us-west-2"),
					},
				},
			},
		}
	}
	cases := []struct {
		name                string
		req                 *pb.HeadObjectRequest
		contentLength       int64
		lastModified        time.Time
		credOpts            []credential.AwsCredentialPersistedStateOption
		storageOpts         []awsStoragePersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
		expectedDetails     *pb.StorageBucketCredentialState
	}{
		{
			name:                "empty object key",
			req:                 &pb.HeadObjectRequest{},
			expectedErrContains: "key is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil bucket",
			req: &pb.HeadObjectRequest{
				Key: "/foo/bar/key",
			},
			expectedErrContains: "bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "empty bucket name",
			req: &pb.HeadObjectRequest{
				Key:    "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "bucketName is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil attributes",
			req: &pb.HeadObjectRequest{
				Key: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
				},
			},
			expectedErrContains: "attributes is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			req: &pb.HeadObjectRequest{
				Key: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "credential persisted state setup error",
			req:  validRequest(),
			credOpts: []credential.AwsCredentialPersistedStateOption{
				func(s *credential.AwsCredentialPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "storage persisted state setup error",
			req:  validRequest(),
			storageOpts: []awsStoragePersistedStateOption{
				func(s *awsStoragePersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:     "headObject error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithHeadObjectError(TestAwsS3Error("AccessDenied", "HeadObject", "not authorized")),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: head object",
			expectedErrCode:     codes.PermissionDenied,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "headObject throttle error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithHeadObjectError(TestAwsS3Error("ThrottlingException", "HeadObject", "throttling exception")),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: head object",
			expectedErrCode:     codes.Unavailable,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "headObject not found error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithHeadObjectError(TestAwsS3Error("NoSuchKey", "HeadObject", "resource not found")),
					),
				),
			},
			expectedErrContains: "aws service s3: head object",
			expectedErrCode:     codes.NotFound,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:          "success",
			req:           validRequest(),
			credOpts:      validSTSMock(),
			contentLength: 1024,
			lastModified:  createTime(t, "2006-01-02T15:04:05Z"),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{
							ContentLength: 1024,
							LastModified:  aws.Time(createTime(t, "2006-01-02T15:04:05Z")),
						}),
					),
				),
			},
		},
		{
			name: "success with dynamic credentials",
			req: &pb.HeadObjectRequest{
				Key: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
			},
			credOpts:      validSTSMock(),
			contentLength: 1024,
			lastModified:  createTime(t, "2006-01-02T15:04:05Z"),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{
							ContentLength: 1024,
							LastModified:  aws.Time(createTime(t, "2006-01-02T15:04:05Z")),
						}),
					),
				),
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.HeadObject(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.expectedErrContains)
				assert.Equal(tc.expectedErrCode, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				if tc.expectedDetails != nil {
					var state *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							state = errDetail
							break
						}
					}
					require.NotNil(state)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Read, state.State.Read, false)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Write, state.State.Write, false)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Delete, state.State.Delete, false)
				} else {
					assert.Len(st.Details(), 0)
				}
				return
			}
			require.NoError(err)
			require.NotNil(resp)
			require.Equal(tc.contentLength, resp.ContentLength)
			require.Equal(tc.lastModified.String(), resp.LastModified.AsTime().String())
		})
	}
}

func TestStoragePlugin_ValidatePermissions(t *testing.T) {
	validRequest := func() *pb.ValidatePermissionsRequest {
		return &pb.ValidatePermissionsRequest{
			Bucket: &storagebuckets.StorageBucket{
				BucketName: "foo",
				Secrets:    credential.MockStaticCredentialSecrets(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion: structpb.NewStringValue("us-west-2"),
					},
				},
			},
		}
	}
	cases := []struct {
		name                string
		req                 *pb.ValidatePermissionsRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		storageOpts         []awsStoragePersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
		expectedDetails     *pb.StorageBucketCredentialState
	}{
		{
			name:                "nil bucket",
			req:                 &pb.ValidatePermissionsRequest{},
			expectedErrContains: "bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "empty bucket name",
			req: &pb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "bucketName is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil attributes",
			req: &pb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
				},
			},
			expectedErrContains: "attributes is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			req: &pb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "credential persisted state setup error",
			req:  validRequest(),
			credOpts: []credential.AwsCredentialPersistedStateOption{
				func(s *credential.AwsCredentialPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "storage persisted state setup error",
			req:  validRequest(),
			storageOpts: []awsStoragePersistedStateOption{
				func(s *awsStoragePersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:     "dryRunValidation failed putObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(TestAwsS3Error("AccessDenied", "PutObject", "not authorized")),
					testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
					testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
					testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
						return &s3.ListObjectsV2Output{
							Contents: []s3types.Object{
								{
									Key: i.Prefix,
								},
							},
						}
					}),
				)),
			},
			expectedErrContains: "aws service s3: invalid credentials: put object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed putObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(TestAwsS3Error("ThrottlingException", "PutObject", "throttling exception")),
					testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
					testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
					testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
						return &s3.ListObjectsV2Output{
							Contents: []s3types.Object{
								{
									Key: i.Prefix,
								},
							},
						}
					}),
				)),
			},
			expectedErrContains: "aws service s3: throttling: put object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed getObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectError(TestAwsS3Error("AccessDenied", "GetObject", "not authorized")),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: get object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed getObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectError(TestAwsS3Error("ThrottlingException", "GetObject", "throttling exception")),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: get object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed headObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectError(TestAwsS3Error("AccessDenied", "HeadObject", "not authorized")),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: head object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "dryRunValidation failed headObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectError(TestAwsS3Error("ThrottlingException", "HeadObject", "throttling exception")),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: head object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "success",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
		},
		{
			name: "success with dynamic credentials",
			req: &pb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
			},
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
						testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: i.Prefix,
									},
								},
							}
						}),
					),
				),
			},
		},
		{
			name:     "dryRunValidation failed putObject with missing list expected key",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(TestAwsS3Error("AccessDenied", "PutObject", "not authorized")),
					testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
					testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
					testMockS3WithListObjectsV2OutputFunc(func(i *s3.ListObjectsV2Input) *s3.ListObjectsV2Output {
						return &s3.ListObjectsV2Output{
							Contents: []s3types.Object{},
						}
					}),
				)),
			},
			expectedErrContains: "aws service s3: invalid credentials: put object",
			expectedErrCode:     codes.FailedPrecondition,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
					Write: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
					Delete: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_OK,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.ValidatePermissions(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.expectedErrContains)
				assert.Equal(tc.expectedErrCode, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				if tc.expectedDetails != nil {
					var state *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							state = errDetail
							break
						}
					}
					require.NotNil(state)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Read, state.State.Read, true)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Write, state.State.Write, true)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Delete, state.State.Delete, true)
				} else {
					assert.Len(st.Details(), 0)
				}
				return
			}
			require.NoError(err)
			require.NotNil(resp)
		})
	}
}

func TestStoragePlugin_GetObject(t *testing.T) {
	validRequest := func() *pb.GetObjectRequest {
		return &pb.GetObjectRequest{
			Key: "/foo/bar/key",
			Bucket: &storagebuckets.StorageBucket{
				BucketName: "foo",
				Secrets:    credential.MockStaticCredentialSecrets(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion: structpb.NewStringValue("us-west-2"),
					},
				},
			},
		}
	}
	cases := []struct {
		name                string
		req                 *pb.GetObjectRequest
		objectData          []byte
		credOpts            []credential.AwsCredentialPersistedStateOption
		storageOpts         []awsStoragePersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
		expectedDetails     *pb.StorageBucketCredentialState
	}{
		{
			name:                "empty object key",
			req:                 &pb.GetObjectRequest{},
			expectedErrContains: "key is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil bucket",
			req: &pb.GetObjectRequest{
				Key: "/foo/bar/key",
			},
			expectedErrContains: "bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "missing bucket name",
			req: &pb.GetObjectRequest{
				Key:    "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "bucketName is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil attributes",
			req: &pb.GetObjectRequest{
				Key: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
				},
			},
			expectedErrContains: "attributes is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			req: &pb.GetObjectRequest{
				Key: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "credential persisted state setup error",
			req:  validRequest(),
			credOpts: []credential.AwsCredentialPersistedStateOption{
				func(s *credential.AwsCredentialPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "storage persisted state setup error",
			req:  validRequest(),
			storageOpts: []awsStoragePersistedStateOption{
				func(s *awsStoragePersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:     "getObject error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectError(TestAwsS3Error("AccessDenied", "GetObject", "not authorized")),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: get object",
			expectedErrCode:     codes.PermissionDenied,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "getObject no such key",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectError(TestAwsS3Error("NoSuchKey", "GetObject", "resource not found")),
					),
				),
			},
			expectedErrContains: "aws service s3: get object",
			expectedErrCode:     codes.NotFound,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "getObject invalid state",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectError(TestAwsS3Error("InvalidObjectState", "GetObject", "resource is in cold storage")),
					),
				),
			},
			expectedErrContains: "aws service s3: get object",
			expectedErrCode:     codes.NotFound,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "getObject no such bucket",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectError(TestAwsS3Error("NoSuchBucket", "GetObject", "bucket does not exist")),
					),
				),
			},
			expectedErrContains: "aws service s3: get object",
			expectedErrCode:     codes.NotFound,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "bucket does not exist",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "getObject throttle error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectError(TestAwsS3Error("ThrottlingException", "GetObject", "throttling exception")),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: get object",
			expectedErrCode:     codes.Unavailable,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Read: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name: "with chunk size",
			req: func() *pb.GetObjectRequest {
				request := validRequest()
				request.ChunkSize = 16384
				return request
			}(),
			credOpts:   validSTSMock(),
			objectData: []byte("test"),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{
							Body: io.NopCloser(bytes.NewReader([]byte("test"))),
						}),
					),
				),
			},
		},
		{
			name:       "success",
			req:        validRequest(),
			credOpts:   validSTSMock(),
			objectData: []byte("test"),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{
							Body: io.NopCloser(bytes.NewReader([]byte("test"))),
						}),
					),
				),
			},
		},
		{
			name: "success with dynamic credentials",
			req: &pb.GetObjectRequest{
				Key: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
			},
			credOpts:   validSTSMock(),
			objectData: []byte("test"),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{
							Body: io.NopCloser(bytes.NewReader([]byte("test"))),
						}),
					),
				),
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			stream := newGetObjectStreamMock()
			err := p.GetObject(tc.req, stream)
			if tc.expectedErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.expectedErrContains)
				assert.Equal(tc.expectedErrCode, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				if tc.expectedDetails != nil {
					var state *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							state = errDetail
							break
						}
					}
					require.NotNil(state)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Read, state.State.Read, false)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Write, state.State.Write, false)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Delete, state.State.Delete, false)
				} else {
					assert.Len(st.Details(), 0)
				}
				return
			}
			require.NoError(err)

			resp, err := stream.Recv()
			require.NoError(err)
			require.NotNil(resp)
			require.EqualValues(tc.objectData, resp.FileChunk)
		})
	}
}

func TestStoragePlugin_PutObject(t *testing.T) {
	td := t.TempDir()

	emptyFilePath := path.Join(td, "empty-file-test")
	emptyFile, err := os.Create(emptyFilePath)
	require.NoError(t, err)
	require.NoError(t, emptyFile.Close())

	validFilePath := path.Join(td, "valid-file-test")
	validFile, err := os.Create(validFilePath)
	require.NoError(t, err)
	n, err := validFile.WriteString("CONTENT CHECK")
	require.NoError(t, err)
	require.Equal(t, len("CONTENT CHECK"), n)
	require.NoError(t, validFile.Close())

	validRequest := func() *pb.PutObjectRequest {
		return &pb.PutObjectRequest{
			Bucket: &storagebuckets.StorageBucket{
				BucketName: "external-obj-store",
				Secrets:    credential.MockStaticCredentialSecrets(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion: structpb.NewStringValue("us-west-2"),
					},
				},
			},
			Key:  "mock-object",
			Path: validFilePath,
		}
	}

	cases := []struct {
		name                string
		credOpts            []credential.AwsCredentialPersistedStateOption
		storageOpts         []awsStoragePersistedStateOption
		request             *pb.PutObjectRequest
		setup               func()
		expectedObject      []byte
		expectedErrContains string
		expectedErrCode     codes.Code
		expectedDetails     *pb.StorageBucketCredentialState
	}{
		{
			name:                "missing request",
			expectedErrContains: "request is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:                "missing object key",
			request:             &pb.PutObjectRequest{},
			expectedErrContains: "key is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "missing bucket",
			request: &pb.PutObjectRequest{
				Key: "mock-object",
			},
			expectedErrContains: "bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "missing bucket name",
			request: &pb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{},
				Key:    "mock-object",
			},
			expectedErrContains: "bucketName is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "missing attributes",
			request: &pb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "external-obj-store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
				},
				Key: "mock-object",
			},
			expectedErrContains: "attributes is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "missing path",
			request: &pb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "external-obj-store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Key: "mock-object",
			},
			expectedErrContains: "path is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "file does not exist",
			request: &pb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "external-obj-store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Key:  "mock-object",
				Path: path.Join(td, "file-does-not-exist"),
			},
			expectedErrContains: "failed to open file",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "path is a directory",
			request: &pb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "external-obj-store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Key:  "mock-object",
				Path: td,
			},
			expectedErrContains: "path is not a file",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "file is empty",
			request: &pb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "external-obj-store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("us-west-2"),
						},
					},
				},
				Key:  "mock-object",
				Path: emptyFilePath,
			},
			expectedErrContains: "file is empty",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			request: &pb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "external-obj-store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{},
					},
				},
				Key:  "mock-object",
				Path: validFilePath,
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:    "credential persisted state setup error",
			request: validRequest(),
			credOpts: []credential.AwsCredentialPersistedStateOption{
				func(s *credential.AwsCredentialPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:    "storage persisted state setup error",
			request: validRequest(),
			storageOpts: []awsStoragePersistedStateOption{
				func(s *awsStoragePersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:     "putObject error",
			request:  validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectError(TestAwsS3Error("AccessDenied", "PutObject", "not authorized")),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: put object",
			expectedErrCode:     codes.PermissionDenied,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "putObject no such bucket",
			request:  validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectError(TestAwsS3Error("NoSuchBucket", "PutObject", "bucket does not exist")),
					),
				),
			},
			expectedErrContains: "aws service s3: put object",
			expectedErrCode:     codes.NotFound,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "bucket does not exist",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "throttle error",
			request:  validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectError(TestAwsS3Error("ThrottlingException", "PutObject", "throttling exception")),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: put object",
			expectedErrCode:     codes.Unavailable,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Write: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:           "missing checksum from aws",
			request:        validRequest(),
			credOpts:       validSTSMock(),
			expectedObject: []byte("CONTENT CHECK"),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						&testMockS3State{
							PutObjectBody: []byte("CONTENT CHECK"),
						},
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
					),
				),
			},
			expectedErrContains: "missing checksum response from aws",
			expectedErrCode:     codes.Internal,
			expectedDetails:     nil,
		},
		{
			name:           "mismatched checksum",
			request:        validRequest(),
			credOpts:       validSTSMock(),
			expectedObject: []byte("CONTENT CHECK"),
			storageOpts: func() []awsStoragePersistedStateOption {
				hash := sha256.New()
				_, err := hash.Write([]byte("CONTENT CHECK"))
				require.NoError(t, err)
				return []awsStoragePersistedStateOption{
					withTestS3APIFunc(
						newTestMockS3(
							&testMockS3State{
								PutObjectBody: []byte("CONTENT CHECK"),
							},
							testMockS3WithPutObjectOutput(&s3.PutObjectOutput{
								ChecksumSHA256: aws.String(string(hash.Sum(nil))),
							}),
						),
					),
				}
			}(),
			expectedErrContains: "mismatched checksum",
			expectedErrCode:     codes.Aborted,
			expectedDetails:     nil,
		},
		{
			name:           "valid file",
			request:        validRequest(),
			credOpts:       validSTSMock(),
			expectedObject: []byte("CONTENT CHECK"),
			storageOpts: func() []awsStoragePersistedStateOption {
				hash := sha256.New()
				_, err := hash.Write([]byte("CONTENT CHECK"))
				require.NoError(t, err)
				checksum := base64.StdEncoding.EncodeToString(hash.Sum(nil))
				return []awsStoragePersistedStateOption{
					withTestS3APIFunc(
						newTestMockS3(
							&testMockS3State{
								PutObjectBody: []byte("CONTENT CHECK"),
							},
							testMockS3WithPutObjectOutput(&s3.PutObjectOutput{
								ChecksumSHA256: aws.String(checksum),
							}),
						),
					),
				}
			}(),
		},
		{
			name: "valid file using dynamic credentials",
			request: &pb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "external-obj-store",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Key:  "mock-object",
				Path: validFilePath,
			},
			credOpts:       validSTSMock(),
			expectedObject: []byte("CONTENT CHECK"),
			storageOpts: func() []awsStoragePersistedStateOption {
				hash := sha256.New()
				_, err := hash.Write([]byte("CONTENT CHECK"))
				require.NoError(t, err)
				checksum := base64.StdEncoding.EncodeToString(hash.Sum(nil))
				return []awsStoragePersistedStateOption{
					withTestS3APIFunc(
						newTestMockS3(
							&testMockS3State{
								PutObjectBody: []byte("CONTENT CHECK"),
							},
							testMockS3WithPutObjectOutput(&s3.PutObjectOutput{
								ChecksumSHA256: aws.String(checksum),
							}),
						),
					),
				}
			}(),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			if tc.request != nil && len(tc.expectedObject) > 0 {
				data, err := os.ReadFile(tc.request.Path)
				require.NoError(err)
				require.ElementsMatch(data, tc.expectedObject)
			}
			resp, err := p.PutObject(context.Background(), tc.request)
			if tc.expectedErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.expectedErrContains)
				assert.Equal(tc.expectedErrCode, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				if tc.expectedDetails != nil {
					var state *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							state = errDetail
							break
						}
					}
					require.NotNil(state)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Read, state.State.Read, false)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Write, state.State.Write, false)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Delete, state.State.Delete, false)
				} else {
					assert.Len(st.Details(), 0)
				}
				return
			}
			require.NoError(err)
			require.NotNil(resp)

			hash := sha256.New()
			_, err = hash.Write(tc.expectedObject)
			require.NoError(err)
			require.True(bytes.Equal(hash.Sum(nil), resp.GetChecksumSha_256()))
		})
	}
}

func TestStoragePlugin_DeleteObjects(t *testing.T) {
	validRequest := func() *pb.DeleteObjectsRequest {
		return &pb.DeleteObjectsRequest{
			Bucket: &storagebuckets.StorageBucket{
				BucketName: "external-obj-store",
				Secrets:    credential.MockStaticCredentialSecrets(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion: structpb.NewStringValue("us-west-2"),
					},
				},
			},
			KeyPrefix: "abc/",
		}
	}

	validRecursiveRequest := func() *pb.DeleteObjectsRequest {
		return &pb.DeleteObjectsRequest{
			Bucket: &storagebuckets.StorageBucket{
				BucketName: "external-obj-store",
				Secrets:    credential.MockStaticCredentialSecrets(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						credential.ConstRegion: structpb.NewStringValue("us-west-2"),
					},
				},
			},
			KeyPrefix: "abc/",
			Recursive: true,
		}
	}

	cases := []struct {
		name                string
		req                 *pb.DeleteObjectsRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		storageOpts         []awsStoragePersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
		expectedDetails     *pb.StorageBucketCredentialState
		expected            uint32
	}{
		{
			name:                "empty key prefix",
			req:                 &pb.DeleteObjectsRequest{},
			expectedErrContains: "key prefix is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil bucket",
			req: &pb.DeleteObjectsRequest{
				KeyPrefix: "/foo/bar/key",
			},
			expectedErrContains: "bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "missing bucket name",
			req: &pb.DeleteObjectsRequest{
				KeyPrefix: "/foo/bar/key",
				Bucket:    &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "bucketName is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil attributes",
			req: &pb.DeleteObjectsRequest{
				KeyPrefix: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
				},
			},
			expectedErrContains: "attributes is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			req: &pb.DeleteObjectsRequest{
				KeyPrefix: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "credential persisted state setup error",
			req:  validRequest(),
			credOpts: []credential.AwsCredentialPersistedStateOption{
				func(s *credential.AwsCredentialPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "storage persisted state setup error",
			req:  validRequest(),
			storageOpts: []awsStoragePersistedStateOption{
				func(s *awsStoragePersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:     "DeleteObject error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithDeleteObjectError(TestAwsS3Error("AccessDenied", "DeleteObject", "not authorized")),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: delete object",
			expectedErrCode:     codes.PermissionDenied,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Delete: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "ListObjectV2 error",
			req:      validRecursiveRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithListObjectsV2Error(TestAwsS3Error("AccessDenied", "ListObjectsV2", "not authorized")),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: list objects",
			expectedErrCode:     codes.PermissionDenied,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Delete: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "DeleteObjects error",
			req:      validRecursiveRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithListObjectsV2Output(&s3.ListObjectsV2Output{
							IsTruncated: false,
							Contents: []s3types.Object{
								{
									Key: aws.String("abc/abc"),
								},
							},
						}),
						testMockS3WithDeleteObjectsError(TestAwsS3Error("AccessDenied", "DeleteObjects", "not authorized")),
					),
				),
			},
			expectedErrContains: "aws service s3: invalid credentials: delete objects",
			expectedErrCode:     codes.PermissionDenied,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Delete: &pb.Permission{
						State:        pb.StateType_STATE_TYPE_ERROR,
						ErrorDetails: "not authorized",
						CheckedAt:    timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "DeleteObject throttle error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithDeleteObjectError(TestAwsS3Error("ThrottlingException", "DeleteObject", "throttling exception")),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: delete object",
			expectedErrCode:     codes.Unavailable,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Delete: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "ListObjectsV2 throttle error",
			req:      validRecursiveRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithListObjectsV2Error(TestAwsS3Error("ThrottlingException", "ListObjectsV2", "throttling exception")),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: list objects",
			expectedErrCode:     codes.Unavailable,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Delete: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "DeleteObjects throttle error",
			req:      validRecursiveRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithListObjectsV2Output(&s3.ListObjectsV2Output{
							IsTruncated: false,
							Contents: []s3types.Object{
								s3types.Object{
									Key: aws.String("abc/abc"),
								},
							},
						}),
						testMockS3WithDeleteObjectsError(TestAwsS3Error("ThrottlingException", "DeleteObjects", "throttling exception")),
					),
				),
			},
			expectedErrContains: "aws service s3: throttling: delete objects",
			expectedErrCode:     codes.Unavailable,
			expectedDetails: &pb.StorageBucketCredentialState{
				State: &pb.Permissions{
					Delete: &pb.Permission{
						State:     pb.StateType_STATE_TYPE_UNKNOWN,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
		},
		{
			name:     "success",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithDeleteObjectOutput(&s3.DeleteObjectOutput{}),
					),
				),
			},
			expected: 1,
		},
		{
			name:     "recursive success",
			req:      validRecursiveRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithListObjectsV2Output(&s3.ListObjectsV2Output{
							IsTruncated: false,
							Contents: []s3types.Object{
								{Key: aws.String("abc/abc1")},
								{Key: aws.String("abc/abc2")},
								{Key: aws.String("abc/abc3")},
							},
						}),
						testMockS3WithDeleteObjectsOutput(&s3.DeleteObjectsOutput{
							Deleted: []s3types.DeletedObject{
								{},
								{},
								{},
							},
						}),
					),
				),
			},
			expected: 3,
		},
		{
			name:     "recursive success empty",
			req:      validRecursiveRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithListObjectsV2Output(&s3.ListObjectsV2Output{
							IsTruncated: false,
							Contents:    []s3types.Object{},
						}),
						// no deleted response since it shouldn't be called
					),
				),
			},
			expected: 0,
		},
		{
			name: "success with dynamic credentials",
			req: &pb.DeleteObjectsRequest{
				KeyPrefix: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
							credential.ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
							credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
			},
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithDeleteObjectOutput(&s3.DeleteObjectOutput{}),
					),
				),
			},
			expected: 1,
		},
		// NOTE: there is no automated test for checking continuation tokens or multiple
		// delete calls due to not having a stack for output responses. this was tested
		// manually
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			res, err := p.DeleteObjects(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.expectedErrContains)
				assert.Equal(tc.expectedErrCode, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				if tc.expectedDetails != nil {
					var state *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							state = errDetail
							break
						}
					}
					require.NotNil(state)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Read, state.State.Read, false)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Write, state.State.Write, false)
					internal.CheckSimilarPermission(assert, tc.expectedDetails.State.Delete, state.State.Delete, false)
				} else {
					assert.Len(st.Details(), 0)
				}
				return
			}
			require.NoError(err)

			require.NoError(err)
			require.NotNil(res)
			require.Equal(tc.expected, res.ObjectsDeleted)
		})
	}
}
