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
	"io/ioutil"
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
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
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
		expectedPersistedData map[string]any
	}{
		{
			name:                "nil storage bucket",
			req:                 &pb.OnCreateStorageBucketRequest{},
			expectedErrContains: "bucket is required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "empty bucket name",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{},
			},
			expectedErrContains: "bucketName is required",
			expectedErrCode:     codes.InvalidArgument,
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
		},
		{
			name: "invalid region",
			req: &pb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("foobar"),
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
			expectedErrCode:     codes.InvalidArgument,
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
			expectedErrContains: fmt.Sprintf("error during credential rotation: error rotating credentials: error calling CreateAccessKey: error calling iam.GetUser: %s", testGetUserErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:     "dryRunValidation failed putObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(errors.New(testPutObjectErr)),
				)),
			},
			expectedErrContains: "error failed to put object: test error for PutObject",
			expectedErrCode:     codes.Internal,
		},
		{
			name:     "dryRunValidation putObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(new(throttleErr)),
				)),
			},
			expectedErrContains: "error failed to put object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
						testMockS3WithGetObjectError(errors.New(testGetObjectErr)),
					),
				),
			},
			expectedErrContains: "error failed to get object: test error for GetObject",
			expectedErrCode:     codes.Internal,
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
						testMockS3WithGetObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error failed to get object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
						testMockS3WithHeadObjectError(errors.New(testHeadObjectErr)),
					),
				),
			},
			expectedErrContains: "error failed to get head object: test error for HeadObject",
			expectedErrCode:     codes.Internal,
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
						testMockS3WithHeadObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error failed to get head object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
			require := require.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.OnCreateStorageBucket(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
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

// TODO: add tests for changing:
// roleARN values
// access/secret keys
// swithcing between static & dynamic credentials
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
			name: "invalid region",
			req: &pb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("foobar"),
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
			},
			expectedErrContains: "not a valid region: foobar",
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
			expectedErrCode:     codes.FailedPrecondition,
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
			expectedErrContains: fmt.Sprintf("error attempting to replace credentials: error deleting old access key: %s", testDeleteAccessKeyErr),
			expectedErrCode:     codes.InvalidArgument,
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
			expectedErrContains: fmt.Sprintf("error during credential rotation: error rotating credentials: error calling CreateAccessKey: error calling iam.GetUser: %s", testGetUserErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name:     "dryRunValidation failed putObject",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(errors.New(testPutObjectErr)),
				)),
			},
			expectedErrContains: "error failed to put object: test error for PutObject",
			expectedErrCode:     codes.Internal,
		},
		{
			name:     "dryRunValidation failed putObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(new(throttleErr)),
				)),
			},
			expectedErrContains: "error failed to put object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
						testMockS3WithGetObjectError(errors.New(testGetObjectErr)),
					),
				),
			},
			expectedErrContains: "error failed to get object: test error for GetObject",
			expectedErrCode:     codes.Internal,
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
						testMockS3WithGetObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error failed to get object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
						testMockS3WithHeadObjectError(errors.New(testHeadObjectErr)),
					),
				),
			},
			expectedErrContains: "error failed to get head object: test error for HeadObject",
			expectedErrCode:     codes.Internal,
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
						testMockS3WithHeadObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error failed to get head object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
						testMockS3WithHeadObjectError(fmt.Errorf("head object failed oops")),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithPutObjectOutput(&s3.PutObjectOutput{}),
					),
				),
			},
			expectedErrContains: "head object failed oops",
			expectedErrCode:     codes.InvalidArgument,
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
						testMockS3WithPutObjectError(fmt.Errorf("put object failed oops")),
						testMockS3WithGetObjectOutput(&s3.GetObjectOutput{}),
						testMockS3WithHeadObjectOutput(&s3.HeadObjectOutput{}),
					),
				),
			},
			expectedErrContains: "put object failed oops",
			expectedErrCode:     codes.InvalidArgument,
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
			expectedErrContains: "delete access key fail oops",
			expectedErrCode:     codes.InvalidArgument,
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
						testMockS3WithPutObjectError(fmt.Errorf("put object fail oops")),
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
			expectedErrContains: "put object fail oops",
			expectedErrCode:     codes.InvalidArgument,
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
			expectedErrContains: "create access key fail oops",
			expectedErrCode:     codes.InvalidArgument,
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
			require := require.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.OnUpdateStorageBucket(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.NotNil(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
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
			name: "invalid region",
			req: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    credential.MockStaticCredentialSecrets(),
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("foobar"),
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
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
			expectedErrContains: fmt.Sprintf("error removing rotated credentials during storage bucket deletion: error deleting old access key: %s", testDeleteAccessKeyErr),
			expectedErrCode:     codes.Aborted,
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
			require := require.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.OnDeleteStorageBucket(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.NotNil(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
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
			name: "invalid region",
			req: &pb.HeadObjectRequest{
				Key: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("foobar"),
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
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
						testMockS3WithHeadObjectError(errors.New(testHeadObjectErr)),
					),
				),
			},
			expectedErrContains: "error getting head object from s3: test error for HeadObject",
			expectedErrCode:     codes.Internal,
		},
		{
			name:     "headObject throttle error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithHeadObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error getting head object from s3: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
			require := require.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.HeadObject(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Nil(resp)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
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
			name: "invalid region",
			req: &pb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("foobar"),
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
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
					testMockS3WithPutObjectError(errors.New(testPutObjectErr)),
				)),
			},
			expectedErrContains: "error failed to put object: test error for PutObject",
			expectedErrCode:     codes.Internal,
		},
		{
			name:     "dryRunValidation failed putObject throttle",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(newTestMockS3(
					nil,
					testMockS3WithPutObjectError(new(throttleErr)),
				)),
			},
			expectedErrContains: "error failed to put object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
						testMockS3WithGetObjectError(errors.New(testGetObjectErr)),
					),
				),
			},
			expectedErrContains: "error failed to get object: test error for GetObject",
			expectedErrCode:     codes.Internal,
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
						testMockS3WithGetObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error failed to get object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
						testMockS3WithHeadObjectError(errors.New(testHeadObjectErr)),
					),
				),
			},
			expectedErrContains: "error failed to get head object: test error for HeadObject",
			expectedErrCode:     codes.Internal,
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
						testMockS3WithHeadObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error failed to get head object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			resp, err := p.ValidatePermissions(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Nil(resp)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
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
			name: "invalid region",
			req: &pb.GetObjectRequest{
				Key: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("foobar"),
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
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
						testMockS3WithGetObjectError(errors.New(testGetObjectErr)),
					),
				),
			},
			expectedErrContains: "error getting object from s3: test error for GetObject",
			expectedErrCode:     codes.Internal,
		},
		{
			name:     "getObject throttle error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithGetObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error getting object from s3: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
							Body: ioutil.NopCloser(bytes.NewReader([]byte("test"))),
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
							Body: ioutil.NopCloser(bytes.NewReader([]byte("test"))),
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
							Body: ioutil.NopCloser(bytes.NewReader([]byte("test"))),
						}),
					),
				),
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			stream := newGetObjectStreamMock()
			err := p.GetObject(tc.req, stream)
			if tc.expectedErrContains != "" {
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
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
			expectedErrCode:     codes.Internal,
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
			name: "invalid region",
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
							credential.ConstRegion: structpb.NewStringValue("foobar"),
						},
					},
				},
				Key:  "mock-object",
				Path: validFilePath,
			},
			expectedErrContains: "not a valid region: foobar",
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
						testMockS3WithPutObjectError(errors.New(testPutObjectErr)),
					),
				),
			},
			expectedErrContains: "error putting object into s3: test error for PutObject",
			expectedErrCode:     codes.Internal,
		},
		{
			name:     "throttle error",
			request:  validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithPutObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error putting object into s3: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
			expectedErrCode:     codes.Internal,
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
			require := require.New(t)
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
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(tc.expectedErrCode.String(), status.Code(err).String())
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
			name: "invalid region",
			req: &pb.DeleteObjectsRequest{
				KeyPrefix: "/foo/bar/key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstRegion: structpb.NewStringValue("foobar"),
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
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
						testMockS3WithDeleteObjectError(errors.New(testDeleteObjectErr)),
					),
				),
			},
			expectedErrContains: "error deleting S3 object: test error for DeleteObject",
			expectedErrCode:     codes.Internal,
		},
		{
			name:     "ListObjectV2 error",
			req:      validRecursiveRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithListObjectsV2Error(errors.New(testListObjectV2Err)),
					),
				),
			},
			expectedErrContains: "error iterating S3 bucket contents: test error for ListObjectV2",
			expectedErrCode:     codes.Internal,
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
								s3types.Object{
									Key: aws.String("abc/abc"),
								},
							},
						}),
						testMockS3WithDeleteObjectsError(errors.New(testDeleteObjectsErr)),
					),
				),
			},
			expectedErrContains: "error deleting S3 object(s): test error for DeleteObjects",
			expectedErrCode:     codes.Internal,
		},
		{
			name:     "DeleteObject throttle error",
			req:      validRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithDeleteObjectError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error deleting S3 object: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
		},
		{
			name:     "ListObjectsV2 throttle error",
			req:      validRecursiveRequest(),
			credOpts: validSTSMock(),
			storageOpts: []awsStoragePersistedStateOption{
				withTestS3APIFunc(
					newTestMockS3(
						nil,
						testMockS3WithListObjectsV2Error(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error iterating S3 bucket contents: ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
						testMockS3WithDeleteObjectsError(new(throttleErr)),
					),
				),
			},
			expectedErrContains: "error deleting S3 object(s): ThrottlingException",
			expectedErrCode:     codes.Unavailable,
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
								s3types.Object{
									Key: aws.String("abc/abc1"),
								},
								s3types.Object{
									Key: aws.String("abc/abc2"),
								},
								s3types.Object{
									Key: aws.String("abc/abc3"),
								},
							},
						}),
						testMockS3WithDeleteObjectsOutput(&s3.DeleteObjectsOutput{
							Deleted: []s3types.DeletedObject{
								s3types.DeletedObject{},
								s3types.DeletedObject{},
								s3types.DeletedObject{},
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
			require := require.New(t)
			p := &StoragePlugin{
				testCredStateOpts:    tc.credOpts,
				testStorageStateOpts: tc.storageOpts,
			}
			res, err := p.DeleteObjects(context.Background(), tc.req)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
				return
			}
			require.NoError(err)

			require.NoError(err)
			require.NotNil(res)
			require.Equal(tc.expected, res.ObjectsDeleted)
		})
	}
}
