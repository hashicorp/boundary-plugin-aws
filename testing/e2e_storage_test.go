// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary-plugin-aws/plugin/service/storage"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// NOTE: this test does not vaildate against dynamic credentials because
// this credential type can only be tested on an EC2 instance.
func TestStoragePlugin(t *testing.T) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		t.Skip("set AWS_REGION to use this test")
	}
	if envAccessKeyId := os.Getenv("AWS_ACCESS_KEY_ID"); envAccessKeyId == "" {
		t.Skip("set AWS_ACCESS_KEY_ID to use this test")
	}
	if envSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); envSecretAccessKey == "" {
		t.Skip("set AWS_SECRET_ACCESS_KEY to use this test")
	}

	require := require.New(t)
	tf, err := NewTestTerraformer("testdata/storage")
	require.NoError(err)
	require.NotNil(tf)

	t.Log("===== deploying test Terraform workspace =====")
	err = tf.Deploy()
	require.NoError(err)

	t.Cleanup(func() {
		t.Log("===== destroying test Terraform workspace =====")
		if err := tf.Destroy(); err != nil {
			t.Logf("WARNING: could not run Terraform destroy: %s", err)
		}
	})

	bucketName, err := tf.GetOutputString("bucket_name")
	require.NoError(err)
	require.NotEmpty(bucketName)

	iamAccessKeyIds, err := tf.GetOutputSlice("iam_access_key_ids")
	require.NoError(err)
	require.Len(iamAccessKeyIds, expectedIamUserCount)

	iamSecretAccessKeys, err := tf.GetOutputSlice("iam_secret_access_keys")
	require.NoError(err)
	require.Len(iamSecretAccessKeys, expectedIamUserCount)

	iamAccessKeyMissingGetObject, err := tf.GetOutputString("iam_access_key_missing_get_obj")
	require.NoError(err)

	iamSecretAccessKeyMissingGetObject, err := tf.GetOutputString("iam_secret_access_key_missing_get_obj")
	require.NoError(err)

	iamAccessKeyMissingPutObject, err := tf.GetOutputString("iam_access_key_missing_put_obj")
	require.NoError(err)

	iamSecretAccessKeyMissingPutObject, err := tf.GetOutputString("iam_secret_access_key_missing_put_obj")
	require.NoError(err)

	iamAccessKeyMissingDeleteObject, err := tf.GetOutputString("iam_access_key_missing_delete_obj")
	require.NoError(err)

	iamSecretAccessKeyMissingDeleteObject, err := tf.GetOutputString("iam_secret_access_key_missing_delete_obj")
	require.NoError(err)

	s3PaginationTestObjectCount, err := tf.GetOutput("s3_pagination_test_object_count")
	require.NoError(err)
	objectCountFloat, ok := s3PaginationTestObjectCount.(float64)
	require.True(ok)
	objectCount := int(objectCountFloat)

	// Start the workflow now. Set up the storage bucket. Note that this
	// will cause the state to go out of drift above in the sense that
	// the access key ID/secret access key will no longer be valid. We
	// will assert this through the returned state.
	p := new(storage.StoragePlugin)
	ctx := context.Background()

	// ********************
	// * OnCreateStorageBucket
	// ********************
	//
	// Test non-rotation (using primary user).
	keyid, secret := testPluginOnCreateStorageBucket(ctx, t, p, bucketName, region, iamAccessKeyIds[0].(string), iamSecretAccessKeys[0].(string), false)
	// Test rotation next.
	keyid, secret = testPluginOnCreateStorageBucket(ctx, t, p, bucketName, region, keyid, secret, true)

	// ********************
	// * OnUpdateStorageBucket
	// ********************
	//
	// Test no-op non-rotation.
	keyid, secret = testPluginOnUpdateStorageBucket(ctx, t, p, bucketName, region, keyid, secret, "", "", false, false)
	// Switch to rotation.
	keyid, secret = testPluginOnUpdateStorageBucket(ctx, t, p, bucketName, region, keyid, secret, "", "", false, true)
	// Test no-op with rotation.
	keyid, secret = testPluginOnUpdateStorageBucket(ctx, t, p, bucketName, region, keyid, secret, "", "", true, true)
	// Switch credentials to next user. Don't rotate.
	keyid, secret = testPluginOnUpdateStorageBucket(ctx, t, p, bucketName, region, keyid, secret, iamAccessKeyIds[1].(string), iamSecretAccessKeys[1].(string), true, false)
	// Switch credentials to next user. Add rotation.
	keyid, secret = testPluginOnUpdateStorageBucket(ctx, t, p, bucketName, region, keyid, secret, iamAccessKeyIds[2].(string), iamSecretAccessKeys[2].(string), false, true)
	// Switch to next user, with rotation disabled.
	keyid, secret = testPluginOnUpdateStorageBucket(ctx, t, p, bucketName, region, keyid, secret, iamAccessKeyIds[3].(string), iamSecretAccessKeys[3].(string), true, false)
	// Last case - switch to another user and keep rotation off.
	keyid, secret = testPluginOnUpdateStorageBucket(ctx, t, p, bucketName, region, keyid, secret, iamAccessKeyIds[4].(string), iamSecretAccessKeys[4].(string), false, false)

	// ********************
	// * OnDeleteStorageBucket
	// ********************
	//
	// Test non-rotated.
	testPluginOnDeleteStorageBucket(ctx, t, p, bucketName, region, keyid, secret, false)
	// Test as if we had rotated these credentials (note that this
	// makes this test set unusable).
	testPluginOnDeleteStorageBucket(ctx, t, p, bucketName, region, keyid, secret, true)

	// ********************
	// * Object Methods: PutObject, GetObject, HeadObject, DeleteObjects
	// ********************
	//
	// Reassign the keyid and secret first.
	keyid, secret = iamAccessKeyIds[5].(string), iamSecretAccessKeys[5].(string)
	testPluginObjectMethods(ctx, t, p, bucketName, region, keyid, secret)

	// ********************
	// * ListObjects
	// ********************
	testListObjects(ctx, t, p, objectCount, bucketName, region, keyid, secret)

	// ********************
	// * Validate Permissions
	// ********************
	//
	var expectedSBCState *pb.StorageBucketCredentialState

	// Validate error is returned for missing get object permission
	expectedSBCState = &pb.StorageBucketCredentialState{
		State: &pb.Permissions{
			Write: &pb.Permission{
				State: pb.StateType_STATE_TYPE_OK,
			},
			Read: &pb.Permission{
				State: pb.StateType_STATE_TYPE_ERROR,
			},
			Delete: &pb.Permission{
				State: pb.StateType_STATE_TYPE_OK,
			},
		},
	}
	testPluginValidatePermissions(ctx, t, p, bucketName, region, iamAccessKeyMissingGetObject, iamSecretAccessKeyMissingGetObject, expectedSBCState)

	// Validate error is returned for missing put object permission
	expectedSBCState = &pb.StorageBucketCredentialState{
		State: &pb.Permissions{
			Write: &pb.Permission{
				State: pb.StateType_STATE_TYPE_ERROR,
			},
			Read: &pb.Permission{
				// Since we cannot write an object to S3,
				// we cannot test against the ability to read from S3.
				State: pb.StateType_STATE_TYPE_UNKNOWN,
			},
			Delete: &pb.Permission{
				// We can still try deleting an object that does
				// not exist in the S3 bucket to validate access.
				State: pb.StateType_STATE_TYPE_OK,
			},
		},
	}
	testPluginValidatePermissions(ctx, t, p, bucketName, region, iamAccessKeyMissingPutObject, iamSecretAccessKeyMissingPutObject, expectedSBCState)

	// Validate error is returned for missing delete object permission
	expectedSBCState = &pb.StorageBucketCredentialState{
		State: &pb.Permissions{
			Write: &pb.Permission{
				State: pb.StateType_STATE_TYPE_OK,
			},
			Read: &pb.Permission{
				State: pb.StateType_STATE_TYPE_OK,
			},
			Delete: &pb.Permission{
				State: pb.StateType_STATE_TYPE_ERROR,
			},
		},
	}
	testPluginValidatePermissions(ctx, t, p, bucketName, region, iamAccessKeyMissingDeleteObject, iamSecretAccessKeyMissingDeleteObject, expectedSBCState)
}

func testPluginOnCreateStorageBucket(ctx context.Context, t *testing.T, p *storage.StoragePlugin, bucketName, region, accessKeyId, secretAccessKey string, rotate bool) (string, string) {
	t.Helper()
	t.Logf("testing OnCreateStorageBucket (region=%s, rotate=%t)", region, rotate)
	require := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: !rotate,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
	})
	require.NoError(err)
	request := &pb.OnCreateStorageBucketRequest{
		Bucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Secrets:    reqSecrets,
			Attributes: reqAttrs,
		},
	}
	response, err := p.OnCreateStorageBucket(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	return validatePersistedSecrets(t, persisted.GetData(), accessKeyId, secretAccessKey, rotate)
}

func testPluginOnUpdateStorageBucket(
	ctx context.Context, t *testing.T, p *storage.StoragePlugin, bucketName,
	region, currentAccessKeyId, currentSecretAccessKey, newAccessKeyId, newSecretAccessKey string,
	rotated, rotate bool,
) (string, string) {
	t.Helper()
	t.Logf("testing OnUpdateStorageBucket (region=%s, newcreds=%t, rotated=%t, rotate=%t)", region, newAccessKeyId != "" && newSecretAccessKey != "", rotated, rotate)
	require := require.New(t)

	// Take a timestamp of the current time to get a point in time to
	// reference, ensuring that we are updating credential rotation
	// timestamps.
	currentCredsLastRotatedTime := time.Now()

	reqCurrentAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: !rotated,
	})
	require.NoError(err)
	reqNewAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: !rotate,
	})
	require.NoError(err)
	var reqSecrets *structpb.Struct
	if newAccessKeyId != "" && newSecretAccessKey != "" {
		reqSecrets, err = structpb.NewStruct(map[string]any{
			credential.ConstAccessKeyId:     newAccessKeyId,
			credential.ConstSecretAccessKey: newSecretAccessKey,
		})
		require.NoError(err)
	}
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     currentAccessKeyId,
		credential.ConstSecretAccessKey: currentSecretAccessKey,
		credential.ConstCredsLastRotatedTime: func() string {
			if rotated {
				return currentCredsLastRotatedTime.Format(time.RFC3339Nano)
			}

			return (time.Time{}).Format(time.RFC3339Nano)
		}(),
	})
	require.NoError(err)
	require.NotNil(reqPersistedSecrets)
	request := &pb.OnUpdateStorageBucketRequest{
		CurrentBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: reqCurrentAttrs,
		},
		NewBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: reqNewAttrs,
			Secrets:    reqSecrets,
		},
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: reqPersistedSecrets,
		},
	}
	response, err := p.OnUpdateStorageBucket(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	return validateUpdateSecrets(t, persisted.GetData(), currentCredsLastRotatedTime, currentAccessKeyId, currentSecretAccessKey, newAccessKeyId, newSecretAccessKey, rotated, rotate)
}

func testPluginOnDeleteStorageBucket(ctx context.Context, t *testing.T, p *storage.StoragePlugin, bucketName, region, accessKeyId, secretAccessKey string, rotated bool) {
	t.Helper()
	t.Logf("testing OnDeleteStorageBucket (region=%s, rotated=%t)", region, rotated)
	require := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: !rotated,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
	})
	require.NoError(err)
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
		credential.ConstCredsLastRotatedTime: func() string {
			if rotated {
				return time.Now().Format(time.RFC3339Nano)
			}

			return (time.Time{}).Format(time.RFC3339Nano)
		}(),
	})
	require.NoError(err)
	request := &pb.OnDeleteStorageBucketRequest{
		Bucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: reqAttrs,
			Secrets:    reqSecrets,
		},
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: reqPersistedSecrets,
		},
	}
	response, err := p.OnDeleteStorageBucket(ctx, request)
	require.NoError(err)
	require.NotNil(response)

	// We want to test the validity of the credentials post-deletion.
	if rotated {
		// The credentials should no longer be valid.
		requireCredentialsInvalid(t, accessKeyId, secretAccessKey)
	} else {
		// The credentials should still be valid. Sleep 10s first just to
		// be sure, since we're not rotating.
		time.Sleep(time.Second * 10)
		requireCredentialsValid(t, accessKeyId, secretAccessKey)
	}
}

func testPluginValidatePermissions(ctx context.Context, t *testing.T, p *storage.StoragePlugin, bucketName, region, accessKeyId, secretAccessKey string, expectedState *pb.StorageBucketCredentialState) {
	t.Helper()
	t.Logf("testing ValidatePermissions")
	require, assert := require.New(t), assert.New(t)

	require.NotNil(expectedState)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: true,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
	})
	require.NoError(err)

	req := &pb.ValidatePermissionsRequest{
		Bucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: reqAttrs,
			Secrets:    reqSecrets,
		},
	}

	_, err = p.ValidatePermissions(ctx, req)
	require.Error(err)

	var actualSBCState *pb.StorageBucketCredentialState
	if st, ok := status.FromError(err); ok {
		for _, detail := range st.Details() {
			if statusDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
				actualSBCState = statusDetail
				break
			}
		}
	}
	require.NotNil(actualSBCState)
	require.NotNil(actualSBCState.GetState())

	expectedReadState := expectedState.GetState().GetRead()
	if expectedReadState != nil {
		actualReadState := actualSBCState.GetState().GetRead()
		require.NotNil(actualReadState)
		assert.Equal(expectedReadState.GetState(), actualReadState.GetState())
		assert.NotEmpty(actualReadState.GetCheckedAt())
		if expectedReadState.GetState() == pb.StateType_STATE_TYPE_ERROR {
			assert.NotEmpty(actualReadState.GetErrorDetails())
		}
	}

	expectedWriteState := expectedState.GetState().GetWrite()
	if expectedWriteState != nil {
		actualWriteState := actualSBCState.GetState().GetWrite()
		require.NotNil(actualWriteState)
		assert.Equal(expectedWriteState.GetState(), actualWriteState.GetState())
		assert.NotEmpty(actualWriteState.GetCheckedAt())
		if expectedWriteState.GetState() == pb.StateType_STATE_TYPE_ERROR {
			assert.NotEmpty(actualWriteState.GetErrorDetails())
		}
	}

	expectedDeleteState := expectedState.GetState().GetDelete()
	if expectedDeleteState != nil {
		actualDeleteState := actualSBCState.GetState().GetDelete()
		require.NotNil(actualDeleteState)
		assert.Equal(expectedDeleteState.GetState(), actualDeleteState.GetState())
		assert.NotEmpty(actualDeleteState.GetCheckedAt())
		if expectedDeleteState.GetState() == pb.StateType_STATE_TYPE_ERROR {
			assert.NotEmpty(actualDeleteState.GetErrorDetails())
		}
	}
}

func testPluginObjectMethods(ctx context.Context, t *testing.T, p *storage.StoragePlugin, bucketName, region, accessKeyId, secretAccessKey string) {
	t.Helper()
	t.Logf("testing PutObject")
	require := require.New(t)

	testDataPath, err := filepath.Abs("./testdata/storage/test_object_data")
	require.NoError(err)
	require.FileExists(testDataPath)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: true,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
	})
	require.NoError(err)

	objectKey := uuid.New().String()
	putObjReq := &pb.PutObjectRequest{
		Bucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: reqAttrs,
			Secrets:    reqSecrets,
		},
		Key:  objectKey,
		Path: testDataPath,
	}
	putObjResp, err := p.PutObject(ctx, putObjReq)
	require.NoError(err)
	require.NotNil(putObjResp)
	require.NotEmpty(putObjResp.GetChecksumSha_256())

	t.Logf("testing HeadObject")
	headObjReq := &pb.HeadObjectRequest{
		Bucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: reqAttrs,
			Secrets:    reqSecrets,
		},
		Key: objectKey,
	}
	headObjResp, err := p.HeadObject(ctx, headObjReq)
	require.NoError(err)
	require.NotNil(headObjResp)
	require.NotEmpty(headObjResp.GetContentLength())
	require.NotEmpty(headObjResp.GetLastModified())

	// Need to create a GRPC server to test GetObject
	t.Logf("testing GetObject")
	lis, err := net.Listen("tcp", "[::1]:2030")
	require.NoError(err)
	grpcServer := grpc.NewServer()
	pb.RegisterStoragePluginServiceServer(grpcServer, &storage.StoragePlugin{})
	go func() {
		grpcServer.Serve(lis)
	}()

	conn, err := grpc.Dial("[::1]:2030", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(err)
	defer conn.Close()
	client := pb.NewStoragePluginServiceClient(conn)

	stream, err := client.GetObject(ctx, &pb.GetObjectRequest{
		Bucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: reqAttrs,
			Secrets:    reqSecrets,
		},
		Key: objectKey,
	})
	require.NoError(err)

	var actualData []byte
	expectedData, err := os.ReadFile(testDataPath)
	require.NoError(err)
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			require.NoError(stream.CloseSend())
			break
		} else if err != nil {
			require.NoError(err)
		}
		actualData = append(actualData, resp.GetFileChunk()...)
	}
	require.Equal(expectedData, actualData)
	require.NoError(conn.Close())
	grpcServer.Stop()
}

// testListObjects verifies top-level and recursive listing by matching the exact keys and types of returned objects.
func testListObjects(ctx context.Context, t *testing.T, p *storage.StoragePlugin, objectCount int, bucketName, region, accessKeyId, secretAccessKey string) {
	t.Helper()
	t.Logf("testing ListObjects (bucket=%s, region=%s, expectedObjects=%d, creds=%t)",
		bucketName,
		region,
		objectCount,
		accessKeyId != "" && secretAccessKey != "",
	)
	r := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: true,
	})
	r.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
	})
	r.NoError(err)

	bucket := &storagebuckets.StorageBucket{
		BucketName: bucketName,
		Attributes: reqAttrs,
		Secrets:    reqSecrets,
	}

	// Test Scenario 1: Non-Paginated Listing
	t.Run("NonPaginatedListing", func(t *testing.T) {

		// Subtest for the non-recursive (top-level) option
		t.Run("TopLevel", func(t *testing.T) {
			r := require.New(t)
			t.Logf("testing ListObjects for a small set with recursive=false")
			req := &pb.ListObjectsRequest{
				Bucket:    bucket,
				KeyPrefix: "list-objects/",
				Recursive: false,
			}
			resp, err := p.ListObjects(ctx, req)
			r.NoError(err)
			r.NotNil(resp)

			expectedObjects := []*pb.Object{
				{Key: "list-objects/file1.txt", IsDir: false},
				{Key: "list-objects/data.json", IsDir: false},
				{Key: "list-objects/nested-dir/", IsDir: true},
				{Key: "list-objects/empty-nested-dir/", IsDir: true},
			}
			r.ElementsMatch(resp.Objects, expectedObjects)
		})

		// Subtest for the recursive option
		t.Run("Recursive", func(t *testing.T) {
			r := require.New(t)
			t.Logf("testing ListObjects for a small set with recursive=true")
			req := &pb.ListObjectsRequest{
				Bucket:    bucket,
				KeyPrefix: "list-objects/",
				Recursive: true,
			}
			resp, err := p.ListObjects(ctx, req)
			r.NoError(err)
			r.NotNil(resp)

			expectedObjects := []*pb.Object{
				{Key: "list-objects/file1.txt", IsDir: false},
				{Key: "list-objects/data.json", IsDir: false},
				{Key: "list-objects/nested-dir/file2.txt", IsDir: false},
				{Key: "list-objects/nested-dir/", IsDir: true},
				{Key: "list-objects/empty-nested-dir/", IsDir: true},
			}

			r.ElementsMatch(resp.Objects, expectedObjects)
		})
	})

	// Test Scenario 2: Paginated Top-Level Listing
	t.Run("TopLevelListing", func(t *testing.T) {
		// Subtest for the root prefix
		t.Run("AtRoot", func(t *testing.T) {
			r := require.New(t)
			t.Logf("testing ListObjects with recursive=false at root prefix")
			req := &pb.ListObjectsRequest{
				Bucket:    bucket,
				KeyPrefix: "list-objects-paginated/",
				Recursive: false,
			}
			resp, err := p.ListObjects(ctx, req)
			r.NoError(err)
			r.NotNil(resp)

			var expectedObjects []*pb.Object
			for i := 0; i < objectCount; i++ {
				key := fmt.Sprintf("list-objects-paginated/root-file-%d.txt", i)
				expectedObjects = append(expectedObjects, &pb.Object{Key: key, IsDir: false})
			}
			for i := 0; i < objectCount; i++ {
				keyEmpty := fmt.Sprintf("list-objects-paginated/empty-dir-%d/", i)
				expectedObjects = append(expectedObjects, &pb.Object{Key: keyEmpty, IsDir: true})
				keyNested := fmt.Sprintf("list-objects-paginated/nested-dir-%d/", i)
				expectedObjects = append(expectedObjects, &pb.Object{Key: keyNested, IsDir: true})
			}

			r.ElementsMatch(resp.Objects, expectedObjects)
		})

		// Subtest for a nested prefix
		t.Run("AtNestedPrefix", func(t *testing.T) {
			r := require.New(t)
			t.Logf("testing ListObjects with recursive=false at a nested prefix")
			req := &pb.ListObjectsRequest{
				Bucket:    bucket,
				KeyPrefix: "list-objects-paginated/nested-dir-7/",
				Recursive: false,
			}
			resp, err := p.ListObjects(ctx, req)
			r.NoError(err)
			r.NotNil(resp)

			expectedObjects := []*pb.Object{
				{Key: "list-objects-paginated/nested-dir-7/data-file-7.json", IsDir: false},
			}

			r.ElementsMatch(resp.Objects, expectedObjects)
		})
	})

	// Test Scenario 3: Paginated Recursive Listing
	t.Run("RecursiveListing", func(t *testing.T) {
		r := require.New(t)
		t.Logf("testing ListObjects with recursive=true")
		req := &pb.ListObjectsRequest{
			Bucket:    bucket,
			KeyPrefix: "list-objects-paginated/",
			Recursive: true,
		}
		resp, err := p.ListObjects(ctx, req)
		r.NoError(err)
		r.NotNil(resp)

		var expectedObjects []*pb.Object
		for i := 0; i < objectCount; i++ {
			keyFile := fmt.Sprintf("list-objects-paginated/root-file-%d.txt", i)
			expectedObjects = append(expectedObjects, &pb.Object{Key: keyFile, IsDir: false})
			keyNestedFile := fmt.Sprintf("list-objects-paginated/nested-dir-%d/data-file-%d.json", i, i)
			expectedObjects = append(expectedObjects, &pb.Object{Key: keyNestedFile, IsDir: false})
		}
		for i := 0; i < objectCount; i++ {
			keyNestedDir := fmt.Sprintf("list-objects-paginated/nested-dir-%d/", i)
			expectedObjects = append(expectedObjects, &pb.Object{Key: keyNestedDir, IsDir: true})
			keyEmptyDir := fmt.Sprintf("list-objects-paginated/empty-dir-%d/", i)
			expectedObjects = append(expectedObjects, &pb.Object{Key: keyEmptyDir, IsDir: true})
			keyNestedEmptyDir := fmt.Sprintf("list-objects-paginated/empty-dir-%d/dir-%d/", i, i)
			expectedObjects = append(expectedObjects, &pb.Object{Key: keyNestedEmptyDir, IsDir: true})
		}

		r.ElementsMatch(resp.Objects, expectedObjects)
	})

	// Test Scenario 4: Edge cases
	t.Run("EdgeCases", func(t *testing.T) {
		// Subtest for a prefix that doesn't exist
		t.Run("NonExistentPrefix", func(t *testing.T) {
			r := require.New(t)
			t.Logf("testing ListObjects for a non-existent prefix")
			req := &pb.ListObjectsRequest{
				Bucket:    bucket,
				KeyPrefix: "this/prefix/does/not/exist/",
				Recursive: false,
			}
			resp, err := p.ListObjects(ctx, req)
			r.NoError(err)
			r.NotNil(resp)
			r.Empty(resp.Objects)
		})

		// Subtest for listing inside a known empty directory
		t.Run("InsideEmptyDirectory", func(t *testing.T) {
			r := require.New(t)
			t.Logf("testing ListObjects inside an empty directory")
			req := &pb.ListObjectsRequest{
				Bucket:    bucket,
				KeyPrefix: "list-objects-paginated/empty-dirs/dir-10/",
				Recursive: false,
			}
			resp, err := p.ListObjects(ctx, req)
			r.NoError(err)
			r.NotNil(resp)
			r.Empty(resp.Objects)
		})
	})
}
