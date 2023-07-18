// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
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
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

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

	// Start the workflow now. Set up the host catalog. Note that this
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
	// * Object Methods: PutObject, GetObject, HeadObject
	// ********************
	//
	// Reassign the keyid and secret first.
	keyid, secret = iamAccessKeyIds[5].(string), iamSecretAccessKeys[5].(string)
	testPluginObjectMethods(ctx, t, p, bucketName, region, keyid, secret)

	// ********************
	// * Validate Permissions
	// ********************
	//
	// Validate error is returned for missing get object permission
	testPluginValidatePermissions(ctx, t, p, bucketName, region, iamAccessKeyMissingGetObject, iamSecretAccessKeyMissingGetObject)

	// Validate error is returned for missing put object permission
	testPluginValidatePermissions(ctx, t, p, bucketName, region, iamAccessKeyMissingPutObject, iamSecretAccessKeyMissingPutObject)
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

func testPluginValidatePermissions(ctx context.Context, t *testing.T, p *storage.StoragePlugin, bucketName, region, accessKeyId, secretAccessKey string) {
	t.Helper()
	t.Logf("testing ValidatePermissions")
	require := require.New(t)

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
	lis, err := net.Listen("tcp", "localhost:2030")
	require.NoError(err)
	grpcServer := grpc.NewServer()
	pb.RegisterStoragePluginServiceServer(grpcServer, &storage.StoragePlugin{})
	go func() {
		grpcServer.Serve(lis)
	}()

	conn, err := grpc.Dial("localhost:2030", grpc.WithTransportCredentials(insecure.NewCredentials()))
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
