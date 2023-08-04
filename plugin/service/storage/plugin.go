package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"path"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	cred "github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Ensure that we are implementing StoragePluginServiceServer
var _ pb.StoragePluginServiceServer = (*StoragePlugin)(nil)

// StoragePlugin implements the StoragePluginServiceServer interface for the
// AWS storage service plugin.
type StoragePlugin struct {
	pb.UnimplementedStoragePluginServiceServer

	// testCredStateOpts are passed in to the stored state to control test behavior
	testCredStateOpts []cred.AwsCredentialPersistedStateOption

	// testStorageStateOpts are passed in to the stored state to control test behavior
	testStorageStateOpts []awsStoragePersistedStateOption
}

// OnCreateStorageBucket is called when a storage bucket is created.
func (p *StoragePlugin) OnCreateStorageBucket(ctx context.Context, req *pb.OnCreateStorageBucketRequest) (*pb.OnCreateStorageBucketResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "bucket is required")
	}
	if bucket.BucketName == "" {
		return nil, status.Error(codes.InvalidArgument, "bucketName is required")
	}

	secrets := bucket.GetSecrets()
	if secrets == nil {
		return nil, status.Error(codes.InvalidArgument, "secrets is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(secrets, storageAttributes.Region)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithAccessKeyId(credConfig.AccessKey),
			cred.WithSecretAccessKey(credConfig.SecretKey),
			cred.WithRegion(credConfig.Region),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	// Try to rotate the credentials if we're not skipping them.
	if !storageAttributes.DisableCredentialRotation {
		if err := credState.RotateCreds(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error during credential rotation: %s", err)
		}
	} else {
		// Simply validate if we aren't rotating.
		if err := credState.ValidateCreds(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error during credential validation: %s", err)
		}
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	// perform dry run to ensure we can interact with the bucket as expected.
	if err := dryRunValidation(ctx, storageState, storageAttributes, bucket); err != nil {
		return nil, err
	}

	persistedProto, err := storageState.toProto()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &pb.OnCreateStorageBucketResponse{
		Persisted: persistedProto,
	}, nil
}

// OnUpdateStorageBucket is called when a storage bucket is updated.
func (p *StoragePlugin) OnUpdateStorageBucket(ctx context.Context, req *pb.OnUpdateStorageBucketRequest) (*pb.OnUpdateStorageBucketResponse, error) {
	// For storage buckets we only need to really validate what is
	// currently in the new copy of the storage bucket data, so skip
	// fetching the new copy to keep things a little less messy.
	bucket := req.GetNewBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "new bucket is required")
	}
	if bucket.BucketName == "" {
		return nil, status.Error(codes.InvalidArgument, "new bucketName is required")
	}

	var updateSecrets bool
	secrets := bucket.GetSecrets()
	if secrets != nil {
		// We will be updating secrets this run, but what exactly that
		// means will be determined later.
		updateSecrets = true
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "new bucket attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	// Get the persisted data.
	// NOTE: We might need to change this at a later time. I'm not too
	// sure *exactly* what scenarios we might encounter that would
	// ultimately mean that we would have to handle an empty or missing
	// state in update, but what we are ultimately assuming here
	// (implicitly through awsStoragePersistedStateFromProto) is that
	// the state will exist and be populated. Personally I think this
	// is fine and important, but this may change in the future.
	credState, err := cred.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetData(),
		append(p.testCredStateOpts, cred.WithRegion(storageAttributes.Region))...)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error loading persisted state: %s", err)
	}

	if storageAttributes.DisableCredentialRotation && !updateSecrets {
		// This is a validate check to make sure that we aren't disabling
		// rotation for credentials currently being managed by rotation.
		// This is not allowed.
		if !credState.CredsLastRotatedTime.IsZero() {
			return nil, status.Error(codes.FailedPrecondition, "cannot disable rotation for already-rotated credentials")
		}
	}

	if updateSecrets {
		storageSecrets, err := cred.GetCredentialsConfig(secrets, storageAttributes.Region)
		if err != nil {
			return nil, err
		}

		// Replace the credentials. This checks the timestamp on the last
		// rotation time as well and deletes the credentials if we are
		// managing them (ie: if we've rotated them before).
		if err := credState.ReplaceCreds(storageSecrets.AccessKey, storageSecrets.SecretKey); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error attempting to replace credentials: %s", err)
		}
	}

	if !storageAttributes.DisableCredentialRotation && credState.CredsLastRotatedTime.IsZero() {
		// If we're enabling rotation now but didn't before, or have
		// freshly replaced credentials, we can rotate here.
		if err := credState.RotateCreds(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error during credential rotation: %s", err)
		}
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error loading persisted state: %s", err)
	}

	// perform dry run to ensure we can interact with the bucket as expected.
	if err := dryRunValidation(ctx, storageState, storageAttributes, bucket); err != nil {
		return nil, err
	}

	persistedProto, err := storageState.toProto()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &pb.OnUpdateStorageBucketResponse{
		Persisted: persistedProto,
	}, nil
}

// OnDeleteStorageBucket is called when a storage bucket is deleted.
func (p *StoragePlugin) OnDeleteStorageBucket(ctx context.Context, req *pb.OnDeleteStorageBucketRequest) (*pb.OnDeleteStorageBucketResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "bucket is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	// NOTE: This check was added to support the Boundary 0.13.2 release as a hotfix for
	// empty secrets. Future releases of the plugin will correctly handle empty secrets.
	if req.GetPersisted().GetData() == nil {
		return &pb.OnDeleteStorageBucketResponse{}, nil
	}

	// Get the persisted data.
	// NOTE: We return on error here, blocking the delete. This may or
	// may not be an overzealous approach to maintaining database/state
	// integrity. May need to be changed at later time if there are
	// scenarios where we might be deleting things and any secret state
	// may be corrupt/and or legitimately missing.
	credState, err := cred.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetData(),
		append(p.testCredStateOpts, cred.WithRegion(storageAttributes.Region))...)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error loading persisted state: %s", err)
	}

	_, err = newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error loading persisted state: %s", err)
	}

	if !credState.CredsLastRotatedTime.IsZero() {
		// Delete old/existing credentials. This is done with the same
		// credentials to ensure that it has the proper permissions to do
		// it.
		if err := credState.DeleteCreds(); err != nil {
			return nil, status.Errorf(codes.Aborted, "error removing rotated credentials during storage bucket deletion: %s", err)
		}
	}

	return &pb.OnDeleteStorageBucketResponse{}, nil
}

// HeadObject is called to get the metadata of an object.
func (p *StoragePlugin) HeadObject(ctx context.Context, req *pb.HeadObjectRequest) (*pb.HeadObjectResponse, error) {
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}

	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "bucket is required")
	}

	if bucket.BucketName == "" {
		return nil, status.Error(codes.InvalidArgument, "bucketName is required")
	}

	secrets := bucket.GetSecrets()
	if secrets == nil {
		return nil, status.Error(codes.InvalidArgument, "secrets is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(secrets, storageAttributes.Region)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithAccessKeyId(credConfig.AccessKey),
			cred.WithSecretAccessKey(credConfig.SecretKey),
			cred.WithRegion(credConfig.Region),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	opts := []s3Option{}
	if storageAttributes.Region != "" {
		opts = append(opts, WithRegion(storageAttributes.Region))
	}
	if storageAttributes.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(storageAttributes.EndpointUrl))
	}
	s3Client, err := storageState.S3Client(ctx, opts...)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error getting S3 client: %s", err)
	}

	objectKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	resp, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return nil, parseAWSErrCode("error getting head object from s3", err)
	}
	return &pb.HeadObjectResponse{
		ContentLength: resp.ContentLength,
		LastModified:  timestamppb.New(*resp.LastModified),
	}, nil
}

// ValidatePermissions is called to validate the secrets associated with the storage bucket.
func (p *StoragePlugin) ValidatePermissions(ctx context.Context, req *pb.ValidatePermissionsRequest) (*pb.ValidatePermissionsResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "bucket is required")
	}

	if bucket.BucketName == "" {
		return nil, status.Error(codes.InvalidArgument, "bucketName is required")
	}

	secrets := bucket.GetSecrets()
	if secrets == nil {
		return nil, status.Error(codes.InvalidArgument, "secrets is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(secrets, storageAttributes.Region)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithAccessKeyId(credConfig.AccessKey),
			cred.WithSecretAccessKey(credConfig.SecretKey),
			cred.WithRegion(credConfig.Region),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	// perform dry run to ensure we can interact with the bucket as expected.
	if err := dryRunValidation(ctx, storageState, storageAttributes, bucket); err != nil {
		return nil, err
	}

	return &pb.ValidatePermissionsResponse{}, nil
}

// GetObject is called when retrieving objects from an s3 bucket.
// GetObject is a blocking call until the stream has been recieved in full.
func (p *StoragePlugin) GetObject(req *pb.GetObjectRequest, stream pb.StoragePluginService_GetObjectServer) error {
	if req.GetKey() == "" {
		return status.Error(codes.InvalidArgument, "key is required")
	}

	bucket := req.GetBucket()
	if bucket == nil {
		return status.Error(codes.InvalidArgument, "bucket is required")
	}

	if bucket.GetBucketName() == "" {
		return status.Error(codes.InvalidArgument, "bucketName is required")
	}

	secrets := bucket.GetSecrets()
	if secrets == nil {
		return status.Error(codes.InvalidArgument, "secrets is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return status.Error(codes.InvalidArgument, "attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return err
	}

	credConfig, err := cred.GetCredentialsConfig(secrets, storageAttributes.Region)
	if err != nil {
		return err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithAccessKeyId(credConfig.AccessKey),
			cred.WithSecretAccessKey(credConfig.SecretKey),
			cred.WithRegion(credConfig.Region),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	opts := []s3Option{}
	if storageAttributes.Region != "" {
		opts = append(opts, WithRegion(storageAttributes.Region))
	}
	if storageAttributes.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(storageAttributes.EndpointUrl))
	}
	s3Client, err := storageState.S3Client(stream.Context(), opts...)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "error getting S3 client: %s", err)
	}

	objectKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	resp, err := s3Client.GetObject(stream.Context(), &s3.GetObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return parseAWSErrCode("error getting object from s3", err)
	}

	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	chunkSize := req.GetChunkSize()
	if chunkSize == 0 {
		chunkSize = defaultStreamChunkSize
	}
	for {
		buffer := make([]byte, chunkSize)
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return status.Errorf(codes.Internal, "error reading chunk from s3: %s", err)
		}
		if n > 0 {
			if err := stream.Send(&pb.GetObjectResponse{
				FileChunk: buffer[:n],
			}); err != nil {
				return status.Errorf(codes.Internal, "error sending chunk to client: %s", err)
			}
		}
		if err == io.EOF {
			break
		}
	}

	return nil
}

// PutObject is called when putting objects into an s3 bucket.
func (p *StoragePlugin) PutObject(ctx context.Context, req *pb.PutObjectRequest) (*pb.PutObjectResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "request is required")
	}
	if req.GetKey() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "key is required")
	}
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "bucket is required")
	}
	if bucket.GetBucketName() == "" {
		return nil, status.Error(codes.InvalidArgument, "bucketName is required")
	}
	secrets := bucket.GetSecrets()
	if secrets == nil {
		return nil, status.Error(codes.InvalidArgument, "secrets is required")
	}
	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "attributes is required")
	}
	if req.GetPath() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "path is required")
	}
	file, err := os.Open(req.GetPath())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to open file")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read file info")
	}
	if info.IsDir() {
		return nil, status.Errorf(codes.InvalidArgument, "path is not a file")
	}
	if info.Size() == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "file is empty")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(secrets, storageAttributes.Region)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithAccessKeyId(credConfig.AccessKey),
			cred.WithSecretAccessKey(credConfig.SecretKey),
			cred.WithRegion(credConfig.Region),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error setting up persisted state: %s", err)
	}

	opts := []s3Option{}
	if storageAttributes.Region != "" {
		opts = append(opts, WithRegion(storageAttributes.Region))
	}
	if storageAttributes.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(storageAttributes.EndpointUrl))
	}
	s3Client, err := storageState.S3Client(ctx, opts...)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error getting S3 client: %s", err)
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to calcualte hash")
	}
	checksum := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to rewind file pointer")
	}

	objectKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	resp, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:            aws.String(bucket.GetBucketName()),
		Key:               aws.String(objectKey),
		Body:              file,
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		ChecksumSHA256:    aws.String(checksum),
	})
	if err != nil {
		return nil, parseAWSErrCode("error putting object into s3", err)
	}
	if resp.ChecksumSHA256 == nil {
		return nil, status.Errorf(codes.Internal, "missing checksum response from aws")
	}
	if checksum != *resp.ChecksumSHA256 {
		return nil, status.Errorf(codes.Internal, "mismatched checksum")
	}
	decodedChecksum, err := base64.StdEncoding.DecodeString(*resp.ChecksumSHA256)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode checksum value from aws")
	}
	return &pb.PutObjectResponse{
		ChecksumSha_256: decodedChecksum,
	}, nil
}

// dryRunValidation validates that the IAM role policy attached to the given secrets of the
// storage bucket has the minimum required permissions needed for this plugin to function
// as expected. This function will create an object in the s3 bucket to validate it has
// PutObject permissions. This function will read the same file it had uploaded to validate
// it has GetObject permissions. This function will read the metadata of the same file it
// had uploaded to validate it has GetObjectAttributes permissions.
func dryRunValidation(ctx context.Context, state *awsStoragePersistedState, attrs *StorageAttributes, bucket *storagebuckets.StorageBucket) error {
	if state == nil {
		return status.Error(codes.InvalidArgument, "persisted state is required")
	}
	if attrs == nil {
		return status.Error(codes.InvalidArgument, "attributes is required")
	}
	if bucket == nil {
		return status.Error(codes.InvalidArgument, "bucket is required")
	}

	opts := []s3Option{}
	if attrs.Region != "" {
		opts = append(opts, WithRegion(attrs.Region))
	}
	if attrs.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(attrs.EndpointUrl))
	}

	client, err := state.S3Client(ctx, opts...)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "error getting S3 client: %s", err)
	}

	objectKey := path.Join(bucket.GetBucketPrefix(), uuid.New().String())
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader([]byte("hashicorp boundary aws plugin access test")),
	}); err != nil {
		return parseAWSErrCode("error failed to put object", err)
	}

	if _, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
	}); err != nil {
		return parseAWSErrCode("error failed to get object", err)
	}

	if _, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
	}); err != nil {
		return parseAWSErrCode("error failed to get head object", err)
	}

	// attempt to delete the test object created for the dry run validation,
	// this step is allowed to fail because DeleteObject is not a required
	// operation for the plugin.
	client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
	})

	return nil
}

// parseAWSErrCode detects if an aws error is a throttle error.
// If the error is a throttle error, then an Unavailable status code
// is returned. Otherwise the default status code is an Internal error.
func parseAWSErrCode(msg string, err error) error {
	errCode := codes.Internal
	retryErr := retry.ThrottleErrorCode{
		Codes: retry.DefaultThrottleErrorCodes,
	}
	if retryErr.IsErrorThrottle(err).Bool() {
		errCode = codes.Unavailable
	}
	return status.Errorf(errCode, "%s: %s", msg, err)
}
