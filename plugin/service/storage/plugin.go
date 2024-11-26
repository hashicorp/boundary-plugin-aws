// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	cred "github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary-plugin-aws/internal/errors"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-multierror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Ensure that we are implementing StoragePluginServiceServer
var _ pb.StoragePluginServiceServer = (*StoragePlugin)(nil)

// clientCache caches previously initialized S3API clients created with a RoleARN attribute.
type clientCache struct {
	// cache is a map of cached s3 clients. The key of the map
	// is the public id of the storage bucket
	cache map[string]S3API
	sync.RWMutex
}

// StoragePlugin implements the StoragePluginServiceServer interface for the
// AWS storage service plugin.
type StoragePlugin struct {
	pb.UnimplementedStoragePluginServiceServer

	// testCredStateOpts are passed in to the stored state to control test behavior
	testCredStateOpts []cred.AwsCredentialPersistedStateOption

	// testStorageStateOpts are passed in to the stored state to control test behavior
	testStorageStateOpts []awsStoragePersistedStateOption

	clients *clientCache
}

// New creates a new StoragePlugin
func New() *StoragePlugin {
	c := &clientCache{
		cache: make(map[string]S3API),
	}
	return &StoragePlugin{
		clients: c,
	}
}

// getClient returns an S3API client for the given storage bucket id.
func (p *StoragePlugin) getClient(ctx context.Context,
	storageBucketId string,
	storageState *awsStoragePersistedState,
	opt ...s3Option) (S3API, error) {
	if storageBucketId == "" {
		// No storage bucket ID to key cache on, create new client and return
		client, err := storageState.s3Client(ctx, opt...)
		if err != nil {
			return nil, errors.BadRequestStatus("error creating S3 client: %s", err)
		}
		return client, nil
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing options in cache: %w", err)
	}

	if opts.withCacheRefresh {
		// Forced cache refresh
		p.clients.Lock()
		defer p.clients.Unlock()
		client, err := storageState.s3Client(ctx, opt...)
		if err != nil {
			return nil, errors.BadRequestStatus("error creating S3 client: %s", err)
		}
		p.clients.cache[storageBucketId] = client
		return client, nil
	}

	p.clients.RLock()
	client, ok := p.clients.cache[storageBucketId]
	p.clients.RUnlock()

	if !ok || client.Credentials().Expired() {
		// We got a cache miss or the credentials has expired, time to refresh
		p.clients.Lock()
		defer p.clients.Unlock()

		// Check cache again in case another caller updated it since we got the lock
		client, ok = p.clients.cache[storageBucketId]
		if ok && !client.Credentials().Expired() {
			// Got a cache hit with valid credentials, return cached client
			return client, nil
		}

		// Create new client and cache it
		var err error
		client, err = storageState.s3Client(ctx, opt...)
		if err != nil {
			return nil, errors.BadRequestStatus("error creating S3 client: %s", err)
		}
		p.clients.cache[storageBucketId] = client
	}
	return client, nil
}

type s3Caller func(client S3API) (any, error)

// call gets the s3client and passes it to the s3caller function, if a permission error is returned
// it forces a cache refresh and tries again.
func (p *StoragePlugin) call(
	ctx context.Context,
	fn s3Caller,
	storageBucketId string,
	storageState *awsStoragePersistedState,
	opts ...s3Option) (any, error) {

	s3Client, err := p.getClient(ctx, storageBucketId, storageState, opts...)
	if err != nil {
		return nil, errors.BadRequestStatus("error getting S3 client: %s", err)
	}
	firstAttempt := true
	for {
		resp, err := fn(s3Client)
		if err != nil {
			st, _ := errors.ParseAWSError("", err)
			if st.Code() == codes.PermissionDenied && firstAttempt {
				// We got a permission error, this is the first time so refresh cache and try again
				firstAttempt = false
				opts = append(opts, WithCacheRefresh(true))
				s3Client, err = p.getClient(ctx, storageBucketId, storageState, opts...)
				if err != nil {
					return nil, errors.BadRequestStatus("error refreshing S3 client: %s", err)
				}
				continue
			}
			return nil, err
		}
		return resp, nil
	}
}

// OnCreateStorageBucket is called when a storage bucket is created.
func (p *StoragePlugin) OnCreateStorageBucket(ctx context.Context, req *pb.OnCreateStorageBucketRequest) (*pb.OnCreateStorageBucketResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, errors.BadRequestStatus("bucket is required")
	}
	if bucket.BucketName == "" {
		return nil, errors.BadRequestStatus("bucketName is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, errors.BadRequestStatus("attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(bucket.GetSecrets(), storageAttributes.CredentialAttributes, storageAttributes.DualStack)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithCredentialsConfig(credConfig),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	// Try to rotate AWS static credentials
	if cred.GetCredentialType(credConfig) == cred.StaticAWS && !storageAttributes.DisableCredentialRotation {
		if err := credState.RotateCreds(ctx); err != nil {
			return nil, err
		}
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	// perform dry run to ensure we can interact with the bucket as expected.
	if st := dryRunValidation(ctx, storageState, storageAttributes, bucket); st != nil {
		return nil, st.Err()
	}

	persistedProto, err := storageState.toProto()
	if err != nil {
		return nil, errors.BadRequestStatus(err.Error())
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
	newBucket := req.GetNewBucket()
	if newBucket == nil {
		return nil, errors.BadRequestStatus("new bucket is required")
	}
	if newBucket.BucketName == "" {
		return nil, errors.BadRequestStatus("new bucketName is required")
	}
	currentBucket := req.GetCurrentBucket()
	if currentBucket == nil {
		return nil, errors.BadRequestStatus("current bucket is required")
	}

	oldAttrs := currentBucket.GetAttributes()
	if oldAttrs == nil {
		return nil, errors.BadRequestStatus("current bucket attributes is required")
	}
	oldStorageAttributes, err := getStorageAttributes(oldAttrs)
	if err != nil {
		return nil, err
	}
	newAttrs := newBucket.GetAttributes()
	if newAttrs == nil {
		return nil, errors.BadRequestStatus("new bucket attributes is required")
	}
	newStorageAttributes, err := getStorageAttributes(newAttrs)
	if err != nil {
		return nil, err
	}

	credState, err := cred.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetData(),
		oldStorageAttributes.CredentialAttributes,
		oldStorageAttributes.DualStack,
		p.testCredStateOpts...)
	if err != nil {
		return nil, errors.BadRequestStatus("error loading persisted state: %s", err)
	}

	// Verify the incoming credentials are valid and return any errors to the
	// user if they're not. Note this doesn't validate the credentials against
	// AWS - it only does logical validation on the fields.
	updatedCredentials, err := cred.GetCredentialsConfig(newBucket.GetSecrets(), newStorageAttributes.CredentialAttributes, newStorageAttributes.DualStack)
	if err != nil {
		return nil, err
	}

	// We will be updating credentials when one of two changes occur:
	// 1. the new bucket has secrets for static credentials, in which case we need to delete the old static credentials
	// 2. the new bucket has a different roleARN value for dynamic credentials
	if newBucket.GetSecrets() != nil || newStorageAttributes.RoleArn != oldStorageAttributes.RoleArn {
		// Ensure the incoming credentials are valid for interaction with the S3
		// Bucket before replacing them.
		newCredState, err := cred.NewAwsCredentialPersistedState(
			append([]cred.AwsCredentialPersistedStateOption{
				cred.WithCredentialsConfig(updatedCredentials),
			}, p.testCredStateOpts...)...,
		)
		if err != nil {
			return nil, errors.BadRequestStatus("error setting up new credential persisted state: %s", err)
		}
		newStorageState, err := newAwsStoragePersistedState(
			append([]awsStoragePersistedStateOption{
				withCredentials(newCredState),
			}, p.testStorageStateOpts...)...,
		)
		if err != nil {
			return nil, errors.BadRequestStatus("error loading persisted state: %s", err)
		}
		if st := dryRunValidation(ctx, newStorageState, newStorageAttributes, newBucket); st != nil {
			return nil, st.Err()
		}

		// Replace the existing credential state.
		// This checks the timestamp on the last rotation time as well
		// and deletes the credentials if we are managing them
		// (ie: if we've rotated them before).
		if err := credState.ReplaceCreds(ctx, updatedCredentials); err != nil {
			return nil, err
		}
	}

	if cred.GetCredentialType(credState.CredentialsConfig) == cred.StaticAWS {
		// This is a validate check to make sure that we aren't disabling
		// rotation for credentials currently being managed by rotation.
		// This is not allowed.
		if newStorageAttributes.DisableCredentialRotation && newBucket.GetSecrets() == nil {
			if !credState.CredsLastRotatedTime.IsZero() {
				return nil, errors.BadRequestStatus("cannot disable rotation for already-rotated credentials")
			}
		}

		// If we're enabling rotation now but didn't before, or have
		// freshly replaced credentials, we can rotate here.
		if !newStorageAttributes.DisableCredentialRotation && credState.CredsLastRotatedTime.IsZero() {
			if err := credState.RotateCreds(ctx); err != nil {
				return nil, err
			}
		}
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error loading persisted state: %s", err)
	}

	// perform dry run to ensure we can interact with the bucket as expected.
	if st := dryRunValidation(ctx, storageState, newStorageAttributes, newBucket); st != nil {
		return nil, st.Err()
	}

	persistedProto, err := storageState.toProto()
	if err != nil {
		return nil, errors.BadRequestStatus(err.Error())
	}

	return &pb.OnUpdateStorageBucketResponse{
		Persisted: persistedProto,
	}, nil
}

// OnDeleteStorageBucket is called when a storage bucket is deleted.
func (p *StoragePlugin) OnDeleteStorageBucket(ctx context.Context, req *pb.OnDeleteStorageBucketRequest) (*pb.OnDeleteStorageBucketResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, errors.BadRequestStatus("bucket is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, errors.BadRequestStatus("attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	// Get the persisted data.
	// NOTE: We return on error here, blocking the delete. This may or
	// may not be an overzealous approach to maintaining database/state
	// integrity. May need to be changed at later time if there are
	// scenarios where we might be deleting things and any secret state
	// may be corrupt/and or legitimately missing.
	credState, err := cred.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetData(),
		storageAttributes.CredentialAttributes,
		storageAttributes.DualStack,
		p.testCredStateOpts...)
	if err != nil {
		return nil, errors.BadRequestStatus("error loading persisted state: %s", err)
	}

	_, err = newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error loading persisted state: %s", err)
	}

	// try to delete static credentials
	if cred.GetCredentialType(credState.CredentialsConfig) == cred.StaticAWS {
		if !credState.CredsLastRotatedTime.IsZero() {
			// Delete old/existing credentials. This is done with the same
			// credentials to ensure that it has the proper permissions to do
			// it.
			if err := credState.DeleteCreds(ctx); err != nil {
				return nil, err
			}
		}
	}

	return &pb.OnDeleteStorageBucketResponse{}, nil
}

// HeadObject is called to get the metadata of an object.
func (p *StoragePlugin) HeadObject(ctx context.Context, req *pb.HeadObjectRequest) (*pb.HeadObjectResponse, error) {
	if req.GetKey() == "" {
		return nil, errors.BadRequestStatus("key is required")
	}

	bucket := req.GetBucket()
	if bucket == nil {
		return nil, errors.BadRequestStatus("bucket is required")
	}

	if bucket.BucketName == "" {
		return nil, errors.BadRequestStatus("bucketName is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, errors.BadRequestStatus("attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(bucket.GetSecrets(), storageAttributes.CredentialAttributes, storageAttributes.DualStack)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithCredentialsConfig(credConfig),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	opts := []s3Option{}
	if storageAttributes.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(storageAttributes.EndpointUrl))
	}
	if storageAttributes.DualStack {
		opts = append(opts, WithDualStack(storageAttributes.DualStack))
	}

	objectKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	headCall := func(s3Client S3API) (any, error) {
		return s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucket.GetBucketName()),
			Key:    aws.String(objectKey),
		})
	}
	headResp, err := p.call(ctx, headCall, bucket.GetId(), storageState, opts...)
	if err != nil {
		return nil, parseS3Error("head object", err, req).Err()
	}
	resp := headResp.(*s3.HeadObjectOutput)

	return &pb.HeadObjectResponse{
		ContentLength: aws.ToInt64(resp.ContentLength),
		LastModified:  timestamppb.New(*resp.LastModified),
	}, nil
}

// ValidatePermissions is called to validate the secrets associated with the storage bucket.
func (p *StoragePlugin) ValidatePermissions(ctx context.Context, req *pb.ValidatePermissionsRequest) (*pb.ValidatePermissionsResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, errors.BadRequestStatus("bucket is required")
	}

	if bucket.BucketName == "" {
		return nil, errors.BadRequestStatus("bucketName is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, errors.BadRequestStatus("attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(bucket.GetSecrets(), storageAttributes.CredentialAttributes, storageAttributes.DualStack)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithCredentialsConfig(credConfig),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	// perform dry run to ensure we can interact with the bucket as expected.
	if st := dryRunValidation(ctx, storageState, storageAttributes, bucket); st != nil {
		return nil, st.Err()
	}

	return &pb.ValidatePermissionsResponse{}, nil
}

// GetObject is called when retrieving objects from an s3 bucket.
// GetObject is a blocking call until the stream has been recieved in full.
func (p *StoragePlugin) GetObject(req *pb.GetObjectRequest, stream pb.StoragePluginService_GetObjectServer) error {
	if req.GetKey() == "" {
		return errors.BadRequestStatus("key is required")
	}

	bucket := req.GetBucket()
	if bucket == nil {
		return errors.BadRequestStatus("bucket is required")
	}

	if bucket.GetBucketName() == "" {
		return errors.BadRequestStatus("bucketName is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return errors.BadRequestStatus("attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return err
	}

	credConfig, err := cred.GetCredentialsConfig(bucket.GetSecrets(), storageAttributes.CredentialAttributes, storageAttributes.DualStack)
	if err != nil {
		return err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithCredentialsConfig(credConfig),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	opts := []s3Option{}
	if storageAttributes.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(storageAttributes.EndpointUrl))
	}
	if storageAttributes.DualStack {
		opts = append(opts, WithDualStack(storageAttributes.DualStack))
	}

	objectKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	getCall := func(s3Client S3API) (any, error) {
		return s3Client.GetObject(stream.Context(), &s3.GetObjectInput{
			Bucket: aws.String(bucket.GetBucketName()),
			Key:    aws.String(objectKey),
		})
	}
	getResp, err := p.call(stream.Context(), getCall, bucket.GetId(), storageState, opts...)
	if err != nil {
		return parseS3Error("get object", err, req).Err()
	}
	resp := getResp.(*s3.GetObjectOutput)

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
			return errors.UnknownStatus("error reading chunk from s3: %s", err)
		}
		if n > 0 {
			if err := stream.Send(&pb.GetObjectResponse{
				FileChunk: buffer[:n],
			}); err != nil {
				return errors.UnknownStatus("error sending chunk to client: %s", err)
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
		return nil, errors.BadRequestStatus("request is required")
	}
	if req.GetKey() == "" {
		return nil, errors.BadRequestStatus("key is required")
	}
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, errors.BadRequestStatus("bucket is required")
	}
	if bucket.GetBucketName() == "" {
		return nil, errors.BadRequestStatus("bucketName is required")
	}
	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, errors.BadRequestStatus("attributes is required")
	}
	if req.GetPath() == "" {
		return nil, errors.BadRequestStatus("path is required")
	}
	file, err := os.Open(req.GetPath())
	if err != nil {
		return nil, errors.BadRequestStatus("failed to open file")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.BadRequestStatus("failed to read file info")
	}
	if info.IsDir() {
		return nil, errors.BadRequestStatus("path is not a file")
	}
	if info.Size() == 0 {
		return nil, errors.BadRequestStatus("file is empty")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(bucket.GetSecrets(), storageAttributes.CredentialAttributes, storageAttributes.DualStack)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithCredentialsConfig(credConfig),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	opts := []s3Option{}
	if storageAttributes.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(storageAttributes.EndpointUrl))
	}
	if storageAttributes.DualStack {
		opts = append(opts, WithDualStack(storageAttributes.DualStack))
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, errors.UnknownStatus("failed to calcualte hash")
	}
	checksum := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, errors.UnknownStatus("failed to rewind file pointer")
	}
	objectKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())

	putCall := func(s3Client S3API) (any, error) {
		return s3Client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:            aws.String(bucket.GetBucketName()),
			Key:               aws.String(objectKey),
			Body:              file,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
			ChecksumSHA256:    aws.String(checksum),
		})
	}
	putResp, err := p.call(ctx, putCall, bucket.GetId(), storageState, opts...)
	if err != nil {
		return nil, parseS3Error("put object", err, req).Err()
	}
	resp := putResp.(*s3.PutObjectOutput)

	if resp.ChecksumSHA256 == nil {
		return nil, errors.UnknownStatus("missing checksum response from aws")
	}
	if checksum != *resp.ChecksumSHA256 {
		return nil, checksumMistmatchStatus()
	}
	decodedChecksum, err := base64.StdEncoding.DecodeString(*resp.ChecksumSHA256)
	if err != nil {
		return nil, errors.UnknownStatus("failed to decode checksum value from aws")
	}
	return &pb.PutObjectResponse{
		ChecksumSha_256: decodedChecksum,
	}, nil
}

// DeleteObjects is used to delete one or many objects from an s3 bucket.
func (p *StoragePlugin) DeleteObjects(ctx context.Context, req *pb.DeleteObjectsRequest) (*pb.DeleteObjectsResponse, error) {
	if req.GetKeyPrefix() == "" {
		return nil, errors.BadRequestStatus("key prefix is required")
	}

	bucket := req.GetBucket()
	if bucket == nil {
		return nil, errors.BadRequestStatus("bucket is required")
	}

	if bucket.GetBucketName() == "" {
		return nil, errors.BadRequestStatus("bucketName is required")
	}

	attrs := bucket.GetAttributes()
	if attrs == nil {
		return nil, errors.BadRequestStatus("attributes is required")
	}

	storageAttributes, err := getStorageAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := cred.GetCredentialsConfig(bucket.GetSecrets(), storageAttributes.CredentialAttributes, storageAttributes.DualStack)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := cred.NewAwsCredentialPersistedState(
		append([]cred.AwsCredentialPersistedStateOption{
			cred.WithCredentialsConfig(credConfig),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	storageState, err := newAwsStoragePersistedState(
		append([]awsStoragePersistedStateOption{
			withCredentials(credState),
		}, p.testStorageStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatus("error setting up persisted state: %s", err)
	}

	opts := []s3Option{}
	if storageAttributes.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(storageAttributes.EndpointUrl))
	}

	prefix := path.Join(bucket.GetBucketPrefix(), req.GetKeyPrefix())
	if strings.HasSuffix(req.GetKeyPrefix(), "/") {
		// path.Join ends by "cleaning" the path, including removing a trailing slash, if
		// it exists. given that a slash is used to denote a folder, it is required here.
		prefix += "/"
	}

	if !req.Recursive {
		deleteCall := func(s3Client S3API) (any, error) {
			return s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket.GetBucketName()),
				Key:    aws.String(prefix),
			})
		}
		_, err := p.call(ctx, deleteCall, bucket.GetId(), storageState, opts...)
		if err != nil {
			return nil, parseS3Error("delete object", err, req).Err()
		}

		if err != nil {
			return nil, parseS3Error("delete object", err, req).Err()
		}
		return &pb.DeleteObjectsResponse{
			ObjectsDeleted: uint32(1),
		}, nil
	}

	const maxkeys = 1000
	objects := []types.ObjectIdentifier{}
	client, err := p.getClient(ctx, bucket.GetId(), storageState, opts...)
	if err != nil {
		return nil, errors.BadRequestStatus("error getting S3 client: %s", err)
	}
	var conToken *string
	truncated, firstAttempt := true, true
	for truncated {
		res, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket.GetBucketName()),
			Prefix:            aws.String(prefix),
			MaxKeys:           aws.Int32(maxkeys),
			ContinuationToken: conToken,
		})
		if err != nil {
			st, _ := errors.ParseAWSError("", err)
			if st.Code() == codes.PermissionDenied && firstAttempt {
				// This is first attempt and we get a permission error, refresh cache and try again
				firstAttempt = false
				opts = append(opts, WithCacheRefresh(true))
				client, err = p.getClient(ctx, bucket.GetId(), storageState, opts...)
				if err != nil {
					return nil, errors.BadRequestStatus("error refreshing S3 client: %s", err)
				}
				continue
			}

			return nil, parseS3Error("list objects", err, req).Err()
		}
		truncated = aws.ToBool(res.IsTruncated)
		conToken = res.NextContinuationToken
		for _, o := range res.Contents {
			objects = append(objects, types.ObjectIdentifier{
				Key: o.Key,
			})
		}
	}

	deleted := 0

	for i := 0; i < len(objects); i += maxkeys {
		toDelete := objects[i:min(len(objects), i+maxkeys)] // min is required to avoid an out of bounds panic
		res, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket.GetBucketName()),
			Delete: &types.Delete{
				Objects: toDelete,
			},
		})
		if err != nil {
			return nil, parseS3Error("delete objects", err, req).Err()
		}
		deleted += len(res.Deleted)
	}

	return &pb.DeleteObjectsResponse{
		ObjectsDeleted: uint32(deleted),
	}, nil
}

// dryRunValidation validates that the IAM role policy attached to the given secrets of the
// storage bucket has the minimum required permissions needed for this plugin to function
// as expected. This function will create an object in the s3 bucket to validate it has
// PutObject permissions. This function will read the same file it had uploaded to validate
// it has GetObject permissions. This function will read the metadata of the same file it
// had uploaded to validate it has GetObjectAttributes permissions.
func dryRunValidation(ctx context.Context, state *awsStoragePersistedState, attrs *StorageAttributes, bucket *storagebuckets.StorageBucket) *status.Status {
	if state == nil {
		return status.New(codes.InvalidArgument, "persisted state is required")
	}
	if attrs == nil {
		return status.New(codes.InvalidArgument, "attributes is required")
	}
	if bucket == nil {
		return status.New(codes.InvalidArgument, "bucket is required")
	}

	opts := []s3Option{}
	if attrs.EndpointUrl != "" {
		opts = append(opts, WithEndpoint(attrs.EndpointUrl))
	}
	if attrs.DualStack {
		opts = append(opts, WithDualStack(attrs.DualStack))
	}

	client, err := state.s3Client(ctx, opts...)
	if err != nil {
		return status.New(codes.InvalidArgument, fmt.Sprintf("error getting S3 client: %s", err))
	}

	var errs *multierror.Error
	permissions := &pb.Permissions{}
	// we track the codes returned by ParseAWSError and pick the most severe one by using the max func

	objectKey := path.Join(bucket.GetBucketPrefix(), uuid.New().String())
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader([]byte("hashicorp boundary aws plugin access test")),
	}); err != nil {
		var st *status.Status
		st, permissions.Write = errors.ParseAWSError("put object", err)
		errs = multierror.Append(errs, st.Err())
	} else {
		permissions.Write = &pb.Permission{State: pb.StateType_STATE_TYPE_OK, CheckedAt: timestamppb.Now()}
	}

	if _, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
	}); err != nil {
		var st *status.Status
		st, permissions.Read = errors.ParseAWSError("get object", err)
		errs = multierror.Append(errs, st.Err())
	} else {
		permissions.Read = &pb.Permission{State: pb.StateType_STATE_TYPE_OK, CheckedAt: timestamppb.Now()}
	}

	if _, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
	}); err != nil {
		var st *status.Status
		st, permissions.Read = errors.ParseAWSError("head object", err)
		errs = multierror.Append(errs, st.Err())
	}

	if res, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket.GetBucketName()),
		Prefix: aws.String(objectKey),
	}); err != nil {
		var st *status.Status
		st, permissions.Read = errors.ParseAWSError("list object", err)
		errs = multierror.Append(errs, st.Err())
	} else if res == nil || len(res.Contents) != 1 || *res.Contents[0].Key != objectKey {
		permissions.Read = &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, CheckedAt: timestamppb.Now()}
		errs = multierror.Append(errs, status.New(codes.Aborted, fmt.Sprintf("list response did not contain the expected key: %+v", res)).Err())
	}

	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket.GetBucketName()),
		Key:    aws.String(objectKey),
	}); err != nil {
		var st *status.Status
		st, permissions.Delete = errors.ParseAWSError("delete object", err)
		errs = multierror.Append(errs, st.Err())
	} else {
		permissions.Delete = &pb.Permission{State: pb.StateType_STATE_TYPE_OK, CheckedAt: timestamppb.Now()}
	}

	if errs != nil {
		st := status.New(codes.FailedPrecondition, fmt.Sprintf("failed to validate provided aws credentials: %v", errs.Unwrap()))
		state := &pb.StorageBucketCredentialState{State: permissions}
		if st, err = st.WithDetails(state); err != nil {
			st = status.New(codes.Internal, err.Error())
		}
		return st
	}

	return nil
}
