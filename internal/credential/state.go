// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/hashicorp/boundary-plugin-aws/internal/values"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"google.golang.org/protobuf/types/known/structpb"
)

type CredentialType int

const (
	// StaticAWS denotes an Access Key Id that begins with "AKIA". These are
	// long-term access keys, provided by AWS, for an IAM user or an AWS account
	// root user.
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html#sec-access-keys-and-secret-access-keys
	StaticAWS CredentialType = iota

	// DynamicAWS denotes the presence of a RoleARN, or an Access Key Id that
	// begins with "ASIA". The latter are temporary credentials access keys that
	// are created using AWS STS operations.
	DynamicAWS

	// StaticOther denotes the presence of an Access Key Id that does not follow
	// the AKIA/ASIA convention outlined by AWS.
	StaticOther

	// Unknown is a catch-all for everything else.
	Unknown
)

// rotationWaitTimeout controls the time we wait for credential rotation to
// succeed. This is important to ensure that rotated credentials can be used
// right away.
const rotationWaitTimeout = time.Second * 30

type AwsCredentialPersistedStateOption func(s *AwsCredentialPersistedState) error

// AwsCredentialPersistedState is the persisted state for the AWS credential.
type AwsCredentialPersistedState struct {
	// CredentialsConfig is the credential configuration for the AWS credential.
	CredentialsConfig *awsutil.CredentialsConfig
	// CredsLastRotatedTime is the last rotation of aws secrets for the AWS credential.
	CredsLastRotatedTime time.Time

	// testOpts are options that should be used for testing only
	testOpts []awsutil.Option
}

// WithStateTestOpts enables unit testing different edge cases
// when using CredentialsConfig. This should never be used in
// production code. This should only be used in unit tests.
func WithStateTestOpts(opts []awsutil.Option) AwsCredentialPersistedStateOption {
	return func(s *AwsCredentialPersistedState) error {
		s.testOpts = opts
		return nil
	}
}

// WithCredentialsConfig sets the value for CredentialsConfig in the credential persisted state.
func WithCredentialsConfig(x *awsutil.CredentialsConfig) AwsCredentialPersistedStateOption {
	return func(s *AwsCredentialPersistedState) error {
		if s.CredentialsConfig != nil {
			return errors.New("credentials config already set")
		}

		s.CredentialsConfig = x
		return nil
	}
}

// WithCredsLastRotatedTime sets the value for CredsLastRotatedTime in the credential persisted state.
func WithCredsLastRotatedTime(t time.Time) AwsCredentialPersistedStateOption {
	return func(s *AwsCredentialPersistedState) error {
		if !s.CredsLastRotatedTime.IsZero() {
			return errors.New("last rotation time already set")
		}

		s.CredsLastRotatedTime = t
		return nil
	}
}

// NewAwsCredentialPersistedState returns a AwsCredentialPersistedState.
// Supported options include: WithAccessKeyId, WithSecretAccessKey
// WithCredsLastRotatedTime, & WithRegion.
func NewAwsCredentialPersistedState(opts ...AwsCredentialPersistedStateOption) (*AwsCredentialPersistedState, error) {
	s := new(AwsCredentialPersistedState)
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ValidateCreds takes the credentials configuration from the persisted state
// and runs sts.GetCallerIdentity for the current credentials, which is done
// to check that the credentials are valid.
func (s *AwsCredentialPersistedState) ValidateCreds(ctx context.Context) error {
	if s.CredentialsConfig == nil {
		return errors.New("missing credentials config")
	}
	if _, err := s.CredentialsConfig.GetCallerIdentity(ctx, s.testOpts...); err != nil {
		return fmt.Errorf("error validating credentials: %w", err)
	}
	return nil
}

// RotateCreds takes the access key and secret key from the persisted state and creates a new access/secret key,
// then deletes the old access key. If deletion of the old access key is successful, the new access key/secret key are
// written into the credentials config and the persisted state. On any error, the old credentials are not overwritten.
// This ensures that any generated new secret key never leaves this function in case of an error, even though it will
// still result in an extraneous access key existing.
func (s *AwsCredentialPersistedState) RotateCreds(ctx context.Context) error {
	if s.CredentialsConfig == nil {
		return errors.New("missing credentials config")
	}
	if GetCredentialType(s.CredentialsConfig) != StaticAWS {
		return errors.New("invalid credential type")
	}
	if err := s.CredentialsConfig.RotateKeys(ctx, append([]awsutil.Option{
		awsutil.WithValidityCheckTimeout(rotationWaitTimeout),
	}, s.testOpts...)...); err != nil {
		return fmt.Errorf("error rotating credentials: %w", err)
	}
	s.CredsLastRotatedTime = time.Now()
	return nil
}

// ReplaceCreds replaces the access key in the state with a new key.
// If the existing key was rotated at any point in time, it is
// deleted first, otherwise it's left alone.
func (s *AwsCredentialPersistedState) ReplaceCreds(ctx context.Context, credentialsConfig *awsutil.CredentialsConfig) error {
	if credentialsConfig == nil {
		return errors.New("missing new credentials config")
	}
	if s.CredentialsConfig == nil {
		return errors.New("missing credentials config")
	}

	// Delete old/existing credentials. This action is only possible for static credential types.
	// This is done with the same credentials to ensure that it has the proper permissions to do it.
	ct := GetCredentialType(s.CredentialsConfig)
	if !s.CredsLastRotatedTime.IsZero() && ct == StaticAWS {
		if err := s.DeleteCreds(ctx); err != nil {
			return err
		}
	}

	// Set the new attributes and clear the rotated time.
	s.CredentialsConfig = credentialsConfig
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// DeleteCreds deletes the credentials in the state. The access key
// ID, secret access key, and rotation time fields are zeroed out in
// the state just to ensure that they cannot be re-used after.
func (s *AwsCredentialPersistedState) DeleteCreds(ctx context.Context) error {
	if s.CredentialsConfig == nil {
		return errors.New("missing credentials config")
	}
	if GetCredentialType(s.CredentialsConfig) != StaticAWS {
		return errors.New("invalid credential type")
	}

	if err := s.CredentialsConfig.DeleteAccessKey(ctx, s.CredentialsConfig.AccessKey, s.testOpts...); err != nil {
		// Determine if the deletion error was due to a missing
		// resource. If it was, just pass it.
		var awsErr *iamTypes.NoSuchEntityException
		if errors.As(err, &awsErr) && awsErr.ErrorCode() == "NoSuchEntity" {
			s.CredentialsConfig = nil
			s.CredsLastRotatedTime = time.Time{}
			return nil
		}

		// Otherwise treat it as an actual error.
		return err
	}

	s.CredentialsConfig = nil
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// GenerateCredentialChain returns a AWS configuration for the credentials in the state.
func (s *AwsCredentialPersistedState) GenerateCredentialChain(ctx context.Context) (*aws.Config, error) {
	return s.CredentialsConfig.GenerateCredentialChain(ctx, s.testOpts...)
}

// ToMap returns a map of the credentials stored in the persisted state.
// ToMap will return an empty map for temporary credentials. ToMap will
// return a map for long-term credentials with following keys:
// access_key_id, secret_access_key & creds_last_rotated_time
func (s *AwsCredentialPersistedState) ToMap() map[string]any {
	ct := GetCredentialType(s.CredentialsConfig)
	// Dynamic AWS credentials are temporary credentials that expire within an hour.
	// ToMap() returns an empty map here so that Boundary does not store temporary
	// credentials into the database.
	//
	// Uknown credentials are not aws compatiable secrets that may have been provided
	// for a non-aws s3 compatiable service. These credentials will not be returned
	// because the plugin does not know how to manage non-aws credentials.
	if ct == DynamicAWS || ct == Unknown {
		return map[string]any{}
	}
	return map[string]any{
		ConstAccessKeyId:          s.CredentialsConfig.AccessKey,
		ConstSecretAccessKey:      s.CredentialsConfig.SecretKey,
		ConstCredsLastRotatedTime: s.CredsLastRotatedTime.Format(time.RFC3339Nano),
	}
}

// AwsCredentialPersistedStateFromProto parses values out of a protobuf struct input
// and returns a AwsCredentialPersistedState used for configuring an AWS session.
func AwsCredentialPersistedStateFromProto(secrets *structpb.Struct, attrs *CredentialAttributes, opts ...AwsCredentialPersistedStateOption) (*AwsCredentialPersistedState, error) {
	// initialize secrets if it is nil
	// secrets can be nil because static credentials are optional
	if secrets == nil {
		secrets = &structpb.Struct{
			Fields: map[string]*structpb.Value{},
		}
	}

	if attrs == nil {
		return nil, fmt.Errorf("missing credential attributes")
	}

	accessKeyId, err := values.GetStringValue(secrets, ConstAccessKeyId, false)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	secretAccessKey, err := values.GetStringValue(secrets, ConstSecretAccessKey, false)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	credsLastRotatedTime, err := values.GetTimeValue(secrets, ConstCredsLastRotatedTime)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	s, err := NewAwsCredentialPersistedState(opts...)
	if err != nil {
		return nil, err
	}

	awsOpts := append([]awsutil.Option{}, s.testOpts...)
	if accessKeyId != "" && secretAccessKey != "" {
		awsOpts = append(awsOpts,
			awsutil.WithAccessKey(accessKeyId),
			awsutil.WithSecretKey(secretAccessKey),
		)
	}
	if attrs.Region != "" {
		awsOpts = append(awsOpts, awsutil.WithRegion(attrs.Region))
	}
	if attrs.RoleArn != "" {
		awsOpts = append(awsOpts, awsutil.WithRoleArn(attrs.RoleArn))
	}
	if attrs.RoleExternalId != "" {
		awsOpts = append(awsOpts, awsutil.WithRoleExternalId(attrs.RoleExternalId))
	}
	if attrs.RoleSessionName != "" {
		awsOpts = append(awsOpts, awsutil.WithRoleSessionName(attrs.RoleSessionName))
	}
	if len(attrs.RoleTags) != 0 {
		awsOpts = append(awsOpts, awsutil.WithRoleTags(attrs.RoleTags))
	}
	credentialsConfig, err := awsutil.NewCredentialsConfig(awsOpts...)
	if err != nil {
		return nil, err
	}
	s.CredentialsConfig = credentialsConfig
	s.CredsLastRotatedTime = credsLastRotatedTime

	return s, nil
}

// GetCredentialType returns the credential type based on the given
// AccessKey/RoleARN. See CredentialType definition for more information.
func GetCredentialType(cc *awsutil.CredentialsConfig) CredentialType {
	if cc == nil {
		return Unknown
	}

	if len(cc.RoleARN) > 0 || strings.HasPrefix(cc.AccessKey, "ASIA") {
		return DynamicAWS
	}
	if strings.HasPrefix(cc.AccessKey, "AKIA") {
		return StaticAWS
	}
	if len(cc.AccessKey) > 0 {
		return StaticOther
	}

	return Unknown
}
