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
	awsutilv2 "github.com/hashicorp/go-secure-stdlib/awsutil"
	"google.golang.org/protobuf/types/known/structpb"
)

type CredentialType int

const (
	Unknown CredentialType = iota
	Static
	Dynamic
)

// rotationWaitTimeout controls the time we wait for credential rotation to
// succeed. This is important to ensure that rotated credentials can be used
// right away.
const rotationWaitTimeout = time.Second * 30

type AwsCredentialPersistedStateOption func(s *AwsCredentialPersistedState) error

// AwsCredentialPersistedState is the persisted state for the AWS credential.
type AwsCredentialPersistedState struct {
	// CredentialsConfig is the credential configuration for the AWS credential.
	CredentialsConfig *awsutilv2.CredentialsConfig
	// CredsLastRotatedTime is the last rotation of aws secrets for the AWS credential.
	CredsLastRotatedTime time.Time

	// testOpts are options that should be used for testing only
	testOpts []awsutilv2.Option
}

// WithStateTestOpts enables unit testing different edge cases
// when using CredentialsConfig. This should never be used in
// production code. This should only be used in unit tests.
func WithStateTestOpts(opts []awsutilv2.Option) AwsCredentialPersistedStateOption {
	return func(s *AwsCredentialPersistedState) error {
		s.testOpts = opts
		return nil
	}
}

// WithCredentialsConfig sets the value for CredentialsConfig in the credential persisted state.
func WithCredentialsConfig(x *awsutilv2.CredentialsConfig) AwsCredentialPersistedStateOption {
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
	if GetCredentialType(s.CredentialsConfig.AccessKey) != Static {
		return errors.New("invalid credential type")
	}
	if err := s.CredentialsConfig.RotateKeys(ctx, append([]awsutilv2.Option{
		awsutilv2.WithValidityCheckTimeout(rotationWaitTimeout),
	}, s.testOpts...)...); err != nil {
		return fmt.Errorf("error rotating credentials: %w", err)
	}
	s.CredsLastRotatedTime = time.Now()
	return nil
}

// ReplaceCreds replaces the access key in the state with a new key.
// If the existing key was rotated at any point in time, it is
// deleted first, otherwise it's left alone.
func (s *AwsCredentialPersistedState) ReplaceCreds(ctx context.Context, credentialsConfig *awsutilv2.CredentialsConfig) error {
	if credentialsConfig == nil {
		return errors.New("missing new credentials config")
	}
	if s.CredentialsConfig == nil {
		return errors.New("missing credentials config")
	}
	if GetCredentialType(s.CredentialsConfig.AccessKey) != Static {
		return errors.New("invalid credential type")
	}

	// Delete old/existing credentials. This action is only possible for static credential types.
	// This is done with the same credentials to ensure that it has the proper permissions to do it.
	if !s.CredsLastRotatedTime.IsZero() {
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
	if GetCredentialType(s.CredentialsConfig.AccessKey) != Static {
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
	if HasDynamicCredentials(s.CredentialsConfig.AccessKey) {
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

	awsOpts := append([]awsutilv2.Option{}, s.testOpts...)
	if accessKeyId != "" && secretAccessKey != "" {
		awsOpts = append(awsOpts,
			awsutilv2.WithAccessKey(accessKeyId),
			awsutilv2.WithSecretKey(secretAccessKey),
		)
	}
	if attrs.Region != "" {
		awsOpts = append(awsOpts, awsutilv2.WithRegion(attrs.Region))
	}
	if attrs.RoleArn != "" {
		awsOpts = append(awsOpts, awsutilv2.WithRoleArn(attrs.RoleArn))
	}
	if attrs.RoleExternalId != "" {
		awsOpts = append(awsOpts, awsutilv2.WithRoleExternalId(attrs.RoleExternalId))
	}
	if attrs.RoleSessionName != "" {
		awsOpts = append(awsOpts, awsutilv2.WithRoleSessionName(attrs.RoleSessionName))
	}
	if len(attrs.RoleTags) != 0 {
		awsOpts = append(awsOpts, awsutilv2.WithRoleTags(attrs.RoleTags))
	}
	credentialsConfig, err := awsutilv2.NewCredentialsConfig(awsOpts...)
	if err != nil {
		return nil, err
	}
	s.CredentialsConfig = credentialsConfig
	s.CredsLastRotatedTime = credsLastRotatedTime

	return s, nil
}

// GetCredentialType returns the credential type based on the given AWS AccessKey.
//
// https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html#sec-access-keys-and-secret-access-keys
// Access key IDs beginning with ASIA are temporary credentials access keys that you create using AWS STS operations.
//
// https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html#sec-access-keys-and-secret-access-keys
// Access key IDs beginning with AKIA are long-term access keys for an IAM user or an AWS account root user.
func GetCredentialType(accessKey string) CredentialType {
	if strings.HasPrefix(accessKey, "ASIA") {
		return Dynamic
	}
	if strings.HasPrefix(accessKey, "AKIA") {
		return Static
	}
	return Unknown
}

// HasDynamicCredentials returns true if the access key is a dynamic credential type.
func HasDynamicCredentials(accessKey string) bool {
	return strings.HasPrefix(accessKey, "ASIA")
}

// HasStaticCredentials returns true if the access key is a static credential type.
func HasStaticCredentials(accessKey string) bool {
	return strings.HasPrefix(accessKey, "AKIA")
}
