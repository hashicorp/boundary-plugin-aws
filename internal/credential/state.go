package credential

import (
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/boundary-plugin-host-aws/internal/values"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"google.golang.org/protobuf/types/known/structpb"
)

// rotationWaitTimeout controls the time we wait for credential rotation to
// succeed. This is important to ensure that rotated credentials can be used
// right away.
const rotationWaitTimeout = time.Second * 30

type AwsCredentialPersistedStateOption func(s *AwsCredentialPersistedState) error

// AwsCredentialPersistedState is the persisted state for the AWS credential.
type AwsCredentialPersistedState struct {
	// AccessKeyId is the access key id for the AWS credential.
	AccessKeyId string
	// SecretAccessKey is the secret access key for the AWS credential.
	SecretAccessKey string
	// CredsLastRotatedTime is the last rotation of aws secrets for the AWS credential.
	CredsLastRotatedTime time.Time

	// testOpts are options that should be used for testing only
	testOpts []awsutil.Option

	// Region is not a part of persisted state but if set is passed to clients
	// created with this state
	region string
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

// WithAccessKeyId sets the value for AccesskeyId in the storage persisted state.
func WithAccessKeyId(x string) AwsCredentialPersistedStateOption {
	return func(s *AwsCredentialPersistedState) error {
		if s.AccessKeyId != "" {
			return errors.New("access key id already set")
		}

		s.AccessKeyId = x
		return nil
	}
}

// WithSecretAccessKey sets the value for SecretAccessKey in the storage persisted state.
func WithSecretAccessKey(x string) AwsCredentialPersistedStateOption {
	return func(s *AwsCredentialPersistedState) error {
		if s.SecretAccessKey != "" {
			return errors.New("secret access key already set")
		}

		s.SecretAccessKey = x
		return nil
	}
}

// WithCredsLastRotatedTime sets the value for CredsLastRotatedTime in the storage persisted state.
func WithCredsLastRotatedTime(t time.Time) AwsCredentialPersistedStateOption {
	return func(s *AwsCredentialPersistedState) error {
		if !s.CredsLastRotatedTime.IsZero() {
			return errors.New("last rotation time already set")
		}

		s.CredsLastRotatedTime = t
		return nil
	}
}

// WithRegion sets the value for region in the storage persisted state.
func WithRegion(with string) AwsCredentialPersistedStateOption {
	return func(s *AwsCredentialPersistedState) error {
		if s.region != "" {
			return errors.New("region already set")
		}

		s.region = with
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

// ValidateCreds takes the access key and secret key from the persisted state
// and runs sts.GetCallerIdentity for the current credentials, which is done
// to check that the credentials are valid.
func (s *AwsCredentialPersistedState) ValidateCreds() error {
	c, err := awsutil.NewCredentialsConfig(append([]awsutil.Option{
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
		awsutil.WithRegion(s.region),
	}, s.testOpts...)...)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if _, err := c.GetCallerIdentity(s.testOpts...); err != nil {
		return fmt.Errorf("error validating credentials: %w", err)
	}

	return nil
}

// RotateCreds takes the access key and secret key from the persisted state and creates a new access/secret key,
// then deletes the old access key. If deletion of the old access key is successful, the new access key/secret key are
// written into the credentials config and the persisted state. On any error, the old credentials are not overwritten.
// This ensures that any generated new secret key never leaves this function in case of an error, even though it will
// still result in an extraneous access key existing.
func (s *AwsCredentialPersistedState) RotateCreds() error {
	c, err := awsutil.NewCredentialsConfig(append([]awsutil.Option{
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
		awsutil.WithRegion(s.region),
	}, s.testOpts...)...)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if err := c.RotateKeys(append([]awsutil.Option{
		awsutil.WithValidityCheckTimeout(rotationWaitTimeout),
	}, s.testOpts...)...); err != nil {
		return fmt.Errorf("error rotating credentials: %w", err)
	}

	s.AccessKeyId = c.AccessKey
	s.SecretAccessKey = c.SecretKey
	s.CredsLastRotatedTime = time.Now()

	return nil
}

// ReplaceCreds replaces the access key in the state with a new key.
// If the existing key was rotated at any point in time, it is
// deleted first, otherwise it's left alone.
func (s *AwsCredentialPersistedState) ReplaceCreds(accessKeyId, secretAccessKey string) error {
	if accessKeyId == "" {
		return errors.New("access key id cannot be empty")
	}

	if secretAccessKey == "" {
		return errors.New("secret access key cannot be empty")
	}

	if accessKeyId == s.AccessKeyId {
		return errors.New("attempting to replace access key with the same one")
	}

	if !s.CredsLastRotatedTime.IsZero() {
		// Delete old/existing credentials. This is done with the same
		// credentials to ensure that it has the proper permissions to do
		// it.
		if err := s.DeleteCreds(); err != nil {
			return err
		}
	}

	// Set the new attributes and clear the rotated time.
	s.AccessKeyId = accessKeyId
	s.SecretAccessKey = secretAccessKey
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// DeleteCreds deletes the credentials in the state. The access key
// ID, secret access key, and rotation time fields are zeroed out in
// the state just to ensure that they cannot be re-used after.
func (s *AwsCredentialPersistedState) DeleteCreds() error {
	c, err := awsutil.NewCredentialsConfig(append([]awsutil.Option{
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
		awsutil.WithRegion(s.region),
	}, s.testOpts...)...)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if err := c.DeleteAccessKey(s.AccessKeyId, s.testOpts...); err != nil {
		// Determine if the deletion error was due to a missing
		// resource. If it was, just pass it.
		var awsErr awserr.Error
		if errors.As(err, &awsErr) {
			if awsErr.Code() == iam.ErrCodeNoSuchEntityException {
				s.AccessKeyId = ""
				s.SecretAccessKey = ""
				s.CredsLastRotatedTime = time.Time{}
				return nil
			}
		}

		// Otherwise treat it as an actual error.
		return err
	}

	s.AccessKeyId = ""
	s.SecretAccessKey = ""
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// GetSession returns a configured AWS session for the credentials in
// the state.
func (s *AwsCredentialPersistedState) GetSession() (*session.Session, error) {
	c, err := awsutil.NewCredentialsConfig(append([]awsutil.Option{
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
		awsutil.WithRegion(s.region),
	}, s.testOpts...)...)
	if err != nil {
		return nil, err
	}

	return c.GetSession()
}

// ToMap returns a map of the credentials stored in the persisted state,
// which includes the following keys: access_key_id, secret_access_key,
// & creds_last_rotated_time
func (s *AwsCredentialPersistedState) ToMap() map[string]any {
	return map[string]any{
		ConstAccessKeyId:          s.AccessKeyId,
		ConstSecretAccessKey:      s.SecretAccessKey,
		ConstCredsLastRotatedTime: s.CredsLastRotatedTime.Format(time.RFC3339Nano),
	}
}

// AwsCredentialPersistedStateFromProto parses values out of a protobuf struct input
// and returns a AwsCredentialPersistedState used for configuring an AWS session.
// An error is returned if any of the following fields are missing from the protobuf
// struct input or have invalid value types: access_key_id, secret_access_key, &
// creds_last_rotated_time.
func AwsCredentialPersistedStateFromProto(in *structpb.Struct, opts ...AwsCredentialPersistedStateOption) (*AwsCredentialPersistedState, error) {
	if in == nil {
		return nil, errors.New("missing persisted secrets")
	}

	accessKeyId, err := values.GetStringValue(in, ConstAccessKeyId, true)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	secretAccessKey, err := values.GetStringValue(in, ConstSecretAccessKey, true)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	credsLastRotatedTime, err := values.GetTimeValue(in, ConstCredsLastRotatedTime)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	s, err := NewAwsCredentialPersistedState(opts...)
	if err != nil {
		return nil, err
	}

	s.AccessKeyId = accessKeyId
	s.SecretAccessKey = secretAccessKey
	s.CredsLastRotatedTime = credsLastRotatedTime

	return s, nil
}
