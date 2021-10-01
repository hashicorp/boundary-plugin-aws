package plugin

import (
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"google.golang.org/protobuf/types/known/structpb"
)

type awsCatalogPersistedState struct {
	AccessKeyId          string
	SecretAccessKey      string
	CredsLastRotatedTime time.Time
}

func awsCatalogPersistedStateFromProto(in *pb.HostCatalogPersisted) (*awsCatalogPersistedState, error) {
	data := in.GetSecrets()
	if data == nil {
		return nil, errors.New("missing persisted secrets")
	}

	accessKeyId, err := getStringValue(data, constAccessKeyId, true)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	secretAccessKey, err := getStringValue(data, constSecretAccessKey, true)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	credsLastRotatedTime, err := getTimeValue(data, constCredsLastRotatedTime)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	return &awsCatalogPersistedState{
		AccessKeyId:          accessKeyId,
		SecretAccessKey:      secretAccessKey,
		CredsLastRotatedTime: credsLastRotatedTime,
	}, nil
}

func (s *awsCatalogPersistedState) ToProto() (*pb.HostCatalogPersisted, error) {
	data, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:          s.AccessKeyId,
		constSecretAccessKey:      s.SecretAccessKey,
		constCredsLastRotatedTime: s.CredsLastRotatedTime.Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, fmt.Errorf("error converting state to structpb.Struct: %w", err)
	}

	return &pb.HostCatalogPersisted{Secrets: data}, nil
}

func (s *awsCatalogPersistedState) ValidateCreds() error {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if _, err := c.GetCallerIdentity(); err != nil {
		return fmt.Errorf("error validating credentials: %w", err)
	}

	return nil
}

func (s *awsCatalogPersistedState) RotateCreds() error {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if err := c.RotateKeys(awsutil.WithValidityCheckTimeout(rotationWaitTimeout)); err != nil {
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
func (s *awsCatalogPersistedState) ReplaceCreds(accessKeyId, secretAccessKey string) error {
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
func (s *awsCatalogPersistedState) DeleteCreds() error {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if err := c.DeleteAccessKey(s.AccessKeyId); err != nil {
		// Determine if the deletion error was due to a missing
		// resource. If it was, just pass it.
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == iam.ErrCodeNoSuchEntityException {
			s.AccessKeyId = ""
			s.SecretAccessKey = ""
			s.CredsLastRotatedTime = time.Time{}
			return nil
		}

		// Otherwise treat it as an actual error.
		return fmt.Errorf("error deleting old access key: %w", err)
	}

	s.AccessKeyId = ""
	s.SecretAccessKey = ""
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// GetSession returns a configured AWS session for the credentials in
// the state.
func (s *awsCatalogPersistedState) GetSession() (*session.Session, error) {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return nil, err
	}

	return c.GetSession()
}

// EC2Client returns a configured EC2 client based on the session
// information stored in the state.
func (s *awsCatalogPersistedState) EC2Client(region string) (*ec2.EC2, error) {
	sess, err := s.GetSession()
	if err != nil {
		return nil, fmt.Errorf("error getting AWS session: %w", err)
	}

	return ec2.New(sess, aws.NewConfig().WithRegion(region)), nil
}
