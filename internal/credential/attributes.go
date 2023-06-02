package credential

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/hashicorp/boundary-plugin-aws/internal/errors"
	"github.com/hashicorp/boundary-plugin-aws/internal/values"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"google.golang.org/protobuf/types/known/structpb"
)

// CredentialAttributes contains attributes used for AWS credentials
type CredentialAttributes struct {
	// Region is the region associated with the aws credentials
	Region string

	// DisableCredentialRotation disables the rotation of aws secrets associated with the plugin
	DisableCredentialRotation bool
}

// GetCredentialsConfig parses values out of a protobuf struct input and returns a
// CredentialsConfig used for configuring an AWS session. An error is returned if
// any of the following fields are missing from the protobuf struct input or have
// invalid value types: access_key_id, secret_access_key. An error is returned if
// any unrecognized fields are found in the protobuf struct input.
func GetCredentialsConfig(in *structpb.Struct, region string) (*awsutil.CredentialsConfig, error) {
	unknownFields := values.StructFields(in)
	badFields := make(map[string]string)

	accessKey, err := values.GetStringValue(in, ConstAccessKeyId, true)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", ConstAccessKeyId)] = err.Error()
	}
	delete(unknownFields, ConstAccessKeyId)

	secretKey, err := values.GetStringValue(in, ConstSecretAccessKey, true)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", ConstSecretAccessKey)] = err.Error()
	}
	delete(unknownFields, ConstSecretAccessKey)

	if region == "" {
		badFields[fmt.Sprintf("attributes.%s", ConstRegion)] = err.Error()
	}

	// the creds_last_rotated_time field will be found in the input struct for
	// persisted secrets, this value is not needed for creating the CredentialsConfig
	delete(unknownFields, ConstCredsLastRotatedTime)
	for s := range unknownFields {
		badFields[fmt.Sprintf("secrets.%s", s)] = "unrecognized field"
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the secrets provided", badFields)
	}

	return awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(accessKey),
		awsutil.WithSecretKey(secretKey),
		awsutil.WithRegion(region),
	)
}

// GetCredentialAttributes parses values out of a protobuf struct input and returns a
// CredentialAttributes used for configuring an AWS session. An error is returned if
// any of the following fields are missing from the protobuf struct input or have
// invalid value types: region, disableCredentialRotation
func GetCredentialAttributes(in *structpb.Struct) (*CredentialAttributes, error) {
	badFields := make(map[string]string)

	region, err := values.GetStringValue(in, ConstRegion, true)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstRegion)] = err.Error()
	}

	if region != "" {
		if _, found := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region); !found {
			badFields[fmt.Sprintf("attributes.%s", ConstRegion)] = fmt.Sprintf("not a valid region: %s", region)
		}
	}

	disableCredentialRotation, err := values.GetBoolValue(in, ConstDisableCredentialRotation, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstDisableCredentialRotation)] = err.Error()
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the attributes provided", badFields)
	}

	return &CredentialAttributes{
		Region:                    region,
		DisableCredentialRotation: disableCredentialRotation,
	}, nil
}
