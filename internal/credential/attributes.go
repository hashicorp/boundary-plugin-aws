// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

	// RoleArn is the role arn associated with the aws credentials
	RoleArn string

	// RoleExternalId is the external id associated with the aws credentials
	RoleExternalId string

	// RoleSessionName is the session name associated with the aws credentials
	RoleSessionName string

	// RoleTags is the tags associated with the aws credentials
	RoleTags map[string]string
}

// GetCredentialsConfig parses values out of a protobuf struct secrets and returns a
// CredentialsConfig used for configuring an AWS session. An error is returned if
// any unrecognized fields are found in the protobuf struct input.
func GetCredentialsConfig(secrets *structpb.Struct, attrs *CredentialAttributes, required bool) (*awsutil.CredentialsConfig, error) {
	// initialize secrets if it is nil
	// secrets can be nil because static credentials are optional
	if secrets == nil {
		secrets = &structpb.Struct{
			Fields: make(map[string]*structpb.Value),
		}
	}

	unknownFields := values.StructFields(secrets)
	badFields := make(map[string]string)

	accessKey, err := values.GetStringValue(secrets, ConstAccessKeyId, required)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", ConstAccessKeyId)] = err.Error()
	}
	delete(unknownFields, ConstAccessKeyId)

	secretKey, err := values.GetStringValue(secrets, ConstSecretAccessKey, required)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", ConstSecretAccessKey)] = err.Error()
	}
	delete(unknownFields, ConstSecretAccessKey)

	// the creds_last_rotated_time field will be found in the input struct for
	// persisted secrets, this value is not needed for creating the CredentialsConfig
	delete(unknownFields, ConstCredsLastRotatedTime)
	for s := range unknownFields {
		badFields[fmt.Sprintf("secrets.%s", s)] = "unrecognized field"
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the secrets provided", badFields)
	}

	opts := []awsutil.Option{
		awsutil.WithEnvironmentCredentials(true),
	}
	if accessKey != "" && secretKey != "" {
		opts = append(opts,
			awsutil.WithAccessKey(accessKey),
			awsutil.WithSecretKey(secretKey),
		)
	}
	if attrs.Region != "" {
		opts = append(opts, awsutil.WithRegion(attrs.Region))
	}
	if attrs.RoleArn != "" {
		opts = append(opts, awsutil.WithRoleArn(attrs.RoleArn))
	}
	if attrs.RoleExternalId != "" {
		opts = append(opts, awsutil.WithRoleExternalId(attrs.RoleExternalId))
	}
	if attrs.RoleSessionName != "" {
		opts = append(opts, awsutil.WithRoleSessionName(attrs.RoleSessionName))
	}
	if len(attrs.RoleTags) != 0 {
		opts = append(opts, awsutil.WithRoleTags(attrs.RoleTags))
	}

	return awsutil.NewCredentialsConfig(opts...)
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

	roleArn, err := values.GetStringValue(in, ConstRoleArn, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstRoleArn)] = err.Error()
	}

	roleExternalId, err := values.GetStringValue(in, ConstRoleExternalId, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstRoleExternalId)] = err.Error()
	}

	roleSessionName, err := values.GetStringValue(in, ConstRoleSessionName, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstRoleSessionName)] = err.Error()
	}

	roleTags, err := values.GetMapString(in, ConstRoleTags, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstRoleTags)] = err.Error()
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the attributes provided", badFields)
	}

	return &CredentialAttributes{
		Region:                    region,
		DisableCredentialRotation: disableCredentialRotation,
		RoleArn:                   roleArn,
		RoleExternalId:            roleExternalId,
		RoleSessionName:           roleSessionName,
		RoleTags:                  roleTags,
	}, nil
}
