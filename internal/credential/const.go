// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package credential

const (
	// ConstRegion is the key for the region in the aws credentials.
	ConstRegion = "region"

	// ConstAccessKeyId is the key for the access key id in the aws credentials.
	ConstAccessKeyId = "access_key_id"

	// ConstSecretAccessKey is the key for the secret access key in the aws credentials.
	ConstSecretAccessKey = "secret_access_key"

	// ConstDisableCredentialRotation is the key for the disable credential rotation in the aws credentials.
	ConstDisableCredentialRotation = "disable_credential_rotation"

	// ConstCredsLastRotatedTime is the key for the last rotated time in the aws credentials.
	ConstCredsLastRotatedTime = "creds_last_rotated_time"

	// ConstRoleArn is the key for assuming a IAM role.
	ConstRoleArn = "role_arn"

	// ConstRoleExternalId is the key for the external id used for assuming a IAM role.
	ConstRoleExternalId = "role_external_id"

	// ConstRoleSessionName is the key for the session name used for assuming a IAM role.
	ConstRoleSessionName = "role_session_name"

	// ConstRoleTags is the key for the tags used for assuming a IAM role.
	ConstRoleTags = "role_tags"

	// ConstTargetRegion is the key for the region of the target account in the aws credentials.
	ConstTargetRegion = "target_region"

	// ConstTargetRoleArn is the key for assuming a IAM role for the target account.
	ConstTargetRoleArn = "target_role_arn"

	// ConstTargetRoleExternalId is the key for the external id used for assuming a IAM role for the target account.
	ConstTargetRoleExternalId = "target_role_external_id"

	// ConstTargetRoleSessionName is the key for the session name used for assuming a IAM role of the target account.
	ConstTargetRoleSessionName = "target_role_session_name"

	// ConstTargetRoleTags is the key for the tags used for assuming a IAM role of the target account.
	ConstTargetRoleTags = "target_role_tags"
)
