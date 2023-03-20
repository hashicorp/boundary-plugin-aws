package credential

const (
	// ConstAccessKey is the key for the region in the aws credentials.
	ConstRegion = "region"

	// ConstAccessKey is the key for the access key id in the aws credentials.
	ConstAccessKeyId = "access_key_id"

	// ConstSecretAccessKey is the key for the secret access key in the aws credentials.
	ConstSecretAccessKey = "secret_access_key"

	// ConstDisableCredentialRotation is the key for the disable credential rotation in the aws credentials.
	ConstDisableCredentialRotation = "disable_credential_rotation"

	// ConstCredsLastRotatedTime is the key for the last rotated time in the aws credentials.
	ConstCredsLastRotatedTime = "creds_last_rotated_time"
)
