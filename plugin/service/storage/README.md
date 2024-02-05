## Getting Started

To create a storage bucket (using default scope created by `boundary dev`):

```
boundary storage-buckets create \
 -scope-id p_1234567890 \
 -name "Example Plugin-Based Storage Bucket" \
 -description "Description for plugin-based storage bucket" \
 -plugin-name aws \
 -bucket-name="session_recording_storage" \
 -bucket-prefix="foo/bar/zoo" \
 -worker-filter ‘“aws-access” in “/tags/type”’ \
 -attr region=REGION \
 -attr endpoint_url=0.0.0.0 \
 -secret access_key_id='KEY' \
 -secret secret_access_key='SECRET'
```

### Required IAM Privileges

The following IAM privileges, at the very least, are required to be attached to
a configured IAM user for this provider:

Example policy:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:GetObjectAttributes"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::session_recording_storage/foo/bar/zoo/*"
    }
  ]
}
```

* `iam:GetUser`, `iam:CreateAccessKey`, and `iam:DeleteAccessKey`, configured to
  the IAM user to allow static credential rotation. Example policy:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "iam:DeleteAccessKey",
        "iam:GetUser",
        "iam:CreateAccessKey"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:iam::123456789012:user/JohnDoe"
    }
  ]
}
```

### Attributes

The following `attributes` are valid on an AWS storage bucket resource:

- `disable_credential_rotation` (bool): If `true`, credential rotation will not
  be performed.
- `region` (string): The region to configure the storage bucket for.
- `endpoint_url` (string): The endpoint to configure the storage.
- `role_arn` (string): The role arn configured for the assume role provider.
- `role_external_id` (string):  The external id configured for the assume role provider.
- `role_session_name` (string): The session name configured for the assume role provider.
- `role_tags` (object): The key-value pair tags configured for the assume role provider.

An example of how to utilize the [endpoint attribute](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)
See the [Credential Rotation](../../../README.md#credential-rotation) readme for more information.

### Secrets

The following `secrets` are optional on an AWS storage bucket resource:

- `access_key_id` (string): The access key ID for the IAM user to use with this
  storage bucket.
- `secret_access_key` (string): The secret access key for the IAM user to use
  with this storage bucket.

See the [Credential Rotation](../../../README.md#credential-rotation) readme for more information.
