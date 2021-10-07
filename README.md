# AWS Host Plugin for HashiCorp Boundary

This repo contains a Host-type plugin for [HashiCorp
Boundary](https://www.boundaryproject.io/) allowing dynamically sourcing hosts
from Amazon EC2.

Host sets created with this plugin define filters which select and group like
instances within AWS; these host sets can in turn be added to targets within
Boundary as host sources.

At creation or update of a host catalog of this type, configuration of the
plugin is performed via the attribute/secret values passed to the create or
update calls actions. These values are input as JSON objects; the expected types
are indicated below with the valid fields.

The plugin fetches hosts through the
[DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
call.

## Credential Rotation

Although credentials are stored encrypted within Boundary, by default this
plugin will attempt to rotate credentials when they are supplied through the
`secrets` object on a create or update call to the host catalog resource. The
given credentials will be used to create a new credential, and then the given
credential will be revoked. In this way, after rotation, only Boundary knows the
client secret in use by this plugin.

## Required IAM Privileges

The following IAM privileges, at the very least, are required to be attached to
a configured IAM user for this provider:

* `ec2:DescribeInstances`, configured to `*` (`DescribeInstances` cannot be
  scoped to a resource ARN). Example policy:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

* `iam:GetUser`, `iam:CreateAccessKey`, and `iam:DeleteAccessKey`, configured to
  the IAM user to allow credential rotation. Example policy:

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

## Attributes and Secrets

### Host Catalog

The following `attributes` are valid on an AWS host catalog resource:

- `disable_credential_rotation` (bool): If `true`, credential rotation will not
  be performed. See the [Credential Rotation](#credential-rotation) section
  above.
- `region` (string): The region to configure the host catalog for. All host sets
  in this catalog will be configured for this region.

The following `secrets` are valid on an AWS host catalog resource:

- `access_key_id` (string): The access key ID for the IAM user to use with this
  host catalog.
- `secret_access_key` (string): The secret access key for the IAM user to use
  with this host catalog.

### Host Set

The following attributes are valid on an AWS host Set resource:

- `filters` (object): An object of filters to filter off of. For a list of
  filter options, check out [describe-instances in the AWS CLI
  reference](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html).

#### Supplying Filters on the Boundary CLI

As `filters` is part of a host set's attributes and may contain dashes where are
not identifier-friendly, it's recommended you that supply attributes for AWS
host sets as a full JSON string. Example:

```
boundary host-sets create plugin -host-catalog-id hc_1234567890 --attributes '{"filters":{"tag-name":["foo"]}}'
```
