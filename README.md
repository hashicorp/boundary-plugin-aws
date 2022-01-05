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

## Getting Started

Refer to [Attributes and Secrets](#attributes-and-secrets) for more detail on
configuration options for host catalogs and sets.

To create a host catalog (using default scope created by `boundary dev`):

```
boundary host-catalogs create plugin \
 -scope-id p_1234567890 \
 -name "Example Plugin-Based Host Catalog" \
 -description "Description for plugin-based host catalog" \
 -plugin-name aws \
 -attr region=REGION \
 -secret access_key_id='KEY' \
 -secret secret_access_key='SECRET'
```

To create a host set, filtering the host set based on tag keys `foo` or `bar`
(either tag can be present), ensuring that any targets set to this host set only
connect to external addresses in the `54.0.0.0/8` class A subnet:

```
boundary host-sets create plugin \
 -host-catalog-id HOST_CATALOG_ID \
 -name "Example Plugin-Based Host Set" \
 -description "Description for plugin-based host set" \
 -attr filters=tag-key=foo,bar \
 -preferred-endpoint "cidr:54.0.0.0/8"
```

As above, but instances must have both tags (both `foo` and `bar` *must* be
present):

```
boundary host-sets create plugin \
 -host-catalog-id HOST_CATALOG_ID \
 -name "Example Plugin-Based Host Set" \
 -description "Description for plugin-based host set" \
 -attr filters=tag-key=foo \
 -attr filters=tag-key=bar \
 -preferred-endpoint "cidr:54.0.0.0/8"
```

As above, but matching on tag key and launch date:

```
boundary host-sets create plugin \
 -host-catalog-id HOST_CATALOG_ID \
 -name "Example Plugin-Based Host Set" \
 -description "Description for plugin-based host set" \
 -attr filters=tag-key=foo \
 -attr filters=launch-time=2022-01-04T* \
 -preferred-endpoint "cidr:54.0.0.0/8"
```

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

- `filters` (array of strings): An array of string filters in the format
  `key=val1,val2`. The key corresponds to a filter option, and the value(s) are
  a comma-separated list. For a list of filter options, check out
  [describe-instances in the AWS CLI
  reference](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html).
