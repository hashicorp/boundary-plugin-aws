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

As above, but matching on tag key named "development" with value "prod" or "dev"
and launch date:

```
boundary host-sets create plugin \
 -host-catalog-id HOST_CATALOG_ID \
 -name "Example Plugin-Based Host Set" \
 -description "Description for plugin-based host set" \
 -attr filters=tag:development=prod,dev \
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
  be performed. See the [Credential Rotation](../../../README.md#credential-rotation) readme for more information.
- `region` (string): The region to configure the host catalog for. All host sets
  in this catalog will be configured for this region.

The following `secrets` are required on an AWS host catalog resource:

- `access_key_id` (string): The access key ID for the IAM user to use with this
  host catalog.
- `secret_access_key` (string): The secret access key for the IAM user to use
  with this host catalog.

See the [Credential Rotation](../../../README.md#credential-rotation) readme for more information.

### Host Set

The following attributes are valid on an AWS host Set resource:

- `filters` (array of strings): An array of string filters in the format
  `key=val1,val2`. The key corresponds to a filter option, and the value(s) are
  a comma-separated list. For a list of filter options, check out
  [describe-instances in the AWS CLI
  reference](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html).