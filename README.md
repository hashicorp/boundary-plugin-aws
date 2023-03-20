# AWS Plugin for HashiCorp Boundary

This repo contains the aws plugin for [HashiCorp
Boundary](https://www.boundaryproject.io/).

## Credential Rotation

Although credentials are stored encrypted within Boundary, by default this
plugin will attempt to rotate credentials when they are supplied through the
`secrets` object on a create or update call to the host catalog resource. The
given credentials will be used to create a new credential, and then the given
credential will be revoked. In this way, after rotation, only Boundary knows the
client secret in use by this plugin.

Credential rotation can be turned off by setting the 
`disable_credential_rotation` attribute to `true`.

## Dynamic Hosts

This plugin supports dynamically sourcing hosts from Amazon EC2.

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

[Getting Started](https://github.com/hashicorp/boundary-plugin-aws/plugin/service/host/README.md)
