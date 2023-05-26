# AWS Plugin for HashiCorp Boundary

This repo contains the aws plugin for [HashiCorp
Boundary](https://www.boundaryproject.io/).

## Credential Rotation

Although credentials are stored encrypted within Boundary, by default this
plugin will attempt to rotate credentials when they are supplied through the
`secrets` object. The given credentials will be used to create a new credential,
and then the given credential will be revoked. In this way, after rotation,
only Boundary knows the client secret in use by this plugin.

Credential rotation can be turned off by setting the 
`disable_credential_rotation` attribute to `true`.

## Dynamic Hosts

This plugin supports dynamically sourcing hosts from Amazon EC2.

Host sets created with this plugin define filters which select and group like
instances within AWS; these host sets can in turn be added to targets within
Boundary as host sources.

At creation, update or deletion of a host catalog of this type, configuration of the
plugin is performed via the attribute/secret values passed to the create, update, or
delete calls actions. The values passed in to the plugin here are the attributes set
on on a host catalog in boundary.

The plugin fetches hosts through the
[DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
call.

[Getting Started](https://github.com/hashicorp/boundary-plugin-aws/plugin/service/host/README.md)

## Storage Bucket

This plugin supports storing and fetching objects from Amazon S3.

Files created with this plugin are stored as objects defined by the bucket
name and bucket prefix values configured in the storage bucket resource;
these storage bucket resources can in turn be associated to targets within
Boundary.

At creation, update or deletion of a storage bucket of this type, configuration of the
plugin is performed via the attribute/secret values passed to the create, update, or 
delete calls actions. The values passed in to the plugin here are the attributes set
on on a storage bucket in boundary.

The plugin fetches files through the
[GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)
call.

The plugin stores files through the
[PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
call.

The plugin fetches metadata about the files through the
[HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html)
call.

[Getting Started](https://github.com/hashicorp/boundary-plugin-aws/plugin/service/storage/README.md)
