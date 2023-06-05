// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"github.com/hashicorp/boundary-plugin-aws/plugin/service/host"
	"github.com/hashicorp/boundary-plugin-aws/plugin/service/storage"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// Ensure that AWSPlugin implementings the following services:
//
//	HostPluginServiceServer
//	StoragePluginServiceServer
var (
	_ pb.HostPluginServiceServer    = (*host.HostPlugin)(nil)
	_ pb.StoragePluginServiceServer = (*storage.StoragePlugin)(nil)
)

// AwsPlugin contains a collection of all aws plugin services.
type AwsPlugin struct {
	// HostPlugin implements the HostPluginServiceServer interface for
	// supporting dynamically sourcing hosts from Amazon EC2
	*host.HostPlugin

	// StoragePlugin implements the StoragePluginServiceServer interface for
	// supporting storing and retrieving BSR files from Amazon S3
	*storage.StoragePlugin
}

func NewAwsPlugin() *AwsPlugin {
	return &AwsPlugin{
		HostPlugin:    &host.HostPlugin{},
		StoragePlugin: &storage.StoragePlugin{},
	}
}
