package plugin

import (
	"github.com/hashicorp/boundary-plugin-host-aws/plugin/service/host"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// Ensure that AWSPlugin implementings the following services:
//
//	HostPluginServiceServer
var (
	_ pb.HostPluginServiceServer = (*host.HostPlugin)(nil)
)

// AwsPlugin contains a collection of all aws plugin services.
type AwsPlugin struct {
	// HostPlugin implements the HostPluginServiceServer interface for
	// supporting dynamically sourcing hosts from Amazon EC2
	*host.HostPlugin
}
