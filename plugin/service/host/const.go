// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package host

const (
	// ConstDescribeInstancesFilters is the key for the filter in the dynamic host set.
	ConstDescribeInstancesFilters = "filters"

	// ConstInstanceNameTagKey denotes the special AWS tag key that contains an EC2
	// instance's name. This field is to be matched literally.
	ConstInstanceNameTagKey = "Name"

	// ConstAwsDualStack is the key for the dualstack flag in the aws s3 client.
	ConstAwsDualStack = "dual_stack"

	// ConstPrimaryInterfaceOnly limits host discovery to the primary ENI.
	ConstPrimaryInterfaceOnly = "primary_interface_only"

	// ConstExcludePrivateIps excludes private IPv4 addresses.
	ConstExcludePrivateIps = "exclude_private_ips"

	// ConstExcludePublicIps excludes public IPv4 addresses associated to ENI IPs.
	ConstExcludePublicIps = "exclude_public_ips"

	// ConstExcludeIpv6 excludes IPv6 addresses.
	ConstExcludeIpv6 = "exclude_ipv6"
)
