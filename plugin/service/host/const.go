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

	// ConstInstanceAddressesOnly is the key (instance_addresses_only) that specifies whether
	// only the instance addresses (private IPv4/DNS, public IPv4/DNS, and IPv6) are synced,
	// or all addresses, including those from secondary ENIs, are synced.
	ConstInstanceAddressesOnly = "instance_addresses_only"
)
