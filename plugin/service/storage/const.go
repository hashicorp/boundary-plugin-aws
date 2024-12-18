// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

const (
	// ConstAwsEndpointUrl is the key for the endpoint url in the aws s3 client.
	ConstAwsEndpointUrl = "endpoint_url"

	// ConstAwsDualStack is the key for the dualstack flag in the aws s3 client.
	ConstAwsDualStack = "dual_stack"

	// defaultStreamChunkSize is the recommened chunk size for sending data through a stream
	defaultStreamChunkSize = 65536 // 64 KiB
)
