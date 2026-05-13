// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"fmt"

	cred "github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary-plugin-aws/internal/errors"
	"github.com/hashicorp/boundary-plugin-aws/internal/values"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// CatalogAttributes is a Go-native representation of the Attributes
// map.
type CatalogAttributes struct {
	*cred.CredentialAttributes

	// DualStack is used for configuring how the aws client will resolve requests.
	DualStack bool

	// PrimaryInterfaceOnly restricts discovery to the instance's primary ENI.
	PrimaryInterfaceOnly bool

	// ExcludePrivateIps controls whether private IPv4 addresses are omitted.
	ExcludePrivateIps bool

	// ExcludePublicIps controls whether public IPv4 addresses are omitted.
	ExcludePublicIps bool

	// ExcludeIpv6 controls whether IPv6 addresses are omitted.
	ExcludeIpv6 bool
}

func getCatalogAttributes(in *structpb.Struct) (*CatalogAttributes, error) {
	unknownFields := values.StructFields(in)
	badFields := make(map[string]string)

	var err error
	credAttributes, err := cred.GetCredentialAttributes(in)
	if err != nil {
		return nil, err
	}

	dualStack, err := values.GetBoolValue(in, ConstAwsDualStack, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstAwsDualStack)] = err.Error()
	}
	delete(unknownFields, ConstAwsDualStack)

	primaryInterfaceOnly, err := values.GetBoolValue(in, ConstPrimaryInterfaceOnly, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstPrimaryInterfaceOnly)] = err.Error()
	}
	delete(unknownFields, ConstPrimaryInterfaceOnly)

	excludePrivateIPs, err := values.GetBoolValue(in, ConstExcludePrivateIps, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstExcludePrivateIps)] = err.Error()
	}
	delete(unknownFields, ConstExcludePrivateIps)

	excludePublicIPs, err := values.GetBoolValue(in, ConstExcludePublicIps, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstExcludePublicIps)] = err.Error()
	}
	delete(unknownFields, ConstExcludePublicIps)

	excludeIpv6, err := values.GetBoolValue(in, ConstExcludeIpv6, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstExcludeIpv6)] = err.Error()
	}
	delete(unknownFields, ConstExcludeIpv6)

	if excludePrivateIPs && excludePublicIPs && excludeIpv6 {
		badFields[fmt.Sprintf("attributes.%s", ConstExcludePrivateIps)] = "cannot be combined with exclude_public_ips and exclude_ipv6"
		badFields[fmt.Sprintf("attributes.%s", ConstExcludePublicIps)] = "cannot be combined with exclude_private_ips and exclude_ipv6"
		badFields[fmt.Sprintf("attributes.%s", ConstExcludeIpv6)] = "cannot be combined with exclude_private_ips and exclude_public_ips"
	}

	for s := range unknownFields {
		switch s {
		// Ignore knownFields from CredentialAttributes
		case cred.ConstRegion:
			continue
		case cred.ConstDisableCredentialRotation:
			continue
		case cred.ConstRoleArn:
			continue
		case cred.ConstRoleExternalId:
			continue
		case cred.ConstRoleSessionName:
			continue
		case cred.ConstRoleTags:
			continue
		default:
			badFields[fmt.Sprintf("attributes.%s", s)] = "unrecognized field"
		}
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Invalid arguments in catalog attributes", badFields)
	}

	return &CatalogAttributes{
		CredentialAttributes: credAttributes,
		DualStack:            dualStack,
		PrimaryInterfaceOnly: primaryInterfaceOnly,
		ExcludePrivateIps:    excludePrivateIPs,
		ExcludePublicIps:     excludePublicIPs,
		ExcludeIpv6:          excludeIpv6,
	}, nil
}

// SetAttributes is a Go-native representation of the Attributes map that can be
// used for decoding the incoming map via mapstructure.
type SetAttributes struct {
	Filters []string
}

func getSetAttributes(in *structpb.Struct) (*SetAttributes, error) {
	var setAttrs SetAttributes

	// Quick validation to ensure that there's no non-filter attributes
	// here for now. Make this more complex if we add more attributes
	// to host sets.
	unknownFields := values.StructFields(in)
	badFields := make(map[string]string)
	delete(unknownFields, ConstDescribeInstancesFilters)
	for a := range unknownFields {
		badFields[fmt.Sprintf("attributes.%s", a)] = "unrecognized field"
	}
	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the attributes provided", badFields)
	}

	// Mapstructure complains if it expects a slice as output and sees a scalar
	// value. Rather than use WeakDecode and risk unintended consequences, I'm
	// manually making this change if necessary.
	inMap := in.AsMap()
	if filtersRaw, ok := inMap[ConstDescribeInstancesFilters]; ok {
		switch filterVal := filtersRaw.(type) {
		case string:
			inMap[ConstDescribeInstancesFilters] = []string{filterVal}
		}
	}

	if err := mapstructure.Decode(inMap, &setAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error decoding set attributes: %s", err)
	}

	return &setAttrs, nil
}
