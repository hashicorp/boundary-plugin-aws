// Copyright (c) HashiCorp, Inc.
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
}

func getCatalogAttributes(in *structpb.Struct) (*CatalogAttributes, error) {
	unknownFields := values.StructFields(in)
	badFields := make(map[string]string)

	var err error
	credAttributes, err := cred.GetCredentialAttributes(in)
	if err != nil {
		return nil, err
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
