// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"fmt"

	cred "github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary-plugin-aws/internal/errors"
	"github.com/hashicorp/boundary-plugin-aws/internal/values"
	"google.golang.org/protobuf/types/known/structpb"
)

// StorageAttributes is a Go-native representation of the Attributes
// map.
type StorageAttributes struct {
	*cred.CredentialAttributes

	// EndpointUrl is used for configuring how the aws client will resolve requests.
	EndpointUrl string
}

func getStorageAttributes(in *structpb.Struct) (*StorageAttributes, error) {
	unknownFields := values.StructFields(in)
	badFields := make(map[string]string)

	var err error
	credAttributes, err := cred.GetCredentialAttributes(in)
	if err != nil {
		return nil, err
	}

	endpointUrl, err := values.GetStringValue(in, ConstAwsEndpointUrl, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstAwsEndpointUrl)] = err.Error()
	}
	delete(unknownFields, ConstAwsEndpointUrl)

	for s := range unknownFields {
		switch s {
		// Ignore knownFields from CredentialAttributes
		case cred.ConstRegion:
			continue
		case cred.ConstDisableCredentialRotation:
			continue
		default:
			badFields[fmt.Sprintf("attributes.%s", s)] = "unrecognized field"
		}
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Invalid arguments in storage bucket attributes", badFields)
	}

	return &StorageAttributes{
		CredentialAttributes: credAttributes,
		EndpointUrl:          endpointUrl,
	}, nil
}
