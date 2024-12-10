// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"testing"

	cred "github.com/hashicorp/boundary-plugin-aws/internal/credential"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetStorageAttributes(t *testing.T) {
	cases := []struct {
		name                string
		in                  *structpb.Struct
		expected            *StorageAttributes
		expectedErrContains string
		expectedDetails     *pb.StorageBucketCredentialState
	}{
		{
			name: "missing region",
			in: &structpb.Struct{
				Fields: make(map[string]*structpb.Value),
			},
			expectedErrContains: "missing required value \"region\"",
		},
		{
			name: "unknown fields",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region": structpb.NewStringValue("us-west-2"),
					"foo":    structpb.NewBoolValue(true),
					"bar":    structpb.NewBoolValue(true),
				},
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
		},
		{
			name: "good w/ endpoint",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":       structpb.NewStringValue("us-west-2"),
					"endpoint_url": structpb.NewStringValue("0.0.0.0"),
				},
			},
			expected: &StorageAttributes{
				CredentialAttributes: &cred.CredentialAttributes{
					Region: "us-west-2",
				},
				EndpointUrl: "0.0.0.0",
			},
		},
		{
			name: "good w/o endpoint",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region": structpb.NewStringValue("us-west-2"),
				},
			},
			expected: &StorageAttributes{
				CredentialAttributes: &cred.CredentialAttributes{
					Region: "us-west-2",
				},
			},
		},
		{
			name: "credential attributes",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":                      structpb.NewStringValue("us-west-2"),
					"disable_credential_rotation": structpb.NewBoolValue(true),
					"role_arn":                    structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
					"role_external_id":            structpb.NewStringValue("1234567890"),
					"role_session_name":           structpb.NewStringValue("test-session"),
					"role_tags": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"foo": structpb.NewStringValue("bar"),
						},
					}),
				},
			},
			expected: &StorageAttributes{
				CredentialAttributes: &cred.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: true,
					RoleArn:                   "arn:aws:iam::123456789012:role/S3Access",
					RoleExternalId:            "1234567890",
					RoleSessionName:           "test-session",
					RoleTags: map[string]string{
						"foo": "bar",
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			actual, err := getStorageAttributes(tc.in)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(codes.InvalidArgument, status.Code(err))

				st, ok := status.FromError(err)
				require.True(ok)
				assert.Len(st.Details(), 0)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}
