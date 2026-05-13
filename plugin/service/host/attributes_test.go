// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	cred "github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetCatalogAttributes(t *testing.T) {
	cases := []struct {
		name                string
		in                  *structpb.Struct
		expected            *CatalogAttributes
		expectedErrContains string
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
			name: "with dual stack",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":     structpb.NewStringValue("us-west-2"),
					"dual_stack": structpb.NewBoolValue(true),
				},
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: false,
				},
				DualStack: true,
			},
		},
		{
			name: "with primary interface only",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":                 structpb.NewStringValue("us-west-2"),
					"primary_interface_only": structpb.NewBoolValue(true),
				},
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: false,
				},
				PrimaryInterfaceOnly: true,
			},
		},
		{
			name: "with exclude public ip",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":             structpb.NewStringValue("us-west-2"),
					"exclude_public_ips": structpb.NewBoolValue(true),
				},
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: false,
				},
				ExcludePublicIps: true,
			},
		},
		{
			name: "with exclude private ip",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":              structpb.NewStringValue("us-west-2"),
					"exclude_private_ips": structpb.NewBoolValue(true),
				},
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: false,
				},
				ExcludePrivateIps: true,
			},
		},
		{
			name: "with mixed attributes",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":                 structpb.NewStringValue("us-west-2"),
					"dual_stack":             structpb.NewBoolValue(true),
					"exclude_private_ips":    structpb.NewBoolValue(true),
					"exclude_ipv6":           structpb.NewBoolValue(true),
					"primary_interface_only": structpb.NewBoolValue(true),
				},
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: false,
				},
				DualStack:            true,
				ExcludePrivateIps:    true,
				ExcludeIpv6:          true,
				PrimaryInterfaceOnly: true,
			},
		},
		{
			name: "can exclude public and private IPs when IPv6 remains enabled",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":              structpb.NewStringValue("us-west-2"),
					"exclude_private_ips": structpb.NewBoolValue(true),
					"exclude_public_ips":  structpb.NewBoolValue(true),
				},
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: false,
				},
				ExcludePrivateIps: true,
				ExcludePublicIps:  true,
			},
		},
		{
			name: "cannot exclude public private and IPv6 together",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region":              structpb.NewStringValue("us-west-2"),
					"exclude_private_ips": structpb.NewBoolValue(true),
					"exclude_public_ips":  structpb.NewBoolValue(true),
					"exclude_ipv6":        structpb.NewBoolValue(true),
				},
			},
			expectedErrContains: "attributes.exclude_ipv6: cannot be combined with exclude_private_ips and exclude_public_ips, attributes.exclude_private_ips: cannot be combined with exclude_public_ips and exclude_ipv6, attributes.exclude_public_ips: cannot be combined with exclude_private_ips and exclude_ipv6",
		},
		{
			name: "default",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"region": structpb.NewStringValue("us-west-2"),
				},
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: false,
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
			expected: &CatalogAttributes{
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
			require := require.New(t)

			actual, err := getCatalogAttributes(tc.in)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestGetSetAttributes(t *testing.T) {
	cases := []struct {
		name                string
		in                  map[string]any
		normalized          map[string]any
		expected            *SetAttributes
		expectedErrContains string
	}{
		{
			name:     "missing",
			in:       map[string]any{},
			expected: &SetAttributes{},
		},
		{
			name: "non-string-slice value",
			in: map[string]any{
				ConstDescribeInstancesFilters: "zip=foo,bar",
			},
			expected: &SetAttributes{
				Filters: []string{"zip=foo,bar"},
			},
		},
		{
			name: "bad filter element value",
			in: map[string]any{
				ConstDescribeInstancesFilters: []any{1},
			},
			expectedErrContains: "expected type 'string', got unconvertible type 'float64'",
		},
		{
			name: "unknown fields",
			in: map[string]any{
				"foo": true,
				"bar": true,
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
		},
		{
			name: "good",
			in: map[string]any{
				ConstDescribeInstancesFilters: []any{
					"foo=bar",
					"zip=zap",
				},
			},
			expected: &SetAttributes{
				Filters: []string{"foo=bar", "zip=zap"},
			},
		},
		{
			name: "good with filter transform",
			in: map[string]any{
				ConstDescribeInstancesFilters: "foo=bar",
			},
			normalized: map[string]any{
				ConstDescribeInstancesFilters: []any{"foo=bar"},
			},
			expected: &SetAttributes{
				Filters: []string{"foo=bar"},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			p := new(HostPlugin)
			normalizedOut, err := p.NormalizeSetData(context.Background(), &plugin.NormalizeSetDataRequest{Attributes: input})
			require.NoError(err)

			if tc.normalized != nil {
				normalized, err := structpb.NewStruct(tc.normalized)
				require.NoError(err)
				require.Empty(cmp.Diff(normalized, normalizedOut.Attributes, protocmp.Transform()))
			}
			input = normalizedOut.Attributes
			actual, err := getSetAttributes(input)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}
