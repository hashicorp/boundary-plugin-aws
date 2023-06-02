package host

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
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
		in                  map[string]any
		expected            *CatalogAttributes
		expectedErrContains string
	}{
		{
			name:                "missing region",
			in:                  map[string]any{},
			expectedErrContains: "missing required value \"region\"",
		},
		{
			name: "bad value for disable_credential_rotation",
			in: map[string]any{
				credential.ConstRegion:                    "us-west-2",
				credential.ConstDisableCredentialRotation: "sure",
			},
			expectedErrContains: "unexpected type for value \"disable_credential_rotation\": want bool, got string",
		},
		{
			name: "unknown fields",
			in: map[string]any{
				credential.ConstRegion: "us-west-2",
				"foo":                  true,
				"bar":                  true,
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
		},
		{
			name: "default",
			in: map[string]any{
				credential.ConstRegion: "us-west-2",
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: false,
				},
			},
		},
		{
			name: "with disable_credential_rotation",
			in: map[string]any{
				credential.ConstRegion:                    "us-west-2",
				credential.ConstDisableCredentialRotation: true,
			},
			expected: &CatalogAttributes{
				CredentialAttributes: &credential.CredentialAttributes{
					Region:                    "us-west-2",
					DisableCredentialRotation: true,
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := getCatalogAttributes(input)
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
