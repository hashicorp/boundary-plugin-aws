package storage

import (
	"testing"

	cred "github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetStorageAttributes(t *testing.T) {
	cases := []struct {
		name                string
		in                  map[string]any
		expected            *StorageAttributes
		expectedErrContains string
	}{
		{
			name:                "missing region",
			in:                  map[string]any{},
			expectedErrContains: "missing required value \"region\"",
		},
		{
			name: "unknown fields",
			in: map[string]any{
				"region": "us-west-2",
				"foo":    true,
				"bar":    true,
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
		},
		{
			name: "good w/ endpoint",
			in: map[string]any{
				cred.ConstRegion:    "us-west-2",
				ConstAwsEndpointUrl: "0.0.0.0",
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
			in: map[string]any{
				cred.ConstRegion: "us-west-2",
			},
			expected: &StorageAttributes{
				CredentialAttributes: &cred.CredentialAttributes{
					Region: "us-west-2",
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

			actual, err := getStorageAttributes(input)
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
