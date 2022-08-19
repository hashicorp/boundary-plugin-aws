package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
			name:                "missing region",
			in:                  mustStruct(map[string]interface{}{}),
			expectedErrContains: "missing required value \"region\"",
		},
		{
			name: "bad value for disable_credential_rotation",
			in: mustStruct(map[string]interface{}{
				constRegion:                    "us-west-2",
				constDisableCredentialRotation: "sure",
			}),
			expectedErrContains: "unexpected type for value \"disable_credential_rotation\": want bool, got string",
		},
		{
			name: "unknown fields",
			in: mustStruct(map[string]interface{}{
				constRegion: "us-west-2",
				"foo":       true,
				"bar":       true,
			}),
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
		},
		{
			name: "default",
			in: mustStruct(map[string]interface{}{
				constRegion: "us-west-2",
			}),
			expected: &CatalogAttributes{
				Region:                    "us-west-2",
				DisableCredentialRotation: false,
			},
		},
		{
			name: "with disable_credential_rotation",
			in: mustStruct(map[string]interface{}{
				constRegion:                    "us-west-2",
				constDisableCredentialRotation: true,
			}),
			expected: &CatalogAttributes{
				Region:                    "us-west-2",
				DisableCredentialRotation: true,
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

func TestGetCatalogSecrets(t *testing.T) {
	cases := []struct {
		name                string
		in                  *structpb.Struct
		expected            *CatalogSecrets
		expectedErrContains string
	}{
		{
			name:                "missing access_key_id",
			in:                  mustStruct(map[string]interface{}{}),
			expectedErrContains: "missing required value \"access_key_id\"",
		},
		{
			name: "missing secret_access_key",
			in: mustStruct(map[string]interface{}{
				constAccessKeyId: "foobar",
			}),
			expectedErrContains: "missing required value \"secret_access_key\"",
		},
		{
			name: "unknown fields",
			in: mustStruct(map[string]interface{}{
				constAccessKeyId:     "foobar",
				constSecretAccessKey: "bazqux",
				"foo":                true,
				"bar":                true,
			}),
			expectedErrContains: "secrets.bar: unrecognized field, secrets.foo: unrecognized field",
		},
		{
			name: "good",
			in: mustStruct(map[string]interface{}{
				constAccessKeyId:     "foobar",
				constSecretAccessKey: "bazqux",
			}),
			expected: &CatalogSecrets{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := getCatalogSecrets(tc.in)
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
		in                  *structpb.Struct
		normalized          *structpb.Struct
		expected            *SetAttributes
		expectedErrContains string
	}{
		{
			name:     "missing",
			in:       mustStruct(map[string]interface{}{}),
			expected: &SetAttributes{},
		},
		{
			name: "non-string-slice value",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: "zip=foo,bar",
			}),
			expected: &SetAttributes{
				Filters: []string{"zip=foo,bar"},
			},
		},
		{
			name: "bad filter element value",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{1},
			}),
			expectedErrContains: "expected type 'string', got unconvertible type 'float64'",
		},
		{
			name: "unknown fields",
			in: mustStruct(map[string]interface{}{
				"foo": true,
				"bar": true,
			}),
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
		},
		{
			name: "good",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{
					"foo=bar",
					"zip=zap",
				},
			}),
			expected: &SetAttributes{
				Filters: []string{"foo=bar", "zip=zap"},
			},
		},
		{
			name: "good with filter transform",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: "foo=bar",
			}),
			normalized: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{"foo=bar"},
			}),
			expected: &SetAttributes{
				Filters: []string{"foo=bar"},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := new(AwsPlugin)
			normalizedOut, err := p.NormalizeSetData(context.Background(), &plugin.NormalizeSetDataRequest{Attributes: tc.in})
			require.NoError(err)
			if tc.normalized != nil {
				require.Empty(cmp.Diff(tc.normalized, normalizedOut.Attributes, protocmp.Transform()))
			}
			tc.in = normalizedOut.Attributes
			actual, err := getSetAttributes(tc.in)
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

func TestGetStringValue(t *testing.T) {
	cases := []struct {
		name        string
		in          *structpb.Struct
		key         string
		required    bool
		expected    string
		expectedErr string
	}{
		{
			name:        "required missing",
			in:          mustStruct(map[string]interface{}{}),
			key:         "foo",
			required:    true,
			expectedErr: "missing required value \"foo\"",
		},
		{
			name:     "optional missing",
			in:       mustStruct(map[string]interface{}{}),
			key:      "foo",
			expected: "",
		},
		{
			name: "non-string value",
			in: mustStruct(map[string]interface{}{
				"foo": 1,
			}),
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want string, got float64",
		},
		{
			name: "required empty",
			in: mustStruct(map[string]interface{}{
				"foo": "",
			}),
			key:         "foo",
			required:    true,
			expectedErr: "value \"foo\" cannot be empty",
		},
		{
			name: "good",
			in: mustStruct(map[string]interface{}{
				"foo": "bar",
			}),
			key:      "foo",
			expected: "bar",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := getStringValue(tc.in, tc.key, tc.required)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestGetBoolValue(t *testing.T) {
	cases := []struct {
		name        string
		in          *structpb.Struct
		key         string
		required    bool
		expected    bool
		expectedErr string
	}{
		{
			name:        "required missing",
			in:          mustStruct(map[string]interface{}{}),
			key:         "foo",
			required:    true,
			expectedErr: "missing required value \"foo\"",
		},
		{
			name:     "optional missing",
			in:       mustStruct(map[string]interface{}{}),
			key:      "foo",
			expected: false,
		},
		{
			name: "non-bool value",
			in: mustStruct(map[string]interface{}{
				"foo": "bar",
			}),
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want bool, got string",
		},
		{
			name: "good",
			in: mustStruct(map[string]interface{}{
				"foo": true,
			}),
			key:      "foo",
			expected: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := getBoolValue(tc.in, tc.key, tc.required)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestGetTimeValue(t *testing.T) {
	staticTime := time.Now()

	cases := []struct {
		name        string
		in          *structpb.Struct
		key         string
		expected    time.Time
		expectedErr string
	}{
		{
			name:     "missing",
			in:       mustStruct(map[string]interface{}{}),
			key:      "foo",
			expected: time.Time{},
		},
		{
			name: "non-time value",
			in: mustStruct(map[string]interface{}{
				"foo": 1,
			}),
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want string, got float64",
		},
		{
			name: "bad parse",
			in: mustStruct(map[string]interface{}{
				"foo": "bar",
			}),
			key:         "foo",
			expectedErr: "could not parse time in value \"foo\": parsing time \"bar\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"bar\" as \"2006\"",
		},
		{
			name: "good",
			in: mustStruct(map[string]interface{}{
				"foo": staticTime.Format(time.RFC3339Nano),
			}),
			key: "foo",
			expected: func() time.Time {
				u, err := time.Parse(time.RFC3339Nano, staticTime.Format(time.RFC3339Nano))
				if err != nil {
					panic(err)
				}

				return u
			}(),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := getTimeValue(tc.in, tc.key)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestValidateRegion(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		expectedErr string
	}{
		{
			name:        "invalid region",
			in:          "foobar",
			expectedErr: "not a valid region: foobar",
		},
		{
			name:        "good",
			in:          "us-west-2",
			expectedErr: "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			err := validateRegion(tc.in)
			if tc.expectedErr != "" {
				require.Contains(err.Error(), tc.expectedErr)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
		})
	}
}
