// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package values

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetStringValue(t *testing.T) {
	cases := []struct {
		name        string
		in          map[string]any
		key         string
		required    bool
		expected    string
		expectedErr string
	}{
		{
			name:        "required missing",
			in:          map[string]any{},
			key:         "foo",
			required:    true,
			expectedErr: "missing required value \"foo\"",
		},
		{
			name:     "optional missing",
			in:       map[string]any{},
			key:      "foo",
			expected: "",
		},
		{
			name: "non-string value",
			in: map[string]any{
				"foo": 1,
			},
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want string, got float64",
		},
		{
			name: "required empty",
			in: map[string]any{
				"foo": "",
			},
			key:         "foo",
			required:    true,
			expectedErr: "value \"foo\" cannot be empty",
		},
		{
			name: "good",
			in: map[string]any{
				"foo": "bar",
			},
			key:      "foo",
			expected: "bar",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := GetStringValue(input, tc.key, tc.required)
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
		in          map[string]any
		key         string
		required    bool
		expected    bool
		expectedErr string
	}{
		{
			name:        "required missing",
			in:          map[string]any{},
			key:         "foo",
			required:    true,
			expectedErr: "missing required value \"foo\"",
		},
		{
			name:     "optional missing",
			in:       map[string]any{},
			key:      "foo",
			expected: false,
		},
		{
			name: "non-bool value",
			in: map[string]any{
				"foo": "bar",
			},
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want bool, got string",
		},
		{
			name: "good",
			in: map[string]any{
				"foo": true,
			},
			key:      "foo",
			expected: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := GetBoolValue(input, tc.key, tc.required)
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
		in          map[string]any
		key         string
		expected    time.Time
		expectedErr string
	}{
		{
			name:     "missing",
			in:       map[string]any{},
			key:      "foo",
			expected: time.Time{},
		},
		{
			name: "non-time value",
			in: map[string]any{
				"foo": 1,
			},
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want string, got float64",
		},
		{
			name: "bad parse",
			in: map[string]any{
				"foo": "bar",
			},
			key:         "foo",
			expectedErr: "could not parse time in value \"foo\": parsing time \"bar\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"bar\" as \"2006\"",
		},
		{
			name: "good",
			in: map[string]any{
				"foo": staticTime.Format(time.RFC3339Nano),
			},
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

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := GetTimeValue(input, tc.key)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestGetMapStringString(t *testing.T) {
	cases := []struct {
		name        string
		in          *structpb.Struct
		key         string
		required    bool
		expected    map[string]string
		expectedErr string
	}{
		{
			name:        "required missing",
			in:          &structpb.Struct{},
			key:         "foo",
			required:    true,
			expectedErr: "missing required value \"foo\"",
		},
		{
			name: "optional missing",
			in:   &structpb.Struct{},
			key:  "foo",
		},
		{
			name: "non-map[string]string value",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewBoolValue(true),
				},
			},
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want map[string]string, got bool",
		},
		{
			name: "empty map",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{},
					}),
				},
			},
			key:      "foo",
			expected: map[string]string{},
		},
		{
			name: "non-string value in map",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"bar": structpb.NewBoolValue(true),
						},
					}),
				},
			},
			key:         "foo",
			expectedErr: "unexpected type for value in map[\"bar\"]: want string, got bool",
		},
		{
			name: "good",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"bar": structpb.NewStringValue("zoo"),
						},
					}),
				},
			},
			key: "foo",
			expected: map[string]string{
				"bar": "zoo",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			actual, err := GetMapStringString(tc.in, tc.key, tc.required)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}
