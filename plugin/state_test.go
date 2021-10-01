package plugin

import (
	"testing"
	"time"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
)

func TestAwsCatalogPersistedStateFromProto(t *testing.T) {
	cases := []struct {
		name        string
		in          *pb.HostCatalogPersisted
		expected    *awsCatalogPersistedState
		expectedErr string
	}{
		{
			name: "no secrets",
			in: &pb.HostCatalogPersisted{
				Secrets: nil,
			},
			expectedErr: "missing persisted secrets",
		},
		{
			name: "missing access key ID",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(nil),
			},
			expectedErr: "persisted state integrity error: missing required value \"access_key_id\"",
		},
		{
			name: "missing secret access key",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId: "foobar",
				}),
			},
			expectedErr: "persisted state integrity error: missing required value \"secret_access_key\"",
		},
		{
			name: "bad last rotated time",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId:          "foobar",
					constSecretAccessKey:      "bazqux",
					constCredsLastRotatedTime: "notatime",
				}),
			},
			expectedErr: "persisted state integrity error: could not parse time in value \"creds_last_rotated_time\": parsing time \"notatime\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"notatime\" as \"2006\"",
		},
		{
			name: "good with non-zero timestamp",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId:          "foobar",
					constSecretAccessKey:      "bazqux",
					constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
				}),
			},
			expected: &awsCatalogPersistedState{
				AccessKeyId:     "foobar",
				SecretAccessKey: "bazqux",
				CredsLastRotatedTime: func() time.Time {
					t, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")
					if err != nil {
						panic(err)
					}

					return t
				}(),
			},
		},
		{
			name: "good with zero timestamp",
			in: &pb.HostCatalogPersisted{
				// Nil should be the same as empty map here
				Secrets: mustStruct(map[string]interface{}{
					constAccessKeyId:          "foobar",
					constSecretAccessKey:      "bazqux",
					constCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
				}),
			},
			expected: &awsCatalogPersistedState{
				AccessKeyId:          "foobar",
				SecretAccessKey:      "bazqux",
				CredsLastRotatedTime: time.Time{},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := awsCatalogPersistedStateFromProto(tc.in)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}
