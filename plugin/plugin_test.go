package plugin

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestOnCreateCatalogErr(t *testing.T) {
	cases := []struct {
		name        string
		req         *pb.OnCreateCatalogRequest
		opts        []awsCatalogPersistedStateOption
		expectedErr string
	}{
		{
			name:        "nil catalog",
			req:         &pb.OnCreateCatalogRequest{},
			expectedErr: "catalog is nil",
		},
		{
			name: "nil secrets",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{},
			},
			expectedErr: "secrets are required",
		},
		{
			name: "nil attributes",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErr: "attributes are required",
		},
		{
			name: "invalid region",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
					}),
				},
			},
			expectedErr: "not a valid region: foobar",
		},
		{
			name: "missing access key ID",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "us-west-2",
					}),
				},
			},
			expectedErr: "missing required value \"access_key_id\"",
		},
		{
			name: "missing secret access key",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId: "foobar",
					}),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "us-west-2",
					}),
				},
			},
			expectedErr: "missing required value \"secret_access_key\"",
		},
		{
			name: "invalid value for skipping rotation",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:     "foobar",
						constSecretAccessKey: "bazqux",
					}),
					Attributes: mustStruct(map[string]interface{}{
						constRegion:                    "us-west-2",
						constDisableCredentialRotation: "sure",
					}),
				},
			},
			expectedErr: "unexpected type for value \"disable_credential_rotation\": want bool, got string",
		},
		{
			name: "persisted state setup error",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:     "foobar",
						constSecretAccessKey: "bazqux",
					}),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "us-west-2",
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				func(s *awsCatalogPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErr: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
		},
		{
			name: "rotation error",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:     "foobar",
						constSecretAccessKey: "bazqux",
					}),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "us-west-2",
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				}),
			},
			expectedErr: fmt.Sprintf("error during credential rotation: error rotating credentials: error calling CreateAccessKey: error calling aws.GetUser: %s", testGetUserErr),
		},
		{
			name: "validation error",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:     "foobar",
						constSecretAccessKey: "bazqux",
					}),
					Attributes: mustStruct(map[string]interface{}{
						constRegion:                    "us-west-2",
						constDisableCredentialRotation: true,
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withStateTestOpts([]awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(
							awsutil.WithGetCallerIdentityError(errors.New(testGetCallerIdentityErr)),
						),
					),
				}),
			},
			expectedErr: fmt.Sprintf("error during credential validation: error validating credentials: %s", testGetCallerIdentityErr),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &AwsPlugin{
				testStateOpts: tc.opts,
			}
			_, err := p.OnCreateCatalog(context.Background(), tc.req)
			require.EqualError(err, tc.expectedErr)
		})
	}
}

func TestOnUpdateCatalogErr(t *testing.T) {
	cases := []struct {
		name        string
		req         *pb.OnUpdateCatalogRequest
		opts        []awsCatalogPersistedStateOption
		expectedErr string
	}{
		{
			name:        "nil new catalog",
			req:         &pb.OnUpdateCatalogRequest{},
			expectedErr: "new catalog is nil",
		},
		{
			name: "nil new attributes",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErr: "new catalog missing attributes",
		},
		{
			name: "invalid region",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
					}),
				},
			},
			expectedErr: "not a valid region: foobar",
		},
		{
			name: "persisted state setup error",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "us-west-2",
					}),
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:          "foobar",
						constSecretAccessKey:      "bazqux",
						constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				func(s *awsCatalogPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErr: fmt.Sprintf("error loading persisted state: %s", testOptionErr),
		},
		{
			name: "invalid value for credential rotation",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion:                    "us-west-2",
						constDisableCredentialRotation: "sure",
					}),
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:          "foobar",
						constSecretAccessKey:      "bazqux",
						constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
					}),
				},
			},
			expectedErr: "unexpected type for value \"disable_credential_rotation\": want bool, got string",
		},
		{
			name: "cannot disable rotation for already rotated credentials",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion:                    "us-west-2",
						constDisableCredentialRotation: true,
					}),
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:          "foobar",
						constSecretAccessKey:      "bazqux",
						constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
					}),
				},
			},
			expectedErr: "cannot disable rotation for already-rotated credentials",
		},
		{
			name: "updating secrets, missing access key id",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "us-west-2",
					}),
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:          "foobar",
						constSecretAccessKey:      "bazqux",
						constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
					}),
				},
			},
			expectedErr: "missing required value \"access_key_id\"",
		},
		{
			name: "updating secrets, missing secret access key",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId: "foobar",
					}),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "us-west-2",
					}),
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:          "foobar",
						constSecretAccessKey:      "bazqux",
						constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
					}),
				},
			},
			expectedErr: "missing required value \"secret_access_key\"",
		},
		{
			name: "updating secrets, replace error",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:     "onetwo",
						constSecretAccessKey: "threefour",
					}),
					Attributes: mustStruct(map[string]interface{}{
						constRegion:                    "us-west-2",
						constDisableCredentialRotation: true,
					}),
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:          "foobar",
						constSecretAccessKey:      "bazqux",
						constCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				}),
			},
			expectedErr: fmt.Sprintf("error attempting to replace credentials: error deleting old access key: %s", testDeleteAccessKeyErr),
		},
		{
			name: "rotation error",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "us-west-2",
					}),
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:     "foobar",
						constSecretAccessKey: "bazqux",
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				}),
			},
			expectedErr: fmt.Sprintf("error during credential rotation: error rotating credentials: error calling CreateAccessKey: error calling aws.GetUser: %s", testGetUserErr),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &AwsPlugin{
				testStateOpts: tc.opts,
			}
			_, err := p.OnUpdateCatalog(context.Background(), tc.req)
			require.EqualError(err, tc.expectedErr)
		})
	}
}
