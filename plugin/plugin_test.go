package plugin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPluginOnCreateCatalogErr(t *testing.T) {
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

func TestPluginOnUpdateCatalogErr(t *testing.T) {
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

func TestPluginOnDeleteCatalogErr(t *testing.T) {
	cases := []struct {
		name        string
		req         *pb.OnDeleteCatalogRequest
		opts        []awsCatalogPersistedStateOption
		expectedErr string
	}{
		{
			name: "persisted state setup error",
			req: &pb.OnDeleteCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
			name: "delete error",
			req: &pb.OnDeleteCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				withStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				}),
			},
			expectedErr: fmt.Sprintf("error removing rotated credentials during catalog deletion: error deleting old access key: %s", testDeleteAccessKeyErr),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &AwsPlugin{
				testStateOpts: tc.opts,
			}
			_, err := p.OnDeleteCatalog(context.Background(), tc.req)
			require.EqualError(err, tc.expectedErr)
		})
	}
}

func TestPluginOnCreateSetErr(t *testing.T) {
	cases := []struct {
		name        string
		req         *pb.OnCreateSetRequest
		opts        []awsCatalogPersistedStateOption
		expectedErr string
	}{
		{
			name:        "nil catalog",
			req:         &pb.OnCreateSetRequest{},
			expectedErr: "catalog is nil",
		},
		{
			name: "nil catalog attributes",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErr: "catalog missing attributes",
		},
		{
			name: "persisted state setup error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
			name: "invalid region",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
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
			expectedErr: "catalog validation error: not a valid region: foobar",
		},
		{
			name: "nil set",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
			expectedErr: "set is nil",
		},
		{
			name: "nil attributes in set",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Set: &hostsets.HostSet{},
			},
			expectedErr: "set missing attributes",
		},
		{
			name: "client load error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Set: &hostsets.HostSet{
					Attributes: mustStruct(map[string]interface{}{
						constDescribeInstancesFilters: map[string]interface{}{
							"tag-key": []interface{}{"foo"},
						},
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withStateTestOpts([]awsutil.Option{
					awsutil.MockOptionErr(errors.New(testOptionErr)),
				}),
			},
			expectedErr: fmt.Sprintf("error getting EC2 client: error getting AWS session: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "buildDescribeInstancesInput error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Set: &hostsets.HostSet{
					Attributes: mustStruct(map[string]interface{}{
						constDescribeInstancesFilters: map[string]interface{}{
							"tag-key": "foo",
						},
					}),
				},
			},
			expectedErr: "error building DescribeInstances parameters: error building filters: unexpected type for filter values in \"tag-key\": want array, got string",
		},
		{
			name: "DescribeInstances error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Set: &hostsets.HostSet{
					Attributes: mustStruct(map[string]interface{}{
						constDescribeInstancesFilters: map[string]interface{}{
							"tag-key": []interface{}{"foo"},
						},
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesError(errors.New(testDescribeInstancesError)),
				)),
			},
			expectedErr: fmt.Sprintf("error performing dry run of DescribeInstances: %s", testDescribeInstancesError),
		},
		{
			name: "DescribeInstances non-error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Set: &hostsets.HostSet{
					Attributes: mustStruct(map[string]interface{}{
						constDescribeInstancesFilters: map[string]interface{}{
							"tag-key": []interface{}{"foo"},
						},
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
				)),
			},
			expectedErr: "query error: DescribeInstances DryRun should have returned error, but none was found",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &AwsPlugin{
				testStateOpts: tc.opts,
			}
			_, err := p.OnCreateSet(context.Background(), tc.req)
			require.EqualError(err, tc.expectedErr)
		})
	}
}

func TestPluginOnUpdateSetErr(t *testing.T) {
	cases := []struct {
		name        string
		req         *pb.OnUpdateSetRequest
		opts        []awsCatalogPersistedStateOption
		expectedErr string
	}{
		{
			name:        "nil catalog",
			req:         &pb.OnUpdateSetRequest{},
			expectedErr: "catalog is nil",
		},
		{
			name: "nil catalog attributes",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErr: "catalog missing attributes",
		},
		{
			name: "persisted state setup error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
			name: "invalid region",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
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
			expectedErr: "catalog validation error: not a valid region: foobar",
		},
		{
			name: "nil set",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
			expectedErr: "new set is nil",
		},
		{
			name: "nil attributes in set",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				NewSet: &hostsets.HostSet{},
			},
			expectedErr: "new set missing attributes",
		},
		{
			name: "client load error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				NewSet: &hostsets.HostSet{
					Attributes: mustStruct(map[string]interface{}{
						constDescribeInstancesFilters: map[string]interface{}{
							"tag-key": []interface{}{"foo"},
						},
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withStateTestOpts([]awsutil.Option{
					awsutil.MockOptionErr(errors.New(testOptionErr)),
				}),
			},
			expectedErr: fmt.Sprintf("error getting EC2 client: error getting AWS session: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "buildDescribeInstancesInput error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				NewSet: &hostsets.HostSet{
					Attributes: mustStruct(map[string]interface{}{
						constDescribeInstancesFilters: map[string]interface{}{
							"tag-key": "foo",
						},
					}),
				},
			},
			expectedErr: "error building DescribeInstances parameters: error building filters: unexpected type for filter values in \"tag-key\": want array, got string",
		},
		{
			name: "DescribeInstances error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				NewSet: &hostsets.HostSet{
					Attributes: mustStruct(map[string]interface{}{
						constDescribeInstancesFilters: map[string]interface{}{
							"tag-key": []interface{}{"foo"},
						},
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesError(errors.New(testDescribeInstancesError)),
				)),
			},
			expectedErr: fmt.Sprintf("error performing dry run of DescribeInstances: %s", testDescribeInstancesError),
		},
		{
			name: "DescribeInstances non-error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				NewSet: &hostsets.HostSet{
					Attributes: mustStruct(map[string]interface{}{
						constDescribeInstancesFilters: map[string]interface{}{
							"tag-key": []interface{}{"foo"},
						},
					}),
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
				)),
			},
			expectedErr: "query error: DescribeInstances DryRun should have returned error, but none was found",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &AwsPlugin{
				testStateOpts: tc.opts,
			}
			_, err := p.OnUpdateSet(context.Background(), tc.req)
			require.EqualError(err, tc.expectedErr)
		})
	}
}

func TestPluginListHostsErr(t *testing.T) {
	cases := []struct {
		name        string
		req         *pb.ListHostsRequest
		opts        []awsCatalogPersistedStateOption
		expectedErr string
	}{
		{
			name:        "nil catalog",
			req:         &pb.ListHostsRequest{},
			expectedErr: "catalog is nil",
		},
		{
			name: "nil catalog attributes",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErr: "catalog missing attributes",
		},
		{
			name: "persisted state setup error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
			name: "invalid region",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
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
			expectedErr: "catalog validation error: not a valid region: foobar",
		},
		{
			name: "nil sets",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
			expectedErr: "sets is nil",
		},
		{
			name: "set missing id",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Sets: []*hostsets.HostSet{&hostsets.HostSet{}},
			},
			expectedErr: "set missing id",
		},
		{
			name: "set missing attributes",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Sets: []*hostsets.HostSet{
					&hostsets.HostSet{
						Id: "foobar",
					},
				},
			},
			expectedErr: "set missing attributes",
		},
		{
			name: "buildDescribeInstancesInput error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Sets: []*hostsets.HostSet{
					&hostsets.HostSet{
						Id: "foobar",
						Attributes: mustStruct(map[string]interface{}{
							constDescribeInstancesFilters: map[string]interface{}{
								"tag-key": "foo",
							},
						}),
					},
				},
			},
			expectedErr: "error building DescribeInstances parameters for host set id \"foobar\": error building filters: unexpected type for filter values in \"tag-key\": want array, got string",
		},
		{
			name: "client load error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Sets: []*hostsets.HostSet{
					&hostsets.HostSet{
						Id: "foobar",
						Attributes: mustStruct(map[string]interface{}{
							constDescribeInstancesFilters: map[string]interface{}{
								"tag-key": []interface{}{"foo"},
							},
						}),
					},
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withStateTestOpts([]awsutil.Option{
					awsutil.MockOptionErr(errors.New(testOptionErr)),
				}),
			},
			expectedErr: fmt.Sprintf("error getting EC2 client: error getting AWS session: error reading options in NewCredentialsConfig: %s", testOptionErr),
		},
		{
			name: "DescribeInstances error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Sets: []*hostsets.HostSet{
					&hostsets.HostSet{
						Id: "foobar",
						Attributes: mustStruct(map[string]interface{}{
							constDescribeInstancesFilters: map[string]interface{}{
								"tag-key": []interface{}{"foo"},
							},
						}),
					},
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesError(errors.New(testDescribeInstancesError)),
				)),
			},
			expectedErr: fmt.Sprintf("error running DescribeInstances for host set id \"foobar\": %s", testDescribeInstancesError),
		},
		{
			name: "awsInstanceToHost error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
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
				Sets: []*hostsets.HostSet{
					&hostsets.HostSet{
						Id: "foobar",
						Attributes: mustStruct(map[string]interface{}{
							constDescribeInstancesFilters: map[string]interface{}{
								"tag-key": []interface{}{"foo"},
							},
						}),
					},
				},
			},
			opts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesOutput(
						&ec2.DescribeInstancesOutput{
							Reservations: []*ec2.Reservation{
								&ec2.Reservation{
									Instances: []*ec2.Instance{
										&ec2.Instance{
											// Blank so we error out
										},
									},
								},
							},
						},
					),
				)),
			},
			expectedErr: "error processing host results for host set id \"foobar\": response integrity error: missing instance state",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &AwsPlugin{
				testStateOpts: tc.opts,
			}
			_, err := p.ListHosts(context.Background(), tc.req)
			require.EqualError(err, tc.expectedErr)
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

func TestGetMapValue(t *testing.T) {
	cases := []struct {
		name        string
		in          *structpb.Struct
		key         string
		expected    map[string]interface{}
		expectedErr string
	}{
		{
			name:     "missing",
			in:       mustStruct(map[string]interface{}{}),
			key:      "foo",
			expected: make(map[string]interface{}),
		},
		{
			name: "non-map value",
			in: mustStruct(map[string]interface{}{
				"foo": "bar",
			}),
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want map, got string",
		},
		{
			name: "good",
			in: mustStruct(map[string]interface{}{
				"foo": map[string]interface{}{
					"one": "two",
				},
			}),
			key: "foo",
			expected: map[string]interface{}{
				"one": "two",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := getMapValue(tc.in, tc.key)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestGetValidateRegionValue(t *testing.T) {
	cases := []struct {
		name        string
		in          *structpb.Struct
		key         string
		expected    string
		expectedErr string
	}{
		{
			name:        "missing",
			in:          mustStruct(map[string]interface{}{}),
			key:         "region",
			expectedErr: fmt.Sprintf("missing required value %q", constRegion),
		},
		{
			name: "invalid region",
			in: mustStruct(map[string]interface{}{
				constRegion: "foobar",
			}),
			expectedErr: "not a valid region: foobar",
		},
		{
			name: "good",
			in: mustStruct(map[string]interface{}{
				constRegion: "us-west-2",
			}),
			expected: "us-west-2",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := getValidateRegionValue(tc.in)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestBuildFilters(t *testing.T) {
	cases := []struct {
		name        string
		in          *structpb.Struct
		expected    []*ec2.Filter
		expectedErr string
	}{
		{
			name: "map value error",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: "foo",
			}),
			expectedErr: fmt.Sprintf("unexpected type for value %q: want map, got string", constDescribeInstancesFilters),
		},
		{
			name: "bad filter values",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: map[string]interface{}{
					"foo": "bar",
				},
			}),
			expectedErr: "unexpected type for filter values in \"foo\": want array, got string",
		},
		{
			name: "bad filter element value",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: map[string]interface{}{
					"foo": []interface{}{1},
				},
			}),
			expectedErr: "unexpected type for filter element value 1: want string, got float64",
		},
		{
			name: "good without instance-state-name",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: map[string]interface{}{
					"foo": []interface{}{"bar"},
				},
			}),
			expected: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("foo"),
					Values: aws.StringSlice([]string{"bar"}),
				},
				&ec2.Filter{
					Name:   aws.String("instance-state-name"),
					Values: aws.StringSlice([]string{ec2.InstanceStateNameRunning}),
				},
			},
		},
		{
			name: "good with instance-state-name",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: map[string]interface{}{
					"foo":                 []interface{}{"bar"},
					"instance-state-name": []interface{}{"static"},
				},
			}),
			expected: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("foo"),
					Values: aws.StringSlice([]string{"bar"}),
				},
				&ec2.Filter{
					Name:   aws.String("instance-state-name"),
					Values: aws.StringSlice([]string{"static"}),
				},
			},
		},
		{
			name: "empty filter set",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: map[string]interface{}{},
			}),
			expected: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("instance-state-name"),
					Values: aws.StringSlice([]string{ec2.InstanceStateNameRunning}),
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := buildFilters(tc.in)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			sort.Sort(ec2FilterSorter(actual))
			require.Equal(tc.expected, actual)
		})
	}
}

func TestBuildDescribeInstancesInput(t *testing.T) {
	cases := []struct {
		name        string
		in          *structpb.Struct
		dryRun      bool
		expected    *ec2.DescribeInstancesInput
		expectedErr string
	}{
		{
			name: "buildFilters error",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: "foo",
			}),
			expectedErr: fmt.Sprintf("error building filters: unexpected type for value %q: want map, got string", constDescribeInstancesFilters),
		},
		{
			name: "good, dry run",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: map[string]interface{}{
					"foo": []interface{}{"bar"},
				},
			}),
			dryRun: true,
			expected: &ec2.DescribeInstancesInput{
				DryRun: aws.Bool(true),
				Filters: []*ec2.Filter{
					&ec2.Filter{
						Name:   aws.String("foo"),
						Values: aws.StringSlice([]string{"bar"}),
					},
					&ec2.Filter{
						Name:   aws.String("instance-state-name"),
						Values: aws.StringSlice([]string{ec2.InstanceStateNameRunning}),
					},
				},
			},
		},
		{
			name: "good, real run",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: map[string]interface{}{
					"foo": []interface{}{"bar"},
				},
			}),
			dryRun: false,
			expected: &ec2.DescribeInstancesInput{
				DryRun: aws.Bool(false),
				Filters: []*ec2.Filter{
					&ec2.Filter{
						Name:   aws.String("foo"),
						Values: aws.StringSlice([]string{"bar"}),
					},
					&ec2.Filter{
						Name:   aws.String("instance-state-name"),
						Values: aws.StringSlice([]string{ec2.InstanceStateNameRunning}),
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := buildDescribeInstancesInput(tc.in, tc.dryRun)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestAwsInstanceToHost(t *testing.T) {
	cases := []struct {
		name        string
		instance    *ec2.Instance
		expected    *pb.ListHostsResponseHost
		expectedErr string
	}{
		{
			name:        "nil instance",
			instance:    nil,
			expectedErr: "response integrity error: missing instance entry",
		},
		{
			name:        "nil instance state",
			instance:    &ec2.Instance{},
			expectedErr: "response integrity error: missing instance state",
		},
		{
			name: "missing instance state name",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{},
			},
			expectedErr: "response integrity error: missing instance state name",
		},
		{
			name: "missing instance id",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
			},
			expectedErr: "response integrity error: missing instance id",
		},
		{
			name: "instance not running",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameTerminated),
				},
				InstanceId: aws.String("foobar"),
			},
			expected: nil,
		},
		{
			name: "nil interface entry",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
				InstanceId:        aws.String("foobar"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{nil},
			},
			expectedErr: "response integrity error: interface entry is nil",
		},
		{
			name: "nil interface address entry",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
				InstanceId: aws.String("foobar"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{nil},
					},
				},
			},
			expectedErr: "response integrity error: interface address entry is nil",
		},
		{
			name: "good, single IP w/public addr",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp: aws.String("1.1.1.1"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1"},
			},
		},
		{
			name: "good, private",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								PrivateIpAddress: aws.String("10.0.0.1"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1"},
			},
		},
		{
			name: "good, multiple interfaces",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								PrivateIpAddress: aws.String("10.0.0.2"),
							},
						},
					},
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp: aws.String("1.1.1.1"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1", "10.0.0.2"},
			},
		},
		{
			name: "good, multiple public interfaces",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp: aws.String("1.1.1.2"),
								},
								PrivateIpAddress: aws.String("10.0.0.2"),
							},
						},
					},
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp: aws.String("1.1.1.1"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1", "10.0.0.2", "1.1.1.2"},
			},
		},
		{
			name: "good, multiple addresses on single interface",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp: aws.String("1.1.1.1"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
							},
							&ec2.InstancePrivateIpAddress{
								PrivateIpAddress: aws.String("10.0.0.2"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1", "10.0.0.2"},
			},
		},
		{
			name: "good, single IP w/public addr and IPv6",
			instance: &ec2.Instance{
				State: &ec2.InstanceState{
					Name: aws.String(ec2.InstanceStateNameRunning),
				},
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp: aws.String("1.1.1.1"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
							},
						},
						Ipv6Addresses: []*ec2.InstanceIpv6Address{
							nil, // Just coverage for nil assertion which is skipped
							&ec2.InstanceIpv6Address{Ipv6Address: aws.String("some::fake::address")},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1", "some::fake::address"},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := awsInstanceToHost(tc.instance)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}
