package plugin

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
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

func TestOnDeleteCatalogErr(t *testing.T) {
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

func TestOnCreateSetErr(t *testing.T) {
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

func TestOnUpdateSetErr(t *testing.T) {
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

func TestListHostsErr(t *testing.T) {
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
