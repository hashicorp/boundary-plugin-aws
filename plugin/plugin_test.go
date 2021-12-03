package plugin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

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
			name: "error reading attributes",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErr: "missing required value \"region\"",
		},
		{
			name: "error reading secrets",
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
			name: "invalid region",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: mustStruct(map[string]interface{}{
						constAccessKeyId:     "foobar",
						constSecretAccessKey: "bazqux",
					}),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
					}),
				},
			},
			expectedErr: "not a valid region: foobar",
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
			name: "error reading attributes",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErr: "missing required value \"region\"",
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
			name: "error reading secrets",
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
			name: "error reading catalog attributes",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErr: "integrity error in host catalog attributes: missing required value \"region\"",
		},
		{
			name: "invalid region",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
					}),
				},
			},
			expectedErr: "integrity error in host catalog attributes: not a valid region: foobar",
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
			name: "set attribute load error",
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
						"foo": true,
						"bar": true,
					}),
				},
			},
			expectedErr: "error parsing set attributes: unknown set attribute fields provided: bar, foo",
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
						constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
						constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
			name: "DescribeInstances non-error array filter",
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
						constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
		{
			name: "DescribeInstances non-error string filter",
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
						constDescribeInstancesFilters: "tag-key=foo",
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
			name: "catalog attribute load error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErr: "integrity error in host catalog attributes: missing required value \"region\"",
		},
		{
			name: "invalid region",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
					}),
				},
			},
			expectedErr: "integrity error in host catalog attributes: not a valid region: foobar",
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
			name: "set attribute load error",
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
						"foo": true,
						"bar": true,
					}),
				},
			},
			expectedErr: "error parsing set attributes: unknown set attribute fields provided: bar, foo",
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
						constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
						constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
						constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
			name: "error reading catalog attributes",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
			},
			expectedErr: "integrity error in host catalog attributes: missing required value \"region\"",
		},
		{
			name: "invalid region",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attributes: mustStruct(map[string]interface{}{
						constRegion: "foobar",
					}),
				},
			},
			expectedErr: "integrity error in host catalog attributes: not a valid region: foobar",
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
			name: "set attribute load error",
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
							"foo": true,
							"bar": true,
						}),
					},
				},
			},
			expectedErr: "error parsing set attributes: unknown set attribute fields provided: bar, foo",
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
					{
						Id: "foobar",
						Attributes: mustStruct(map[string]interface{}{
							constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
					{
						Id: "foobar",
						Attributes: mustStruct(map[string]interface{}{
							constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
					{
						Id: "foobar",
						Attributes: mustStruct(map[string]interface{}{
							constDescribeInstancesFilters: []interface{}{"tag-key=foo"},
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
			expectedErr: "error processing host results for host set id \"foobar\": response integrity error: missing instance id",
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

func TestBuildFilters(t *testing.T) {
	cases := []struct {
		name                string
		in                  *structpb.Struct
		expected            []*ec2.Filter
		expectedErrContains string
	}{

		{
			name: "good without instance-state-name",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{
					"foo=bar",
				},
			}),
			expected: []*ec2.Filter{
				{
					Name:   aws.String("foo"),
					Values: aws.StringSlice([]string{"bar"}),
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: aws.StringSlice([]string{ec2.InstanceStateNameRunning}),
				},
			},
		},
		{
			name: "good with instance-state-name",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{
					"foo=bar",
					"instance-state-name=static",
				},
			}),
			expected: []*ec2.Filter{
				{
					Name:   aws.String("foo"),
					Values: aws.StringSlice([]string{"bar"}),
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: aws.StringSlice([]string{"static"}),
				},
			},
		},
		{
			name: "good with multiple values",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{
					"foo=bar,baz",
				},
			}),
			expected: []*ec2.Filter{
				{
					Name:   aws.String("foo"),
					Values: aws.StringSlice([]string{"bar", "baz"}),
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: aws.StringSlice([]string{ec2.InstanceStateNameRunning}),
				},
			},
		},
		{
			name: "empty filter set",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{},
			}),
			expected: []*ec2.Filter{
				{
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
			attrs, err := getSetAttributes(tc.in)
			require.NoError(err)
			actual, err := buildFilters(attrs)
			if tc.expectedErrContains != "" {
				require.Contains(err.Error(), tc.expectedErrContains)
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
			name: "good, dry run",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{
					"foo=bar",
				},
			}),
			dryRun: true,
			expected: &ec2.DescribeInstancesInput{
				DryRun: aws.Bool(true),
				Filters: []*ec2.Filter{
					{
						Name:   aws.String("foo"),
						Values: aws.StringSlice([]string{"bar"}),
					},
					{
						Name:   aws.String("instance-state-name"),
						Values: aws.StringSlice([]string{ec2.InstanceStateNameRunning}),
					},
				},
			},
		},
		{
			name: "good, real run",
			in: mustStruct(map[string]interface{}{
				constDescribeInstancesFilters: []interface{}{
					"foo=bar",
				},
			}),
			dryRun: false,
			expected: &ec2.DescribeInstancesInput{
				DryRun: aws.Bool(false),
				Filters: []*ec2.Filter{
					{
						Name:   aws.String("foo"),
						Values: aws.StringSlice([]string{"bar"}),
					},
					{
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
			attrs, err := getSetAttributes(tc.in)
			require.NoError(err)
			actual, err := buildDescribeInstancesInput(attrs, tc.dryRun)
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
			name:        "missing instance id",
			instance:    &ec2.Instance{},
			expectedErr: "response integrity error: missing instance id",
		},
		{
			name: "nil interface entry",
			instance: &ec2.Instance{
				InstanceId:        aws.String("foobar"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{nil},
			},
			expectedErr: "response integrity error: interface entry is nil",
		},
		{
			name: "nil interface address entry",
			instance: &ec2.Instance{
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
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp:      aws.String("1.1.1.1"),
									PublicDnsName: aws.String("test.example.com"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
								PrivateDnsName:   aws.String("test.example.internal"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1"},
				DnsNames:    []string{"test.example.internal", "test.example.com"},
			},
		},
		{
			name: "good, private",
			instance: &ec2.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								PrivateIpAddress: aws.String("10.0.0.1"),
								PrivateDnsName:   aws.String("test.example.internal"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1"},
				DnsNames:    []string{"test.example.internal"},
			},
		},
		{
			name: "good, multiple interfaces",
			instance: &ec2.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								PrivateIpAddress: aws.String("10.0.0.2"),
								PrivateDnsName:   aws.String("test2.example.internal"),
							},
						},
					},
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp:      aws.String("1.1.1.1"),
									PublicDnsName: aws.String("test.example.com"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
								PrivateDnsName:   aws.String("test.example.internal"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1", "10.0.0.2"},
				DnsNames:    []string{"test.example.internal", "test.example.com", "test2.example.internal"},
			},
		},
		{
			name: "good, multiple public interfaces",
			instance: &ec2.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp:      aws.String("1.1.1.2"),
									PublicDnsName: aws.String("test2.example.com"),
								},
								PrivateIpAddress: aws.String("10.0.0.2"),
								PrivateDnsName:   aws.String("test2.example.internal"),
							},
						},
					},
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp:      aws.String("1.1.1.1"),
									PublicDnsName: aws.String("test.example.com"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
								PrivateDnsName:   aws.String("test.example.internal"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1", "10.0.0.2", "1.1.1.2"},
				DnsNames:    []string{"test.example.internal", "test.example.com", "test2.example.internal", "test2.example.com"},
			},
		},
		{
			name: "good, multiple addresses on single interface",
			instance: &ec2.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{
					&ec2.InstanceNetworkInterface{
						PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
							&ec2.InstancePrivateIpAddress{
								Association: &ec2.InstanceNetworkInterfaceAssociation{
									PublicIp:      aws.String("1.1.1.1"),
									PublicDnsName: aws.String("test.example.com"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
								PrivateDnsName:   aws.String("test.example.internal"),
							},
							&ec2.InstancePrivateIpAddress{
								PrivateIpAddress: aws.String("10.0.0.2"),
								PrivateDnsName:   aws.String("test2.example.internal"),
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  "foobar",
				IpAddresses: []string{"10.0.0.1", "1.1.1.1", "10.0.0.2"},
				DnsNames:    []string{"test.example.internal", "test.example.com", "test2.example.internal"},
			},
		},
		{
			name: "good, single IP w/public addr and IPv6",
			instance: &ec2.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
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
				DnsNames:    []string{"test.example.internal", "test.example.com"},
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
