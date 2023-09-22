// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPluginOnCreateCatalogErr(t *testing.T) {
	cases := []struct {
		name                string
		req                 *pb.OnCreateCatalogRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		catalogOpts         []awsCatalogPersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
	}{
		{
			name:                "nil catalog",
			req:                 &pb.OnCreateCatalogRequest{},
			expectedErrContains: "catalog is nil",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil attributes",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErrContains: "attributes are required",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading secrets",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
			},
			expectedErrContains: "missing required value \"access_key_id\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "invalid region",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						}},
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("foobar"),
							},
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						}},
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				func(s *awsCatalogPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error setting up persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "rotation error",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						}},
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				}),
			},
			expectedErrContains: fmt.Sprintf("error during credential rotation: error rotating credentials: error calling CreateAccessKey: error calling iam.GetUser: %s", testGetUserErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "validation error",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						}},
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
								credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(
							awsutil.WithGetCallerIdentityError(errors.New(testGetCallerIdentityErr)),
						),
					),
				}),
			},
			expectedErrContains: fmt.Sprintf("error during credential validation: error validating credentials: %s", testGetCallerIdentityErr),
			expectedErrCode:     codes.InvalidArgument,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &HostPlugin{
				testCredStateOpts:    tc.credOpts,
				testCatalogStateOpts: tc.catalogOpts,
			}
			_, err := p.OnCreateCatalog(context.Background(), tc.req)
			require.Contains(err.Error(), tc.expectedErrContains)
			require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
		})
	}
}

func TestPluginOnUpdateCatalogErr(t *testing.T) {
	cases := []struct {
		name                string
		req                 *pb.OnUpdateCatalogRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		catalogOpts         []awsCatalogPersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
	}{
		{
			name:                "nil new catalog",
			req:                 &pb.OnUpdateCatalogRequest{},
			expectedErrContains: "new catalog is nil",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil new attributes",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErrContains: "new catalog missing attributes",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading attributes",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "invalid region",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("foobar"),
							},
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				func(s *awsCatalogPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "cannot disable rotation for already rotated credentials",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
								credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			expectedErrContains: "cannot disable rotation for already-rotated credentials",
			expectedErrCode:     codes.FailedPrecondition,
		},
		{
			name: "error reading secrets",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			expectedErrContains: "missing required value \"access_key_id\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "updating secrets, replace error",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_onetwo"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("threefour"),
						},
					},
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion:                    structpb.NewStringValue("us-west-2"),
								credential.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				}),
			},
			expectedErrContains: fmt.Sprintf("error attempting to replace credentials: error deleting old access key: %s", testDeleteAccessKeyErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "rotation error",
			req: &pb.OnUpdateCatalogRequest{
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithGetUserError(errors.New(testGetUserErr)),
						),
					),
				}),
			},
			expectedErrContains: fmt.Sprintf("error during credential rotation: error rotating credentials: error calling CreateAccessKey: error calling iam.GetUser: %s", testGetUserErr),
			expectedErrCode:     codes.InvalidArgument,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &HostPlugin{
				testCredStateOpts:    tc.credOpts,
				testCatalogStateOpts: tc.catalogOpts,
			}
			_, err := p.OnUpdateCatalog(context.Background(), tc.req)
			require.Contains(err.Error(), tc.expectedErrContains)
			require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
		})
	}
}

func TestPluginOnDeleteCatalogErr(t *testing.T) {
	cases := []struct {
		name                string
		req                 *pb.OnDeleteCatalogRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		catalogOpts         []awsCatalogPersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
	}{
		{
			name: "persisted state setup error",
			req: &pb.OnDeleteCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				func(s *awsCatalogPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "delete error",
			req: &pb.OnDeleteCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithIAMAPIFunc(
						awsutil.NewMockIAM(
							awsutil.WithDeleteAccessKeyError(errors.New(testDeleteAccessKeyErr)),
						),
					),
				}),
			},
			expectedErrContains: fmt.Sprintf("error removing rotated credentials during catalog deletion: error deleting old access key: %s", testDeleteAccessKeyErr),
			expectedErrCode:     codes.Aborted,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &HostPlugin{
				testCredStateOpts:    tc.credOpts,
				testCatalogStateOpts: tc.catalogOpts,
			}
			_, err := p.OnDeleteCatalog(context.Background(), tc.req)
			require.Contains(err.Error(), tc.expectedErrContains)
			require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
		})
	}
}

func TestPluginOnCreateSetErr(t *testing.T) {
	cases := []struct {
		name                string
		req                 *pb.OnCreateSetRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		catalogOpts         []awsCatalogPersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
	}{
		{
			name:                "nil catalog",
			req:                 &pb.OnCreateSetRequest{},
			expectedErrContains: "catalog is nil",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil catalog attributes",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErrContains: "catalog missing attributes",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading catalog attributes",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "invalid region",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("foobar"),
							},
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				func(s *awsCatalogPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil set",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			expectedErrContains: "set is nil",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil attributes in set",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{},
			},
			expectedErrContains: "set missing attributes",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "set attribute load error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"foo": structpb.NewBoolValue(true),
								"bar": structpb.NewBoolValue(true),
							},
						},
					},
				},
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "client load error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstDescribeInstancesFilters: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.MockOptionErr(errors.New(testOptionErr)),
				}),
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: error reading options in NewCredentialsConfig: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "DescribeInstances error",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstDescribeInstancesFilters: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesError(errors.New(testDescribeInstancesError)),
				)),
			},
			expectedErrContains: fmt.Sprintf("error performing dry run of DescribeInstances: %s", testDescribeInstancesError),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "DescribeInstances non-error array filter",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstDescribeInstancesFilters: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
				)),
			},
			expectedErrContains: "query error: DescribeInstances DryRun should have returned error, but none was found",
			expectedErrCode:     codes.FailedPrecondition,
		},
		{
			name: "DescribeInstances non-error string filter",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstDescribeInstancesFilters: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
				)),
			},
			expectedErrContains: "query error: DescribeInstances DryRun should have returned error, but none was found",
			expectedErrCode:     codes.FailedPrecondition,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &HostPlugin{
				testCredStateOpts:    tc.credOpts,
				testCatalogStateOpts: tc.catalogOpts,
			}
			_, err := p.OnCreateSet(context.Background(), tc.req)
			require.Contains(err.Error(), tc.expectedErrContains)
			require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
		})
	}
}

func TestPluginOnUpdateSetErr(t *testing.T) {
	cases := []struct {
		name                string
		req                 *pb.OnUpdateSetRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		catalogOpts         []awsCatalogPersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
	}{
		{
			name:                "nil catalog",
			req:                 &pb.OnUpdateSetRequest{},
			expectedErrContains: "catalog is nil",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil catalog attributes",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErrContains: "catalog missing attributes",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "catalog attribute load error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErrContains: "missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "invalid region",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("foobar"),
							},
						},
					},
				},
			},
			expectedErrContains: "not a valid region: foobar",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				func(s *awsCatalogPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil set",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			expectedErrContains: "new set is nil",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil attributes in set",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{},
			},
			expectedErrContains: "new set missing attributes",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "set attribute load error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"foo": structpb.NewBoolValue(true),
								"bar": structpb.NewBoolValue(true),
							},
						},
					},
				},
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "client load error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstDescribeInstancesFilters: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.MockOptionErr(errors.New(testOptionErr)),
				}),
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: error reading options in NewCredentialsConfig: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "DescribeInstances error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstDescribeInstancesFilters: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesError(errors.New(testDescribeInstancesError)),
				)),
			},
			expectedErrContains: fmt.Sprintf("error performing dry run of DescribeInstances: %s", testDescribeInstancesError),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "DescribeInstances non-error",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstDescribeInstancesFilters: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
				)),
			},
			expectedErrContains: "query error: DescribeInstances DryRun should have returned error, but none was found",
			expectedErrCode:     codes.FailedPrecondition,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &HostPlugin{
				testCredStateOpts:    tc.credOpts,
				testCatalogStateOpts: tc.catalogOpts,
			}
			_, err := p.OnUpdateSet(context.Background(), tc.req)
			require.Contains(err.Error(), tc.expectedErrContains)
			require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
		})
	}
}

func TestPluginListHostsErr(t *testing.T) {
	cases := []struct {
		name                string
		req                 *pb.ListHostsRequest
		credOpts            []credential.AwsCredentialPersistedStateOption
		catalogOpts         []awsCatalogPersistedStateOption
		expectedErrContains string
		expectedErrCode     codes.Code
	}{
		{
			name:                "nil catalog",
			req:                 &pb.ListHostsRequest{},
			expectedErrContains: "catalog is nil",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil catalog attributes",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
				},
			},
			expectedErrContains: "catalog missing attributes",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "error reading catalog attributes",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErrContains: "attributes.region: missing required value \"region\"",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "invalid region",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("foobar"),
							},
						},
					},
				},
			},
			expectedErrContains: "not a valid region: ",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				func(s *awsCatalogPersistedState) error {
					return errors.New(testOptionErr)
				},
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "nil sets",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			expectedErrContains: "sets is nil",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "set missing id",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Sets: []*hostsets.HostSet{{}},
			},
			expectedErrContains: "set missing id",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "set missing attributes",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "foobar",
					},
				},
			},
			expectedErrContains: "set missing attributes",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "set attribute load error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "foobar",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"foo": structpb.NewBoolValue(true),
									"bar": structpb.NewBoolValue(true),
								},
							},
						},
					},
				},
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "client load error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "foobar",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									ConstDescribeInstancesFilters: structpb.NewListValue(
										&structpb.ListValue{
											Values: []*structpb.Value{
												structpb.NewStringValue("tag-key=foo"),
											},
										},
									),
								},
							},
						},
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.MockOptionErr(errors.New(testOptionErr)),
				}),
			},
			expectedErrContains: fmt.Sprintf("error loading persisted state: error reading options in NewCredentialsConfig: %s", testOptionErr),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "DescribeInstances error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "foobar",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									ConstDescribeInstancesFilters: structpb.NewListValue(
										&structpb.ListValue{
											Values: []*structpb.Value{
												structpb.NewStringValue("tag-key=foo"),
											},
										},
									),
								},
							},
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesError(errors.New(testDescribeInstancesError)),
				)),
			},
			expectedErrContains: fmt.Sprintf("error running DescribeInstances for host set id \"foobar\": %s", testDescribeInstancesError),
			expectedErrCode:     codes.InvalidArgument,
		},
		{
			name: "awsInstanceToHost error",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								credential.ConstRegion: structpb.NewStringValue("us-west-2"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:          structpb.NewStringValue("AKIA_foobar"),
							credential.ConstSecretAccessKey:      structpb.NewStringValue("bazqux"),
							credential.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "foobar",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									ConstDescribeInstancesFilters: structpb.NewListValue(
										&structpb.ListValue{
											Values: []*structpb.Value{
												structpb.NewStringValue("tag-key=foo"),
											},
										},
									),
								},
							},
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesOutput(
						&ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											// Blank so we error out
										},
									},
								},
							},
						},
					),
				)),
			},
			expectedErrContains: "error processing host results for host set id \"foobar\": response integrity error: missing instance id",
			expectedErrCode:     codes.InvalidArgument,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			p := &HostPlugin{
				testCredStateOpts:    tc.credOpts,
				testCatalogStateOpts: tc.catalogOpts,
			}
			_, err := p.ListHosts(context.Background(), tc.req)
			require.Contains(err.Error(), tc.expectedErrContains)
			require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
		})
	}
}

func TestBuildFilters(t *testing.T) {
	cases := []struct {
		name                string
		in                  map[string]any
		expected            []types.Filter
		expectedErrContains string
	}{
		{
			name: "good without instance-state-name",
			in: map[string]any{
				ConstDescribeInstancesFilters: []any{"foo=bar"},
			},
			expected: []types.Filter{
				{
					Name:   aws.String("foo"),
					Values: []string{"bar"},
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: []string{string(types.InstanceStateNameRunning)},
				},
			},
		},
		{
			name: "good with instance-state-name",
			in: map[string]any{
				ConstDescribeInstancesFilters: []any{
					"foo=bar",
					"instance-state-name=static",
				},
			},
			expected: []types.Filter{
				{
					Name:   aws.String("foo"),
					Values: []string{"bar"},
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: []string{"static"},
				},
			},
		},
		{
			name: "good with multiple values",
			in: map[string]any{
				ConstDescribeInstancesFilters: []any{
					"foo=bar,baz",
				},
			},
			expected: []types.Filter{
				{
					Name:   aws.String("foo"),
					Values: []string{"bar", "baz"},
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: []string{string(types.InstanceStateNameRunning)},
				},
			},
		},
		{
			name: "empty filter set",
			in: map[string]any{
				ConstDescribeInstancesFilters: []any{},
			},
			expected: []types.Filter{
				{
					Name:   aws.String("instance-state-name"),
					Values: []string{string(types.InstanceStateNameRunning)},
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

			attrs, err := getSetAttributes(input)
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
		in          map[string]any
		dryRun      bool
		expected    *ec2.DescribeInstancesInput
		expectedErr string
	}{
		{
			name: "good, dry run",
			in: map[string]any{
				ConstDescribeInstancesFilters: []any{
					"foo=bar",
				},
			},
			dryRun: true,
			expected: &ec2.DescribeInstancesInput{
				DryRun: aws.Bool(true),
				Filters: []types.Filter{
					{
						Name:   aws.String("foo"),
						Values: []string{"bar"},
					},
					{
						Name:   aws.String("instance-state-name"),
						Values: []string{string(types.InstanceStateNameRunning)},
					},
				},
			},
		},
		{
			name: "good, real run",
			in: map[string]any{
				ConstDescribeInstancesFilters: []any{
					"foo=bar",
				},
			},
			dryRun: false,
			expected: &ec2.DescribeInstancesInput{
				DryRun: aws.Bool(false),
				Filters: []types.Filter{
					{
						Name:   aws.String("foo"),
						Values: []string{"bar"},
					},
					{
						Name:   aws.String("instance-state-name"),
						Values: []string{string(types.InstanceStateNameRunning)},
					},
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

			attrs, err := getSetAttributes(input)
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
		instance    types.Instance
		expected    *pb.ListHostsResponseHost
		expectedErr string
	}{
		{
			name:        "missing instance id",
			instance:    types.Instance{},
			expectedErr: "response integrity error: missing instance id",
		},
		{
			name: "good, single IP w/public addr",
			instance: types.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []types.InstanceNetworkInterface{
					{
						PrivateIpAddress: aws.String("10.0.0.1"),
						PrivateDnsName:   aws.String("test.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								Association: &types.InstanceNetworkInterfaceAssociation{
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
			instance: types.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				NetworkInterfaces: []types.InstanceNetworkInterface{
					{
						PrivateIpAddress: aws.String("10.0.0.1"),
						PrivateDnsName:   aws.String("test.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
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
			instance: types.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []types.InstanceNetworkInterface{
					{
						PrivateIpAddress: aws.String("10.0.0.2"),
						PrivateDnsName:   aws.String("test2.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								PrivateIpAddress: aws.String("10.0.0.2"),
								PrivateDnsName:   aws.String("test2.example.internal"),
							},
						},
					},
					{
						PrivateIpAddress: aws.String("10.0.0.1"),
						PrivateDnsName:   aws.String("test.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								Association: &types.InstanceNetworkInterfaceAssociation{
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
			instance: types.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []types.InstanceNetworkInterface{
					{
						PrivateIpAddress: aws.String("10.0.0.2"),
						PrivateDnsName:   aws.String("test2.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								Association: &types.InstanceNetworkInterfaceAssociation{
									PublicIp:      aws.String("1.1.1.2"),
									PublicDnsName: aws.String("test2.example.com"),
								},
								PrivateIpAddress: aws.String("10.0.0.2"),
								PrivateDnsName:   aws.String("test2.example.internal"),
							},
						},
					},
					{
						PrivateIpAddress: aws.String("10.0.0.1"),
						PrivateDnsName:   aws.String("test.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								Association: &types.InstanceNetworkInterfaceAssociation{
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
			instance: types.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []types.InstanceNetworkInterface{
					{
						PrivateIpAddress: aws.String("10.0.0.1"),
						PrivateDnsName:   aws.String("test.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								Association: &types.InstanceNetworkInterfaceAssociation{
									PublicIp:      aws.String("1.1.1.1"),
									PublicDnsName: aws.String("test.example.com"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
								PrivateDnsName:   aws.String("test.example.internal"),
							},
							{
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
			instance: types.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				NetworkInterfaces: []types.InstanceNetworkInterface{
					{
						PrivateIpAddress: aws.String("10.0.0.1"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								Association: &types.InstanceNetworkInterfaceAssociation{
									PublicIp: aws.String("1.1.1.1"),
								},
								PrivateIpAddress: aws.String("10.0.0.1"),
							},
						},
						Ipv6Addresses: []types.InstanceIpv6Address{
							{Ipv6Address: nil}, // Just coverage for nil assertion which is skipped
							{Ipv6Address: aws.String("some::fake::address")},
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
		{
			name: "good, single IP w/public addr and external name",
			instance: types.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				Tags: []types.Tag{
					{Key: aws.String("Name"), Value: aws.String("test-instance-actual-name")}, // The tag name is "Name", not "name".
					{Key: aws.String("name"), Value: aws.String("test-instance-fake-name")},
					{Key: aws.String("contains-Name"), Value: aws.String("test-instance-contains-name")},
				},
				NetworkInterfaces: []types.InstanceNetworkInterface{
					{
						PrivateIpAddress: aws.String("10.0.0.1"),
						PrivateDnsName:   aws.String("test.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								Association: &types.InstanceNetworkInterfaceAssociation{
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
				ExternalId:   "foobar",
				ExternalName: "test-instance-actual-name",
				IpAddresses:  []string{"10.0.0.1", "1.1.1.1"},
				DnsNames:     []string{"test.example.internal", "test.example.com"},
			},
		},
		{
			name: "good, single IP w/public addr and external name",
			instance: types.Instance{
				InstanceId:       aws.String("foobar"),
				PrivateIpAddress: aws.String("10.0.0.1"),
				PrivateDnsName:   aws.String("test.example.internal"),
				PublicIpAddress:  aws.String("1.1.1.1"),
				PublicDnsName:    aws.String("test.example.com"),
				Tags: []types.Tag{
					{Key: aws.String("Name"), Value: aws.String("test-instance-actual-name")}, // The tag name is "Name", not "name".
					{Key: aws.String("name"), Value: aws.String("test-instance-fake-name")},
					{Key: aws.String("contains-Name"), Value: aws.String("test-instance-contains-name")},
				},
				NetworkInterfaces: []types.InstanceNetworkInterface{
					{
						PrivateIpAddress: aws.String("10.0.0.1"),
						PrivateDnsName:   aws.String("test.example.internal"),
						PrivateIpAddresses: []types.InstancePrivateIpAddress{
							{
								Association: &types.InstanceNetworkInterfaceAssociation{
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
				ExternalId:   "foobar",
				ExternalName: "test-instance-actual-name",
				IpAddresses:  []string{"10.0.0.1", "1.1.1.1"},
				DnsNames:     []string{"test.example.internal", "test.example.com"},
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

func TestAppendDistinct(t *testing.T) {
	cases := []struct {
		name     string
		slice    []string
		elems    []*string
		expected []string
	}{
		{
			name:     "empty slice, empty elems",
			slice:    []string{},
			elems:    []*string{},
			expected: []string{},
		},
		{
			name:     "empty elems",
			slice:    []string{"bar"},
			elems:    []*string{},
			expected: []string{"bar"},
		},
		{
			name:     "skip nil elem",
			slice:    []string{"bar"},
			elems:    []*string{nil},
			expected: []string{"bar"},
		},
		{
			name:     "skip empty elem",
			slice:    []string{"bar"},
			elems:    []*string{aws.String("")},
			expected: []string{"bar"},
		},
		{
			name:  "skip duplicate elem",
			slice: []string{"bar"},
			elems: []*string{
				aws.String("bar"),
				aws.String("foo"),
				aws.String("foo"),
			},
			expected: []string{"bar", "foo"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual := appendDistinct(tc.slice, tc.elems...)
			require.ElementsMatch(actual, tc.expected)
		})
	}
}
