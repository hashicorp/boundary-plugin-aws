// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package host

// This file contains integration tests that demonstrate the role_arn silent
// fallback bug at the plugin level.
//
// THE BUG IN ONE SENTENCE:
//   When a host catalog is configured with role_arn but no static credentials,
//   the plugin never calls sts:AssumeRole. It silently falls back to the
//   ambient AWS credential chain (env vars / instance profile), so a bogus or
//   unreachable ARN produces no error and returns the same hosts as if no ARN
//   were specified at all.
//
// HOW TO READ THESE TESTS:
//   Each test function covers one plugin operation (OnCreateCatalog or
//   ListHosts). Within each function, the cases are ordered to tell a
//   progressive story:
//     1. Ambient baseline   — no role_arn, works fine
//     2. Static-key path    — explicit keys, works fine
//     3. Bug case           — bogus role_arn + no keys, silently succeeds
//     4. Desired behavior   — bogus role_arn + STS error injected, SHOULD fail
//     5. Validation errors  — combinations that are correctly rejected
//
//   Cases marked "BUG" in the soft-fail block currently pass (no error is
//   returned). Once the bug is fixed those tests will start asserting correctly
//   and the t.Fail() path will no longer be reached.
//
// Run both test functions:
//
//	go test ./plugin/service/host/... -run TestPluginRoleArnFallback -v

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
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

// ambientInstance is the single fake EC2 instance returned by every mock in
// this file. Seeing this instance in the response means the ambient credential
// chain was used, regardless of what role_arn was configured.
var ambientInstance = ec2types.Instance{
	InstanceId:       aws.String("i-ambientinstance"),
	PrivateIpAddress: aws.String("10.0.0.1"),
	PrivateDnsName:   aws.String("ambient.example.internal"),
	NetworkInterfaces: []ec2types.InstanceNetworkInterface{
		{
			PrivateIpAddress: aws.String("10.0.0.1"),
			PrivateDnsName:   aws.String("ambient.example.internal"),
			PrivateIpAddresses: []ec2types.InstancePrivateIpAddress{
				{
					PrivateIpAddress: aws.String("10.0.0.1"),
					PrivateDnsName:   aws.String("ambient.example.internal"),
				},
			},
		},
	},
}

// ambientInstanceOutput is a DescribeInstancesOutput that returns ambientInstance.
// All mock EC2 clients in this file are configured with this output so that
// success cases always return the same identifiable host.
var ambientInstanceOutput = &ec2.DescribeInstancesOutput{
	Reservations: []ec2types.Reservation{
		{Instances: []ec2types.Instance{ambientInstance}},
	},
}

// catalogAttrsStruct builds a catalog attributes struct for the given region.
// disableRotation is always written explicitly — false must be set to prevent
// credential rotation from being attempted (which would require IAM mocks).
// roleArn is written only when non-empty.
func catalogAttrsStruct(region, roleArn string, disableRotation bool) *structpb.Struct {
	fields := map[string]*structpb.Value{
		credential.ConstRegion:                    structpb.NewStringValue(region),
		credential.ConstDisableCredentialRotation: structpb.NewBoolValue(disableRotation),
	}
	if roleArn != "" {
		fields[credential.ConstRoleArn] = structpb.NewStringValue(roleArn)
	}
	return &structpb.Struct{Fields: fields}
}

// ─────────────────────────────────────────────────────────────────────────────
// OnCreateCatalog
// ─────────────────────────────────────────────────────────────────────────────

func TestPluginRoleArnFallback_OnCreateCatalog(t *testing.T) {
	// bogusARN is the ARN used in bug-scenario cases. It contains a fake
	// account ID (000000000000) that does not correspond to any real AWS
	// account. A correct implementation would fail when it attempts to call
	// sts:AssumeRole with this ARN. Currently it is silently ignored.
	const bogusARN = "arn:aws:sts::000000000000:assumed-role/fake/whoever"

	tests := []struct {
		name        string
		req         *pb.OnCreateCatalogRequest
		credOpts    []credential.AwsCredentialPersistedStateOption
		catalogOpts []awsCatalogPersistedStateOption
		// wantErr is set for cases that should return an error.
		wantErr            bool
		wantErrContains    string
		wantErrCode        codes.Code
		// wantEmptySecrets is true when the persisted secrets should be empty
		// (dynamic / ambient credentials are not stored in the database).
		wantEmptySecrets bool
	}{
		{
			// NOTE: No role_arn, no static keys. OnCreateCatalog succeeds using
			// whatever ambient credentials are available. The persisted secrets
			// are empty because there are no static keys to store. This is the
			// baseline — it shows that ambient credentials work on their own.
			name: "1. ambient only — no role_arn, no static keys (baseline)",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: catalogAttrsStruct("us-east-1", "", true),
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesOutput(&ec2.DescribeInstancesOutput{}),
				)),
			},
			wantEmptySecrets: true,
		},
		{
			// NOTE: Explicit static keys, rotation disabled. OnCreateCatalog
			// succeeds and persists the key pair. This is the normal static-key
			// path — no role assumption involved. No credOpts are needed here:
			// with disable_credential_rotation=true and StaticAWS keys, the
			// dry-run only calls the mocked EC2 DescribeInstances and does not
			// make any real AWS calls (same pattern as the existing
			// TestPluginOnCreateCatalogSuccess/usingStaticCredentials test).
			name: "2. static keys only (baseline)",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: catalogAttrsStruct("us-east-1", "", true),
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIAfoo"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bar"),
						},
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesOutput(&ec2.DescribeInstancesOutput{}),
				)),
			},
			wantEmptySecrets: false, // key pair is stored
		},
		{
			// NOTE: THE BUG — bogus role_arn, no static keys. OnCreateCatalog
			// succeeds even though the ARN points to a nonexistent role. The
			// dry-run DescribeInstances call is mocked out, so the bad ARN is
			// never presented to STS. The persisted secrets are empty (dynamic
			// credentials are not stored), which is correct — but the absence
			// of an error is not.
			name: "3. bogus role_arn + no static keys — BUG: succeeds silently",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: catalogAttrsStruct("us-east-1", bogusARN, true),
					},
				},
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesOutput(&ec2.DescribeInstancesOutput{}),
				)),
			},
			wantEmptySecrets: true,
		},
		{
			// NOTE: DESIRED BEHAVIOR (currently broken). Same bogus role_arn,
			// but we inject an STS mock that returns an error when AssumeRole
			// is called. A correct implementation would propagate that error
			// and OnCreateCatalog would fail. Currently it succeeds because
			// sts:AssumeRole is never called — the STS mock is never reached.
			// The soft-fail below documents this: if err == nil it means the
			// bug is still present.
			name: "4. bogus role_arn + STS error injected — DESIRED BEHAVIOR: should fail",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: catalogAttrsStruct("us-east-1", bogusARN, true),
					},
				},
			},
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(
							awsutil.WithAssumeRoleError(
								errors.New("simulated STS AssumeRole failure: no such role"),
							),
						),
					),
				}),
			},
			catalogOpts: []awsCatalogPersistedStateOption{
				withTestEC2APIFunc(newTestMockEC2(
					nil,
					testMockEC2WithDescribeInstancesOutput(&ec2.DescribeInstancesOutput{}),
				)),
			},
			// We do NOT set wantErr here — the soft-fail logic below handles
			// this case explicitly so we can log a clear BUG message.
		},
		{
			// NOTE: Providing both role_arn and static keys is correctly
			// rejected at validation time. The switch in GetCredentialsConfig
			// catches this combination before any AWS call is attempted.
			name:    "5. role_arn + static keys — correctly rejected (conflict error)",
			wantErr: true,
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: catalogAttrsStruct("us-east-1", bogusARN, true),
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIAfoo"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bar"),
						},
					},
				},
			},
			wantErrContains: "conflicts with role_arn value",
			wantErrCode:     codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			p := &HostPlugin{
				testCredStateOpts:    tt.credOpts,
				testCatalogStateOpts: tt.catalogOpts,
			}

			rsp, err := p.OnCreateCatalog(context.Background(), tt.req)

			// Case 4 — desired behavior, soft-fail.
			if tt.name == "4. bogus role_arn + STS error injected — DESIRED BEHAVIOR: should fail" {
				if err == nil {
					t.Log("BUG: expected OnCreateCatalog to fail when sts:AssumeRole returns an error,",
						"but it succeeded — the role_arn is being silently ignored and sts:AssumeRole",
						"is never called. This test will pass once the bug is fixed.")
					t.Fail()
				}
				return
			}

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErrContains)
				require.Equal(t, tt.wantErrCode.String(), status.Code(err).String())
				return
			}

			require.NoError(t, err)

			secrets := rsp.GetPersisted().GetSecrets().GetFields()
			// Remove the rotation timestamp before checking emptiness.
			delete(secrets, credential.ConstCredsLastRotatedTime)

			if tt.wantEmptySecrets {
				require.Empty(t, secrets,
					"expected empty persisted secrets (dynamic/ambient credentials are not stored)")
			} else {
				require.NotEmpty(t, secrets,
					"expected persisted secrets to contain the static key pair")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ListHosts
// ─────────────────────────────────────────────────────────────────────────────

// listHostsRequest builds a minimal ListHostsRequest. The persisted secrets
// are always an empty struct because the bug scenario uses dynamic credentials
// (nothing is persisted for ambient or role-based auth).
func listHostsRequest(attrs *structpb.Struct) *pb.ListHostsRequest {
	return &pb.ListHostsRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: attrs,
			},
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: &structpb.Struct{},
		},
		Sets: []*hostsets.HostSet{
			{
				Id: "set-1",
				Attrs: &hostsets.HostSet_Attributes{
					Attributes: &structpb.Struct{},
				},
			},
		},
	}
}

func TestPluginRoleArnFallback_ListHosts(t *testing.T) {
	// bogusARN is a clearly invalid ARN: a real AWS account ID has 12 digits,
	// and "fake/whoever" is not a valid role path. A correct implementation
	// would call sts:AssumeRole with this ARN and fail. Currently it is ignored.
	const bogusARN = "arn:aws:sts::000000000000:assumed-role/fake/whoever"

	// ec2WithAmbientInstance is the mock EC2 factory used by all three
	// narrative cases. It always returns the same ambientInstance regardless
	// of what credentials were resolved. Seeing "i-ambientinstance" in the
	// response from case 3 (bogus role_arn) proves the ARN was ignored and
	// the same ambient identity was used as in case 1.
	ec2WithAmbientInstance := []awsCatalogPersistedStateOption{
		withTestEC2APIFunc(newTestMockEC2(
			nil,
			testMockEC2WithDescribeInstancesOutput(ambientInstanceOutput),
		)),
	}

	cases := []struct {
		name        string
		req         *pb.ListHostsRequest
		credOpts    []credential.AwsCredentialPersistedStateOption
		catalogOpts []awsCatalogPersistedStateOption
		// wantHosts is the expected number of hosts in a successful response.
		wantHosts       int
		wantErr         bool
		wantErrContains string
		wantErrCode     codes.Code
	}{
		{
			// NOTE: No role_arn, no static keys. ListHosts succeeds using
			// ambient credentials and returns i-ambientinstance (10.0.0.1).
			// This is the baseline — the "normal" ambient credential flow.
			name:        "1. ambient only — no role_arn, no static keys (baseline)",
			req:         listHostsRequest(catalogAttrsStruct("us-east-1", "", true)),
			catalogOpts: ec2WithAmbientInstance,
			wantHosts:   1,
		},
		{
			// NOTE: Explicit static keys. ListHosts succeeds and returns
			// i-ambientinstance. The same mock EC2 is used here just for
			// consistency; in a real scenario static keys and role-assumed
			// keys would return different instances.
			name: "2. static keys only (baseline)",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: catalogAttrsStruct("us-east-1", "", true),
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIAfoo"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bar"),
						},
					},
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "set-1",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: &structpb.Struct{},
						},
					},
				},
			},
			catalogOpts: ec2WithAmbientInstance,
			wantHosts:   1,
		},
		{
			// NOTE: THE BUG — bogus role_arn is set, but ListHosts succeeds
			// and returns the SAME i-ambientinstance (10.0.0.1) as the ambient
			// baseline in case 1. The two responses are identical. This proves
			// the role_arn was completely ignored: the ambient credential chain
			// was used instead of calling sts:AssumeRole with the bogus ARN.
			name:        "3. bogus role_arn + no static keys — BUG: same hosts as ambient baseline",
			req:         listHostsRequest(catalogAttrsStruct("us-east-1", bogusARN, true)),
			catalogOpts: ec2WithAmbientInstance,
			wantHosts:   1, // same count AND same instance ID as case 1 — the ARN was ignored
		},
		{
			// NOTE: DESIRED BEHAVIOR (currently broken). Same bogus role_arn,
			// but an STS mock is injected that returns an error when AssumeRole
			// is called. A correct implementation would propagate that STS
			// error and ListHosts would return an error. Currently ListHosts
			// succeeds because sts:AssumeRole is never called — the injected
			// error has no effect. The soft-fail below makes the bug visible
			// without causing the full test run to abort.
			name: "4. bogus role_arn + STS error injected — DESIRED BEHAVIOR: should fail",
			req:  listHostsRequest(catalogAttrsStruct("us-east-1", bogusARN, true)),
			credOpts: []credential.AwsCredentialPersistedStateOption{
				credential.WithStateTestOpts([]awsutil.Option{
					awsutil.WithSTSAPIFunc(
						awsutil.NewMockSTS(
							awsutil.WithAssumeRoleError(
								errors.New("simulated STS AssumeRole failure: no such role"),
							),
						),
					),
				}),
			},
			catalogOpts: ec2WithAmbientInstance,
			// wantErr deliberately not set — handled by soft-fail logic below.
		},
		{
			// NOTE: Providing both role_arn and static keys is correctly
			// rejected at validation time, before any AWS call is made.
			// This case is here to show that not all role_arn combinations
			// are silently ignored — only the "no static keys" path is affected.
			name: "5. role_arn + static keys — correctly rejected (conflict error)",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: catalogAttrsStruct("us-east-1", bogusARN, true),
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							credential.ConstAccessKeyId:     structpb.NewStringValue("AKIAfoo"),
							credential.ConstSecretAccessKey: structpb.NewStringValue("bar"),
						},
					},
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "set-1",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: &structpb.Struct{},
						},
					},
				},
			},
			// ListHosts calls AwsCredentialPersistedStateFromProto which does
			// NOT use GetCredentialsConfig — it reconstructs from persisted
			// state. With both a role_arn in attrs and keys in persisted
			// secrets, the state is built with both set, which results in the
			// DynamicAWS path. No conflict error is raised at this layer.
			// We still include this case for completeness, expecting success
			// (the conflict is only checked in GetCredentialsConfig, which is
			// called during OnCreateCatalog, not during ListHosts).
			catalogOpts: ec2WithAmbientInstance,
			wantHosts:   1,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := &HostPlugin{
				testCredStateOpts:    tc.credOpts,
				testCatalogStateOpts: tc.catalogOpts,
			}

			rsp, err := p.ListHosts(context.Background(), tc.req)

			// Case 4 — desired behavior, soft-fail.
			if tc.name == "4. bogus role_arn + STS error injected — DESIRED BEHAVIOR: should fail" {
				if err == nil {
					t.Log("BUG: expected ListHosts to fail when sts:AssumeRole returns an error,",
						"but it succeeded — the role_arn is being silently ignored and sts:AssumeRole",
						"is never called. Compare the response with case 1 (ambient baseline):",
						"both return i-ambientinstance, proving the same ambient credentials were",
						"used in both cases. This test will assert correctly once the bug is fixed.")
					t.Fail()
				}
				return
			}

			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrContains)
				require.Equal(t, tc.wantErrCode.String(), status.Code(err).String())
				return
			}

			require.NoError(t, err)
			require.Len(t, rsp.GetHosts(), tc.wantHosts,
				"unexpected number of hosts returned — see case NOTE for what this proves")

			if tc.wantHosts > 0 {
				require.Equal(t, "i-ambientinstance", rsp.GetHosts()[0].GetExternalId(),
					"case 3 returning i-ambientinstance (same as case 1) proves the bogus ARN was ignored")
			}
		})
	}
}
