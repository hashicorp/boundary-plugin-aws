// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package testing

// This file contains table-driven test infrastructure for AssumeRole and
// cross-role (two-hop) Dynamic Host Catalog scenarios. Each plugin operation
// has a corresponding case type and runner function. The orchestrator in
// e2e_host_test.go populates the case tables using the Terraform outputs.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary-plugin-aws/plugin/service/host"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// ---------------------------------------------------------------------------
// Attr builders
// ---------------------------------------------------------------------------

// roleArnAttrs builds catalog attributes for a single-hop AssumeRole catalog.
func roleArnAttrs(region, roleArn string) map[string]any {
	return map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: true,
		credential.ConstRoleArn:                   roleArn,
	}
}

// crossRoleAttrs builds catalog attributes for a two-hop cross-role catalog.
func crossRoleAttrs(region, principalRoleArn, targetRoleArn string) map[string]any {
	return map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: true,
		credential.ConstRoleArn:                   principalRoleArn,
		credential.ConstTargetRoleArn:             targetRoleArn,
	}
}

// tagFilterSetAttrs builds set attributes with a single tag-key filter.
func tagFilterSetAttrs(tags []string) map[string]any {
	return map[string]any{
		host.ConstDescribeInstancesFilters: []any{fmt.Sprintf("tag-key=%s", strings.Join(tags, ","))},
	}
}

// ---------------------------------------------------------------------------
// Table-driven runners
// ---------------------------------------------------------------------------

type onCreateCatalogCase struct {
	name         string
	catalogAttrs map[string]any
	wantErr      string // empty = expect success with empty persisted secrets
}

func testOnCreateCatalogCases(ctx context.Context, t *testing.T, p *host.HostPlugin, cases []onCreateCatalogCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			require := require.New(t)
			attrs, err := structpb.NewStruct(tc.catalogAttrs)
			require.NoError(err)
			resp, err := p.OnCreateCatalog(ctx, &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{Attributes: attrs},
				},
			})
			if tc.wantErr != "" {
				require.Error(err)
				st, ok := status.FromError(err)
				require.True(ok)
				require.Contains(st.Message(), tc.wantErr)
				return
			}
			require.NoError(err)
			require.NotNil(resp)
			// Dynamic credentials are never stored — persisted secrets should be empty.
			require.Empty(resp.GetPersisted().GetSecrets().GetFields())
		})
	}
}

type onUpdateCatalogCase struct {
	name         string
	catalogAttrs map[string]any // used for both current and new when currentAttrs/newAttrs are nil
	currentAttrs map[string]any // optional: override current catalog attrs
	newAttrs     map[string]any // optional: override new catalog attrs
	wantErr      string
}

func testOnUpdateCatalogCases(ctx context.Context, t *testing.T, p *host.HostPlugin, cases []onUpdateCatalogCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			require := require.New(t)
			currentRaw := tc.catalogAttrs
			if tc.currentAttrs != nil {
				currentRaw = tc.currentAttrs
			}
			newRaw := tc.catalogAttrs
			if tc.newAttrs != nil {
				newRaw = tc.newAttrs
			}
			currentAttrs, err := structpb.NewStruct(currentRaw)
			require.NoError(err)
			newAttrs, err := structpb.NewStruct(newRaw)
			require.NoError(err)
			resp, err := p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{
				CurrentCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{Attributes: currentAttrs},
				},
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{Attributes: newAttrs},
				},
				Persisted: &pb.HostCatalogPersisted{},
			})
			if tc.wantErr != "" {
				require.Error(err)
				st, ok := status.FromError(err)
				require.True(ok)
				require.Contains(st.Message(), tc.wantErr)
				return
			}
			require.NoError(err)
			require.NotNil(resp)
			// Dynamic credentials are never stored — persisted secrets should be empty.
			require.Empty(resp.GetPersisted().GetSecrets().GetFields())
		})
	}
}

type onSetCase struct {
	name         string
	catalogAttrs map[string]any
	tags         []string // nil = no filter (empty set attrs)
	wantErr      string
}

func testOnCreateSetCases(ctx context.Context, t *testing.T, p *host.HostPlugin, cases []onSetCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			require := require.New(t)
			catalogAttrs, err := structpb.NewStruct(tc.catalogAttrs)
			require.NoError(err)
			setRaw := map[string]any{host.ConstDescribeInstancesFilters: []any{}}
			if len(tc.tags) > 0 {
				setRaw = tagFilterSetAttrs(tc.tags)
			}
			setAttrs, err := structpb.NewStruct(setRaw)
			require.NoError(err)
			resp, err := p.OnCreateSet(ctx, &pb.OnCreateSetRequest{
				Catalog:   &hostcatalogs.HostCatalog{Attrs: &hostcatalogs.HostCatalog_Attributes{Attributes: catalogAttrs}},
				Set:       &hostsets.HostSet{Attrs: &hostsets.HostSet_Attributes{Attributes: setAttrs}},
				Persisted: &pb.HostCatalogPersisted{},
			})
			if tc.wantErr != "" {
				require.Error(err)
				st, ok := status.FromError(err)
				require.True(ok)
				require.Contains(st.Message(), tc.wantErr)
				return
			}
			require.NoError(err)
			require.NotNil(resp)
		})
	}
}

func testOnUpdateSetCases(ctx context.Context, t *testing.T, p *host.HostPlugin, cases []onSetCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			require := require.New(t)
			catalogAttrs, err := structpb.NewStruct(tc.catalogAttrs)
			require.NoError(err)
			setRaw := map[string]any{host.ConstDescribeInstancesFilters: []any{}}
			if len(tc.tags) > 0 {
				setRaw = tagFilterSetAttrs(tc.tags)
			}
			setAttrs, err := structpb.NewStruct(setRaw)
			require.NoError(err)
			set := &hostsets.HostSet{Attrs: &hostsets.HostSet_Attributes{Attributes: setAttrs}}
			resp, err := p.OnUpdateSet(ctx, &pb.OnUpdateSetRequest{
				Catalog:    &hostcatalogs.HostCatalog{Attrs: &hostcatalogs.HostCatalog_Attributes{Attributes: catalogAttrs}},
				CurrentSet: set,
				NewSet:     set,
				Persisted:  &pb.HostCatalogPersisted{},
			})
			if tc.wantErr != "" {
				require.Error(err)
				st, ok := status.FromError(err)
				require.True(ok)
				require.Contains(st.Message(), tc.wantErr)
				return
			}
			require.NoError(err)
			require.NotNil(resp)
		})
	}
}

type listHostsCase struct {
	name         string
	catalogAttrs map[string]any
	tags         []string
	expected     map[string][]string // nil = don't assert instances (error cases)
	wantErr      string
}

func testListHostsCases(ctx context.Context, t *testing.T, p *host.HostPlugin, cases []listHostsCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			require := require.New(t)
			catalogAttrs, err := structpb.NewStruct(tc.catalogAttrs)
			require.NoError(err)
			sets := make([]*hostsets.HostSet, len(tc.tags))
			for i, tag := range tc.tags {
				setAttrs, err := structpb.NewStruct(map[string]any{
					host.ConstDescribeInstancesFilters: []any{fmt.Sprintf("tag-key=%s", tag)},
				})
				require.NoError(err)
				sets[i] = &hostsets.HostSet{
					Id:    fmt.Sprintf("hostset-%d", i),
					Attrs: &hostsets.HostSet_Attributes{Attributes: setAttrs},
				}
			}
			resp, err := p.ListHosts(ctx, &pb.ListHostsRequest{
				Catalog:   &hostcatalogs.HostCatalog{Attrs: &hostcatalogs.HostCatalog_Attributes{Attributes: catalogAttrs}},
				Sets:      sets,
				Persisted: &pb.HostCatalogPersisted{},
			})
			if tc.wantErr != "" {
				require.Error(err)
				st, ok := status.FromError(err)
				require.True(ok)
				require.Contains(st.Message(), tc.wantErr)
				return
			}
			require.NoError(err)
			require.NotNil(resp)
			expectedInstances := make(map[string][]string)
			for i, tag := range tc.tags {
				for _, instanceId := range tc.expected[tag] {
					expectedInstances[instanceId] = append(expectedInstances[instanceId], fmt.Sprintf("hostset-%d", i))
				}
			}
			actualInstances := make(map[string][]string)
			for _, h := range resp.GetHosts() {
				actualInstances[h.ExternalId] = h.SetIds
			}
			require.Equal(expectedInstances, actualInstances)
			t.Logf("success: %d hosts matched", len(actualInstances))
		})
	}
}
