// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary-plugin-aws/plugin/service/host"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const expectedEc2InstanceCount = 5

var expectedTags = []string{"foo", "bar", "baz"}

func TestHostPlugin(t *testing.T) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		t.Skip("set AWS_REGION to use this test")
	}
	if envAccessKeyId := os.Getenv("AWS_ACCESS_KEY_ID"); envAccessKeyId == "" {
		t.Skip("set AWS_ACCESS_KEY_ID to use this test")
	}
	if envSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); envSecretAccessKey == "" {
		t.Skip("set AWS_SECRET_ACCESS_KEY to use this test")
	}

	require := require.New(t)
	tf, err := NewTestTerraformer("testdata/host")
	require.NoError(err)
	require.NotNil(tf)

	t.Log("===== deploying test Terraform workspace =====")
	err = tf.Deploy()
	require.NoError(err)

	defer func() {
		t.Log("===== destroying test Terraform workspace =====")
		if err := tf.Destroy(); err != nil {
			t.Logf("WARNING: could not run Terraform destroy: %s", err)
		}
	}()

	iamUserNames, err := tf.GetOutputSlice("iam_user_names")
	require.NoError(err)
	require.Len(iamUserNames, expectedIamUserCount)

	iamUserArns, err := tf.GetOutputSlice("iam_user_arns")
	require.NoError(err)
	require.Len(iamUserArns, expectedIamUserCount)

	iamAccessKeyIds, err := tf.GetOutputSlice("iam_access_key_ids")
	require.NoError(err)
	require.Len(iamAccessKeyIds, expectedIamUserCount)

	iamSecretAccessKeys, err := tf.GetOutputSlice("iam_secret_access_keys")
	require.NoError(err)
	require.Len(iamSecretAccessKeys, expectedIamUserCount)

	ec2InstanceIds, err := tf.GetOutputSlice("instance_ids")
	require.NoError(err)
	require.Len(ec2InstanceIds, expectedEc2InstanceCount)

	ec2InstanceAddrs, err := tf.GetOutputMap("instance_addrs")
	require.NoError(err)
	require.Len(ec2InstanceAddrs, expectedEc2InstanceCount)

	ec2InstanceTags, err := tf.GetOutputMap("instance_tags")
	require.NoError(err)
	require.Len(ec2InstanceTags, expectedEc2InstanceCount)

	// Start the workflow now. Set up the host catalog. Note that this
	// will cause the state to go out of drift above in the sense that
	// the access key ID/secret access key will no longer be valid. We
	// will assert this through the returned state.
	p := new(host.HostPlugin)
	ctx := context.Background()

	// ********************
	// * OnCreateCatalog
	// ********************
	//
	// Test non-rotation (using primary user).
	keyid, secret := testPluginOnCreateCatalog(ctx, t, p, region, iamAccessKeyIds[0].(string), iamSecretAccessKeys[0].(string), false)
	// Test rotation next.
	keyid, secret = testPluginOnCreateCatalog(ctx, t, p, region, keyid, secret, true)

	// ********************
	// * OnUpdateCatalog
	// ********************
	//
	// Test no-op non-rotation.
	keyid, secret = testPluginOnUpdateCatalog(ctx, t, p, region, keyid, secret, "", "", false, false)
	// Switch to rotation.
	keyid, secret = testPluginOnUpdateCatalog(ctx, t, p, region, keyid, secret, "", "", false, true)
	// Test no-op with rotation.
	keyid, secret = testPluginOnUpdateCatalog(ctx, t, p, region, keyid, secret, "", "", true, true)
	// Switch credentials to next user. Don't rotate.
	keyid, secret = testPluginOnUpdateCatalog(ctx, t, p, region, keyid, secret, iamAccessKeyIds[1].(string), iamSecretAccessKeys[1].(string), true, false)
	// Switch credentials to next user. Add rotation.
	keyid, secret = testPluginOnUpdateCatalog(ctx, t, p, region, keyid, secret, iamAccessKeyIds[2].(string), iamSecretAccessKeys[2].(string), false, true)
	// Switch to next user, with rotation disabled.
	keyid, secret = testPluginOnUpdateCatalog(ctx, t, p, region, keyid, secret, iamAccessKeyIds[3].(string), iamSecretAccessKeys[3].(string), true, false)
	// Last case - switch to another user and keep rotation off.
	keyid, secret = testPluginOnUpdateCatalog(ctx, t, p, region, keyid, secret, iamAccessKeyIds[4].(string), iamSecretAccessKeys[4].(string), false, false)

	// ********************
	// * OnDeleteCatalog
	// ********************
	//
	// Test non-rotated.
	testPluginOnDeleteCatalog(ctx, t, p, region, keyid, secret, false)
	// Test as if we had rotated these credentials (note that this
	// makes this test set unusable).
	testPluginOnDeleteCatalog(ctx, t, p, region, keyid, secret, true)

	// ********************
	// * Host set stuff
	// ********************
	// Reassign the keyid and secret first.
	keyid, secret = iamAccessKeyIds[5].(string), iamSecretAccessKeys[5].(string)
	// Process the collection of instances and index by expected tag names.
	expectedTagInstancesMap := make(map[string][]string)
	for instanceId, instanceTags := range ec2InstanceTags {
		for tagKey := range instanceTags.(map[string]any) {
			for _, expectedTag := range expectedTags {
				if tagKey == expectedTag {
					expectedTagInstancesMap[tagKey] = append(expectedTagInstancesMap[tagKey], instanceId)
				}
			}
		}
	}

	cases := [][]string{
		{"foo"},
		{"bar"},
		{"baz"},
		{"foo", "bar"},
		{"foo", "baz"},
		{"bar", "baz"},
		{"foo", "bar", "baz"},
	}

	for _, tc := range cases {
		// Test create/update in one step
		testPluginOnCreateUpdateSet(ctx, t, p, region, keyid, secret, tc)
		// Test ListHosts
		testPluginListHosts(ctx, t, p, region, keyid, secret, tc, expectedTagInstancesMap)
		// TODO: add OnDeleteSet if it needs to be implemented
	}
}

func testPluginOnCreateCatalog(ctx context.Context, t *testing.T, p *host.HostPlugin, region, accessKeyId, secretAccessKey string, rotate bool) (string, string) {
	t.Helper()
	t.Logf("testing OnCreateCatalog (region=%s, rotate=%t)", region, rotate)
	require := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: !rotate,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
	})
	require.NoError(err)
	request := &pb.OnCreateCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: reqAttrs,
			},
			Secrets: reqSecrets,
		},
	}
	response, err := p.OnCreateCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	return validatePersistedSecrets(t, persisted.GetSecrets(), accessKeyId, secretAccessKey, rotate)
}

func testPluginOnUpdateCatalog(
	ctx context.Context, t *testing.T, p *host.HostPlugin,
	region, currentAccessKeyId, currentSecretAccessKey, newAccessKeyId, newSecretAccessKey string,
	rotated, rotate bool,
) (string, string) {
	t.Helper()
	t.Logf("testing OnUpdateCatalog (region=%s, newcreds=%t, rotated=%t, rotate=%t)", region, newAccessKeyId != "" && newSecretAccessKey != "", rotated, rotate)
	require := require.New(t)

	// Take a timestamp of the current time to get a point in time to
	// reference, ensuring that we are updating credential rotation
	// timestamps.
	currentCredsLastRotatedTime := time.Now()

	reqCurrentAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: !rotated,
	})
	require.NoError(err)
	reqNewAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: !rotate,
	})
	require.NoError(err)
	var reqSecrets *structpb.Struct
	if newAccessKeyId != "" && newSecretAccessKey != "" {
		reqSecrets, err = structpb.NewStruct(map[string]any{
			credential.ConstAccessKeyId:     newAccessKeyId,
			credential.ConstSecretAccessKey: newSecretAccessKey,
		})
		require.NoError(err)
	}
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     currentAccessKeyId,
		credential.ConstSecretAccessKey: currentSecretAccessKey,
		credential.ConstCredsLastRotatedTime: func() string {
			if rotated {
				return currentCredsLastRotatedTime.Format(time.RFC3339Nano)
			}

			return (time.Time{}).Format(time.RFC3339Nano)
		}(),
	})
	require.NoError(err)
	require.NotNil(reqPersistedSecrets)
	request := &pb.OnUpdateCatalogRequest{
		CurrentCatalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: reqCurrentAttrs,
			},
		},
		NewCatalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: reqNewAttrs,
			},
			Secrets: reqSecrets,
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	response, err := p.OnUpdateCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	return validateUpdateSecrets(t, persisted.GetSecrets(), currentCredsLastRotatedTime, currentAccessKeyId, currentSecretAccessKey, newAccessKeyId, newSecretAccessKey, rotated, rotate)
}

func testPluginOnDeleteCatalog(ctx context.Context, t *testing.T, p *host.HostPlugin, region, accessKeyId, secretAccessKey string, rotated bool) {
	t.Helper()
	t.Logf("testing OnDeleteCatalog (region=%s, rotated=%t)", region, rotated)
	require := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: !rotated,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
	})
	require.NoError(err)
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:     accessKeyId,
		credential.ConstSecretAccessKey: secretAccessKey,
		credential.ConstCredsLastRotatedTime: func() string {
			if rotated {
				return time.Now().Format(time.RFC3339Nano)
			}

			return (time.Time{}).Format(time.RFC3339Nano)
		}(),
	})
	require.NoError(err)
	request := &pb.OnDeleteCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: reqAttrs,
			},
			Secrets: reqSecrets,
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	response, err := p.OnDeleteCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)

	// We want to test the validity of the credentials post-deletion.
	if rotated {
		// The credentials should no longer be valid.
		requireCredentialsInvalid(t, accessKeyId, secretAccessKey)
	} else {
		// The credentials should still be valid. Sleep 10s first just to
		// be sure, since we're not rotating.
		time.Sleep(time.Second * 10)
		requireCredentialsValid(t, accessKeyId, secretAccessKey)
	}
}

func testPluginOnCreateUpdateSet(ctx context.Context, t *testing.T, p *host.HostPlugin, region, accessKeyId, secretAccessKey string, tags []string) {
	t.Helper()
	t.Logf("testing OnCreateSet (region=%s, tags=%v)", region, tags)
	require := require.New(t)
	catalogAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: true, // Note that this does nothing in sets, but just noting for tests
	})
	require.NoError(err)
	setAttrs, err := structpb.NewStruct(map[string]any{
		host.ConstDescribeInstancesFilters: []any{fmt.Sprintf("tag-key=%s", strings.Join(tags, ","))},
	})
	require.NoError(err)
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:          accessKeyId,
		credential.ConstSecretAccessKey:      secretAccessKey,
		credential.ConstCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
	})
	require.NoError(err)
	createRequest := &pb.OnCreateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: catalogAttrs,
			},
		},
		Set: &hostsets.HostSet{
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: setAttrs,
			},
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	createResponse, err := p.OnCreateSet(ctx, createRequest)
	require.NoError(err)
	require.NotNil(createResponse)

	// Do an update test in the same function, as it's pretty much the
	// same function right now.
	t.Logf("testing OnUpdateSet (region=%s, tags=%v)", region, tags)
	updateRequest := &pb.OnUpdateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: catalogAttrs,
			},
		},
		CurrentSet: &hostsets.HostSet{
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: setAttrs,
			},
		},
		NewSet: &hostsets.HostSet{
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: setAttrs,
			},
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	updateResponse, err := p.OnUpdateSet(ctx, updateRequest)
	require.NoError(err)
	require.NotNil(updateResponse)
}

func testPluginListHosts(ctx context.Context, t *testing.T, p *host.HostPlugin, region, accessKeyId, secretAccessKey string, tags []string, expected map[string][]string) {
	t.Helper()
	t.Logf("testing ListHosts (region=%s, tags=%v)", region, tags)
	require := require.New(t)
	catalogAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstRegion:                    region,
		credential.ConstDisableCredentialRotation: true, // Note that this does nothing in sets, but just noting for tests
	})
	require.NoError(err)
	sets := make([]*hostsets.HostSet, len(tags))
	for i, tag := range tags {
		setAttrs, err := structpb.NewStruct(map[string]any{
			host.ConstDescribeInstancesFilters: []any{fmt.Sprintf("tag-key=%s", tag)},
		})
		require.NoError(err)
		sets[i] = &hostsets.HostSet{
			Id: fmt.Sprintf("hostset-%d", i),
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: setAttrs,
			},
		}
	}
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstAccessKeyId:          accessKeyId,
		credential.ConstSecretAccessKey:      secretAccessKey,
		credential.ConstCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
	})
	require.NoError(err)
	request := &pb.ListHostsRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: catalogAttrs,
			},
		},
		Sets: sets,
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	response, err := p.ListHosts(ctx, request)
	require.NoError(err)
	require.NotNil(response)

	// Validate the returned instances by ID. Assemble the instance
	// details from the expected set.
	expectedInstances := make(map[string][]string)
	for i, tag := range tags {
		for _, instanceId := range expected[tag] {
			expectedInstances[instanceId] = append(expectedInstances[instanceId], fmt.Sprintf("hostset-%d", i))
		}
	}

	// Take the returned hosts by ID and create the same kind of map.
	actualInstances := make(map[string][]string)
	for _, host := range response.GetHosts() {
		actualInstances[host.ExternalId] = host.SetIds
	}

	// Compare
	require.Equal(expectedInstances, actualInstances)
	// Success
	t.Logf("testing ListHosts: success (region=%s, tags=%v, expected/actual=(len=%d, ids=%s))", region, tags, len(actualInstances), actualInstances)
}
