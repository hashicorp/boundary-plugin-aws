// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package testing

// This file contains the TestHostPlugin orchestrator. It deploys the Terraform
// workspace, collects outputs, and calls the per-credential-type helper
// functions defined in e2e_host_static_test.go and e2e_host_assumerole_test.go.

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/boundary-plugin-aws/plugin/service/host"
	"github.com/stretchr/testify/require"
)

const (
	envTargetAccessKeyId     = "TARGET_AWS_ACCESS_KEY_ID"
	envTargetSecretAccessKey = "TARGET_AWS_SECRET_ACCESS_KEY"
	envTargetSessionToken    = "TARGET_AWS_SESSION_TOKEN"
	envTargetRegion          = "TARGET_AWS_REGION"
)

const expectedEc2InstanceCount = 5

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

	// Collect cross-account credentials up front so they can be passed as
	// Terraform variables. The cross-account section is skipped (not failed)
	// when these are absent, but we need the values available before Deploy.
	targetAccessKeyId := os.Getenv(envTargetAccessKeyId)
	targetSecretAccessKey := os.Getenv(envTargetSecretAccessKey)
	targetSessionToken := os.Getenv(envTargetSessionToken)
	targetRegion := os.Getenv(envTargetRegion)
	if targetRegion == "" {
		targetRegion = region
	}

	tfVars := map[string]string{}
	if targetAccessKeyId != "" && targetSecretAccessKey != "" {
		tfVars["target_access_key_id"] = targetAccessKeyId
		tfVars["target_secret_access_key"] = targetSecretAccessKey
		tfVars["target_region"] = targetRegion
		if targetSessionToken != "" {
			tfVars["target_session_token"] = targetSessionToken
		}
	}

	tf, err := NewTestTerraformer("testdata/host", tfVars)
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

	rawExpectedTags, err := tf.GetOutputSlice("instance_tag_keys")
	require.NoError(err)
	require.Len(rawExpectedTags, 3)
	expectedTags := make([]string, 0, len(rawExpectedTags))
	for _, rawExpectedTag := range rawExpectedTags {
		expectedTags = append(expectedTags, rawExpectedTag.(string))
	}

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
	expectedTagInstancesMap := buildExpectedTagInstancesMap(ec2InstanceTags, expectedTags)

	requireTagInstancesMatchProvisioned(t, ec2InstanceIds, expectedTagInstancesMap)

	cases := [][]string{
		{expectedTags[0]},
		{expectedTags[1]},
		{expectedTags[2]},
		{expectedTags[0], expectedTags[1]},
		{expectedTags[0], expectedTags[2]},
		{expectedTags[1], expectedTags[2]},
		{expectedTags[0], expectedTags[1], expectedTags[2]},
	}

	for _, tc := range cases {
		// Test create/update in one step
		testPluginOnCreateUpdateSet(ctx, t, p, region, keyid, secret, tc)
		// Test ListHosts
		testPluginListHosts(ctx, t, p, region, keyid, secret, tc, expectedTagInstancesMap)
		// TODO: add OnDeleteSet if it needs to be implemented
	}

	// finally lets test instance_addresses_only catalog attribute correctly syncs only instance addresses
	testInstanceAddressesOnlyListHosts(ctx, t, p, tf, region, keyid, secret)

	// ********************
	// * AssumeRole - Happy Path & Error Cases
	// ********************
	assumeRoleArn, err := tf.GetOutputString("assume_role_arn")
	require.NoError(err)

	noTrustRoleArn, err := tf.GetOutputString("assume_role_no_trust_arn")
	require.NoError(err)

	missingPermRoleArn, err := tf.GetOutputString("assume_role_no_ec2_permission_arn")
	require.NoError(err)

	testOnCreateCatalogCases(ctx, t, p, []onCreateCatalogCase{
		{name: "assume role happy path", catalogAttrs: roleArnAttrs(region, assumeRoleArn)},
		{name: "assume role no trust", catalogAttrs: roleArnAttrs(region, noTrustRoleArn), wantErr: "AccessDenied"},
		{name: "assume role missing ec2 permission", catalogAttrs: roleArnAttrs(region, missingPermRoleArn), wantErr: "UnauthorizedOperation"},
	})
	testOnUpdateCatalogCases(ctx, t, p, []onUpdateCatalogCase{
		{name: "assume role happy path", catalogAttrs: roleArnAttrs(region, assumeRoleArn)},
		{name: "assume role no trust", catalogAttrs: roleArnAttrs(region, noTrustRoleArn), wantErr: "AccessDenied"},
		{name: "assume role missing ec2 permission", currentAttrs: roleArnAttrs(region, assumeRoleArn), newAttrs: roleArnAttrs(region, missingPermRoleArn), wantErr: "UnauthorizedOperation"},
	})
	testOnCreateSetCases(ctx, t, p, []onSetCase{
		{name: "assume role happy path", catalogAttrs: roleArnAttrs(region, assumeRoleArn), tags: cases[0]},
		{name: "assume role no trust", catalogAttrs: roleArnAttrs(region, noTrustRoleArn), wantErr: "AccessDenied"},
		{name: "assume role missing ec2 permission", catalogAttrs: roleArnAttrs(region, missingPermRoleArn), wantErr: "UnauthorizedOperation"},
	})
	testOnUpdateSetCases(ctx, t, p, []onSetCase{
		{name: "assume role happy path", catalogAttrs: roleArnAttrs(region, assumeRoleArn), tags: cases[0]},
		{name: "assume role no trust", catalogAttrs: roleArnAttrs(region, noTrustRoleArn), wantErr: "AccessDenied"},
		{name: "assume role missing ec2 permission", catalogAttrs: roleArnAttrs(region, missingPermRoleArn), wantErr: "UnauthorizedOperation"},
	})
	testListHostsCases(ctx, t, p, []listHostsCase{
		{name: "assume role happy path", catalogAttrs: roleArnAttrs(region, assumeRoleArn), tags: cases[0], expected: expectedTagInstancesMap},
		{name: "assume role no trust", catalogAttrs: roleArnAttrs(region, noTrustRoleArn), tags: cases[0], wantErr: "AccessDenied"},
		{name: "assume role missing ec2 permission", catalogAttrs: roleArnAttrs(region, missingPermRoleArn), tags: cases[0], wantErr: "UnauthorizedOperation"},
	})

	// ********************
	// * Cross-Role AssumeRole - Happy Path & Error Cases
	// ********************
	// These tests exercise the two-hop role chain within a single AWS account.
	// The principal role has no ec2:DescribeInstances; the target role
	// (assume_role) does. The plugin must assume the principal first, then use
	// those credentials to assume the target role before calling DescribeInstances.
	// This validates the plugin's chained credential logic without requiring a
	// second AWS account.
	crossRolePrincipalArn, err := tf.GetOutputString("cross_role_principal_arn")
	require.NoError(err)

	crossRolePrincipalNoTrustArn, err := tf.GetOutputString("cross_role_principal_no_trust_arn")
	require.NoError(err)

	crossRoleTargetNoTrustArn, err := tf.GetOutputString("cross_role_target_no_trust_arn")
	require.NoError(err)

	crossRoleTargetNoEc2PermissionArn, err := tf.GetOutputString("cross_role_target_no_ec2_permission_arn")
	require.NoError(err)

	// assume_role_arn is reused as the cross-role target — it has ec2:DescribeInstances
	// and its trust policy allows the cross-role principal to assume it.
	testOnCreateCatalogCases(ctx, t, p, []onCreateCatalogCase{
		{name: "cross-role happy path", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, assumeRoleArn)},
		{name: "cross-role principal no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalNoTrustArn, assumeRoleArn), wantErr: "AccessDenied"},
		{name: "cross-role target no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoTrustArn), wantErr: "AccessDenied"},
		{name: "cross-role target missing ec2 permission", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoEc2PermissionArn), wantErr: "UnauthorizedOperation"},
	})
	testOnUpdateCatalogCases(ctx, t, p, []onUpdateCatalogCase{
		{name: "cross-role happy path", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, assumeRoleArn)},
		{name: "cross-role principal no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalNoTrustArn, assumeRoleArn), wantErr: "AccessDenied"},
		{name: "cross-role target no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoTrustArn), wantErr: "AccessDenied"},
		{name: "cross-role target missing ec2 permission", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoEc2PermissionArn), wantErr: "UnauthorizedOperation"},
	})
	testOnCreateSetCases(ctx, t, p, []onSetCase{
		{name: "cross-role happy path", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, assumeRoleArn), tags: cases[0]},
		{name: "cross-role principal no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalNoTrustArn, assumeRoleArn), wantErr: "AccessDenied"},
		{name: "cross-role target no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoTrustArn), wantErr: "AccessDenied"},
		{name: "cross-role target missing ec2 permission", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoEc2PermissionArn), wantErr: "UnauthorizedOperation"},
	})
	testOnUpdateSetCases(ctx, t, p, []onSetCase{
		{name: "cross-role happy path", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, assumeRoleArn), tags: cases[0]},
		{name: "cross-role principal no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalNoTrustArn, assumeRoleArn), wantErr: "AccessDenied"},
		{name: "cross-role target no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoTrustArn), wantErr: "AccessDenied"},
		{name: "cross-role target missing ec2 permission", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoEc2PermissionArn), wantErr: "UnauthorizedOperation"},
	})
	testListHostsCases(ctx, t, p, []listHostsCase{
		{name: "cross-role happy path", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, assumeRoleArn), tags: cases[0], expected: expectedTagInstancesMap},
		{name: "cross-role principal no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalNoTrustArn, assumeRoleArn), tags: cases[0], wantErr: "AccessDenied"},
		{name: "cross-role target no trust", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoTrustArn), tags: cases[0], wantErr: "AccessDenied"},
		{name: "cross-role target missing ec2 permission", catalogAttrs: crossRoleAttrs(region, crossRolePrincipalArn, crossRoleTargetNoEc2PermissionArn), tags: cases[0], wantErr: "UnauthorizedOperation"},
	})
	// ********************
	// * Cross-Account AssumeRole - Happy Path & Error Cases
	// ********************
	// These tests require credentials for a second AWS account supplied via
	// TARGET_AWS_ACCESS_KEY_ID, TARGET_AWS_SECRET_ACCESS_KEY, and (for
	// temporary credentials) TARGET_AWS_SESSION_TOKEN. They are skipped
	// (not failed) when the access key ID or secret access key are absent.
	if targetAccessKeyId == "" || targetSecretAccessKey == "" {
		t.Log("skipping cross-account tests: set TARGET_AWS_ACCESS_KEY_ID and TARGET_AWS_SECRET_ACCESS_KEY to enable")
	} else {
		crossAccountPrincipalArn, err := tf.GetOutputString("cross_account_principal_arn")
		require.NoError(err)

		crossAccountPrincipalNoTrustArn, err := tf.GetOutputString("cross_account_principal_no_trust_arn")
		require.NoError(err)

		crossAccountTargetArn, err := tf.GetOutputString("cross_account_target_arn")
		require.NoError(err)

		crossAccountTargetNoTrustArn, err := tf.GetOutputString("cross_account_target_no_trust_arn")
		require.NoError(err)

		crossAccountTargetNoEc2PermissionArn, err := tf.GetOutputString("cross_account_target_no_ec2_permission_arn")
		require.NoError(err)

		targetEc2InstanceIds, err := tf.GetOutputSlice("target_instance_ids")
		require.NoError(err)
		require.Len(targetEc2InstanceIds, expectedEc2InstanceCount)

		targetEc2InstanceTags, err := tf.GetOutputMap("target_instance_tags")
		require.NoError(err)
		expectedTargetTagInstancesMap := buildExpectedTagInstancesMap(targetEc2InstanceTags, expectedTags)

		requireTagInstancesMatchProvisioned(t, targetEc2InstanceIds, expectedTargetTagInstancesMap)

		testOnCreateCatalogCases(ctx, t, p, []onCreateCatalogCase{
			{name: "cross-account happy path", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetArn)},
			{name: "cross-account principal no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalNoTrustArn, crossAccountTargetArn), wantErr: "AccessDenied"},
			{name: "cross-account target no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoTrustArn), wantErr: "AccessDenied"},
			{name: "cross-account target missing ec2 permission", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoEc2PermissionArn), wantErr: "UnauthorizedOperation"},
		})
		testOnUpdateCatalogCases(ctx, t, p, []onUpdateCatalogCase{
			{name: "cross-account happy path", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetArn)},
			{name: "cross-account principal no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalNoTrustArn, crossAccountTargetArn), wantErr: "AccessDenied"},
			{name: "cross-account target no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoTrustArn), wantErr: "AccessDenied"},
			{name: "cross-account target missing ec2 permission", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoEc2PermissionArn), wantErr: "UnauthorizedOperation"},
		})
		testOnCreateSetCases(ctx, t, p, []onSetCase{
			{name: "cross-account happy path", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetArn), tags: cases[0]},
			{name: "cross-account principal no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalNoTrustArn, crossAccountTargetArn), wantErr: "AccessDenied"},
			{name: "cross-account target no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoTrustArn), wantErr: "AccessDenied"},
			{name: "cross-account target missing ec2 permission", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoEc2PermissionArn), wantErr: "UnauthorizedOperation"},
		})
		testOnUpdateSetCases(ctx, t, p, []onSetCase{
			{name: "cross-account happy path", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetArn), tags: cases[0]},
			{name: "cross-account principal no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalNoTrustArn, crossAccountTargetArn), wantErr: "AccessDenied"},
			{name: "cross-account target no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoTrustArn), wantErr: "AccessDenied"},
			{name: "cross-account target missing ec2 permission", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoEc2PermissionArn), wantErr: "UnauthorizedOperation"},
		})
		testListHostsCases(ctx, t, p, []listHostsCase{
			{name: "cross-account happy path", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetArn), tags: cases[0], expected: expectedTargetTagInstancesMap},
			{name: "cross-account principal no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalNoTrustArn, crossAccountTargetArn), tags: cases[0], wantErr: "AccessDenied"},
			{name: "cross-account target no trust", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoTrustArn), tags: cases[0], wantErr: "AccessDenied"},
			{name: "cross-account target missing ec2 permission", catalogAttrs: crossRoleAttrs(targetRegion, crossAccountPrincipalArn, crossAccountTargetNoEc2PermissionArn), tags: cases[0], wantErr: "UnauthorizedOperation"},
		})
	}
}
