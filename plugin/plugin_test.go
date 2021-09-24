package plugin

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	pluginTesting "github.com/hashicorp/boundary-host-plugin-aws/testing"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const expectedIamUserCount = 6
const expectedEc2InstanceCount = 5

var expectedTags = []string{"foo", "bar", "baz"}

func TestPlugin(t *testing.T) {
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
	tf, err := pluginTesting.NewTestTerraformer("testdata/basic")
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
	p := new(AwsPlugin)
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
		for tagKey := range instanceTags.(map[string]interface{}) {
			for _, expectedTag := range expectedTags {
				if tagKey == expectedTag {
					expectedTagInstancesMap[tagKey] = append(expectedTagInstancesMap[tagKey], instanceId)
				}
			}
		}
	}

	cases := [][]string{
		{"foo"},
		{"foo", "bar"},
		{"bar"},
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

func testPluginOnCreateCatalog(ctx context.Context, t *testing.T, p *AwsPlugin, region, accessKeyId, secretAccessKey string, rotate bool) (string, string) {
	t.Helper()
	t.Logf("testing OnCreateCatalog (region=%s, rotate=%t)", region, rotate)
	require := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]interface{}{
		constRegion:                    region,
		constDisableCredentialRotation: !rotate,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:     accessKeyId,
		constSecretAccessKey: secretAccessKey,
	})
	require.NoError(err)
	request := &pb.OnCreateCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: reqAttrs,
			Secrets:    reqSecrets,
		},
	}
	response, err := p.OnCreateCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	persistedData := persisted.GetData()
	require.NotNil(persistedData)
	persistedAccessKeyId, err := getStringValue(persistedData, constAccessKeyId, true)
	require.NoError(err)
	require.NotZero(persistedAccessKeyId)
	if rotate {
		require.NotEqual(accessKeyId, persistedAccessKeyId)
	} else {
		require.Equal(accessKeyId, persistedAccessKeyId)
	}

	persistedSecretAccessKey, err := getStringValue(persistedData, constSecretAccessKey, true)
	require.NoError(err)
	require.NotZero(persistedSecretAccessKey)
	if rotate {
		require.NotEqual(secretAccessKey, persistedSecretAccessKey)
	} else {
		require.Equal(secretAccessKey, persistedSecretAccessKey)
	}

	persistedCredsLastRotatedTime, err := getTimeValue(persistedData, constCredsLastRotatedTime)
	require.NoError(err)
	if rotate {
		require.NotZero(persistedCredsLastRotatedTime)
		requireCredentialsInvalid(t, accessKeyId, secretAccessKey)
	} else {
		require.Zero(persistedCredsLastRotatedTime)
	}

	return persistedAccessKeyId, persistedSecretAccessKey
}

func testPluginOnUpdateCatalog(
	ctx context.Context, t *testing.T, p *AwsPlugin,
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

	reqCurrentAttrs, err := structpb.NewStruct(map[string]interface{}{
		constRegion:                    region,
		constDisableCredentialRotation: !rotated,
	})
	require.NoError(err)
	reqNewAttrs, err := structpb.NewStruct(map[string]interface{}{
		constRegion:                    region,
		constDisableCredentialRotation: !rotate,
	})
	require.NoError(err)
	var reqSecrets *structpb.Struct
	if newAccessKeyId != "" && newSecretAccessKey != "" {
		reqSecrets, err = structpb.NewStruct(map[string]interface{}{
			constAccessKeyId:     newAccessKeyId,
			constSecretAccessKey: newSecretAccessKey,
		})
		require.NoError(err)
	}
	reqPersistedData, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:     currentAccessKeyId,
		constSecretAccessKey: currentSecretAccessKey,
		constCredsLastRotatedTime: func() string {
			if rotated {
				return currentCredsLastRotatedTime.Format(time.RFC3339Nano)
			}

			return (time.Time{}).Format(time.RFC3339Nano)
		}(),
	})
	require.NoError(err)
	require.NotNil(reqPersistedData)
	request := &pb.OnUpdateCatalogRequest{
		CurrentCatalog: &hostcatalogs.HostCatalog{
			Attributes: reqCurrentAttrs,
		},
		NewCatalog: &hostcatalogs.HostCatalog{
			Attributes: reqNewAttrs,
			Secrets:    reqSecrets,
		},
		Persisted: &pb.HostCatalogPersisted{
			Data: reqPersistedData,
		},
	}
	response, err := p.OnUpdateCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	persistedData := persisted.GetData()
	require.NotNil(persistedData)

	// Complex checks based on the scenarios.
	persistedAccessKeyId, err := getStringValue(persistedData, constAccessKeyId, true)
	require.NoError(err)
	require.NotZero(persistedAccessKeyId)
	persistedSecretAccessKey, err := getStringValue(persistedData, constSecretAccessKey, true)
	require.NoError(err)
	require.NotZero(persistedSecretAccessKey)
	persistedCredsLastRotatedTime, err := getTimeValue(persistedData, constCredsLastRotatedTime)
	require.NoError(err)

	// Our test scenarios are complex due the multi-dimensional nature
	// of criteria, so we lay them out in a switch below.
	switch {
	case newAccessKeyId != "" && rotated && rotate:
		// The new access key ID was provided, we had previously rotated
		// the credentials before, and the new credential set is to be
		// rotated as well. In this case, the old credentials should have
		// been deleted, and the new credentials should have been rotated,
		// hence, should not match the new credentials initially
		// provided. Rotation time should be non-zero and updated.
		requireCredentialsInvalid(t, currentAccessKeyId, currentSecretAccessKey)
		require.NotEqual(persistedAccessKeyId, newAccessKeyId)
		require.NotEqual(persistedSecretAccessKey, newSecretAccessKey)
		require.NotZero(persistedCredsLastRotatedTime)
		require.True(persistedCredsLastRotatedTime.After(currentCredsLastRotatedTime))

	case newAccessKeyId != "" && rotated && !rotate:
		// The new access key ID was provided, we had previously rotated
		// the credentials before, and the new credential is *not*
		// rotated. In this case, the old credentials should have
		// been deleted, But the new credentials should have not been
		// rotated, and hence should be the same. Rotation time should be
		// zero.
		requireCredentialsInvalid(t, currentAccessKeyId, currentSecretAccessKey)
		require.Equal(persistedAccessKeyId, newAccessKeyId)
		require.Equal(persistedSecretAccessKey, newSecretAccessKey)
		require.Zero(persistedCredsLastRotatedTime)

	case newAccessKeyId != "" && !rotated && rotate:
		// The new access key ID was provided, we *have not* previously
		// rotated the credentials, and the new credential set is to be
		// rotated. In this case, the old credentials should have been
		// left alone, and the new credentials should have been rotated,
		// hence, should not match the new credentials initially
		// provided. Rotation time should be non-zero, but updated.
		requireCredentialsValid(t, currentAccessKeyId, currentSecretAccessKey)
		require.NotEqual(persistedAccessKeyId, newAccessKeyId)
		require.NotEqual(persistedSecretAccessKey, newSecretAccessKey)
		require.NotZero(persistedCredsLastRotatedTime)
		require.True(persistedCredsLastRotatedTime.After(currentCredsLastRotatedTime))

	case newAccessKeyId != "" && !rotated && !rotate:
		// The new access key ID was provided, but we have not rotated
		// the credentials previously and we still don't plan on rotating
		// them. In this case, the old credentials should still be valid,
		// and the persisted ones should match the new ones provided.
		// Rotation time should be zero.
		requireCredentialsValid(t, currentAccessKeyId, currentSecretAccessKey)
		require.Equal(persistedAccessKeyId, newAccessKeyId)
		require.Equal(persistedSecretAccessKey, newSecretAccessKey)
		require.Zero(persistedCredsLastRotatedTime)

	case newAccessKeyId == "" && rotated && rotate:
		// No new credentials have been provided, but we have previously
		// rotated and are still rotating credentials. This is a no-op.
		// Existing credentials should still be valid and match the ones
		// persisted to state. Rotation time should be identical since
		// no new rotation occurred.
		requireCredentialsValid(t, currentAccessKeyId, currentSecretAccessKey)
		require.Equal(persistedAccessKeyId, currentAccessKeyId)
		require.Equal(persistedSecretAccessKey, currentSecretAccessKey)
		require.NotZero(persistedCredsLastRotatedTime)
		require.True(currentCredsLastRotatedTime.Equal(persistedCredsLastRotatedTime))

	case newAccessKeyId == "" && rotated && !rotate:
		// No new credentials have been provided, and we have previously
		// rotated the credentials. This is actually an error.
		//
		// TODO: validate this scenario through unit testing. For now if
		// we for some reason try to test this with this function, return
		// an error.
		require.FailNow("testing rotated-to-not-rotated scenario not implemented by this helper")

	case newAccessKeyId == "" && !rotated && rotate:
		// No new credentials have been provided, and while we did not
		// rotate before, we want to switch to rotation. In this case,
		// the existing persisted credentials should have been rotated,
		// with a new non-zero timestamp.
		requireCredentialsInvalid(t, currentAccessKeyId, currentSecretAccessKey)
		require.NotEqual(persistedAccessKeyId, currentAccessKeyId)
		require.NotEqual(persistedSecretAccessKey, currentSecretAccessKey)
		require.NotZero(persistedCredsLastRotatedTime)

	case newAccessKeyId == "" && !rotated && !rotate:
		// No new credentials have been provided and we have not, nor do
		// not, plan on rotating the credentials. This is a no-op.
		// Existing credentials should still be valid and match the ones
		// persisted to state. Rotation time should remain at zero.
		requireCredentialsValid(t, currentAccessKeyId, currentSecretAccessKey)
		require.Equal(persistedAccessKeyId, currentAccessKeyId)
		require.Equal(persistedSecretAccessKey, currentSecretAccessKey)
		require.Zero(persistedCredsLastRotatedTime)

	default:
		// Scenario was reached that was not covered by this function.
		require.FailNow("unknown test scenario")
	}

	return persistedAccessKeyId, persistedSecretAccessKey
}

func testPluginOnDeleteCatalog(ctx context.Context, t *testing.T, p *AwsPlugin, region, accessKeyId, secretAccessKey string, rotated bool) {
	t.Helper()
	t.Logf("testing OnDeleteCatalog (region=%s, rotated=%t)", region, rotated)
	require := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]interface{}{
		constRegion:                    region,
		constDisableCredentialRotation: !rotated,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:     accessKeyId,
		constSecretAccessKey: secretAccessKey,
	})
	require.NoError(err)
	reqPersistedData, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:     accessKeyId,
		constSecretAccessKey: secretAccessKey,
		constCredsLastRotatedTime: func() string {
			if rotated {
				return time.Now().Format(time.RFC3339Nano)
			}

			return (time.Time{}).Format(time.RFC3339Nano)
		}(),
	})
	require.NoError(err)
	request := &pb.OnDeleteCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: reqAttrs,
			Secrets:    reqSecrets,
		},
		Persisted: &pb.HostCatalogPersisted{
			Data: reqPersistedData,
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

func testPluginOnCreateUpdateSet(ctx context.Context, t *testing.T, p *AwsPlugin, region, accessKeyId, secretAccessKey string, tags []string) {
	t.Helper()
	t.Logf("testing OnCreateSet (region=%s, tags=%v)", region, tags)
	require := require.New(t)
	catalogAttrs, err := structpb.NewStruct(map[string]interface{}{
		constRegion:                    region,
		constDisableCredentialRotation: true, // Note that this does nothing in sets, but just noting for tests
	})
	require.NoError(err)
	setAttrs, err := structpb.NewStruct(map[string]interface{}{
		constDescribeInstancesFilters: map[string]interface{}{
			"tag-key": func() []interface{} {
				result := make([]interface{}, len(tags))
				for i, tag := range tags {
					result[i] = tag
				}

				return result
			}(),
		},
	})
	require.NoError(err)
	reqPersistedData, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:          accessKeyId,
		constSecretAccessKey:      secretAccessKey,
		constCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
	})
	require.NoError(err)
	createRequest := &pb.OnCreateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: catalogAttrs,
		},
		Set: &hostsets.HostSet{
			Attributes: setAttrs,
		},
		Persisted: &pb.HostCatalogPersisted{
			Data: reqPersistedData,
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
			Attributes: catalogAttrs,
		},
		CurrentSet: &hostsets.HostSet{
			Attributes: setAttrs,
		},
		NewSet: &hostsets.HostSet{
			Attributes: setAttrs,
		},
		Persisted: &pb.HostCatalogPersisted{
			Data: reqPersistedData,
		},
	}
	updateResponse, err := p.OnUpdateSet(ctx, updateRequest)
	require.NoError(err)
	require.NotNil(updateResponse)
}

func testPluginListHosts(ctx context.Context, t *testing.T, p *AwsPlugin, region, accessKeyId, secretAccessKey string, tags []string, expected map[string][]string) {
	t.Helper()
	t.Logf("testing ListHosts (region=%s, tags=%v)", region, tags)
	require := require.New(t)
	catalogAttrs, err := structpb.NewStruct(map[string]interface{}{
		constRegion:                    region,
		constDisableCredentialRotation: true, // Note that this does nothing in sets, but just noting for tests
	})
	require.NoError(err)
	sets := make([]*hostsets.HostSet, len(tags))
	for i, tag := range tags {
		setAttrs, err := structpb.NewStruct(map[string]interface{}{
			constDescribeInstancesFilters: map[string]interface{}{
				"tag-key": []interface{}{tag},
			},
		})
		require.NoError(err)
		sets[i] = &hostsets.HostSet{
			Attributes: setAttrs,
		}
	}
	reqPersistedData, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:          accessKeyId,
		constSecretAccessKey:      secretAccessKey,
		constCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
	})
	require.NoError(err)
	request := &pb.ListHostsRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: catalogAttrs,
		},
		Sets: sets,
		Persisted: &pb.HostCatalogPersisted{
			Data: reqPersistedData,
		},
	}
	response, err := p.ListHosts(ctx, request)
	require.NoError(err)
	require.NotNil(response)

	// Validate the returned instances by ID. Assemble the instance
	// details from the expected set.
	expectedInstances := make(map[string]struct{})
	for _, tag := range tags {
		for _, instanceId := range expected[tag] {
			expectedInstances[instanceId] = struct{}{}
		}
	}

	// Take the returned hosts by ID and create the same kind of map.
	actualInstances := make(map[string]struct{})
	for _, host := range response.GetHosts() {
		actualInstances[host.ExternalId] = struct{}{}
	}

	// Compare
	require.Equal(expectedInstances, actualInstances)
	// Success
	ids := make([]string, len(expectedInstances))
	for k := range expectedInstances {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	t.Logf("testing ListHosts: success (region=%s, tags=%v, expected/actual=(len=%d, ids=%s))", region, tags, len(ids), strings.Join(ids, ","))
}

func requireCredentialsInvalid(t *testing.T, accessKeyId, secretAccessKey string) {
	t.Helper()
	require := require.New(t)

	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(accessKeyId),
		awsutil.WithSecretKey(secretAccessKey),
	)
	require.NoError(err)

	// We need to wait for invalidation as while awsutil waits for
	// credential creation, deletion of the old credentials returns
	// immediately.
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
waitErr:
	for {
		_, err = c.GetCallerIdentity()
		if err != nil {
			break
		}

		select {
		case <-time.After(time.Second):
			// pass

		case <-timeoutCtx.Done():
			break waitErr
		}
	}

	require.NotNil(err)
	awsErr, ok := err.(awserr.Error)
	require.True(ok)
	require.Equal("InvalidClientTokenId", awsErr.Code())
}

func requireCredentialsValid(t *testing.T, accessKeyId, secretAccessKey string) {
	t.Helper()
	require := require.New(t)

	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(accessKeyId),
		awsutil.WithSecretKey(secretAccessKey),
	)
	require.NoError(err)
	_, err = c.GetCallerIdentity()
	require.NoError(err)
}
