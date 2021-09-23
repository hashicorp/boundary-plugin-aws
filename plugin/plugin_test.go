package plugin

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	pluginTesting "github.com/hashicorp/boundary-host-plugin-aws/testing"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

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

	err = tf.Deploy()
	require.NoError(err)

	defer func() {
		if err := tf.Destroy(); err != nil {
			t.Logf("WARNING: could not run Terraform destroy: %s", err)
		}
	}()

	iamUserName, err := tf.GetOutputString("iam_user_name")
	require.NoError(err)
	require.NotZero(iamUserName)

	iamUserArn, err := tf.GetOutputString("iam_user_arn")
	require.NoError(err)
	require.NotZero(iamUserArn)

	iamAccessKeyId, err := tf.GetOutputString("iam_access_key_id")
	require.NoError(err)
	require.NotZero(iamAccessKeyId)

	iamSecretAccessKey, err := tf.GetOutputString("iam_secret_access_key")
	require.NoError(err)
	require.NotZero(iamSecretAccessKey)

	ec2InstanceIds, err := tf.GetOutputSlice("instance_ids")
	require.NoError(err)
	require.Len(ec2InstanceIds, 5)

	ec2InstanceAddrs, err := tf.GetOutputMap("instance_addrs")
	require.NoError(err)
	require.Len(ec2InstanceAddrs, 5)

	ec2InstanceTags, err := tf.GetOutputMap("instance_tags")
	require.NoError(err)
	require.Len(ec2InstanceTags, 5)

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
	// Test rotation first.
	iamAccessKeyId, iamSecretAccessKey = testPluginOnCreateCatalog(ctx, t, p, region, iamAccessKeyId, iamSecretAccessKey, true)
	// Test non-rotation next.
	iamAccessKeyId, iamSecretAccessKey = testPluginOnCreateCatalog(ctx, t, p, region, iamAccessKeyId, iamSecretAccessKey, false)

	// ********************
	// * OnUpdateCatalog
	// ********************
	//
	// Test no-op non-rotation.
	iamAccessKeyId, iamSecretAccessKey = testPluginOnCreateCatalog(ctx, t, p, region, iamAccessKeyId, iamSecretAccessKey, "", "", false, false)
	// Switch to rotation.
	iamAccessKeyId, iamSecretAccessKey = testPluginOnCreateCatalog(ctx, t, p, region, iamAccessKeyId, iamSecretAccessKey, "", "", false, true)
	// Test no-op with rotation.
	iamAccessKeyId, iamSecretAccessKey = testPluginOnCreateCatalog(ctx, t, p, region, iamAccessKeyId, iamSecretAccessKey, "", "", true, true)
	// Switch credentials to other user.
}

func testPluginOnCreateCatalog(ctx context.Context, t *testing.T, p *AwsPlugin, region, accessKeyId, secretAccessKey string, rotate bool) (string, string) {
	t.Helper()
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
	persistedDataMap := persistedData.AsMap()
	require.NotNil(persistedDataMap)
	persistedAccessKeyId, ok := persistedDataMap[constAccessKeyId]
	require.True(ok)
	require.NotZero(persistedAccessKeyId)
	if rotate {
		require.NotEqual(accessKeyId, persistedAccessKeyId)
	} else {
		require.Equal(accessKeyId, persistedAccessKeyId)
	}

	persistedSecretAccessKey, ok := persistedDataMap[constSecretAccessKey]
	require.True(ok)
	require.NotZero(persistedSecretAccessKey)
	if rotate {
		require.NotEqual(secretAccessKey, persistedSecretAccessKey)
	} else {
		require.Equal(secretAccessKey, persistedSecretAccessKey)
	}

	persistedCredsLastRotatedTime, ok := persistedDataMap[constCredsLastRotatedTime]
	require.True(ok)
	if rotate {
		require.NotZero(persistedCredsLastRotatedTime)
	} else {
		require.Zero(persistedCredsLastRotatedTime)
	}

	return persistedAccessKeyId.(string), persistedSecretAccessKey.(string)
}

func testPluginOnUpdateCatalog(
	ctx context.Context, t *testing.T, p *AwsPlugin,
	region, currentAccessKeyId, currentSecretAccessKey, newAccessKeyId, newSecretAccessKey string,
	rotated, rotate bool,
) (string, string) {
	t.Helper()
	require := require.New(t)

	// Take a timestamp of the current time to get a point in time to
	// reference, ensuring that we are updating credential rotation
	// timestamps.
	currentLastRotationTime = time.Now()

	reqCurrentAttrs, err := structpb.NewStruct(map[string]interface{}{
		constRegion:                    region,
		constDisableCredentialRotation: !rotated,
	})
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
	}
	reqPersistedData, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:     currentAccessKeyId,
		constSecretAccessKey: currentSecretAccessKey,
		constCredsLastRotatedTime: func() time.Time {
			if rotated {
				return currentLastRotationTime
			}

			return time.Time{}
		}(),
	})
	require.NoError(err)
	onUpdateCatalogRequest := &pb.OnUpdateCatalogRequest{
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
	response, err := p.OnCreateCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	persistedData := persisted.GetData()
	require.NotNil(persistedData)
	persistedDataMap := persistedData.AsMap()
	require.NotNil(persistedDataMap)

	// Complex checks based on the scenarios.
	persistedAccessKeyId, ok := persistedDataMap[constAccessKeyId]
	require.True(ok)
	require.NotZero(persistedAccessKeyId)
	persistedSecretAccessKey, ok := persistedDataMap[constSecretAccessKey]
	require.True(ok)
	require.NotZero(persistedSecretAccessKey)
	persistedCredsLastRotatedTime, ok := persistedDataMap[constCredsLastRotatedTime]
	require.True(ok)

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
		require.CredentialsInvalid(t, currentAccessKeyId, currentSecretAccessKey)
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
		require.CredentialsInvalid(t, currentAccessKeyId, currentSecretAccessKey)
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
		require.CredentialsValid(t, currentAccessKeyId, currentSecretAccessKey)
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
		require.CredentialsValid(t, currentAccessKeyId, currentSecretAccessKey)
		require.Equal(persistedAccessKeyId, newAccessKeyId)
		require.Equal(persistedSecretAccessKey, newSecretAccessKey)
		require.Zero(persistedCredsLastRotatedTime)

	case newAccessKeyId == "" && rotated && rotate:
		// No new credentials have been provided, but we have previously
		// rotated and are still rotating credentials. This is a no-op.
		// Existing credentials should still be valid and match the ones
		// persisted to state. Rotation time should be identical since
		// no new rotation occurred.
		require.CredentialsValid(t, currentAccessKeyId, currentSecretAccessKey)
		require.Equal(persistedAccessKeyId, currentAccessKeyId)
		require.Equal(persistedSecretAccessKey, currentSecretAccessKey)
		require.NotZero(persistedCredsLastRotatedTime)
		require.Equal(currentCredsLastRotatedTime, persistedCredsLastRotatedTime)

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
		require.CredentialsInvalid(t, currentAccessKeyId, currentSecretAccessKey)
		require.NotEqual(persistedAccessKeyId, currentAccessKeyId)
		require.NotEqual(persistedSecretAccessKey, currentSecretAccessKey)
		require.NotZero(persistedCredsLastRotatedTime)

	case newAccessKeyId == "" && !rotated && !rotate:
		// No new credentials have been provided and we have not, nor do
		// not, plan on rotating the credentials. This is a no-op.
		// Existing credentials should still be valid and match the ones
		// persisted to state. Rotation time should remain at zero.
		require.CredentialsValid(t, currentAccessKeyId, currentSecretAccessKey)
		require.Equal(persistedAccessKeyId, currentAccessKeyId)
		require.Equal(persistedSecretAccessKey, currentSecretAccessKey)
		require.Zero(persistedCredsLastRotatedTime)

	default:
		// Scenario was reached that was not covered by this function.
		require.FailNow("unknown test scenario")
	}

	return persistedAccessKeyId.(string), persistedSecretAccessKey.(string)
}

func requireCredentailsInvalid(t *testing.T, accessKeyId, secretAccessKey string) {
	t.Helper()
	require := require.New(t)

	err := c.GetCallerIdentity()
	require.NotNil(err)
	awsErr, ok := err.(awserr.Error)
	require.True(ok)
	require.Equal("InvalidClientTokenId", awsErr.Code())
}

func requireCredentailsvValid(t *testing.T, accessKeyId, secretAccessKey string) {
	t.Helper()
	require := require.New(t)

	err := c.GetCallerIdentity()
	require.NoError(err)
}
