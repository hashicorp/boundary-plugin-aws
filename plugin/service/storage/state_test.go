package storage

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/hashicorp/boundary-plugin-host-aws/internal/credential"
	"github.com/stretchr/testify/require"
)

func TestAwsStoragePersistedStateS3Client(t *testing.T) {
	require := require.New(t)
	cred, err := credential.NewAwsCredentialPersistedState(
		credential.WithRegion("us-west-2"),
		credential.WithAccessKeyId("foobar"),
		credential.WithSecretAccessKey("barfoo"),
	)
	require.NoError(err)

	state, err := newAwsStoragePersistedState(
		withCredentials(cred),
		withTestS3APIFunc(newTestMockS3(nil)),
	)
	require.NoError(err)

	clientRaw, err := state.S3Client(context.Background(), WithRegion("us-west-2"), WithEndpoint("0.0.0.0"))
	require.NoError(err)
	require.NotNil(clientRaw)
	client, ok := clientRaw.(*testMockS3)
	require.True(ok)
	require.NotNil(client)
	require.Equal("us-west-2", client.Region)

	endpoint, err := client.Endpoint.ResolveEndpoint(s3.ServiceID, client.Region)
	require.NoError(err)
	require.Equal("0.0.0.0", endpoint.URL)
	require.Equal("us-west-2", endpoint.SigningRegion)
	require.Equal("aws", endpoint.PartitionID)
}
