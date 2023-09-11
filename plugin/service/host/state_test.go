// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	awsutilv2 "github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/stretchr/testify/require"
)

func TestAwsCatalogPersistedStateEC2Client(t *testing.T) {
	require := require.New(t)
	cred, err := credential.NewAwsCredentialPersistedState(
		credential.WithCredentialsConfig(&awsutilv2.CredentialsConfig{
			Region:    "us-west-2",
			AccessKey: "foobar",
			SecretKey: "barfoo",
		}),
	)
	require.NoError(err)

	state, err := newAwsCatalogPersistedState(
		withCredentials(cred),
		withTestEC2APIFunc(newTestMockEC2(nil)),
	)
	require.NoError(err)

	clientRaw, err := state.EC2Client(context.Background())
	require.NoError(err)
	require.NotNil(clientRaw)
	client, ok := clientRaw.(*testMockEC2)
	require.True(ok)
	require.NotNil(client)
	require.Equal("us-west-2", client.Region)
}
