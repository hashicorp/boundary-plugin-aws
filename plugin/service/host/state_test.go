// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/stretchr/testify/require"
)

func TestAwsCatalogPersistedStateEC2Client(t *testing.T) {
	require := require.New(t)
	cred, err := credential.NewAwsCredentialPersistedState(
		credential.WithRegion("us-west-2"),
		credential.WithAccessKeyId("foobar"),
		credential.WithSecretAccessKey("barfoo"),
	)
	require.NoError(err)

	state, err := newAwsCatalogPersistedState(
		withCredentials(cred),
		withTestEC2APIFunc(newTestMockEC2(nil)),
	)
	require.NoError(err)

	clientRaw, err := state.EC2Client(context.Background(), WithRegion("us-west-2"))
	require.NoError(err)
	require.NotNil(clientRaw)
	client, ok := clientRaw.(*testMockEC2)
	require.True(ok)
	require.NotNil(client)
	require.Equal("us-west-2", client.Region)
}
