// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTestTerraformer(t *testing.T) {
	require := require.New(t)

	tf, err := NewTestTerraformer("testdata")
	require.NoError(err)
	require.NotNil(tf)
	require.Nil(tf.state)

	err = tf.Deploy()
	require.NoError(err)
	require.NotNil(tf.state)

	data, err := tf.GetOutput("random_id_decimal")
	require.NoError(err)
	dataStr, ok := data.(string)
	require.True(ok)
	require.True(strings.HasPrefix(dataStr, "test-foo"))
	dataInt, err := strconv.Atoi(strings.TrimPrefix(dataStr, "test-foo"))
	require.NoError(err)
	require.NotZero(dataInt)

	err = tf.Destroy()
	require.NoError(err)
	require.Nil(tf.state)
}
