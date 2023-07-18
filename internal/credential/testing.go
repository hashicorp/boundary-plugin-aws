// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testOptionErr            = "test option error"
	testGetCallerIdentityErr = "test error for GetCallerIdentity"
	testGetUserErr           = "test error for GetUser"
	testDeleteAccessKeyErr   = "test error for DeleteAccessKey"
)

type testMockIAMState struct {
	DeleteAccessKeyCalled bool
}

func (s *testMockIAMState) Reset() {
	s.DeleteAccessKeyCalled = false
}

type testMockIAM struct {
	iamiface.IAMAPI

	State *testMockIAMState
}

func (m *testMockIAM) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	m.State.DeleteAccessKeyCalled = true
	return m.IAMAPI.DeleteAccessKey(input)
}

func newTestMockIAM(state *testMockIAMState, opts ...awsutil.MockIAMOption) awsutil.IAMAPIFunc {
	return func(sess *session.Session) (iamiface.IAMAPI, error) {
		m := &testMockIAM{
			State: state,
		}
		f := awsutil.NewMockIAM(opts...)
		var err error

		m.IAMAPI, err = f(sess)
		return m, err
	}
}

// MockStaticCredentialSecrets returns a *structpb.Struct that contains two
// key pair values: (access_key_id, AKIA_foobar) & (secret_access_key, bazqux)
func MockStaticCredentialSecrets() *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			ConstAccessKeyId:     structpb.NewStringValue("AKIA_foobar"),
			ConstSecretAccessKey: structpb.NewStringValue("bazqux"),
		},
	}
}

// MockAssumeRoleAttributes returns a *structpb.Struct that contains six key pair values:
//
//	(region, region)
//	(disable_credential_rotation, disableRotate)
//	(role_arn, arn:aws:iam::123456789012:role/S3Access)
//	(role_external_id, 1234567890)
//	(role_session_name, ec2-assume-role-provider)
//	(role_tags, struct{foo:bar})
func MockAssumeRoleAttributes(region string, disableRotate bool) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			ConstRegion:                    structpb.NewStringValue(region),
			ConstDisableCredentialRotation: structpb.NewBoolValue(disableRotate),
			ConstRoleArn:                   structpb.NewStringValue("arn:aws:iam::123456789012:role/S3Access"),
			ConstRoleExternalId:            structpb.NewStringValue("1234567890"),
			ConstRoleSessionName:           structpb.NewStringValue("ec2-assume-role-provider"),
			ConstRoleTags: structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			}),
		},
	}
}
