package credential

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
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
