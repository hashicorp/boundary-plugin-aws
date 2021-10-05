package plugin

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
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

func (m *testMockIAM) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	m.State.DeleteAccessKeyCalled = true
	return m.IAMAPI.DeleteAccessKey(input)
}
