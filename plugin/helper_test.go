package plugin

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"google.golang.org/protobuf/types/known/structpb"
)

const testDescribeInstancesError = "DescribeInstances error"

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

type testMockEC2State struct {
	DescribeInstancesCalled      bool
	DescribeInstancesInputParams *ec2.DescribeInstancesInput
}

func (s *testMockEC2State) Reset() {
	s.DescribeInstancesCalled = false
	s.DescribeInstancesInputParams = nil
}

type testMockEC2 struct {
	ec2iface.EC2API

	State                   *testMockEC2State
	Region                  string
	DescribeInstancesOutput *ec2.DescribeInstancesOutput
	DescribeInstancesError  error
}

type testMockEC2Option func(m *testMockEC2) error

func testMockEC2WithDescribeInstancesOutput(o *ec2.DescribeInstancesOutput) testMockEC2Option {
	return func(m *testMockEC2) error {
		m.DescribeInstancesOutput = o
		return nil
	}
}

func testMockEC2WithDescribeInstancesError(e error) testMockEC2Option {
	return func(m *testMockEC2) error {
		m.DescribeInstancesError = e
		return nil
	}
}

func newTestMockEC2(state *testMockEC2State, opts ...testMockEC2Option) ec2APIFunc {
	return func(sess *session.Session, cfgs ...*aws.Config) (ec2iface.EC2API, error) {
		m := &testMockEC2{
			State: state,
		}

		for _, opt := range opts {
			if err := opt(m); err != nil {
				return nil, err
			}
		}

		for _, cfg := range cfgs {
			// Last region takes precedence
			m.Region = *cfg.Region
		}

		return m, nil
	}
}

func (m *testMockEC2) DescribeInstances(input *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
	if m.State != nil {
		m.State.DescribeInstancesCalled = true
		m.State.DescribeInstancesInputParams = input
	}

	if m.DescribeInstancesError != nil {
		return nil, m.DescribeInstancesError
	}

	return m.DescribeInstancesOutput, nil
}

func mustStruct(in map[string]interface{}) *structpb.Struct {
	out, err := structpb.NewStruct(in)
	if err != nil {
		panic(err)
	}

	return out
}
