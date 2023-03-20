package host

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
)

const (
	testOptionErr              = "test option error"
	testGetUserErr             = "test error for GetUser"
	testGetCallerIdentityErr   = "test error for GetCallerIdentity"
	testDeleteAccessKeyErr     = "test error for DeleteAccessKey"
	testDescribeInstancesError = "DescribeInstances error"
)

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

type ec2FilterSorter []*ec2.Filter

func (s ec2FilterSorter) Len() int           { return len(s) }
func (s ec2FilterSorter) Less(i, j int) bool { return *s[i].Name < *s[j].Name }
func (s ec2FilterSorter) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
