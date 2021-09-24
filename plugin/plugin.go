package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"google.golang.org/protobuf/types/known/structpb"
)

// rotationWaitTimeout controls the time we wait for credential rotation to
// succeed. This is important to ensure that rotated credentials can be used
// right away.
const rotationWaitTimeout = time.Second * 30

// AwsPlugin implements the HostPluginServiceServer interface for the
// AWS plugin.
type AwsPlugin struct {
	pb.UnimplementedHostPluginServiceServer
}

// Ensure that we are implementing HostPluginServiceServer
var (
	_ pb.HostPluginServiceServer = (*AwsPlugin)(nil)
)

func (p *AwsPlugin) OnCreateCatalog(ctx context.Context, req *pb.OnCreateCatalogRequest) (*pb.OnCreateCatalogResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.New("catalog is nil")
	}

	secrets := catalog.GetSecrets()
	if secrets == nil {
		return nil, errors.New("secrets are required")
	}

	attrs := catalog.GetAttributes()
	if secrets == nil {
		return nil, errors.New("attributes are required")
	}

	if _, err := getValidateRegionValue(attrs); err != nil {
		return nil, err
	}

	accessKeyId, err := getStringValue(secrets, constAccessKeyId, true)
	if err != nil {
		return nil, err
	}

	secretAccessKey, err := getStringValue(secrets, constSecretAccessKey, true)
	if err != nil {
		return nil, err
	}

	skipRotate, err := getBoolValue(attrs, constDisableCredentialRotation, false)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	state := &awsCatalogPersistedState{
		AccessKeyId:     accessKeyId,
		SecretAccessKey: secretAccessKey,
	}

	// Try to rotate the credentials if we're not skipping them.
	if !skipRotate {
		if err := state.RotateCreds(); err != nil {
			return nil, fmt.Errorf("error during credential rotation: %w", err)
		}
	} else {
		// Simply validate if we aren't rotating.
		if err := state.ValidateCreds(); err != nil {
			return nil, fmt.Errorf("error during credential validation: %w", err)
		}
	}

	persistedProto, err := state.ToProto()
	if err != nil {
		return nil, err
	}

	return &pb.OnCreateCatalogResponse{
		Persisted: persistedProto,
	}, nil
}

func (p *AwsPlugin) OnUpdateCatalog(ctx context.Context, req *pb.OnUpdateCatalogRequest) (*pb.OnUpdateCatalogResponse, error) {
	// For host catalogs we only need to really validate what is
	// currently in the new copy of the host catalog data, so skip
	// fetching the new copy to keep things a little less messy.
	catalog := req.GetNewCatalog()
	if catalog == nil {
		return nil, errors.New("new catalog is nil")
	}

	var updateSecrets bool
	secrets := catalog.GetSecrets()
	if secrets != nil {
		// We will be updating secrets this run, but what exactly that
		// means will be determined later.
		updateSecrets = true
	}

	attrs := catalog.GetAttributes()
	if attrs == nil {
		return nil, errors.New("new catalog missing attributes")
	}

	// Validate the region.
	if _, err := getValidateRegionValue(attrs); err != nil {
		return nil, err
	}

	// Get the persisted data.
	// NOTE: We might need to change this at a later time. I'm not too
	// sure *exactly* what scenarios we might encounter that would
	// ultimately mean that we would have to handle an empty or missing
	// state in update, but what we are ultimately assuming here
	// (implicitly through awsCatalogPersistedStateFromProto) is that
	// the state will exist and be populated. Personally I think this
	// is fine and important, but this may change in the future.
	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted())
	if err != nil {
		return nil, err
	}

	skipRotate, err := getBoolValue(attrs, constDisableCredentialRotation, false)
	if err != nil {
		return nil, err
	}

	if skipRotate && !updateSecrets {
		// This is a validate check to make sure that we aren't disabling
		// rotation for credentials currently being managed by rotation.
		// This is not allowed.
		if !state.CredsLastRotatedTime.IsZero() {
			return nil, errors.New("cannot disable rotation for already-rotated credentials")
		}
	}

	if updateSecrets {
		accessKeyId, err := getStringValue(secrets, constAccessKeyId, true)
		if err != nil {
			return nil, err
		}

		secretAccessKey, err := getStringValue(secrets, constSecretAccessKey, true)
		if err != nil {
			return nil, err
		}

		// Replace the credentials. This checks the timestamp on the last
		// rotation time as well and deletes the credentials if we are
		// managing them (ie: if we've rotated them before).
		if err := state.ReplaceCreds(accessKeyId, secretAccessKey); err != nil {
			return nil, fmt.Errorf("error attempting to replace credentials: %w", err)
		}
	}

	if !skipRotate && state.CredsLastRotatedTime.IsZero() {
		// If we're enabling rotation now but didn't before, or have
		// freshly replaced credentials, we can rotate here.
		if err := state.RotateCreds(); err != nil {
			return nil, fmt.Errorf("error during credential rotation: %w", err)
		}
	}

	// That's it!
	persistedProto, err := state.ToProto()
	if err != nil {
		return nil, err
	}

	return &pb.OnUpdateCatalogResponse{
		Persisted: persistedProto,
	}, nil
}

func (p *AwsPlugin) OnDeleteCatalog(ctx context.Context, req *pb.OnDeleteCatalogRequest) (*pb.OnDeleteCatalogResponse, error) {
	// Get the persisted data.
	// NOTE: We return on error here, blocking the delete. This may or
	// may not be an overzealous approach to maintaining database/state
	// integrity. May need to be changed at later time if there are
	// scenarios where we might be deleting things and any secret state
	// may be corrupt/and or legitimately missing.
	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted())
	if err != nil {
		return nil, err
	}

	if !state.CredsLastRotatedTime.IsZero() {
		// Delete old/existing credentials. This is done with the same
		// credentials to ensure that it has the proper permissions to do
		// it.
		if err := state.DeleteCreds(); err != nil {
			return nil, err
		}
	}

	return &pb.OnDeleteCatalogResponse{}, nil
}

func (p *AwsPlugin) OnCreateSet(ctx context.Context, req *pb.OnCreateSetRequest) (*pb.OnCreateSetResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.New("catalog is nil")
	}

	catalogAttrs := catalog.GetAttributes()
	if catalogAttrs == nil {
		return nil, errors.New("catalog missing attributes")
	}

	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted())
	if err != nil {
		return nil, err
	}

	// Get/validate the region.
	region, err := getValidateRegionValue(catalogAttrs)
	if err != nil {
		return nil, err
	}

	set := req.GetSet()
	if set == nil {
		return nil, errors.New("set is nil")
	}

	setAttrs := set.GetAttributes()
	if setAttrs == nil {
		return nil, errors.New("set missing attributes")
	}

	ec2Client, err := state.EC2Client(region)
	if err != nil {
		return nil, fmt.Errorf("error getting EC2 client: %w", err)
	}

	input, err := buildDescribeInstancesInput(setAttrs, true)
	if err != nil {
		return nil, fmt.Errorf("error building DescribeInstances parameters: %w", err)
	}

	_, err = ec2Client.DescribeInstances(input)
	if err == nil {
		return nil, errors.New("query error: DescribeInstances DryRun should have returned error, but none was found")
	}

	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "DryRunOperation" {
		// Success
		return &pb.OnCreateSetResponse{}, nil
	}

	return nil, fmt.Errorf("error performing dry run of DescribeInstances: %w", err)
}

func (p *AwsPlugin) OnUpdateSet(ctx context.Context, req *pb.OnUpdateSetRequest) (*pb.OnUpdateSetResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.New("catalog is nil")
	}

	catalogAttrs := catalog.GetAttributes()
	if catalogAttrs == nil {
		return nil, errors.New("catalog missing attributes")
	}

	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted())
	if err != nil {
		return nil, err
	}

	// Get/validate the region.
	region, err := getValidateRegionValue(catalogAttrs)
	if err != nil {
		return nil, err
	}

	// As with catalog, we don't need to really look at the old host
	// set here, just need to work off of/validate the new set config
	set := req.GetNewSet()
	if set == nil {
		return nil, errors.New("new set is nil")
	}

	setAttrs := set.GetAttributes()
	if setAttrs == nil {
		return nil, errors.New("new set missing attributes")
	}

	ec2Client, err := state.EC2Client(region)
	if err != nil {
		return nil, fmt.Errorf("error getting EC2 client: %w", err)
	}

	input, err := buildDescribeInstancesInput(setAttrs, true)
	if err != nil {
		return nil, fmt.Errorf("error building DescribeInstances parameters: %w", err)
	}

	_, err = ec2Client.DescribeInstances(input)
	if err == nil {
		return nil, errors.New("query error: DescribeInstances DryRun should have returned error, but none was found")
	}

	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "DryRunOperation" {
		// Success
		return &pb.OnUpdateSetResponse{}, nil
	}

	return nil, fmt.Errorf("error performing dry run of DescribeInstances: %w", err)
}

func (p *AwsPlugin) OnDeleteSet(ctx context.Context, req *pb.OnDeleteSetRequest) (*pb.OnDeleteSetResponse, error) {
	// No-op, AWS host set does not maintain anything that requires
	// cleanup
	return nil, nil
}

func (p *AwsPlugin) ListHosts(ctx context.Context, req *pb.ListHostsRequest) (*pb.ListHostsResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.New("catalog is nil")
	}

	catalogAttrs := catalog.GetAttributes()
	if catalogAttrs == nil {
		return nil, errors.New("catalog missing attributes")
	}

	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted())
	if err != nil {
		return nil, err
	}

	// Get/validate the region.
	region, err := getValidateRegionValue(catalogAttrs)
	if err != nil {
		return nil, err
	}

	sets := req.GetSets()
	if sets == nil {
		return nil, errors.New("sets is nil")
	}

	// Build all the queries in advance.
	type hostSetQuery struct {
		Id          string
		Input       *ec2.DescribeInstancesInput
		Output      *ec2.DescribeInstancesOutput
		OutputHosts []*pb.ListHostsResponseHost
	}

	queries := make([]hostSetQuery, len(sets))
	for i, set := range sets {
		// Validate Id since we use it in output
		if set.GetId() == "" {
			return nil, errors.New("set missing id")
		}

		setAttrs := set.GetAttributes()
		if setAttrs == nil {
			return nil, errors.New("set missing attributes")
		}

		input, err := buildDescribeInstancesInput(setAttrs, false)
		if err != nil {
			return nil, fmt.Errorf("error building DescribeInstances parameters for host set id %q: %w", set.GetId(), err)
		}
		queries[i] = hostSetQuery{
			Id:    set.GetId(),
			Input: input,
		}
	}

	ec2Client, err := state.EC2Client(region)
	if err != nil {
		return nil, fmt.Errorf("error getting EC2 client: %w", err)
	}

	// Run all queries now and assemble output.
	var maxLen int
	for i, query := range queries {
		output, err := ec2Client.DescribeInstances(query.Input)
		if err != nil {
			return nil, fmt.Errorf("error running DescribeInstances for host set id %q: %w", query.Id, err)
		}

		queries[i].Output = output

		// Process the output here, we will normalize this into a single
		// set of hosts afterwards (possibly removing duplicates).
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				host, err := awsInstanceToHost(instance)
				if err != nil {
					return nil, fmt.Errorf("error processing host results for host set id %q: %w", query.Id, err)
				}

				if host == nil {
					// Nil result means we don't include the host (instance not
					// running, or some other issue).
					continue
				}

				queries[i].OutputHosts = append(queries[i].OutputHosts, host)
				maxLen++ // Increment maximum counter for allocation later
			}
		}
	}

	// Now de-duplicate the hosts for the output.
	hostResults := make([]*pb.ListHostsResponseHost, 0, maxLen)
	seenInstances := make(map[string]struct{})
	for _, query := range queries {
		for _, host := range query.OutputHosts {
			if _, ok := seenInstances[host.ExternalId]; ok {
				continue
			}

			hostResults = append(hostResults, host)
			seenInstances[host.ExternalId] = struct{}{}
		}
	}

	// Done!
	return &pb.ListHostsResponse{
		Hosts: hostResults,
	}, nil
}

type awsCatalogPersistedState struct {
	AccessKeyId          string
	SecretAccessKey      string
	CredsLastRotatedTime time.Time
}

func awsCatalogPersistedStateFromProto(in *pb.HostCatalogPersisted) (*awsCatalogPersistedState, error) {
	data := in.GetData()
	if data == nil {
		return nil, errors.New("missing data")
	}

	accessKeyId, err := getStringValue(data, constAccessKeyId, true)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	secretAccessKey, err := getStringValue(data, constSecretAccessKey, true)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	credsLastRotatedTime, err := getTimeValue(data, constCredsLastRotatedTime)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	return &awsCatalogPersistedState{
		AccessKeyId:          accessKeyId,
		SecretAccessKey:      secretAccessKey,
		CredsLastRotatedTime: credsLastRotatedTime,
	}, nil
}

func (s *awsCatalogPersistedState) ToProto() (*pb.HostCatalogPersisted, error) {
	data, err := structpb.NewStruct(map[string]interface{}{
		constAccessKeyId:          s.AccessKeyId,
		constSecretAccessKey:      s.SecretAccessKey,
		constCredsLastRotatedTime: s.CredsLastRotatedTime.Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, fmt.Errorf("error converting state to structpb.Struct: %w", err)
	}

	return &pb.HostCatalogPersisted{Data: data}, nil
}

func (s *awsCatalogPersistedState) ValidateCreds() error {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if _, err := c.GetCallerIdentity(); err != nil {
		return fmt.Errorf("error validating credentials: %w", err)
	}

	return nil
}

func (s *awsCatalogPersistedState) RotateCreds() error {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if err := c.RotateKeys(awsutil.WithValidityCheckTimeout(rotationWaitTimeout)); err != nil {
		return fmt.Errorf("error rotating credentials: %w", err)
	}

	s.AccessKeyId = c.AccessKey
	s.SecretAccessKey = c.SecretKey
	s.CredsLastRotatedTime = time.Now()

	return nil
}

// ReplaceCreds replaces the access key in the state with a new key.
// If the existing key was rotated at any point in time, it is
// deleted first, otherwise it's left alone.
func (s *awsCatalogPersistedState) ReplaceCreds(accessKeyId, secretAccessKey string) error {
	if accessKeyId == "" {
		return errors.New("access key id cannot be empty")
	}

	if secretAccessKey == "" {
		return errors.New("secret access key cannot be empty")
	}

	if accessKeyId == s.AccessKeyId {
		return errors.New("attempting to replace access key with the same one")
	}

	if !s.CredsLastRotatedTime.IsZero() {
		// Delete old/existing credentials. This is done with the same
		// credentials to ensure that it has the proper permissions to do
		// it.
		if err := s.DeleteCreds(); err != nil {
			return err
		}
	}

	// Set the new attributes and clear the rotated time.
	s.AccessKeyId = accessKeyId
	s.SecretAccessKey = secretAccessKey
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// DeleteCreds deletes the credentials in the state. The access key
// ID, secret access key, and rotation time fields are zeroed out in
// the state just to ensure that they cannot be re-used after.
func (s *awsCatalogPersistedState) DeleteCreds() error {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if err := c.DeleteAccessKey(s.AccessKeyId); err != nil {
		// Determine if the deletion error was due to a missing
		// resource. If it was, just pass it.
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == iam.ErrCodeNoSuchEntityException {
			s.AccessKeyId = ""
			s.SecretAccessKey = ""
			s.CredsLastRotatedTime = time.Time{}
			return nil
		}

		// Otherwise treat it as an actual error.
		return fmt.Errorf("error deleting old access key: %w", err)
	}

	s.AccessKeyId = ""
	s.SecretAccessKey = ""
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// GetSession returns a configured AWS session for the credentials in
// the state.
func (s *awsCatalogPersistedState) GetSession() (*session.Session, error) {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return nil, err
	}

	return c.GetSession()
}

// EC2Client returns a configured EC2 client based on the session
// information stored in the state.
func (s *awsCatalogPersistedState) EC2Client(region string) (*ec2.EC2, error) {
	sess, err := s.GetSession()
	if err != nil {
		return nil, fmt.Errorf("error getting AWS session: %w", err)
	}

	return ec2.New(sess, aws.NewConfig().WithRegion(region)), nil
}

func getStringValue(in *structpb.Struct, k string, required bool) (string, error) {
	mv := in.AsMap()
	v, ok := mv[k]
	if !ok {
		if required {
			return "", fmt.Errorf("missing required value %q", k)
		}

		return "", nil
	}

	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("unexpected type for value %q: want string, got %T", k, v)
	}

	if s == "" && required {
		return "", fmt.Errorf("value %q cannot be empty", k)
	}

	return s, nil
}

func getBoolValue(in *structpb.Struct, k string, required bool) (bool, error) {
	mv := in.AsMap()
	v, ok := mv[k]
	if !ok {
		if required {
			return false, fmt.Errorf("missing required value %q", k)
		}

		return false, nil
	}

	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected type for value %q: want bool, got %T", k, v)
	}

	return b, nil
}

func getTimeValue(in *structpb.Struct, k string) (time.Time, error) {
	mv := in.AsMap()
	v, ok := mv[k]
	if !ok {
		return time.Time{}, nil
	}

	tRaw, ok := v.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("unexpected type for value %q: want string, got %T", k, v)
	}

	t, err := time.Parse(time.RFC3339Nano, tRaw)
	if err != nil {
		return time.Time{}, fmt.Errorf("could not parse time in value %q: %w", k, err)
	}

	return t, nil
}

func getMapValue(in *structpb.Struct, k string) (map[string]interface{}, error) {
	mv := in.AsMap()
	v, ok := mv[k]
	if !ok {
		return make(map[string]interface{}), nil
	}

	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected type for value %q: want map, got %T", k, v)
	}

	return m, nil
}

func getValidateRegionValue(in *structpb.Struct) (string, error) {
	region, err := getStringValue(in, constRegion, true)
	if err != nil {
		return "", err
	}

	_, found := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
	if !found {
		return "", fmt.Errorf("not a valid region: %s", region)
	}

	return region, nil
}

func buildFilters(in *structpb.Struct) ([]*ec2.Filter, error) {
	var filters []*ec2.Filter
	m, err := getMapValue(in, constDescribeInstancesFilters)
	if err != nil {
		return nil, err
	}

	var foundStateFilter bool
	for k, v := range m {
		if k == "instance-state-code" || k == "instance-state-name" {
			foundStateFilter = true
		}

		w, ok := v.([]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected type for filter values in %q: want array, got %T", k, v)
		}

		var filterValues []*string
		for _, e := range w {
			f, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("unexpected type for filter value %v: want array, got %T", e, e)
			}

			filterValues = append(filterValues, aws.String(f))
		}

		filters = append(filters, &ec2.Filter{
			Name:   aws.String(k),
			Values: filterValues,
		})
	}

	if !foundStateFilter {
		// if there is no explicit instance state filter, add the
		// instance-state-name = ["running"] to the filter set. This
		// ensures that we filter on running instances only at the API
		// side, saving time when processing results.
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("instance-state-name"),
			Values: aws.StringSlice([]string{ec2.InstanceStateNameRunning}),
		})
	}

	return filters, nil
}

func buildDescribeInstancesInput(attrs *structpb.Struct, dryRun bool) (*ec2.DescribeInstancesInput, error) {
	filters, err := buildFilters(attrs)
	if err != nil {
		return nil, fmt.Errorf("error building filters: %w", err)
	}

	return &ec2.DescribeInstancesInput{
		DryRun:  aws.Bool(dryRun),
		Filters: filters,
	}, nil
}

// awsInstanceToHost processes data from an ec2.Instance and returns
// a ListHostsResponseHost with the ID and network addresses
// populated.
//
// Returns nil if the instance is not ready (ie: powered down,
// hibernated, or terminated).
func awsInstanceToHost(instance *ec2.Instance) (*pb.ListHostsResponseHost, error) {
	// Integrity check: some fields should always be non-nil. Check
	// those.
	if instance == nil {
		return nil, errors.New("response integrity error: missing instance entry")
	}

	if instance.State == nil {
		return nil, errors.New("response integrity error: missing instance state")
	}

	if aws.StringValue(instance.State.Name) == "" {
		return nil, errors.New("response integrity error: missing instance state name")
	}

	if aws.StringValue(instance.InstanceId) == "" {
		return nil, errors.New("response integrity error: missing instance id")
	}

	// Abort this if the instance is not ready
	if aws.StringValue(instance.State.Name) != ec2.InstanceStateNameRunning {
		return nil, nil
	}

	result := new(pb.ListHostsResponseHost)

	// External ID is the instance ID.
	result.ExternalId = aws.StringValue(instance.InstanceId)

	// First IP address is always the private IP address field if it's
	// populated
	if aws.StringValue(instance.PrivateIpAddress) != "" {
		result.IpAddresses = append(result.IpAddresses, aws.StringValue(instance.PrivateIpAddress))
	}

	// Public IP address is next.
	if aws.StringValue(instance.PublicIpAddress) != "" {
		result.IpAddresses = append(result.IpAddresses, aws.StringValue(instance.PublicIpAddress))
	}

	// Now go through all of the interfaces and log the IP address of
	// every interface.
	for _, iface := range instance.NetworkInterfaces {
		if iface == nil {
			// Probably will never happen, but just in case
			return nil, errors.New("response integrity error: interface entry is nil")
		}

		// Iterate through the private IP addresses and log the
		// information.
		for _, addr := range iface.PrivateIpAddresses {
			if addr == nil {
				return nil, errors.New("response integrity error: interface address entry is nil")
			}

			// Check to see if the PrivateIpAddress matches the one
			// reported at the top-level of the instance (let's call it the
			// "default address"). If it doesn't, add it.
			if aws.StringValue(addr.PrivateIpAddress) != "" {
				if aws.StringValue(instance.PrivateIpAddress) != aws.StringValue(addr.PrivateIpAddress) {
					result.IpAddresses = append(result.IpAddresses, aws.StringValue(addr.PrivateIpAddress))
				}
			}

			// Do the same for the default public IP address and the
			// public association on the interface.
			if addr.Association != nil && addr.Association.PublicIp != nil && aws.StringValue(addr.Association.PublicIp) != "" {
				if instance.PublicIpAddress != nil && aws.StringValue(instance.PublicIpAddress) != aws.StringValue(addr.Association.PublicIp) {
					result.IpAddresses = append(result.IpAddresses, aws.StringValue(addr.Association.PublicIp))
				}
			}
		}

		// Add the IPv6 addresses.
		for _, addr := range iface.Ipv6Addresses {
			if addr == nil {
				continue
			}

			if addr.Ipv6Address != nil && aws.StringValue(addr.Ipv6Address) != "" {
				result.IpAddresses = append(result.IpAddresses, aws.StringValue(addr.Ipv6Address))
			}
		}
	}

	// Done
	return result, nil
}
