package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/ec2"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// rotationWaitTimeout controls the time we wait for credential rotation to
// succeed. This is important to ensure that rotated credentials can be used
// right away.
const rotationWaitTimeout = time.Second * 30

// AwsPlugin implements the HostPluginServiceServer interface for the
// AWS plugin.
type AwsPlugin struct {
	pb.UnimplementedHostPluginServiceServer

	// testStateOpts are passed in to the stored state to control test behavior
	testStateOpts []awsCatalogPersistedStateOption
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
	if attrs == nil {
		return nil, errors.New("attributes are required")
	}

	catalogAttributes, err := getCatalogAttributes(attrs)
	if err != nil {
		return nil, err
	}
	catalogSecrets, err := getCatalogSecrets(secrets)
	if err != nil {
		return nil, err
	}

	if err := validateRegion(catalogAttributes.Region); err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	state, err := newAwsCatalogPersistedState(append([]awsCatalogPersistedStateOption{
		withAccessKeyId(catalogSecrets.AccessKeyId),
		withSecretAccessKey(catalogSecrets.SecretAccessKey),
	}, p.testStateOpts...)...)
	if err != nil {
		return nil, fmt.Errorf("error setting up persisted state: %w", err)
	}

	// Try to rotate the credentials if we're not skipping them.
	if !catalogAttributes.DisableCredentialRotation {
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

	catalogAttributes, err := getCatalogAttributes(attrs)
	if err != nil {
		return nil, err
	}

	if err := validateRegion(catalogAttributes.Region); err != nil {
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
	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted(), p.testStateOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading persisted state: %w", err)
	}

	if catalogAttributes.DisableCredentialRotation && !updateSecrets {
		// This is a validate check to make sure that we aren't disabling
		// rotation for credentials currently being managed by rotation.
		// This is not allowed.
		if !state.CredsLastRotatedTime.IsZero() {
			return nil, errors.New("cannot disable rotation for already-rotated credentials")
		}
	}

	if updateSecrets {
		catalogSecrets, err := getCatalogSecrets(secrets)
		if err != nil {
			return nil, err
		}

		// Replace the credentials. This checks the timestamp on the last
		// rotation time as well and deletes the credentials if we are
		// managing them (ie: if we've rotated them before).
		if err := state.ReplaceCreds(catalogSecrets.AccessKeyId, catalogSecrets.SecretAccessKey); err != nil {
			return nil, fmt.Errorf("error attempting to replace credentials: %w", err)
		}
	}

	if !catalogAttributes.DisableCredentialRotation && state.CredsLastRotatedTime.IsZero() {
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
	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted(), p.testStateOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading persisted state: %w", err)
	}

	if !state.CredsLastRotatedTime.IsZero() {
		// Delete old/existing credentials. This is done with the same
		// credentials to ensure that it has the proper permissions to do
		// it.
		if err := state.DeleteCreds(); err != nil {
			return nil, fmt.Errorf("error removing rotated credentials during catalog deletion: %w", err)
		}
	}

	return &pb.OnDeleteCatalogResponse{}, nil
}

func (p *AwsPlugin) OnCreateSet(ctx context.Context, req *pb.OnCreateSetRequest) (*pb.OnCreateSetResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.New("catalog is nil")
	}

	catalogAttrsRaw := catalog.GetAttributes()
	if catalogAttrsRaw == nil {
		return nil, errors.New("catalog missing attributes")
	}

	catalogAttributes, err := getCatalogAttributes(catalogAttrsRaw)
	if err != nil {
		return nil, fmt.Errorf("integrity error in host catalog attributes: %w", err)
	}

	if err := validateRegion(catalogAttributes.Region); err != nil {
		return nil, fmt.Errorf("integrity error in host catalog attributes: %w", err)
	}

	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted(), p.testStateOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading persisted state: %w", err)
	}

	set := req.GetSet()
	if set == nil {
		return nil, errors.New("set is nil")
	}

	if set.GetAttributes() == nil {
		return nil, errors.New("set missing attributes")
	}
	setAttrs, err := getSetAttributes(set.GetAttributes())
	if err != nil {
		return nil, fmt.Errorf("error parsing set attributes: %w", err)
	}

	ec2Client, err := state.EC2Client(catalogAttributes.Region)
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

	catalogAttrsRaw := catalog.GetAttributes()
	if catalogAttrsRaw == nil {
		return nil, errors.New("catalog missing attributes")
	}

	catalogAttributes, err := getCatalogAttributes(catalogAttrsRaw)
	if err != nil {
		return nil, fmt.Errorf("integrity error in host catalog attributes: %w", err)
	}

	if err := validateRegion(catalogAttributes.Region); err != nil {
		return nil, fmt.Errorf("integrity error in host catalog attributes: %w", err)
	}

	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted(), p.testStateOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading persisted state: %w", err)
	}

	// As with catalog, we don't need to really look at the old host
	// set here, just need to work off of/validate the new set config
	set := req.GetNewSet()
	if set == nil {
		return nil, errors.New("new set is nil")
	}

	if set.GetAttributes() == nil {
		return nil, errors.New("new set missing attributes")
	}
	setAttrs, err := getSetAttributes(set.GetAttributes())
	if err != nil {
		return nil, fmt.Errorf("error parsing set attributes: %w", err)
	}

	ec2Client, err := state.EC2Client(catalogAttributes.Region)
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
	return &pb.OnDeleteSetResponse{}, nil
}

func (p *AwsPlugin) ListHosts(ctx context.Context, req *pb.ListHostsRequest) (*pb.ListHostsResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.New("catalog is nil")
	}

	catalogAttrsRaw := catalog.GetAttributes()
	if catalogAttrsRaw == nil {
		return nil, errors.New("catalog missing attributes")
	}

	catalogAttributes, err := getCatalogAttributes(catalogAttrsRaw)
	if err != nil {
		return nil, fmt.Errorf("integrity error in host catalog attributes: %w", err)
	}

	if err := validateRegion(catalogAttributes.Region); err != nil {
		return nil, fmt.Errorf("integrity error in host catalog attributes: %w", err)
	}

	state, err := awsCatalogPersistedStateFromProto(req.GetPersisted(), p.testStateOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading persisted state: %w", err)
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

		if set.GetAttributes() == nil {
			return nil, errors.New("set missing attributes")
		}
		setAttrs, err := getSetAttributes(set.GetAttributes())
		if err != nil {
			return nil, fmt.Errorf("error parsing set attributes: %w", err)
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

	ec2Client, err := state.EC2Client(catalogAttributes.Region)
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

				queries[i].OutputHosts = append(queries[i].OutputHosts, host)
				maxLen++ // Increment maximum counter for allocation later
			}
		}
	}

	// Now de-duplicate the hosts for the output. Maintain two sets:
	// * A slice of hosts that will be used in the output
	// * A map of hosts indexed by their external ID
	//
	// The map will is used in de-duplication to determine whether or
	// not we've seen the host before to simply add the query's set ID
	// to the list of set IDs that the host was seen in.
	hostResultSlice := make([]*pb.ListHostsResponseHost, 0, maxLen)
	hostResultMap := make(map[string]*pb.ListHostsResponseHost)
	for _, query := range queries {
		for _, host := range query.OutputHosts {
			if existingHost, ok := hostResultMap[host.ExternalId]; ok {
				// Existing host, just add the set ID to the list of seen IDs
				// and continue
				existingHost.SetIds = append(existingHost.SetIds, query.Id)
				continue
			}

			// This will be the first seen entry, so append the set ID to
			// this host, and add it.
			host.SetIds = append(host.SetIds, query.Id)
			hostResultSlice = append(hostResultSlice, host)
			hostResultMap[host.ExternalId] = host
		}
	}

	// Done!
	return &pb.ListHostsResponse{
		Hosts: hostResultSlice,
	}, nil
}

func validateRegion(region string) error {
	_, found := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
	if !found {
		return fmt.Errorf("not a valid region: %s", region)
	}

	return nil
}

func buildFilters(attrs *SetAttributes) ([]*ec2.Filter, error) {
	var filters []*ec2.Filter
	var foundStateFilter bool
	for _, filterAttr := range attrs.Filters {
		// Each filter arrives in "k=v1,v2" format. First, split on equal sign.
		splitFilter := strings.Split(filterAttr, "=")
		switch {
		case len(splitFilter) != 2:
			return nil, fmt.Errorf("expected filter %q to contain a single equal sign", filterAttr)
		case len(splitFilter[0]) == 0:
			return nil, fmt.Errorf("filter %q contains an empty filter key", filterAttr)
		case len(splitFilter[1]) == 0:
			return nil, fmt.Errorf("filter %q contains an empty value", filterAttr)
		}

		filterKey, filterValue := splitFilter[0], splitFilter[1]
		if filterKey == "instance-state-code" || filterKey == "instance-state-name" {
			foundStateFilter = true
		}

		var filterValues []*string
		for _, val := range strings.Split(filterValue, ",") {
			filterValues = append(filterValues, aws.String(val))
		}

		filters = append(filters, &ec2.Filter{
			Name:   aws.String(filterKey),
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

func buildDescribeInstancesInput(attrs *SetAttributes, dryRun bool) (*ec2.DescribeInstancesInput, error) {
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
func awsInstanceToHost(instance *ec2.Instance) (*pb.ListHostsResponseHost, error) {
	// Integrity check: some fields should always be non-nil. Check
	// those.
	if instance == nil {
		return nil, errors.New("response integrity error: missing instance entry")
	}

	if aws.StringValue(instance.InstanceId) == "" {
		return nil, errors.New("response integrity error: missing instance id")
	}

	result := new(pb.ListHostsResponseHost)

	// External ID is the instance ID.
	result.ExternalId = aws.StringValue(instance.InstanceId)

	// First IP address/dns name are always the private fields if they
	// are populated
	if aws.StringValue(instance.PrivateIpAddress) != "" {
		result.IpAddresses = append(result.IpAddresses, aws.StringValue(instance.PrivateIpAddress))
	}
	if aws.StringValue(instance.PrivateDnsName) != "" {
		result.DnsNames = append(result.DnsNames, aws.StringValue(instance.PrivateDnsName))
	}

	// Public IP address/dns names are next
	if aws.StringValue(instance.PublicIpAddress) != "" {
		result.IpAddresses = append(result.IpAddresses, aws.StringValue(instance.PublicIpAddress))
	}
	if aws.StringValue(instance.PublicDnsName) != "" {
		result.DnsNames = append(result.DnsNames, aws.StringValue(instance.PublicDnsName))
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

			// Check to see if the PrivateIpAddress/PrivateDnsName fields
			// match the ones reported at the top-level of the instance.
			// If they don't, add them.
			if aws.StringValue(addr.PrivateIpAddress) != "" {
				if aws.StringValue(instance.PrivateIpAddress) != aws.StringValue(addr.PrivateIpAddress) {
					result.IpAddresses = append(result.IpAddresses, aws.StringValue(addr.PrivateIpAddress))
				}
			}
			if aws.StringValue(addr.PrivateDnsName) != "" {
				if aws.StringValue(instance.PrivateDnsName) != aws.StringValue(addr.PrivateDnsName) {
					result.DnsNames = append(result.DnsNames, aws.StringValue(addr.PrivateDnsName))
				}
			}

			// Do the same for the top-level public IP address/DNS name and
			// the public association on the interface.
			if addr.Association != nil && aws.StringValue(addr.Association.PublicIp) != "" {
				if aws.StringValue(instance.PublicIpAddress) != aws.StringValue(addr.Association.PublicIp) {
					result.IpAddresses = append(result.IpAddresses, aws.StringValue(addr.Association.PublicIp))
				}
			}
			if addr.Association != nil && aws.StringValue(addr.Association.PublicDnsName) != "" {
				if aws.StringValue(instance.PublicDnsName) != aws.StringValue(addr.Association.PublicDnsName) {
					result.DnsNames = append(result.DnsNames, aws.StringValue(addr.Association.PublicDnsName))
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
