package host

// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

import (
	"context"
	goerrors "errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	"github.com/hashicorp/boundary-plugin-aws/internal/credential"
	"github.com/hashicorp/boundary-plugin-aws/internal/errors"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// HostPlugin implements the HostPluginServiceServer interface for the
// AWS host service plugin.
type HostPlugin struct {
	pb.UnimplementedHostPluginServiceServer

	// testCredStateOpts are passed in to the stored state to control test behavior
	testCredStateOpts []credential.AwsCredentialPersistedStateOption

	// testCatalogStateOpts are passed in to the stored state to control test behavior
	testCatalogStateOpts []awsCatalogPersistedStateOption
}

type hostSetQuery struct {
	Id          string
	Input       *ec2.DescribeInstancesInput
	Output      *ec2.DescribeInstancesOutput
	OutputHosts []*pb.ListHostsResponseHost
}

const defaultSessionName = "boundary-default"
const dryRunOperationErrorCode = "DryRunOperation"
const errBuildDescribeInstancesInput = "error building DescribeInstances input: %s"
const errDryRunFailed = "error performing DescribeInstances dry run: %s"

// Ensure that we are implementing HostPluginServiceServer
var _ pb.HostPluginServiceServer = (*HostPlugin)(nil)

// OnCreateCatalog is called when a dynamic host catalog is created.
func (p *HostPlugin) OnCreateCatalog(ctx context.Context, req *pb.OnCreateCatalogRequest) (*pb.OnCreateCatalogResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.BadRequestStatus("catalog is required")
	}

	attrs := catalog.GetAttributes()
	if attrs == nil {
		return nil, errors.BadRequestStatus("attributes are required")
	}

	catalogAttributes, err := getCatalogAttributes(attrs)
	if err != nil {
		return nil, err
	}
	credConfig, err := credential.GetCredentialsConfig(catalog.GetSecrets(), catalogAttributes.CredentialAttributes, catalogAttributes.DualStack)
	if err != nil {
		return nil, err
	}

	// Set up the creds in our persisted state.
	credState, err := credential.NewAwsCredentialPersistedState(
		append([]credential.AwsCredentialPersistedStateOption{
			credential.WithCredentialsConfig(credConfig),
		}, p.testCredStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatusf("error setting up persisted state: %s", err)
	}

	// Try to rotate AWS static credentials
	if credential.GetCredentialType(credState.CredentialsConfig) == credential.StaticAWS && !catalogAttributes.DisableCredentialRotation {
		if err := credState.RotateCreds(ctx); err != nil {
			return nil, err
		}
	}

	catalogState, err := newAwsCatalogPersistedState(
		append([]awsCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatusf("error setting up persisted state: %s", err)
	}

	opts := []ec2Option{}
	if catalogAttributes.DualStack {
		opts = append(opts, WithDualStack(catalogAttributes.DualStack))
	}
	input, err := buildDescribeInstancesInput(&SetAttributes{}, true)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, errBuildDescribeInstancesInput, err)
	}
	// Run a DescribeInstances request with DryRun set to true to ensure
	// we can interact with AWS resources as expected.
	if _, err := checkHosts(ctx, catalogState, input, opts, catalogAttributes.TargetAccount); err != nil {
		return nil, fmt.Errorf(errDryRunFailed, err)
	}

	persistedProto, err := catalogState.toProto()
	if err != nil {
		return nil, errors.BadRequestStatusf("error converting persisted state to proto: %s", err)
	}

	return &pb.OnCreateCatalogResponse{
		Persisted: persistedProto,
	}, nil
}

// OnUpdateCatalog is called when a dynamic host catalog is updated.
func (p *HostPlugin) OnUpdateCatalog(ctx context.Context, req *pb.OnUpdateCatalogRequest) (*pb.OnUpdateCatalogResponse, error) {
	// For host catalogs we only need to really validate what is
	// currently in the new copy of the host catalog data, so skip
	// fetching the new copy to keep things a little less messy.
	currentCatalog := req.GetCurrentCatalog()
	if currentCatalog == nil {
		return nil, errors.BadRequestStatus("current catalog is required")
	}
	newCatalog := req.GetNewCatalog()
	if newCatalog == nil {
		return nil, errors.BadRequestStatus("new catalog is required")
	}

	oldAttrs := currentCatalog.GetAttributes()
	if oldAttrs == nil {
		return nil, errors.BadRequestStatus("current catalog attributes are required")
	}
	oldCatalogAttributes, err := getCatalogAttributes(oldAttrs)
	if err != nil {
		return nil, err
	}
	newAttrs := newCatalog.GetAttributes()
	if newAttrs == nil {
		return nil, errors.BadRequestStatus("new catalog attributes are required")
	}
	newCatalogAttributes, err := getCatalogAttributes(newAttrs)
	if err != nil {
		return nil, err
	}

	credState, err := credential.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetSecrets(),
		oldCatalogAttributes.CredentialAttributes,
		oldCatalogAttributes.DualStack,
		p.testCredStateOpts...)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	// Verify the incoming credentials are valid and return any errors to the
	// user if they're not. Note this doesn't validate the credentials against
	// AWS - it only does logical validation on the fields.
	updatedCredentials, err := credential.GetCredentialsConfig(newCatalog.GetSecrets(), newCatalogAttributes.CredentialAttributes, newCatalogAttributes.DualStack)
	if err != nil {
		return nil, err
	}

	// We will be updating credentials when one of two changes occur:
	// 1. the new catalog has secrets for static credentials, in which case we need to delete the old static credentials
	// 2. the new catalog has a different roleARN value for dynamic credentials
	if newCatalog.GetSecrets() != nil || newCatalogAttributes.RoleArn != oldCatalogAttributes.RoleArn {
		// Ensure the incoming credentials are valid for interaction with the S3
		// Bucket before replacing them.
		newCredState, err := credential.NewAwsCredentialPersistedState(
			append([]credential.AwsCredentialPersistedStateOption{
				credential.WithCredentialsConfig(updatedCredentials),
			}, p.testCredStateOpts...)...,
		)
		if err != nil {
			return nil, errors.BadRequestStatusf("error setting up new credential persisted state: %s", err)
		}
		newCatalogState, err := newAwsCatalogPersistedState(
			append([]awsCatalogPersistedStateOption{
				withCredentials(newCredState),
			}, p.testCatalogStateOpts...)...,
		)
		if err != nil {
			return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
		}

		opts := []ec2Option{}
		if newCatalogAttributes.DualStack {
			opts = append(opts, WithDualStack(newCatalogAttributes.DualStack))
		}
		input, err := buildDescribeInstancesInput(&SetAttributes{}, true)
		if err != nil {
			return nil, status.Errorf(codes.Unknown, errBuildDescribeInstancesInput, err)
		}
		// Run a DescribeInstances request with DryRun set to true to ensure
		// we can interact with AWS resources as expected.
		if _, err := checkHosts(ctx, newCatalogState, input, opts, newCatalogAttributes.TargetAccount); err != nil {
			return nil, fmt.Errorf(errDryRunFailed, err)
		}

		// Replace the existing credential state.
		// This checks the timestamp on the last rotation time as well
		// and deletes the credentials if we are managing them
		// (ie: if we've rotated them before).
		if err := credState.ReplaceCreds(ctx, updatedCredentials); err != nil {
			return nil, err
		}
	}

	if credential.GetCredentialType(credState.CredentialsConfig) == credential.StaticAWS {
		// This is a validate check to make sure that we aren't disabling
		// rotation for credentials currently being managed by rotation.
		// This is not allowed.
		if newCatalogAttributes.DisableCredentialRotation && newCatalog.GetSecrets() == nil {
			if !credState.CredsLastRotatedTime.IsZero() {
				return nil, errors.BadRequestStatus("cannot disable rotation for already-rotated credentials")
			}
		}

		// If we're enabling rotation now but didn't before, or have
		// freshly replaced credentials, we can rotate here.
		if !newCatalogAttributes.DisableCredentialRotation && credState.CredsLastRotatedTime.IsZero() {
			if err := credState.RotateCreds(ctx); err != nil {
				return nil, err
			}
		}
	}

	catalogState, err := newAwsCatalogPersistedState(
		append([]awsCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	opts := []ec2Option{}
	if newCatalogAttributes.DualStack {
		opts = append(opts, WithDualStack(newCatalogAttributes.DualStack))
	}
	input, err := buildDescribeInstancesInput(&SetAttributes{}, true)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, errBuildDescribeInstancesInput, err)
	}
	// Run a DescribeInstances request with DryRun set to true to ensure
	// we can interact with AWS resources as expected.
	if _, err := checkHosts(ctx, catalogState, input, opts, newCatalogAttributes.TargetAccount); err != nil {
		return nil, fmt.Errorf(errDryRunFailed, err)
	}

	persistedProto, err := catalogState.toProto()
	if err != nil {
		return nil, errors.BadRequestStatusf("error converting persisted state to proto: %s", err)
	}

	return &pb.OnUpdateCatalogResponse{
		Persisted: persistedProto,
	}, nil
}

// OnDeleteCatalog is called when a dynamic host catalog is deleted.
func (p *HostPlugin) OnDeleteCatalog(ctx context.Context, req *pb.OnDeleteCatalogRequest) (*pb.OnDeleteCatalogResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.BadRequestStatus("catalog is required")
	}

	attrs := catalog.GetAttributes()
	if attrs == nil {
		return nil, errors.BadRequestStatus("catalog attributes are required")
	}

	catalogAttributes, err := getCatalogAttributes(attrs)
	if err != nil {
		return nil, err
	}

	// Get the persisted data.
	// NOTE: We return on error here, blocking the delete. This may or
	// may not be an overzealous approach to maintaining database/state
	// integrity. May need to be changed at later time if there are
	// scenarios where we might be deleting things and any secret state
	// may be corrupt/and or legitimately missing.
	credState, err := credential.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetSecrets(),
		catalogAttributes.CredentialAttributes,
		catalogAttributes.DualStack,
		p.testCredStateOpts...)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	_, err = newAwsCatalogPersistedState(
		append([]awsCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	// try to delete static credentials
	if credential.GetCredentialType(credState.CredentialsConfig) == credential.StaticAWS {
		if !credState.CredsLastRotatedTime.IsZero() {
			// Delete old/existing credentials. This is done with the same
			// credentials to ensure that it has the proper permissions to do
			// it.
			if err := credState.DeleteCreds(ctx); err != nil {
				return nil, err
			}
		}
	}

	return &pb.OnDeleteCatalogResponse{}, nil
}

// NormalizeSetData currently ensures that "filters" is an array value, even
// though it's accepted as a string value for CLI UX reasons
func (p *HostPlugin) NormalizeSetData(ctx context.Context, req *pb.NormalizeSetDataRequest) (*pb.NormalizeSetDataResponse, error) {
	if req.Attributes == nil {
		return new(pb.NormalizeSetDataResponse), nil
	}

	val := req.Attributes.Fields["filters"]
	if val == nil {
		return &pb.NormalizeSetDataResponse{Attributes: req.Attributes}, nil
	}
	stringVal, ok := val.Kind.(*structpb.Value_StringValue)
	if !ok {
		return &pb.NormalizeSetDataResponse{Attributes: req.Attributes}, nil
	}

	retAttrs := proto.Clone(req.Attributes).(*structpb.Struct)
	retAttrs.Fields["filters"] = structpb.NewListValue(
		&structpb.ListValue{
			Values: []*structpb.Value{
				structpb.NewStringValue(stringVal.StringValue),
			},
		})

	return &pb.NormalizeSetDataResponse{Attributes: retAttrs}, nil
}

// OnCreateSet is called when a dynamic host set is created.
func (p *HostPlugin) OnCreateSet(ctx context.Context, req *pb.OnCreateSetRequest) (*pb.OnCreateSetResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.BadRequestStatus("catalog is required")
	}

	catalogAttrsRaw := catalog.GetAttributes()
	if catalogAttrsRaw == nil {
		return nil, errors.BadRequestStatus("catalog attributes are required")
	}

	catalogAttributes, err := getCatalogAttributes(catalogAttrsRaw)
	if err != nil {
		return nil, err
	}

	credState, err := credential.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetSecrets(),
		catalogAttributes.CredentialAttributes,
		catalogAttributes.DualStack,
		p.testCredStateOpts...)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	catalogState, err := newAwsCatalogPersistedState(
		append([]awsCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	set := req.GetSet()
	if set == nil {
		return nil, errors.BadRequestStatus("set is required")
	}

	if set.GetAttributes() == nil {
		return nil, errors.BadRequestStatus("set attributes are required")
	}
	setAttrs, err := getSetAttributes(set.GetAttributes())
	if err != nil {
		return nil, err
	}

	opts := []ec2Option{}
	if catalogAttributes.DualStack {
		opts = append(opts, WithDualStack(catalogAttributes.DualStack))
	}
	input, err := buildDescribeInstancesInput(setAttrs, true)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, errBuildDescribeInstancesInput, err)
	}
	// Run a DescribeInstances request with DryRun set to true to ensure
	// we can interact with AWS resources as expected.
	if _, err := checkHosts(ctx, catalogState, input, opts, catalogAttributes.TargetAccount); err != nil {
		return nil, fmt.Errorf(errDryRunFailed, err)
	}

	return &pb.OnCreateSetResponse{}, nil
}

// OnUpdateSet is called when a dynamic host set is updated.
func (p *HostPlugin) OnUpdateSet(ctx context.Context, req *pb.OnUpdateSetRequest) (*pb.OnUpdateSetResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.BadRequestStatus("catalog is required")
	}

	catalogAttrsRaw := catalog.GetAttributes()
	if catalogAttrsRaw == nil {
		return nil, errors.BadRequestStatus("catalog attributes are required")
	}

	catalogAttributes, err := getCatalogAttributes(catalogAttrsRaw)
	if err != nil {
		return nil, err
	}

	credState, err := credential.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetSecrets(),
		catalogAttributes.CredentialAttributes,
		catalogAttributes.DualStack,
		p.testCredStateOpts...)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	catalogState, err := newAwsCatalogPersistedState(
		append([]awsCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	// As with catalog, we don't need to really look at the old host
	// set here, just need to work off of/validate the new set config
	set := req.GetNewSet()
	if set == nil {
		return nil, errors.BadRequestStatus("new set is required")
	}

	if set.GetAttributes() == nil {
		return nil, errors.BadRequestStatus("new set attributes are required")
	}
	setAttrs, err := getSetAttributes(set.GetAttributes())
	if err != nil {
		return nil, err
	}

	opts := []ec2Option{}
	if catalogAttributes.DualStack {
		opts = append(opts, WithDualStack(catalogAttributes.DualStack))
	}
	input, err := buildDescribeInstancesInput(setAttrs, true)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, errBuildDescribeInstancesInput, err)
	}
	// Run a DescribeInstances request with DryRun set to true to ensure
	// we can interact with AWS resources as expected.
	if _, err := checkHosts(ctx, catalogState, input, opts, catalogAttributes.TargetAccount); err != nil {
		return nil, fmt.Errorf(errDryRunFailed, err)
	}

	return &pb.OnUpdateSetResponse{}, nil
}

// OnDeleteSet is called when a dynamic host set is deleted.
func (p *HostPlugin) OnDeleteSet(ctx context.Context, req *pb.OnDeleteSetRequest) (*pb.OnDeleteSetResponse, error) {
	// No-op, AWS host set does not maintain anything that requires
	// cleanup
	return &pb.OnDeleteSetResponse{}, nil
}

// ListHosts returns the list of ec2 hosts and their descriptions.
func (p *HostPlugin) ListHosts(ctx context.Context, req *pb.ListHostsRequest) (*pb.ListHostsResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, errors.BadRequestStatus("catalog is required")
	}

	catalogAttrsRaw := catalog.GetAttributes()
	if catalogAttrsRaw == nil {
		return nil, errors.BadRequestStatus("catalog attributes are required")
	}

	catalogAttributes, err := getCatalogAttributes(catalogAttrsRaw)
	if err != nil {
		return nil, err
	}

	credState, err := credential.AwsCredentialPersistedStateFromProto(
		req.GetPersisted().GetSecrets(),
		catalogAttributes.CredentialAttributes,
		catalogAttributes.DualStack,
		p.testCredStateOpts...)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	catalogState, err := newAwsCatalogPersistedState(
		append([]awsCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, errors.BadRequestStatusf("error loading persisted state: %s", err)
	}

	sets := req.GetSets()
	if sets == nil {
		return nil, errors.BadRequestStatus("sets are required")
	}

	// Build all the queries in advance.
	queries := make([]hostSetQuery, len(sets))
	for i, set := range sets {
		// Validate Id since we use it in output
		if set.GetId() == "" {
			return nil, errors.BadRequestStatus("set id is required")
		}

		if set.GetAttributes() == nil {
			return nil, errors.BadRequestStatusf("set %s attributes are required", set.GetId())
		}
		setAttrs, err := getSetAttributes(set.GetAttributes())
		if err != nil {
			return nil, err
		}

		input, err := buildDescribeInstancesInput(setAttrs, false)
		if err != nil {
			return nil, errors.BadRequestStatusf("error building DescribeInstances parameters for host set id %q: %s", set.GetId(), err)
		}
		queries[i] = hostSetQuery{
			Id:    set.GetId(),
			Input: input,
		}
	}

	opts := []ec2Option{}
	if catalogAttributes.DualStack {
		opts = append(opts, WithDualStack(catalogAttributes.DualStack))
	}

	// Run all queries now and assemble output.
	var maxLen int
	for i, query := range queries {
		output, err := checkHosts(ctx, catalogState, query.Input, opts, catalogAttributes.TargetAccount)
		if err != nil {
			if catalogAttributes.TargetAccount != nil {
				return nil, errors.BadRequestStatusf("unable to list hosts for host set %q: %s", query.Id, err)
			}
			return nil, errors.BadRequestStatusf("error retrieving host results for host set id %q: %s", query.Id, err)
		}

		queries[i].Output = output
		if output == nil {
			continue
		}

		// Process the output here, we will normalize this into a single
		// set of hosts afterwards (possibly removing duplicates).
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				host, err := awsInstanceToHost(instance, catalogAttributes)
				if err != nil {
					return nil, errors.BadRequestStatusf("error processing host results for host set id %q: %s", query.Id, err)
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

func buildFilters(attrs *SetAttributes) ([]types.Filter, error) {
	var filters []types.Filter
	var foundStateFilter bool
	for _, filterAttr := range attrs.Filters {
		// Each filter arrives in "k=v1,v2" format. First, split on equal sign.
		splitFilter := strings.Split(filterAttr, "=")
		switch {
		case len(splitFilter) != 2:
			return nil, errors.BadRequestStatusf("expected filter %q to contain a single equal sign", filterAttr)
		case len(splitFilter[0]) == 0:
			return nil, errors.BadRequestStatusf("filter %q contains an empty filter key", filterAttr)
		case len(splitFilter[1]) == 0:
			return nil, errors.BadRequestStatusf("filter %q contains an empty value", filterAttr)
		}

		filterKey, filterValue := splitFilter[0], splitFilter[1]
		if filterKey == "instance-state-code" || filterKey == "instance-state-name" {
			foundStateFilter = true
		}

		filters = append(filters, types.Filter{
			Name:   aws.String(filterKey),
			Values: strings.Split(filterValue, ","),
		})
	}

	if !foundStateFilter {
		// if there is no explicit instance state filter, add the
		// instance-state-name = ["running"] to the filter set. This
		// ensures that we filter on running instances only at the API
		// side, saving time when processing results.
		filters = append(filters, types.Filter{
			Name:   aws.String("instance-state-name"),
			Values: []string{string(types.InstanceStateNameRunning)},
		})
	}

	return filters, nil
}

func buildDescribeInstancesInput(attrs *SetAttributes, dryRun bool) (*ec2.DescribeInstancesInput, error) {
	filters, err := buildFilters(attrs)
	if err != nil {
		return nil, err
	}

	return &ec2.DescribeInstancesInput{
		DryRun:  aws.Bool(dryRun),
		Filters: filters,
	}, nil
}

// awsInstanceToHost processes data from an ec2.Instance and returns
// a ListHostsResponseHost with the ID and network addresses
// populated.
func awsInstanceToHost(instance types.Instance, catalogAttributes *CatalogAttributes) (*pb.ListHostsResponseHost, error) {
	if aws.ToString(instance.InstanceId) == "" {
		return nil, fmt.Errorf("response integrity error: missing instance id")
	}
	if catalogAttributes == nil {
		return nil, fmt.Errorf("response integrity error: missing catalog attributes")
	}

	result := new(pb.ListHostsResponseHost)

	// External ID is the instance ID.
	result.ExternalId = aws.ToString(instance.InstanceId)

	// External Name is the AWS "Name" tag, if it exists.
	for _, t := range instance.Tags {
		if aws.ToString(t.Key) == ConstInstanceNameTagKey {
			result.ExternalName = aws.ToString(t.Value)
			break
		}
	}

	// First let's get the instance's Private IPv4/DNS, Public IPv4/DNS, and IPv6 addresses
	result.IpAddresses = appendDistinct(result.IpAddresses, instance.PrivateIpAddress, instance.PublicIpAddress, instance.Ipv6Address)
	result.DnsNames = appendDistinct(result.DnsNames, instance.PrivateDnsName, instance.PublicDnsName)

	if catalogAttributes.InstanceAddressesOnly {
		// return early as we already have the instance addresses
		return result, nil
	}

	// Now go through all of the interfaces and sync the IP address of
	// every interface.
	for _, iface := range instance.NetworkInterfaces {
		// Populate default IP addresses/DNS name similar to how we do
		// for the entire instance.
		result.IpAddresses = appendDistinct(result.IpAddresses, iface.PrivateIpAddress)
		result.DnsNames = appendDistinct(result.DnsNames, iface.PrivateDnsName)

		// Iterate through the private IP addresses and log the
		// information.
		for _, addr := range iface.PrivateIpAddresses {
			result.IpAddresses = appendDistinct(result.IpAddresses, addr.PrivateIpAddress)
			result.DnsNames = appendDistinct(result.DnsNames, addr.PrivateDnsName)
			if addr.Association != nil {
				result.IpAddresses = appendDistinct(result.IpAddresses, addr.Association.PublicIp)
				result.DnsNames = appendDistinct(result.DnsNames, addr.Association.PublicDnsName)
			}
		}

		// Add the IPv6 addresses.
		for _, addr := range iface.Ipv6Addresses {
			result.IpAddresses = appendDistinct(result.IpAddresses, addr.Ipv6Address)
		}
	}

	// Done
	return result, nil
}

func checkHosts(ctx context.Context,
	principalCatalogState *awsCatalogPersistedState,
	input *ec2.DescribeInstancesInput,
	opts []ec2Option,
	target *credential.CredentialAttributes,
) (*ec2.DescribeInstancesOutput, error) {
	if principalCatalogState == nil {
		return nil, fmt.Errorf("unable to create EC2 client from catalog state")
	}

	var ec2Client EC2API
	var err error
	if target == nil {
		// use the principal account to execute the DescribeInstances command
		ec2Client, err = principalCatalogState.EC2Client(ctx, opts...)
		if err != nil {
			return nil, err
		}
	} else {
		// use the target account to execute the DescribeInstances command
		ec2Client, err = ec2ClientForTarget(ctx, principalCatalogState, target, opts)
		if err != nil {
			return nil, fmt.Errorf("EC2 client setup failed for target account: %w", err)
		}
	}

	output, err := ec2Client.DescribeInstances(ctx, input)
	if err != nil {
		var awsErr smithy.APIError
		ok := goerrors.As(err, &awsErr)
		if ok && awsErr.ErrorCode() == dryRunOperationErrorCode {
			// successful DryRun validation, no response necessary, no error thrown
			return nil, nil
		}

		if target != nil {
			return nil, fmt.Errorf("EC2 DescribeInstances failed for target account: %w", err)
		}
		return nil, err
	}

	return output, nil
}

// ec2ClientForTarget builds an EC2 client to query the target account.
// The hop is a continuation of the principal session: STS AssumeRole is called
// as the principal to get to the target, then EC2 uses the resulting temporary credentials.
// This is not a second worker-level credential chain on the target attributes.
func ec2ClientForTarget(
	ctx context.Context,
	principalCatalogState *awsCatalogPersistedState,
	target *credential.CredentialAttributes,
	opts []ec2Option) (EC2API, error) {
	// Reuse the principal SDK config (HTTP client, retries, logger, and the
	// principal identity).
	principalCfg, err := principalCatalogState.GenerateCredentialChain(ctx)
	if err != nil {
		return nil, fmt.Errorf("principal AWS configuration could not be loaded: %w", err)
	}
	if principalCfg == nil {
		return nil, fmt.Errorf("nil principal AWS configuration while configuring EC2 client for target account")
	}

	// STS must run as the principal so the target role's trust policy sees that
	// identity, not the worker's. Session name, external ID, and tags are
	// forwarded from attrs when set so the AssumeRole matches the target role's configuration.
	stsClient := sts.NewFromConfig(*principalCfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, target.RoleArn, func(o *stscreds.AssumeRoleOptions) {
		if target.RoleSessionName != "" {
			o.RoleSessionName = target.RoleSessionName
		} else {
			// STS may reject the AssumeRole request if session name is not provided.
			o.RoleSessionName = defaultSessionName
		}
		if target.RoleExternalId != "" {
			o.ExternalID = &target.RoleExternalId
		}
		for k, v := range target.RoleTags {
			o.Tags = append(o.Tags, stsTypes.Tag{
				Key:   aws.String(k),
				Value: aws.String(v),
			})
		}
	})

	// Same worker SDK environment as the principal; only identity and region change.
	targetCfg := principalCfg.Copy()
	targetCfg.Credentials = aws.NewCredentialsCache(provider)
	if target.Region != "" {
		targetCfg.Region = target.Region
	}

	parsed, err := getOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("EC2 client options are invalid: %w", err)
	}
	// Dual-stack is the worker's path to AWS endpoints, not per-account. Apply
	// it on the hopped client the same way EC2Client does for the principal.
	var ec2Opts []func(*ec2.Options)
	if parsed.withDualStack {
		ec2Opts = append(ec2Opts, ec2.WithEndpointResolverV2(&endpointResolver{
			dualStack: parsed.withDualStack,
		}))
	}

	if principalCatalogState.testEC2APIFunc != nil {
		return principalCatalogState.testEC2APIFunc(targetCfg)
	}
	return ec2.NewFromConfig(targetCfg, ec2Opts...), nil
}

// appendDistinct will append the elements to the slice
// if an element is not nil, empty, and does not exist in slice.
func appendDistinct(slice []string, elems ...*string) []string {
	for _, e := range elems {
		value := aws.ToString(e)
		if value == "" || stringInSlice(slice, value) {
			continue
		}
		slice = append(slice, value)
	}
	return slice
}

// stringInSlice returns true if the slice contains the given element.
func stringInSlice(s []string, x string) bool {
	for _, y := range s {
		if x == y {
			return true
		}
	}
	return false
}
