package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/iam"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"google.golang.org/protobuf/types/known/structpb"
)

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

	if err := validateRegionValue(attrs); err != nil {
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
	}

	return &pb.OnCreateCatalogResponse{
		Persisted: state.ToProto(),
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
	if secrets == nil {
		// We will be updating secrets this run, but what exactly that
		// means will be determined later.
		updateSecrets = true
	}

	attrs := catalog.GetAttributes()
	if attrs == nil {
		return nil, errors.New("new catalog missing attributes")
	}

	// Validate the region.
	if err := validateRegionValue(attrs); err != nil {
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
	return &pb.OnCreateCatalogResponse{
		Persisted: state.ToProto(),
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

	return nil, nil
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

	// Validate the region.
	if err := validateRegionValue(catalogAttrs); err != nil {
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

  // validate the request by populating the 

	return nil, errors.New("not implemented")
}

func (p *AwsPlugin) OnUpdateSet(ctx context.Context, req *pb.OnUpdateSetRequest) (*pb.OnUpdateSetResponse, error) {
	return nil, errors.New("not implemented")
}

func (p *AwsPlugin) OnDeleteSet(ctx context.Context, req *pb.OnDeleteSetRequest) (*pb.OnDeleteSetResponse, error) {
	return nil, errors.New("not implemented")
}

func (p *AwsPlugin) ListHosts(ctx context.Context, req *pb.ListHostsRequest) (*pb.ListHostsResponse, error) {
	return nil, errors.New("not implemented")
}

type awsCatalogPersistedState struct {
	AccessKeyId          string
	SecretAccessKey      string
	CredsLastRotatedTime time.Time
}

func awsCatalogPersistedStateFromProto(in *pb.HostCatalogPersisted) (*awsCatalogPersistedState, error) {
	data := in.GetData()
	if data != nil {
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

	credsLastRotatedTime, err := getTimeValue(data, constDisableCredentialRotation)
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

func (s *awsCatalogPersistedState) RotateCreds() error {
	c, err := awsutil.NewCredentialsConfig(
		awsutil.WithAccessKey(s.AccessKeyId),
		awsutil.WithSecretKey(s.SecretAccessKey),
	)
	if err != nil {
		return fmt.Errorf("error loading credentials: %w", err)
	}

	if err := c.RotateKeys(); err != nil {
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

func validateRegionValue(in *structpb.Struct) error {
	region, err := getStringValue(in, constRegion, true)
	if err != nil {
		return err
	}

	_, found := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
	if !found {
		return fmt.Errorf("not a valid region: %s", region)
	}

	return nil
}

func buildFilters(in *structpb.Struct) ([]*ec2.Filter, error) {
	var filters []*ec2.Filter
  m, err := 
  m := in.AsMap()
	for k, v := range m[constDescribeInstancesFilters] {
		w, ok := v.([]interface{})
    if !ok {
      return nil, 
    }
		var filterValues []*string
		for _, e := range m["values"].([]interface{}) {
			filterValues = append(filterValues, aws.String(e.(string)))
		}
		filters = append(filters, &ec2.Filter{
			Name:   aws.String(m["name"].(string)),
			Values: filterValues,
		})
	}
	return filters
}
