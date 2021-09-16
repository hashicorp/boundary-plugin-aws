package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

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

	// TODO: do something to validate that the region is valid on
	// create
	_, err := getStringValue(attrs, constRegion, true)
	if err != nil {
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

	skipRotate, err := getBoolValue(secrets, constDisableCredentialRotation, false)
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
	return nil, errors.New("not implemented")
}

func (p *AwsPlugin) OnDeleteCatalog(ctx context.Context, req *pb.OnDeleteCatalogRequest) (*pb.OnDeleteCatalogResponse, error) {
	return nil, errors.New("not implemented")
}

func (p *AwsPlugin) OnCreateSet(ctx context.Context, req *pb.OnCreateSetRequest) (*pb.OnCreateSetResponse, error) {
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
