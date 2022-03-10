package plugin

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func invalidArgumentError(msg string, f map[string]string) error {
	var fieldMsgs []string
	for field, val := range f {
		fieldMsgs = append(fieldMsgs, fmt.Sprintf("%s: %s", field, val))
	}
	if len(fieldMsgs) > 0 {
		sort.Strings(fieldMsgs)
		msg = fmt.Sprintf("%s: [%s]", msg, strings.Join(fieldMsgs, ", "))
	}
	return status.Error(codes.InvalidArgument, msg)
}

// CatalogAttributes is a Go-native representation of the Attributes
// map.
type CatalogAttributes struct {
	Region                    string
	DisableCredentialRotation bool
}

func getCatalogAttributes(in *structpb.Struct) (*CatalogAttributes, error) {
	unknownFields := structFields(in)
	result := new(CatalogAttributes)
	badFields := make(map[string]string)

	var err error
	result.Region, err = getStringValue(in, constRegion, true)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", constRegion)] = err.Error()
	}
	delete(unknownFields, constRegion)

	result.DisableCredentialRotation, err = getBoolValue(in, constDisableCredentialRotation, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", constDisableCredentialRotation)] = err.Error()
	}
	delete(unknownFields, constDisableCredentialRotation)

	for s := range unknownFields {
		badFields[fmt.Sprintf("attributes.%s", s)] = "unrecognized field"
	}

	if len(badFields) > 0 {
		return nil, invalidArgumentError("Invalid arguments in catalog attributes", badFields)
	}

	return result, nil
}

// CatalogSecrets is a Go-native representation of the Secrets map.
type CatalogSecrets struct {
	AccessKeyId     string
	SecretAccessKey string
}

func getCatalogSecrets(in *structpb.Struct) (*CatalogSecrets, error) {
	unknownFields := structFields(in)
	result := new(CatalogSecrets)
	badFields := make(map[string]string)

	var err error
	result.AccessKeyId, err = getStringValue(in, constAccessKeyId, true)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", constAccessKeyId)] = err.Error()
	}
	delete(unknownFields, constAccessKeyId)

	result.SecretAccessKey, err = getStringValue(in, constSecretAccessKey, true)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", constSecretAccessKey)] = err.Error()
	}
	delete(unknownFields, constSecretAccessKey)

	for s := range unknownFields {
		badFields[fmt.Sprintf("secrets.%s", s)] = "unrecognized field"
	}

	if len(badFields) > 0 {
		return nil, invalidArgumentError("Error in the secrets provided", badFields)
	}

	return result, nil
}

// SetAttributes is a Go-native representation of the Attributes map that can be
// used for decoding the incoming map via mapstructure.
type SetAttributes struct {
	Filters []string
}

func getSetAttributes(in *structpb.Struct) (*SetAttributes, error) {
	var setAttrs SetAttributes

	// Quick validation to ensure that there's no non-filter attributes
	// here for now. Make this more complex if we add more attributes
	// to host sets.
	unknownFields := structFields(in)
	badFields := make(map[string]string)
	delete(unknownFields, constDescribeInstancesFilters)
	for a := range unknownFields {
		badFields[fmt.Sprintf("attributes.%s", a)] = "unrecognized field"
	}
	if len(badFields) > 0 {
		return nil, invalidArgumentError("Error in the attributes provided", badFields)
	}

	// Mapstructure complains if it expects a slice as output and sees a scalar
	// value. Rather than use WeakDecode and risk unintended consequences, I'm
	// manually making this change if necessary.
	inMap := in.AsMap()
	if filtersRaw, ok := inMap[constDescribeInstancesFilters]; ok {
		switch filterVal := filtersRaw.(type) {
		case string:
			inMap[constDescribeInstancesFilters] = []string{filterVal}
		}
	}

	if err := mapstructure.Decode(inMap, &setAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error decoding set attributes: %s", err)
	}

	return &setAttrs, nil
}

func getStringValue(in *structpb.Struct, k string, required bool) (string, error) {
	mv := in.GetFields()
	v, ok := mv[k]
	if !ok {
		if required {
			return "", fmt.Errorf("missing required value %q", k)
		}

		return "", nil
	}

	s, ok := v.AsInterface().(string)
	if !ok {
		return "", fmt.Errorf("unexpected type for value %q: want string, got %T", k, v.AsInterface())
	}

	if s == "" && required {
		return "", fmt.Errorf("value %q cannot be empty", k)
	}

	return s, nil
}

func getBoolValue(in *structpb.Struct, k string, required bool) (bool, error) {
	mv := in.GetFields()
	v, ok := mv[k]
	if !ok {
		if required {
			return false, fmt.Errorf("missing required value %q", k)
		}

		return false, nil
	}

	b, ok := v.AsInterface().(bool)
	if !ok {
		return false, fmt.Errorf("unexpected type for value %q: want bool, got %T", k, v.AsInterface())
	}

	return b, nil
}

func getTimeValue(in *structpb.Struct, k string) (time.Time, error) {
	mv := in.GetFields()
	v, ok := mv[k]
	if !ok {
		return time.Time{}, nil
	}

	tRaw, ok := v.AsInterface().(string)
	if !ok {
		return time.Time{}, fmt.Errorf("unexpected type for value %q: want string, got %T", k, v.AsInterface())
	}

	t, err := time.Parse(time.RFC3339Nano, tRaw)
	if err != nil {
		return time.Time{}, fmt.Errorf("could not parse time in value %q: %w", k, err)
	}

	return t, nil
}

func structFields(s *structpb.Struct) map[string]struct{} {
	m := make(map[string]struct{}, len(s.GetFields()))
	for k := range s.GetFields() {
		m[k] = struct{}{}
	}

	return m
}

func keysAsString(m map[string]struct{}) string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}

	sort.Strings(s)
	return strings.Join(s, ", ")
}
