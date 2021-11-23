package plugin

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"google.golang.org/protobuf/types/known/structpb"
)

// CatalogAttributes is a Go-native representation of the Attributes
// map.
type CatalogAttributes struct {
	Region                    string
	DisableCredentialRotation bool
}

func getCatalogAttributes(in *structpb.Struct) (*CatalogAttributes, error) {
	unknownFields := structFields(in)
	result := new(CatalogAttributes)

	var err error
	result.Region, err = getStringValue(in, constRegion, true)
	if err != nil {
		return nil, err
	}
	delete(unknownFields, constRegion)

	result.DisableCredentialRotation, err = getBoolValue(in, constDisableCredentialRotation, false)
	if err != nil {
		return nil, err
	}
	delete(unknownFields, constDisableCredentialRotation)

	if len(unknownFields) != 0 {
		return nil, fmt.Errorf("unknown catalog attribute fields provided: %s", keysAsString(unknownFields))
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

	var err error
	result.AccessKeyId, err = getStringValue(in, constAccessKeyId, true)
	if err != nil {
		return nil, err
	}
	delete(unknownFields, constAccessKeyId)

	result.SecretAccessKey, err = getStringValue(in, constSecretAccessKey, true)
	if err != nil {
		return nil, err
	}
	delete(unknownFields, constSecretAccessKey)

	if len(unknownFields) != 0 {
		return nil, fmt.Errorf("unknown catalog secret fields provided: %s", keysAsString(unknownFields))
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
	delete(unknownFields, constDescribeInstancesFilters)
	if len(unknownFields) != 0 {
		return nil, fmt.Errorf("unknown set attribute fields provided: %s", keysAsString(unknownFields))
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
		return nil, fmt.Errorf("error decoding set attributes: %w", err)
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
