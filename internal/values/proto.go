// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package values

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

// GetStringValue returns a string value and no error if the given key
// is found in the provided proto struct input. An error is returned
// if the key is not found or the value type is not a string. An error is
// returned if the parameter argument "required" is set to true
// and the value from the proto struct input is empty.
func GetStringValue(in *structpb.Struct, k string, required bool) (string, error) {
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

// GetBoolValue returns a boolean value and no error if the given key
// is found in the provided proto struct input. An error is returned
// if the key is not found or the value type is not a bool.
func GetBoolValue(in *structpb.Struct, k string, required bool) (bool, error) {
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

// GetTimeValue returns a time.Time value and no error if the given key
// is found in the provided proto struct input. An error is returned
// if the key is not found or the value type is not a parsable. The
// expected time layout is RFC3339Nano.
func GetTimeValue(in *structpb.Struct, k string) (time.Time, error) {
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

// GetMapStringString returns a map[string]string value and no error if the given key
// is found in the provided proto struct input. An error is returned if the key
// is not found or the value type is not map[string]string.
func GetMapStringString(in *structpb.Struct, k string, required bool) (map[string]string, error) {
	mv := in.GetFields()
	v, ok := mv[k]
	if !ok {
		if required {
			return nil, fmt.Errorf("missing required value %q", k)
		}
		return nil, nil
	}
	result := map[string]string{}
	m, ok := v.AsInterface().(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected type for value %q: want map[string]string, got %T", k, v.AsInterface())
	}
	for mapKey, mapValue := range m {
		e, ok := mapValue.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected type for value in map[%q]: want string, got %T", mapKey, mapValue)
		}
		result[mapKey] = e
	}
	return result, nil
}

// StructFields returns a map[string]struct{} of the
// proto struct input.
func StructFields(s *structpb.Struct) map[string]struct{} {
	m := make(map[string]struct{}, len(s.GetFields()))
	for k := range s.GetFields() {
		m[k] = struct{}{}
	}

	return m
}
