// Copyright (c) 2024 IndyKite
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utilities

import (
	"fmt"
	"time"

	objects "github.com/indykite/indykite-sdk-go/gen/indykite/objects/v1beta2"
	"github.com/open-policy-agent/opa/ast"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type transformer[T any] func(obj ast.Object) (*T, error)

func getValue[T any](getters ...transformer[T]) transformer[T] {
	return func(obj ast.Object) (*T, error) {
		for _, getter := range getters {
			res, err := getter(obj)
			if err != nil {
				return nil, fmt.Errorf("invalid value: %v", obj)
			}
			if res != nil {
				return res, nil
			}
		}

		if obj.Len() == 0 {
			return nil, nil
		}

		return nil, fmt.Errorf("invalid value: %v", obj)
	}
}

func getObjectsValue(term *ast.Term) (*objects.Value, error) {
	valueObj, ok := term.Value.(ast.Object)
	if !ok {
		return nil, fmt.Errorf("invalid value: %v", term)
	}

	// Using loop over transformer functions to lower the cyclomatic complexity reported by DeepSource
	return getValue[objects.Value](
		getStringValue,
		getBoolValue,
		getIntegerValue,
		getDoubleValue,
		getTimeValue,
		getDurationValue,
		getArrayValue,
		getMapValue,
	)(valueObj)
}

func getParamValue[T any](value ast.Object, keys []string) (*T, error) {
	var paramValue *ast.Term
	for _, key := range keys {
		paramValue = value.Get(ast.StringTerm(key))
		if paramValue != nil {
			break
		}
	}
	if paramValue == nil {
		return nil, nil
	}
	if typedValue, ok := paramValue.Value.(T); ok {
		return &typedValue, nil
	}
	return nil, fmt.Errorf("invalid value type: %v", paramValue.Value)
}

func getStringValue(obj ast.Object) (*objects.Value, error) {
	paramValue, err := getParamValue[ast.String](obj, stringValueKeys)
	if err != nil {
		return nil, err
	}
	if paramValue == nil {
		return nil, nil
	}
	return &objects.Value{
		Type: &objects.Value_StringValue{
			StringValue: string(*paramValue),
		},
	}, nil
}

func getBoolValue(value ast.Object) (*objects.Value, error) {
	paramValue, err := getParamValue[ast.Boolean](value, boolValueKeys)
	if err != nil {
		return nil, err
	}
	if paramValue == nil {
		return nil, nil
	}
	return &objects.Value{
		Type: &objects.Value_BoolValue{
			BoolValue: bool(*paramValue),
		},
	}, nil
}

func getIntegerValue(value ast.Object) (*objects.Value, error) {
	paramValue, err := getParamValue[ast.Number](value, integerValueKeys)
	if err != nil {
		return nil, err
	}
	if paramValue == nil {
		return nil, nil
	}
	intVal, ok := paramValue.Int64()
	if !ok {
		return nil, fmt.Errorf("invalid integer value: %v", paramValue)
	}
	return &objects.Value{
		Type: &objects.Value_IntegerValue{
			IntegerValue: intVal,
		},
	}, nil
}

func getDoubleValue(value ast.Object) (*objects.Value, error) {
	paramValue, err := getParamValue[ast.Number](value, doubleValueKeys)
	if err != nil {
		return nil, err
	}
	if paramValue == nil {
		return nil, nil
	}
	doubleVal, ok := paramValue.Float64()
	if !ok {
		return nil, fmt.Errorf("invalid integer value: %v", paramValue)
	}
	return &objects.Value{
		Type: &objects.Value_DoubleValue{
			DoubleValue: doubleVal,
		},
	}, nil
}

func getTimeValue(value ast.Object) (*objects.Value, error) {
	paramValue, err := getParamValue[ast.String](value, timeValueKeys)
	if err != nil {
		return nil, err
	}
	if paramValue == nil {
		return nil, nil
	}
	timeValue, err := time.Parse("2006-01-02T15:04:05Z0700", string(*paramValue))
	if err != nil {
		return nil, err
	}
	return &objects.Value{
		Type: &objects.Value_TimeValue{
			TimeValue: timestamppb.New(timeValue),
		},
	}, nil
}

func getDurationValue(value ast.Object) (*objects.Value, error) {
	paramValue, err := getParamValue[ast.String](value, durationValueKeys)
	if err != nil {
		return nil, err
	}
	if paramValue == nil {
		return nil, nil
	}
	durationValue, err := time.ParseDuration(string(*paramValue))
	if err != nil {
		return nil, err
	}
	return &objects.Value{
		Type: &objects.Value_DurationValue{
			DurationValue: durationpb.New(durationValue),
		},
	}, nil
}

var (
	valuesKeys = []string{"values"}
)

func getArrayValue(value ast.Object) (*objects.Value, error) {
	obj, err := getParamValue[ast.Object](value, arrayValueKeys)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, nil
	}
	var paramValue *ast.Value
	paramValue, err = getParamValue[ast.Value](*obj, valuesKeys)
	if err != nil {
		return nil, err
	}
	if paramValue == nil {
		return nil, nil
	}
	arrayValue, ok := (*paramValue).(*ast.Array)
	if !ok {
		return nil, fmt.Errorf("invalid array value: %v", value)
	}
	values := make([]*objects.Value, arrayValue.Len())
	for i := 0; i < arrayValue.Len(); i++ {
		v, err := getObjectsValue(arrayValue.Elem(i))
		if err != nil {
			return nil, err
		}
		values[i] = v
	}
	return &objects.Value{
		Type: &objects.Value_ArrayValue{
			ArrayValue: &objects.Array{
				Values: values,
			},
		},
	}, nil
}

var (
	fieldsKeys = []string{"fields"}
)

func getMapValue(value ast.Object) (*objects.Value, error) {
	obj, err := getParamValue[ast.Object](value, mapValueKeys)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, nil
	}
	var paramValue *ast.Value
	paramValue, err = getParamValue[ast.Value](*obj, fieldsKeys)
	if err != nil {
		return nil, err
	}
	if paramValue == nil {
		return nil, nil
	}
	valueMap, ok := (*paramValue).(ast.Object)
	if !ok {
		return nil, fmt.Errorf("invalid map value: %v", value)
	}
	fields := make(map[string]*objects.Value, valueMap.Len())
	for _, key := range valueMap.Keys() {
		v, err := getObjectsValue(valueMap.Get(key))
		if err != nil {
			return nil, err
		}
		fields[string(key.Value.(ast.String))] = v
	}
	return &objects.Value{
		Type: &objects.Value_MapValue{
			MapValue: &objects.Map{
				Fields: fields,
			},
		},
	}, nil
}
