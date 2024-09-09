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
	authorizationpb "github.com/indykite/indykite-sdk-go/gen/indykite/authorization/v1beta1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

// ParseInputParams parses inputParams to a map of param's name to [authorizationpb.InputParam].
func ParseInputParams(inputParams *ast.Term, pos int) (map[string]*authorizationpb.InputParam, error) {
	if inputParams == nil {
		return nil, nil
	}

	inputParamObj, ok := inputParams.Value.(ast.Object)
	if !ok {
		return nil, nil
	}

	result := map[string]*authorizationpb.InputParam{}

	for _, key := range inputParamObj.Keys() {
		inputParamKey := string(key.Value.(ast.String))
		inputParamValue, err := parseInputParamValue(key, inputParamObj.Get(key), pos)
		if err != nil {
			return nil, err
		}
		result[inputParamKey] = inputParamValue
	}

	return result, nil
}

var (
	stringValueKeys   = []string{"string_value", "stringValue"}
	boolValueKeys     = []string{"bool_value", "boolValue"}
	integerValueKeys  = []string{"integer_value", "integerValue"}
	doubleValueKeys   = []string{"double_value", "doubleValue"}
	timeValueKeys     = []string{"time_value", "timeValue"}
	durationValueKeys = []string{"duration_value", "durationValue"}
	arrayValueKeys    = []string{"array_value", "arrayValue"}
	mapValueKeys      = []string{"map_value", "mapValue"}
)

func getStringInputParam(value ast.Object) (*authorizationpb.InputParam, error) {
	val, err := getStringValue(value)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return &authorizationpb.InputParam{
		Value: &authorizationpb.InputParam_StringValue{
			StringValue: val.GetStringValue(),
		},
	}, nil
}

func getBoolInputParam(value ast.Object) (*authorizationpb.InputParam, error) {
	val, err := getBoolValue(value)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return &authorizationpb.InputParam{
		Value: &authorizationpb.InputParam_BoolValue{
			BoolValue: val.GetBoolValue(),
		},
	}, nil
}

func getIntegerInputParam(value ast.Object) (*authorizationpb.InputParam, error) {
	val, err := getIntegerValue(value)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return &authorizationpb.InputParam{
		Value: &authorizationpb.InputParam_IntegerValue{
			IntegerValue: val.GetIntegerValue(),
		},
	}, nil
}

func getDoubleInputParam(value ast.Object) (*authorizationpb.InputParam, error) {
	val, err := getDoubleValue(value)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return &authorizationpb.InputParam{
		Value: &authorizationpb.InputParam_DoubleValue{
			DoubleValue: val.GetDoubleValue(),
		},
	}, nil
}

func getTimeInputParam(value ast.Object) (*authorizationpb.InputParam, error) {
	val, err := getTimeValue(value)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return &authorizationpb.InputParam{
		Value: &authorizationpb.InputParam_TimeValue{
			TimeValue: val.GetTimeValue(),
		},
	}, nil
}

func getDurationInputParam(value ast.Object) (*authorizationpb.InputParam, error) {
	val, err := getDurationValue(value)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return &authorizationpb.InputParam{
		Value: &authorizationpb.InputParam_DurationValue{
			DurationValue: val.GetDurationValue(),
		},
	}, nil
}

func getArrayInputParam(value ast.Object) (*authorizationpb.InputParam, error) {
	val, err := getArrayValue(value)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return &authorizationpb.InputParam{
		Value: &authorizationpb.InputParam_ArrayValue{
			ArrayValue: val.GetArrayValue(),
		},
	}, nil
}

func getMapInputParam(value ast.Object) (*authorizationpb.InputParam, error) {
	val, err := getMapValue(value)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return &authorizationpb.InputParam{
		Value: &authorizationpb.InputParam_MapValue{
			MapValue: val.GetMapValue(),
		},
	}, nil
}

func parseInputParamValue(key, value *ast.Term, pos int) (*authorizationpb.InputParam, error) {
	valueObj, ok := value.Value.(ast.Object)
	if !ok {
		return nil, builtins.NewOperandErr(pos, "invalid input parameter %s: %v", key, value)
	}

	// Using loop over transformer functions to lower the cyclomatic complexity reported by DeepSource
	res, err := getValue[authorizationpb.InputParam](
		getStringInputParam,
		getBoolInputParam,
		getIntegerInputParam,
		getDoubleInputParam,
		getTimeInputParam,
		getDurationInputParam,
		getArrayInputParam,
		getMapInputParam,
	)(valueObj)

	if err != nil {
		return nil, builtins.NewOperandErr(pos, "invalid input parameter %s: %v", key, err)
	}

	return res, nil
}
