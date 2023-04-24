// Copyright (c) 2023 IndyKite
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

package functions

import (
	authorizationpb "github.com/indykite/jarvis-sdk-go/gen/indykite/authorization/v1beta1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

const inputParamsKey = "input_params"
const policyTagsKey = "policy_tags"

var allowedKeyNames = [...]string{
	inputParamsKey,
	policyTagsKey,
}

var allowedKeys = ast.NewSet()

func init() {
	createAllowedKeys()
}

func createAllowedKeys() {
	for _, element := range allowedKeyNames {
		allowedKeys.Add(ast.StringTerm(element))
	}
}

func validateOptionOperand(term *ast.Term, pos int) (ast.Object, error) {
	obj, err := builtins.ObjectOperand(term.Value, pos)
	if err != nil {
		return nil, err
	}

	requestKeys := ast.NewSet(obj.Keys()...)

	invalidKeys := requestKeys.Diff(allowedKeys)
	if invalidKeys.Len() != 0 {
		return nil, builtins.NewOperandErr(pos, "invalid request parameters(s): %v", invalidKeys)
	}

	return obj, nil
}

func parsePolicyTags(options ast.Object) []string {
	var result []string

	policyTagsValueTerm := getOptionsValue(options, policyTagsKey)
	if policyTagsValueTerm == nil {
		return result
	}

	policyTagsArray, ok := policyTagsValueTerm.Value.(*ast.Array)
	if !ok {
		return result
	}

	policyTagsArray.Foreach(func(t *ast.Term) {
		switch v := t.Value.(type) {
		case ast.String:
			result = append(result, string(v))
		default:
			return
		}
	})

	return result
}

func parseInputParams(options ast.Object) (map[string]*authorizationpb.InputParam, error) {
	result := map[string]*authorizationpb.InputParam{}

	inputParamsValueTerm := getOptionsValue(options, inputParamsKey)
	if inputParamsValueTerm == nil {
		return result, nil
	}

	inputParamObj, ok := inputParamsValueTerm.Value.(ast.Object)
	if !ok {
		return result, nil
	}

	for _, key := range inputParamObj.Keys() {
		inputParamKey := string(key.Value.(ast.String))
		inputParamValue, err := parseInputParam(inputParamsValueTerm.Get(key))
		if err != nil {
			return nil, err
		}
		result[inputParamKey] = inputParamValue
	}

	return result, nil
}

func getOptionsValue(options ast.Object, key string) *ast.Term {
	for _, k := range options.Keys() {
		if string(k.Value.(ast.String)) == key {
			return options.Get(k)
		}
	}
	return nil
}

func parseInputParam(value *ast.Term) (*authorizationpb.InputParam, error) {
	switch v := value.Value.(type) {
	case ast.String:
		return &authorizationpb.InputParam{Value: &authorizationpb.InputParam_StringValue{StringValue: string(v)}}, nil
	case ast.Number:
		if integerValue, isNumber := v.Int64(); isNumber {
			return &authorizationpb.InputParam{
				Value: &authorizationpb.InputParam_IntegerValue{IntegerValue: integerValue},
			}, nil
		} else if doubleValue, isDouble := v.Float64(); isDouble {
			return &authorizationpb.InputParam{
				Value: &authorizationpb.InputParam_DoubleValue{DoubleValue: doubleValue},
			}, nil
		}
	case ast.Boolean:
		return &authorizationpb.InputParam{Value: &authorizationpb.InputParam_BoolValue{BoolValue: bool(v)}}, nil
	}
	// Next line is unreachable. OPA will complain based on declaration of function, when types do not match.
	return nil, builtins.NewOperandTypeErr(3, value.Value, "string", "number", "boolean")
}
