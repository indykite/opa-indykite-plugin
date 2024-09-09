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
	authorizationpb "github.com/indykite/indykite-sdk-go/gen/indykite/authorization/v1beta1"
	objects "github.com/indykite/indykite-sdk-go/gen/indykite/objects/v1beta1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

const inputParamsKey = "inputParams"
const policyTagsKey = "policyTags"
const subjectTypeToken = "token"
const subjectTypeID = "id"
const subjectTypeProperty = "property"
const subjectTypeExternalID = "external_id"

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

func parsePolicyTags(options *ast.Term) []string {
	if options == nil {
		return nil
	}

	policyTagsArray, ok := options.Value.(*ast.Array)
	if !ok {
		return nil
	}

	result := make([]string, 0, policyTagsArray.Len())
	policyTagsArray.Foreach(func(value *ast.Term) {
		result = append(result, string(value.Value.(ast.String)))
	})

	return result
}

func extractSubject(subjectValue ast.Value, pos int) (*authorizationpb.Subject, error) {
	subject, ok := subjectValue.(ast.Object)
	if !ok {
		return nil, builtins.NewOperandTypeErr(pos, subjectValue, "object")
	}
	idObject := subject.Get(ast.StringTerm("id"))
	if idObject == nil {
		return nil, builtins.NewOperandTypeErr(pos, subjectValue, "id")
	}
	idValue := idObject.Value.(ast.String)

	switch getSubjectType(subject) {
	case subjectTypeToken:
		return &authorizationpb.Subject{Subject: &authorizationpb.Subject_AccessToken{
			AccessToken: string(idValue),
		}}, nil
	case subjectTypeID:
		return &authorizationpb.Subject{Subject: &authorizationpb.Subject_DigitalTwinId{
			DigitalTwinId: &authorizationpb.DigitalTwin{Id: string(idValue)},
		}}, nil
	case subjectTypeProperty:
		propertyObject := subject.Get(ast.StringTerm("property"))
		if propertyObject == nil {
			return nil, builtins.NewOperandTypeErr(pos, subjectValue, "property")
		}
		propertyValue := propertyObject.Value.(ast.String)
		return &authorizationpb.Subject{
			Subject: &authorizationpb.Subject_DigitalTwinProperty{
				DigitalTwinProperty: &authorizationpb.Property{
					Type:  string(propertyValue),
					Value: objects.String(string(idValue)),
				},
			},
		}, nil
	case subjectTypeExternalID:
		nodeTypeObject := subject.Get(ast.StringTerm("type"))
		if nodeTypeObject == nil {
			return nil, builtins.NewOperandTypeErr(pos, subjectValue, "type")
		}
		nodeType := nodeTypeObject.Value.(ast.String)
		return &authorizationpb.Subject{
			Subject: &authorizationpb.Subject_ExternalId{
				ExternalId: &authorizationpb.ExternalID{
					Type:       string(nodeType),
					ExternalId: string(idValue),
				},
			},
		}, nil
	}

	// Next line is unreachable. OPA will complain based on declaration of function, when types do not match.
	return nil, builtins.NewOperandTypeErr(pos, subjectValue, "object")
}

func getSubjectType(subject ast.Object) string {
	typeObject := subject.Get(ast.StringTerm("subjectType"))
	if typeObject == nil {
		return subjectTypeToken
	}
	typeValue := typeObject.Value.(ast.String)
	return string(typeValue)
}
