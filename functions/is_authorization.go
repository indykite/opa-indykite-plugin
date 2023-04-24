// Copyright (c) 2022 IndyKite
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
	"github.com/indykite/jarvis-sdk-go/errors"
	authorizationpb "github.com/indykite/jarvis-sdk-go/gen/indykite/authorization/v1beta1"
	identitypb "github.com/indykite/jarvis-sdk-go/gen/indykite/identity/v1beta2"
	objects "github.com/indykite/jarvis-sdk-go/gen/indykite/objects/v1beta1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"

	"github.com/indykite/opa-indykite-plugin/utilities"
)

const (
	termPropertyType  = "property_type"
	termPropertyValue = "property_value"
)

func init() {
	rego.RegisterBuiltin3(
		&rego.Function{
			Name: "indy.is_authorized",
			Decl: types.NewFunction(
				types.Args(
					types.Named("digital_twin_identifier", types.NewAny(
						types.S,
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("digital_twin_id", types.S),
							types.NewStaticProperty("tenant_id", types.S),
						}, nil),
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty(termPropertyType, types.S),
							types.NewStaticProperty(termPropertyValue, types.S),
						}, nil),
					)),
					types.Named("resources", types.NewArray(nil, types.NewObject([]*types.StaticProperty{
						types.NewStaticProperty("id", types.S),
						types.NewStaticProperty("type", types.S),
						types.NewStaticProperty("actions", types.NewArray(nil, types.S)),
					}, nil))),
					types.Named("options", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
				),
				types.Named("authorization_decisions", types.NewObject([]*types.StaticProperty{
					types.NewStaticProperty("decision_time", types.N),
					types.NewStaticProperty("decisions", types.NewObject(nil, types.NewDynamicProperty(
						types.S,
						types.NewObject(nil, types.NewDynamicProperty(
							types.S,
							types.NewObject(nil, types.NewDynamicProperty(
								types.S,
								types.NewObject(nil, types.NewDynamicProperty(
									types.S,
									types.NewObject([]*types.StaticProperty{
										types.NewStaticProperty("allow", types.B),
									}, nil),
								)),
							)),
						)),
					))),
				}, nil)),
			),
		},
		func(bCtx rego.BuiltinContext, dtIdentifier, resources, options *ast.Term) (*ast.Term, error) {
			optionsObj, err := validateOptionOperand(options, 2)
			if err != nil {
				return nil, err
			}

			req := &authorizationpb.IsAuthorizedRequest{}
			req.PolicyTags = parsePolicyTags(optionsObj)
			req.InputParams, err = parseInputParams(optionsObj)
			if err != nil {
				return nil, err
			}
			if err = ast.As(resources.Value, &req.Resources); err != nil {
				return nil, err
			}

			digitalTwinIdentifier, err := extractDigitalTwinIdentifier(dtIdentifier.Value, 1)
			if err != nil {
				return nil, err
			}
			req.Subject = &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_DigitalTwinIdentifier{
					DigitalTwinIdentifier: digitalTwinIdentifier,
				},
			}

			client, err := AuthorizationClient(bCtx.Context)
			if err != nil {
				return nil, err
			}
			var resp *authorizationpb.IsAuthorizedResponse
			resp, err = client.IsAuthorizedWithRawRequest(bCtx.Context, req)
			var obj ast.Object

			if statusErr := errors.FromError(err); statusErr != nil {
				if errors.IsServiceError(statusErr) {
					return nil, statusErr
				}
				obj = ast.NewObject(ast.Item(ast.StringTerm("error"), utilities.BuildUserError(statusErr)))
			} else {
				obj = buildIsAuthorizedObjectFromResponse(resp)
			}

			return &ast.Term{Value: obj}, nil
		},
	)
}

func extractDigitalTwinIdentifier(identifierValue ast.Value, pos int) (*identitypb.DigitalTwinIdentifier, error) {
	switch identifier := identifierValue.(type) {
	case ast.String:
		return &identitypb.DigitalTwinIdentifier{Filter: &identitypb.DigitalTwinIdentifier_AccessToken{
			AccessToken: string(identifier),
		}}, nil
	case ast.Object:
		isDigitalTwinObject := identifier.Get(ast.StringTerm("digital_twin_id")) != nil
		if isDigitalTwinObject {
			return parseDigitalTwin(identifier)
		}
		return parseDigitalTwinProperty(identifier)
	}
	// Next line is unreachable. OPA will complain based on declaration of function, when types do not match.
	return nil, builtins.NewOperandTypeErr(pos, identifierValue, "string", "object")
}

func parseDigitalTwinProperty(identifier ast.Object) (*identitypb.DigitalTwinIdentifier, error) {
	var propertyType, propertyValue ast.String
	propertyType = identifier.Get(ast.StringTerm(termPropertyType)).Value.(ast.String)
	propertyValue = identifier.Get(ast.StringTerm(termPropertyValue)).Value.(ast.String)

	return &identitypb.DigitalTwinIdentifier{Filter: &identitypb.DigitalTwinIdentifier_PropertyFilter{
		PropertyFilter: &identitypb.PropertyFilter{
			Type:  string(propertyType),
			Value: objects.String(string(propertyValue)),
		},
	}}, nil
}

func parseDigitalTwin(identifier ast.Object) (*identitypb.DigitalTwinIdentifier, error) {
	var dtID, tenantID ast.String
	dtID = identifier.Get(ast.StringTerm("digital_twin_id")).Value.(ast.String)
	tenantID = identifier.Get(ast.StringTerm("tenant_id")).Value.(ast.String)

	return &identitypb.DigitalTwinIdentifier{Filter: &identitypb.DigitalTwinIdentifier_DigitalTwin{
		DigitalTwin: &identitypb.DigitalTwin{Id: string(dtID), TenantId: string(tenantID)},
	}}, nil
}

func buildIsAuthorizedObjectFromResponse(resp *authorizationpb.IsAuthorizedResponse) ast.Object {
	decisions := ast.NewObject()

	for resourceType, dec := range resp.Decisions {
		resources := ast.NewObject()
		for resourceKey, resourceValue := range dec.Resources {
			actions := ast.NewObject()
			for actionKey, actionValue := range resourceValue.Actions {
				actions.Insert(ast.StringTerm(actionKey), ast.NewTerm(ast.NewObject(
					ast.Item(ast.StringTerm("allow"), ast.BooleanTerm(actionValue.Allow)),
				)))
			}
			resources.Insert(ast.StringTerm(resourceKey), ast.NewTerm(actions))
		}
		decisions.Insert(ast.StringTerm(resourceType), ast.NewTerm(resources))
	}

	obj := ast.NewObject(
		ast.Item(ast.StringTerm("error"), ast.NullTerm()),
		ast.Item(ast.StringTerm("decision_time"), ast.IntNumberTerm(int(resp.DecisionTime.AsTime().Unix()))),
		ast.Item(ast.StringTerm("decisions"), ast.NewTerm(decisions)),
	)

	return obj
}
