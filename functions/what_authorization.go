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
	"github.com/indykite/indykite-sdk-go/errors"
	authorizationpb "github.com/indykite/indykite-sdk-go/gen/indykite/authorization/v1beta1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"github.com/indykite/opa-indykite-plugin/utilities"
)

func init() {
	rego.RegisterBuiltin3(
		&rego.Function{
			Name: "indy.what_authorized",
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
					types.Named("resourcesTypes", types.NewArray(nil, types.NewAny(
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("type", types.S),
						}, nil),
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("type", types.S),
							types.NewStaticProperty("actions", types.NewArray(nil, types.S)),
						}, nil),
					))),
					types.Named("options", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
				),
				types.Named("authorization_decisions", types.NewObject([]*types.StaticProperty{
					types.NewStaticProperty("decision_time", types.N),
					types.NewStaticProperty("decisions", types.NewObject(nil, types.NewDynamicProperty(
						types.S,
						types.NewObject(nil, types.NewDynamicProperty(
							types.S,
							types.NewObject([]*types.StaticProperty{
								types.NewStaticProperty("externalId", types.B),
							}, nil),
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

			req := &authorizationpb.WhatAuthorizedRequest{}
			req.PolicyTags = parsePolicyTags(optionsObj)
			req.InputParams, err = parseInputParams(optionsObj)
			if err != nil {
				return nil, err
			}
			if err = ast.As(resources.Value, &req.ResourceTypes); err != nil {
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
			var resp *authorizationpb.WhatAuthorizedResponse
			resp, err = client.WhatAuthorizedWithRawRequest(bCtx.Context, req)
			var obj ast.Object

			if statusErr := errors.FromError(err); statusErr != nil {
				if errors.IsServiceError(statusErr) {
					return nil, statusErr
				}
				obj = ast.NewObject(ast.Item(ast.StringTerm("error"), utilities.BuildUserError(statusErr)))
			} else {
				obj = buildWhatAuthorizedObjectFromResponse(resp)
			}

			return &ast.Term{Value: obj}, nil
		},
	)
}

func buildWhatAuthorizedObjectFromResponse(resp *authorizationpb.WhatAuthorizedResponse) ast.Object {
	decisions := ast.NewObject()

	for resourceType, dec := range resp.Decisions {
		actions := ast.NewObject()
		for actionKey, actionValue := range dec.Actions {
			resources := ast.NewArray()
			for _, r := range actionValue.Resources {
				resource := ast.NewTerm(ast.NewObject(
					ast.Item(ast.StringTerm("externalId"), ast.StringTerm(r.ExternalId)),
				))
				resources = resources.Append(resource)
			}
			actions.Insert(ast.StringTerm(actionKey), ast.NewTerm(resources))
		}
		decisions.Insert(ast.StringTerm(resourceType), ast.NewTerm(actions))
	}

	obj := ast.NewObject(
		ast.Item(ast.StringTerm("error"), ast.NullTerm()),
		ast.Item(ast.StringTerm("decision_time"), ast.IntNumberTerm(int(resp.DecisionTime.AsTime().Unix()))),
		ast.Item(ast.StringTerm("decisions"), ast.NewTerm(decisions)),
	)

	return obj
}
