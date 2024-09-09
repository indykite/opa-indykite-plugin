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
	rego.RegisterBuiltin4(
		&rego.Function{
			Name: "indy.what_authorized",
			Decl: types.NewFunction(
				types.Args(
					types.Named("subject", types.NewAny(
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("id", types.S),
						}, nil),
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("id", types.S),
							types.NewStaticProperty("subjectType", types.S),
						}, nil),
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("id", types.S),
							types.NewStaticProperty("subjectType", types.S),
							types.NewStaticProperty("property", types.S),
						}, nil),
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("id", types.S),
							types.NewStaticProperty("subjectType", types.S),
							types.NewStaticProperty("type", types.S),
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
					types.Named(inputParamsKey, types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
					types.Named(policyTagsKey, types.NewArray(nil, types.S)),
				),
				types.Named("authorizationResponse", types.NewObject([]*types.StaticProperty{
					types.NewStaticProperty("decisionTime", types.N),
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
		func(bCtx rego.BuiltinContext, subject, resourceTypes, inputParams, policyTags *ast.Term) (*ast.Term, error) {
			var (
				err error
				req = &authorizationpb.WhatAuthorizedRequest{}
			)

			req.Subject, err = extractSubject(subject.Value, 1)
			if err != nil {
				return nil, err
			}

			if err = ast.As(resourceTypes.Value, &req.ResourceTypes); err != nil {
				return nil, err
			}

			req.InputParams, err = utilities.ParseInputParams(inputParams, 3)
			if err != nil {
				return nil, err
			}

			req.PolicyTags = parsePolicyTags(policyTags)

			client, err := AuthorizationClient(bCtx.Context)
			if err != nil {
				return nil, err
			}

			var (
				resp *authorizationpb.WhatAuthorizedResponse
				obj  ast.Object
			)
			resp, err = client.WhatAuthorizedWithRawRequest(bCtx.Context, req)
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
		ast.Item(ast.StringTerm("decisionTime"), ast.IntNumberTerm(int(resp.DecisionTime.AsTime().Unix()))),
		ast.Item(ast.StringTerm("decisions"), ast.NewTerm(decisions)),
	)

	return obj
}
